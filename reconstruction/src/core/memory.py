"""Single-pass memory extraction via Volatility3.

Key optimization: reads ALL mapped pages of dockerd ONCE into RAM,
then provides O(n) pattern matching via bytes.find() on cached data.
Eliminates the ~50s-per-scan BytesScanner overhead entirely.
"""
import sys
import struct
import time
import bisect
import io
import os
import logging
from pathlib import Path
from .evidence import error


class _VolatilityDiagnostics(logging.Handler):
    def __init__(self, target):
        super().__init__(logging.WARNING)
        self.target = target

    def emit(self, record):
        self.target.append({'stage': 'volatility', 'logger': record.name,
                            'severity': record.levelname, 'message': record.getMessage()})


class ProcessInfo:
    __slots__ = ('pid', 'ppid', 'comm')

    def __init__(self, pid, ppid, comm):
        self.pid = pid
        self.ppid = ppid
        self.comm = comm

    def __repr__(self):
        return f"<Process pid={self.pid} ppid={self.ppid} comm={self.comm}>"


class CachedProcessMemory:
    """In-memory cache of a process's full virtual address space.

    After loading, provides fast random-access reads and multi-pattern
    searching without any further Volatility3 layer calls.
    """

    def __init__(self):
        self._regions = []   # [(start_vaddr, bytes), ...] sorted by vaddr
        self._starts = []    # [start_vaddr, ...] for binary search
        self.total_bytes = 0
        self.region_count = 0
        self._raw_chunks = []  # temporary: [(vaddr, bytes), ...] unsorted
        self.diagnostics = []

    def add_chunk(self, vaddr, data):
        """Append a memory chunk. Call finalize() after all chunks are added."""
        self._raw_chunks.append((vaddr, data))
        self.total_bytes += len(data)

    def finalize(self):
        """Sort chunks and merge contiguous regions for efficient access."""
        self._raw_chunks.sort(key=lambda x: x[0])

        if not self._raw_chunks:
            self.region_count = 0
            return

        merged = []
        cur_start, cur_parts = self._raw_chunks[0][0], [self._raw_chunks[0][1]]
        cur_end = cur_start + len(self._raw_chunks[0][1])

        for vaddr, data in self._raw_chunks[1:]:
            if vaddr == cur_end:
                cur_parts.append(data)
                cur_end += len(data)
            else:
                merged.append((cur_start, b''.join(cur_parts)))
                cur_start = vaddr
                cur_parts = [data]
                cur_end = vaddr + len(data)
        merged.append((cur_start, b''.join(cur_parts)))

        self._regions = merged
        self._starts = [s for s, _ in merged]
        self.region_count = len(merged)
        self._raw_chunks = []

    def read_safe(self, addr, size):
        """Read bytes at virtual address. Returns None on failure."""
        if size < 0 or addr < 0:
            return None
        idx = bisect.bisect_right(self._starts, addr) - 1
        if idx < 0:
            return None
        start, data = self._regions[idx]
        offset = addr - start
        end = offset + size
        if offset < 0 or end > len(data):
            return None
        return data[offset:end]

    def find_all(self, pattern):
        """Find all occurrences of byte pattern. Returns list of virtual addresses."""
        if isinstance(pattern, str):
            pattern = pattern.encode()
        if not pattern:
            raise ValueError('Search pattern must not be empty')
        results = []
        for start, data in self._regions:
            pos = 0
            while True:
                idx = data.find(pattern, pos)
                if idx == -1:
                    break
                results.append(start + idx)
                pos = idx + 1
        return results

    def find_any_8byte_value(self, target_values):
        """Single-pass search for any 8-byte value from target_values set.
        
        Returns list of (virtual_address, matched_value).
        This is O(N) where N is total memory bytes, regardless of how many
        target values there are, since set lookup is O(1).
        """
        if not target_values:
            return []
        target_set = set(target_values)
        _unpack = struct.Struct('<Q').unpack_from
        results = []
        for start, data in self._regions:
            n = (len(data) // 8) * 8
            for off in range(0, n, 8):
                val = _unpack(data, off)[0]
                if val in target_set:
                    results.append((start + off, val))
        return results

    def find_pointer_to(self, target_addr):
        """Find all 8-byte LE pointers to target_addr in cached memory."""
        return self.find_all(struct.pack('<Q', target_addr))

    def find_any_pointer_to(self, target_addrs):
        """Single-pass search for pointers to ANY address in target_addrs."""
        if not target_addrs:
            return []
        
        target_set = set(target_addrs)
        results = []
        import struct
        
        # If the number of targets is small, multi-pass C-level find() is much faster
        if len(target_set) <= 20:
            patterns = [(addr, struct.pack('<Q', addr)) for addr in target_set]
            for start, data in self._regions:
                for addr, pattern in patterns:
                    pos = 0
                    while True:
                        idx = data.find(pattern, pos)
                        if idx == -1:
                            break
                        results.append((start + idx, addr))
                        pos = idx + 1
        else:
            # Fallback to single-pass Python unpack for large target sets to avoid O(K*N) explosion
            _unpack = struct.Struct('<Q').unpack_from
            for start, data in self._regions:
                n = (len(data) // 8) * 8
                for off in range(0, n, 8):
                    val = _unpack(data, off)[0]
                    if val in target_set:
                        results.append((start + off, val))
        return results


class VolatilityLoader:
    """Initializes Volatility3 and extracts process data."""

    def __init__(self, dump_path, symbol_paths=None, venv_path=None):
        self.dump_path = dump_path
        self.symbol_paths = symbol_paths or []
        self.venv_path = venv_path or os.environ.get('VOLATILITY_SITE_PACKAGES')
        self.diagnostics = []
        self.coverage = {}
        self._ctx = None
        self._kernel = None
        self._pslist = None

    def initialize(self):
        """Set up Volatility3 framework and parse the dump."""
        if self.venv_path and self.venv_path not in sys.path:
            sys.path.insert(0, self.venv_path)

        from volatility3.framework import contexts, constants, automagic, plugins
        from volatility3 import framework
        import volatility3.plugins
        import volatility3.symbols
        from volatility3.plugins.linux import pslist

        # Keep generated caches in the workspace, not the user's read-only
        # profile. Isolate processes so concurrent replays do not lock SQLite.
        cache = Path(__file__).resolve().parents[2] / 'outputs' / 'volatility_cache' / str(os.getpid())
        cache.mkdir(parents=True, exist_ok=True)
        constants.CACHE_PATH = str(cache)
        constants.OFFLINE = True
        logger = logging.getLogger('volatility3')
        for handler in list(logger.handlers):
            if isinstance(handler, _VolatilityDiagnostics):
                logger.removeHandler(handler)
        logger.addHandler(_VolatilityDiagnostics(self.diagnostics))
        logger.propagate = False

        if self.symbol_paths:
            volatility3.symbols.__path__ = self.symbol_paths + constants.SYMBOL_BASEPATHS

        framework.require_interface_version(2, 0, 0)
        framework.import_files(volatility3.plugins, True)

        ctx = contexts.Context()
        abs_path = os.path.abspath(self.dump_path)
        uri = Path(abs_path).as_uri()
        ctx.config['automagic.LayerStacker.single_location'] = uri

        autos = automagic.available(ctx)
        autos = automagic.choose_automagic(autos, pslist.PsList)
        constructed = plugins.construct_plugin(ctx, autos, pslist.PsList, 'plugins', None, None)

        self._ctx = ctx
        self._kernel = ctx.modules[constructed.config['kernel']]
        self._pslist = pslist.PsList

    def list_processes(self):
        """Enumerate all processes. Returns list of ProcessInfo."""
        procs = []
        for task in self._pslist.list_tasks(self._ctx, self._kernel.name):
            comm = task.comm.cast("string", max_length=16, errors="replace")
            pid = int(task.pid)
            try:
                ppid = int(task.parent.pid) if hasattr(task, 'parent') and task.parent else 0
            except Exception as exc:
                self.diagnostics.append(error('process.parent', exc, pid=pid))
                ppid = 0
            procs.append(ProcessInfo(pid, ppid, comm))
        return procs

    def extract_process_memory(self, comm=None, pid=None, progress_cb=None):
        """Extract all mapped pages of a process into CachedProcessMemory.

        Returns (CachedProcessMemory, elapsed_seconds).
        """
        target_task = None
        for task in self._pslist.list_tasks(self._ctx, self._kernel.name):
            if pid is not None:
                if int(task.pid) == pid:
                    target_task = task
                    break
            else:
                c = task.comm.cast("string", max_length=16, errors="replace")
                if c == comm:
                    target_task = task
                    break
        if not target_task:
            search_key = pid if pid is not None else comm
            raise RuntimeError(f"Process '{search_key}' not found in memory dump")

        layer_name = target_task.add_process_layer()
        pl = self._ctx.layers[layer_name]

        mem = CachedProcessMemory()
        t0 = time.time()
        chunk_count = 0

        for chunk_offset, chunk_size, _mo, _ms, _ln in pl.mapping(0, (pl.maximum_address + 1) // 2, ignore_errors=True):
            try:
                data = pl.read(chunk_offset, chunk_size, pad=False)
                mem.add_chunk(chunk_offset, data)
                chunk_count += 1
                if progress_cb and chunk_count % 10000 == 0:
                    progress_cb(mem.total_bytes, time.time() - t0)
            except Exception as exc:
                mem.diagnostics.append(error('memory.read', exc, address=chunk_offset, size=chunk_size))

        mem.finalize()
        elapsed = time.time() - t0
        return mem, elapsed

    def extract_target_processes(self, comms, progress_cb=None):
        """Extract memory for multiple processes by comm name.
        
        Handles Page Fault exceptions gracefully if a process is swapped out.
        Returns dict: {pid: {'comm': comm, 'mem': CachedProcessMemory}}
        """
        results = {}
        for task in self._pslist.list_tasks(self._ctx, self._kernel.name):
            c = task.comm.cast("string", max_length=16, errors="replace")
            if c in comms:
                pid = int(task.pid)
                try:
                    layer_name = task.add_process_layer()
                    if layer_name is None:
                        self.coverage[pid] = {'comm': c, 'status': 'unavailable', 'reason': 'process_layer_unavailable; swap_or_missing_pages_possible'}
                        getattr(self, 'log', print)(f"[!] Process {c} (PID: {pid}) layer creation failed (Page Fault/Swap). Skipping.")
                        continue
                    pl = self._ctx.layers[layer_name]
                    
                    mem = CachedProcessMemory()
                    chunk_count = 0
                    
                    for chunk_offset, chunk_size, _mo, _ms, _ln in pl.mapping(0, (pl.maximum_address + 1) // 2, ignore_errors=True):
                        try:
                            data = pl.read(chunk_offset, chunk_size, pad=False)
                            mem.add_chunk(chunk_offset, data)
                            chunk_count += 1
                        except Exception as exc:
                            mem.diagnostics.append(error('memory.read', exc, address=chunk_offset, size=chunk_size))
                    
                    mem.finalize()
                    results[pid] = {'comm': c, 'mem': mem}
                    self.coverage[pid] = {'comm': c, 'status': 'partial' if mem.total_bytes else 'unavailable',
                        'readable_bytes': mem.total_bytes, 'regions': mem.region_count,
                        'mapping_policy': 'resident_mappings_only; absent_and_swapped_pages_not_zero_filled',
                        'errors': mem.diagnostics}
                    getattr(self, 'log', print)(f"[*] Extracted {c} (PID: {pid}) memory: {mem.total_bytes / 1024 / 1024:.2f} MB")
                except Exception as e:
                    self.diagnostics.append(error('memory.extract', e, pid=pid, comm=c))
                    self.coverage[pid] = {'comm': c, 'status': 'unavailable', 'reason': str(e)}
                    getattr(self, 'log', print)(f"[!] Error extracting memory for {c} (PID: {pid}): {e}")
        return results

    def discover_containers_via_kernel(self):
        """Builds a mapping of CID -> running PIDs via kernel cgroups/namespaces."""
        layer_name = self._kernel.layer_name
        kernel_tasks = list(self._pslist.list_tasks(self._ctx, self._kernel.name))
        
        containers = {}
        host_mnt_ns = None
        for task in kernel_tasks:
            if task.pid == 1:
                try: host_mnt_ns = int(task.nsproxy.mnt_ns.ns.inum)
                except Exception as exc:
                    self.diagnostics.append(error('namespace.host', exc, pid=1))
                break
                
        for task in kernel_tasks:
            pid = int(task.pid)
            try:
                if not task.mm: continue
            except Exception as exc:
                self.diagnostics.append(error('process.mm', exc, pid=pid))
                continue
            
            cgroup_path = self._read_cgroup_path(task)
            if cgroup_path:
                cid = self._extract_container_id_from_cgroup(cgroup_path)
                if cid:
                    if cid not in containers:
                        mnt_ns = None
                        try: mnt_ns = int(task.nsproxy.mnt_ns.ns.inum)
                        except Exception as exc:
                            self.diagnostics.append(error('namespace.mount', exc, pid=pid))
                        containers[cid] = {'pids': [], 'mnt_ns': mnt_ns, 'cgroup_path': cgroup_path, 'strategy': 'cgroup'}
                    containers[cid]['pids'].append(pid)
                    continue
                    
            if cgroup_path:
                is_docker_related = any(pat in cgroup_path.lower() for pat in ['docker', 'containerd', 'kubepod', 'lxc', 'podman'])
                if is_docker_related:
                    try:
                        if task.nsproxy and task.nsproxy.mnt_ns:
                            task_mnt_ns = int(task.nsproxy.mnt_ns.ns.inum)
                            if host_mnt_ns and task_mnt_ns != host_mnt_ns:
                                ns_key = f"NS_{task_mnt_ns}"
                                if ns_key not in containers:
                                    containers[ns_key] = {'pids': [], 'mnt_ns': task_mnt_ns, 'cgroup_path': cgroup_path or 'unknown', 'strategy': 'namespace'}
                                containers[ns_key]['pids'].append(pid)
                    except Exception as exc:
                        self.diagnostics.append(error('namespace.fallback', exc, pid=pid))
                    
        ns_only = {k: v for k, v in containers.items() if k.startswith('NS_')}
        cgroup_entries = {k: v for k, v in containers.items() if not k.startswith('NS_')}
        ns_to_cid = {}
        for cid, info in cgroup_entries.items():
            if info['mnt_ns']:
                ns_to_cid.setdefault(info['mnt_ns'], set()).add(cid)
        for ns_key, ns_info in ns_only.items():
            mnt_ns = ns_info['mnt_ns']
            if len(ns_to_cid.get(mnt_ns, set())) == 1:
                cid = next(iter(ns_to_cid[mnt_ns]))
                cgroup_entries[cid].setdefault('correlations', []).append({
                    'source': 'unique_mount_namespace', 'namespace': mnt_ns,
                    'pids': ns_info['pids'], 'confidence': 'medium'})
                for pid in ns_info['pids']:
                    if pid not in cgroup_entries[cid]['pids']: cgroup_entries[cid]['pids'].append(pid)
            else:
                cgroup_entries[ns_key] = ns_info
        return cgroup_entries

    def _read_cgroup_path(self, task):
        try:
            css_set = task.cgroups
            if not css_set: return None
            cgrp = None
            if hasattr(css_set, 'dfl_cgrp') and css_set.dfl_cgrp:
                cgrp = css_set.dfl_cgrp
            if not cgrp and hasattr(css_set, 'subsys'):
                try:
                    for css in css_set.subsys:
                        if css and hasattr(css, 'cgroup') and css.cgroup:
                            cgrp = css.cgroup
                            break
                except Exception as exc:
                    self.diagnostics.append(error('cgroup.v1', exc, pid=int(task.pid)))
            if not cgrp: return None
            parts = []
            kn = cgrp.kn if hasattr(cgrp, 'kn') else None
            max_depth = 256
            visited = set()
            while kn and max_depth > 0:
                if int(kn) in visited:
                    self.diagnostics.append({'stage': 'cgroup.path', 'pid': int(task.pid), 'reason': 'cycle'})
                    break
                visited.add(int(kn))
                max_depth -= 1
                try:
                    name_ptr = kn.name
                    if not name_ptr: break
                    name = name_ptr.dereference().cast("string", max_length=256, errors="replace")
                    if not name or name == '': break
                    parts.append(str(name))
                    parent = kn.parent if kn.has_member('parent') else kn.member('__parent')
                    if not parent or parent == kn: break
                    kn = parent
                except Exception as exc:
                    self.diagnostics.append(error('cgroup.path', exc, pid=int(task.pid)))
                    break
            if parts:
                parts.reverse()
                return '/' + '/'.join(parts)
            return None
        except Exception as exc:
            self.diagnostics.append(error('cgroup', exc, pid=int(task.pid)))
            return None

    def _extract_container_id_from_cgroup(self, cgroup_path):
        import re
        if not cgroup_path: return None
        m = re.search(r'docker-([0-9a-f]{64})\.scope', cgroup_path)
        if m: return m.group(1)
        m = re.search(r'(?:cri-containerd|crio|libpod)-([0-9a-f]{64})\.scope', cgroup_path)
        if m: return m.group(1)
        m = re.search(r'/docker/([0-9a-f]{64})', cgroup_path)
        if m: return m.group(1)
        m = re.search(r'/([0-9a-f]{64})(?:/|$)', cgroup_path)
        if m: return m.group(1)
        return None

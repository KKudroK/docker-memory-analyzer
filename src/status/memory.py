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

    def find_pointer_to(self, target_addr):
        """Find all 8-byte LE pointers to target_addr in cached memory."""
        return self.find_all(struct.pack('<Q', target_addr))

    def find_any_pointer_to(self, target_addrs):
        """Single-pass search for pointers to ANY address in target_addrs.

        Much faster than calling find_pointer_to() for each address when
        there are many targets (O(n) vs O(n*k)).
        Returns [(pointer_location, target_addr), ...].
        """
        if not target_addrs:
            return []
        target_set = set(target_addrs)
        _unpack = struct.Struct('<Q').unpack_from
        results = []
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
        self.venv_path = venv_path or r'C:\Users\gksgm\AppData\Local\AndroidLab\.venv\Lib\site-packages'
        self._ctx = None
        self._kernel = None
        self._pslist = None

    def initialize(self):
        """Set up Volatility3 framework and parse the dump."""
        if self.venv_path not in sys.path:
            sys.path.insert(0, self.venv_path)

        from volatility3.framework import contexts, constants, automagic, plugins
        from volatility3 import framework
        import volatility3.plugins
        import volatility3.symbols
        from volatility3.plugins.linux import pslist

        if self.symbol_paths:
            volatility3.symbols.__path__ = self.symbol_paths + constants.SYMBOL_BASEPATHS

        framework.require_interface_version(2, 0, 0)
        framework.import_files(volatility3.plugins, True)

        ctx = contexts.Context()
        uri = 'file:///' + self.dump_path.replace('\\', '/')
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
            except Exception:
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

        for chunk_offset, chunk_size, _mo, _ms, _ln in pl.mapping(0, pl.maximum_address, ignore_errors=True):
            try:
                data = pl.read(chunk_offset, chunk_size, pad=True)
                mem.add_chunk(chunk_offset, data)
                chunk_count += 1
                if progress_cb and chunk_count % 10000 == 0:
                    progress_cb(mem.total_bytes, time.time() - t0)
            except Exception:
                pass

        mem.finalize()
        elapsed = time.time() - t0
        return mem, elapsed

# Internal network backend for linux.docker.Docker; shared readers live in linux/_artifacts.

# Source section: identity
"""Runtime argv evidence supplements cgroups without treating ancestry as proof."""
import re

from volatility3.plugins.linux._artifacts import network as network_readers
from volatility3.plugins.linux._artifacts.cgroups import (
    CgroupPathPolicy,
    effective_cgroups,
    effective_cgroup_path,
)
from volatility3.plugins.linux._artifacts.core import CollectionSession, pointer_string
from volatility3.plugins.linux._artifacts.namespaces import namespace_inum
from volatility3.plugins.linux._artifacts.tasks import (
    walk_list,
    read_argv,
    NETWORK_ARGV,
    list_tasks,
)

def identity_display_labels(known):
    """Use at least twelve ID characters, extending prefixes until unique."""
    labels = {}
    for cid in known:
        length = 12
        while any((other != cid and other[:length] == cid[:length] for other in known)):
            length += 1
        labels[cid] = cid[:length]
    return labels

def identity_cgroup_candidates(paths):
    """Recognize runtime naming grammars, not arbitrary 64-hex path components.

    Names remain runtime-path evidence, not proof of a reachable Docker store.
    Preserve raw paths separately so nonstandard names remain inspectable.
    """
    result = set()
    for path in paths:
        parts = path.strip('/').split('/')
        for index, part in enumerate(parts):
            scope = re.fullmatch('(?:docker|cri-containerd|crio|libpod)-([0-9a-f]{64})\\.scope', part)
            if scope:
                result.add(scope.group(1))
            elif index and parts[index - 1] == 'docker' and re.fullmatch('[0-9a-f]{64}', part):
                result.add(part)
    return sorted(result)

def identity_member_id(task):
    """One complete own-cgroup ID; ancestry and namespace never grant membership."""
    ids = identity_cgroup_candidates(task.get('cgroup_paths', []))
    if len(ids) != 1 or task.get('identity_conflict') or task.get('cgroup_complete') is False or task.get('pid_conflict'):
        return None
    assigned = sorted(set(task.get('container_candidates', [])))
    if assigned and assigned != ids:
        return None
    return ids[0]

def identity_parent_address(task):
    return hex(int(task.real_parent))

def identity_runtime_argv(c, task):
    return read_argv(c.context, task, NETWORK_ARGV)

def identity_collect(c, records):
    by_address = {r['address']: r for r in records}
    shims = {}
    for task in c.tasks:
        record = by_address.get(hex(task.vol.offset))
        if record is None:
            continue
        record['parent'] = c.read('task.parent', task, identity_parent_address, args=(task,))
        comm = record['comm']
        if record['pid'] != record['tgid']:
            continue
        if not comm.startswith('containerd-shim'):
            continue
        args = c.read('identity.runtime_argv', task, identity_runtime_argv, [], args=(c, task))
        ids = [args[i + 1] for i, arg in enumerate(args[:-1]) if arg in ('-id', '--id') and re.fullmatch('[0-9a-f]{64}', args[i + 1])]
        if ids:
            shims[record['address']] = sorted(set(ids))
            record['shim_container_candidates'] = shims[record['address']]
    for record in records:
        node, seen = (record, set())
        while node.get('parent') in by_address:
            address = node['parent']
            if address == node['address']:
                if node.get('pid') != 0:
                    c.issue('identity.ancestry', node['address'], ValueError('non-root task is its own parent'))
                break
            if address in seen or len(seen) >= c.limit:
                c.issue('identity.ancestry', record['address'], ValueError('parent cycle/limit'))
                break
            seen.add(address)
            if address in shims:
                record['shim_ancestry_candidates'] = shims[address]
                if not record['container_candidates']:
                    record['container_candidates'] = shims[address]
                    record['identity_evidence'] = 'shim_argv_ancestry_candidate'
                elif set(record['container_candidates']) != set(shims[address]):
                    record['identity_conflict'] = True
                break
            node = by_address[address]
    for ns in c.nets.values():
        ns['container_candidates'] = sorted({cid for r in records if r.get('namespace') == ns['address'] for cid in r['container_candidates']})

# Source section: sockets
"""FD ownership and bounded reciprocal UNIX peer discovery."""
import socket
from volatility3.framework.objects import utility
from volatility3.framework.symbols.linux import network
from volatility3.framework.symbols import linux

def sockets_fd_table(files, limit):
    if files.has_member('fdt'):
        if not files.fdt:
            raise ValueError('NULL fdtable')
        table = files.fdt.dereference()
    elif files.has_member('fd') and files.has_member('max_fds'):
        table = files
    else:
        raise NotImplementedError('files_struct FD layout unavailable')
    count = int(table.max_fds)
    if not 0 <= count <= limit:
        raise ValueError(f'max_fds={count} outside safety budget 0..{limit}')
    if count and (not table.fd):
        raise ValueError('NULL fd pointer with nonempty fdtable')
    return (table, count)

def sockets_file_dentry(filp):
    if filp.has_member('f_path'):
        return filp.get_dentry()
    if filp.has_member('f_dentry'):
        return filp.f_dentry
    raise NotImplementedError('file dentry layout unavailable')

def sockets_read_sock(c, sk, source):
    """Parse a socket independently from the FD(s) that reference it."""
    common = sk.member('__sk_common')
    ns = c.net_pointer(common.skc_net)
    if not ns:
        raise ValueError('NULL socket namespace')
    c.read('socket.namespace', sk, lambda: c.namespace(c.obj('net', ns), 'sock.__sk_common.skc_net'))
    row = {'socket': hex(sk.vol.offset), 'namespace': hex(int(ns)), 'family': int(common.skc_family), 'source': source, 'receive_queue_packets': int(sk.sk_receive_queue.qlen), 'state': int(common.skc_state), 'socket_type': int(sk.sk_type), 'protocol_number': int(sk.sk_protocol)}
    if row['family'] in (2, 10):
        inet = sk.cast('inet_sock')
        row.update(protocol=str(inet.get_protocol()), source_port=int(inet.get_src_port()), destination_port=int(inet.get_dst_port()))
        if row['family'] == 10:
            row['source_ip'] = socket.inet_ntop(socket.AF_INET6, c.layer.read(common.skc_v6_rcv_saddr.vol.offset, 16))
            row['destination_ip'] = socket.inet_ntop(socket.AF_INET6, c.layer.read(common.skc_v6_daddr.vol.offset, 16))
        else:
            row['source_ip'] = str(inet.get_src_addr())
            row['destination_ip'] = str(inet.get_dst_addr())
    elif row['family'] == 1:
        unix = sk.cast('unix_sock')
        row['path'] = None
        if unix.addr:
            length = int(unix.addr.len)
            path_offset = c.kernel.get_type('sockaddr_un').relative_child_offset('sun_path')
            if not path_offset <= length <= c.kernel.get_type('sockaddr_un').size:
                raise ValueError('invalid sockaddr_un length')
            raw = c.layer.read(unix.addr.name.vol.offset + path_offset, length - path_offset)
            row['path_bytes_hex'] = raw.hex()
            row['abstract'] = raw.startswith(b'\x00')
            row['path'] = '@' + raw[1:].decode('utf-8', errors='backslashreplace') if row['abstract'] else raw.rstrip(b'\x00').decode('utf-8', errors='backslashreplace')
        row['peer'] = hex(int(unix.peer))
        if sk.sk_socket:
            row['state_name'] = unix.get_state()
    return row

def sockets_merge_holders(rows):
    unique = {}
    for row in rows:
        holder = {key: row[key] for key in ('pid', 'fd', 'file')}
        if row['socket'] not in unique:
            unique[row['socket']] = dict({key: value for key, value in row.items() if key not in ('pid', 'fd', 'file')}, holders=[])
        if holder not in unique[row['socket']]['holders']:
            unique[row['socket']]['holders'].append(holder)
    return unique

def sockets_record_cached_holders(errors, indices, pid):
    """A failed immutable FD slot is scanned once; all affected tasks are recorded."""
    for index in indices:
        affected = errors[index].setdefault('affected_holders', [])
        holder = {'pid': pid, 'fd': errors[index].get('fd')}
        if holder not in affected:
            affected.append(holder)

def sockets_expand_unix_peers(c, unique, selected_pids):
    """One hop only, with family and reciprocal backlink validation."""
    seeds = [row for row in unique.values() if row['family'] == 1 and any((h['pid'] in selected_pids for h in row['holders']))]
    for row in seeds:
        peer = row.get('peer')
        if peer in (None, '0x0', row['socket']) or peer in unique:
            continue

        def read_peer():
            sk = c.obj('sock', int(peer, 16))
            result = sockets_read_sock(c, sk, 'unix_sock.peer')
            if result['family'] != 1 or result.get('peer') != row['socket']:
                raise ValueError('UNIX peer family/backlink mismatch')
            result.update(holders=[], confidence='reciprocal_kernel_peer', discovery='unix_peer')
            unique[result['socket']] = result
        c.read('socket.unix_peer', peer, read_peer)

def sockets_collect(c, task_records=None):
    network.NetSymbols.apply(c.context.symbol_space[c.kernel.symbol_table_name])
    socket_fops = c.kernel.object_from_symbol('socket_file_ops').vol.offset
    rows = []
    files_cache = {}
    file_cache = {}
    for task in c.tasks:

        def task_fds():
            if not task.files:
                return
            files_key = int(task.files)
            pid = int(task.pid)
            if files_key in files_cache:
                cached, indices = files_cache[files_key]
                rows.extend((dict(row, pid=pid) for row in cached))
                sockets_record_cached_holders(c.errors, indices, pid)
                return
            start_row = len(rows)
            indices = []
            fdt, count = sockets_fd_table(task.files.dereference(), c.limit)
            fds = utility.array_of_pointers(fdt.fd.dereference(), count, c.kernel.symbol_table_name + '!file', c.context) if count else []
            for fd in range(count):

                def entry():
                    filp = fds[fd]
                    if not filp:
                        return
                    address = int(filp)
                    if address in file_cache:
                        result = file_cache[address]
                        if result is not None:
                            rows.append(dict(result, pid=pid, fd=fd, file=hex(address)))
                        return
                    if int(filp.f_op) != socket_fops:
                        file_cache[address] = None
                        return
                    dentry = sockets_file_dentry(filp)
                    inode = dentry.d_inode
                    if not inode:
                        raise ValueError(f'socket file {hex(address)} has NULL d_inode')
                    alloc = linux.LinuxUtilities.container_of(int(inode), 'socket_alloc', 'vfs_inode', c.kernel)
                    if alloc is None:
                        if inode:
                            offset = c.kernel.get_type('socket_alloc').relative_child_offset('vfs_inode')
                            c.layer.read(int(inode) - offset, 1)
                        raise ValueError('socket_alloc container_of unavailable')
                    if not alloc.socket.sk:
                        return
                    sk = alloc.socket.sk.dereference()
                    if sk.sk_socket and int(sk.sk_socket) != alloc.socket.vol.offset:
                        raise ValueError('socket.sk -> sk_socket backlink mismatch')
                    result = sockets_read_sock(c, sk, 'task.files -> fd -> file -> socket_alloc.socket.sk')
                    result.update(confidence='fd_reachable_socket_object', discovery='fd')
                    file_cache[address] = result
                    rows.append(dict(result, pid=pid, fd=fd, file=hex(address)))
                before = len(c.errors)
                c.read('socket.fd', task, entry)
                for index in range(before, len(c.errors)):
                    c.errors[index].update(pid=pid, fd=fd, files_struct=hex(files_key))
                    indices.append(index)
            files_cache[files_key] = (rows[start_row:], indices)
            sockets_record_cached_holders(c.errors, indices, pid)
        c.read('socket.task', task, task_fds)
    unique = sockets_merge_holders(rows)
    selected_pids = {t['pid'] for t in task_records or [] if identity_member_id(t)}
    sockets_expand_unix_peers(c, unique, selected_pids)
    return list(unique.values())

# Source section: conntrack
"""Confirmed conntrack tuples (observed flows, not firewall configuration)."""
import socket
from volatility3.framework.objects import utility

def conntrack_symbols(c, names):
    found = {n: c.kernel.object_from_symbol(n).vol.offset for n in names if c.kernel.has_symbol(n)}
    if len(found) == len(names):
        return found

    def modules():
        for mod in c.walk(c.kernel.object_from_symbol('modules'), 'module', 'list'):
            if utility.array_to_string(mod.name) != 'nf_conntrack':
                continue
            ks = mod.kallsyms.dereference()
            sym_type = ks.symtab.vol.subtype.vol.type_name.split('!')[-1]
            for sym in c.array(int(ks.symtab), sym_type, int(ks.num_symtab)):
                offset = int(sym.st_name)
                name = c.layer.read(int(ks.strtab) + offset, 128).split(b'\x00', 1)[0].decode('ascii', errors='replace')
                if name in names:
                    found[name] = int(sym.st_value) & c.layer.address_mask
    c.read('conntrack.module_symbols', 'modules', modules)
    return found

def conntrack_tuple_data(c, value):
    family, protocol = (int(value.src.l3num), int(value.dst.protonum))
    if family not in (2, 10):
        return {'family': family, 'protocol': protocol}
    size, af = (4, socket.AF_INET) if family == 2 else (16, socket.AF_INET6)
    row = {'family': family, 'protocol': protocol, 'source_ip': socket.inet_ntop(af, c.layer.read(value.src.u3.vol.offset, size)), 'destination_ip': socket.inet_ntop(af, c.layer.read(value.dst.u3.vol.offset, size))}
    if protocol in (6, 17, 33, 132, 136):
        row['source_port'] = int.from_bytes(c.layer.read(value.src.u.vol.offset, 2), 'big')
        row['destination_port'] = int.from_bytes(c.layer.read(value.dst.u.vol.offset, 2), 'big')
    return row

def conntrack_collect(c, unsupported):
    rows = []
    required = ('hlist_nulls_head', 'nf_conntrack_tuple_hash', 'nf_conn')
    missing = [name for name in required if not c.kernel.has_type(name)]
    if missing:
        unsupported.append({'feature': 'conntrack', 'reason': 'ISF types absent: ' + ', '.join(missing)})
        return rows
    names = ('nf_conntrack_hash', 'nf_conntrack_htable_size')
    found = conntrack_symbols(c, names)
    if any((n not in found for n in names)):
        unsupported.append({'feature': 'conntrack', 'reason': 'hash symbols absent in kernel/module kallsyms'})
        return rows

    def scan():
        address = int(c.obj('pointer', found[names[0]]))
        count = int(c.obj('unsigned int', found[names[1]]))
        if not address or count <= 0:
            raise ValueError('NULL conntrack hash or nonpositive bucket count')
        heads = c.array(address, 'hlist_nulls_head', count)
        entry_offset = c.kernel.get_type('nf_conntrack_tuple_hash').relative_child_offset('hnnode')
        tuples_offset = c.kernel.get_type('nf_conn').relative_child_offset('tuplehash')
        tuple_size = c.kernel.get_type('nf_conntrack_tuple_hash').size
        all_seen = set()
        for head in heads:

            def bucket():
                link, seen = (int(head.first), set())
                while link and (not link & 1):
                    if link in seen or len(seen) >= c.limit:
                        raise ValueError('conntrack cycle or limit')
                    seen.add(link)
                    entry = c.obj('nf_conntrack_tuple_hash', link - entry_offset)
                    direction = int(entry.tuple.dst.dir)
                    if direction not in (0, 1):
                        raise ValueError('invalid conntrack direction')
                    ct = c.obj('nf_conn', entry.vol.offset - tuples_offset - direction * tuple_size)
                    link = int(entry.hnnode.next)
                    if ct.vol.offset in all_seen:
                        continue
                    all_seen.add(ct.vol.offset)

                    def record():
                        namespace = c.net_pointer(ct.ct_net)
                        if not namespace:
                            raise ValueError('NULL conntrack namespace')
                        if hex(namespace) not in c.context_namespaces:
                            return
                        status = int(ct.status)
                        original, reply = (ct.tuplehash[0].tuple, ct.tuplehash[1].tuple)
                        if (int(original.dst.dir), int(reply.dst.dir)) != (0, 1):
                            raise ValueError('conntrack tuple direction pair mismatch')
                        if (int(original.src.l3num), int(original.dst.protonum)) != (int(reply.src.l3num), int(reply.dst.protonum)):
                            raise ValueError('conntrack tuple family/protocol mismatch')
                        rows.append({'address': hex(ct.vol.offset), 'namespace': hex(namespace), 'original': conntrack_tuple_data(c, ct.tuplehash[0].tuple), 'reply': conntrack_tuple_data(c, ct.tuplehash[1].tuple), 'status': status, 'snat': bool(status & 1 << 4), 'dnat': bool(status & 1 << 5), 'source': 'nf_conntrack_hash -> tuplehash -> nf_conn', 'confidence': 'hashed_flow_object', 'limitation': 'flow state; does not enumerate configured NAT rules'})
                    c.read('conntrack.entry', ct, record)
            c.read('conntrack.bucket', head, bucket)
    c.read('conntrack.hash', found, scan)
    return rows

# Source section: context
"""Observed ID references, FD holders and direct kernel object relations only."""

def context_task_ids(task):
    cid = identity_member_id(task)
    return [cid] if cid else []

def context_build(report):
    tasks = {t['pid']: t for t in report['tasks']}
    nets = {n['address']: n for n in report['namespaces']}
    sockets = {s['socket']: s for s in report['sockets']}
    contexts = {}
    for task in report['tasks']:
        for cid in context_task_ids(task):
            item = contexts.setdefault(cid, {'id': cid, 'pids': [], 'tasks': [], 'namespaces': [], 'cgroup_paths': [], 'identity_sources': [], 'socket_ids': [], 'generation': [], 'warnings': []})
            item['pids'].append(task['tgid'])
            item['tasks'].append(task['address'])
            if task.get('namespace'):
                item['namespaces'].append(task['namespace'])
            item['cgroup_paths'].extend(task.get('cgroup_paths', []))
            item['identity_sources'].append(task.get('identity_evidence', 'unknown'))
            if task['pid'] == task['tgid']:
                item['generation'].append({k: task.get(k) for k in ('pid', 'address', 'comm', 'start_time', 'start_boottime', 'namespaces')})
    for item in contexts.values():
        for key in ('pids', 'tasks', 'namespaces', 'cgroup_paths', 'identity_sources'):
            item[key] = sorted(set(item[key]))
        if any((nets.get(n, {}).get('is_initial') for n in item['namespaces'])):
            item['warnings'].append('host_network_namespace_shared')
        if len(item['namespaces']) > 1:
            item['warnings'].append('tasks_span_multiple_network_namespaces')
    ownership = {}
    for sid, sock in sockets.items():
        holders = []
        for h in sock['holders']:
            t = tasks.get(h['pid'], {})
            holders.append(dict(h, tgid=t.get('tgid', h['pid']), container_ids=context_task_ids(t), task_namespace=t.get('namespace'), identity_conflict=t.get('identity_conflict', False)))
        cids = sorted({cid for h in holders for cid in h['container_ids']})
        ownership[sid] = {'container_ids': cids, 'holders': holders}
        for cid in cids:
            contexts[cid]['socket_ids'].append(sid)
            if any((h['container_ids'] == [cid] and h['task_namespace'] != sock['namespace'] for h in holders)):
                contexts[cid]['warnings'].append('socket_namespace_differs_from_holder')
    relations = []

    def relation(kind, left, right, evidence, confidence, limitation):
        a, b = (ownership[left], ownership[right])
        if not a['container_ids'] and (not b['container_ids']):
            return
        relations.append({'kind': kind, 'left_socket': left, 'right_socket': right, 'left_containers': a['container_ids'], 'right_containers': b['container_ids'], 'left_holders': a['holders'], 'right_holders': b['holders'], 'evidence': evidence, 'confidence': confidence, 'limitation': limitation})
    for sid, sock in sockets.items():
        peer = sock.get('peer')
        if sock['family'] == 1 and peer in sockets and (sid < peer) and (sockets[peer]['family'] == 1) and (sockets[peer].get('peer') == sid):
            relation('unix_peer', sid, peer, [sid, peer], 'reciprocal_kernel_peer', 'current peer relation; not a history of messages or their contents')
    structural = []
    for address, ns in nets.items():
        if address in (None, '', '0x0', 0):
            continue
        members = sorted((cid for cid, item in contexts.items() if address in item['namespaces']))
        if len(members) > 1:
            structural.append({'kind': 'shared_netns', 'members': members, 'evidence': [address], 'confidence': 'same_namespace_object'})
    for sid, owner in ownership.items():
        if len(owner['container_ids']) > 1:
            structural.append({'kind': 'shared_socket', 'members': owner['container_ids'], 'evidence': [sid], 'confidence': 'same_fd_reachable_socket'})
    for item in contexts.values():
        item['warnings'] = sorted(set(item['warnings']))
        item['socket_ids'] = sorted(set(item['socket_ids']))
    return {'containers': [contexts[k] for k in sorted(contexts)], 'socket_ownership': ownership, 'relations': relations, 'structural_relations': structural, 'unresolved_tasks': [t['address'] for t in report['tasks'] if t.get('container_candidates') and (not context_task_ids(t))], 'scope': 'complete own-cgroup runtime ID references; not authenticated runtime inventory', 'relation_policy': 'only reciprocal UNIX peer or shared kernel object; no endpoint correlation'}

# Source section: collector
"""Kernel objects are identities; IP prefixes and names are attributes only."""
import ipaddress
import socket
from volatility3.framework.objects import utility
from volatility3.plugins.linux import pslist

class Collector(CollectionSession):

    def __init__(self, context, kernel_name):
        super().__init__(context, kernel_name)
        self.limit = 100000
        self.cgroup_cache = {}
        self.errors = []
        self.nets = {}
        self.tasks = []
        self.init_net_address = None

    def issue(self, stage, obj, exc):
        self.errors.append({'stage': stage, 'address': hex(obj.vol.offset) if hasattr(obj, 'vol') else str(obj), 'error': type(exc).__name__, 'detail': str(exc)})

    def read(self, stage, obj, fn, default=None, *, args=()):
        try:
            return fn(*args)
        except Exception as exc:
            self.issue(stage, obj, exc)
            return default


    def walk(self, head, typename, member):
        return walk_list(self, head, typename, member, check_backlinks=False)

    def cstring(self, ptr):
        return pointer_string(ptr)

    def net_pointer(self, value):
        """Stock net_device extension pattern: possible_net_t or old net*."""
        wrapped = value.has_member('net')
        return int(value.net) if wrapped else int(value)

    def array(self, address, typename, count):
        if not 0 <= count <= self.limit:
            raise ValueError(f'array count {count} exceeds limit')
        return self.kernel.object('array', offset=int(address), absolute=True, subtype=self.kernel.get_type(typename), count=count)

    def namespace(self, net, source):
        address = int(net.vol.offset)
        if not address:
            raise ValueError('NULL network namespace')
        if address not in self.nets:
            self.nets[address] = {'object': net, 'address': hex(address), 'sources': [], 'pids': [], 'container_candidates': []}
            self.nets[address]['inode'] = self.read('net.inum', net, lambda: namespace_inum(net))
        if source not in self.nets[address]['sources']:
            self.nets[address]['sources'].append(source)
        return self.nets[address]

    def cgroups(self, task):
        if not task.cgroups:
            return []
        css = task.cgroups.dereference()
        cache_key = int(css.vol.offset)
        if cache_key in self.cgroup_cache:
            return list(self.cgroup_cache[cache_key])
        errors_before = len(self.errors)
        groups = effective_cgroups(css, read=self.read)
        paths = []
        for group in groups:
            path = self.read('cgroup.path', group, lambda: self.cgroup_path(group))
            if path is not None and path not in paths:
                paths.append(path)
        if len(self.errors) == errors_before:
            self.cgroup_cache[cache_key] = tuple(paths)
        return paths

    def cgroup_path(self, group):
        return effective_cgroup_path(group, self.cstring, self.limit, policy=CgroupPathPolicy.NETWORK)[0]

    def append_tasks(self, iterator, seen):
        """Consume a stock task iterator with a bounded output and deduplication by PID."""
        for count, task in enumerate(iterator):
            if count >= self.limit:
                raise ValueError('task iterator output budget exceeded')
            pid = int(task.pid)
            if pid not in seen:
                seen.add(pid)
                self.tasks.append(task)

    def discover_tasks(self):
        """Reuse stock process discovery; supplement with psscan for unlinked tasks."""
        self.tasks = []
        seen = set()
        leaders = list_tasks(self.context, self.kernel.name, include_threads=False)
        self.read('tasks.list', 'PsList.list_tasks', self.append_tasks, args=(leaders, seen))
        try:
            from volatility3.plugins.linux import psscan
            hidden_leaders = psscan.PsScan.scan_tasks(self.context, self.kernel.name, self.kernel.layer_name)
            self.read('tasks.psscan', 'PsScan.scan_tasks', self.append_tasks, args=(hidden_leaders, seen))
        except Exception:
            pass
        for leader in list(self.tasks):
            self.read('tasks.threads', leader, self.append_thread_tasks, args=(leader, seen))

    def append_thread_tasks(self, leader, seen):
        self.append_tasks(leader.get_threads(), seen)

    def collect_namespaces(self):
        """Resolve relocated symbols and register namespaces through one reader."""
        self.nets = {}
        self.init_net_address = None
        if self.kernel.has_symbol('net_namespace_list'):
            list_head = 'net_namespace_list'
            try:
                # ISF symbol addresses need the module's relocation offset.
                # Supplying the type also supports BTF symbols without type metadata.
                list_head = self.symbol('net_namespace_list', 'list_head')
                for net in self.walk(list_head, 'net', 'list'):
                    self.read('net', net, self.namespace, args=(net, 'net_namespace_list'))
            except Exception as exc:
                self.issue('net_namespace_list', list_head, exc)
        if self.kernel.has_symbol('init_net'):
            init_net = self.read('init_net', 'init_net', self.symbol, args=('init_net', 'net'))
            if init_net is not None:
                # Use the same relocated, layer-masked object address as task pointers.
                self.init_net_address = hex(int(init_net.vol.offset))
                self.read('net', init_net, self.namespace, args=(init_net, 'init_net'))

    def collect_tasks(self):
        self.discover_tasks()
        records = []
        for task in self.tasks:
            record = self.read('task.identity', task, lambda: {'address': hex(task.vol.offset), 'pid': int(task.pid), 'tgid': int(task.tgid), 'comm': utility.array_to_string(task.comm), 'container_candidates': [], 'source': 'PsList.list_tasks + task.get_threads', 'confidence': 'reachable_task_object'})
            if record is None:
                continue
            errors_before = len(self.errors)
            paths = self.read('task.cgroups', task, self.cgroups, [], args=(task,))
            record['cgroup_paths'] = paths
            record['cgroup_complete'] = len(self.errors) == errors_before
            record['container_candidates'] = identity_cgroup_candidates(paths)
            record['identity_evidence'] = 'cgroup_path_candidate' if record['container_candidates'] else 'unresolved'
            proxy = self.read('task.nsproxy', task, lambda: task.nsproxy.dereference() if task.nsproxy else None)
            if proxy is not None:
                net = self.read('task.net', task, lambda: proxy.net_ns.dereference() if proxy.net_ns else None)
                if net is not None:
                    ns = self.namespace(net, 'task.nsproxy.net_ns')
                    ns['pids'].append(record['pid'])
                    ns['container_candidates'] = sorted(set(ns['container_candidates'] + record['container_candidates']))
                    record['namespace'] = ns['address']
            for field in ('start_time', 'start_boottime'):
                if task.has_member(field):
                    record[field] = self.read('task.' + field, task, lambda f=field: int(task.member(f)))
            records.append(record)
        by_pid = {}
        for record in records:
            by_pid.setdefault(record['pid'], []).append(record)
        for pid, duplicates in by_pid.items():
            if len(duplicates) > 1:
                for record in duplicates:
                    record['pid_conflict'] = True
                self.issue('task.pid_conflict', str(pid), ValueError('distinct task objects share one PID; membership excluded'))
        return records

    def address(self, ifa, family):
        if family == 4:
            raw = self.layer.read(ifa.ifa_local.vol.offset, 4)
            prefix = int(ifa.ifa_prefixlen)
            flags, scope = (int(ifa.ifa_flags), int(ifa.ifa_scope))
        else:
            raw = self.layer.read(ifa.addr.vol.offset, 16)
            prefix = int(ifa.prefix_len)
            flags, scope = (int(ifa.flags), int(ifa.scope))
        ip = socket.inet_ntop(socket.AF_INET if family == 4 else socket.AF_INET6, raw)
        cidr = f'{ip}/{prefix}'
        return {'address': hex(ifa.vol.offset), 'family': family, 'ip': ip, 'prefix': prefix, 'cidr': cidr, 'subnet': str(ipaddress.ip_network(cidr, strict=False)), 'flags': flags, 'scope': scope}

    def interface(self, net, dev):
        row = {'address': hex(dev.vol.offset), 'namespace': net['address'], 'namespace_inode': net['inode'], 'container_candidates': net['container_candidates'], 'pids': net['pids'], 'name': utility.array_to_string(dev.name), 'ifindex': int(dev.ifindex), 'addresses': [], 'source': 'kernel.net.dev_base_head', 'confidence': 'direct_object_membership'}
        row['device_namespace'] = self.read('interface.nd_net', dev, lambda: hex(self.net_pointer(dev.nd_net)))
        if row['device_namespace'] is not None and row['device_namespace'] != net['address']:
            raise ValueError('dev_base_head and nd_net disagree')
        for field in ('mtu', 'flags', 'promiscuity', 'operstate', 'type'):
            row[field] = self.read('interface.' + field, dev, lambda: int(dev.member(field)))

        def mac():
            size = int(dev.addr_len)
            if not 0 <= size <= 32:
                raise ValueError('invalid hardware address length')
            return ':'.join((f'{b:02x}' for b in self.layer.read(int(dev.dev_addr), size)))
        row['mac'] = self.read('interface.mac', dev, mac)
        if dev.has_member('rtnl_link_ops') and dev.rtnl_link_ops:
            row['kind'] = self.read('interface.kind', dev, lambda: network_readers.link_kind(dev, self.cstring))

        def ipv4():
            if not dev.has_member('ip_ptr') or not dev.ip_ptr:
                return
            ipdev = dev.ip_ptr.dereference().cast('in_device')
            ptr, seen = (ipdev.ifa_list, set())
            for _ in range(self.limit):
                if not ptr:
                    return
                if int(ptr) in seen:
                    raise ValueError('IPv4 address cycle')
                seen.add(int(ptr))
                ifa = ptr.dereference()
                value = self.read('ipv4.entry', ifa, lambda: self.address(ifa, 4))
                if value:
                    row['addresses'].append(value)
                ptr = ifa.ifa_next
            if ptr:
                raise ValueError('IPv4 address limit')

        def ipv6():
            if not dev.has_member('ip6_ptr') or not dev.ip6_ptr:
                return
            ipdev = dev.ip6_ptr.dereference().cast('inet6_dev')
            for ifa in self.walk(ipdev.addr_list, 'inet6_ifaddr', 'if_list'):
                value = self.read('ipv6.entry', ifa, lambda: self.address(ifa, 6))
                if value:
                    row['addresses'].append(value)
        self.read('interface.ipv4', dev, ipv4)
        self.read('interface.ipv6', dev, ipv6)
        return row

    def collect(self, features=None):
        """Collect only explicitly selected core evidence; export never widens scope."""
        features = {'sockets'} if features is None else set(features)
        if not features <= {'sockets', 'interfaces', 'conntrack'}:
            raise ValueError('Unknown collection features')
        self.collect_namespaces()
        tasks = self.collect_tasks()
        identity_collect(self, tasks)
        for task in self.tasks:
            proxy = self.read('task.nsproxy', task, lambda: task.nsproxy.dereference() if task.nsproxy else None)
            if proxy:
                net = self.read('nsproxy.net_ns', proxy, lambda: proxy.net_ns.dereference() if proxy.net_ns else None)
                if net:
                    self.read('net', net, self.namespace, args=(net, 'task.nsproxy.net_ns'))
        members = {task.get('namespace') for task in tasks if identity_member_id(task)}
        unsupported = []
        for ns in self.nets.values():
            ns['is_initial'] = ns['address'] == self.init_net_address
            ns['initial_identity_known'] = self.init_net_address is not None
            if features & {'interfaces', 'conntrack'} and ns['address'] in members and (ns['is_initial'] or not ns['initial_identity_known']):
                unsupported.append({'feature': 'container_namespace_context', 'namespace': ns['address'], 'reason': 'host-shared or unknown initial namespace; use container FD sockets for attribution'})
        self.context_namespaces = {ns['address'] for ns in self.nets.values() if ns['address'] in members and (not ns['is_initial']) and ns['initial_identity_known']}
        interfaces = []
        if 'interfaces' in features:
            for net in list(self.nets.values()):
                if net['address'] not in self.context_namespaces:
                    continue

                def devices():
                    for dev in network_readers.devices(self, net['object']):
                        value = self.read('interface', dev, self.interface, args=(net, dev))
                        if value:
                            interfaces.append(value)
                self.read('net.devices', net['object'], devices)
        socket_rows = self.read('socket.collect', 'kernel', sockets_collect, [], args=(self, tasks)) if 'sockets' in features else []
        flow_rows = self.read('conntrack.collect', 'kernel', conntrack_collect, [], args=(self, unsupported)) if 'conntrack' in features else []
        for ns in self.nets.values():
            ns['is_initial'] = ns['address'] == self.init_net_address
            ns['initial_identity_known'] = self.init_net_address is not None
        if 'sockets' in features:
            unsupported.append({'feature': 'socket_coverage', 'reason': 'FD-reachable sockets and reciprocal UNIX peers only; no orphan/TIME_WAIT inventory'})
        report = {'schema_version': 4, 'tasks': tasks, 'unsupported': unsupported, 'sockets': socket_rows, 'metadata': {'kernel_symbol_table': self.kernel.symbol_table_name, 'kernel_layer': self.kernel.layer_name, 'requested_features': sorted(features), 'kernel_virtual_offset': hex(self.kernel.offset), 'traversal_limit': self.limit, 'identity_policy': 'complete unique own-cgroup ID, checked against shim ancestry; addresses identify snapshot objects', 'collection_scope': 'FD holders across tasks for sharing evidence; interface/conntrack context restricted to confirmed non-host container namespaces', 'snapshot_limit': 'live acquisition may smear time; successful parsing is not exhaustive coverage'}, 'conntrack': flow_rows, 'namespaces': [{k: v for k, v in ns.items() if k != 'object'} for ns in self.nets.values()], 'interfaces': interfaces, 'errors': self.errors, 'summary': {'tasks': len(tasks), 'namespaces': len(self.nets), 'interfaces': len(interfaces), 'addresses': sum((len(i['addresses']) for i in interfaces)), 'sockets': len(socket_rows), 'conntrack': len(flow_rows), 'errors': len(self.errors)}}
        report['container_context'] = context_build(report)
        for key in ('containers', 'relations', 'structural_relations'):
            report['summary'][key] = len(report['container_context'][key])
        return report

# Source section: views
"""Container membership and namespace context, without endpoint-based ownership.

All IDs in a shared namespace remain visible even when one member is selected.
Initial-net resources cannot be attributed to a host-network container by netns
alone. Those resources are omitted from context views with an explicit diagnostic;
the container's own FD sockets remain available in the sockets view.
"""
from volatility3.framework import renderers

def views_value(item):
    return renderers.NotAvailableValue() if item is None else item

def views_text(item):
    return str(item).encode('unicode_escape').decode('ascii')

def views_endpoint(item, side):
    ip = item.get(side + '_ip')
    if ip is None:
        return renderers.NotAvailableValue()
    port = item.get(side + '_port')
    if port is None:
        return ip
    return f'[{ip}]:{port}' if item.get('family') == 10 else f'{ip}:{port}'

def views_scope(report, prefixes=None):
    """Map exact net object addresses to own-cgroup members, not to IP owners."""
    members = {}
    known = set()
    for task in report['tasks']:
        cid = identity_member_id(task)
        if cid:
            known.add(cid)
            ns = task.get('namespace')
            if ns not in (None, '', '0x0'):
                members.setdefault(ns, set()).add(cid)
    selected = set(known)
    if prefixes:
        selected = set()
        for prefix in prefixes:
            matches = {cid for cid in known if cid.startswith(prefix.lower())}
            if len(matches) != 1:
                raise ValueError(f'Container prefix {prefix!r} matched {len(matches)} IDs')
            selected.update(matches)
    return (members, selected)

def views_columns(view):
    common = [('Container IDs', str), ('NetNS', int)]
    schemas = {'containers': [('Container ID', str), ('Tasks', int), ('Processes', int), ('Sockets', int), ('NetNS', str)], 'interfaces': common + [('Interface', str), ('Address', str), ('MAC', str)], 'conntrack': common + [('Proto', str), ('Source', str), ('Destination', str), ('NAT', str)], 'diagnostics': [('Kind', str), ('Stage', str), ('Object', str), ('Detail', str)]}
    return schemas[view]

def views_rows(report, view, prefixes=None):
    members, selected = views_scope(report, prefixes)
    nets = {ns['address']: ns for ns in report['namespaces']}
    known = {cid for task in report['tasks'] if (cid := identity_member_id(task))}
    labels = identity_display_labels(known)
    if view == 'diagnostics':
        for error in report.get('errors', []):
            yield (0, ('error', views_text(error['stage']), str(error['address']), views_text(error['error'] + ': ' + error['detail'])))
        for item in report.get('unsupported', []):
            yield (0, ('unsupported', views_text(item['feature']), str(item.get('namespace', item.get('interface', ''))), views_text(item['reason'])))
        for task in report['tasks']:
            if task.get('container_candidates') and (not identity_member_id(task)):
                yield (0, ('unresolved', 'identity', task['address'], 'No complete, unique, nonconflicting own-cgroup membership'))
        return
    if view == 'containers':
        for cid in sorted(selected):
            tasks = [t for t in report['tasks'] if identity_member_id(t) == cid]
            pids = {t['pid'] for t in tasks}
            sockets = {s['socket'] for s in report['sockets'] if any((h['pid'] in pids for h in s['holders']))}
            namespaces = {t['namespace'] for t in tasks if t.get('namespace')}
            inodes = {str(nets.get(ns, {}).get('inode') or '?') for ns in namespaces}
            yield (0, (labels[cid], len(tasks), len({t['tgid'] for t in tasks}), len(sockets), ', '.join(sorted(inodes))))
        return
    for item in report.get(view, []):
        ns_addr = item.get('namespace')
        cids = members.get(ns_addr, set())
        if not cids.intersection(selected):
            continue
        ns = nets.get(ns_addr, {})
        if ns.get('is_initial') or not ns.get('initial_identity_known', True):
            continue
        common = (', '.join((labels[cid] for cid in sorted(cids))), views_value(ns.get('inode')))
        if view == 'interfaces':
            for ip in item.get('addresses') or [{}]:
                cidr = ip['ip'] + '/' + str(ip['prefix']) if ip.get('ip') is not None and ip.get('prefix') is not None else ip.get('ip')
                yield (0, common + (views_text(item['name']), views_value(cidr), views_value(item.get('mac'))))
        elif view == 'conntrack':
            orig = item['original']
            proto = {1: 'ICMP', 6: 'TCP', 17: 'UDP', 58: 'ICMPv6', 132: 'SCTP'}.get(orig['protocol'], f"IPPROTO_{orig['protocol']}")
            if orig['family'] == 10 and proto != 'ICMPv6':
                proto += 'v6'
            nat = '+'.join((name for name, key in [('SNAT', 'snat'), ('DNAT', 'dnat')] if item[key]))
            yield (0, common + (proto, views_endpoint(orig, 'source'), views_endpoint(orig, 'destination'), nat or 'None'))

# Source section: plugin
"""Typed socket/holder records; rendering belongs to the selected CLI renderer."""
import json
import logging
from volatility3.framework import interfaces, renderers
from volatility3.framework.renderers import format_hints
from volatility3.framework.configuration import requirements
from volatility3.framework.symbols.linux import network
from volatility3.framework.symbols import linux
from volatility3.plugins.linux import pslist
from volatility3.plugins.linux._vertical import vertical_grid
vollog = logging.getLogger(__name__)

def plugin_value_or_absent(value, converter=None):
    if value is None:
        return renderers.NotAvailableValue()
    return converter(value) if converter else value

def plugin_address_value(value):
    if value in (None, '', '0x0', 0):
        return renderers.NotAvailableValue()
    return format_hints.Hex(int(value, 16) if isinstance(value, str) else int(value))

def plugin_namespace_inode(nets, address):
    net = nets.get(address)
    if net is None:
        return renderers.NotAvailableValue()
    if net.get('inode') is None:
        return renderers.UnreadableValue()
    return int(net['inode'])

class InspectNetworks(interfaces.plugins.PluginInterface):
    hidden = True  # Exposed through linux.docker.Docker --inspect-networks.
    _required_framework_version = (2, 22, 0)
    _version = (11, 0, 1)

    @classmethod
    def get_requirements(cls):
        return [requirements.ModuleRequirement(name='kernel', description='Linux kernel (validated x86-64 scope)', architectures=['Intel64']), requirements.VersionRequirement(name='net_symbols', component=network.NetSymbols, version=(1, 0, 0)), requirements.VersionRequirement(name='linuxutils', component=linux.LinuxUtilities, version=(2, 0, 0)), requirements.VersionRequirement(name='pslist', component=pslist.PsList, version=(4, 0, 0)), requirements.ListRequirement(name='container', description='Filter by unambiguous observed ID reference(s) or prefix(es); not Docker inventory', element_type=str, optional=True), requirements.ChoiceRequirement(name='view', description='Container evidence view; diagnostics checks all retained collectors', choices=['sockets', 'relations', 'containers', 'interfaces', 'conntrack', 'diagnostics'], default='sockets', optional=True), requirements.BooleanRequirement(name='dump-evidence', description='Save evidence for this view; does not enable extra collectors', default=False, optional=True)]

    def run(self):
        view = self.config.get('view', 'sockets')
        features_by_view = {'sockets': {'sockets'}, 'relations': {'sockets'}, 'containers': {'sockets'}, 'interfaces': {'interfaces'}, 'conntrack': {'conntrack'}, 'diagnostics': {'sockets', 'interfaces', 'conntrack'}}
        if view not in features_by_view:
            raise ValueError('Unsupported view: ' + str(view))
        report = Collector(self.context, self.config['kernel']).collect(features=features_by_view[view])
        known = {cid for task in report['tasks'] if (cid := plugin_container_member_id(task))}
        plugin_select_containers(known, self.config.get('container'))
        if self.config.get('dump-evidence', False):
            with self.open('network_evidence.json') as handle:
                handle.write(json.dumps(report, indent=2, ensure_ascii=False).encode('utf-8'))
        self._log_diagnostics(report)
        if view == 'relations':
            return vertical_grid(plugin_relation_columns(), plugin_relation_rows(report, self.config.get('container')))
        if view != 'sockets':
            return vertical_grid(views_columns(view), views_rows(report, view, self.config.get('container')))
        return vertical_grid(self._columns(), self._generator(report))

    def _log_diagnostics(self, report):
        for error in report.get('errors', []):
            vollog.debug('Parse error stage=%s object=%s type=%s detail=%s affected_holders=%s', error['stage'], error['address'], error['error'], error['detail'], error.get('affected_holders', []))
        for item in report.get('unsupported', []):
            vollog.debug('Unsupported feature=%s object=%s reason=%s', item['feature'], item.get('interface', item.get('namespace', '')), item['reason'])
        for address in report['container_context'].get('unresolved_tasks', []):
            vollog.debug('Conflicting or multiple ID references for task %s; ID not assigned', address)

    @staticmethod
    def _columns():
        return [('Container ID', str), ('NetNS', int), ('Proto', str), ('PID', int), ('Process', str), ('FD', int), ('Local', str), ('Remote', str), ('State', str)]

    def _generator(self, report):
        tasks = {task['pid']: task for task in report['tasks']}
        nets = {net['address']: net for net in report['namespaces']}
        eligible = {pid: plugin_container_member_id(task) for pid, task in tasks.items()}
        known = {cid for cid in eligible.values() if cid}
        selected, labels = plugin_select_containers(known, self.config.get('container'))
        seen = set()
        for sock in report['sockets']:
            for holder in sock['holders']:
                cid = eligible.get(holder['pid'])
                if cid is None or cid not in selected:
                    continue
                task = tasks[holder['pid']]
                key = (cid, task['tgid'], holder['fd'], holder.get('file'), sock['socket'])
                if key in seen:
                    continue
                seen.add(key)
                proto, state = plugin_socket_labels(sock)
                yield (0, (labels[cid], plugin_namespace_inode(nets, sock['namespace']), proto, task['tgid'], task['comm'], holder['fd'], plugin_socket_endpoint(sock, 'source'), plugin_socket_endpoint(sock, 'destination'), state))

def plugin_container_member_id(task):
    return identity_member_id(task)

def plugin_select_containers(known, prefixes):
    selected = set(known)
    if prefixes:
        selected = set()
        for prefix in prefixes:
            matches = {cid for cid in known if cid.startswith(prefix.lower())}
            if len(matches) != 1:
                raise ValueError(f'Container prefix {prefix!r} matched {len(matches)} IDs; use a longer/existing ID')
            selected.update(matches)
    return (selected, identity_display_labels(known))

def plugin_relation_columns():
    return [('Relation', str), ('Container ID', str), ('Object', format_hints.Hex), ('Peer Container', str), ('Peer Object', format_hints.Hex), ('Evidence', str)]

def plugin_relation_rows(report, prefixes=None):
    tasks = []
    for task in report['tasks']:
        cid = plugin_container_member_id(task)
        if cid:
            tasks.append(dict(task, container_candidates=[cid], identity_conflict=False))
    pids = {task['pid'] for task in tasks}
    sockets = [dict(sock, holders=[h for h in sock['holders'] if h['pid'] in pids]) for sock in report['sockets']]
    model = context_build(dict(report, tasks=tasks, sockets=sockets))
    known = {item['id'] for item in model['containers']}
    selected, labels = plugin_select_containers(known, prefixes)
    for item in model['structural_relations']:
        for cid in item['members']:
            if cid in selected:
                yield (0, (item['kind'], labels[cid], plugin_address_value(item['evidence'][0]), renderers.NotApplicableValue(), renderers.NotApplicableValue(), item['confidence']))
    for item in model['relations']:
        for left in item['left_containers'] or [None]:
            for right in item['right_containers'] or [None]:
                if left not in selected and right not in selected:
                    continue
                yield (0, (item['kind'], plugin_value_or_absent(labels.get(left)), plugin_address_value(item['left_socket']), plugin_value_or_absent(labels.get(right)), plugin_address_value(item['right_socket']), item['confidence']))

def plugin_socket_endpoint(sock, side):
    if sock['family'] == 1:
        if side == 'destination':
            return renderers.NotApplicableValue()
        path = sock.get('path')
        return plugin_value_or_absent(path, lambda value: value.encode('unicode_escape').decode('ascii'))
    if sock['family'] not in (2, 10):
        return renderers.NotApplicableValue()
    ip, port = (sock.get(side + '_ip'), sock.get(side + '_port'))
    if ip is None or port is None:
        return renderers.NotAvailableValue()
    return f'[{ip}]:{port}' if sock['family'] == 10 else f'{ip}:{port}'

def plugin_socket_labels(sock):
    family, protocol = (sock['family'], sock.get('protocol_number'))
    if family == 1:
        return ('UNIX', plugin_value_or_absent(sock.get('state_name'), str))
    if family in (2, 10):
        label = {6: 'TCP', 17: 'UDP'}.get(protocol, str(sock.get('protocol', protocol)))
        if family == 10:
            label += 'v6'
        states = {1: 'ESTABLISHED', 2: 'SYN_SENT', 3: 'SYN_RECV', 4: 'FIN_WAIT1', 5: 'FIN_WAIT2', 6: 'TIME_WAIT', 7: 'CLOSE', 8: 'CLOSE_WAIT', 9: 'LAST_ACK', 10: 'LISTEN', 11: 'CLOSING', 12: 'NEW_SYN_RECV'}
        state = sock.get('state')
        return (label, states.get(state, str(state)) if protocol == 6 and state is not None else plugin_value_or_absent(state, str))
    return (f'AF_{family}/PROTO_{protocol}', plugin_value_or_absent(sock.get('state'), str))

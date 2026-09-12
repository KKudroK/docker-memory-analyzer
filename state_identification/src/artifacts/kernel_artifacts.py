"""Kernel execution evidence with explicit partial-read and traversal coverage."""
import hashlib
import socket
import struct
from .evidence import error, redact


def inode_pages(inode, errors=None):
    """Version-aware page-cache traversal, including multi-page folios."""
    if not hasattr(inode, 'get_pages'):
        yield from inode.get_contents()
        return
    errors = errors if errors is not None else []
    def pages():
        if not hasattr(inode, '_context'):
            yield from inode.get_pages()
            return
        if not inode.i_mapping or not inode.i_mapping.nrpages:
            return
        from volatility3.framework.symbols.linux import PageCache
        cache = PageCache(context=inode._context, kernel_module_name='kernel', page_cache=inode.i_mapping.dereference())
        layer = cache.vmlinux.context.layers[cache.vmlinux.layer_name]
        for address in cache._idstorage.get_entries(inode.i_mapping.i_pages):
            if not address:
                continue
            try:
                if not layer.is_valid(address):
                    raise ValueError(f'Invalid cached page address {address:#x}')
                page = cache.vmlinux.object('page', offset=address, absolute=True)
                if not page.is_valid():
                    raise ValueError(f'Invalid cached page {address:#x}')
                yield page
            except Exception as exc:
                errors.append(error('page_cache.entry', exc, address=address))
    seen = set()
    for page in pages():
        if int(page.vol.offset) in seen:
            continue
        seen.add(int(page.vol.offset))
        if int(page.mapping) != int(inode.i_mapping):
            raise ValueError('Page-cache mapping does not match inode')
        index = int(page.index if page.has_member('index') else page.member('__folio_index'))
        count = 1
        flags = int(page.flags.f) if page.flags.has_member('f') else int(page.flags)
        head = page.pageflags_enum.get('PG_head')
        if head is not None and flags & (1 << head):
            folio = page.cast('folio')
            count = int(folio.member('_nr_pages'))
            if not 1 <= count <= 1048576:
                raise ValueError('Invalid folio page count')
        for part in range(count):
            current = page if part == 0 else page._context.object(page.vol.type_name,
                layer_name=page.vol.layer_name, offset=int(page.vol.offset) + part * page.vol.size)
            content = current.get_content()
            if content is None:
                raise ValueError(f'Page content unavailable: index {index + part}')
            yield index + part, content


def cached_content(inode, limit=16 * 1024 * 1024, include_raw=False):
    """Preserve page offsets and holes; never concatenate sparse pages."""
    cache, cache_key = None, None
    context = getattr(inode, '_context', None)
    if context is not None and not include_raw:
        cache = getattr(context, '_forensic_page_cache', None)
        if cache is None:
            cache = {}
            context._forensic_page_cache = cache
        actual = inode.dereference() if hasattr(inode, 'dereference') else inode
        cache_key = (int(actual.vol.offset), limit)
        if cache_key in cache:
            return dict(cache[cache_key])
    size = int(inode.i_size)
    result = {'size': size, 'source': 'kernel.page_cache', 'segments': [], 'errors': [],
              'complete': False, 'limit_bytes': limit}
    recovered = 0
    try:
        for index, content in inode_pages(inode, result['errors']):
            offset = index * 4096
            if offset >= size:
                continue
            content = content[:max(0, min(len(content), size - offset, limit - recovered))]
            if content:
                result['segments'].append({'offset': offset, 'length': len(content),
                    'sha256': hashlib.sha256(content).hexdigest(),
                    'text': redact(content.decode('utf-8', errors='replace'))})
                recovered += len(content)
                if include_raw:
                    result['segments'][-1]['raw'] = bytes(content)
            if recovered >= limit and recovered < size:
                result['errors'].append({'stage': 'page_cache', 'reason': 'content_limit_reached'})
                break
    except Exception as exc:
        result['errors'].append(error('page_cache', exc))
    result['segments'].sort(key=lambda s: s['offset'])
    cursor, holes = 0, []
    for segment in result['segments']:
        if segment['offset'] > cursor:
            holes.append([cursor, segment['offset']])
        cursor = max(cursor, segment['offset'] + segment['length'])
    if cursor < size:
        holes.append([cursor, size])
    result['missing_ranges'] = holes
    result['recovered_bytes'] = recovered
    result['complete'] = not holes and not result['errors']
    if cache is not None:
        cache[cache_key] = dict(result)
    return result


def socket_info(filp, kernel):
    from volatility3.framework.symbols.linux import LinuxUtilities
    inode = filp.get_dentry().d_inode
    alloc = LinuxUtilities.container_of(int(inode), 'socket_alloc', 'vfs_inode', kernel)
    sock = alloc.socket.sk
    family = sock.get_family()
    result = {'family': family, 'socket_address': int(sock), 'inode': int(inode.i_ino)}
    if family in ('AF_INET', 'AF_INET6'):
        inet = sock.dereference().cast('inet_sock')
        result.update({'source_address': inet.get_src_addr(), 'source_port': inet.get_src_port(),
                       'destination_address': inet.get_dst_addr(), 'destination_port': inet.get_dst_port(),
                       'state': inet.get_state(), 'protocol': inet.get_protocol()})
        if family == 'AF_INET6':
            common = sock.member('__sk_common')
            layer = sock._context.layers[sock.vol.layer_name]
            result['source_address'] = socket.inet_ntop(socket.AF_INET6, layer.read(common.skc_v6_rcv_saddr.vol.offset, 16))
            result['destination_address'] = socket.inet_ntop(socket.AF_INET6, layer.read(common.skc_v6_daddr.vol.offset, 16))
    elif family == 'AF_UNIX':
        unix = sock.dereference().cast('unix_sock')
        result.update({'path': unix.get_name(), 'state': unix.get_state(), 'peer_address': int(unix.peer)})
    else:
        result['limitation'] = 'endpoint parser unavailable for this family'
    from .ipc_artifacts import socket_queues
    result['queues'] = socket_queues(sock.dereference(), kernel)
    return result


def parse_kernel_structs(ctx, kernel_symbol_table, task, vmlinux, host_task=None):
    from volatility3.framework.symbols.linux import LinuxUtilities
    from volatility3.framework.objects import utility
    data = {'pid': int(task.pid), 'task_address': int(task.vol.offset), 'source': 'kernel.task_struct',
            'confidence': 'high', 'errors': [], 'files': [], 'nsproxy': {}, 'cred': {}, 'metrics': {}}

    def attempt(stage, fn):
        try:
            return fn()
        except Exception as exc:
            data['errors'].append(error(stage, exc))
            return None

    data['comm'] = attempt('comm', lambda: task.comm.cast('string', max_length=16, errors='replace'))
    data['tgid'] = attempt('tgid', lambda: int(task.tgid))
    data['flags'] = attempt('flags', lambda: int(task.flags))
    data['state'] = attempt('state', lambda: int(task.member('__state') if task.has_member('__state') else task.state))
    data['real_parent'] = attempt('parent', lambda: {'pid': int(task.real_parent.pid),
                                      'address': int(task.real_parent), 'comm': utility.array_to_string(task.real_parent.comm)})
    for field in ('uid', 'euid', 'suid', 'fsuid', 'gid', 'egid', 'sgid', 'fsgid'):
        data['cred'][field] = attempt('cred.' + field, lambda f=field: int(getattr(getattr(task.cred, f), 'val', getattr(task.cred, f))))
    for field in ('cap_inheritable', 'cap_permitted', 'cap_effective', 'cap_bset', 'cap_ambient'):
        def capability(f=field):
            value = getattr(task.cred, f)
            if value.has_member('val'):
                raw = value.val
                try:
                    return hex(int(raw))
                except (TypeError, ValueError):
                    return hex(sum(int(v) << (32 * i) for i, v in enumerate(raw)))
            return str(value)
        data['cred'][field] = attempt('cred.' + field, capability)
    for field in ('start_time', 'start_boottime', 'utime', 'stime', 'min_flt', 'maj_flt', 'nvcsw', 'nivcsw'):
        data['metrics'][field] = attempt('metrics.' + field, lambda f=field: int(getattr(task, f)))
    for field in ('mnt_ns', 'pid_ns_for_children', 'net_ns', 'uts_ns', 'ipc_ns', 'cgroup_ns'):
        data['nsproxy'][field] = attempt('namespace.' + field, lambda f=field: int(getattr(task.nsproxy, f).ns.inum))
    data['nsproxy']['user_ns'] = attempt('namespace.user_ns', lambda: int(task.cred.user_ns.ns.inum))
    for field in ('arg', 'env'):
        def read_range(f=field):
            mm = task.mm
            start, end = int(getattr(mm, f + '_start')), int(getattr(mm, f + '_end'))
            if end < start or end - start > 16 * 1024 * 1024:
                raise ValueError(f'{f} range invalid or exceeds 16 MiB: {start:#x}-{end:#x}')
            layer = ctx.layers[task.add_process_layer()]
            segments, missing = [], []
            address = start
            while address < end:
                length = min(4096 - (address % 4096), end - address)
                try:
                    segments.append((address, layer.read(address, length, pad=False)))
                except Exception as exc:
                    missing.append(error(f'{f}.read', exc, address=address, length=length))
                address += length
            data[f + '_coverage'] = {'start': start, 'end': end, 'errors': missing}
            data['errors'].extend(missing)
            if missing:
                data[f + '_fragments'] = [{'address': a, 'text': b.decode('utf-8', errors='replace')} for a, b in segments]
                return None
            return [v.decode('utf-8', errors='replace') for v in b''.join(b for _, b in segments).split(b'\0') if v]
        data['argv' if field == 'arg' else 'env'] = attempt(field, read_range)
    data['cmdline'] = ' '.join(data.get('argv') or [])
    def filesystem_context():
        from .file_targets import dentry_chain, resolve_file
        fs = {'cwd': dentry_chain(task.fs.pwd.dentry), 'root': dentry_chain(task.fs.root.dentry)}
        if task.mm.exe_file:
            fs['executable'] = {'path': str(LinuxUtilities.path_for_file(ctx, task, task.mm.exe_file)),
                                'target': resolve_file(task.mm.exe_file, vmlinux, ctx, task, host_task)}
        return fs
    data['filesystem_context'] = attempt('filesystem_context', filesystem_context)
    data['kernel_objects'] = {}
    for name in ('mm', 'cred', 'nsproxy', 'files', 'fs'):
        value = attempt('object.' + name, lambda n=name: int(getattr(task, n)))
        if value:
            data['kernel_objects'][name] = value
    data['memory_maps'] = []
    def memory_maps():
        for vma in task.mm.get_vma_iter():
            item = {'start': int(vma.vm_start), 'end': int(vma.vm_end),
                'file_page_offset': int(vma.vm_pgoff), 'protection': vma.get_protection(),
                'path': vma.get_name(ctx, task), 'address': int(vma.vol.offset)}
            data['memory_maps'].append(item)
            try:
                if vma.vm_file and vma.vm_file.f_mapping and vma.vm_file.f_mapping.host:
                    backing = vma.vm_file.f_mapping.host
                    item['backing_inode_address'] = int(backing)
                    if int(backing.i_mode) & 0o170000 == 0o100000:
                        item['content'] = cached_content(backing)
            except Exception as exc:
                item['error'] = error('vma.page_cache', exc)
    attempt('memory_maps', memory_maps)
    # Iterate the full allocated FD table; isolate failures per descriptor.
    def files():
        table = task.files
        count = int(table.get_max_fds())
        if count > 1048576:
            raise ValueError(f'FD capacity exceeds corruption guard: {count}')
        data['fd_capacity'] = count
        fds = utility.array_of_pointers(table.get_fds(), count=count,
                           subtype=kernel_symbol_table + '!file', context=ctx)
        for number, filp in enumerate(fds):
            if not filp:
                continue
            item = {'fd': number, 'address': int(filp), 'errors': []}
            try:
                item['path'] = str(LinuxUtilities.path_for_file(ctx, task, filp))
                item['position'], item['flags'] = int(filp.f_pos), int(filp.f_flags)
                inode = filp.get_dentry().d_inode
                item['inode'], item['mode'] = int(inode.i_ino), int(inode.i_mode)
                item['inode_address'] = int(inode)
                from .file_targets import resolve_file
                item['target'] = resolve_file(filp, vmlinux, ctx, task, host_task)
                from .ipc_artifacts import pipe_info, lock_info
                item['locks'] = lock_info(inode, vmlinux)
                if item['mode'] & 0o170000 == 0o140000:
                    item['socket'] = socket_info(filp, vmlinux)
                elif item['mode'] & 0o170000 == 0o100000:
                    backing = filp.f_mapping.host if filp.f_mapping and filp.f_mapping.host else inode
                    item['content'] = cached_content(backing)
                    item['content']['backing_inode_address'] = int(backing)
                elif item['mode'] & 0o170000 == 0o010000:
                    item['pipe'] = pipe_info(inode)
            except Exception as exc:
                item['errors'].append(error('fd', exc))
            data['files'].append(item)
    attempt('files', files)
    # All interfaces and all IPv4 addresses, including loopback.
    data['interfaces'] = []
    def interfaces():
        netns = task.nsproxy.net_ns
        for device in netns.dev_base_head.to_list(kernel_symbol_table + '!net_device', 'dev_list'):
            item = {'name': utility.array_to_string(device.name), 'index': int(device.ifindex),
                    'address': int(device.vol.offset), 'ipv4': [], 'ipv6': [], 'errors': []}
            data['interfaces'].append(item)
            try:
                if device.ip_ptr:
                    ipdev = device.ip_ptr.dereference().cast('in_device')
                    address, seen = ipdev.ifa_list, set()
                    while address and int(address) not in seen:
                        seen.add(int(address))
                        item['ipv4'].append(socket.inet_ntoa(struct.pack('<I', int(address.ifa_address))))
                        address = address.ifa_next
            except Exception as exc:
                item['error'] = error('interface', exc)
            try:
                if device.ip6_ptr:
                    ipdev = device.ip6_ptr.dereference().cast('inet6_dev')
                    for i, addr in enumerate(ipdev.addr_list.to_list(kernel_symbol_table + '!inet6_ifaddr', 'if_list')):
                        if i >= 65536:
                            raise ValueError('IPv6 interface address traversal limit')
                        raw = ctx.layers[addr.vol.layer_name].read(addr.addr.vol.offset, 16, pad=False)
                        item['ipv6'].append({'address': socket.inet_ntop(socket.AF_INET6, raw),
                            'prefix_len': int(addr.prefix_len), 'scope': int(addr.scope), 'flags': int(addr.flags),
                            'structure_address': int(addr.vol.offset)})
            except Exception as exc:
                item['errors'].append(error('interface.ipv6', exc))
    attempt('interfaces', interfaces)
    return data


def walk_cache(task, ctx, max_nodes=100000, root_dentry=None, root_path='/'):
    """Walk resident dentries without fixture-name filters or a depth cutoff."""
    result = {'files': [], 'errors': [], 'visited': 0, 'complete': False,
              'scope': 'task root dentry tree; mounted filesystems require separate roots'}
    seen, stack = set(), []
    try:
        stack.append((root_dentry if root_dentry is not None else task.fs.root.dentry.dereference(), root_path))
        while stack:
            dentry, path = stack.pop()
            if hasattr(dentry, 'dereference'):
                dentry = dentry.dereference()
            address = int(dentry.vol.offset)
            if address in seen:
                continue
            seen.add(address)
            if len(seen) > max_nodes:
                result['errors'].append({'stage': 'dcache', 'reason': 'node_limit_reached', 'limit': max_nodes})
                break
            try:
                inode = dentry.d_inode
                if inode and int(inode.i_mode) & 0o170000 == 0o100000:
                    result['files'].append({'path': path, 'dentry_address': address, 'inode': int(inode.i_ino),
                                            'content': cached_content(inode)})
            except Exception as exc:
                result['errors'].append(error('dcache.inode', exc, address=address, path=path))
            try:
                for child in dentry.get_subdirs():
                    name = child.d_name.name_as_str()
                    if name not in ('.', '..', ''):
                        stack.append((child, path.rstrip('/') + '/' + name))
            except Exception as exc:
                result['errors'].append(error('dcache.node', exc, address=address, path=path))
        result['visited'] = len(seen)
        result['complete'] = not result['errors']
    except Exception as exc:
        result['errors'].append(error('dcache.root', exc))
    return result


def reconstruct(loader, result):
    tasks = {int(t.pid): t for t in loader._pslist.list_tasks(loader._ctx, loader._kernel.name)}
    parsed_cache, root_cache = {}, {}
    result['timeline'] = [dict(e, temporal_basis='daemon_event_timestamp', confidence='medium') for e in result['events']]
    result['port_forwarding'] = []
    for pid, task in tasks.items():
        try:
            if task.comm.cast('string', max_length=16, errors='replace') != 'docker-proxy':
                continue
            mm = task.mm
            start, end = int(mm.arg_start), int(mm.arg_end)
            if not 0 <= end - start <= 16 * 1024 * 1024:
                raise ValueError('Invalid proxy argument range')
            raw = loader._ctx.layers[task.add_process_layer()].read(start, end - start, pad=False)
            argv = [s.decode('utf-8', errors='replace') for s in raw.split(b'\0') if s]
            mapping = {'source': 'kernel.docker_proxy.argv', 'pid': pid, 'confidence': 'medium'}
            for i, value in enumerate(argv[:-1]):
                if value in ('-host-ip', '-host-port', '-container-ip', '-container-port', '-proto'):
                    mapping[value[1:].replace('-', '_')] = argv[i + 1]
            result['port_forwarding'].append(mapping)
        except Exception as exc:
            result['parsing_errors'].append(error('proxy', exc, pid=pid))
    for container in result['containers']:
        pids = set((container.get('kernel') or {}).get('pids', []))
        container['processes'], container['cached_files'], container['correlations'] = [], [], []
        container['mounts'] = []
        for field, owner in [('Created', container.get('container') or {}),
                             ('StartedAt', container.get('state') or {}), ('FinishedAt', container.get('state') or {})]:
            if owner.get(field):
                result['timeline'].append({'container_id': container['container_id'], 'action': field,
                    'timestamp': owner[field], 'source': 'dockerd.heap', 'confidence': 'medium',
                    'temporal_basis': 'object_timestamp; may describe a historical allocation'})
        seen_mounts = set()
        # PID membership corroborates a daemon PID; never merge solely by namespace.
        for pid in sorted(pids):
            task = tasks.get(pid)
            if task is None:
                container['parsing_errors'].append({'stage': 'task', 'pid': pid, 'reason': 'not_in_task_list'})
                continue
            inferred = next((c for c in (container.get('kernel') or {}).get('correlations', []) if pid in c.get('pids', [])), None)
            container['correlations'].append({'pid': pid, 'source': inferred['source'] if inferred else 'kernel.cgroup',
                                             'confidence': 'medium' if inferred else 'high'})
            if pid not in parsed_cache:
                parsed_cache[pid] = parse_kernel_structs(loader._ctx, loader._kernel.symbol_table_name, task, loader._kernel, tasks.get(1))
            container['processes'].append(parsed_cache[pid])
            try:
                root = int(task.fs.root.dentry)
                if root not in root_cache:
                    root_cache[root] = walk_cache(task, loader._ctx)
                cache = root_cache[root]
                if not any(c['root_address'] == root for c in container.get('dcache_coverage', [])):
                    container.setdefault('dcache_coverage', []).append({'root_address': root, **{k: v for k, v in cache.items() if k != 'files'}})
                    container['cached_files'].extend(cache['files'])
            except Exception as exc:
                container['parsing_errors'].append(error('dcache', exc, pid=pid))
            try:
                from volatility3.plugins.linux.mountinfo import MountInfo
                for mount in task.nsproxy.mnt_ns.get_mount_points():
                    address = int(mount.vol.offset)
                    if address in seen_mounts:
                        continue
                    seen_mounts.add(address)
                    try:
                        info = MountInfo.get_mountinfo(mount, task)
                        if info is None:
                            container['mounts'].append({'address': address, 'error': 'mount_metadata_unavailable'})
                            continue
                        info = dict(info._asdict())
                        info['mnt_id'], info['parent_id'] = int(info['mnt_id']), int(info['parent_id'])
                        container['mounts'].append({'address': address, **info})
                        root_dentry = mount.get_mnt_root()
                        if hasattr(root_dentry, 'dereference'):
                            root_dentry = root_dentry.dereference()
                        root_address = int(root_dentry.vol.offset)
                        if info['mnt_type'] in ('overlay', 'ext4', 'xfs', 'btrfs', 'tmpfs'):
                            cache_key = (root_address, info['path_root'])
                            if cache_key not in root_cache:
                                root_cache[cache_key] = walk_cache(task, loader._ctx, root_dentry=root_dentry, root_path=info['path_root'])
                            cache = root_cache[cache_key]
                            coverage = container.setdefault('dcache_coverage', [])
                            if not any(c['root_address'] == root_address and c.get('mount_path') == info['path_root'] for c in coverage):
                                coverage.append({'root_address': root_address, 'mount_path': info['path_root'], **{k: v for k, v in cache.items() if k != 'files'}})
                                container['cached_files'].extend(cache['files'])
                    except Exception as exc:
                        container['parsing_errors'].append(error('mount', exc, address=address))
            except Exception as exc:
                container['parsing_errors'].append(error('mounts', exc, pid=pid))
    result['reconstruction_limits'] = ['No causal ordering inferred from task lists or namespace membership',
        'Only resident page-cache content is recoverable; missing ranges are explicit',
        'Mounted overlay/ext4/xfs/btrfs/tmpfs roots traversed; pseudo filesystems only have mount metadata',
        'Socket linear and page-fragment payloads attempted; chained frag_list and TCP retransmit tree not decoded',
        'IPC pages must be resident; no inference of bytes already consumed before capture']
    # Keep each recovered payload once while retaining per-file coverage and
    # provenance at every FD/VMA/dcache reference.
    contents = {}
    for container in result['containers']:
        entries = list(container.get('cached_files', []))
        for process in container.get('processes', []):
            entries.extend(process.get('files', []))
            entries.extend(process.get('memory_maps', []))
        for entry in entries:
            content = entry.get('content')
            if not content or not content.get('segments'):
                continue
            identity = repr([(s['offset'], s['length'], s['sha256']) for s in content['segments']]).encode()
            key = hashlib.sha256(identity).hexdigest()
            contents.setdefault(key, {'segments': content['segments'], 'source': content['source']})
            entry['content'] = {k: v for k, v in content.items() if k != 'segments'}
            entry['content']['content_ref'] = key
    result['file_contents'] = contents

"""Layer → owner/structure → artifact, with object-specific field provenance."""
from collections import defaultdict
from .evidence import redact
from .reporting import fields, without_payload, artifact_row


def show(result, reconstruction=False, verbose=False):
    index = defaultdict(list)
    for record in result.get('field_reads', []):
        index[record.get('base_address')].append(record)
    printed = set()

    def origins(address, pid=None, depth=0):
        if not verbose or not address:
            return
        address = hex(address) if isinstance(address, int) else address
        records = [r for r in index.get(address, []) if pid is None or r.get('source_pid') == pid]
        if not records:
            fields({'Origin': f'{address}: no recorded field addresses (not inferred)'}, indent=6)
            return
        if all((r.get('source_pid'), r.get('structure'), r['field_address'], r['field']) in printed for r in records):
            fields({'Origin': f'{address}: field locations already listed above'}, indent=6)
            return
        for r in records:
            key = (r.get('source_pid'), r.get('structure'), r['field_address'], r['field'])
            if key in printed:
                continue
            printed.add(key)
            target = f' -> {r["target_address"]} ({r.get("target_size", "?")} bytes)' if r.get('target_address') else ''
            fields({f'@ {r["structure"].split("!")[-1]}.{r["field"]}':
                    f'{r["field_address"]}, +{r["offset"]}, {r["size"]} bytes{target}'}, indent=6)
            if depth < 6 and r['field_address'] != address:
                if r['field_address'] in index:
                    origins(r['field_address'], pid, depth + 1)

    def section(name):
        print('\n' + '-' * 100)
        print(name)
        print('-' * 100)

    def values(name, obj, keys=None, address=None, pid=None):
        print('\n    ' + name)
        obj = without_payload(obj or {})
        if not verbose and keys is not None:
            obj = {k: obj[k] for k in keys if k in obj}
        fields(redact(obj), indent=6)
        origins(address, pid)

    print('\n' + '=' * 100)
    print(f'{"RECONSTRUCTION" if reconstruction else "DOCKERD HEAP STATE"} / {result["label"]}')
    print('=' * 100)
    fields({'Elapsed (s)': round(result['timing']['total'], 2)})
    section('STATE RESULTS — dockerd heap only')
    for c in result['containers']:
        print(f'  RESULT: {c["status"].upper()} | {c.get("container_name") or "unresolved ID residue"}')
        fields({'Container ID': c['container_id']}, indent=4)
        if not reconstruction:
            from .semantic_artifacts import actions_flow
            state = c.get('state') or {}
            flags = ('Running', 'Paused', 'Restarting', 'OOMKilled', 'RemovalInProgress', 'Dead', 'Removed')
            fields({'Flags': ' | '.join(f'{k}={str(state.get(k)).lower() if state.get(k) is not None else "?"}' for k in flags),
                    'Actions (observed)': actions_flow(c.get('events', [])),
                    'Exit code': state.get('ExitCode')}, indent=4)
            if c.get('status') == 'Restarting':
                print('    Exit code = previous process termination; restart has not completed.')
            print('    Actions are timestamp-ordered heap observations, not a complete audit log.')
    section('USER SPACE — grouped by process')
    owners = defaultdict(list)
    for c in result['containers']:
        selected = next((x for x in c.get('dockerd_candidates', [])
                         if x.get('container') == c.get('container') and x.get('container')), {})
        if c.get('container'):
            owners[('dockerd', selected.get('source_pid'))].append((c, selected))
        for name in ('containerd', 'shim'):
            if c.get(name):
                owners[('containerd-shim' if name == 'shim' else name, c[name].get('source_pid'))].append((c, name))
    for (name, pid), entries in owners.items():
        print(f'\n  {name} | PID {pid if pid is not None else "unrecorded"}')
        for c, owner in entries:
            fields({'Container': c.get('container_name') or c['container_id']}, indent=4)
            if name == 'dockerd':
                values('container.Container', c['container'], ('ID', 'Name', 'ImageID'), owner.get('cbase'), pid)
                for key, pointer, keys in [('state', 'State_ptr', ('Pid', 'ExitCode', 'ErrorMsg')),
                                           ('config', 'Config_ptr', ('Image',)), ('hostconfig', 'HostConfig_ptr', ())]:
                    if verbose or key != 'hostconfig':
                        values('container.' + key, c.get(key), keys, c['container'].get(pointer), pid)
                if verbose:
                    events = {(e.get('action'), e.get('timestamp')): e for e in c.get('events', [])}
                    values('Heap event observations (not current state)',
                           {str(k): {'source': e.get('source'), 'address': e.get('addr')} for k, e in events.items()})
                    for e in events.values():
                        origins(e.get('addr'), pid)
            else:
                obj = dict(c[owner])
                if 'OciSpec' in obj:
                    obj['OciSpec sections (full values in JSON)'] = ', '.join(obj.pop('OciSpec'))
                values(name + ' heap object', obj,
                       ('Image', 'Runtime.Name', 'ProcessArgs', 'ProcessCwd', 'pid', 'Bundle'), obj.get('_address'), pid)
    processes = [(c, p) for c in result['containers'] for p in c.get('processes', [])]
    for c, p in processes:
        print(f'\n  Application PID {p["pid"]} | {c.get("container_name") or c["container_id"]}')
        values('User virtual memory: argv / environ', {'argv': p.get('argv'), **({'env': p.get('env')} if verbose else {})})
        if verbose:
            fields({'Origin path': 'task_struct.mm -> mm_struct.arg_start/arg_end and env_start/env_end'}, indent=6)
            origins(p.get('kernel_objects', {}).get('mm'))
            fields({'arg range': p.get('arg_coverage'), 'env range': p.get('env_coverage')}, indent=6)
    if reconstruction:
        section('KERNEL SPACE — grouped by structure')
        for struct, key, keys in [('task_struct', None, ('pid', 'tgid', 'comm', 'real_parent', 'state')),
                                  ('cred', 'cred', ('uid', 'euid', 'gid', 'egid')),
                                  ('nsproxy', 'nsproxy', ('mnt_ns', 'pid_ns_for_children', 'net_ns'))]:
            print('\n  ' + struct)
            for _, p in processes:
                values(f'PID {p["pid"]}', {k: p.get(k) for k in keys} if key is None else p.get(key),
                       keys, p.get('task_address') if key is None else p.get('kernel_objects', {}).get(key))
        for structure, key in [('vm_area_struct / mm_struct', 'memory_maps'), ('file / inode / address_space', 'files')]:
            print('\n  ' + structure)
            if verbose:
                fields({'Field route': 'task_struct.mm -> vm_area_struct.vm_start/vm_end/vm_pgoff/vm_flags/vm_file'
                        if key == 'memory_maps' else 'task_struct.files -> files_struct.fdt -> fdtable.fd[index] -> file.f_path/f_pos/f_flags/f_mapping; inode.i_ino/i_mode'}, indent=4)
            for _, p in processes:
                fields({f'PID {p["pid"]}': f'{len(p.get(key, []))} records'}, indent=4)
                if not verbose:
                    continue
                for entry in p.get(key, []):
                    label = f'FD {entry.get("fd")}' if key == 'files' else f'{entry.get("start", 0):#x}-{entry.get("end", 0):#x}'
                    artifact_row(label, entry.get('path'),
                                 {k: v for k, v in entry.items() if k not in ('path', 'content', 'socket', 'pipe', 'locks', 'errors')},
                                 entry.get('content'), entry.get('errors'))
                    origins(entry.get('address'))
                    origins(entry.get('inode_address'))
        for title, key in [('sock / inet_sock / unix_sock / sk_buff', 'socket'),
                           ('pipe_inode_info / pipe_buffer', 'pipe'), ('file_lock_context / file_lock', 'locks')]:
            print('\n  ' + title)
            for _, p in processes:
                entries = [f for f in p.get('files', []) if key in f]
                if key == 'socket':
                    observations = [q for f in entries for q in f[key].get('queues', {}).values()]
                    detail = f'{sum(q.get("recovered_bytes", 0) for q in observations)} queue payload bytes'
                elif key == 'pipe':
                    observations = [f[key] for f in entries]
                    detail = f'{sum(q.get("recovered_bytes", 0) for q in observations)} pipe payload bytes'
                else:
                    observations = [f[key] for f in entries]
                    detail = f'{sum(len(q.get("entries", [])) for q in observations)} lock entries'
                fields({f'PID {p["pid"]}': f'{len(entries)} FD references; {detail}; '
                        f'{sum(len(q.get("errors", [])) for q in observations)} errors'}, indent=4)
                for f in entries:
                    obj = f[key]
                    if verbose:
                        values(f'PID {p["pid"]} / FD {f["fd"]}', obj, address=obj.get('address') or obj.get('socket_address'))
                        for b in obj.get('buffers', []) + obj.get('entries', []):
                            origins(b.get('address'))
                        for queue in obj.get('queues', {}).values():
                            origins(queue.get('address'))
                            for packet in queue.get('packets', []):
                                origins(packet.get('address'))
                                origins(packet.get('shared_info_address'))
                                for fragment in packet.get('fragments', []):
                                    origins(fragment.get('address'))
        print('\n  net_device / in_ifaddr / inet6_ifaddr')
        if verbose:
            fields({'Field routes': 'task_struct.nsproxy.net_ns.dev_base_head -> net_device; '
                    'IPv4: ip_ptr.ifa_list -> in_ifaddr.ifa_address/ifa_next; '
                    'IPv6: ip6_ptr.addr_list -> inet6_ifaddr.addr/prefix_len/scope/flags'}, indent=4)
        for _, p in processes:
            for interface in p.get('interfaces', []):
                values(f'PID {p["pid"]} / {interface.get("name")}', interface, ('name', 'ipv4', 'ipv6'), interface.get('address'))
                for addr in interface.get('ipv6', []):
                    origins(addr.get('structure_address'))
        for title, key in [('mount / vfsmount', 'mounts'), ('dentry / inode / page', 'cached_files')]:
            print('\n  ' + title)
            for c in result['containers']:
                fields({c.get('container_name') or c['container_id']: f'{len(c.get(key, []))} records'}, indent=4)
                if verbose:
                    for e in c.get(key, []):
                        artifact_row(title, e.get('path') or e.get('path_root'),
                                     {k: v for k, v in e.items() if k not in ('content', 'fields', 'path')}, e.get('content'))
                        origins(e.get('address') or e.get('dentry_address'))
        section('COLLECTION COVERAGE / LIMITATIONS')
        from .artifact_inventory import inventory
        remaining = set()
        for c in result['containers']:
            counts = inventory(c)
            remaining.update(counts.pop('not_collected'))
            values(c.get('container_name') or c['container_id'], counts,
                   ('processes', 'fd_entries', 'complete_content_fd_entries', 'partial_content_fd_entries',
                    'cached_content_complete', 'cached_content_partial', 'ipc_collection_errors'))
        fields({'Not collected': sorted(remaining), 'Limits': result.get('reconstruction_limits', []),
                'Payload format': 'Redacted text + hashes; not a lossless binary export'})
    fields({'Collection diagnostics': len(result.get('parsing_errors', []))})
    if verbose:
        fields({'Diagnostics': result.get('parsing_errors', []),
                'Provenance semantics': 'Kernel field address resolution is not proof of successful value decoding; errors are retained.',
                'Unprinted candidates / remaining reads': 'Preserved in JSON: field_reads and *_candidates'})

"""Container/process reports with netstat/lsof-style interpreted object links."""
from .reporting import fields, folded, width, clean
from .evidence import redact
from .semantic_artifacts import correlate, actions_flow


def grid(headers, rows, caps):
    rows = [[clean(v) for v in row] for row in rows]
    sizes = [min(cap, max([width(h)] + [width(row[i]) for row in rows])) for i, (h, cap) in enumerate(zip(headers, caps))]
    def line(values):
        print('    ' + '  '.join(v + ' ' * max(0, sizes[i] - width(v)) for i, v in enumerate(values)).rstrip())
    line(headers)
    line(['-' * n for n in sizes])
    for row in rows:
        chunks = [list(folded(v, sizes[i])) for i, v in enumerate(row)]
        for n in range(max(map(len, chunks))):
            line([part[n] if n < len(part) else '' for part in chunks])
    if not rows:
        print('    (none recovered)')
    print()


def endpoint(s, prefix):
    addr, port = s.get(prefix + '_address'), s.get(prefix + '_port')
    if addr is None:
        return '?'
    return f'[{addr}]:{port}' if ':' in addr else f'{addr}:{port}'


def owner_label(owner):
    return f'{owner.get("container_name") or owner["container_id"][:12]} PID {owner["pid"]}/FD {owner["fd"]}'


def show(result, verbose=False):
    # This derives links from collected addresses/endpoints, never external state.
    if any('relationships' not in f for c in result['containers'] for p in c.get('processes', []) for f in p.get('files', [])):
        correlate(result)
    print('\n' + '=' * 110)
    print(f'RECONSTRUCTION / {result["label"]} / {result["timing"]["total"]:.2f}s')
    reads = {}
    for r in result.get('field_reads', []):
        reads.setdefault(r.get('base_address'), []).append(r)
    seen_origins = set()
    def origin(address, names=None, pid=None, depth=0):
        if not verbose or not address:
            return
        key = hex(address) if isinstance(address, int) else address
        for r in reads.get(key, []):
            if (names is None or r['field'] in names) and (pid is None or r.get('source_pid') == pid):
                identity = (r.get('source_pid'), r['structure'], r['field_address'], r['field'])
                if identity in seen_origins:
                    continue
                seen_origins.add(identity)
                fields({f'@ {r["structure"].split("!")[-1]}.{r["field"]}':
                        f'{r["field_address"]} (+{r["offset"]}, {r["size"]} B)'}, indent=6)
                if depth < 5 and r['field_address'] != key:
                    origin(r['field_address'], pid=pid, depth=depth + 1)
    for c in result['containers']:
        print('\n' + '=' * 110)
        print(f'CONTAINER  {c.get("container_name") or "unresolved residue"}')
        print(f'RESULT: {c["status"].upper()}')
        fields({'ID': c['container_id']})
        print('\n  [USER SPACE]')
        state = c.get('state') or {}
        selected = next((x for x in c.get('dockerd_candidates', []) if x.get('container') == c.get('container') and x.get('container')), {})
        print(f'\n    dockerd | PID {selected.get("source_pid", "unrecorded")}')
        fields({'Image': (c.get('config') or {}).get('Image'),
                'Actions (observed)': actions_flow(c.get('events', [])), 'Exit code (heap)': state.get('ExitCode')}, indent=4)
        origin((c.get('container') or {}).get('State_ptr'), pid=selected.get('source_pid'))
        value = c.get('containerd') or {}
        if value:
            print(f'\n    containerd | PID {value.get("source_pid", "unrecorded")}')
            details = {'Runtime': value.get('Runtime.Name'), 'Image reference': value.get('Image'),
                       'Snapshotter': value.get('Snapshotter')}
            if verbose:
                details.update({'Snapshot key': value.get('SnapshotKey'), 'OCI args': value.get('ProcessArgs'),
                                'OCI cwd': value.get('ProcessCwd'), 'OCI user': value.get('ProcessUser')})
            fields(redact(details), indent=6)
            origin(value.get('_address'), pid=value.get('source_pid'))
        image = c.get('containerd_image') or {}
        if image:
            print('\n    containerd Image')
            fields({'Name': image.get('Name'), 'Digest': image.get('Target.Digest'),
                    'Media type': image.get('Target.MediaType'), 'Size': image.get('Target.Size'),
                    'Created': image.get('CreatedAt'), 'Updated': image.get('UpdatedAt')}, indent=6)
            origin(image.get('_address'), pid=image.get('source_pid'))
        value = c.get('shim') or {}
        if value:
            print(f'\n    containerd-shim | PID {value.get("source_pid", "unrecorded")}')
            details = {'Init PID': value.get('pid'), 'Bundle': value.get('Bundle'),
                       'Rootfs': value.get('Rootfs'), 'Exited': value.get('exited')}
            if verbose:
                details.update({'Work directory': value.get('WorkDir'), 'Stdin': value.get('stdio.Stdin'),
                                'Stdout': value.get('stdio.Stdout'), 'Stderr': value.get('stdio.Stderr'),
                                'Terminal': value.get('stdio.Terminal')})
            fields(details, indent=6)
            origin(value.get('_address'), pid=value.get('source_pid'))
        print()
        for p in c.get('processes', []):
            print('  ' + '-' * 104)
            parent = p.get('real_parent') or {}
            print(f'  PROCESS PID {p["pid"]} ({p.get("comm", "?")}) | PPID {parent.get("pid", "?")} ({parent.get("comm", "?")})')
            print('\n  USER SPACE / argv & environment')
            fields(redact({'Command': p.get('cmdline'), **({'Environment': p.get('env')} if verbose else {})}), indent=4)
            origin(p.get('kernel_objects', {}).get('mm'), ('arg_start', 'arg_end', 'env_start', 'env_end'))
            print('\n  KERNEL SPACE / task_struct, cred, nsproxy')
            cred, ns = p.get('cred', {}), p.get('nsproxy', {})
            fields({'Identity': f'uid={cred.get("uid")} euid={cred.get("euid")} gid={cred.get("gid")}',
                    'Namespaces': f'pid={ns.get("pid_ns_for_children")} net={ns.get("net_ns")} mnt={ns.get("mnt_ns")}'}, indent=4)
            fs = p.get('filesystem_context') or {}
            fields({'Executable': fs.get('executable', {}).get('path'),
                    'CWD (filesystem relative)': fs.get('cwd', {}).get('filesystem_relative_path'),
                    'Root (filesystem relative)': fs.get('root', {}).get('filesystem_relative_path')}, indent=4)
            origin(p.get('task_address'), ('pid', 'tgid', 'real_parent', 'cred', 'nsproxy', 'files', 'mm'))
            origin(p.get('kernel_objects', {}).get('cred'))
            origin(p.get('kernel_objects', {}).get('fs'))
            origin(fs.get('executable', {}).get('target', {}).get('file_address'))
            print('\n  INTERFACES / net_device -> IPv4 / IPv6 addresses')
            grid(['IFACE', 'IPv4', 'IPv6'], [[i.get('name'), ', '.join(i.get('ipv4', [])) or '-',
                 ', '.join(f'{a["address"]}/{a["prefix_len"]}' for a in i.get('ipv6', [])) or '-'] for i in p.get('interfaces', [])], [12, 32, 48])
            print('\n  NETWORK / sock -> endpoints -> peer owners')
            rows = []
            for f in p.get('files', []):
                if 'socket' not in f:
                    continue
                s = f['socket']
                rx = s.get('queues', {}).get('sk_receive_queue', {})
                tx = s.get('queues', {}).get('sk_write_queue', {})
                family = s.get('family')
                local = s.get('path') or '(unnamed)' if family == 'AF_UNIX' else endpoint(s, 'source')
                remote = hex(s['peer_address']) if family == 'AF_UNIX' and s.get('peer_address') else '-' if family == 'AF_UNIX' else endpoint(s, 'destination')
                rows.append([f['fd'], s.get('protocol') or family, local, remote, s.get('state'),
                             rx.get('recovered_bytes', '?'), tx.get('recovered_bytes', '?')])
            grid(['FD', 'PROTO', 'LOCAL', 'REMOTE/PEER', 'STATE', 'RX(B)', 'TX(B)'], rows, [4, 9, 25, 25, 13, 8, 8])
            print('    RX/TX = recovered queue bytes, not live netstat counters; unread bytes remain explicit in JSON.')
            peer_rows = []
            for f in p.get('files', []):
                if 'socket' not in f:
                    continue
                links = f.get('relationships', {})
                if links.get('peers'):
                    peer_rows.append([f['fd'], links.get('peer_basis'),
                                      '; '.join(owner_label(x) for x in links['peers'])])
                elif f['socket'].get('peer_address'):
                    peer_rows.append([f['fd'], 'direct pointer',
                                      'owner not among recovered container tasks'])
                origin(f['socket'].get('socket_address'))
            if peer_rows:
                print('\n  CONNECTION LINKS')
                grid(['FD', 'BASIS', 'PEER OWNER'], peer_rows, [4, 48, 52])
            print('\n  OPEN FILES / fdtable -> file -> dentry/mount -> inode -> backing storage')
            rows = []
            for f in p.get('files', []):
                if 'socket' in f:
                    continue
                mode, flags = f.get('mode', 0), f.get('flags', 0)
                kind = 'PIPE/FIFO' if 'pipe' in f else 'REG' if mode & 0o170000 == 0o100000 else 'DEVICE/OTHER'
                content, target = f.get('content', {}), f.get('target', {})
                rows.append([f['fd'], ('R', 'W', 'RW', '?')[flags & 3], kind, f.get('position'),
                             target.get('filesystem', '?'), f.get('path'),
                             f'{content.get("recovered_bytes", 0)}/{content.get("size", "?")}' if content else '-'])
            grid(['FD', 'MODE', 'TYPE', 'POS', 'FS', 'TARGET', 'READ/SIZE'], rows, [4, 4, 12, 8, 12, 48, 18])
            relationship_rows, resolution_rows = [], []
            for f in p.get('files', []):
                if 'socket' in f:
                    continue
                target, links = f.get('target', {}), f.get('relationships', {})
                if target:
                    backing = target.get('backing', {})
                    chain = f'FD {f["fd"]} -> file {f.get("address", 0):#x} -> dentry {target.get("dentry_address", 0):#x}'
                    chain += f' -> mount {target.get("mount_id", "?")} -> inode {target.get("inode_number", "?")}'
                    if backing:
                        chain += f' -> {backing.get("filesystem")} backing inode {backing.get("inode_number")}'
                    if verbose or backing.get('different_from_path_inode'):
                        fields({'Resolution': chain}, indent=4)
                    resolved_path = target.get('filesystem_relative_path')
                    if resolved_path and (verbose or resolved_path != f.get('path')):
                        resolution_rows.append([f['fd'], resolved_path,
                                                f'dev={target.get("device")} inode={target.get("inode_number")}'])
                    if verbose:
                        fields({'Dentry ancestry': ' -> '.join(f'{n["name"] or "/"}@{n["address"]:#x}' for n in target.get('dentry_chain', []))}, indent=4)
                    if target.get('errors'):
                        fields({'Resolution errors': target['errors']}, indent=4)
                if links.get('shared_file_description'):
                    relationship_rows.append([f['fd'], 'shared file',
                                              '; '.join(owner_label(x) for x in links['shared_file_description'])])
                if links.get('pipe_owners'):
                    relationship_rows.append([f['fd'], 'pipe peer',
                        f'{"; ".join(owner_label(x) for x in links["pipe_owners"])}; buffered={f["pipe"].get("recovered_bytes")} B'])
                if links.get('mapped_by'):
                    relationship_rows.append([f['fd'], 'mapped by', '; '.join(
                        f'PID {x["pid"]} {x["start"]:#x}-{x["end"]:#x}' for x in links['mapped_by'])])
                for lock in f.get('locks', {}).get('entries', []):
                    end = 'EOF' if lock.get('end') == 9223372036854775807 else lock.get('end')
                    kind = {0: 'READ/shared', 1: 'WRITE/exclusive', 2: 'UNLOCK'}.get(lock.get('type'), 'unknown')
                    relationship_rows.append([f['fd'], 'lock',
                        f'{lock.get("kind")} {kind}; PID {lock.get("pid")}; range {lock.get("start")}..{end}'])
                origin(f.get('address'))
                origin(f.get('inode_address'))
                origin(target.get('backing', {}).get('inode_address'))
                origin(target.get('path_address'))
                origin(target.get('mount_address'))
                origin(target.get('backing', {}).get('mapping_address'))
                for node in target.get('dentry_chain', []):
                    origin(node.get('address'), ('d_name', 'd_parent', 'd_inode'))
                if f.get('errors'):
                    fields({f'FD {f["fd"]} errors': f['errors']}, indent=4)
            if resolution_rows:
                print('  RESOLVED FILESYSTEM PATHS')
                grid(['FD', 'FILESYSTEM-RELATIVE PATH', 'STORAGE ID'], resolution_rows, [4, 70, 28])
            if relationship_rows:
                print('  FILE / PIPE / MMAP LINKS')
                grid(['FD', 'RELATION', 'TARGET'], relationship_rows, [4, 14, 78])
            print('\n  MEMORY MAPS / vm_area_struct -> backing inode')
            if verbose:
                grid(['RANGE', 'PERM', 'FILE', 'BACKING INODE'],
                     [[f'{v["start"]:#x}-{v["end"]:#x}', v.get('protection'), v.get('path'),
                       hex(v['backing_inode_address']) if v.get('backing_inode_address') else '-'] for v in p.get('memory_maps', [])], [35, 5, 55, 18])
                for v in p.get('memory_maps', []):
                    origin(v.get('address'))
            else:
                fields({'VMAs': len(p.get('memory_maps', [])),
                        'File backed': sum(bool(v.get('backing_inode_address')) for v in p.get('memory_maps', []))}, indent=4)
            print()
        print('  ' + '-' * 104)
        print('  KERNEL SPACE / FILESYSTEM / mount and cache coverage\n')
        grid(['MOUNT', 'FS', 'ROOT', 'OPTIONS'], [[m.get('mnt_id'), m.get('mnt_type'), m.get('path_root'), m.get('mnt_opts')] for m in c.get('mounts', [])], [6, 12, 55, 25])
        cache = c.get('cached_files', [])
        fields({'Cached paths': len(cache), 'Partial/unread cached paths': sum(not f.get('content', {}).get('complete', False) for f in cache)}, indent=4)
    print('\n' + '=' * 110)
    print('SUMMARY')
    print('  TCP endpoint matches are candidates; direct UNIX/pipe/file links use object identity.')
    print('  Full artifacts, payload coverage, errors and source fields remain in JSON. Missing evidence is not absence.')
    fields({'Limits': result.get('reconstruction_limits', []), 'Collection diagnostics': len(result.get('parsing_errors', []))}, indent=2)

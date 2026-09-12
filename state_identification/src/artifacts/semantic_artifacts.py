"""Follow recorded object identities; distinguish direct links from endpoint matches."""
from collections import defaultdict


def actions_flow(events):
    unique = {}
    for e in events:
        time = e.get('time_nano') or (e.get('time_unix') or 0) * 1000000000
        unique.setdefault((time, e.get('action')), e)
    actions = [str(e.get('action') or '?') for _, e in sorted(unique.items(), key=lambda item: (item[0][0], str(item[0][1])))]
    if len(actions) > 16:
        actions = actions[:6] + [f'... ({len(actions) - 12} observations omitted) ...'] + actions[-6:]
    return ' -> '.join(actions) or '(no event evidence)'


def correlate(result):
    """Indexes do not equate same paths/inode numbers across mounts/namespaces."""
    descriptors, sockets, pipes, file_objects = [], defaultdict(list), defaultdict(list), defaultdict(list)
    for c in result['containers']:
        for p in c.get('processes', []):
            for f in p.get('files', []):
                owner = {'container_id': c['container_id'], 'container_name': c.get('container_name'),
                         'pid': p['pid'], 'fd': f['fd'], 'path': f.get('path')}
                descriptors.append((c, p, f, owner))
                if f.get('address'):
                    file_objects[f['address']].append(owner)
                if f.get('socket', {}).get('socket_address'):
                    sockets[f['socket']['socket_address']].append(owner)
                if f.get('pipe', {}).get('address'):
                    pipes[f['pipe']['address']].append(owner)
    for c, p, f, owner in descriptors:
        links = {'source': 'derived_from_recorded_kernel_objects', 'shared_file_description': [], 'peers': []}
        links['shared_file_description'] = [x for x in file_objects.get(f.get('address'), []) if x != owner]
        s = f.get('socket', {})
        if s.get('peer_address'):
            links['peer_basis'] = 'direct unix_sock.peer pointer'
            links['peers'] = sockets.get(s['peer_address'], [])
        elif s.get('family') in ('AF_INET', 'AF_INET6') and s.get('protocol') == 'TCP' and s.get('state') != 'LISTEN':
            links['peer_basis'] = 'reverse TCP endpoint match; candidate, not direct pointer or causal proof'
            for oc, op, of, other in descriptors:
                t = of.get('socket', {})
                if other == owner or t.get('protocol') != 'TCP' or t.get('family') != s['family'] or t.get('state') == 'LISTEN':
                    continue
                keys = ('source_address', 'source_port', 'destination_address', 'destination_port')
                left = tuple(s.get(k) for k in keys)
                right = tuple(t.get(k) for k in (keys[2], keys[3], keys[0], keys[1]))
                if None not in left and left == right:
                    # Loopback endpoints cannot establish cross-netns relationships.
                    if s.get('source_address') in ('127.0.0.1', '::1') and p.get('nsproxy', {}).get('net_ns') != op.get('nsproxy', {}).get('net_ns'):
                        continue
                    links['peers'].append(other)
        if f.get('pipe', {}).get('address'):
            links['pipe_owners'] = [x for x in pipes[f['pipe']['address']] if x != owner]
            links['pipe_basis'] = 'same pipe_inode_info address'
        backing = f.get('content', {}).get('backing_inode_address')
        links['mapped_by'] = [{'pid': op['pid'], 'start': v['start'], 'end': v['end'], 'path': v.get('path')}
            for oc in result['containers'] for op in oc.get('processes', []) for v in op.get('memory_maps', [])
            if backing and v.get('backing_inode_address') == backing]
        f['relationships'] = links
    result['relationship_scope'] = 'Recovered container tasks only; absent owner does not prove absent process. TCP peer matches are candidates.'

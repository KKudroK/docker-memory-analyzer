"""Container membership and namespace context, without endpoint-based ownership.

All IDs in a shared namespace remain visible even when one member is selected.
Initial-net resources cannot be attributed to a host-network container by netns
alone. Those resources are omitted from context views with an explicit diagnostic;
the container's own FD sockets remain available in the sockets view.
"""
from volatility3.framework import renderers
from . import identity


def value(item):
    return renderers.NotAvailableValue() if item is None else item


def text(item):
    return str(item).encode('unicode_escape').decode('ascii')


def endpoint(item, side):
    ip = item.get(side + '_ip')
    if ip is None:
        return renderers.NotAvailableValue()
    port = item.get(side + '_port')
    if port is None:
        return ip
    return f'[{ip}]:{port}' if item.get('family') == 10 else f'{ip}:{port}'


def scope(report, prefixes=None):
    """Map exact net object addresses to own-cgroup members, not to IP owners."""
    members = {}
    known = set()
    for task in report['tasks']:
        cid = identity.member_id(task)
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
    return members, selected


def columns(view):
    common = [('Container IDs', str), ('NetNS', int)]
    schemas = {
        'containers': [('Container ID', str), ('Tasks', int), ('Processes', int),
                       ('Sockets', int), ('NetNS', str)],
        'interfaces': common + [('Interface', str), ('Address', str), ('MAC', str)],
        'conntrack': common + [('Proto', str), ('Source', str), ('Destination', str), ('NAT', str)],
        'diagnostics': [('Kind', str), ('Stage', str), ('Object', str), ('Detail', str)]}
    return schemas[view]


def rows(report, view, prefixes=None):
    members, selected = scope(report, prefixes)
    nets = {ns['address']: ns for ns in report['namespaces']}
    # Include unselected namespace members when choosing collision-free labels.
    known = {cid for task in report['tasks'] if (cid := identity.member_id(task))}
    labels = identity.display_labels(known)
    if view == 'diagnostics':
        for error in report.get('errors', []):
            yield 0, ('error', text(error['stage']), str(error['address']),
                      text(error['error'] + ': ' + error['detail']))
        for item in report.get('unsupported', []):
            yield 0, ('unsupported', text(item['feature']),
                      str(item.get('namespace', item.get('interface', ''))), text(item['reason']))
        for task in report['tasks']:
            if task.get('container_candidates') and not identity.member_id(task):
                yield 0, ('unresolved', 'identity', task['address'],
                          'No complete, unique, nonconflicting own-cgroup membership')
        return
    if view == 'containers':
        for cid in sorted(selected):
            tasks = [t for t in report['tasks'] if identity.member_id(t) == cid]
            pids = {t['pid'] for t in tasks}
            sockets = {s['socket'] for s in report['sockets'] if any(h['pid'] in pids for h in s['holders'])}
            namespaces = {t['namespace'] for t in tasks if t.get('namespace')}
            inodes = {str(nets.get(ns, {}).get('inode') or '?') for ns in namespaces}
            yield 0, (labels[cid], len(tasks), len({t['tgid'] for t in tasks}), len(sockets),
                      ', '.join(sorted(inodes)))
        return
    for item in report.get(view, []):
        ns_addr = item.get('namespace')
        cids = members.get(ns_addr, set())
        if not cids.intersection(selected):
            continue
        ns = nets.get(ns_addr, {})
        if ns.get('is_initial') or not ns.get('initial_identity_known', True):
            continue
        common = (', '.join(labels[cid] for cid in sorted(cids)), value(ns.get('inode')))
        if view == 'interfaces':
            for ip in item.get('addresses') or [{}]:
                cidr = (ip['ip'] + '/' + str(ip['prefix']) if ip.get('ip') is not None and
                        ip.get('prefix') is not None else ip.get('ip'))
                yield 0, common + (text(item['name']), value(cidr), value(item.get('mac')))
        elif view == 'conntrack':
            orig = item['original']
            proto = {1: 'ICMP', 6: 'TCP', 17: 'UDP', 58: 'ICMPv6',
                     132: 'SCTP'}.get(orig['protocol'], f"IPPROTO_{orig['protocol']}")
            if orig['family'] == 10 and proto != 'ICMPv6':
                proto += 'v6'
            # Summarize explicit status flags; full reply tuples remain in evidence.
            nat = '+'.join(name for name, key in [('SNAT', 'snat'), ('DNAT', 'dnat')] if item[key])
            yield 0, common + (proto, endpoint(orig, 'source'), endpoint(orig, 'destination'), nat or 'None')

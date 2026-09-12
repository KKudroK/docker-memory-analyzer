"""One ip-address/netstat-style table with independent interface and socket rows."""


def endpoint(ip, port):
    if not ip:
        return '-'
    return f'[{ip}]:{port}' if ':' in ip else f'{ip}:{port}'


def table(report, include_host=False):
    columns = ['Container', 'PID', 'NetNS', 'Interface', 'MAC', 'Address',
               'Host link', 'Protocol', 'Local', 'Remote', 'State']
    nets = {n['address']: n for n in report['namespaces']}
    devs = {d['address']: d for d in report['interfaces']}
    tasks = {t['pid']: t for t in report['tasks']}
    sockets = {s['socket']: s for s in report['sockets']}
    selected = {a for a, n in nets.items() if include_host or n['container_candidates']}

    def ids(values):
        return ','.join(c[:12] for c in sorted(set(values))) or '-'

    def name(address):
        return devs.get(address, {}).get('name', address or '-')

    def hostlink(device):
        links = []
        for edge in report['links']:
            if edge['source'] != device or edge['kind'] not in ('veth_peer', 'veth_peer_candidate'):
                continue
            bridges = [b for b in report['links'] if b['source'] == edge['target'] and b['kind'] == 'bridge_port']
            label = name(edge['target'])
            if bridges:
                label += ' -> ' + ','.join(name(b['target']) for b in bridges)
            if edge['kind'].endswith('candidate'):
                label += ' [candidate]'
            links.append(label)
        return '; '.join(links) or '-'

    states = {1: 'ESTABLISHED', 2: 'SYN_SENT', 3: 'SYN_RECV', 4: 'FIN_WAIT1',
              5: 'FIN_WAIT2', 6: 'TIME_WAIT', 7: 'CLOSE', 8: 'CLOSE_WAIT',
              9: 'LAST_ACK', 10: 'LISTEN', 11: 'CLOSING'}
    rows = []
    for ns in sorted(selected, key=lambda a: (str(nets[a].get('inode')), a)):
        net = nets[ns]
        inode = net.get('inode')
        pids = sorted({tasks[p]['tgid'] for p in net['pids'] if p in tasks})
        for device in sorted((d for d in devs.values() if d['namespace'] == ns), key=lambda d: (d['ifindex'], d['address'])):
            addresses = sorted({a['cidr'] for a in device['addresses']})
            for address in addresses or ['-']:
                rows.append([ids(net['container_candidates']), ','.join(map(str, pids)) or '-',
                             inode, device['name'], device.get('mac'), address,
                             hostlink(device['address']), '-', '-', '-', '-'])
        for sock in sorted((s for s in sockets.values() if s['namespace'] == ns),
                           key=lambda s: (s['family'], s.get('protocol', ''), s.get('source_port', 0), s['socket'])):
            if sock['family'] not in (1, 2, 10):
                continue
            protocol = sock.get('protocol', 'UNIX')
            local = endpoint(sock.get('source_ip'), sock.get('source_port'))
            remote = endpoint(sock.get('destination_ip'), sock.get('destination_port'))
            state = states.get(sock['state'], str(sock['state']))
            if sock['family'] == 1:
                local = sock.get('path') or '(unnamed)'
                peer = sock.get('peer', '0x0')
                remote = '-' if peer == '0x0' else sockets.get(peer, {}).get('path') or '(unresolved peer)'
                if sock.get('socket_type') == 2:
                    state = 'UNCONN' if sock['state'] == 7 else state
            elif protocol == 'UDP' and sock['state'] == 7:
                state = 'UNCONN'
            # CID is holder identity, not every container sharing the socket namespace.
            owners = {(tasks.get(h['pid'], {}).get('tgid', h['pid']),
                       ids(tasks.get(h['pid'], {}).get('container_candidates', [])))
                      for h in sock['holders']}
            for pid, container in sorted(owners):
                rows.append([container, pid, inode, '-', '-', '-', '-',
                             protocol, local, remote, state])
    return [(c, str) for c in columns], [
        tuple('-' if v is None else str(v).replace('\n', '\\n').replace('\t', '\\t') for v in row)
        for row in rows
    ]

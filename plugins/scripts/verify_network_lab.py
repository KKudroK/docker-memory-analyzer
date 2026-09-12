"""Semantic assertions for S01_single_rich; does not modify evidence or dump."""
import argparse
import json
from pathlib import Path


def verify(report):
    checks = []

    def check(name, condition):
        checks.append({'check': name, 'passed': bool(condition)})

    check('no parsing errors in supported paths', not report['errors'])
    eth = [d for d in report['interfaces'] if d['name'] == 'eth0' and d['container_candidates']]
    check('one identified eth0', len(eth) == 1)
    if len(eth) != 1:
        return checks
    eth = eth[0]
    ns = eth['namespace']
    check('namespace inode', eth['namespace_inode'] == 4026532729)
    check('MTU', eth['mtu'] == 1450)
    check('all five eth0 addresses', {a['cidr'] for a in eth['addresses']} == {
        '172.30.10.10/16', '172.30.20.20/16', 'fd42:30::10/64', 'fd42:30::20/64', 'fe80::42:acff:fe1e:a/64'})
    check('actual IPv4 prefix', {a['subnet'] for a in eth['addresses'] if a['family'] == 4} == {'172.30.0.0/16'})
    check('container threads retained', {3925, 4001, 4002} <= set(eth['pids']))
    check('initial namespace distinguished', any(n['is_initial'] and n['address'] != ns for n in report['namespaces']))
    check('loopback retained despite MAC', any(d['name'] == 'lo' and d['namespace'] == ns and d['container_candidates'] for d in report['interfaces']))
    peers = [e for e in report['links'] if e['source'] == eth['address'] and e['kind'] in ('veth_peer', 'veth_peer_candidate')]
    check('peer relationship retained', bool(peers))
    if peers:
        check('host peer joins bridge', any(e['kind'] == 'bridge_port' and e['source'] == peers[0]['target'] for e in report['links']))
    sockets = [s for s in report['sockets'] if any(h['pid'] == 3925 for h in s['holders'])]
    check('nine workload sockets, no thread duplicates', len(sockets) == 9)
    for port, family, protocol in ((18080, 2, 'TCP'), (18081, 10, 'TCP'), (53535, 2, 'UDP'), (53536, 10, 'UDP')):
        check(f'{protocol}/{family}/{port}', any(s.get('source_port') == port and s['family'] == family and s['protocol'] == protocol for s in sockets))
    check('four established loopback endpoints', len([s for s in sockets if s['state'] == 1]) == 4)
    check('UNIX fd 3 and exact path', any(s.get('path') == '/tmp/inspect_networks.sock' and {'pid': 3925, 'fd': 3, 'file': s['holders'][0]['file']} in s['holders'] for s in sockets))
    check('DNS socket namespace differs from holder namespace', any(s['namespace'] == ns and s.get('source_ip') == '127.0.0.11' and any(h['pid'] == 1935 for h in s['holders']) for s in report['sockets']))
    routes = [r for r in report['routes'] if r['namespace'] == ns]
    for destination, gateway in (('0.0.0.0/0', '172.30.0.1'), ('::/0', 'fd42:30::1'), ('198.51.100.0/24', '172.30.0.1')):
        check('route ' + destination, any(r['destination'] == destination and any(n['gateway'] == gateway for n in r['nexthops']) for r in routes))
    check('ARP and NDP retained', {2, 10} <= {n['family'] for n in report['neighbors']})
    check('explicit multicast membership', any(m['namespace'] == ns and m['group'] == '239.42.42.42' for m in report['multicast']))
    check('policy rules retained', any(r['namespace'] == ns and r['table'] == 254 for r in report['rules']))
    check('bridge FDB retained', bool(report['bridge_fdb']))
    check('conntrack retained', bool(report['conntrack']))
    check('one proxy configuration, not one per thread', len(report['published_ports']) == 1 and report['published_ports'][0]['mapping']['host-port'] == '18080')
    check('unsupported coverage explicit', bool(report['unsupported']))
    for key in ('tasks', 'namespaces', 'interfaces', 'links', 'sockets', 'routes', 'rules', 'neighbors', 'conntrack', 'multicast', 'bridge_fdb'):
        check('summary ' + key, report['summary'][key] == len(report[key]))
    return checks


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('evidence', type=Path)
    args = parser.parse_args()
    checks = verify(json.loads(args.evidence.read_text(encoding='utf-8')))
    print(json.dumps({'passed': sum(c['passed'] for c in checks), 'total': len(checks), 'checks': checks}, indent=2))
    raise SystemExit(0 if all(c['passed'] for c in checks) else 1)

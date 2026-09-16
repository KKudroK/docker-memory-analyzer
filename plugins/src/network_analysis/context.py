"""Observed ID references, FD holders and direct kernel object relations only."""
from . import identity


def task_ids(task):
    cid = identity.member_id(task)
    return [cid] if cid else []


def build(report):
    tasks = {t['pid']: t for t in report['tasks']}
    nets = {n['address']: n for n in report['namespaces']}
    sockets = {s['socket']: s for s in report['sockets']}
    contexts = {}
    for task in report['tasks']:
        for cid in task_ids(task):
            item = contexts.setdefault(cid, {'id': cid, 'pids': [], 'tasks': [], 'namespaces': [],
                                            'cgroup_paths': [], 'identity_sources': [], 'socket_ids': [],
                                            'generation': [], 'warnings': []})
            item['pids'].append(task['tgid'])
            item['tasks'].append(task['address'])
            if task.get('namespace'):item['namespaces'].append(task['namespace'])
            item['cgroup_paths'].extend(task.get('cgroup_paths', []))
            item['identity_sources'].append(task.get('identity_evidence', 'unknown'))
            if task['pid'] == task['tgid']:
                item['generation'].append({k: task.get(k) for k in ('pid','address','comm','start_time','start_boottime','namespaces')})
    for item in contexts.values():
        for key in ('pids','tasks','namespaces','cgroup_paths','identity_sources'):
            item[key] = sorted(set(item[key]))
        if any(nets.get(n, {}).get('is_initial') for n in item['namespaces']):
            item['warnings'].append('host_network_namespace_shared')
        if len(item['namespaces']) > 1:
            item['warnings'].append('tasks_span_multiple_network_namespaces')
    ownership = {}
    for sid, sock in sockets.items():
        holders = []
        for h in sock['holders']:
            t = tasks.get(h['pid'], {})
            holders.append(dict(h, tgid=t.get('tgid', h['pid']), container_ids=task_ids(t),
                                task_namespace=t.get('namespace'), identity_conflict=t.get('identity_conflict', False)))
        cids = sorted({cid for h in holders for cid in h['container_ids']})
        ownership[sid] = {'container_ids': cids, 'holders': holders}
        for cid in cids:
            contexts[cid]['socket_ids'].append(sid)
            if any(h['container_ids'] == [cid] and h['task_namespace'] != sock['namespace'] for h in holders):
                contexts[cid]['warnings'].append('socket_namespace_differs_from_holder')
    relations = []
    def relation(kind, left, right, evidence, confidence, limitation):
        a, b = ownership[left], ownership[right]
        if not a['container_ids'] and not b['container_ids']:return
        relations.append({'kind':kind,'left_socket':left,'right_socket':right,
                          'left_containers':a['container_ids'],'right_containers':b['container_ids'],
                          'left_holders':a['holders'],'right_holders':b['holders'],
                          'evidence':evidence,'confidence':confidence,'limitation':limitation})
    for sid, sock in sockets.items():
        peer = sock.get('peer')
        if (sock['family'] == 1 and peer in sockets and sid < peer and
                sockets[peer]['family'] == 1 and sockets[peer].get('peer') == sid):
            relation('unix_peer',sid,peer,[sid,peer],'reciprocal_kernel_peer',
                     'current peer relation; not a history of messages or their contents')
    structural=[]
    for address, ns in nets.items():
        if address in (None, '', '0x0', 0):
            continue
        members=sorted(cid for cid,item in contexts.items() if address in item['namespaces'])
        if len(members)>1:
            structural.append({'kind':'shared_netns','members':members,'evidence':[address],
                               'confidence':'same_namespace_object'})
    for sid, owner in ownership.items():
        if len(owner['container_ids'])>1:
            structural.append({'kind':'shared_socket','members':owner['container_ids'],
                               'evidence':[sid],'confidence':'same_fd_reachable_socket'})
    for item in contexts.values():
        item['warnings']=sorted(set(item['warnings']))
        item['socket_ids']=sorted(set(item['socket_ids']))
    return {'containers':[contexts[k] for k in sorted(contexts)],'socket_ownership':ownership,
            'relations':relations,'structural_relations':structural,
            'unresolved_tasks':[t['address'] for t in report['tasks'] if t.get('container_candidates') and not task_ids(t)],
            'scope':'complete own-cgroup runtime ID references; not authenticated runtime inventory',
            'relation_policy':'only reciprocal UNIX peer or shared kernel object; no endpoint correlation'}

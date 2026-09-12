"""Runtime argv evidence supplements cgroups without treating ancestry as proof."""
import re


def collect(c, records):
    by_address = {r['address']: r for r in records}
    shims, published = {}, []
    for task in c.tasks:
        record = by_address.get(hex(task.vol.offset))
        if record is None:
            continue
        def parent():
            return hex(int(task.real_parent))
        record['parent'] = c.read('task.parent', task, parent)
        comm = record['comm']
        if record['pid'] != record['tgid']:
            continue
        if not (comm.startswith('containerd-shim') or comm == 'docker-proxy'):
            continue
        if c.identity_mode == 'cgroup' and comm.startswith('containerd-shim'):
            continue
        def argv():
            if not task.mm:
                return []
            start, end = int(task.mm.arg_start), int(task.mm.arg_end)
            if not 0 <= end - start <= 65536:
                raise ValueError('runtime argv length out of bounds')
            name = task.add_process_layer()
            if name is None:
                raise ValueError('runtime process layer unavailable')
            return c.context.layers[name].read(start, end - start).decode('utf-8', errors='replace').split('\0')
        args = c.read('identity.runtime_argv', task,
                      lambda: c.measure('identity.shim_argv', argv), [])
        if comm.startswith('containerd-shim'):
            ids = [args[i + 1] for i, arg in enumerate(args[:-1]) if arg in ('-id', '--id') and re.fullmatch('[0-9a-f]{64}', args[i + 1])]
            if ids:
                shims[record['address']] = sorted(set(ids))
                record['shim_container_candidates'] = shims[record['address']]
        else:
            # Whitelist network flags only: never dump entire argv or environment.
            flags = ('-host-ip', '-host-port', '-container-ip', '-container-port', '-proto')
            values = {arg[1:]: args[i + 1] for i, arg in enumerate(args[:-1]) if arg in flags}
            if values:
                published.append({'pid': record['pid'], 'task': record['address'], 'namespace': record.get('namespace'),
                                  'mapping': values, 'source': 'docker-proxy argv', 'confidence': 'runtime_configuration',
                                  'limitation': 'not proof of a matching NAT rule or successful forwarding'})
    if c.identity_mode == 'cgroup':
        for ns in c.nets.values():
            ns['container_candidates'] = sorted({cid for r in records if r.get('namespace') == ns['address'] for cid in r['container_candidates']})
        return published
    for record in records:
        node, seen = record, set()
        while node.get('parent') in by_address:
            address = node['parent']
            if address in seen or len(seen) >= c.limit:
                c.issue('identity.ancestry', record['address'], ValueError('parent cycle/limit'))
                break
            seen.add(address)
            c.count('objects_visited', 'task_ancestry')
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
    return published

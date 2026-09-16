"""Runtime argv evidence supplements cgroups without treating ancestry as proof."""
import re


def display_labels(known):
    """Use at least twelve ID characters, extending prefixes until unique."""
    labels = {}
    for cid in known:
        length = 12
        while any(other != cid and other[:length] == cid[:length] for other in known):
            length += 1
        labels[cid] = cid[:length]
    return labels


def cgroup_candidates(paths):
    """Recognize runtime naming grammars, not arbitrary 64-hex path components.

    Names remain runtime-path evidence, not proof of a reachable Docker store.
    Preserve raw paths separately so nonstandard names remain inspectable.
    """
    result = set()
    for path in paths:
        parts = path.strip('/').split('/')
        for index, part in enumerate(parts):
            scope = re.fullmatch(r'(?:docker|cri-containerd|crio|libpod)-([0-9a-f]{64})\.scope', part)
            if scope:
                result.add(scope.group(1))
            elif index and parts[index - 1] == 'docker' and re.fullmatch(r'[0-9a-f]{64}', part):
                result.add(part)
    return sorted(result)


def member_id(task):
    """One complete own-cgroup ID; ancestry and namespace never grant membership."""
    ids = cgroup_candidates(task.get('cgroup_paths', []))
    if (len(ids) != 1 or task.get('identity_conflict') or
            task.get('cgroup_complete') is False or task.get('pid_conflict')):
        return None
    assigned = sorted(set(task.get('container_candidates', [])))
    if assigned and assigned != ids:
        return None
    return ids[0]


def parent_address(task):
    return hex(int(task.real_parent))


def runtime_argv(c, task):
    if not task.mm:
        return []
    start, end = int(task.mm.arg_start), int(task.mm.arg_end)
    if not 0 <= end - start <= 65536:
        raise ValueError('runtime argv length out of bounds')
    name = task.add_process_layer()
    if name is None:
        raise ValueError('runtime process layer unavailable')
    return c.context.layers[name].read(start, end - start).decode('utf-8', errors='replace').split('\0')


def collect(c, records):
    by_address = {r['address']: r for r in records}
    shims = {}
    for task in c.tasks:
        record = by_address.get(hex(task.vol.offset))
        if record is None:
            continue
        record['parent'] = c.read('task.parent', task, parent_address, args=(task,))
        comm = record['comm']
        if record['pid'] != record['tgid']:
            continue
        if not comm.startswith('containerd-shim'):
            continue
        args = c.read('identity.runtime_argv', task, runtime_argv, [], args=(c, task))
        ids = [args[i + 1] for i, arg in enumerate(args[:-1])
               if arg in ('-id', '--id') and re.fullmatch('[0-9a-f]{64}', args[i + 1])]
        if ids:
            shims[record['address']] = sorted(set(ids))
            record['shim_container_candidates'] = shims[record['address']]
    for record in records:
        node, seen = record, set()
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

"""Symbol-driven IPv4 trie and IPv6 FIB traversal.

Hash-size adapters follow include/net/{ip_fib,ip6_fib}.h: presence of the
CONFIG_*_MULTIPLE_TABLES-only rules_ops member selects the 256-bucket layout.
"""
import ipaddress
import socket
from volatility3.framework.objects import utility


def nexthop(c, common):
    family = int(common.nhc_gw_family)
    gateway = None
    if family in (2, 10):
        gateway = socket.inet_ntop(socket.AF_INET if family == 2 else socket.AF_INET6, c.layer.read(common.nhc_gw.vol.offset, 4 if family == 2 else 16))
    return {'interface': hex(int(common.nhc_dev)), 'ifindex': int(common.nhc_oif),
            'gateway': gateway, 'gateway_family': family, 'flags': int(common.nhc_flags)}


def ipv4(c, ns, table, rows):
    # tb_data is a pointer in current kernels; older ISFs describe inline data.
    from volatility3.framework import objects
    data = int(table.tb_data) if isinstance(table.tb_data, objects.Pointer) else table.tb_data.vol.offset
    root = c.obj('trie', data).kv[0]
    pending, seen = [root], set()
    while pending:
        node = pending.pop()
        if node.vol.offset in seen or len(seen) >= c.limit:
            raise ValueError('IPv4 trie cycle or limit')
        seen.add(node.vol.offset)
        bits, pos = int(node.bits), int(node.pos)
        if bits or pos:
            count = 1 if pos == 32 else 1 << bits
            if count > c.limit:
                raise ValueError('IPv4 trie fanout limit')
            children = utility.array_of_pointers(node.tnode, count, c.kernel.symbol_table_name + '!key_vector', c.context)
            pending.extend(p.dereference() for p in children if p)
            continue
        for alias in c.hlist(node.leaf, 'fib_alias', 'fa_list'):
            def entry():
                info = alias.fa_info.dereference()
                prefix = 32 - int(alias.fa_slen)
                cidr = str(ipaddress.ip_network((int(node.key), prefix), strict=False))
                row = {'address': hex(alias.vol.offset), 'namespace': ns['address'], 'family': 4,
                       'table': int(alias.tb_id) if alias.has_member('tb_id') else int(table.tb_id),
                       'destination': cidr, 'priority': int(info.fib_priority), 'protocol': int(info.fib_protocol),
                       'scope': int(info.fib_scope), 'type': int(alias.fa_type), 'nexthops': [],
                       'source': 'net.ipv4.fib_main/fib_default -> trie -> fib_alias -> fib_info', 'confidence': 'direct_pointer'}
                rows.append(row)
                if info.has_member('nh') and info.nh:
                    row['unresolved_nexthop_object'] = hex(int(info.nh))
                else:
                    for nh in c.array(info.fib_nh.vol.offset, 'fib_nh', int(info.fib_nhs)):
                        row['nexthops'].append(nexthop(c, nh.nh_common))
            c.read('route.ipv4.entry', alias, entry)


def ipv6(c, ns, table, rows):
    pending, seen, infos = [table.tb6_root], set(), set()
    while pending:
        node = pending.pop()
        if node.vol.offset in seen or len(seen) >= c.limit:
            raise ValueError('IPv6 tree cycle or limit')
        seen.add(node.vol.offset)
        for field in ('left', 'right', 'subtree'):
            if node.has_member(field) and node.member(field):
                pending.append(node.member(field).dereference())
        ptr, chain = node.leaf, set()
        while ptr:
            if int(ptr) in chain or len(chain) >= c.limit:
                raise ValueError('IPv6 route chain cycle or limit')
            chain.add(int(ptr))
            info = ptr.dereference()
            ptr = info.fib6_next
            if info.vol.offset in infos:
                continue  # FIB internal nodes may reference the same leaf.
            infos.add(info.vol.offset)
            if int(info.fib6_table) != table.vol.offset:
                continue  # per-net null route sentinel
            def entry():
                ip = socket.inet_ntop(socket.AF_INET6, c.layer.read(info.fib6_dst.addr.vol.offset, 16))
                row = {'address': hex(info.vol.offset), 'namespace': ns['address'], 'family': 6,
                       'table': int(table.tb6_id), 'destination': str(ipaddress.ip_network(f'{ip}/{int(info.fib6_dst.plen)}', strict=False)),
                       'priority': int(info.fib6_metric), 'protocol': int(info.fib6_protocol), 'flags': int(info.fib6_flags),
                       'nexthops': [], 'source': 'net.ipv6.fib6_*_tbl -> fib6_node -> fib6_info', 'confidence': 'direct_pointer'}
                rows.append(row)
                if info.has_member('nh') and info.nh:
                    row['unresolved_nexthop_object'] = hex(int(info.nh))
                else:
                    nh = c.obj('fib6_nh', info.fib6_nh.vol.offset)
                    row['nexthops'].append(nexthop(c, nh.nh_common))
            c.read('route.ipv6.entry', info, entry)


def collect(c, unsupported):
    rows = []
    unsupported.append({'feature': 'shared_nexthop', 'reason': 'nh object/group routes retain the pointer; shared nexthop groups not expanded'})
    for ns in c.nets.values():
        net, seen = ns['object'], set()
        for family in (4, 6):
            def hashed_tables():
                block = net.ipv4 if family == 4 else net.ipv6
                rules_member = 'rules_ops' if family == 4 else 'fib6_rules_ops'
                count = 256 if block.has_member(rules_member) else (2 if family == 4 else 1)
                typename, member = ('fib_table', 'tb_hlist') if family == 4 else ('fib6_table', 'tb6_hlist')
                for head in c.array(int(block.fib_table_hash), 'hlist_head', count):
                    def bucket():
                        for table in c.hlist(head, typename, member):
                            if table.vol.offset in seen:
                                continue
                            seen.add(table.vol.offset)
                            c.read('route.table', table, lambda: (ipv4 if family == 4 else ipv6)(c, ns, table, rows))
                    c.read('route.table_bucket', head, bucket)
            c.read('route.table_hash', net, hashed_tables)
        for family, field in ((4, 'fib_main'), (4, 'fib_default'), (6, 'fib6_main_tbl'), (6, 'fib6_local_tbl')):
            def table():
                block = net.ipv4 if family == 4 else net.ipv6
                if not block.has_member(field):
                    unsupported.append({'feature': 'route.' + field, 'namespace': ns['address'], 'reason': 'member absent'})
                    return
                ptr = block.member(field)
                if ptr and int(ptr) not in seen:
                    seen.add(int(ptr))
                    (ipv4 if family == 4 else ipv6)(c, ns, ptr.dereference(), rows)
            c.read('route.' + field, net, table)
    return list({(r['namespace'], r['address']): r for r in rows}.values())


def rules(c):
    rows = []
    for ns in c.nets.values():
        for family, field in ((4, 'rules_ops'), (6, 'fib6_rules_ops')):
            def scan():
                block = ns['object'].ipv4 if family == 4 else ns['object'].ipv6
                if not block.has_member(field) or not block.member(field):
                    return
                for rule in c.walk(block.member(field).rules_list, 'fib_rule', 'list'):
                    row = {'address': hex(rule.vol.offset), 'namespace': ns['address'], 'family': family,
                           'source': 'net -> fib_rules_ops.rules_list -> fib_rule', 'confidence': 'direct_pointer',
                           'limitation': 'inventory, not a policy routing evaluator'}
                    rows.append(row)
                    for name in ('pref', 'table', 'action', 'flags', 'mark', 'mark_mask', 'iifindex', 'oifindex', 'l3mdev', 'ip_proto', 'suppress_prefixlen'):
                        if rule.has_member(name):
                            row[name] = c.read('rule.' + name, rule, lambda: int(rule.member(name)))
                    for name in ('iifname', 'oifname'):
                        row[name] = utility.array_to_string(rule.member(name))
                    def prefix_fields():
                        typename = 'fib4_rule' if family == 4 else 'fib6_rule'
                        offset = c.kernel.get_type(typename).relative_child_offset('common')
                        specific = c.obj(typename, rule.vol.offset - offset)
                        for name in ('src', 'dst'):
                            value = specific.member(name)
                            address = value.vol.offset if family == 4 else value.addr.vol.offset
                            length = int(specific.member(name + '_len')) if family == 4 else int(value.plen)
                            ip = socket.inet_ntop(socket.AF_INET if family == 4 else socket.AF_INET6, c.layer.read(address, 4 if family == 4 else 16))
                            row[name] = f'{ip}/{length}'
                    c.read('rule.prefix', rule, prefix_fields)
            c.read('rule.list', ns['object'], scan)
    return rows

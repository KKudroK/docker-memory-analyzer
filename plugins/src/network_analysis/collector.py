"""Kernel objects are identities; IP prefixes and names are attributes only."""
import ipaddress
import re
import socket
import time
from volatility3.framework.objects import utility


class Collector:
    def __init__(self, context, kernel_name, limit=100000, identity_mode='combined', cgroup_cache=True):
        if not 1 <= limit <= 1000000:
            raise ValueError('limit must be in 1..1000000')
        self.context = context
        self.kernel = context.modules[kernel_name]
        self.layer = context.layers[self.kernel.layer_name]
        self.limit = limit
        if identity_mode not in ('combined', 'cgroup', 'shim'):
            raise ValueError('identity_mode must be combined, cgroup, or shim')
        self.identity_mode = identity_mode
        self.cgroup_cache_enabled = bool(cgroup_cache)
        self.cgroup_cache = {}
        self.errors = []
        self.nets = {}
        self.tasks = []
        self.devices = {}
        self.init_net_address = None
        self.metrics = {'timings_ns': {}, 'calls': {}, 'objects_visited': {},
                        'termination': {}, 'cache': {'cgroup_hits': 0, 'cgroup_misses': 0}}

    def count(self, section, key, amount=1):
        if not hasattr(self, 'metrics'):
            self.metrics = {}
        bucket = self.metrics.setdefault(section, {})
        bucket[key] = bucket.get(key, 0) + amount

    def measure(self, name, fn):
        started = time.perf_counter_ns()
        try:
            return fn()
        finally:
            self.count('timings_ns', name, time.perf_counter_ns() - started)
            self.count('calls', name)

    def issue(self, stage, obj, exc):
        self.errors.append({'stage': stage, 'address': hex(obj.vol.offset) if hasattr(obj, 'vol') else str(obj),
                            'error': type(exc).__name__, 'detail': str(exc)})

    def read(self, stage, obj, fn, default=None):
        try:
            return fn()
        except Exception as exc:
            self.issue(stage, obj, exc)
            return default

    def obj(self, name, address):
        return self.kernel.object(name, offset=int(address), absolute=True)

    def walk(self, head, typename, member):
        """Walk list_head ourselves so corrupt links and truncation are reported."""
        seen = {int(head.vol.offset)}
        offset = self.kernel.get_type(typename).relative_child_offset(member)
        link = int(head.next)
        for _ in range(self.limit):
            if link == int(head.vol.offset):
                self.count('termination', 'list_head_return')
                return
            if not link or link in seen:
                self.count('termination', 'list_null_or_cycle')
                raise ValueError('null link or non-head cycle')
            seen.add(link)
            self.count('objects_visited', 'list:' + typename)
            obj = self.obj(typename, link - offset)
            yield obj
            link = int(obj.member(member).next)
        if link == int(head.vol.offset):
            self.count('termination', 'list_head_return')
            return
        self.count('termination', 'list_budget')
        raise ValueError('traversal limit reached')

    def cstring(self, ptr):
        return utility.pointer_to_string(ptr, count=4096) if ptr else ''

    def hlist(self, head, typename, member):
        offset = self.kernel.get_type(typename).relative_child_offset(member)
        link, seen = int(head.first), set()
        while link:
            if link in seen or len(seen) >= self.limit:
                self.count('termination', 'hlist_cycle_or_budget')
                raise ValueError('hlist cycle or traversal limit')
            seen.add(link)
            self.count('objects_visited', 'hlist:' + typename)
            obj = self.obj(typename, link - offset)
            yield obj
            link = int(obj.member(member).next)

    def array(self, address, typename, count):
        if not 0 <= count <= self.limit:
            raise ValueError(f'array count {count} exceeds limit')
        self.count('objects_visited', 'array:' + typename, count)
        return self.kernel.object('array', offset=int(address), absolute=True,
                                  subtype=self.kernel.get_type(typename), count=count)

    def namespace(self, net, source):
        address = int(net.vol.offset)
        if address not in self.nets:
            self.nets[address] = {'object': net, 'address': hex(address), 'sources': [], 'pids': [], 'container_candidates': []}
            self.nets[address]['inode'] = self.read('net.inum', net, lambda: int(net.ns.inum) if net.has_member('ns') else int(net.proc_inum))
        if source not in self.nets[address]['sources']:
            self.nets[address]['sources'].append(source)
        return self.nets[address]

    def cgroups(self, task):
        if not task.cgroups:
            return []
        css = task.cgroups.dereference()
        cache_key = int(css.vol.offset)
        if self.cgroup_cache_enabled and cache_key in self.cgroup_cache:
            self.metrics['cache']['cgroup_hits'] += 1
            return list(self.cgroup_cache[cache_key])
        self.metrics['cache']['cgroup_misses'] += 1
        errors_before = len(self.errors)
        groups = {}
        def default_group():
            if css.has_member('dfl_cgrp') and css.dfl_cgrp:
                groups[int(css.dfl_cgrp)] = css.dfl_cgrp.dereference()
        self.read('cgroup.default', css, default_group)
        if css.has_member('subsys'):
            for index, state in enumerate(css.subsys):
                def subsystem():
                    if state and state.cgroup:
                        groups[int(state.cgroup)] = state.cgroup.dereference()
                self.read('cgroup.subsys.' + str(index), css, subsystem)
        paths = []
        for group in groups.values():
            path = self.read('cgroup.path', group, lambda: self.cgroup_path(group))
            if path is not None and path not in paths:
                paths.append(path)
        # Never cache partial results as a complete css_set resolution.
        if self.cgroup_cache_enabled and len(self.errors) == errors_before:
            self.cgroup_cache[cache_key] = tuple(paths)
        return paths

    def cgroup_path(self, group):
        modern = group.has_member('kn')
        if modern and not group.kn:
            raise ValueError('cgroup has NULL kernfs node')
        node = group.kn.dereference() if modern else group
        parts, seen = [], set()
        while True:
            address = int(node.vol.offset)
            if address in seen:
                self.count('termination', 'kernfs_cycle')
                raise ValueError('cgroup parent cycle')
            if len(seen) >= self.limit:
                self.count('termination', 'kernfs_budget')
                raise ValueError('cgroup path budget exceeded')
            seen.add(address)
            self.count('objects_visited', 'kernfs_node' if modern else 'cgroup')
            if modern:
                parts.append(self.cstring(node.name))
            elif node.has_member('name'):
                parts.append(self.cstring(node.name))
            elif node.has_member('name_copy') and node.name_copy:
                parts.append(utility.array_to_string(node.name_copy.name))
            else:
                raise NotImplementedError('cgroup name layout unavailable')
            parent = node.parent if node.has_member('parent') else node.member('__parent')
            if not parent:
                self.count('termination', 'kernfs_root')
                return '/' + '/'.join(p for p in reversed(parts) if p)
            node = parent.dereference()

    def collect_tasks(self):
        init = self.kernel.object_from_symbol('init_task')
        def scan():
            for task in self.walk(init.tasks, 'task_struct', 'tasks'):
                self.tasks.append(task)
        self.read('tasks.list', init, scan)
        seen = {t.vol.offset for t in self.tasks}
        for leader in list(self.tasks):
            def threads():
                if leader.has_member('thread_node') and leader.signal.has_member('thread_head'):
                    head, member = leader.signal.thread_head, 'thread_node'
                elif leader.has_member('thread_group'):
                    head, member = leader.thread_group, 'thread_group'
                else:
                    raise NotImplementedError('thread list layout unavailable')
                for task in self.walk(head, 'task_struct', member):
                    if task.vol.offset not in seen:
                        seen.add(task.vol.offset)
                        self.tasks.append(task)
            self.read('tasks.threads', leader, threads)
        records = []
        for task in self.tasks:
            record = self.read('task.identity', task, lambda: {
                'address': hex(task.vol.offset), 'pid': int(task.pid), 'tgid': int(task.tgid),
                'comm': utility.array_to_string(task.comm), 'container_candidates': [],
                'source': 'init_task.tasks + task thread lists', 'confidence': 'reachable_task_object'})
            if record is None:
                continue
            paths = (self.read('task.cgroups', task,
                               lambda: self.measure('identity.cgroup_paths', lambda: self.cgroups(task)), [])
                     if self.identity_mode in ('combined', 'cgroup') else [])
            record['cgroup_paths'] = paths
            for path in paths:
                for cid in re.findall(r'(?<![0-9a-f])([0-9a-f]{64})(?![0-9a-f])', path):
                    if cid not in record['container_candidates']:
                        record['container_candidates'].append(cid)
            record['identity_evidence'] = 'cgroup_path_candidate' if record['container_candidates'] else 'unresolved'
            proxy = self.read('task.nsproxy', task, lambda: task.nsproxy.dereference() if task.nsproxy else None)
            if proxy is not None:
                net = self.read('task.net', task, lambda: proxy.net_ns.dereference() if proxy.net_ns else None)
                if net is not None:
                    ns = self.namespace(net, 'task.nsproxy.net_ns')
                    ns['pids'].append(record['pid'])
                    ns['container_candidates'] = sorted(set(ns['container_candidates'] + record['container_candidates']))
                    record['namespace'] = ns['address']
            records.append(record)
        return records

    def address(self, ifa, family):
        if family == 4:
            raw = self.layer.read(ifa.ifa_local.vol.offset, 4)
            prefix = int(ifa.ifa_prefixlen)
            flags, scope = int(ifa.ifa_flags), int(ifa.ifa_scope)
        else:
            raw = self.layer.read(ifa.addr.vol.offset, 16)
            prefix = int(ifa.prefix_len)
            flags, scope = int(ifa.flags), int(ifa.scope)
        ip = socket.inet_ntop(socket.AF_INET if family == 4 else socket.AF_INET6, raw)
        cidr = f'{ip}/{prefix}'
        return {'address': hex(ifa.vol.offset), 'family': family, 'ip': ip, 'prefix': prefix, 'cidr': cidr,
                'subnet': str(ipaddress.ip_network(cidr, strict=False)), 'flags': flags, 'scope': scope}

    def interface(self, net, dev):
        row = {'address': hex(dev.vol.offset), 'namespace': net['address'], 'namespace_inode': net['inode'],
               'container_candidates': net['container_candidates'], 'pids': net['pids'],
               'name': utility.array_to_string(dev.name), 'ifindex': int(dev.ifindex), 'addresses': [],
               'source': 'kernel.net.dev_base_head', 'confidence': 'direct_object_membership'}
        row['device_namespace'] = self.read('interface.nd_net', dev, lambda: hex(int(dev.nd_net.net)))
        if row['device_namespace'] is not None and row['device_namespace'] != net['address']:
            row['confidence'] = 'conflicting_namespace_pointers'
            self.issue('interface.namespace_conflict', dev, ValueError('dev_base_head and nd_net disagree'))
        for field in ('mtu', 'flags', 'promiscuity', 'operstate', 'type'):
            row[field] = self.read('interface.' + field, dev, lambda: int(dev.member(field)))
        def mac():
            size = int(dev.addr_len)
            if not 0 <= size <= 32:
                raise ValueError('invalid hardware address length')
            return ':'.join(f'{b:02x}' for b in self.layer.read(int(dev.dev_addr), size))
        row['mac'] = self.read('interface.mac', dev, mac)
        if dev.has_member('rtnl_link_ops') and dev.rtnl_link_ops:
            row['kind'] = self.read('interface.kind', dev, lambda: self.cstring(dev.rtnl_link_ops.kind))
        def ipv4():
            if not dev.has_member('ip_ptr') or not dev.ip_ptr:
                return
            ipdev = dev.ip_ptr.dereference().cast('in_device')
            ptr, seen = ipdev.ifa_list, set()
            for _ in range(self.limit):
                if not ptr:
                    return
                if int(ptr) in seen:
                    raise ValueError('IPv4 address cycle')
                seen.add(int(ptr))
                ifa = ptr.dereference()
                value = self.read('ipv4.entry', ifa, lambda: self.address(ifa, 4))
                if value:
                    row['addresses'].append(value)
                ptr = ifa.ifa_next
            if ptr:
                raise ValueError('IPv4 address limit')
        def ipv6():
            if not dev.has_member('ip6_ptr') or not dev.ip6_ptr:
                return
            ipdev = dev.ip6_ptr.dereference().cast('inet6_dev')
            for ifa in self.walk(ipdev.addr_list, 'inet6_ifaddr', 'if_list'):
                value = self.read('ipv6.entry', ifa, lambda: self.address(ifa, 6))
                if value:
                    row['addresses'].append(value)
        self.read('interface.ipv4', dev, ipv4)
        self.read('interface.ipv6', dev, ipv6)
        self.devices[int(dev.vol.offset)] = (dev, row)
        return row

    def collect(self, features=None):
        enabled = lambda name: features is None or name in features
        if self.kernel.has_symbol('init_net'):
            initial = self.kernel.object_from_symbol('init_net')
            self.init_net_address = hex(initial.vol.offset)
            self.namespace(initial, 'init_net')
        tasks = self.measure('discovery.tasks', self.collect_tasks)
        from . import identity
        published = self.measure('identity.runtime_and_ancestry', lambda: identity.collect(self, tasks))
        def namespaces():
            head = self.kernel.object_from_symbol('net_namespace_list')
            for net in self.walk(head, 'net', 'list'):
                self.namespace(net, 'net_namespace_list')
        self.measure('discovery.namespaces', lambda: self.read('net.list', 'net_namespace_list', namespaces))
        interfaces = []
        for net in self.nets.values():
            def devices():
                for dev in self.walk(net['object'].dev_base_head, 'net_device', 'dev_list'):
                    value = self.read('interface', dev, lambda: self.interface(net, dev))
                    if value:
                        interfaces.append(value)
            self.measure('network.interfaces', lambda: self.read('net.devices', net['object'], devices))
        from . import topology, sockets, routes, neighbors, conntrack, multicast
        edges, unsupported = self.measure('network.topology', lambda: topology.collect(self))
        socket_rows = self.measure('network.sockets', lambda: self.read('socket.collect', 'kernel', lambda: sockets.collect(self), [])) if enabled('sockets') else []
        route_rows = self.measure('network.routes', lambda: self.read('route.collect', 'kernel', lambda: routes.collect(self, unsupported), [])) if enabled('routes') else []
        neighbor_rows = self.measure('network.neighbors', lambda: self.read('neighbor.collect', 'kernel', lambda: neighbors.collect(self, unsupported), [])) if enabled('neighbors') else []
        flow_rows = self.measure('network.conntrack', lambda: self.read('conntrack.collect', 'kernel', lambda: conntrack.collect(self, unsupported), [])) if enabled('conntrack') else []
        multicast_rows = self.measure('network.multicast', lambda: self.read('multicast.collect', 'kernel', lambda: multicast.collect(self), [])) if enabled('multicast') else []
        rule_rows = self.measure('network.rules', lambda: self.read('rule.collect', 'kernel', lambda: routes.rules(self), [])) if enabled('rules') else []
        fdb_rows = self.measure('network.bridge_fdb', lambda: self.read('bridge.collect', 'kernel', lambda: topology.bridge_fdb(self, unsupported), [])) if enabled('bridge_fdb') else []
        unsupported.extend([
            {'feature': 'firewall_rules', 'reason': 'nftables/iptables rule programs not decoded; conntrack and proxy argv are separate evidence'},
            {'feature': 'runtime_network_metadata', 'reason': 'Docker network ID/name/IPAM/options require runtime metadata; not inferred from prefixes'},
            {'feature': 'socket_coverage', 'reason': 'FD-reachable sockets only; orphan/TIME_WAIT/hash-only sockets not enumerated'},
        ])
        for ns in self.nets.values():
            ns['is_initial'] = ns['address'] == self.init_net_address
            ns['membership'] = 'host_shared_candidate' if ns['is_initial'] and ns['container_candidates'] else ('identified_candidates' if ns['container_candidates'] else 'unattributed')
        return {'schema_version': 1, 'tasks': tasks, 'links': edges, 'unsupported': unsupported, 'sockets': socket_rows,
                'metadata': {'kernel_symbol_table': self.kernel.symbol_table_name, 'kernel_layer': self.kernel.layer_name,
                             'requested_features': sorted(features) if features is not None else ['all_supported'],
                             'kernel_virtual_offset': hex(self.kernel.offset), 'traversal_limit': self.limit,
                             'traversal_limit_semantics': 'corruption safety budget; normal termination uses head/null/root and cycle detection',
                             'identity_mode': self.identity_mode, 'cgroup_cache': self.cgroup_cache_enabled,
                             'metrics': self.metrics,
                             'identity_policy': 'object address within this snapshot; namespace inode and ifindex are attributes',
                             'snapshot_limit': 'a live-acquired dump may contain temporal smearing; successful parsing is not exhaustive coverage'},
                'routes': route_rows, 'neighbors': neighbor_rows,
                'published_ports': published,
                'conntrack': flow_rows,
                'multicast': multicast_rows, 'rules': rule_rows,
                'bridge_fdb': fdb_rows,
                'namespaces': [{k: v for k, v in ns.items() if k != 'object'} for ns in self.nets.values()],
                'interfaces': interfaces, 'errors': self.errors,
                'summary': {'tasks': len(tasks), 'namespaces': len(self.nets), 'interfaces': len(interfaces),
                            'addresses': sum(len(i['addresses']) for i in interfaces), 'sockets': len(socket_rows), 'links': len(edges),
                            'routes': len(route_rows), 'rules': len(rule_rows), 'neighbors': len(neighbor_rows), 'conntrack': len(flow_rows),
                            'multicast': len(multicast_rows), 'bridge_fdb': len(fdb_rows), 'published_ports': len(published), 'errors': len(self.errors)}}

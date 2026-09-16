"""Kernel objects are identities; IP prefixes and names are attributes only."""
import ipaddress
import socket
from volatility3.framework.objects import utility
from volatility3.plugins.linux import pslist


class Collector:
    def __init__(self, context, kernel_name):
        self.context = context
        self.kernel = context.modules[kernel_name]
        self.layer = context.layers[self.kernel.layer_name]
        self.limit = 100000
        self.cgroup_cache = {}
        self.errors = []
        self.nets = {}
        self.tasks = []
        self.init_net_address = None

    def issue(self, stage, obj, exc):
        self.errors.append({'stage': stage, 'address': hex(obj.vol.offset) if hasattr(obj, 'vol') else str(obj),
                            'error': type(exc).__name__, 'detail': str(exc)})

    def read(self, stage, obj, fn, default=None, *, args=()):
        try:
            return fn(*args)
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
                return
            if not link or link in seen:
                raise ValueError('null link or non-head cycle')
            seen.add(link)
            obj = self.obj(typename, link - offset)
            yield obj
            link = int(obj.member(member).next)
        if link == int(head.vol.offset):
            return
        raise ValueError('traversal limit reached')

    def cstring(self, ptr):
        return utility.pointer_to_string(ptr, count=4096) if ptr else ''

    def net_pointer(self, value):
        """Stock net_device extension pattern: possible_net_t or old net*."""
        wrapped = value.has_member('net')
        return int(value.net) if wrapped else int(value)

    def array(self, address, typename, count):
        if not 0 <= count <= self.limit:
            raise ValueError(f'array count {count} exceeds limit')
        return self.kernel.object('array', offset=int(address), absolute=True,
                                  subtype=self.kernel.get_type(typename), count=count)

    def namespace(self, net, source):
        address = int(net.vol.offset)
        if not address:
            raise ValueError('NULL network namespace')
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
        if cache_key in self.cgroup_cache:
            return list(self.cgroup_cache[cache_key])
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
        if len(self.errors) == errors_before:
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
                raise ValueError('cgroup parent cycle')
            if len(seen) >= self.limit:
                raise ValueError('cgroup path budget exceeded')
            seen.add(address)
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
                return '/' + '/'.join(p for p in reversed(parts) if p)
            node = parent.dereference()

    def append_tasks(self, iterator, seen):
        """Consume a stock task iterator with a bounded output and address deduplication."""
        for count, task in enumerate(iterator):
            if count >= self.limit:
                raise ValueError('task iterator output budget exceeded')
            address = int(task.vol.offset)
            if address not in seen:
                seen.add(address)
                self.tasks.append(task)

    def discover_tasks(self):
        """Reuse stock process discovery; isolate each leader's thread enumeration."""
        self.tasks = []
        seen = set()
        leaders = pslist.PsList.list_tasks(self.context, self.kernel.name, include_threads=False)
        self.read('tasks.list', 'PsList.list_tasks', self.append_tasks, args=(leaders, seen))
        for leader in list(self.tasks):
            self.read('tasks.threads', leader, self.append_thread_tasks, args=(leader, seen))

    def append_thread_tasks(self, leader, seen):
        self.append_tasks(leader.get_threads(), seen)

    def collect_tasks(self):
        self.discover_tasks()
        records = []
        for task in self.tasks:
            record = self.read('task.identity', task, lambda: {
                'address': hex(task.vol.offset), 'pid': int(task.pid), 'tgid': int(task.tgid),
                'comm': utility.array_to_string(task.comm), 'container_candidates': [],
                'source': 'PsList.list_tasks + task.get_threads', 'confidence': 'reachable_task_object'})
            if record is None:
                continue
            errors_before = len(self.errors)
            paths = self.read('task.cgroups', task, self.cgroups, [], args=(task,))
            record['cgroup_paths'] = paths
            record['cgroup_complete'] = len(self.errors) == errors_before
            from . import identity
            record['container_candidates'] = identity.cgroup_candidates(paths)
            record['identity_evidence'] = 'cgroup_path_candidate' if record['container_candidates'] else 'unresolved'
            proxy = self.read('task.nsproxy', task, lambda: task.nsproxy.dereference() if task.nsproxy else None)
            if proxy is not None:
                net = self.read('task.net', task, lambda: proxy.net_ns.dereference() if proxy.net_ns else None)
                if net is not None:
                    ns = self.namespace(net, 'task.nsproxy.net_ns')
                    ns['pids'].append(record['pid'])
                    ns['container_candidates'] = sorted(set(ns['container_candidates'] + record['container_candidates']))
                    record['namespace'] = ns['address']
            # These fields describe a task generation, not a Docker state.
            for field in ('start_time', 'start_boottime'):
                if task.has_member(field):
                    record[field] = self.read('task.' + field, task, lambda f=field: int(task.member(f)))
            records.append(record)
        by_pid = {}
        for record in records:
            by_pid.setdefault(record['pid'], []).append(record)
        for pid, duplicates in by_pid.items():
            if len(duplicates) > 1:
                for record in duplicates:
                    record['pid_conflict'] = True
                self.issue('task.pid_conflict', str(pid), ValueError('distinct task objects share one PID; membership excluded'))
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
        row['device_namespace'] = self.read('interface.nd_net', dev, lambda: hex(self.net_pointer(dev.nd_net)))
        if row['device_namespace'] is not None and row['device_namespace'] != net['address']:
            raise ValueError('dev_base_head and nd_net disagree')
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
        return row

    def collect(self, features=None):
        """Collect only explicitly selected core evidence; export never widens scope."""
        from . import identity, sockets, conntrack, context
        features = {'sockets'} if features is None else set(features)
        if not features <= {'sockets', 'interfaces', 'conntrack'}:
            raise ValueError('Unknown collection features')
        if self.kernel.has_symbol('init_net'):
            initial = self.read('net.init', 'init_net', self.kernel.object_from_symbol,
                                args=('init_net',))
            if initial is not None:
                self.init_net_address = hex(initial.vol.offset)
                self.namespace(initial, 'init_net')
        tasks = self.collect_tasks()
        identity.collect(self, tasks)
        members = {task.get('namespace') for task in tasks if identity.member_id(task)}
        unsupported = []
        for ns in self.nets.values():
            ns['is_initial'] = ns['address'] == self.init_net_address
            ns['initial_identity_known'] = self.init_net_address is not None
            if (features & {'interfaces', 'conntrack'} and ns['address'] in members and
                    (ns['is_initial'] or not ns['initial_identity_known'])):
                unsupported.append({'feature': 'container_namespace_context', 'namespace': ns['address'],
                                    'reason': 'host-shared or unknown initial namespace; use container FD sockets for attribution'})
        self.context_namespaces = {ns['address'] for ns in self.nets.values()
                                   if ns['address'] in members and not ns['is_initial'] and ns['initial_identity_known']}
        interfaces = []
        if 'interfaces' in features:
            for net in list(self.nets.values()):
                if net['address'] not in self.context_namespaces:
                    continue
                def devices():
                    for dev in self.walk(net['object'].dev_base_head, 'net_device', 'dev_list'):
                        value = self.read('interface', dev, self.interface, args=(net, dev))
                        if value:
                            interfaces.append(value)
                self.read('net.devices', net['object'], devices)
        socket_rows = (self.read('socket.collect', 'kernel', sockets.collect, [], args=(self, tasks))
                       if 'sockets' in features else [])
        flow_rows = (self.read('conntrack.collect', 'kernel', conntrack.collect, [], args=(self, unsupported))
                     if 'conntrack' in features else [])
        # Socket discovery may add namespaces outside the holder's current nsproxy.
        for ns in self.nets.values():
            ns['is_initial'] = ns['address'] == self.init_net_address
            ns['initial_identity_known'] = self.init_net_address is not None
        if 'sockets' in features:
            unsupported.append({'feature': 'socket_coverage',
                                'reason': 'FD-reachable sockets and reciprocal UNIX peers only; no orphan/TIME_WAIT inventory'})
        report = {'schema_version': 4, 'tasks': tasks, 'unsupported': unsupported, 'sockets': socket_rows,
                  'metadata': {'kernel_symbol_table': self.kernel.symbol_table_name, 'kernel_layer': self.kernel.layer_name,
                               'requested_features': sorted(features), 'kernel_virtual_offset': hex(self.kernel.offset),
                               'traversal_limit': self.limit,
                               'identity_policy': 'complete unique own-cgroup ID, checked against shim ancestry; addresses identify snapshot objects',
                               'collection_scope': 'FD holders across tasks for sharing evidence; interface/conntrack context restricted to confirmed non-host container namespaces',
                               'snapshot_limit': 'live acquisition may smear time; successful parsing is not exhaustive coverage'},
                  'conntrack': flow_rows,
                  'namespaces': [{k: v for k, v in ns.items() if k != 'object'} for ns in self.nets.values()],
                  'interfaces': interfaces, 'errors': self.errors,
                  'summary': {'tasks': len(tasks), 'namespaces': len(self.nets), 'interfaces': len(interfaces),
                              'addresses': sum(len(i['addresses']) for i in interfaces), 'sockets': len(socket_rows),
                              'conntrack': len(flow_rows), 'errors': len(self.errors)}}
        report['container_context'] = context.build(report)
        for key in ('containers', 'relations', 'structural_relations'):
            report['summary'][key] = len(report['container_context'][key])
        return report

"""Independent permission-context readers for symbol-described Linux layouts.

Optional context cannot turn a readable capability into zero. The atomic_flags
NNP adapter uses the documented bit-zero rule, not inferred future semantics.
"""
from volatility3.framework.objects import utility
from volatility3.plugins.linux import mountinfo
from volatility3.plugins.container_support.capabilities_reader import decode_capability, UnsupportedLayout

CAP_FIELDS = ('cap_inheritable', 'cap_permitted', 'cap_effective', 'cap_bounding', 'cap_ambient')
ID_FIELDS = ('uid', 'euid', 'suid', 'fsuid', 'gid', 'egid', 'sgid', 'fsgid')
SAFETY_ITEMS = 65536


class InconsistentData(ValueError):
    """Successfully read fields fail a structural consistency check."""


def observation(feature, status, reason, layout=None):
    value = {'feature': feature, 'status': status, 'reason': reason}
    if layout is not None:
        value['layout'] = layout
    return value


def member(obj, name):
    if not obj.has_member(name):
        raise UnsupportedLayout('Member ' + name + ' is absent from the symbols')
    return obj.member(name)


def capture(observations, feature, fn, layout=None):
    # 필드별 실패를 None과 상태로 남긴다. 실패를 0/빈 집합으로 바꾸거나 다른 성공값을 버리지 않는다.
    try:
        value = fn()
    except UnsupportedLayout as exc:
        observations.append(observation(feature, 'unsupported', str(exc), layout))
    except InconsistentData as exc:
        observations.append(observation(feature, 'inconsistent', str(exc), layout))
    except Exception as exc:
        observations.append(observation(feature, 'read_error', type(exc).__name__ + ': ' + str(exc), layout))
    else:
        observations.append(observation(feature, 'ok', 'Read from memory', layout))
        return value
    return None


def dereference(pointer, name):
    if not int(pointer):
        raise InconsistentData('Null ' + name + ' pointer')
    return pointer.dereference()


def kernel_id(value):
    return int(value.val) if hasattr(value, 'has_member') and value.has_member('val') else int(value)


def anonymous_member(obj, name, depth=0):
    if obj.has_member(name):
        return obj.member(name)
    if depth >= 8:
        raise InconsistentData('Anonymous member nesting exceeds safety limit')
    for key in obj.vol.members:
        if key.startswith('unnamed_member_'):
            try:
                return anonymous_member(obj.member(key), name, depth + 1)
            except UnsupportedLayout:
                pass
    raise UnsupportedLayout('Member ' + name + ' is absent from the symbols')


def map_kernel_id(extents, value):
    matches = [e['namespace_first'] + value - e['kernel_first'] for e in extents
               if e['kernel_first'] <= value < e['kernel_first'] + e['count']]
    if len(matches) > 1:
        raise InconsistentData('Overlapping ID mappings')
    return matches[0] if matches else None


def read_id_map(idmap, module):
    count = int(anonymous_member(idmap, 'nr_extents'))
    if not 0 <= count <= SAFETY_ITEMS:
        raise InconsistentData('Invalid uid/gid map extent count or traversal safety limit exceeded')
    if count == 0:
        return []
    source = anonymous_member(idmap, 'extent')
    if count <= len(source):
        values = [source[i] for i in range(count)]
    else:
        pointer = anonymous_member(idmap, 'forward')
        if not int(pointer):
            raise InconsistentData('Null large ID map pointer')
        size = module.get_type('uid_gid_extent').size
        values = [module.object('uid_gid_extent', offset=int(pointer) + i * size, absolute=True) for i in range(count)]
    result = []
    for extent in values:
        first, lower, size = int(extent.first), int(extent.lower_first), int(extent.count)
        if first < 0 or lower < 0 or size <= 0 or first + size > 0xffffffff or lower + size > 0xffffffff:
            raise InconsistentData('Invalid uid/gid map extent')
        result.append({'namespace_first': first, 'kernel_first': lower, 'count': size})
    for field in ('namespace_first', 'kernel_first'):
        ordered = sorted(result, key=lambda item: item[field])
        if any(a[field] + a['count'] > b[field] for a, b in zip(ordered, ordered[1:])):
            raise InconsistentData('Overlapping uid/gid map extents')
    return result


def namespace_inum(namespace):
    if namespace.has_member('ns'):
        return int(member(namespace.ns, 'inum'))
    if namespace.has_member('proc_inum'):
        return int(namespace.proc_inum)
    raise UnsupportedLayout('Neither namespace.ns.inum nor namespace.proc_inum exists')


class SecurityReader:
    def __init__(self, context, module):
        self.context, self.module = context, module
        self.observations = []
        self.compatibility = self.observations
        self.ns_cache, self.mount_cache = {}, {}
        self.banner = capture(self.observations, 'kernel.banner', lambda: str(module.object_from_symbol('linux_banner').cast(
            'string', max_length=512, encoding='utf-8', errors='replace')).rstrip('\n'))
        self.initial_ns = None
        self.initial_address = None
        try:
            if not module.has_symbol('init_user_ns'):
                raise UnsupportedLayout('init_user_ns symbol is absent; scope cannot be anchored')
            self.initial_ns = module.object_from_symbol('init_user_ns')
            self.initial_address = int(self.initial_ns.vol.offset)
        except UnsupportedLayout as exc:
            self.observations.append(observation('user_namespace.initial', 'unsupported', str(exc)))
        except Exception as exc:
            self.observations.append(observation('user_namespace.initial', 'read_error', str(exc)))

    def raw(self, obj):
        return {'virtual_address': hex(int(obj.vol.offset)), 'size': obj.vol.size,
                'bytes_hex': self.context.layers[obj.vol.layer_name].read(obj.vol.offset, obj.vol.size, pad=False).hex()}

    def user_namespace(self, start):
        address = int(start.vol.offset)
        if address in self.ns_cache:
            return self.ns_cache[address]
        observations = []
        result = {'scope': 'unknown', 'chain_leaf_to_initial': [], 'initial_address': None,
                  'initial_inum': None, 'observations': observations}
        if self.initial_address is not None:
            result['initial_address'] = hex(self.initial_address)
            result['initial_inum'] = capture(observations, 'user_namespace.initial_inum', lambda: namespace_inum(self.initial_ns))
        else:
            observations.append(observation('user_namespace.scope', 'unsupported', 'init_user_ns unavailable; root cannot be authenticated'))
        current, seen, previous_level = start, set(), None
        chain_complete = False
        while current is not None:
            try:
                key = int(current.vol.offset)
                if key in seen or len(seen) >= 33:
                    raise InconsistentData('Invalid/oversized user namespace parent chain')
                seen.add(key)
                node = {'address': hex(key), 'inum': None, 'level': None, 'owner_kernel_uid': None,
                        'group_kernel_gid': None, 'uid_map': None, 'gid_map': None}
                result['chain_leaf_to_initial'].append(node)
                feature = 'user_namespace.' + hex(key)
                node['inum'] = capture(observations, feature + '.inum', lambda: namespace_inum(current))
                for field, output in (('owner', 'owner_kernel_uid'), ('group', 'group_kernel_gid')):
                    node[output] = capture(observations, feature + '.' + field, lambda field=field: kernel_id(member(current, field)))
                for field in ('uid_map', 'gid_map'):
                    node[field] = capture(observations, feature + '.' + field,
                                          lambda field=field: read_id_map(member(current, field), self.module))
                level = int(member(current, 'level'))
                node['level'] = level
                if not 0 <= level <= 32 or (previous_level is not None and level != previous_level - 1):
                    raise InconsistentData('Inconsistent user namespace levels')
                previous_level = level
                pointer = member(current, 'parent')
                if not int(pointer):
                    if self.initial_address is not None and (key != self.initial_address or level != 0):
                        raise InconsistentData('User namespace chain does not reach init_user_ns')
                    chain_complete = True
                    break
                current = pointer.dereference()
            except UnsupportedLayout as exc:
                observations.append(observation('user_namespace.parent_chain', 'unsupported', str(exc)))
                break
            except InconsistentData as exc:
                observations.append(observation('user_namespace.parent_chain', 'inconsistent', str(exc)))
                break
            except Exception as exc:
                observations.append(observation('user_namespace.parent_chain', 'read_error', str(exc)))
                break
        if chain_complete and self.initial_address is not None:
            # user namespace 적용 범위는 init_user_ns까지의 주소·부모·level 연결로 확인한다.
            # EUID 0이나 namespace 번호만으로 초기 namespace라고 추정하지 않는다.
            result['scope'] = 'initial_user_namespace' if address == self.initial_address else 'descendant_user_namespace'
            observations.append(observation('user_namespace.scope', 'ok', 'Parent and level chain reaches init_user_ns'))
        if result['scope'] != 'unknown' and all(x['status'] == 'ok' for x in observations):
            self.ns_cache[address] = result
        return result

    def credentials(self, cred):
        observations = []
        result = {'address': hex(int(cred.vol.offset)), 'ids_kernel': {}, 'ids_in_user_namespace': {},
                  'capability_evidence': {}, 'capabilities': {}, 'securebits': None,
                  'security_blob_address': None, 'lsm_policy': 'not_evaluated', 'observations': observations}
        for name in ID_FIELDS:
            result['ids_kernel'][name] = capture(observations, 'credentials.' + name, lambda name=name: kernel_id(member(cred, name)))
        result['securebits'] = capture(observations, 'credentials.securebits', lambda: int(member(cred, 'securebits')))
        result['security_blob_address'] = capture(observations, 'credentials.security_blob', lambda: hex(int(member(cred, 'security'))))
        for name in CAP_FIELDS:
            result['capabilities'][name] = None
            result['capability_evidence'][name] = None
            field = 'cap_bset' if name == 'cap_bounding' else name
            try:
                if not cred.has_member(field):
                    observations.append(observation(name, 'not_present', 'Credential member ' + field + ' is absent from the symbols'))
                    continue
                decoded = decode_capability(self.context, self.module, cred.member(field))
            except UnsupportedLayout as exc:
                observations.append(observation(name, 'unsupported', str(exc)))
            except ValueError as exc:
                observations.append(observation(name, 'inconsistent', str(exc)))
            except Exception as exc:
                observations.append(observation(name, 'read_error', type(exc).__name__ + ': ' + str(exc)))
            else:
                result['capabilities'][name] = decoded['text']
                result['capability_evidence'][name] = decoded['evidence']
                observations.append(observation(name, 'ok', 'Capability read from memory', decoded['evidence'].get('layout')))
                for item in decoded.get('observations', []):
                    observations.append({**item, 'feature': item['feature'] + '.' + name})
        return result

    def _array_values(self, source, count):
        if len(source) >= count:
            return [source[index] for index in range(count)]
        if self.module is None or not hasattr(source, 'vol') or not hasattr(source.vol, 'subtype'):
            raise UnsupportedLayout('Flexible-array subtype metadata unavailable')
        expanded = self.module.object('array', offset=int(source.vol.offset), absolute=True,
                                      subtype=source.vol.subtype, count=count)
        return list(expanded)

    def supplementary_groups(self, groups):
        count = int(member(groups, 'ngroups'))
        if not 0 <= count <= SAFETY_ITEMS:
            raise InconsistentData('Invalid supplementary group count or safety limit exceeded')
        if count == 0:
            return [], 'empty'
        if groups.has_member('gid'):
            return [kernel_id(x) for x in self._array_values(groups.gid, count)], 'group_info.gid'
        if groups.has_member('small_block') and groups.has_member('blocks'):
            small = groups.small_block
            if count <= len(small):
                return [kernel_id(small[index]) for index in range(count)], 'group_info.small_block'
            if not hasattr(small, 'vol') or not hasattr(small.vol, 'subtype'):
                raise UnsupportedLayout('Legacy group element type unavailable')
            subtype = small.vol.subtype
            item_size = int(subtype.size)
            layer = self.context.layers[self.module.layer_name]
            page_size = getattr(layer, 'page_size', None)
            if page_size is None or item_size <= 0 or int(page_size) % item_size:
                raise UnsupportedLayout('Legacy group block page/element size unavailable')
            per_block = int(page_size) // item_size
            needed = (count + per_block - 1) // per_block
            blocks = int(member(groups, 'nblocks'))
            if not needed <= blocks <= SAFETY_ITEMS:
                raise InconsistentData('Legacy group block count cannot hold ngroups')
            pointers = self._array_values(groups.blocks, needed)
            values = []
            for pointer in pointers:
                if not int(pointer):
                    raise InconsistentData('Null legacy supplementary group block')
                size = min(per_block, count - len(values))
                block = self.module.object('array', offset=int(pointer), absolute=True, subtype=subtype, count=size)
                values.extend(kernel_id(value) for value in block)
            return values, 'group_info.blocks'
        raise UnsupportedLayout('Neither contiguous gid nor small_block/blocks layout exists')

    def enrich_identity(self, result, cred):
        observations = result.setdefault('observations', [])
        result['user_namespace'] = {'scope': 'unknown', 'chain_leaf_to_initial': [], 'observations': []}
        scope = capture(observations, 'credentials.user_namespace', lambda: self.user_namespace(dereference(member(cred, 'user_ns'), 'user namespace')))
        if scope is not None:
            result['user_namespace'] = scope
            observations.extend(scope['observations'])
        chain = result['user_namespace']['chain_leaf_to_initial']
        leaf = chain[0] if chain else {}
        for name, value in result['ids_kernel'].items():
            mappings = leaf.get('uid_map' if 'uid' in name else 'gid_map')
            result['ids_in_user_namespace'][name] = None
            if value is not None and mappings is not None:
                result['ids_in_user_namespace'][name] = capture(observations, 'credentials.mapped_' + name,
                                                               lambda mappings=mappings, value=value: map_kernel_id(mappings, value))
        result['supplementary_gids_kernel'] = None
        result['supplementary_gids_in_user_namespace'] = None
        groups = capture(observations, 'credentials.supplementary_groups', lambda: self.supplementary_groups(
            dereference(member(cred, 'group_info'), 'group_info')))
        if groups is not None:
            gids, layout = groups
            result['supplementary_gids_kernel'] = gids
            observations[-1]['layout'] = layout
            if leaf.get('gid_map') is not None:
                result['supplementary_gids_in_user_namespace'] = capture(observations, 'credentials.mapped_groups',
                    lambda: [map_kernel_id(leaf['gid_map'], value) for value in gids])

    def seccomp(self, task):
        # 모드·선언 개수·필터 연결을 관측한다. BPF 명령을 평가해 syscall 허용 여부를 계산하지 않는다.
        observations = []
        result = {'mode': None, 'mode_name': None, 'filter_count': None, 'declared_filter_count': None,
                  'observed_filter_count': None, 'filter_count_source': None, 'filter_count_cross_checked': False,
                  'filters': [], 'chain_complete': False, 'rules_evaluated': False, 'no_new_privs': None,
                  'atomic_flags': None, 'observations': observations}
        if task.has_member('no_new_privs'):
            result['no_new_privs'] = capture(observations, 'no_new_privs', lambda: bool(int(task.no_new_privs)), 'task.no_new_privs')
        elif task.has_member('atomic_flags'):
            flags = capture(observations, 'no_new_privs', lambda: int(task.atomic_flags), 'task.atomic_flags/PFA_NO_NEW_PRIVS=0')
            if flags is not None:
                result['no_new_privs'] = bool(flags & 1)
                raw = capture(observations, 'no_new_privs.raw', lambda: self.raw(task.atomic_flags))
                result['atomic_flags'] = {**(raw or {}), 'no_new_privs_bit': 0,
                    'rule_source': 'Linux include/linux/sched.h PFA_NO_NEW_PRIVS bit 0 (verified through Linux 7.0); future semantics not inferred'}
        else:
            observations.append(observation('no_new_privs', 'unsupported', 'No supported no_new_privs storage member'))
        seccomp = capture(observations, 'seccomp.structure', lambda: member(task, 'seccomp'))
        if seccomp is None:
            return result
        def read_mode():
            value = int(member(seccomp, 'mode'))
            if value not in (0, 1, 2):
                raise InconsistentData('Unknown seccomp mode value: ' + str(value))
            return value
        result['mode'] = capture(observations, 'seccomp.mode', read_mode)
        if result['mode'] is not None:
            result['mode_name'] = ('disabled', 'strict', 'filter')[result['mode']]
        def read_count():
            field = member(seccomp, 'filter_count')
            value = int(field.counter) if hasattr(field, 'has_member') and field.has_member('counter') else int(field)
            if not 0 <= value <= SAFETY_ITEMS:
                raise InconsistentData('Invalid seccomp filter count or safety limit exceeded')
            return value
        declared = capture(observations, 'seccomp.filter_count', read_count)
        result['declared_filter_count'] = declared
        if declared is not None:
            result['filter_count'], result['filter_count_source'] = declared, 'seccomp.filter_count'
        def walk_filters():
            pointer, seen = member(seccomp, 'filter'), set()
            while int(pointer):
                key = int(pointer)
                if key in seen or len(seen) >= 4096:
                    raise InconsistentData('Invalid/oversized seccomp filter chain')
                seen.add(key)
                item = pointer.dereference()
                record = {'address': hex(key), 'program_address': None, 'log': None}
                result['filters'].append(record)
                record['program_address'] = capture(observations, 'seccomp.filter.' + hex(key) + '.prog', lambda: hex(int(member(item, 'prog'))))
                record['log'] = capture(observations, 'seccomp.filter.' + hex(key) + '.log', lambda: bool(int(member(item, 'log'))))
                pointer = member(item, 'prev')
            return len(seen)
        observed = capture(observations, 'seccomp.filter_chain', walk_filters)
        result['observed_filter_count'] = len(result['filters'])
        result['chain_complete'] = observed is not None
        if observed is not None:
            if declared is None:
                # 선언 필드가 없을 때는 끝까지 읽은 체인의 길이만 대체 개수로 사용한다.
                result['filter_count'], result['filter_count_source'] = observed, 'complete_filter_chain'
            else:
                result['filter_count_cross_checked'] = observed == declared
                if observed != declared:
                    observations.append(observation('seccomp.filter_consistency', 'inconsistent', 'Declared count and observed filter chain disagree'))
            if result['mode'] is not None and ((result['mode'] == 2 and observed == 0) or (result['mode'] != 2 and observed != 0)):
                observations.append(observation('seccomp.mode_consistency', 'inconsistent', 'Seccomp mode and observed filter chain disagree'))
        return result

    def resource_namespaces(self, task):
        observations = []
        result = {'observations': observations}
        proxy = capture(observations, 'resource_namespaces.nsproxy', lambda: dereference(member(task, 'nsproxy'), 'nsproxy'))
        for name, field in (('mount', 'mnt_ns'), ('network', 'net_ns'), ('ipc', 'ipc_ns'), ('uts', 'uts_ns'), ('cgroup', 'cgroup_ns')):
            record = {'address': None, 'inum': None, 'owner_user_namespace_address': None, 'owner_user_namespace_inum': None}
            result[name] = record
            if proxy is None:
                continue
            namespace = capture(observations, 'namespace.' + name, lambda field=field: dereference(member(proxy, field), field))
            if namespace is None:
                continue
            record['address'] = hex(int(namespace.vol.offset))
            record['inum'] = capture(observations, 'namespace.' + name + '.inum', lambda: namespace_inum(namespace))
            owner = capture(observations, 'namespace.' + name + '.owner', lambda: dereference(member(namespace, 'user_ns'), 'namespace owner'))
            if owner is not None:
                record['owner_user_namespace_address'] = hex(int(owner.vol.offset))
                record['owner_user_namespace_inum'] = capture(observations, 'namespace.' + name + '.owner_inum', lambda: namespace_inum(owner))
        return result

    def mounts(self, task):
        observations = []
        result = {'namespace_address': None, 'task_root_mount': None, 'task_root_dentry': None,
                  'entries': [], 'errors': [], 'file_access_policy_evaluated': False, 'observations': observations}
        namespace = capture(observations, 'mounts.namespace', lambda: dereference(member(dereference(member(task, 'nsproxy'), 'nsproxy'), 'mnt_ns'), 'mount namespace'))
        root = capture(observations, 'mounts.task_root', lambda: member(dereference(member(task, 'fs'), 'fs'), 'root'))
        if namespace is not None:
            result['namespace_address'] = hex(int(namespace.vol.offset))
        if root is not None:
            result['task_root_mount'] = capture(observations, 'mounts.root_mnt', lambda: hex(int(member(root, 'mnt'))))
            result['task_root_dentry'] = capture(observations, 'mounts.root_dentry', lambda: hex(int(member(root, 'dentry'))))
        if namespace is None:
            return result
        key = (result['namespace_address'], result['task_root_mount'], result['task_root_dentry'])
        if all(key) and key in self.mount_cache:
            return self.mount_cache[key]
        def collect_mounts():
            if not hasattr(namespace, 'get_mount_points'):
                raise UnsupportedLayout('Volatility mount traversal extension unavailable')
            seen = set()
            # 순회와 경로/옵션 복원은 공식 mnt_namespace 확장·MountInfo API를 호출한다.
            # 이 마운트 정보만으로 특정 파일의 DAC/ACL·LSM 접근 허용까지 판정하지 않는다.
            for mnt in namespace.get_mount_points():
                address = int(mnt.vol.offset)
                if address in seen or len(seen) >= SAFETY_ITEMS:
                    raise InconsistentData('Invalid/oversized mount traversal')
                seen.add(address)
                record = capture(observations, 'mounts.entry.' + hex(address), lambda: mountinfo.MountInfo.get_mountinfo(mnt, task))
                if record is None:
                    result['errors'].append({'mount': hex(address), 'error': 'Mount entry unavailable; see observations'})
                else:
                    result['entries'].append({**record._asdict(), 'mount_address': hex(address)})
            return len(seen)
        capture(observations, 'mounts.traversal', collect_mounts)
        if all(key) and not result['errors'] and all(item['status'] == 'ok' for item in observations):
            self.mount_cache[key] = result
        return result


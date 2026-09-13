"""Group Docker cgroup-v2 members and read their per-task capabilities.

This is a separate user plugin. It does not modify Volatility's installed code.
Container labels come from validated cgroup/kernel links, not fixed PIDs or comm.
Docker runtime registry liveness is outside this plugin's scope.
"""
# 수집 순서: 전체 태스크 → Docker cgroup 소속 → 태스크별 보안 맥락 → 감사 JSON/표.
# 공식 PsList·MountInfo·렌더러 API를 사용하며, 원본 volatility-docker 코드를 복사하거나
# 공식 Capabilities 플러그인을 호출하지 않는다. 실제 덤프 검증 커널은 7.0.0-31-generic이다.
import datetime
import json
import logging
import re

from volatility3.framework import exceptions, interfaces, renderers
from volatility3.framework.configuration import requirements
from volatility3.framework.objects import utility
from volatility3.plugins.linux import pslist, mountinfo
from volatility3.plugins.container_support.identity import CgroupV2Resolver
from volatility3.plugins.container_support.security import SecurityReader
from volatility3.plugins.container_support.layouts import read_pid_chain, inspect_pid_layout, UnsupportedLayoutError
from volatility3.plugins.container_support.capabilities_reader import UnsupportedLayout
from volatility3.plugins.container_support import analyst

LOG = logging.getLogger(__name__)
CAP_FIELDS = ('cap_inheritable', 'cap_permitted', 'cap_effective', 'cap_bounding', 'cap_ambient')


class ContainerCaps(interfaces.plugins.PluginInterface):
    """Group Docker cgroup-v2 tasks and extract their capabilities."""
    _required_framework_version = (2, 13, 0)
    _version = (1, 4, 0)

    @classmethod
    def get_requirements(cls):
        return [
            requirements.ModuleRequirement(name='kernel', description='Linux x86-64 kernel with matching symbols and cgroup v2', architectures=['Intel64']),
            requirements.VersionRequirement(name='pslist', component=pslist.PsList, version=(4, 0, 0)),
            requirements.VersionRequirement(name='mountinfo', component=mountinfo.MountInfo, version=(1, 2, 4)),
            requirements.StringRequirement(name='container', description='Docker ID or unique hex prefix (6-64 characters)', optional=True),
            requirements.BooleanRequirement(name='leaders', description='Only process leaders; default includes threads', default=False, optional=True),
            requirements.ChoiceRequirement(name='view', description='Raw columns or evidence-based analyst report', choices=['raw', 'analyst'], default='raw', optional=True),
        ]

    def _pid_chain(self, task, module):
        return read_pid_chain(task, module)

    @staticmethod
    def _observations(member, audit, source, observations):
        """Preserve unavailable data separately from successful empty values."""
        for observation in observations:
            entry = dict(observation, source=source)
            if entry in member['observations']:
                continue
            member['observations'].append(entry)
            if entry['status'] != 'ok':
                member['Status'] = 'partial'
                detail = dict(entry, tid=member['TID'])
                audit['partial_observations'].append(detail)
                if entry['status'] in ('read_error', 'inconsistent'):
                    audit['field_errors'].append({
                        'tid': member['TID'], 'stage': source + '.' + entry['feature'],
                        'error': entry.get('reason', entry['status']), 'status': entry['status'],
                    })

    @classmethod
    def _failure(cls, member, audit, feature, exc):
        status = ('unsupported' if isinstance(exc, (AttributeError, NotImplementedError, UnsupportedLayoutError, UnsupportedLayout))
                  else 'inconsistent' if isinstance(exc, ValueError) else 'read_error')
        cause = exc
        while cause is not None:
            if isinstance(cause, exceptions.InvalidAddressException):
                status = 'read_error'
                break
            cause = cause.__cause__
        cls._observations(member, audit, feature, [{
            'feature': feature, 'status': status, 'reason': str(exc),
            'exception': type(exc).__name__,
        }])

    def _collect_security(self, task, security, member, audit):
        # Current credentials remain usable if real_cred or an optional field fails.
        # 현재 권한의 출처는 task.cred이며 real_cred는 비교 근거로 별도 보존한다.
        # 주소 차이만으로 권한 상승 이력이나 악성 행위를 판정하지 않는다.
        cred = None
        real_cred = None
        try:
            if not int(task.cred):
                raise ValueError('task.cred is a null pointer')
            member['CredAddress'] = hex(int(task.cred))
            cred = task.cred.dereference()
        except Exception as exc:
            self._failure(member, audit, 'credential_pointer', exc)
        try:
            if not int(task.real_cred):
                raise ValueError('task.real_cred is a null pointer')
            member['RealCredAddress'] = hex(int(task.real_cred))
            real_cred = task.real_cred.dereference()
            if cred is not None:
                member['CredsDiffer'] = int(task.cred) != int(task.real_cred)
        except Exception as exc:
            self._failure(member, audit, 'real_credential_pointer', exc)
        for source, pointer in (('credentials', cred), ('real_credentials', real_cred)):
            if pointer is None:
                continue
            if source == 'real_credentials' and member['CredsDiffer'] is False and 'credentials' in member:
                member[source] = member['credentials']
                continue
            try:
                member[source] = security.credentials(pointer)
                # Enrichment may fail without discarding the capabilities above.
                try:
                    security.enrich_identity(member[source], pointer)
                except Exception as exc:
                    self._failure(member, audit, source + '.identity', exc)
                self._observations(member, audit, source, member[source].get('observations', []))
            except Exception as exc:
                self._failure(member, audit, source, exc)
        current = member.get('credentials', {})
        member['EUID'] = current.get('ids_kernel', {}).get('euid')
        member['Securebits'] = current.get('securebits')
        member.update(current.get('capabilities', {}))
        member['capability_evidence'] = current.get('capability_evidence', {})
        scope = current.get('user_namespace') or {}
        member['CapabilityScope'] = scope.get('scope', 'unknown')
        chain = scope.get('chain_leaf_to_initial') or []
        if chain:
            member['UserNS'] = chain[0].get('inum')
        member['UserEUID'] = current.get('ids_in_user_namespace', {}).get('euid')
        for source, reader in (('seccomp', security.seccomp),
                               ('resource_namespaces', security.resource_namespaces),
                               ('mounts', security.mounts)):
            try:
                member[source] = reader(task)
                self._observations(member, audit, source, member[source].get('observations', []))
                if source == 'mounts' and member[source].get('errors'):
                    raise ValueError('Mount entries incomplete; see mounts.errors')
            except Exception as exc:
                self._failure(member, audit, source, exc)
        seccomp = member.get('seccomp', {})
        member['NoNewPrivs'] = seccomp.get('no_new_privs')
        member['SeccompMode'] = seccomp.get('mode')
        member['SeccompFilters'] = seccomp.get('filter_count')
        resources = member.get('resource_namespaces', {})
        member['MountNS'] = (resources.get('mount') or {}).get('inum')
        member['NetNS'] = (resources.get('network') or {}).get('inum')

    def _bytes(self, obj):
        layer = self.context.layers[obj.vol.layer_name]
        return {'virtual_address': hex(int(obj.vol.offset)), 'size': obj.vol.size,
                'bytes_hex': layer.read(obj.vol.offset, obj.vol.size, pad=False).hex()}

    def run(self):
        module = self.context.modules[self.config['kernel']]
        resolver = CgroupV2Resolver(module)
        security = SecurityReader(self.context, module)
        try:
            pid_layout = inspect_pid_layout(module)
        except UnsupportedLayoutError as exc:
            pid_layout = exc.compatibility
        prefix = self.config.get('container', '') or ''
        if prefix and not re.fullmatch(r'[0-9a-fA-F]{6,64}', prefix):
            raise ValueError('Container prefix must be 6-64 hexadecimal characters')
        prefix = prefix.lower()
        audit = {
            'created_utc': datetime.datetime.now(datetime.timezone.utc).isoformat(),
            'plugin_version': '1.4.0', 'kernel_banner': security.banner,
            'compatibility': {
                'policy': 'matching symbols; structure-selected readers; cgroup v2 and Intel64',
                'membership': resolver.compatibility,
                'pid_namespace': pid_layout,
                'security': getattr(security, 'compatibility', {}),
            },
            'credential_source': 'task.cred (subjective); task.real_cred recorded separately',
            'method': 'task.cgroups -> css_set.dfl_cgrp -> cgroup CSS/kernfs parent chains',
            'scope': 'Docker-marked cgroup-v2 paths; no Docker registry reconstruction; no paused verdict',
            'include_threads': not self.config.get('leaders', False),
            'seen_task_addresses': [], 'seen_tids': [], 'tasks_without_docker_marker': 0,
            'membership_errors': [], 'field_errors': [], 'traversal_errors': [],
            'partial_observations': [],
            'containers': [], 'members': [],
            'thread_inventory': [],
            'not_evaluated': ['LSM policies', 'seccomp BPF rule outcomes', 'per-file DAC/ACL and idmapped-mount decisions'],
        }
        seen = set()
        found_groups = {}
        all_tids_by_pid = {}
        try:
            # 공식 열거 API를 직접 호출한다. 기본값은 스레드 포함이며, 이 목록 밖의
            # 은닉·연결 해제 태스크까지 복구했다고 주장할 수는 없다.
            tasks = pslist.PsList.list_tasks(self.context, self.config['kernel'], include_threads=audit['include_threads'])
            for task in tasks:
                address = int(task.vol.offset)
                if address in seen:
                    continue
                seen.add(address)
                tid = int(task.pid)
                tgid = int(task.tgid)
                all_tids_by_pid.setdefault(tgid, set()).add(tid)
                audit['seen_task_addresses'].append(hex(address))
                audit['seen_tids'].append(tid)
                try:
                    cset, cgroup, chain, group = resolver.resolve(task)
                    key = int(cgroup.vol.offset)
                    if group is None:
                        audit['tasks_without_docker_marker'] += 1
                        continue
                except Exception as exc:
                    audit['membership_errors'].append({'pid': tgid, 'tid': tid, 'task': hex(address), 'error': str(exc)})
                    continue
                # 같은 ID 표식이라도 다른 cgroup 객체는 합치지 않는다.
                group_key = (group['id'], group['root_address'])
                found_groups[group_key] = group
                member = {
                    'ContainerID': group['id'], 'ContainerRoot': group['root_address'],
                    'ContainerPath': group['root_path'], 'CgroupPath': '/' + '/'.join(x['name'] for x in chain if x['name']),
                    'PID': tgid, 'TID': tid, 'Name': utility.array_to_string(task.comm),
                    'TaskAddress': hex(address), 'CssSetAddress': hex(int(cset.vol.offset)),
                    'CgroupAddress': hex(key), 'PIDNS': None, 'NSPID': None, 'NSTID': None,
                    'UserNS': None, 'EUID': None, 'Status': 'ok',
                    'UserEUID': None, 'CapabilityScope': 'unknown', 'CredSource': 'task.cred',
                    'CredsDiffer': None, 'NoNewPrivs': None, 'SeccompMode': None,
                    'SeccompFilters': None, 'Securebits': None, 'MountNS': None, 'NetNS': None,
                    'ExpectedThreads': None,
                    'cgroup_chain': chain, 'capability_evidence': {}, 'observations': [],
                }
                for field in CAP_FIELDS:
                    member[field] = None
                try:
                    pid_chain = self._pid_chain(task, module)
                    leader_chain = self._pid_chain(task.group_leader.dereference(), module)
                    member['pid_chain'] = pid_chain
                    member['PIDNS'] = pid_chain[-1]['namespace']
                    member['NSTID'] = pid_chain[-1]['id']
                    member['NSPID'] = next(x['id'] for x in leader_chain if x['namespace'] == member['PIDNS'])
                except Exception as exc:
                    self._failure(member, audit, 'pid_namespace', exc)
                else:
                    self._observations(member, audit, 'pid_namespace', [{'feature': 'pid_namespace', 'status': 'ok',
                        'layout': 'thread_pid' if task.has_member('thread_pid') else 'pids[PIDTYPE_PID]'}])
                self._collect_security(task, security, member, audit)
                try:
                    member['ExpectedThreads'] = int(task.signal.nr_threads)
                except Exception as exc:
                    self._failure(member, audit, 'thread_count', exc)
                audit['members'].append(member)
        except Exception as exc:
            audit['traversal_errors'].append(str(exc))

        ids = {key[0] for key in found_groups if key[0].startswith(prefix)}
        if prefix and len(ids) > 1:
            raise ValueError('Container prefix is ambiguous; supply more characters')
        selected = [m for m in audit['members'] if m['ContainerID'].startswith(prefix)]
        selected.sort(key=lambda m: (m['ContainerID'], m['ContainerRoot'], m['PID'], m['TID']))
        audit['containers'] = sorted(found_groups.values(), key=lambda g: (g['id'], g['root_address']))
        audit['selected_prefix'] = prefix
        audit['selected_tasks'] = len(selected)
        audit['selected_containers'] = len({(m['ContainerID'], m['ContainerRoot']) for m in selected})
        audit['enumerated_tasks'] = len(seen)
        audit['discovered_docker_tasks'] = len(audit['members'])
        for pid in sorted({m['PID'] for m in audit['members']}):
            members = [m for m in audit['members'] if m['PID'] == pid]
            expected = {m['ExpectedThreads'] for m in members if m['ExpectedThreads'] is not None}
            observed = sorted(all_tids_by_pid[pid])
            can_compare = audit['include_threads'] and len(expected) == 1 and all(m['ExpectedThreads'] is not None for m in members)
            count_matches = len(observed) == next(iter(expected)) if can_compare else None
            audit['thread_inventory'].append({'pid': pid, 'observed_tids_all_cgroups': observed,
                                              'expected_counts': sorted(expected), 'count_matches': count_matches,
                                              'container_member_tids': sorted(m['TID'] for m in members)})
            if count_matches is False:
                for member in members:
                    self._observations(member, audit, 'thread_inventory', [{'feature': 'thread_coverage',
                        'status': 'inconsistent', 'reason': 'Observed TIDs and signal.nr_threads disagree'}])
        audit['coverage_complete_within_enumerated_tasks'] = not (audit['membership_errors'] or audit['traversal_errors'])
        # self.open은 Volatility 출력 디렉터리(-o)를 따른다. 화면을 줄여도 원시 근거는
        # 감사 JSON에 남기며, analyst JSON에는 집합 비교와 확인 항목을 추가한다.
        with self.open('containercaps-audit.json') as handle:
            handle.write(json.dumps(audit, ensure_ascii=False, indent=2).encode('utf-8'))
        if audit['membership_errors'] or audit['field_errors'] or audit['traversal_errors']:
            LOG.warning('ContainerCaps: incomplete observations; inspect containercaps-audit.json (%d membership, %d field, %d traversal errors)', len(audit['membership_errors']), len(audit['field_errors']), len(audit['traversal_errors']))
        if self.config.get('view', 'raw') == 'analyst':
            report = analyst.build_report(audit, selected)
            with self.open('containercaps-analyst.json') as handle:
                handle.write(json.dumps(report, ensure_ascii=False, indent=2).encode('utf-8'))
            return renderers.TreeGrid([(name, str) for name in analyst.SUMMARY_COLUMNS],
                                      ((0, row) for row in analyst.summary_rows(report)))
        columns = [('ContainerID', str), ('ContainerRoot', str), ('CgroupPath', str),
                   ('PID', int), ('TID', int), ('Name', str), ('NSPID', int), ('NSTID', int),
                   ('PIDNS', int), ('UserNS', int), ('EUID', int), ('UserEUID', int),
                   ('CapabilityScope', str), ('CredSource', str), ('CredsDiffer', bool),
                   ('NoNewPrivs', bool), ('SeccompMode', int), ('SeccompFilters', int),
                   ('Securebits', int), ('MountNS', int), ('NetNS', int), ('Status', str)] + [(x, str) for x in CAP_FIELDS]
        def generate():
            for member in selected:
                values = tuple(member[key] if member[key] is not None else renderers.NotAvailableValue() for key, _ in columns)
                yield 0, values
        return renderers.TreeGrid(columns, generate())

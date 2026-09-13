"""Regression checks for preserving partial CAPS results and display states.

Security readers are stubs: these tests exercise collection and presentation,
not a kernel memory fixture or an unfinished security-reader implementation.
"""

from copy import deepcopy
from pathlib import Path
from types import SimpleNamespace
import sys
import unittest

BASE = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(BASE))
import volatility3.plugins
volatility3.plugins.__path__.insert(0, str(BASE / 'plugins'))
from volatility3.framework import exceptions
from volatility3.plugins.containercaps import CAP_FIELDS, ContainerCaps
from volatility3.plugins.container_support.capabilities_reader import UnsupportedLayout
from volatility3.plugins.container_support.layouts import UnsupportedLayoutError
from container_caps import capability_text, compatibility_summary


class Pointer:
    def __init__(self, address, target, error=None):
        self.address, self.target, self.error = address, target, error

    def __int__(self):
        if self.error:
            raise self.error
        return self.address

    def dereference(self):
        if self.error:
            raise self.error
        return self.target


class SecurityStub:
    def __init__(self):
        self.current = {
            'ids_kernel': {'euid': 1000}, 'securebits': 0,
            'capabilities': {field: ('chown' if field == 'cap_effective' else '') for field in CAP_FIELDS},
            'capability_evidence': {'cap_effective': {'raw_mask': '0x1'}},
            'observations': [],
        }
        self.real = deepcopy(self.current)
        self.real['ids_kernel']['euid'] = 0
        self.real['capabilities']['cap_effective'] = 'all'
        self.fail = {}
        self.seccomp_result = {'mode': 2, 'filter_count': 1, 'no_new_privs': False, 'observations': []}
        self.resources = {'mount': {'inum': 30}, 'network': {'inum': 40}, 'observations': []}
        self.mount_result = {'entries': [], 'errors': [], 'observations': []}

    def failure(self, key):
        if key in self.fail:
            raise self.fail[key]

    def credentials(self, pointer):
        self.failure(pointer.kind)
        return deepcopy(self.current if pointer.kind == 'current' else self.real)

    def enrich_identity(self, result, pointer):
        self.failure('identity')
        result['user_namespace'] = {'scope': 'initial_user_namespace', 'chain_leaf_to_initial': [{'inum': 20}]}
        result['ids_in_user_namespace'] = {'euid': result['ids_kernel']['euid']}

    def seccomp(self, task):
        self.failure('seccomp')
        return deepcopy(self.seccomp_result)

    def resource_namespaces(self, task):
        self.failure('resources')
        return deepcopy(self.resources)

    def mounts(self, task):
        self.failure('mounts')
        return deepcopy(self.mount_result)


class CollectionTests(unittest.TestCase):
    def setUp(self):
        self.plugin = ContainerCaps.__new__(ContainerCaps)
        self.security = SecurityStub()
        self.task = SimpleNamespace(
            cred=Pointer(100, SimpleNamespace(kind='current')),
            real_cred=Pointer(200, SimpleNamespace(kind='real')),
        )
        self.member = dict.fromkeys(CAP_FIELDS)
        self.member.update({'TID': 17, 'PID': 17, 'Status': 'ok', 'CredsDiffer': None,
                            'UserNS': None, 'observations': []})
        self.audit = {'partial_observations': [], 'field_errors': [], 'members': [self.member]}

    def collect(self):
        self.plugin._collect_security(self.task, self.security, self.member, self.audit)

    def assert_caps_preserved(self):
        self.assertEqual({field: self.member[field] for field in CAP_FIELDS}, self.security.current['capabilities'])
        self.assertEqual(self.member['EUID'], 1000)
        self.assertEqual(self.member['capability_evidence']['cap_effective']['raw_mask'], '0x1')

    def test_unreadable_real_cred_pointer_keeps_current_capabilities(self):
        self.task.real_cred.error = exceptions.InvalidAddressException('synthetic', 200, 'unreadable pointer')
        self.collect()
        self.assert_caps_preserved()
        self.assertIsNone(self.member['CredsDiffer'])
        self.assertEqual(self.member['Status'], 'partial')
        self.assertEqual(self.audit['field_errors'][0]['status'], 'read_error')

    def test_failure_reading_real_credentials_does_not_replace_current(self):
        self.security.fail['real'] = exceptions.InvalidAddressException('synthetic', 200, 'unreadable credentials')
        self.collect()
        self.assert_caps_preserved()
        self.assertTrue(self.member['CredsDiffer'])
        self.assertNotIn('real_credentials', self.member)

    def test_current_failure_does_not_substitute_real_credentials(self):
        self.security.fail['current'] = exceptions.InvalidAddressException('synthetic', 100, 'current unavailable')
        self.collect()
        self.assertTrue(all(self.member[field] is None for field in CAP_FIELDS))
        self.assertIsNone(self.member['EUID'])
        self.assertEqual(self.member['real_credentials']['capabilities']['cap_effective'], 'all')

    def test_optional_identity_seccomp_namespace_and_mount_errors_keep_all_sets(self):
        self.security.fail.update({
            'identity': NotImplementedError('unknown UID mapping layout'),
            'seccomp': NotImplementedError('unknown seccomp layout'),
            'resources': AttributeError('network namespace field absent'),
            'mounts': exceptions.InvalidAddressException('synthetic', 300, 'mount page absent'),
        })
        self.collect()
        self.assert_caps_preserved()
        self.assertEqual(self.member['CapabilityScope'], 'unknown')
        self.assertIsNone(self.member['SeccompMode'])
        self.assertIsNone(self.member['MountNS'])
        self.assertEqual(self.member['Status'], 'partial')

    def test_one_missing_set_and_one_empty_set_remain_distinct(self):
        self.security.current['capabilities']['cap_ambient'] = None
        self.security.current['observations'] = [{
            'feature': 'cap_ambient', 'status': 'not_present', 'reason': 'field absent in symbols',
        }]
        self.collect()
        self.assertEqual(capability_text(self.member, 'cap_inheritable'), '<없음>')
        self.assertEqual(capability_text(self.member, 'cap_ambient'), '<필드 없음>')
        self.assertEqual(capability_text(self.member, 'cap_effective'), 'chown')
        self.assertEqual(self.audit['field_errors'], [])
        self.assertEqual(self.member['Status'], 'partial')

    def test_no_new_privs_survives_unavailable_seccomp_fields(self):
        self.security.seccomp_result = {
            'mode': None, 'filter_count': None, 'no_new_privs': True,
            'observations': [{'feature': 'seccomp_mode', 'status': 'unsupported', 'reason': 'layout unknown'}],
        }
        self.collect()
        self.assert_caps_preserved()
        self.assertTrue(self.member['NoNewPrivs'])
        self.assertIsNone(self.member['SeccompMode'])
        self.assertIsNone(self.member['SeccompFilters'])

    def test_false_no_new_privs_and_zero_seccomp_are_not_missing(self):
        self.security.seccomp_result = {'mode': 0, 'filter_count': 0, 'no_new_privs': False}
        self.collect()
        self.assertIs(self.member['NoNewPrivs'], False)
        self.assertEqual(self.member['SeccompMode'], 0)
        self.assertEqual(self.member['SeccompFilters'], 0)

    def test_available_mount_namespace_survives_missing_network_namespace(self):
        self.security.resources = {'mount': {'inum': 30}, 'network': None, 'observations': [
            {'feature': 'network_namespace', 'status': 'unsupported', 'reason': 'unknown field'},
        ]}
        self.collect()
        self.assertEqual(self.member['MountNS'], 30)
        self.assertIsNone(self.member['NetNS'])
        self.assert_caps_preserved()

    def test_unknown_capability_name_keeps_value_and_reports_partial(self):
        self.security.current['capabilities']['cap_effective'] = 'chown, CAP_BIT_45'
        self.security.current['observations'] = [{
            'feature': 'capability_names', 'status': 'unsupported',
            'reason': 'name dictionary lacks bit 45', 'layout': 'val_u64',
        }]
        self.collect()
        self.assertEqual(capability_text(self.member, 'cap_effective'), 'chown, CAP_BIT_45')
        self.assertEqual(self.member['Status'], 'partial')
        self.assertEqual(self.audit['field_errors'], [])
        self.assertEqual(self.audit['partial_observations'][0]['tid'], 17)

    def test_repeated_observations_are_deduplicated_per_source(self):
        observation = {'feature': 'cap_ambient', 'status': 'read_error', 'reason': 'missing page'}
        self.plugin._observations(self.member, self.audit, 'credentials', [observation, observation])
        self.plugin._observations(self.member, self.audit, 'credentials', [observation])
        self.assertEqual(len(self.member['observations']), 1)
        self.assertEqual(len(self.audit['partial_observations']), 1)
        self.assertEqual(len(self.audit['field_errors']), 1)
        self.assertEqual(capability_text(self.member, 'cap_ambient'), '<읽기 실패>')

    def test_typed_unsupported_errors_are_not_read_errors_or_inconsistencies(self):
        errors = [UnsupportedLayout('unknown capability shape'),
                  UnsupportedLayoutError('pid_namespace', 'task_struct.thread_pid', 'layout unknown')]
        for error in errors:
            with self.subTest(error=type(error).__name__):
                member = {'TID': 17, 'Status': 'ok', 'observations': []}
                audit = {'partial_observations': [], 'field_errors': []}
                self.plugin._failure(member, audit, 'optional_feature', error)
                self.assertEqual(member['observations'][0]['status'], 'unsupported')
                self.assertEqual(audit['field_errors'], [])

    def test_compatibility_summary_counts_tasks_and_keeps_sources_and_layouts(self):
        observation = {'source': 'credentials', 'feature': 'cap_effective', 'status': 'ok',
                       'layout': {'kind': 'val', 'width': 64}, 'reason': 'read'}
        self.member['observations'] = [observation, dict(observation)]
        second = {'TID': 18, 'observations': [dict(observation, reason='another read'),
                    dict(observation, source='real_credentials'),
                    dict(observation, status='unsupported', layout=None, reason='unknown layout')]}
        summary = compatibility_summary({'members': [self.member, second]})
        self.assertEqual(len(summary), 3)
        current_ok = next(item for item in summary if item['source'] == 'credentials' and item['status'] == 'ok')
        self.assertEqual(current_ok['tasks'], 2)
        self.assertEqual(current_ok['reasons'], ['another read', 'read'])
        self.assertEqual(next(item for item in summary if item['source'] == 'real_credentials')['tasks'], 1)

    def test_old_saved_member_without_observations_has_unknown_not_empty_label(self):
        self.assertEqual(capability_text({'cap_ambient': None}, 'cap_ambient'), '<읽기 실패/미지원>')
        self.assertEqual(compatibility_summary({'members': [{'TID': 17}]}), [])


if __name__ == '__main__':
    unittest.main()

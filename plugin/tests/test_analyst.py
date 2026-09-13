"""Synthetic analyst-view regressions; these do not validate another kernel.

The fixtures intentionally contain no capture-specific PIDs or container IDs.
These checks exercise interpretation boundaries: unavailable evidence must stay
unknown, and a recorded capability difference is not proof of exploitation.
"""
from copy import deepcopy
from pathlib import Path
import sys
import unicodedata
import unittest

BASE = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(BASE / 'plugins'))
from container_support.analyst import build_report, format_report, format_summary, summary_rows


CAPS = ('cap_inheritable', 'cap_permitted', 'cap_effective', 'cap_bounding', 'cap_ambient')


def member(pid=101, tid=None, container_id='a' * 64, root='0x1000', **changes):
    """An observed task with confirmed empty capability sets by default."""
    item = {
        'ContainerID': container_id, 'ContainerRoot': root,
        'ContainerPath': '/docker/' + container_id,
        'CgroupPath': '/docker/' + container_id,
        'PID': pid, 'TID': pid if tid is None else tid, 'Name': 'synthetic',
        'NSPID': 1, 'NSTID': 1 if tid is None else tid, 'PIDNS': 11,
        'UserNS': 12, 'EUID': 0, 'UserEUID': 0,
        'CapabilityScope': 'initial_user_namespace', 'CredSource': 'task.cred',
        'CredsDiffer': False, 'NoNewPrivs': False, 'SeccompMode': 2,
        'SeccompFilters': 1, 'Securebits': 0, 'MountNS': 13, 'NetNS': 14,
        'ExpectedThreads': 1, 'Status': 'ok', 'observations': [],
        'capability_evidence': {},
    }
    for field in CAPS:
        item[field] = ''
        item['capability_evidence'][field] = {
            'raw_mask': '0x0', 'decoded_mask': '0x0', 'names': [],
            'unknown_bits': '0x0', 'out_of_range_bits': '0x0',
        }
    item.update(changes)
    return item


def set_mask(item, field, mask, names=()):
    evidence = item['capability_evidence'][field]
    evidence['raw_mask'] = None if mask is None else hex(mask)
    evidence['decoded_mask'] = None if mask is None else hex(mask)
    evidence['names'] = list(names)
    item[field] = None if mask is None else ', '.join(names)


def audit_for(members, **changes):
    result = {
        'plugin_version': '1.3.0', 'members': members, 'include_threads': True,
        'membership_errors': [], 'field_errors': [], 'traversal_errors': [],
        'partial_observations': [], 'thread_inventory': [],
        'enumerated_tasks': len(members), 'discovered_docker_tasks': len(members),
        'tasks_without_docker_marker': 0, 'selected_tasks': len(members),
        'selected_containers': len({(m['ContainerID'], m['ContainerRoot']) for m in members}),
        'coverage_complete_within_enumerated_tasks': True,
    }
    result.update(changes)
    return result


def report_for(*members, **audit_changes):
    return build_report(audit_for(list(members), **audit_changes), list(members))


def first_task(report):
    return report['groups'][0]['members'][0]


def codes(task):
    return {check['code'] for check in task['checks']}


class AnalystTests(unittest.TestCase):
    def test_confirmed_zero_is_empty_and_comparable(self):
        task = first_task(report_for(member()))
        self.assertIn('EFFECTIVE_EMPTY', codes(task))
        self.assertEqual(task['effective_names'], [])
        self.assertEqual(task['deltas']['permitted_not_effective'], 0)
        self.assertEqual(task['deltas']['effective_not_permitted'], 0)
        self.assertEqual(task['deltas']['ambient_outside_pi'], 0)

    def test_missing_raw_mask_is_not_confirmed_empty(self):
        item = member()
        del item['capability_evidence']['cap_effective']['raw_mask']
        task = first_task(report_for(item))
        self.assertNotIn('EFFECTIVE_EMPTY', codes(task))
        self.assertIsNone(task['deltas']['permitted_not_effective'])
        self.assertIsNone(task['deltas']['effective_not_permitted'])
        comparison = report_for(item)['groups'][0]['comparisons'][0]
        self.assertIn('cap_effective', comparison['unknown_fields'])

    def test_decoded_mask_is_not_substituted_for_raw_mask(self):
        item = member()
        evidence = item['capability_evidence']['cap_effective']
        evidence['raw_mask'] = None
        evidence['decoded_mask'] = '0x0'
        task = first_task(report_for(item))
        self.assertNotIn('EFFECTIVE_EMPTY', codes(task))
        self.assertIsNone(task['deltas']['effective_not_permitted'])

    def test_display_all_without_raw_evidence_does_not_invent_mask(self):
        item = member()
        item['capability_evidence'] = {}
        for field in CAPS:
            item[field] = 'all'
        result = report_for(item)
        task = first_task(result)
        self.assertNotIn('EFFECTIVE_EMPTY', codes(task))
        self.assertNotIn('CAP_REVIEW', codes(task))
        self.assertTrue(all(value is None for value in task['deltas'].values()))
        self.assertTrue(set(CAPS).issubset(result['groups'][0]['comparisons'][0]['unknown_fields']))

    def test_malformed_raw_masks_remain_unknown(self):
        for raw in ('garbage', '', '-0x1', None):
            with self.subTest(raw=raw):
                item = member()
                item['capability_evidence']['cap_effective']['raw_mask'] = raw
                task = first_task(report_for(item))
                self.assertNotIn('EFFECTIVE_EMPTY', codes(task))
                self.assertIsNone(task['deltas']['effective_not_permitted'])

    def test_permitted_but_inactive_bits_are_reported(self):
        item = member()
        set_mask(item, 'cap_permitted', 0x1001, ('chown', 'net_admin'))
        set_mask(item, 'cap_effective', 1, ('chown',))
        task = first_task(report_for(item))
        self.assertEqual(task['deltas']['permitted_not_effective'], 0x1000)
        self.assertIn('PERMITTED_INACTIVE', codes(task))
        self.assertNotIn('EFFECTIVE_OUTSIDE_PERMITTED', codes(task))

    def test_effective_outside_permitted_is_reported(self):
        item = member()
        set_mask(item, 'cap_permitted', 1, ('chown',))
        set_mask(item, 'cap_effective', 0x1001, ('chown', 'net_admin'))
        task = first_task(report_for(item))
        self.assertEqual(task['deltas']['effective_not_permitted'], 0x1000)
        self.assertIn('EFFECTIVE_OUTSIDE_PERMITTED', codes(task))

    def test_ambient_must_be_in_both_permitted_and_inheritable(self):
        item = member()
        set_mask(item, 'cap_permitted', 0b111)
        set_mask(item, 'cap_inheritable', 0b011)
        set_mask(item, 'cap_ambient', 0b101)
        task = first_task(report_for(item))
        self.assertEqual(task['deltas']['ambient_outside_pi'], 0b100)
        self.assertIn('AMBIENT_OUTSIDE_PI', codes(task))

    def test_missing_ambient_operand_prevents_subset_verdict(self):
        item = member()
        set_mask(item, 'cap_inheritable', None)
        set_mask(item, 'cap_ambient', 1, ('chown',))
        task = first_task(report_for(item))
        self.assertIsNone(task['deltas']['ambient_outside_pi'])
        self.assertNotIn('AMBIENT_OUTSIDE_PI', codes(task))

    def test_effective_outside_bounding_is_not_invalid_state(self):
        item = member()
        set_mask(item, 'cap_permitted', 1, ('chown',))
        set_mask(item, 'cap_effective', 1, ('chown',))
        set_mask(item, 'cap_bounding', 0)
        task = first_task(report_for(item))
        invalid_codes = {code for code in codes(task) if 'INVALID' in code or 'OUTSIDE' in code}
        self.assertEqual(invalid_codes, set())
        self.assertEqual(task['deltas']['effective_not_permitted'], 0)

    def test_unknown_and_out_of_range_bits_are_independent(self):
        item = member()
        evidence = item['capability_evidence']['cap_bounding']
        evidence['raw_mask'] = hex(1 << 52)
        evidence['unknown_bits'] = hex(1 << 52)
        evidence['out_of_range_bits'] = '0x0'
        self.assertIn('UNKNOWN_BITS', codes(first_task(report_for(item))))
        self.assertNotIn('OUT_OF_RANGE_BITS', codes(first_task(report_for(item))))
        evidence['unknown_bits'] = '0x0'
        evidence['out_of_range_bits'] = hex(1 << 52)
        self.assertIn('OUT_OF_RANGE_BITS', codes(first_task(report_for(item))))
        self.assertNotIn('UNKNOWN_BITS', codes(first_task(report_for(item))))

    def test_confirmed_zero_metadata_does_not_create_unknown_bit_finding(self):
        task = first_task(report_for(member()))
        self.assertNotIn('UNKNOWN_BITS', codes(task))
        self.assertNotIn('OUT_OF_RANGE_BITS', codes(task))

    def test_explicit_review_capability_names_are_visible(self):
        for name in ('sys_admin', 'sys_module', 'sys_ptrace', 'sys_rawio',
                     'dac_read_search', 'net_admin', 'bpf', 'perfmon',
                     'checkpoint_restore'):
            with self.subTest(name=name):
                item = member()
                set_mask(item, 'cap_permitted', 1, (name,))
                set_mask(item, 'cap_effective', 1, (name,))
                task = first_task(report_for(item))
                self.assertIn('CAP_REVIEW', codes(task))
                self.assertIn(name, task['effective_names'])

    def test_ordinary_capability_is_not_review_finding(self):
        item = member()
        set_mask(item, 'cap_permitted', 1, ('chown',))
        set_mask(item, 'cap_effective', 1, ('chown',))
        self.assertNotIn('CAP_REVIEW', codes(first_task(report_for(item))))

    def test_credential_pointer_difference_is_an_observation(self):
        task = first_task(report_for(member(CredsDiffer=True)))
        self.assertIn('CREDS_DIFFER', codes(task))
        self.assertFalse(any('ESCALAT' in code or 'COMPROMIS' in code for code in codes(task)))

    def test_only_confirmed_seccomp_zero_is_off(self):
        self.assertIn('SECCOMP_OFF', codes(first_task(report_for(member(SeccompMode=0)))))
        self.assertNotIn('SECCOMP_OFF', codes(first_task(report_for(member(SeccompMode=None)))))
        self.assertNotIn('SECCOMP_OFF', codes(first_task(report_for(member(SeccompMode=2)))))

    def test_partial_status_and_non_ok_observations_surface_quality(self):
        items = [member(Status='partial'), member(observations=[{
            'feature': 'cap_effective', 'source': 'credentials',
            'status': 'read_error', 'reason': 'synthetic missing page',
        }])]
        for item in items:
            with self.subTest(item=item):
                self.assertIn('PARTIAL_DATA', codes(first_task(report_for(item))))

    def test_same_container_identifier_different_root_is_not_merged(self):
        result = report_for(member(root='0x1000'), member(pid=201, root='0x2000'))
        self.assertEqual(len(result['groups']), 2)
        self.assertEqual({group['root_address'] for group in result['groups']}, {'0x1000', '0x2000'})
        self.assertTrue(all(len(group['members']) == 1 for group in result['groups']))

    def test_thread_comparison_preserves_difference_and_unknown_together(self):
        first, second, third = member(tid=101), member(tid=102), member(tid=103)
        for item in (first, second, third):
            item['ExpectedThreads'] = 3
        set_mask(first, 'cap_effective', 1, ('chown',))
        set_mask(second, 'cap_effective', 0)
        set_mask(third, 'cap_effective', None)
        result = report_for(first, second, third)
        comparison = result['groups'][0]['comparisons'][0]
        self.assertEqual(comparison['pid'], 101)
        self.assertIn('cap_effective', comparison['different_fields'])
        self.assertIn('cap_effective', comparison['unknown_fields'])
        self.assertEqual(len(result['groups'][0]['members']), 3)

    def test_equal_display_labels_do_not_hide_raw_thread_differences(self):
        first, second = member(tid=101), member(tid=102)
        set_mask(first, 'cap_effective', 1)
        set_mask(second, 'cap_effective', 2)
        first['cap_effective'] = second['cap_effective'] = 'all'
        comparison = report_for(first, second)['groups'][0]['comparisons'][0]
        self.assertIn('cap_effective', comparison['different_fields'])

    def test_quality_counts_are_preserved_without_fabricated_verdicts(self):
        result = report_for(member(), membership_errors=[{}, {}], field_errors=[{}],
                            traversal_errors=[{}, {}, {}], partial_observations=[{}])
        self.assertEqual(result['quality'], {
            'membership_errors': 2, 'field_errors': 1,
            'traversal_errors': 3, 'partial_observations': 1,
        })
        task = first_task(result)
        self.assertFalse(any('PRIVILEGED' in code or 'DOCKER_DEFAULT' in code for code in codes(task)))

    def test_report_does_not_modify_evidence(self):
        items = [member(CredsDiffer=True)]
        audit = audit_for(items)
        before = deepcopy(audit)
        build_report(audit, items)
        self.assertEqual(audit, before)

    def test_equal_seccomp_mode_and_count_do_not_hide_filter_chain_difference(self):
        first, second = member(tid=101), member(tid=102)
        first['seccomp'] = {'chain_complete': True, 'filters': [{'address': '0x8000'}]}
        second['seccomp'] = {'chain_complete': True, 'filters': [{'address': '0x9000'}]}
        comparison = report_for(first, second)['groups'][0]['comparisons'][0]
        self.assertIn('seccomp_filter_chain', comparison['different_fields'])
        self.assertNotIn('seccomp_filter_chain', comparison['unknown_fields'])
        self.assertNotIn('SeccompMode', comparison['different_fields'])
        self.assertNotIn('SeccompFilters', comparison['different_fields'])

    def test_incomplete_seccomp_filter_chain_remains_unknown(self):
        first, second = member(tid=101), member(tid=102)
        first['seccomp'] = {'chain_complete': True, 'filters': [{'address': '0x8000'}]}
        second['seccomp'] = {'chain_complete': False, 'filters': [{'address': '0x8000'}]}
        comparison = report_for(first, second)['groups'][0]['comparisons'][0]
        self.assertIn('seccomp_filter_chain', comparison['unknown_fields'])
        self.assertNotIn('seccomp_filter_chain', comparison['different_fields'])

    def test_terminal_view_wraps_wide_text_and_escapes_memory_controls(self):
        item = member(Name='분석프로세스' * 30 + '\x1b[2J\r\n\t\u202e')
        item['ContainerPath'] = '/docker/' + ('long-path-segment/' * 40)
        item['observations'] = [{
            'source': 'credentials\x1b[0m', 'feature': 'cap_effective\x07',
            'status': 'read_error', 'reason': 'synthetic',
        }]
        text = format_report(report_for(item), width=80)
        for line in text.splitlines():
            # Fixture text has no combining marks; count CJK characters as two cells.
            occupied = sum(2 if unicodedata.east_asian_width(char) in ('W', 'F') else 1
                           for char in line)
            self.assertLessEqual(occupied, 80, line)
        for control in ('\x1b', '\r', '\t', '\u202e', '\x07'):
            self.assertNotIn(control, text)
        self.assertIn('\\x1b', text)

    def test_summary_names_are_short_and_larger_sets_use_raw_bit_count(self):
        examples = ((1, ('chown',), 'CHOWN'),
                    (0x1001, ('chown', 'net_admin'), 'CHOWN,NET_ADMIN'),
                    (7, ('chown', 'dac_override', 'dac_read_search'), '원시 3비트'))
        for mask, names, expected in examples:
            with self.subTest(names=names):
                item = member()
                set_mask(item, 'cap_effective', mask, names)
                set_mask(item, 'cap_permitted', mask, names)
                row = list(summary_rows(report_for(item)))[0]
                self.assertEqual(row[3], expected)

    def test_summary_duplicate_identifier_roots_have_distinct_labels(self):
        items = (member(root='0x1000'), member(pid=201, root='0x2000'))
        rows = list(summary_rows(report_for(*items)))
        self.assertEqual(len(rows), 2)
        self.assertNotEqual(rows[0][0], rows[1][0])
        self.assertTrue(all(row[0].startswith('a' * 12) for row in rows))

    def test_summary_partial_unknown_effective_is_not_empty(self):
        item = member(Status='partial')
        set_mask(item, 'cap_effective', None)
        row = list(summary_rows(report_for(item)))[0]
        self.assertEqual(row[3], '미확인')
        self.assertEqual(row[6], '부분/미확인')
        confirmed = list(summary_rows(report_for(member())))[0]
        self.assertEqual(confirmed[3], '없음')
        text = format_summary(report_for(item))
        self.assertIn('부분/미확인', text)

    def test_summary_check_retains_detected_thread_difference(self):
        first, second = member(tid=101), member(tid=102)
        set_mask(first, 'cap_effective', 1, ('chown',))
        set_mask(first, 'cap_permitted', 1, ('chown',))
        rows = list(summary_rows(report_for(first, second)))
        self.assertEqual(len(rows), 2)
        self.assertTrue(all('차이' in row[6] for row in rows))

    def test_summary_has_exactly_one_seven_column_row_per_observed_task(self):
        items = (member(tid=101), member(tid=102),
                 member(pid=201, container_id='b' * 64, root='0x2000'))
        rows = list(summary_rows(report_for(*items)))
        self.assertEqual(len(rows), len(items))
        self.assertTrue(all(len(row) == 7 for row in rows))
        self.assertEqual({row[1] for row in rows}, {'101/101', '101/102', '201/201'})
        self.assertEqual(list(summary_rows(report_for())), [])


if __name__ == '__main__':
    unittest.main()

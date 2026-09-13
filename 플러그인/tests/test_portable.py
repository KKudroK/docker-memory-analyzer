"""Portable CLI regression tests; all evidence in this file is synthetic."""
import json
from pathlib import Path
import os
import shutil
import subprocess
import sys
import tempfile
import unittest

BASE = Path(__file__).resolve().parents[1]
FIELDS = ('cap_inheritable', 'cap_permitted', 'cap_effective', 'cap_bounding', 'cap_ambient')


class PortableTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='caps test 한글 ')
        self.root = Path(self.temp.name)
        self.results = self.root / 'results'
        self.run = self.results / 'sample'
        self.run.mkdir(parents=True)
        members = []
        for cid, root, pid, tid, cap in [('a' * 64, '0x100', 110, 110, 'chown'),
                                         ('a' * 64, '0x100', 110, 111, ''),
                                         ('a' * 64, '0x100', 112, 112, 'net_admin'),
                                         ('b' * 64, '0x200', 210, 210, 'bpf')]:
            member = {'ContainerID': cid, 'ContainerRoot': root, 'ContainerPath': '/docker/' + cid,
                      'PID': pid, 'TID': tid, 'Name': 'same-name', 'NSPID': 1 if pid % 10 == 0 else 2,
                      'NSTID': tid % 100, 'EUID': 0, 'PIDNS': 55 if cid[0] == 'a' else 66,
                      'UserNS': 77, 'Status': 'ok'}
            member.update({field: cap for field in FIELDS})
            members.append(member)
        self.audit = {'include_threads': True, 'members': members, 'created_utc': 'synthetic fixture',
                      'enumerated_tasks': 10, 'tasks_without_docker_marker': 6, 'discovered_docker_tasks': 4,
                      'scope': 'synthetic test only', 'membership_errors': [], 'field_errors': [], 'traversal_errors': []}
        self.save()
        (self.results / 'latest.json').write_text(json.dumps({'directory': 'sample'}), encoding='utf-8')

    def tearDown(self):
        self.temp.cleanup()

    def save(self):
        (self.run / 'containercaps-audit.json').write_text(json.dumps(self.audit), encoding='utf-8')

    def cli(self, *args, script=None):
        env = {key: value for key, value in os.environ.items() if key not in ('CAPS_DUMP', 'CAPS_SYMBOLS', 'DUMP', 'SYMBOLS')}
        return subprocess.run([sys.executable, '-X', 'utf8', str(script or BASE / 'container_caps.py'), *args],
                              cwd=self.root, env=env, capture_output=True, text=True, encoding='utf-8')

    def test_explicit_inputs_required(self):
        result = self.cli()
        self.assertEqual(result.returncode, 2)
        self.assertIn('--dump', result.stderr)

    def test_two_containers_all_members_and_distinct_capabilities(self):
        result = self.cli('--saved', '--output-root', str(self.results), '--json')
        self.assertEqual(result.returncode, 0, result.stderr)
        groups = json.loads(result.stdout)['groups']
        self.assertEqual([len(g['members']) for g in groups], [3, 1])
        self.assertEqual([m['cap_effective'] for m in groups[0]['members']], ['chown', '', 'net_admin'])
        self.assertEqual(groups[1]['members'][0]['cap_effective'], 'bpf')

    def test_container_filter_keeps_its_threads(self):
        result = self.cli('--saved', '--output-root', str(self.results), '--container', 'aaaaaa', '--json')
        self.assertEqual(result.returncode, 0, result.stderr)
        groups = json.loads(result.stdout)['groups']
        self.assertEqual(len(groups), 1)
        self.assertEqual({m['TID'] for m in groups[0]['members']}, {110, 111, 112})

    def test_relocated_script_and_results(self):
        relocated = self.root / '다른 설치 경로'
        relocated.mkdir()
        shutil.copy2(BASE / 'container_caps.py', relocated)
        moved_results = self.root / 'moved results'
        shutil.move(str(self.results), str(moved_results))
        result = self.cli('--saved', '--output-root', str(moved_results), '--list', script=relocated / 'container_caps.py')
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn('표시 컨테이너 2개', result.stdout)

    def test_unreadable_caps_not_empty_or_success(self):
        self.audit['members'][0]['cap_effective'] = None
        self.audit['members'][0]['Status'] = 'partial'
        self.audit['field_errors'] = [{'tid': 110, 'stage': 'cap_effective', 'error': 'synthetic unreadable'}]
        self.save()
        result = self.cli('--saved', '--output-root', str(self.results), '--json')
        self.assertEqual(result.returncode, 2)
        members = json.loads(result.stdout)['groups'][0]['members']
        self.assertIsNone(members[0]['cap_effective'])
        self.assertEqual(members[1]['cap_effective'], '')

    def test_saved_cannot_silently_ignore_a_new_dump(self):
        result = self.cli('--saved', '--output-root', str(self.results), '--dump=fake.lime')
        self.assertEqual(result.returncode, 2)
        self.assertIn('--saved', result.stderr)

    def test_partial_new_context_prints_missing_maps_without_hiding_empty_caps(self):
        member = self.audit['members'][0]
        member.update(CapabilityScope='unknown', CredSource='task.cred', CredsDiffer=None,
                      UserEUID=None, SeccompMode=None, SeccompFilters=None, NoNewPrivs=False,
                      Securebits=0, MountNS=None, NetNS=None, Status='partial', cap_ambient=None,
                      cap_effective='', credentials={'user_namespace': {'chain_leaf_to_initial': [
                          {'inum': None, 'uid_map': None, 'gid_map': []}]}},
                      observations=[{'source': 'credentials', 'feature': 'cap_ambient',
                                     'status': 'not_present', 'reason': 'synthetic absent member'}])
        self.save()
        result = self.cli('--saved', '--output-root', str(self.results), '--view', 'details')
        self.assertEqual(result.returncode, 2, result.stderr)
        self.assertIn('cap_ambient: <필드 없음>', result.stdout)
        self.assertIn('cap_effective: <없음>', result.stdout)
        self.assertIn('no_new_privs False', result.stdout)
        self.assertIn('uid_map (namespace 시작 / 커널 ID 시작 / 개수): <확인 불가>', result.stdout)

    def test_compatibility_of_old_result_is_not_fabricated(self):
        result = self.cli('--saved', '--output-root', str(self.results), '--compatibility')
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn('구조별 지원 검사가 기록되지 않았습니다', result.stdout)

    def test_incomplete_collections_are_unknown_in_thread_comparison(self):
        for member in self.audit['members'][:2]:
            member['credentials'] = {'ids_kernel': {'uid': 0, 'euid': None}}
            member['seccomp'] = {'filters': [], 'chain_complete': False}
        self.save()
        result = self.cli('--saved', '--output-root', str(self.results), '--json')
        comparison = json.loads(result.stdout)['groups'][0]['process_comparison'][0]
        self.assertIn('credential_ids', comparison['unavailable_fields'])
        self.assertIn('seccomp_filter_chain', comparison['unavailable_fields'])


if __name__ == '__main__':
    unittest.main()

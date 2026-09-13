"""Classification edge cases and independent checks of recorded dump results."""
import base64
import hashlib
import importlib.metadata
import json
from pathlib import Path
import sys
from types import SimpleNamespace
import unittest
from unittest.mock import patch

import volatility3.plugins

BASE = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(BASE))
volatility3.plugins.__path__.insert(0, str(BASE / 'plugins'))
from volatility3.plugins.container_support.identity import identify_docker, read_cgroup_chain
from container_caps import group_members, select_members


def chain(*names):
    return [{'name': name, 'address': hex(4096 + i * 256)} for i, name in enumerate(names)]


class Pointer:
    def __init__(self, value=None):
        self.value = value

    def __int__(self):
        return int(self.value.vol.offset) if self.value else 0

    def dereference(self):
        return self.value


def fake_cgroups():
    groups = []
    for i, name in enumerate(('', 'system.slice', 'docker-' + 'a' * 64 + '.scope')):
        parent = groups[-1] if groups else None
        node = SimpleNamespace(vol=SimpleNamespace(offset=8192 + i * 256))
        node.name = Pointer(SimpleNamespace(vol=SimpleNamespace(offset=100 + i), text=name))
        node.parent = parent.kn if parent else Pointer()
        node.has_member = lambda field: field == 'parent'
        node.member = lambda field, item=node: getattr(item, field)
        group = SimpleNamespace(vol=SimpleNamespace(offset=4096 + i * 256), kn=Pointer(node))
        css = SimpleNamespace(vol=SimpleNamespace(offset=12288 + i * 256), cgroup=Pointer(group), parent=Pointer(parent.self) if parent else Pointer())
        group.self = css
        groups.append(group)
    return groups


class ClassificationTests(unittest.TestCase):
    def test_systemd_scope_with_child_cgroup(self):
        result = identify_docker(chain('', 'system.slice', 'docker-' + 'a' * 64 + '.scope', 'workload'))
        self.assertEqual(result['id'], 'a' * 64)
        self.assertTrue(result['root_path'].endswith('.scope'))

    def test_cgroupfs_layout(self):
        self.assertEqual(identify_docker(chain('', 'docker', 'B' * 64))['id'], 'b' * 64)

    def test_hex_directory_alone_is_not_docker(self):
        self.assertIsNone(identify_docker(chain('', 'system.slice', 'a' * 64)))

    def test_docker_daemon_and_short_id_are_not_membership(self):
        for name in ('docker.service', 'containerd.service', 'docker-abcdef.scope'):
            self.assertIsNone(identify_docker(chain('', 'system.slice', name)))

    def test_nested_docker_uses_nearest_ancestor(self):
        self.assertEqual(identify_docker(chain('', 'docker-' + 'a' * 64 + '.scope', 'docker', 'b' * 64))['id'], 'b' * 64)

    def test_same_id_at_distinct_roots_stays_separate(self):
        members = [{'ContainerID': 'a' * 64, 'ContainerRoot': root, 'ContainerPath': '/docker/a', 'PID': 10, 'TID': 10} for root in ('0x10', '0x20')]
        self.assertEqual(len(group_members(members)), 2)

    def test_shared_root_groups_all_threads(self):
        members = [{'ContainerID': 'a' * 64, 'ContainerRoot': '0x10', 'ContainerPath': '/docker/a', 'PID': 10, 'TID': tid} for tid in (10, 11)]
        self.assertEqual(len(group_members(members)[0]['members']), 2)
        self.assertEqual(len(select_members({'include_threads': True, 'members': members}, leaders=True)), 1)

    def test_ambiguous_prefix_is_rejected(self):
        members = [{'ContainerID': 'aaaaaa' + suffix * 58} for suffix in ('0', '1')]
        with self.assertRaisesRegex(ValueError, '여러'):
            select_members({'include_threads': True, 'members': members}, 'aaaaaa')

    @patch('volatility3.plugins.container_support.identity.utility.pointer_to_string', side_effect=lambda pointer, *a, **k: pointer.value.text)
    def test_parent_links_reconstruct_path(self, _):
        self.assertEqual([x['name'] for x in read_cgroup_chain(fake_cgroups()[-1])], ['', 'system.slice', 'docker-' + 'a' * 64 + '.scope'])

    @patch('volatility3.plugins.container_support.identity.utility.pointer_to_string', side_effect=lambda pointer, *a, **k: pointer.value.text)
    def test_disagreeing_links_are_rejected(self, _):
        groups = fake_cgroups()
        groups[-1].kn.dereference().parent = groups[0].kn
        with self.assertRaisesRegex(ValueError, 'disagree'):
            read_cgroup_chain(groups[-1])

    @patch('volatility3.plugins.container_support.identity.utility.pointer_to_string', side_effect=lambda pointer, *a, **k: pointer.value.text)
    def test_cycles_are_rejected(self, _):
        groups = fake_cgroups()
        groups[0].self.parent = Pointer(groups[-1].self)
        groups[0].kn.dereference().parent = groups[-1].kn
        groups[0].kn.dereference().name.value.text = 'cycle'
        with self.assertRaisesRegex(ValueError, 'Cycle'):
            read_cgroup_chain(groups[-1])


"""Synthetic layout cases; no memory dumps or acquisition results are read."""

from pathlib import Path
from types import SimpleNamespace
import sys
import unittest
from unittest.mock import patch

BASE = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(BASE))
import volatility3.plugins
from volatility3.framework import exceptions
volatility3.plugins.__path__.insert(0, str(BASE / 'plugins'))
from volatility3.plugins.container_support.layouts import (
    UnsupportedLayoutError, inspect_pid_layout, read_pid_chain,
)
from volatility3.plugins.container_support.identity import (
    CgroupV2Resolver, identify_docker, read_cgroup_chain,
)


class Struct:
    def __init__(self, offset=0, **fields):
        self.vol = SimpleNamespace(offset=offset)
        self.fields = fields

    def has_member(self, name):
        return name in self.fields

    def member(self, name):
        return self.fields[name]

    def __getattr__(self, name):
        if name in self.fields:
            return self.fields[name]
        raise AttributeError(name)


class Pointer:
    def __init__(self, target=None, fail=False):
        self.target, self.fail = target, fail

    def __int__(self):
        return self.target.vol.offset if self.target is not None else 0

    def dereference(self):
        if self.fail:
            raise exceptions.InvalidAddressException('synthetic', int(self), 'unreadable pointer')
        return self.target


class Template:
    def __init__(self, *members, size=64, offsets=None):
        self.members, self.size = set(members), size
        self.offsets = offsets or {}

    def has_member(self, name):
        return name in self.members

    def relative_child_offset(self, name):
        return self.offsets[name]


class Module:
    def __init__(self, types, objects=None, choices=None):
        self.types, self.objects, self.choices = types, objects or {}, choices
        self.reads = []

    def get_type(self, name):
        return self.types[name]

    def get_enumeration(self, name):
        if self.choices is None:
            raise KeyError(name)
        return SimpleNamespace(choices=self.choices)

    def object(self, name, offset, absolute):
        assert name == 'upid' and absolute is True
        self.reads.append(offset)
        value = self.objects[offset]
        if isinstance(value, Exception):
            raise value
        return value


def pid_fixture(pointer_field='thread_pid', namespace_field='ns', choices=None, index=0):
    types = {
        'task_struct': Template('pid', pointer_field),
        'pid_link': Template('pid'),
        'pid': Template('level', 'numbers', size=96, offsets={'numbers': 96}),
        'upid': Template('nr', 'ns', size=24),
        'pid_namespace': Template(namespace_field),
        'ns_common': Template('inum'),
    }
    namespaces = [Struct(0x8000 + i * 128, **(
        {'ns': Struct(inum=800 + i)} if namespace_field == 'ns' else {'proc_inum': 800 + i}
    )) for i in range(2)]
    upids = {0x1000 + 96 + i * 24: Struct(nr=77 if i == 0 else 1, ns=Pointer(ns))
             for i, ns in enumerate(namespaces)}
    pid = Struct(0x1000, level=1)
    fields = {'pid': 77}
    if pointer_field == 'thread_pid':
        fields['thread_pid'] = Pointer(pid)
    else:
        fields['pids'] = [Struct(pid=Pointer()) for _ in range(index + 1)]
        fields['pids'][index] = Struct(pid=Pointer(pid))
    return Struct(0x2000, **fields), Module(types, upids, choices)


def cgroup_module(parent='parent'):
    return Module({
        'task_struct': Template('cgroups'),
        'css_set': Template('dfl_cgrp'),
        'cgroup': Template('kn', 'self'),
        'cgroup_subsys_state': Template('parent', 'cgroup'),
        'kernfs_node': Template('name', parent),
    })


def cgroup_fixture(parent_field='parent'):
    groups = []
    for index, name in enumerate(('', 'system.slice', 'docker-' + 'a' * 64 + '.scope')):
        parent = groups[-1] if groups else None
        text = Struct(0x4000 + index, text=name)
        node = Struct(0x5000 + index * 256, name=Pointer(text), **{
            parent_field: parent.kn if parent else Pointer(),
        })
        group = Struct(0x6000 + index * 256, kn=Pointer(node))
        group.fields['self'] = Struct(0x7000 + index * 256, cgroup=Pointer(group),
                                      parent=Pointer(parent.self) if parent else Pointer())
        groups.append(group)
    return groups


class PidLayoutTests(unittest.TestCase):
    def test_thread_pid_with_symbol_sized_flexible_array(self):
        task, module = pid_fixture()
        self.assertEqual(read_pid_chain(task, module), [
            {'level': 0, 'id': 77, 'namespace': 800},
            {'level': 1, 'id': 1, 'namespace': 801},
        ])
        self.assertEqual(module.reads, [0x1060, 0x1078])

    def test_legacy_pid_link_uses_symbol_enum_index(self):
        task, module = pid_fixture('pids', choices={'PIDTYPE_PID': 2}, index=2)
        self.assertEqual(read_pid_chain(task, module)[-1]['id'], 1)
        self.assertEqual(inspect_pid_layout(module)['layout']['pidtype_source'], 'pid_type enumeration')

    def test_missing_enum_uses_documented_pidtype_zero(self):
        task, module = pid_fixture('pids')
        self.assertEqual(read_pid_chain(task, module)[0]['id'], 77)
        self.assertIn('enum absent', inspect_pid_layout(module)['layout']['pidtype_source'])

    def test_present_enum_missing_pidtype_is_not_guessed(self):
        task, module = pid_fixture('pids', choices={'PIDTYPE_PGID': 1})
        with self.assertRaisesRegex(UnsupportedLayoutError, r'pid_type.PIDTYPE_PID'):
            read_pid_chain(task, module)

    def test_legacy_namespace_proc_inum(self):
        task, module = pid_fixture('pids', 'proc_inum')
        self.assertEqual(read_pid_chain(task, module)[-1]['namespace'], 801)

    def test_null_thread_pointer_does_not_try_legacy_alternative(self):
        task, module = pid_fixture()
        module.types['task_struct'].members.add('pids')
        task.fields['pids'] = [Struct(pid=task.thread_pid)]
        task.fields['thread_pid'] = Pointer()
        with self.assertRaisesRegex(ValueError, 'task_struct.thread_pid: null'):
            read_pid_chain(task, module)
        self.assertEqual(module.reads, [])

    def test_null_legacy_pointer(self):
        task, module = pid_fixture('pids')
        task.pids[0].fields['pid'] = Pointer()
        with self.assertRaisesRegex(ValueError, 'null PID pointer'):
            read_pid_chain(task, module)

    def test_pointer_read_error_is_not_reported_as_empty_chain(self):
        task, module = pid_fixture()
        task.thread_pid.fail = True
        with self.assertRaisesRegex(ValueError, 'task_struct.thread_pid: could not read'):
            read_pid_chain(task, module)

    def test_upid_read_error_identifies_array_index(self):
        task, module = pid_fixture()
        module.objects[0x1078] = exceptions.InvalidAddressException('synthetic', 0x1078)
        with self.assertRaisesRegex(ValueError, r'pid.numbers\[1\]: could not read'):
            read_pid_chain(task, module)

    def test_namespace_null_and_read_errors(self):
        for pointer in (Pointer(), Pointer(Struct(123), fail=True)):
            with self.subTest(pointer=pointer):
                task, module = pid_fixture()
                module.objects[0x1078].fields['ns'] = pointer
                with self.assertRaisesRegex(ValueError, r'pid.numbers\[1\].ns'):
                    read_pid_chain(task, module)

    def test_host_tid_cross_check_rejects_different_task(self):
        task, module = pid_fixture()
        task.fields['pid'] = 78
        with self.assertRaisesRegex(ValueError, 'Host TID.*disagree'):
            read_pid_chain(task, module)

    def test_corrupt_namespace_level_is_bounded(self):
        for level in (-1, 33):
            with self.subTest(level=level):
                task, module = pid_fixture()
                task.thread_pid.target.fields['level'] = level
                with self.assertRaisesRegex(ValueError, 'pid.level'):
                    read_pid_chain(task, module)

    def test_required_pid_symbols_fail_with_specific_field(self):
        for name, field in [('task_struct', 'pid'), ('pid', 'numbers'), ('upid', 'ns'), ('ns_common', 'inum')]:
            with self.subTest(name=name, field=field):
                task, module = pid_fixture()
                module.types[name].members.remove(field)
                with self.assertRaisesRegex(UnsupportedLayoutError, name + r'\.' + field):
                    read_pid_chain(task, module)

    def test_unknown_pid_and_namespace_layouts_are_rejected(self):
        for name, missing in [('task_struct', 'thread_pid'), ('pid_namespace', 'ns')]:
            with self.subTest(name=name):
                task, module = pid_fixture()
                module.types[name].members.remove(missing)
                with self.assertRaises(UnsupportedLayoutError):
                    read_pid_chain(task, module)

    def test_invalid_symbol_sizes_do_not_guess_offsets(self):
        for name, size in [('pid', 64), ('upid', 0)]:
            with self.subTest(name=name):
                task, module = pid_fixture()
                module.types[name].size = size
                with self.assertRaises(UnsupportedLayoutError):
                    read_pid_chain(task, module)


class CgroupLayoutTests(unittest.TestCase):
    def test_preflight_reports_both_known_parent_layouts(self):
        for parent in ('parent', '__parent'):
            with self.subTest(parent=parent):
                resolver = CgroupV2Resolver(cgroup_module(parent))
                self.assertEqual(resolver.compatibility['status'], 'ok')
                self.assertEqual(resolver.compatibility['feature'], 'container_membership')
                self.assertEqual(resolver.compatibility['layout']['kernfs_parent'], 'kernfs_node.' + parent)

    def test_each_required_type_is_checked(self):
        for name in cgroup_module().types:
            with self.subTest(name=name):
                module = cgroup_module()
                del module.types[name]
                with self.assertRaises(UnsupportedLayoutError) as error:
                    CgroupV2Resolver(module)
                self.assertEqual(error.exception.field, name)
                self.assertEqual(error.exception.compatibility['status'], 'unsupported')

    def test_each_required_field_is_checked(self):
        for name, template in cgroup_module().types.items():
            for field in template.members:
                with self.subTest(name=name, field=field):
                    module = cgroup_module()
                    module.types[name].members.remove(field)
                    with self.assertRaises(UnsupportedLayoutError) as error:
                        CgroupV2Resolver(module)
                    self.assertIn(name + '.' + field, error.exception.message)

    def test_cgroup_v1_subsys_does_not_replace_default_cgroup(self):
        module = cgroup_module()
        module.types['css_set'] = Template('subsys')
        with self.assertRaisesRegex(UnsupportedLayoutError, 'css_set.dfl_cgrp'):
            CgroupV2Resolver(module)

    @patch('volatility3.plugins.container_support.identity.utility.pointer_to_string', side_effect=lambda pointer, *a, **k: pointer.target.text)
    def test_parent_layouts_resolve_and_cache_validated_path(self, _):
        for parent in ('parent', '__parent'):
            with self.subTest(parent=parent):
                groups = cgroup_fixture(parent)
                resolver = CgroupV2Resolver(cgroup_module(parent))
                task = Struct(cgroups=Pointer(Struct(0x9000, dfl_cgrp=Pointer(groups[-1]))))
                result = resolver.resolve(task)
                self.assertEqual(result[-1]['id'], 'a' * 64)
                self.assertEqual([entry['name'] for entry in result[-2]], ['', 'system.slice', 'docker-' + 'a' * 64 + '.scope'])
                self.assertEqual(resolver.resolve(task), result)

    @patch('volatility3.plugins.container_support.identity.utility.pointer_to_string', side_effect=lambda pointer, *a, **k: pointer.target.text)
    def test_css_and_kernfs_parents_must_agree(self, _):
        groups = cgroup_fixture('__parent')
        groups[-1].kn.target.fields['__parent'] = groups[0].kn
        with self.assertRaisesRegex(ValueError, 'disagree'):
            read_cgroup_chain(groups[-1])

    def test_current_css_must_point_back_to_its_cgroup(self):
        groups = cgroup_fixture()
        groups[-1].self.fields['cgroup'] = Pointer(groups[0])
        with self.assertRaisesRegex(ValueError, 'cgroup.self.cgroup.*disagree'):
            read_cgroup_chain(groups[-1])

    def test_null_cgroup_pointers_are_not_absent_membership(self):
        resolver = CgroupV2Resolver(cgroup_module())
        for task, message in [(Struct(cgroups=Pointer()), 'task_struct.cgroups'),
                              (Struct(cgroups=Pointer(Struct(123, dfl_cgrp=Pointer()))), 'css_set.dfl_cgrp')]:
            with self.subTest(message=message):
                with self.assertRaisesRegex(ValueError, message):
                    resolver.resolve(task)

    def test_bare_hex_and_short_ids_remain_unrecognized(self):
        for name in ('a' * 64, 'docker-abcdef.scope', 'containerd.service'):
            self.assertIsNone(identify_docker([{'name': name, 'address': '0x1234'}]))


if __name__ == '__main__':
    unittest.main()

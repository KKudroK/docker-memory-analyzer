"""Regression cases for corrupt and alternate symbol-described layouts."""
import sys
import unittest
from pathlib import Path
from types import SimpleNamespace as NS

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'tools' / 'volatility3_2_28_0_base'))
sys.path.insert(0, str(ROOT))
from src.network_analysis.collector import Collector
from src.network_analysis.sockets import fd_table


class Obj(NS):
    def has_member(self, name):
        return hasattr(self, name)

    def dereference(self):
        return self

    def __int__(self):
        return self.vol.offset


class CompatibilityTests(unittest.TestCase):
    def collector(self):
        c = Collector.__new__(Collector)
        c.limit, c.errors = 10, []
        c.metrics = {'cache': {'cgroup_hits': 0, 'cgroup_misses': 0}}
        c.cgroup_cache_enabled, c.cgroup_cache = True, {}
        c.cstring = lambda value: value
        return c

    def test_modern_and_old_paths(self):
        for modern in (True, False):
            root = Obj(vol=NS(offset=1), name='', parent=None)
            child = Obj(vol=NS(offset=2), name='docker-test.scope', parent=root)
            group = Obj(kn=child) if modern else child
            self.assertEqual(self.collector().cgroup_path(group), '/docker-test.scope')

    def test_cycle_and_exact_budget(self):
        c = self.collector()
        c.limit = 1
        root = Obj(vol=NS(offset=1), name='', parent=None)
        self.assertEqual(c.cgroup_path(Obj(kn=root)), '/')
        root.parent = root
        with self.assertRaisesRegex(ValueError, 'cycle'):
            c.cgroup_path(Obj(kn=root))

    def test_broken_controller_preserves_valid_path_without_caching(self):
        good = Obj(vol=NS(offset=10), kn=Obj(vol=NS(offset=11), name='docker-test.scope', parent=None))
        bad = Obj(vol=NS(offset=20), kn=None)
        css = Obj(vol=NS(offset=30), dfl_cgrp=good, subsys=[Obj(cgroup=bad)])
        task = Obj(cgroups=css)
        c = self.collector()
        self.assertEqual(c.cgroups(task), ['/docker-test.scope'])
        self.assertEqual(c.errors[0]['stage'], 'cgroup.path')
        self.assertEqual(c.cgroup_cache, {})

    def test_both_fd_layouts(self):
        table = Obj(max_fds=4, fd=123)
        self.assertEqual(fd_table(table, 4), (table, 4))
        self.assertEqual(fd_table(Obj(fdt=table), 4), (table, 4))

    def test_invalid_fd_bounds_and_null(self):
        for count, fd in ((-1, 123), (5, 123), (1, 0)):
            with self.assertRaises(ValueError):
                fd_table(Obj(max_fds=count, fd=fd), 4)
        self.assertEqual(fd_table(Obj(max_fds=0, fd=0), 4)[1], 0)


if __name__ == '__main__':
    unittest.main()

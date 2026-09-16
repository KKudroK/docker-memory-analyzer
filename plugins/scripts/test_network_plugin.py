"""Fast synthetic traversal and corruption tests; no memory image needed."""
import sys
import unittest
from pathlib import Path
from types import SimpleNamespace as NS

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'tools' / 'volatility3'))
sys.path.insert(0, str(ROOT))
from src.network_analysis.collector import Collector



def node(address, next_address):
    item = NS(vol=NS(offset=address), next=next_address)
    item.member = lambda name: item
    return item


class TraversalTests(unittest.TestCase):
    def collector(self, pointers, limit=10):
        c = Collector.__new__(Collector)
        c.limit, c.errors = limit, []
        c.kernel = NS(get_type=lambda name: NS(relative_child_offset=lambda member: 0))
        c.obj = lambda name, addr: pointers[addr]
        return c

    def test_empty_list(self):
        head = node(100, 100)
        self.assertEqual(list(self.collector({}).walk(head, 'task', 'tasks')), [])

    def test_list_order(self):
        c = self.collector({200: node(200, 300), 300: node(300, 100)})
        self.assertEqual([n.vol.offset for n in c.walk(node(100, 200), 'task', 'tasks')], [200, 300])

    def test_non_head_cycle(self):
        c = self.collector({200: node(200, 200)})
        with self.assertRaisesRegex(ValueError, 'cycle'):
            list(c.walk(node(100, 200), 'task', 'tasks'))

    def test_null_link_is_error(self):
        with self.assertRaisesRegex(ValueError, 'null'):
            list(self.collector({}).walk(node(100, 0), 'task', 'tasks'))

    def test_limit_not_empty_success(self):
        c = self.collector({200: node(200, 300)}, limit=1)
        with self.assertRaisesRegex(ValueError, 'limit'):
            list(c.walk(node(100, 200), 'task', 'tasks'))

    def test_exact_limit_is_complete(self):
        c = self.collector({200: node(200, 100)}, limit=1)
        self.assertEqual(len(list(c.walk(node(100, 200), 'task', 'tasks'))), 1)

    def test_budget_is_reported_separately_from_cycle(self):
        c = self.collector({200: node(200, 300)}, limit=1)
        with self.assertRaisesRegex(ValueError, 'limit'):
            list(c.walk(node(100, 200), 'task', 'tasks'))



    def test_read_failure_preserved(self):
        c = self.collector({})
        result = c.read('test', node(42, 0), lambda: 1 / 0, [])
        self.assertEqual(result, [])
        self.assertEqual(c.errors[0]['address'], '0x2a')
        self.assertEqual(c.errors[0]['error'], 'ZeroDivisionError')

    def test_array_limit(self):
        with self.assertRaisesRegex(ValueError, 'count'):
            self.collector({}).array(0, 'task', 11)



if __name__ == "__main__":
    unittest.main()

"""Fast synthetic traversal and corruption tests; no memory image needed."""
import sys
import unittest
from pathlib import Path
from types import SimpleNamespace as NS

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'tools' / 'volatility3'))
sys.path.insert(0, str(ROOT))
from src.network_analysis.collector import Collector
from src.network_analysis.presentation import table


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
        self.assertEqual(c.metrics['termination']['list_head_return'], 1)

    def test_budget_is_reported_separately_from_cycle(self):
        c = self.collector({200: node(200, 300)}, limit=1)
        with self.assertRaisesRegex(ValueError, 'limit'):
            list(c.walk(node(100, 200), 'task', 'tasks'))
        self.assertEqual(c.metrics['termination']['list_budget'], 1)

    def test_hlist(self):
        c = self.collector({200: node(200, 0)})
        self.assertEqual(len(list(c.hlist(NS(first=200), 'neighbor', 'hash'))), 1)

    def test_hlist_cycle(self):
        c = self.collector({200: node(200, 200)})
        with self.assertRaisesRegex(ValueError, 'cycle'):
            list(c.hlist(NS(first=200), 'neighbor', 'hash'))

    def test_read_failure_preserved(self):
        c = self.collector({})
        result = c.read('test', node(42, 0), lambda: 1 / 0, [])
        self.assertEqual(result, [])
        self.assertEqual(c.errors[0]['address'], '0x2a')
        self.assertEqual(c.errors[0]['error'], 'ZeroDivisionError')

    def test_array_limit(self):
        with self.assertRaisesRegex(ValueError, 'count'):
            self.collector({}).array(0, 'task', 11)


class PresentationTests(unittest.TestCase):
    def report(self):
        return {'namespaces':[{'address':'n','inode':42,'pids':[1,2],'container_candidates':['a'*64],'is_initial':False}],
                'tasks':[{'pid':1,'tgid':1,'container_candidates':['a'*64]},{'pid':2,'tgid':1,'container_candidates':['a'*64]}],
                'interfaces':[{'address':'d','namespace':'n','name':'eth0','ifindex':2,'mac':'76:00:00:00:00:01',
                               'addresses':[{'cidr':'10.0.0.2/24'},{'cidr':'10.0.0.3/24'}]}],
                'links':[], 'sockets':[]}

    def test_exact_columns(self):
        self.assertEqual([c[0] for c in table(self.report())[0]],
                         ['Container','PID','NetNS','Interface','MAC','Address','Host link','Protocol','Local','Remote','State'])

    def test_all_addresses_independent_rows(self):
        rows=table(self.report())[1]
        self.assertEqual(len(rows),2)
        self.assertEqual(rows[1][5],'10.0.0.3/24')
        self.assertEqual(rows[0][0],'a'*12)
        self.assertEqual(rows[0][1],'1')
        self.assertEqual(rows[0][2],'42')
        self.assertEqual(rows[0][4],'76:00:00:00:00:01')

    def test_no_unattributed_default(self):
        report=self.report()
        report['namespaces'][0]['container_candidates']=[]
        self.assertEqual(table(report)[1],[])
        self.assertEqual(len(table(report,include_host=True)[1]),2)

    def add_socket(self, report, **extra):
        sock={'socket':'s','namespace':'n','family':10,'protocol':'TCP','source_ip':'::1','source_port':8080,
              'destination_ip':'::1','destination_port':40000,'state':1,
              'holders':[{'pid':1,'fd':4},{'pid':2,'fd':4}]}
        sock.update(extra)
        report['sockets'].append(sock)

    def test_loopback_established_and_thread_dedup(self):
        report=self.report()
        self.add_socket(report)
        rows=table(report)[1]
        self.assertEqual(len(rows),3)
        self.assertEqual(rows[-1][3:7],('-','-','-','-'))
        self.assertEqual(rows[-1][-4:],('TCP','[::1]:8080','[::1]:40000','ESTABLISHED'))

    def test_foreign_holder_not_relabelled_as_container(self):
        report=self.report()
        report['tasks'].append({'pid':3,'tgid':3,'container_candidates':[]})
        self.add_socket(report,holders=[{'pid':3,'fd':4}])
        self.assertEqual(table(report)[1][-1][:3],('-','3','42'))

    def test_shared_namespace_keeps_actual_holder_id(self):
        report=self.report()
        report['namespaces'][0]['container_candidates'].append('b'*64)
        report['tasks'].append({'pid':3,'tgid':3,'container_candidates':['b'*64]})
        self.add_socket(report,holders=[{'pid':1,'fd':4},{'pid':3,'fd':5}])
        rows=table(report)[1]
        self.assertEqual(rows[-2][:2],('a'*12,'1'))
        self.assertEqual(rows[-1][:2],('b'*12,'3'))

    def test_unix_path_and_unknown_peer(self):
        report=self.report()
        self.add_socket(report,family=1,protocol='UNIX',path='/tmp/listener.sock',peer='0x0',state=10)
        self.assertEqual(table(report)[1][-1][-4:],('UNIX','/tmp/listener.sock','-','LISTEN'))


if __name__ == '__main__':
    unittest.main()

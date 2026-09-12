"""Regression checks for evidence loss, false state inference and sparse files."""
import sys
import struct
import unittest
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from src.memory import CachedProcessMemory
from src.structs import StructReader
from src.state_identification import identify
from src.kernel_artifacts import cached_content
from src.evidence import redact
from src.discovery import _pick_best


class CoreTests(unittest.TestCase):
    def test_containerd_image_requires_descriptor_fields(self):
        from src.discovery_containerd import discover_containerd_images
        from src.structs_containerd import ContainerdStructReader, IMAGE

        base = 0x10000
        raw = bytearray(0x800)
        cursor = 0x400

        def put_string(field, value):
            nonlocal cursor
            encoded = value.encode()
            address = base + cursor
            raw[cursor:cursor + len(encoded)] = encoded
            offset = IMAGE[field][0]
            raw[offset:offset + 16] = struct.pack('<QQ', address, len(encoded))
            cursor += len(encoded) + 8

        put_string('Name', 'example/image:latest')
        put_string('Target.MediaType', 'application/vnd.oci.image.manifest.v1+json')
        put_string('Target.Digest', 'sha256:' + 'a' * 64)
        raw[IMAGE['Target.Size'][0]:IMAGE['Target.Size'][0] + 8] = struct.pack('<q', 1234)
        mem = CachedProcessMemory()
        mem.add_chunk(base, bytes(raw)); mem.finalize()
        result = discover_containerd_images(mem, ContainerdStructReader(mem), ['example/image:latest'], log=lambda *args: None)
        self.assertEqual(len(result['example/image:latest']), 1)
        self.assertEqual(result['example/image:latest'][0]['Target.Size'], 1234)

        # The same Name string without descriptor evidence must not become an Image.
        raw[IMAGE['Target.MediaType'][0]:IMAGE['Target.MediaType'][0] + 16] = bytes(16)
        mem = CachedProcessMemory()
        mem.add_chunk(base, bytes(raw)); mem.finalize()
        self.assertEqual(discover_containerd_images(mem, ContainerdStructReader(mem),
                         ['example/image:latest'], log=lambda *args: None), {})

    def test_exit_code_42_raw_bytes(self):
        from src.structs import STATE
        raw = bytearray(256)
        raw[STATE['ExitCode'][0]:STATE['ExitCode'][0] + 8] = struct.pack('<q', 42)
        mem = CachedProcessMemory()
        mem.add_chunk(0x10000, bytes(raw)); mem.finalize()
        state = StructReader(mem).parse_state(0x10000)
        self.assertEqual(state['ExitCode'], 42)
        self.assertEqual(state['ExitCode_evidence']['raw_hex'], '2a00000000000000')

    def test_actions_keep_distinct_times_and_remove_duplicate_allocations(self):
        from src.semantic_artifacts import actions_flow
        events = [{'action': 'start', 'time_nano': 3}, {'action': 'die', 'time_nano': 2},
                  {'action': 'start', 'time_nano': 1}, {'action': 'start', 'time_nano': 1}]
        self.assertEqual(actions_flow(events), 'start -> die -> start')

    def test_shared_objects_and_loopback_namespace_are_distinct(self):
        from src.semantic_artifacts import correlate
        def process(pid, ns, reverse=False):
            ports = (80, 1234) if reverse else (1234, 80)
            return {'pid': pid, 'nsproxy': {'net_ns': ns}, 'files': [{'fd': 3, 'address': pid * 100,
                'socket': {'family': 'AF_INET', 'protocol': 'TCP', 'state': 'ESTABLISHED',
                           'source_address': '127.0.0.1', 'destination_address': '127.0.0.1',
                           'source_port': ports[0], 'destination_port': ports[1]}}]}
        a, b = process(1, 100), process(2, 200, True)
        result = {'containers': [{'container_id': 'a', 'processes': [a]}, {'container_id': 'b', 'processes': [b]}]}
        correlate(result)
        self.assertFalse(a['files'][0]['relationships']['peers'])
        b['nsproxy']['net_ns'] = 100
        correlate(result)
        self.assertEqual(a['files'][0]['relationships']['peers'][0]['pid'], 2)

    def test_layered_report_and_exact_field_origin(self):
        import io
        from contextlib import redirect_stdout
        from src.reporting import show
        c = {'container_id': 'a' * 64, 'container_name': '/fixture', 'status': 'Dead',
             'container': {'Name': '/fixture', 'State_ptr': 4096}, 'state': {'Dead': True},
             'dockerd_candidates': [{'source_pid': 123, 'cbase': 8192,
                                     'container': {'Name': '/fixture', 'State_ptr': 4096}}]}
        result = {'label': 'case', 'timing': {'total': 1}, 'containers': [c],
                  'field_reads': [{'source_pid': 123, 'structure': 'State', 'field': 'Dead',
                      'base_address': '0x1000', 'field_address': '0x1007', 'offset': '0x7', 'size': 1}]}
        out = io.StringIO()
        with redirect_stdout(out):
            show(result, reconstruction=True, verbose=True)
        self.assertIn('USER SPACE', out.getvalue())
        self.assertIn('KERNEL SPACE', out.getvalue())
        self.assertIn('dockerd | PID 123', out.getvalue())
        self.assertIn('@ State.Dead', out.getvalue())
        self.assertIn('0x1007', out.getvalue())

    def test_socket_queue_empty_and_corrupt_are_distinct(self):
        from types import SimpleNamespace as N
        from src.ipc_artifacts import socket_queues
        names = ('sk_receive_queue', 'sk_write_queue', 'sk_error_queue')
        sock = N(**{name: N(vol=N(offset=100), next=100, qlen=0) for name in names})
        queues = socket_queues(sock, None)
        self.assertTrue(all(q['complete'] and q['recovered_bytes'] == 0 for q in queues.values()))
        sock.sk_receive_queue.next = 0
        queues = socket_queues(sock, None)
        self.assertFalse(queues['sk_receive_queue']['complete'])
        self.assertTrue(queues['sk_receive_queue']['errors'])

    def test_pipe_invalid_ring_is_reported(self):
        from types import SimpleNamespace as N
        from src.ipc_artifacts import pipe_info
        class Obj(N):
            def has_member(self, name):
                return name in self.__dict__
            def __int__(self):
                return 1024
            def dereference(self):
                return self
        pipe = Obj(head=4, tail=0, ring_size=3, readers=1, writers=1)
        result = pipe_info(Obj(i_pipe=pipe))
        self.assertFalse(result['complete'])
        self.assertIn('Invalid pipe ring', result['errors'][0]['message'])

    def test_report_uses_status_not_scenario_and_never_dumps_pages(self):
        import io
        from contextlib import redirect_stdout
        from src.reporting import show
        result = {'label': 'fixture', 'scenario_hint': 'dead', 'dump_path': 'fixture.lime', 'timing': {'total': 1},
                  'containers': [{'container_id': 'a' * 64, 'container_name': '/example', 'status': 'Running',
                                  'container': {'ID': 'a' * 64}, 'state': {'Pid': 1}, 'processes': []}],
                  'file_contents': {'key': {'segments': [{'text': 'BINARY_SENTINEL', 'offset': 0}]}}, 'parsing_errors': []}
        for verbose in (False, True):
            output = io.StringIO()
            with redirect_stdout(output):
                show(result, reconstruction=True, verbose=verbose)
            self.assertIn('RESULT: RUNNING', output.getvalue())
            self.assertNotIn('BINARY_SENTINEL', output.getvalue())
            self.assertNotIn('RESULT: DEAD', output.getvalue())
        self.assertEqual(result['file_contents']['key']['segments'][0]['text'], 'BINARY_SENTINEL')

    def test_default_report_keeps_fields_and_hides_confidence(self):
        import io
        from contextlib import redirect_stdout
        from src.reporting import fields, width
        output = io.StringIO()
        with redirect_stdout(output):
            fields({'confidence': 'high', 'Image': 'image', 'Env': ['PATH=/bin'], '한글': '긴 값' * 80})
        rendered = output.getvalue()
        self.assertNotIn('confidence', rendered)
        self.assertIn('Image', rendered)
        self.assertIn('PATH=/bin', rendered)
        self.assertTrue(all(width(line) <= 100 for line in rendered.splitlines()))

    def test_field_read_address_record(self):
        from src.structs import STATE
        mem = CachedProcessMemory(); mem.add_chunk(0x10000, b'\x00' * 8 + b'\x01'); mem.finalize()
        reader = StructReader(mem)
        self.assertTrue(reader.read_field(0x10000, STATE, 'Running'))
        self.assertEqual(reader.field_reads[-1]['field_address'], '0x10008')
        self.assertEqual(reader.field_reads[-1]['field'], 'Running')

    def test_kernel_7_folio_index(self):
        from types import SimpleNamespace
        page = SimpleNamespace(vol=SimpleNamespace(offset=100), mapping=200,
                               flags=SimpleNamespace(f=0, has_member=lambda _: True),
                               pageflags_enum={}, has_member=lambda _: False,
                               member=lambda name: 0 if name == '__folio_index' else None,
                               get_content=lambda: b'abc')
        inode = SimpleNamespace(i_size=3, i_mapping=200, get_pages=lambda: iter([page]))
        result = cached_content(inode)
        self.assertTrue(result['complete'])
        self.assertEqual(result['recovered_bytes'], 3)

    def test_state_collection_never_calls_kernel_correlation(self):
        import tempfile
        from unittest.mock import patch
        from src.pipeline import collect
        class Loader:
            def __init__(self, *args, **kwargs):
                self.diagnostics, self.coverage = [], {}
            def initialize(self):
                pass
            def list_processes(self):
                return []
            def discover_containers_via_kernel(self):
                raise AssertionError('Kernel evidence used in state mode')
            def extract_target_processes(self, targets):
                assert targets == ['dockerd']
                return {}
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'test.lime'; path.touch()
            with patch('src.pipeline.VolatilityLoader', Loader):
                result = collect(path, log=lambda *_: None)
            self.assertEqual(result['analysis_mode'], 'dockerd_heap_state')

    def test_reader_layouts_are_instance_local(self):
        from src.structs import STATE
        mem = CachedProcessMemory()
        mem.add_chunk(0x10000, b'\x00' * 8 + b'\x01\x00')
        mem.finalize()
        first, second = StructReader(mem), StructReader(mem)
        first.layouts[id(STATE)] = {'Running': (9, 1, 'bool')}
        self.assertFalse(first.read_field(0x10000, STATE, 'Running'))
        self.assertTrue(second.read_field(0x10000, STATE, 'Running'))

    def test_empty_cached_symbol_profile_is_rejected(self):
        import tempfile
        from src.evidence import save_json
        from src.symbol_builder import validate_cached_profile
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'profile.json'
            save_json({'version': '1.0.0', 'component': 'dockerd', 'structs': {'State': {}}}, path)
            with self.assertRaises(ValueError):
                validate_cached_profile(path, '1.0.0', 'dockerd')

    def test_secret_values_with_spaces_and_nested_objects(self):
        self.assertEqual(redact('SECRET_KEY=one two three'), 'SECRET_KEY=<redacted>')
        self.assertEqual(redact({'credentials': {'value': 'hidden'}}), {'credentials': '<redacted>'})
        self.assertEqual(redact('TOKEN=one two PATH=/bin'), 'TOKEN=<redacted> PATH=/bin')

    def test_dump2_truth_is_not_scored(self):
        from scripts.evaluate_dump_results import evaluate
        result = evaluate({'label': 'S03_paused'}, Path(__file__).resolve().parents[1] / 'dumps/dump2/S03_paused')
        self.assertEqual(result['evaluation'], 'excluded_noncorresponding_acquisition')
        self.assertEqual(result['checks'], [])

    def test_raw_pages_preserve_utf8_boundaries(self):
        payload = b'a' * 4095 + '한'.encode('utf-8')
        class Inode:
            i_size = len(payload)
            def get_contents(self):
                yield 0, payload[:4096]
                yield 1, payload[4096:]
        result = cached_content(Inode(), include_raw=True)
        self.assertTrue(result['complete'])
        self.assertEqual(b''.join(s['raw'] for s in result['segments']), payload)

    def test_exact_content_limit_is_complete(self):
        class Inode:
            i_size = 3
            def get_contents(self):
                yield 0, b'abc'
        self.assertTrue(cached_content(Inode(), limit=3)['complete'])

    def test_atomic_output_preserves_previous_on_failure(self):
        import tempfile
        from src.evidence import save_json
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'result.json'
            save_json({'valid': True}, path)
            old = path.read_bytes()
            with self.assertRaises(TypeError):
                save_json({'invalid': object()}, path)
            self.assertEqual(path.read_bytes(), old)
            self.assertEqual(len(list(Path(directory).iterdir())), 1)

    def test_candidate_history_does_not_mutate_inputs(self):
        first = {'cbase': 10, 'state_valid': False, 'root': 'root'}
        second = {'cbase': 20, 'state_valid': True}
        result = _pick_best(first, second)
        self.assertEqual(result['cbase'], 20)
        self.assertEqual(result['_alternatives'][0]['cbase'], 10)
        self.assertNotIn('_alternatives', first)
        self.assertNotIn('_alternatives', second)

    def test_sparse_slice_keeps_positions(self):
        mem = CachedProcessMemory()
        mem.add_chunk(0x10000, struct.pack('<QQQ', 0x20000, 3, 3))
        mem.add_chunk(0x20000, struct.pack('<QQQQQQ', 0x30000, 3, 0x40000, 5, 0, 0))
        mem.add_chunk(0x30000, b'one')
        mem.finalize()
        reader = StructReader(mem)
        self.assertEqual(reader.read_string_slice(0x10000, 0), ['one', None, ''])
        self.assertEqual(reader.diagnostics[0]['index'], 1)

    def test_absence_is_not_destroyed(self):
        self.assertEqual(identify(None, False, [])['status'], 'Unknown')

    def test_kernel_presence_does_not_prove_running(self):
        result = identify(None, False, [], {'pids': [50]})
        self.assertEqual(result['status'], 'Unknown')
        self.assertEqual(result['candidate_states'], [])
        self.assertEqual(result['evidence'], [])

    def test_destroy_event_does_not_replace_heap_status(self):
        result = identify(None, False, [{'action': 'destroy'}])
        self.assertEqual(result['status'], 'Unknown')

    def test_heap_state_flags(self):
        from src.state_identification import state_to_status
        base = {k: False for k in ['Running', 'Paused', 'Restarting', 'RemovalInProgress', 'Dead', 'Removed', 'HasBeenStartedBefore']}
        cases = [('created', {}), ('running', {'Running': True}), ('paused', {'Running': True, 'Paused': True}),
                 ('restarting', {'Restarting': True}), ('removing', {'RemovalInProgress': True}),
                 ('dead', {'Dead': True}), ('destroyed', {'Removed': True, 'ErrorMsg': ''}), ('exited', {'HasBeenStartedBefore': True}),
                 ('dead', {'Dead': True, 'Removed': True, 'ErrorMsg': 'unable to remove filesystem'}),
                 ('destroyed', {'Dead': True, 'Removed': True, 'ErrorMsg': ''}),
                 ('dead', {'Dead': True, 'Removed': True, 'ErrorMsg': None})]
        for expected, updates in cases:
            with self.subTest(expected=expected):
                self.assertEqual(state_to_status({**base, **updates}), expected)

    def test_heap_candidate_selection_uses_lifecycle_time(self):
        from src.state_identification import select_candidate
        old = {'state_valid': True, 'root': '/container', 'container': {'Name': '/example'}, 'state': {'StartedAt': '2026-09-10T01:00:00Z'}}
        new = {**old, 'state': {'StartedAt': '2026-09-10T01:00:00Z', 'FinishedAt': '2026-09-10T02:00:00Z'}}
        self.assertIs(select_candidate([old, new]), new)

    def test_unreadable_flags_are_not_false(self):
        self.assertEqual(identify({'Running': None}, True, [])['status'], 'Unknown')

    def test_sparse_page_offsets(self):
        class Inode:
            i_size = 8195
            def get_contents(self):
                yield 2, b'end'
        result = cached_content(Inode())
        self.assertEqual(result['segments'][0]['offset'], 8192)
        self.assertEqual(result['missing_ranges'], [[0, 8192]])
        self.assertFalse(result['complete'])

    def test_redaction_nested(self):
        result = redact({'OciSpec': {'process': {'env': ['SECRET_KEY=hidden', 'PATH=/bin']}}})
        self.assertEqual(result['OciSpec']['process']['env'], ['SECRET_KEY=<redacted>', 'PATH=/bin'])

    def test_search_across_adjacent_chunks(self):
        mem = CachedProcessMemory()
        mem.add_chunk(10, b'ab')
        mem.add_chunk(12, b'cd')
        mem.finalize()
        self.assertEqual(mem.find_all(b'bc'), [11])
        self.assertIsNone(mem.read_safe(12, 3))
        with self.assertRaises(ValueError):
            mem.find_all(b'')


if __name__ == '__main__':
    unittest.main()

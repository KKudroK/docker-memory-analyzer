"""Synthetic permission-scope tests; these do not replace capture validation."""
from pathlib import Path
from types import SimpleNamespace
import sys
import unittest
from unittest.mock import patch

BASE = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(BASE))
import volatility3.plugins
volatility3.plugins.__path__.insert(0, str(BASE / 'plugins'))
from volatility3.plugins.container_support import security
from volatility3.plugins.container_support.security import SecurityReader, anonymous_member, kernel_id, map_kernel_id, read_id_map
from container_caps import compare_threads


class Struct:
    def __init__(self, offset=0, **fields):
        self.vol = SimpleNamespace(offset=offset, members={key: None for key in fields})
        self.fields = fields

    def __getattr__(self, key):
        if key in self.fields:
            return self.fields[key]
        raise AttributeError(key)

    def member(self, key):
        return getattr(self, key)

    def has_member(self, key):
        return key in self.fields


class Ptr:
    def __init__(self, target=None):
        self.target = target

    def __int__(self):
        return self.target.vol.offset if self.target else 0

    def dereference(self):
        if self.target is None:
            raise ValueError('null')
        return self.target


class Broken:
    def __int__(self):
        raise OSError('synthetic unreadable page')


class Array(list):
    def __init__(self, values, offset=0, size=4):
        super().__init__(values)
        self.vol = SimpleNamespace(offset=offset, subtype=SimpleNamespace(size=size))


def idmap(first=0, lower=0, count=0xffffffff):
    return Struct(nr_extents=1, extent=[Struct(first=first, lower_first=lower, count=count)])


class SecurityTests(unittest.TestCase):
    def test_kernel_id_wrapper(self):
        self.assertEqual(kernel_id(Struct(val=100000)), 100000)

    def test_namespace_root_is_not_kernel_root(self):
        mapping = [{'namespace_first': 0, 'kernel_first': 100000, 'count': 65536}]
        self.assertEqual(map_kernel_id(mapping, 100000), 0)
        self.assertIsNone(map_kernel_id(mapping, 0))

    def test_id_mapping_end_is_exclusive(self):
        mapping = [{'namespace_first': 10, 'kernel_first': 100, 'count': 2}]
        self.assertEqual(map_kernel_id(mapping, 101), 11)
        self.assertIsNone(map_kernel_id(mapping, 102))

    def test_anonymous_btf_mapping_layout(self):
        mapping = Struct(unnamed_member_0=Struct(unnamed_member_0=idmap(0, 100000, 65536)))
        self.assertEqual(read_id_map(mapping, None), [{'namespace_first': 0, 'kernel_first': 100000, 'count': 65536}])

    def test_overlapping_maps_rejected(self):
        mapping = Struct(nr_extents=2, extent=[Struct(first=0, lower_first=10, count=3), Struct(first=5, lower_first=12, count=3)])
        with self.assertRaisesRegex(ValueError, 'Overlapping'):
            read_id_map(mapping, None)

    def reader(self):
        root = Struct(offset=100, parent=Ptr(), level=0, owner=Struct(val=0), group=Struct(val=0),
                      ns=Struct(inum=1000), uid_map=idmap(), gid_map=idmap())
        reader = SecurityReader.__new__(SecurityReader)
        reader.initial_ns, reader.initial_address, reader.ns_cache, reader.module = root, 100, {}, None
        reader.context = SimpleNamespace(layers={})
        reader.mount_cache = {}
        reader.raw = lambda obj: {'bytes_hex': 'synthetic'}
        return reader, root

    def test_descendant_scope_reaches_initial_namespace(self):
        reader, root = self.reader()
        child = Struct(offset=200, parent=Ptr(root), level=1, owner=Struct(val=1000), group=Struct(val=1000),
                       ns=Struct(inum=2000), uid_map=idmap(0, 100000, 65536), gid_map=idmap(0, 100000, 65536))
        result = reader.user_namespace(child)
        self.assertEqual(result['scope'], 'descendant_user_namespace')
        self.assertEqual([ns['inum'] for ns in result['chain_leaf_to_initial']], [2000, 1000])
        self.assertEqual(reader.user_namespace(root)['scope'], 'initial_user_namespace')

    def test_unknown_root_is_not_classified_as_host_namespace(self):
        reader, root = self.reader()
        root.vol.offset = 300
        result = reader.user_namespace(root)
        self.assertEqual(result['scope'], 'unknown')
        self.assertTrue(any(x['status'] == 'inconsistent' and 'init_user_ns' in x['reason'] for x in result['observations']))

    def test_seccomp_disabled_and_nnp_are_independent(self):
        reader, _ = self.reader()
        task = Struct(atomic_flags=1, seccomp=Struct(mode=0, filter_count=Struct(counter=0), filter=Ptr()))
        result = reader.seccomp(task)
        self.assertTrue(result['no_new_privs'])
        self.assertEqual(result['mode_name'], 'disabled')
        self.assertFalse(result['rules_evaluated'])

    def test_seccomp_filter_count_mismatch_is_error(self):
        reader, _ = self.reader()
        filt = Struct(offset=400, prev=Ptr(), prog=Ptr(Struct(offset=500)), log=False)
        task = Struct(atomic_flags=0, seccomp=Struct(mode=2, filter_count=Struct(counter=2), filter=Ptr(filt)))
        result = reader.seccomp(task)
        self.assertEqual(result['mode'], 2)
        self.assertEqual(result['filter_count'], 2)
        self.assertEqual(result['observed_filter_count'], 1)
        self.assertFalse(result['filter_count_cross_checked'])
        self.assertTrue(any(x['status'] == 'inconsistent' and 'disagree' in x['reason'] for x in result['observations']))

    def test_initial_namespace_symbol_is_optional_and_banner_is_not_whitelisted(self):
        class Banner:
            def cast(self, *args, **kwargs):
                return 'Linux version 6.1.0-custom '
        module = SimpleNamespace(has_symbol=lambda name: False, object_from_symbol=lambda name: Banner())
        reader = SecurityReader(SimpleNamespace(), module)
        self.assertEqual(reader.banner, 'Linux version 6.1.0-custom ')
        self.assertIsNone(reader.initial_address)
        self.assertTrue(any(x['status'] == 'unsupported' for x in reader.compatibility))

    def test_scope_without_initial_symbol_stays_unknown_but_preserves_maps(self):
        reader, root = self.reader()
        reader.initial_ns, reader.initial_address = None, None
        result = reader.user_namespace(root)
        self.assertEqual(result['scope'], 'unknown')
        self.assertEqual(result['chain_leaf_to_initial'][0]['uid_map'][0]['count'], 0xffffffff)
        self.assertEqual(reader.ns_cache, {})

    def test_uid_map_failure_does_not_erase_gid_map_or_verified_scope(self):
        reader, root = self.reader()
        root.fields['uid_map'] = Struct(nr_extents=Broken(), extent=[])
        result = reader.user_namespace(root)
        self.assertEqual(result['scope'], 'initial_user_namespace')
        self.assertIsNone(result['chain_leaf_to_initial'][0]['uid_map'])
        self.assertIsNotNone(result['chain_leaf_to_initial'][0]['gid_map'])
        self.assertTrue(any(x['status'] == 'read_error' for x in result['observations']))
        self.assertEqual(reader.ns_cache, {})

    @staticmethod
    def fake_decode(context, module, cap):
        value = int(cap)
        return {'text': '' if value == 0 else 'chown', 'evidence': {'decoded_mask': hex(value), 'layout': 'synthetic'}, 'observations': []}

    def test_missing_optional_credential_fields_do_not_block_capabilities(self):
        reader, _ = self.reader()
        cred = Struct(offset=700, cap_inheritable=0, cap_permitted=1, cap_effective=1, cap_bset=1)
        with patch.object(security, 'decode_capability', side_effect=self.fake_decode):
            result = reader.credentials(cred)
        self.assertEqual(result['capabilities']['cap_effective'], 'chown')
        self.assertEqual(result['capabilities']['cap_inheritable'], '')
        self.assertIsNone(result['capabilities']['cap_ambient'])
        self.assertIsNone(result['securebits'])
        self.assertIsNone(result['security_blob_address'])
        self.assertTrue(any(x['feature'] == 'cap_ambient' and x['status'] == 'not_present' for x in result['observations']))

    def test_one_unreadable_capability_does_not_erase_other_sets(self):
        reader, _ = self.reader()
        cred = Struct(offset=700, cap_inheritable=0, cap_permitted=Broken(), cap_effective=1, cap_bset=0, cap_ambient=0)
        with patch.object(security, 'decode_capability', side_effect=self.fake_decode):
            result = reader.credentials(cred)
        self.assertIsNone(result['capabilities']['cap_permitted'])
        self.assertEqual(result['capabilities']['cap_effective'], 'chown')
        self.assertEqual(result['capabilities']['cap_bounding'], '')
        self.assertTrue(any(x['feature'] == 'cap_permitted' and x['status'] == 'read_error' for x in result['observations']))

    def test_decoder_observations_identify_their_capability_set(self):
        reader, _ = self.reader()
        decoded = {'text': 'chown', 'evidence': {}, 'observations': [
            {'feature': 'cap_last_cap', 'status': 'unsupported', 'reason': 'missing'}]}
        with patch.object(security, 'decode_capability', return_value=decoded):
            result = reader.credentials(Struct(offset=700, cap_effective=1))
        self.assertTrue(any(x['feature'] == 'cap_last_cap.cap_effective' for x in result['observations']))

    def test_id_map_uses_symbol_array_capacity_instead_of_fixed_five(self):
        values = [Struct(first=n, lower_first=n + 10, count=1) for n in range(3)]
        mapping = Struct(nr_extents=3, extent=values[:2], forward=1000)
        module = SimpleNamespace(get_type=lambda name: SimpleNamespace(size=12),
            object=lambda name, offset, absolute: values[(offset - 1000) // 12])
        self.assertEqual(len(read_id_map(mapping, module)), 3)

    def test_empty_id_map_does_not_require_storage_layout(self):
        self.assertEqual(read_id_map(Struct(nr_extents=0), None), [])

    def test_groups_are_read_even_if_user_namespace_is_missing(self):
        reader, _ = self.reader()
        cred = Struct(group_info=Ptr(Struct(offset=600, ngroups=2, gid=[Struct(val=10), Struct(val=20)])))
        result = {'ids_kernel': {'euid': 0}, 'ids_in_user_namespace': {}}
        reader.enrich_identity(result, cred)
        self.assertEqual(result['supplementary_gids_kernel'], [10, 20])
        self.assertEqual(result['user_namespace']['scope'], 'unknown')
        self.assertIsNone(result['ids_in_user_namespace']['euid'])

    def test_legacy_small_groups_use_array_capacity(self):
        reader, _ = self.reader()
        gids, layout = reader.supplementary_groups(Struct(ngroups=2, small_block=[7, 8], blocks=[]))
        self.assertEqual(gids, [7, 8])
        self.assertEqual(layout, 'group_info.small_block')

    def test_legacy_large_groups_use_page_and_element_sizes(self):
        reader, _ = self.reader()
        reader.context = SimpleNamespace(layers={'kernel': SimpleNamespace(page_size=16)})
        blocks = {1000: [1, 2, 3, 4], 2000: [5]}
        reader.module = SimpleNamespace(layer_name='kernel',
            object=lambda name, offset, absolute, subtype, count: blocks[offset][:count])
        groups = Struct(ngroups=5, nblocks=2, small_block=Array([0, 0]), blocks=[1000, 2000])
        self.assertEqual(reader.supplementary_groups(groups), ([1, 2, 3, 4, 5], 'group_info.blocks'))

    def test_flexible_group_array_keeps_symbol_subtype(self):
        reader, _ = self.reader()
        source = Array([], offset=1000)
        def objects(name, offset, absolute, subtype, count):
            self.assertIs(subtype, source.vol.subtype)
            self.assertEqual((offset, count), (1000, 2))
            return [Struct(val=8), Struct(val=9)]
        reader.module = SimpleNamespace(object=objects)
        self.assertEqual(reader.supplementary_groups(Struct(ngroups=2, gid=source)), ([8, 9], 'group_info.gid'))

    def test_no_seccomp_member_does_not_hide_no_new_privs(self):
        reader, _ = self.reader()
        result = reader.seccomp(Struct(atomic_flags=1))
        self.assertTrue(result['no_new_privs'])
        self.assertIsNone(result['mode'])
        self.assertIsNone(result['filter_count'])
        self.assertFalse(result['chain_complete'])
        self.assertTrue(any(x['feature'] == 'seccomp.structure' and x['status'] == 'unsupported' for x in result['observations']))

    def test_missing_filter_count_uses_complete_chain_and_preserves_provenance(self):
        reader, _ = self.reader()
        filt = Struct(offset=400, prev=Ptr())
        result = reader.seccomp(Struct(no_new_privs=False, seccomp=Struct(mode=2, filter=Ptr(filt))))
        self.assertEqual(result['filter_count'], 1)
        self.assertEqual(result['filter_count_source'], 'complete_filter_chain')
        self.assertTrue(result['chain_complete'])
        self.assertFalse(result['filter_count_cross_checked'])
        self.assertIsNone(result['filters'][0]['program_address'])
        self.assertIsNone(result['filters'][0]['log'])

    def test_cyclic_filter_chain_is_not_promoted_to_complete_count(self):
        reader, _ = self.reader()
        filt = Struct(offset=400)
        filt.fields['prev'] = Ptr(filt)
        result = reader.seccomp(Struct(no_new_privs=False, seccomp=Struct(mode=2, filter=Ptr(filt))))
        self.assertIsNone(result['filter_count'])
        self.assertEqual(result['observed_filter_count'], 1)
        self.assertFalse(result['chain_complete'])
        self.assertTrue(any(x['status'] == 'inconsistent' for x in result['observations']))

    def test_unreadable_nnp_does_not_hide_seccomp_mode(self):
        reader, _ = self.reader()
        result = reader.seccomp(Struct(atomic_flags=Broken(), seccomp=Struct(mode=0, filter=Ptr())))
        self.assertIsNone(result['no_new_privs'])
        self.assertEqual(result['mode'], 0)
        self.assertEqual(result['filter_count'], 0)

    def test_unreadable_direct_nnp_is_not_a_truthy_object(self):
        reader, _ = self.reader()
        result = reader.seccomp(Struct(no_new_privs=Broken()))
        self.assertIsNone(result['no_new_privs'])
        self.assertTrue(any(x['feature'] == 'no_new_privs' and x['status'] == 'read_error' for x in result['observations']))

    def test_missing_namespace_owner_does_not_hide_namespace_number(self):
        reader, _ = self.reader()
        mnt = Struct(offset=400, proc_inum=1234)
        net = Struct(offset=500, ns=Struct(inum=5678))
        proxy = Struct(offset=600, mnt_ns=Ptr(mnt), net_ns=Ptr(net))
        result = reader.resource_namespaces(Struct(nsproxy=Ptr(proxy)))
        self.assertEqual(result['mount']['inum'], 1234)
        self.assertEqual(result['network']['inum'], 5678)
        self.assertIsNone(result['mount']['owner_user_namespace_inum'])
        self.assertIsNone(result['ipc']['inum'])

    def test_mount_failure_is_returned_as_observation(self):
        reader, _ = self.reader()
        result = reader.mounts(Struct())
        self.assertEqual(result['entries'], [])
        self.assertTrue(any(x['status'] == 'unsupported' for x in result['observations']))
        self.assertEqual(reader.mount_cache, {})

    def test_threads_can_share_caps_but_differ_in_restrictions(self):
        common = {'PID': 12, 'cap_effective': 'all', 'UserNS': 1000, 'NoNewPrivs': False, 'SeccompMode': 0}
        tasks = [{**common, 'TID': 12}, {**common, 'TID': 13, 'NoNewPrivs': True, 'SeccompMode': 2}]
        result = compare_threads(tasks)[0]
        self.assertNotIn('cap_effective', result['different_observed_fields'])
        self.assertIn('NoNewPrivs', result['different_observed_fields'])
        self.assertIn('SeccompMode', result['different_observed_fields'])
        self.assertIn('cap_permitted', result['unavailable_fields'])


if __name__ == '__main__':
    unittest.main()

"""Synthetic decoder tests using Volatility integer/array objects and bytes."""

from pathlib import Path
from types import SimpleNamespace
import sys
import unittest

BASE = Path(__file__).resolve().parents[1]
import volatility3.plugins
volatility3.plugins.__path__.insert(0, str(BASE / 'plugins'))
from volatility3.framework import contexts, exceptions, interfaces, objects
from volatility3.framework.layers.physical import BufferDataLayer
from volatility3.framework.objects.templates import ObjectTemplate
from volatility3.plugins.container_support.capabilities_reader import UnsupportedLayout, decode_capability


class CapStruct:
    def __init__(self, fields, size, offset=16):
        self.fields = fields
        self.vol = SimpleNamespace(layer_name='memory', offset=offset, size=size)

    def has_member(self, name):
        return name in self.fields

    def member(self, name):
        return self.fields[name]


class Module:
    def __init__(self, last, missing=False, error=None):
        self.last, self.missing, self.error = last, missing, error

    def has_symbol(self, name):
        return not self.missing

    def object_from_symbol(self, name):
        if self.error:
            raise self.error
        return self.last


class CapabilityReaderTests(unittest.TestCase):
    def fixture(self, value, layout='val', last=40, missing=False, signed=False, count=2):
        width = 8 if layout == 'val' else 4 if layout == 'scalar' else 4 * count
        data = b'\0' * 16 + value.to_bytes(width, 'little', signed=signed)
        data += b'\0' * (64 - len(data)) + last.to_bytes(4, 'little', signed=True)
        context = contexts.Context()
        context.layers.add_layer(BufferDataLayer(context, 'test', 'memory', data))

        def integer(offset, size, is_signed=False):
            return objects.Integer(context, 'test!integer',
                interfaces.objects.ObjectInformation('memory', offset, 'memory', size=size),
                objects.DataFormatInfo(size, 'little', is_signed))

        if layout == 'array':
            subtype = ObjectTemplate(objects.Integer, type_name='test!u32',
                                     data_format=objects.DataFormatInfo(4, 'little', signed))
            field = objects.Array(context, 'test!array',
                interfaces.objects.ObjectInformation('memory', 16, 'memory', size=width),
                count=count, subtype=subtype)
        else:
            field = integer(16, width, signed)
        cap = CapStruct({'val' if layout == 'val' else 'cap': field}, width)
        module = Module(integer(64, 4, True), missing=missing)
        return context, module, cap

    def decode(self, *args, **kwargs):
        return decode_capability(*self.fixture(*args, **kwargs))

    def test_val_and_two_u32_words_agree_including_high_bit(self):
        mask = (1 << 40) | (1 << 12) | 1
        value = self.decode(mask)
        words = self.decode(mask, layout='array')
        self.assertEqual(value['text'], 'chown, net_admin, checkpoint_restore')
        for key in ('raw_mask', 'decoded_mask', 'bytes_hex', 'names'):
            self.assertEqual(value['evidence'][key], words['evidence'][key])
        self.assertEqual(words['evidence']['layout'], 'cap_u32_array_2')

    def test_one_u32_array_and_scalar_are_explicit_layouts(self):
        for layout, count, expected in [('array', 1, 'cap_u32_array_1'), ('scalar', 2, 'cap_u32_scalar')]:
            result = self.decode(0x1001, layout=layout, count=count)
            self.assertEqual(result['text'], 'chown, net_admin')
            self.assertEqual(result['evidence']['layout'], expected)
            self.assertEqual(result['evidence']['size'], 4)

    def test_zero_preserves_empty_observed_set(self):
        result = self.decode(0)
        self.assertEqual(result['text'], '')
        self.assertEqual(result['evidence']['raw_mask'], '0x0')
        self.assertEqual(result['evidence']['names'], [])

    def test_known_full_range_can_be_all(self):
        self.assertEqual(self.decode((1 << 41) - 1)['text'], 'all')

    def test_missing_last_cap_does_not_infer_all(self):
        result = self.decode((1 << 41) - 1, missing=True)
        self.assertNotEqual(result['text'], 'all')
        self.assertIsNone(result['evidence']['kernel_mask'])
        self.assertIsNone(result['evidence']['out_of_range_bits'])
        self.assertEqual(result['observations'][1]['status'], 'not_present')

    def test_future_capability_has_numeric_name_and_no_all(self):
        result = self.decode((1 << 46) - 1, last=45)
        self.assertIn('CAP_BIT_45', result['text'])
        self.assertNotEqual(result['text'], 'all')
        self.assertEqual(result['evidence']['unknown_bits'], hex(((1 << 46) - 1) & ~((1 << 41) - 1)))
        self.assertEqual(result['evidence']['out_of_range_bits'], '0x0')

    def test_out_of_range_bits_remain_in_evidence_and_text(self):
        result = self.decode((1 << 45) | 1)
        self.assertEqual(result['evidence']['raw_mask'], hex((1 << 45) | 1))
        self.assertEqual(result['evidence']['decoded_mask'], '0x1')
        self.assertEqual(result['evidence']['out_of_range_bits'], hex(1 << 45))
        self.assertEqual(result['text'], 'chown [out_of_range: CAP_BIT_45]')
        self.assertTrue(any(item['status'] == 'inconsistent' for item in result['observations']))

    def test_invalid_negative_kernel_limit_preserves_mask(self):
        result = self.decode(0x1001, last=-1)
        self.assertEqual(result['evidence']['decoded_mask'], '0x1001')
        self.assertIsNone(result['evidence']['kernel_mask'])
        self.assertEqual(result['observations'][1]['status'], 'inconsistent')

    def test_limit_beyond_supported_capacity_is_unknown(self):
        result = self.decode(1, last=128)
        self.assertEqual(result['observations'][1]['status'], 'unsupported')
        self.assertIsNone(result['evidence']['kernel_mask'])

    def test_unreadable_limit_does_not_discard_readable_capability(self):
        context, module, cap = self.fixture(1)
        module.error = exceptions.InvalidAddressException('memory', 64, 'synthetic unavailable page')
        result = decode_capability(context, module, cap)
        self.assertEqual(result['text'], 'chown')
        self.assertEqual(result['observations'][1]['status'], 'read_error')

    def test_unsupported_array_length_is_rejected(self):
        with self.assertRaises(UnsupportedLayout):
            self.decode(1, layout='array', count=3)

    def test_signed_capability_storage_is_rejected(self):
        with self.assertRaises(UnsupportedLayout):
            self.decode(-1, signed=True)

    def test_ambiguous_layout_is_rejected(self):
        context, module, cap = self.fixture(1)
        cap.fields['cap'] = cap.fields['val']
        with self.assertRaises(UnsupportedLayout):
            decode_capability(context, module, cap)

    def test_capability_read_failure_propagates(self):
        context, module, cap = self.fixture(1)
        cap.vol.offset = 1000
        with self.assertRaises(exceptions.InvalidAddressException):
            decode_capability(context, module, cap)

    def test_preserved_bytes_must_match_field_object_value(self):
        context, module, cap = self.fixture(1)
        context.layers['memory'].write(16, (2).to_bytes(8, 'little'))
        with self.assertRaisesRegex(ValueError, 'disagrees'):
            decode_capability(context, module, cap)


if __name__ == '__main__':
    unittest.main()

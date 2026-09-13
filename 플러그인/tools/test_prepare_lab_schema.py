"""가상환경 준비 도우미의 변경 범위·복원·실패 경계 검사."""

from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest
from unittest import mock

import prepare_lab_schema as helper


class SchemaPreparationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        raw = helper.installed_schema().read_bytes()
        helper.schema_state(raw)
        cls.stock = raw.replace(helper.LAB_PATTERN.encode(), helper.STOCK_PATTERN.encode())

    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.path = Path(self.directory.name) / "schema-6.2.0.json"
        self.path.write_bytes(self.stock)
        self.backup = self.path.with_name(self.path.name + helper.BACKUP_SUFFIX)

    def test_apply_repeat_and_restore_preserve_exact_original(self):
        helper.prepare_schema(self.path)
        prepared = self.path.read_bytes()
        self.assertEqual(prepared, self.stock.replace(helper.STOCK_PATTERN.encode(), helper.LAB_PATTERN.encode()))
        self.assertEqual(self.backup.read_bytes(), self.stock)
        helper.prepare_schema(self.path)
        self.assertEqual(self.path.read_bytes(), prepared)
        helper.prepare_schema(self.path, restore=True)
        helper.prepare_schema(self.path, restore=True)
        self.assertEqual(self.path.read_bytes(), self.stock)
        self.assertEqual(self.backup.read_bytes(), self.stock)

    def test_unknown_pattern_is_rejected_without_backup_or_write(self):
        altered = self.stock.replace(helper.STOCK_PATTERN.encode(), b".*")
        self.path.write_bytes(altered)
        with self.assertRaises(RuntimeError):
            helper.prepare_schema(self.path)
        self.assertEqual(self.path.read_bytes(), altered)
        self.assertFalse(self.backup.exists())

    def test_unrelated_schema_change_is_rejected(self):
        altered = self.stock + b"\n"
        self.path.write_bytes(altered)
        with self.assertRaises(RuntimeError):
            helper.prepare_schema(self.path)
        self.assertEqual(self.path.read_bytes(), altered)
        self.assertFalse(self.backup.exists())

    def test_tampered_backup_is_rejected(self):
        self.backup.write_bytes(self.stock + b"\n")
        with self.assertRaises(RuntimeError):
            helper.prepare_schema(self.path)
        self.assertEqual(self.path.read_bytes(), self.stock)

    def test_prepared_without_original_backup_is_rejected(self):
        prepared = self.stock.replace(helper.STOCK_PATTERN.encode(), helper.LAB_PATTERN.encode())
        self.path.write_bytes(prepared)
        with self.assertRaises(RuntimeError):
            helper.prepare_schema(self.path)
        self.assertEqual(self.path.read_bytes(), prepared)

    def test_system_python_is_rejected(self):
        with mock.patch.object(helper.sys, "prefix", helper.sys.base_prefix):
            with self.assertRaisesRegex(RuntimeError, "가상환경"):
                helper.installed_schema()

    def test_wrong_volatility_version_is_rejected(self):
        with mock.patch.object(helper.importlib.metadata, "version", return_value="2.27.0"):
            with self.assertRaisesRegex(RuntimeError, "2.28.0"):
                helper.installed_schema()

    def test_missing_validator_is_rejected(self):
        with mock.patch.object(helper.importlib.util, "find_spec", return_value=None):
            with self.assertRaisesRegex(RuntimeError, "jsonschema"):
                helper.installed_schema()

    def test_external_editable_install_is_rejected(self):
        def find_spec(name):
            return SimpleNamespace(origin=str(self.path.parent / "volatility3" / "__init__.py"))

        with mock.patch.object(helper.importlib.util, "find_spec", side_effect=find_spec):
            with self.assertRaisesRegex(RuntimeError, "가상환경 밖"):
                helper.installed_schema()


if __name__ == "__main__":
    unittest.main()

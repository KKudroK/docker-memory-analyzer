"""Exercise isolated error handlers with actual Volatility exception objects."""
import ast
from pathlib import Path
from types import SimpleNamespace
import unittest

from volatility3.framework import exceptions


source = Path(__file__).resolve().parents[1] / "container_tasks.py"
tree = ast.parse(source.read_text(encoding="utf-8"))
helper = next(n for n in tree.body if isinstance(n, ast.FunctionDef) and n.name == "read_error_text")
plugin = next(n for n in tree.body if isinstance(n, ast.ClassDef) and n.name == "ContainerTasks")
handlers = [n for n in plugin.body if isinstance(n, ast.FunctionDef)
            and n.name in ("_shim_identity", "_cgroup_container_id")]


class ErrorContextTests(unittest.TestCase):
    def exercise(self, exc):
        def fail(*args, **kwargs):
            raise exc

        namespace = {"exceptions": exceptions, "docker_artifacts": SimpleNamespace(
            DockerArtifacts=SimpleNamespace(read_task_argv=fail))}
        exec(compile(ast.Module(body=[helper, *handlers], type_ignores=[]), str(source), "exec"), namespace)
        task = SimpleNamespace(tgid=123, vol=SimpleNamespace(
            offset=0x2000, layer_name="kernel", native_layer_name="physical"))
        owner = SimpleNamespace(context=None, config={"kernel": "kernel"})
        errors = []
        record = namespace["_shim_identity"](owner, task, {}, 0x2000, errors=errors)
        self.assertEqual(record["error"], errors[0])
        self.assertIsNone(record["container_id"])
        result = namespace["_cgroup_container_id"](
            owner, task, {"resolver": SimpleNamespace(resolve=fail)}, errors=errors)
        self.assertIsNone(result)
        self.assertEqual(len(errors), 2)
        for message in errors:
            self.assertIn("task=0x2000", message)
            self.assertIn(type(exc).__name__, message)
        return errors

    def test_invalid_address_without_message(self):
        for message in self.exercise(exceptions.InvalidAddressException("process", 0xdeadbeef)):
            self.assertIn("layer_name=process", message)
            self.assertIn("invalid_address=0xdeadbeef", message)

    def test_paged_invalid_address(self):
        exc = exceptions.PagedInvalidAddressException("process", 0, 12, 0, "page missing")
        for message in self.exercise(exc):
            self.assertIn("invalid_address=0x0", message)
            self.assertIn("layer_name=process", message)
            self.assertIn("page missing", message)

    def test_other_errors_keep_message(self):
        for message in self.exercise(ValueError("invalid argv bounds")):
            self.assertIn("invalid argv bounds", message)
            self.assertNotIn("invalid_address=", message)


if __name__ == "__main__":
    unittest.main()

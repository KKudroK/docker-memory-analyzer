import json
import tempfile
import unittest
from pathlib import Path

from container_state_analyzer.r2 import import_round2_root


class Round2ImportTests(unittest.TestCase):
    def test_imports_memory_only_validation_layout(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            validation = root / "S02_running" / "validation"
            validation.mkdir(parents=True)
            container_id = "a" * 64
            verification = {
                "label": "S02_running",
                "kernel": "7.0.0-31-generic",
                "build_id": "build",
                "container_processes": [],
                "go_state": {
                    "container_id": container_id,
                    "container_address": "0x10",
                    "state_address": "0x20",
                    "restart_count": 0,
                    "state": {"Running": True, "Paused": False, "Restarting": False, "RemovalInProgress": False, "Dead": False, "Pid": 99, "ExitCode": 0},
                },
            }
            tasks = [{"pid": 99, "mm": "0x100", "exit_state": 0, "cgroup": f"/system.slice/docker-{container_id}.scope", "namespaces": {"net_ns": 55}}]
            cgroups = [{"path": f"/system.slice/docker-{container_id}.scope", "css_flags": 10}]
            networks = [{"inum": 4026531833, "devices": [{"name": "veth0"}]}, {"inum": 55, "devices": [{"name": "eth0"}]}]
            for name, value in (("verification.json", verification), ("tasks.json", tasks), ("cgroups.json", cgroups), ("networks.json", networks)):
                (validation / name).write_text(json.dumps(value), encoding="utf-8")

            cases = import_round2_root(root)
            self.assertEqual(len(cases), 1)
            index = cases[0].index()
            self.assertEqual(index["kernel.live_task_count"].value, 1)
            self.assertTrue(index["kernel.target_netns_present"].value)
            self.assertEqual(cases[0].environment["source_policy"], "memory-only")


if __name__ == "__main__":
    unittest.main()

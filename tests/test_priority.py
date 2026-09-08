import unittest

from container_state_analyzer.demo_data import round2_cases
from container_state_analyzer.engine import Analyzer
from container_state_analyzer.priority import evaluate_priority
from container_state_analyzer.rules import load_priority_axes, load_rules


class PriorityTests(unittest.TestCase):
    def test_priority_has_no_weighted_score_and_reports_ablation(self):
        result = evaluate_priority(
            Analyzer(load_rules()),
            round2_cases(),
            load_priority_axes(),
            "state_classification",
        )
        self.assertEqual(result["baseline"]["top1_accuracy"], 1.0)
        self.assertTrue(result["artifact_groups"])
        self.assertNotIn("score", result["artifact_groups"][0])
        self.assertIn("delta_top1_accuracy", result["artifact_groups"][0]["ablation"])
        self.assertEqual(
            result["tamper_scenario"]["masked_groups"],
            ["runtime_flags", "runtime_process", "runtime_history"],
        )


if __name__ == "__main__":
    unittest.main()


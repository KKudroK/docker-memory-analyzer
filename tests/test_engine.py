import unittest

from container_state_analyzer.demo_data import round2_cases
from container_state_analyzer.engine import Analyzer, evaluate_condition
from container_state_analyzer.model import Availability, Observation, ResultCode
from container_state_analyzer.rules import load_rules


class EngineTests(unittest.TestCase):
    def setUp(self):
        self.analyzer = Analyzer(load_rules())

    def test_round2_top1_matches_all_seven_states(self):
        result = self.analyzer.analyze(round2_cases())
        self.assertEqual(result["summary"]["top1_accuracy"], 1.0)
        self.assertEqual(result["summary"]["macro_f1"], 1.0)

    def test_unknown_is_not_treated_as_absent(self):
        condition = {
            "id": "T1",
            "artifact": "kernel.overlay_mounted",
            "layer": "kernel",
            "operator": "eq",
            "expected": False,
            "strength": "decisive",
            "polarity": "support",
        }
        observation = Observation(
            artifact="kernel.overlay_mounted",
            layer="kernel",
            availability=Availability.UNKNOWN,
            collector="test",
        )
        result = evaluate_condition("created", condition, observation, {})
        self.assertIs(result.result, ResultCode.UNKNOWN)

    def test_actual_absence_is_separate_result_for_value_predicate(self):
        condition = {
            "id": "T2",
            "artifact": "kernel.target",
            "layer": "kernel",
            "operator": "eq",
            "expected": 0,
            "strength": "supporting",
            "polarity": "support",
        }
        observation = Observation(
            artifact="kernel.target",
            layer="kernel",
            availability=Availability.ABSENT,
            collector="test",
        )
        result = evaluate_condition("created", condition, observation, {})
        self.assertIs(result.result, ResultCode.ABSENT)

    def test_paused_join_uses_effective_freezer_state(self):
        result = self.analyzer.analyze_case(round2_cases()[2])
        j5 = next(row for row in result["joins"] if row["join_id"] == "J5")
        self.assertEqual(j5["result"], "MATCH")

    def test_config_and_heap_tamper_mismatch_is_visible(self):
        case = round2_cases()[-1]
        for artifact, value in (
            ("container.config.state.running", False),
            ("container.config.state.paused", False),
            ("container.config.state.restarting", False),
            ("container.config.state.dead", False),
        ):
            case.observations.append(
                Observation(
                    artifact=artifact,
                    layer="container",
                    availability=Availability.PRESENT,
                    value=value,
                    collector="test.config",
                    group="container_metadata",
                )
            )
        result = self.analyzer.analyze_case(case)
        j16 = next(row for row in result["joins"] if row["join_id"] == "J16")
        self.assertEqual(j16["result"], "MISMATCH")


if __name__ == "__main__":
    unittest.main()

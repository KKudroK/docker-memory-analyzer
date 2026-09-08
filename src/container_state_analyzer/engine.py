from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass
from typing import Any

from .model import (
    Availability,
    ConditionResult,
    EvidenceCase,
    Observation,
    ResultCode,
    Strength,
)
from .joins import evaluate_joins


STRENGTH_RANK = {
    Strength.WEAK: 1,
    Strength.SUPPORTING: 2,
    Strength.DECISIVE: 3,
}


def _valid_environment(required: dict[str, Any], environment: dict[str, Any]) -> bool:
    return all(environment.get(key) == value for key, value in required.items())


def _predicate(operator: str, actual: Any, expected: Any) -> bool:
    if operator == "eq":
        return actual == expected
    if operator == "ne":
        return actual != expected
    if operator == "gt":
        return actual > expected
    if operator == "gte":
        return actual >= expected
    if operator == "lt":
        return actual < expected
    if operator == "lte":
        return actual <= expected
    if operator == "in":
        return actual in expected
    if operator == "not_in":
        return actual not in expected
    if operator == "truthy":
        return bool(actual)
    if operator == "falsy":
        return not bool(actual)
    if operator == "exists":
        return True
    if operator == "absent":
        return False
    raise ValueError(f"Unsupported operator: {operator}")


def evaluate_condition(
    state: str,
    condition: dict[str, Any],
    observation: Observation | None,
    environment: dict[str, Any],
) -> ConditionResult:
    strength = Strength(condition["strength"])
    artifact = condition["artifact"]
    layer = condition["layer"]
    operator = condition.get("operator", "eq")
    expected = condition.get("expected")
    valid_when = condition.get("valid_when", {})

    if valid_when and not _valid_environment(valid_when, environment):
        code = ResultCode.UNKNOWN
        actual = None
        reason = f"valid_when 불충족: {valid_when}"
    elif observation is None or observation.availability is Availability.UNKNOWN:
        code = ResultCode.UNKNOWN
        actual = None if observation is None else observation.value
        reason = "수집 결과가 없거나 읽기에 실패함"
    elif observation.availability is Availability.ABSENT:
        actual = None
        if operator == "absent":
            code = ResultCode.MATCH
            reason = "수집기가 대상의 실제 부재를 확인함"
        elif operator == "exists":
            code = ResultCode.MISMATCH
            reason = "존재해야 하지만 실제 부재가 확인됨"
        else:
            code = ResultCode.ABSENT
            reason = "대상이 실제로 부재하여 값 조건을 평가할 수 없음"
    else:
        actual = observation.value
        matched = _predicate(operator, actual, expected)
        code = ResultCode.MATCH if matched else ResultCode.MISMATCH
        reason = f"{actual!r} {operator} {expected!r}"

    return ConditionResult(
        condition_id=condition["id"],
        state=state,
        artifact=artifact,
        layer=layer,
        result=code,
        strength=strength,
        polarity=condition.get("polarity", "support"),
        group=condition.get("group", artifact),
        expected=expected,
        actual=actual,
        reason=reason,
        collector=None if observation is None else observation.collector,
    )


@dataclass(slots=True)
class Analyzer:
    rules: dict[str, Any]

    def analyze_case(self, case: EvidenceCase) -> dict[str, Any]:
        index = case.index()
        candidates: list[dict[str, Any]] = []

        for state, state_rule in self.rules["states"].items():
            results = [
                evaluate_condition(state, condition, index.get(condition["artifact"]), case.environment)
                for condition in state_rule["conditions"]
            ]
            contradiction_hits = [
                result
                for result in results
                if result.polarity == "contradiction" and result.result is ResultCode.MATCH
            ]
            support_matches = [
                result
                for result in results
                if result.polarity == "support" and result.result is ResultCode.MATCH
            ]

            # Several collectors can expose the same underlying fact. Count a correlated
            # group once, at its strongest matched condition.
            best_by_group: dict[str, Strength] = {}
            for result in support_matches:
                current = best_by_group.get(result.group)
                if current is None or STRENGTH_RANK[result.strength] > STRENGTH_RANK[current]:
                    best_by_group[result.group] = result.strength

            counts = {
                "decisive": sum(value is Strength.DECISIVE for value in best_by_group.values()),
                "supporting": sum(value is Strength.SUPPORTING for value in best_by_group.values()),
                "weak": sum(value is Strength.WEAK for value in best_by_group.values()),
            }
            support_mismatches = sum(
                result.polarity == "support" and result.result is ResultCode.MISMATCH
                for result in results
            )
            required_ids = {
                condition["id"]
                for condition in state_rule["conditions"]
                if condition.get("required_for_confirmation", False)
            }
            required_unknown = [
                result.condition_id
                for result in results
                if result.condition_id in required_ids
                and result.result in {ResultCode.UNKNOWN, ResultCode.ABSENT}
            ]
            excluded = bool(contradiction_hits)
            rank_key = (
                0 if excluded else 1,
                counts["decisive"],
                counts["supporting"],
                counts["weak"],
                -support_mismatches,
            )
            candidates.append(
                {
                    "state": state,
                    "excluded": excluded,
                    "rank_key": list(rank_key),
                    "evidence_groups": counts,
                    "required_unknown": required_unknown,
                    "contradictions": [result.to_dict() for result in contradiction_hits],
                    "conditions": [result.to_dict() for result in results],
                }
            )

        candidates.sort(key=lambda item: tuple(item["rank_key"]), reverse=True)
        viable = [candidate for candidate in candidates if not candidate["excluded"]]
        decision = "no_candidate"
        predicted_state: str | None = None
        deferred_reasons: list[str] = []

        if viable:
            top = viable[0]
            predicted_state = top["state"]
            runner = viable[1] if len(viable) > 1 else None
            unique_rank = runner is None or top["rank_key"] != runner["rank_key"]
            has_decisive = top["evidence_groups"]["decisive"] > 0
            if not unique_rank:
                deferred_reasons.append("최상위 후보의 근거 등급이 동률임")
            if not has_decisive:
                deferred_reasons.append("decisive 근거가 없음")
            if top["required_unknown"]:
                deferred_reasons.append(
                    "확정 필수 조건이 UNKNOWN/ABSENT: " + ", ".join(top["required_unknown"])
                )
            decision = "confirmed" if not deferred_reasons else "deferred"

        return {
            "case_id": case.case_id,
            "subject": case.subject,
            "ground_truth": case.ground_truth,
            "decision": decision,
            "predicted_state": predicted_state,
            "correct": None if case.ground_truth is None else predicted_state == case.ground_truth,
            "deferred_reasons": deferred_reasons,
            "candidate_order": [candidate["state"] for candidate in candidates],
            "candidates": candidates,
            "observation_summary": self._observation_summary(case),
            "joins": evaluate_joins(case),
            "provenance": case.provenance,
        }

    def analyze(self, cases: list[EvidenceCase]) -> dict[str, Any]:
        analyses = [self.analyze_case(case) for case in cases]
        return {
            "schema_version": "1.0",
            "method": "rule-based four-result correlation",
            "cases": analyses,
            "summary": summarize_results(analyses),
        }

    @staticmethod
    def _observation_summary(case: EvidenceCase) -> dict[str, int]:
        counts: dict[str, int] = defaultdict(int)
        for observation in case.observations:
            counts[observation.availability.value] += 1
        return dict(counts)


def summarize_results(results: list[dict[str, Any]]) -> dict[str, Any]:
    labeled = [result for result in results if result.get("ground_truth")]
    correct = sum(result.get("correct") is True for result in labeled)
    confirmed = [result for result in labeled if result["decision"] == "confirmed"]
    confirmed_correct = sum(result.get("correct") is True for result in confirmed)
    labels = sorted({result["ground_truth"] for result in labeled})
    per_label_f1: dict[str, float] = {}
    for label in labels:
        tp = sum(r["ground_truth"] == label and r["predicted_state"] == label for r in labeled)
        fp = sum(r["ground_truth"] != label and r["predicted_state"] == label for r in labeled)
        fn = sum(r["ground_truth"] == label and r["predicted_state"] != label for r in labeled)
        precision = tp / (tp + fp) if tp + fp else 0.0
        recall = tp / (tp + fn) if tp + fn else 0.0
        per_label_f1[label] = (
            2 * precision * recall / (precision + recall) if precision + recall else 0.0
        )
    return {
        "labeled_cases": len(labeled),
        "top1_accuracy": correct / len(labeled) if labeled else None,
        "macro_f1": sum(per_label_f1.values()) / len(per_label_f1) if per_label_f1 else None,
        "confirmed_coverage": len(confirmed) / len(labeled) if labeled else None,
        "confirmed_accuracy": confirmed_correct / len(confirmed) if confirmed else None,
        "deferred_cases": [r["case_id"] for r in labeled if r["decision"] == "deferred"],
        "incorrect_cases": [r["case_id"] for r in labeled if not r.get("correct")],
        "per_label_f1": per_label_f1,
    }

from __future__ import annotations

from collections import Counter
from copy import deepcopy
from typing import Any

from .engine import Analyzer
from .model import EvidenceCase


ORDINAL = {"low": 1, "medium": 2, "high": 3}


def _ablate(cases: list[EvidenceCase], *, group: str | None = None, layer: str | None = None) -> list[EvidenceCase]:
    cloned = deepcopy(cases)
    for case in cloned:
        case.observations = [
            observation
            for observation in case.observations
            if not ((group and observation.group == group) or (layer and observation.layer == layer))
        ]
    return cloned


def _changed_cases(baseline: dict[str, Any], ablated: dict[str, Any]) -> list[dict[str, Any]]:
    changed: list[dict[str, Any]] = []
    for before, after in zip(baseline["cases"], ablated["cases"]):
        if (before["predicted_state"], before["decision"]) != (
            after["predicted_state"],
            after["decision"],
        ):
            changed.append(
                {
                    "case_id": before["case_id"],
                    "before": {"state": before["predicted_state"], "decision": before["decision"]},
                    "after": {"state": after["predicted_state"], "decision": after["decision"]},
                }
            )
    return changed


def _delta(before: float | None, after: float | None) -> float | None:
    if before is None or after is None:
        return None
    return before - after


def evaluate_priority(
    analyzer: Analyzer,
    cases: list[EvidenceCase],
    priority_config: dict[str, Any],
    objective: str = "state_classification",
) -> dict[str, Any]:
    baseline = analyzer.analyze(cases)
    baseline_summary = baseline["summary"]
    availability = Counter(
        observation.group
        for case in cases
        for observation in case.observations
        if observation.availability.value != "unknown" and observation.group
    )
    rows: list[dict[str, Any]] = []

    for config in priority_config["groups"]:
        group = config["id"]
        ablated = analyzer.analyze(_ablate(cases, group=group))
        summary = ablated["summary"]
        rows.append(
            {
                "group": group,
                "label": config["label"],
                "layer": config["layer"],
                "objective": objective,
                "objective_priority": config["objectives"].get(objective, "low"),
                "axes": config["axes"],
                "observed_values": availability[group],
                "measurement_status": "measured" if availability[group] else "not_measured",
                "ablation": {
                    "top1_accuracy": summary["top1_accuracy"],
                    "confirmed_coverage": summary["confirmed_coverage"],
                    "macro_f1": summary["macro_f1"],
                    "delta_top1_accuracy": _delta(
                        baseline_summary["top1_accuracy"], summary["top1_accuracy"]
                    ),
                    "delta_confirmed_coverage": _delta(
                        baseline_summary["confirmed_coverage"], summary["confirmed_coverage"]
                    ),
                    "delta_macro_f1": _delta(baseline_summary["macro_f1"], summary["macro_f1"]),
                    "changed_cases": _changed_cases(baseline, ablated),
                },
            }
        )

    # The order is lexicographic and inspectable; no hidden weighted confidence score is used.
    def sort_key(row: dict[str, Any]) -> tuple[Any, ...]:
        ablation = row["ablation"]
        return (
            ablation["delta_top1_accuracy"] or 0.0,
            ablation["delta_confirmed_coverage"] or 0.0,
            ablation["delta_macro_f1"] or 0.0,
            1 if row["measurement_status"] == "measured" else 0,
            ORDINAL[row["objective_priority"]],
            ORDINAL[row["axes"]["discrimination"]],
            ORDINAL[row["axes"]["collection_success"]],
            ORDINAL[row["axes"]["tamper_resistance"]],
            -ORDINAL[row["axes"]["extraction_cost"]],
        )

    rows.sort(key=sort_key, reverse=True)
    for rank, row in enumerate(rows, start=1):
        row["rank"] = rank
        loss = row["ablation"]["delta_top1_accuracy"] or 0.0
        coverage_loss = row["ablation"]["delta_confirmed_coverage"] or 0.0
        if row["measurement_status"] == "not_measured":
            row["tier"] = "measurement_gap"
        elif loss > 0 or coverage_loss >= 0.20:
            row["tier"] = "critical"
        elif row["objective_priority"] == "high" or coverage_loss > 0:
            row["tier"] = "important"
        else:
            row["tier"] = "complementary"

    layer_ablation: list[dict[str, Any]] = []
    for layer in ("runtime", "container", "kernel"):
        ablated = analyzer.analyze(_ablate(cases, layer=layer))
        summary = ablated["summary"]
        layer_ablation.append(
            {
                "layer": layer,
                "top1_accuracy": summary["top1_accuracy"],
                "confirmed_coverage": summary["confirmed_coverage"],
                "delta_top1_accuracy": _delta(
                    baseline_summary["top1_accuracy"], summary["top1_accuracy"]
                ),
                "delta_confirmed_coverage": _delta(
                    baseline_summary["confirmed_coverage"], summary["confirmed_coverage"]
                ),
                "changed_cases": _changed_cases(baseline, ablated),
            }
        )

    runtime_tamper = analyzer.analyze(
        _ablate(
            _ablate(_ablate(cases, group="runtime_flags"), group="runtime_process"),
            group="runtime_history",
        )
    )
    return {
        "schema_version": "1.0",
        "objective": objective,
        "ranking_method": "empirical group ablation, then purpose-specific ordinal tie-breaks",
        "baseline": baseline_summary,
        "artifact_groups": rows,
        "measurement_gaps": [row["group"] for row in rows if row["measurement_status"] == "not_measured"],
        "layer_ablation": layer_ablation,
        "tamper_scenario": {
            "name": "runtime state fields unavailable or modified",
            "masked_groups": ["runtime_flags", "runtime_process", "runtime_history"],
            "summary": runtime_tamper["summary"],
            "changed_cases": _changed_cases(baseline, runtime_tamper),
        },
    }

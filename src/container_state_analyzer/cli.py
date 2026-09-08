from __future__ import annotations

import argparse
import os
from pathlib import Path
import sys
from typing import Any

from .demo_data import round2_cases
from .engine import Analyzer
from .io import load_cases, save_cases, save_json
from .priority import evaluate_priority
from .r2 import import_round2_root
from .report import write_html_report
from .rules import load_priority_axes, load_rules


def _write_run(
    cases: list[Any],
    output_dir: Path,
    *,
    rules_path: str | None,
    priority_path: str | None,
    objective: str,
    save_observations: bool = False,
) -> dict[str, Path]:
    analyzer = Analyzer(load_rules(rules_path))
    analysis = analyzer.analyze(cases)
    priority = evaluate_priority(analyzer, cases, load_priority_axes(priority_path), objective)
    output_dir.mkdir(parents=True, exist_ok=True)
    paths = {
        "analysis": save_json(output_dir / "analysis.json", analysis),
        "priority": save_json(output_dir / "priority.json", priority),
        "report": write_html_report(output_dir / "report.html", analysis, priority),
    }
    if save_observations:
        paths["observations"] = save_cases(
            output_dir / "observations.json",
            cases,
            source={"policy": cases[0].environment.get("source_policy") if cases else None},
        )
    _print_summary(analysis, priority, paths)
    return paths


def _print_summary(analysis: dict[str, Any], priority: dict[str, Any], paths: dict[str, Path]) -> None:
    summary = analysis["summary"]
    print("\n[상태 판별]")
    for case in analysis["cases"]:
        marker = "OK" if case.get("correct") else "CHECK"
        print(
            f"  {marker:5} {case['case_id']:<18} -> {case['predicted_state']:<10} ({case['decision']})"
        )
    metric = lambda value: "-" if value is None else f"{value:.3f}"
    print(
        f"\nTop-1={metric(summary['top1_accuracy'])}  "
        f"확정률={metric(summary['confirmed_coverage'])}  "
        f"확정 결과 정확도={metric(summary['confirmed_accuracy'])}"
    )
    print("\n[우선순위 상위 5개]")
    for row in priority["artifact_groups"][:5]:
        print(
            f"  {row['rank']:>2}. {row['label']:<36} {row['tier']:<13} "
            f"정확도 손실={metric(row['ablation']['delta_top1_accuracy'])} "
            f"확정률 손실={metric(row['ablation']['delta_confirmed_coverage'])}"
        )
    print("\n[출력]")
    for name, path in paths.items():
        print(f"  {name:<12} {path.resolve()}")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="container-state",
        description="Docker/Linux memory artifact correlation and state analysis",
    )
    parser.add_argument("--rules", help="custom rules JSON")
    parser.add_argument("--priority-config", help="custom priority axes JSON")
    sub = parser.add_subparsers(dest="command", required=True)

    demo = sub.add_parser("demo", help="run the normalized Google Drive Round2 validation subset")
    demo.add_argument("--output-dir", default="output/round2-demo")
    demo.add_argument("--objective", default="state_classification", choices=["state_classification", "identifier_recovery", "tamper_detection", "activity_reconstruction"])

    round2 = sub.add_parser("round2", help="import a downloaded Round2 folder and analyze all seven states")
    round2.add_argument("--root", required=True, help="folder containing S01_created ... S07_dead")
    round2.add_argument("--output-dir", default="output/round2")
    round2.add_argument("--include-live-sidecars", action="store_true", help="also use config.v2.json copied from the live host; default is memory-only")
    round2.add_argument("--objective", default="state_classification", choices=["state_classification", "identifier_recovery", "tamper_detection", "activity_reconstruction"])

    analyze = sub.add_parser("analyze", help="analyze normalized observation JSON")
    analyze.add_argument("--input", required=True)
    analyze.add_argument("--output-dir", default="output/analysis")
    analyze.add_argument("--objective", default="state_classification", choices=["state_classification", "identifier_recovery", "tamper_detection", "activity_reconstruction"])
    return parser


def main(argv: list[str] | None = None) -> int:
    if os.name == "nt" and hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8")
    parser = build_parser()
    args = parser.parse_args(argv)
    output_dir = Path(args.output_dir)
    if args.command == "demo":
        cases = round2_cases()
        save_observations = True
    elif args.command == "round2":
        cases = import_round2_root(args.root, include_live_sidecars=args.include_live_sidecars)
        save_observations = True
    else:
        cases = load_cases(args.input)
        save_observations = False
    _write_run(
        cases,
        output_dir,
        rules_path=args.rules,
        priority_path=args.priority_config,
        objective=args.objective,
        save_observations=save_observations,
    )
    return 0

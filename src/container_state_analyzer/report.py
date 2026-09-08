from __future__ import annotations

import html
from pathlib import Path
from typing import Any


def _pct(value: float | None) -> str:
    return "-" if value is None else f"{value * 100:.1f}%"


def _e(value: Any) -> str:
    return html.escape(str(value))


def _badge(value: str) -> str:
    return f'<span class="badge {_e(value.lower())}">{_e(value)}</span>'


def write_html_report(
    path: str | Path,
    analysis: dict[str, Any],
    priority: dict[str, Any] | None = None,
) -> Path:
    target = Path(path)
    target.parent.mkdir(parents=True, exist_ok=True)
    summary = analysis["summary"]
    cards = [
        ("Round2 cases", summary["labeled_cases"]),
        ("Top-1 accuracy", _pct(summary["top1_accuracy"])),
        ("Confirmed coverage", _pct(summary["confirmed_coverage"])),
        ("Confirmed accuracy", _pct(summary["confirmed_accuracy"])),
    ]
    case_rows = "".join(
        f"<tr><td>{_e(case['case_id'])}</td><td>{_e(case.get('ground_truth'))}</td>"
        f"<td><strong>{_e(case.get('predicted_state'))}</strong></td>"
        f"<td>{_badge(case['decision'])}</td><td>{'yes' if case.get('correct') else 'no'}</td>"
        f"<td>{_e(', '.join(case.get('deferred_reasons') or []) or '-')}</td></tr>"
        for case in analysis["cases"]
    )
    priority_rows = ""
    layer_rows = ""
    tamper_html = ""
    if priority:
        priority_rows = "".join(
            f"<tr><td>{row['rank']}</td><td><strong>{_e(row['label'])}</strong><br><code>{_e(row['group'])}</code></td>"
            f"<td>{_e(row['layer'])}</td><td>{_badge(row['tier'])}</td><td>{_e(row['measurement_status'])}</td>"
            f"<td>{_pct(row['ablation']['delta_top1_accuracy'])}</td>"
            f"<td>{_pct(row['ablation']['delta_confirmed_coverage'])}</td>"
            f"<td>{_e(row['objective_priority'])}</td>"
            f"<td>{_e(row['axes']['tamper_resistance'])}</td>"
            f"<td>{len(row['ablation']['changed_cases'])}</td></tr>"
            for row in priority["artifact_groups"]
        )
        layer_rows = "".join(
            f"<tr><td>{_e(row['layer'])}</td><td>{_pct(row['top1_accuracy'])}</td>"
            f"<td>{_pct(row['confirmed_coverage'])}</td>"
            f"<td>{_pct(row['delta_top1_accuracy'])}</td>"
            f"<td>{_pct(row['delta_confirmed_coverage'])}</td></tr>"
            for row in priority["layer_ablation"]
        )
        tamper = priority["tamper_scenario"]
        tamper_html = f"""
        <section>
          <div class="section-kicker">TAMPER SCENARIO</div>
          <h2>Runtime 상태 필드가 없거나 변조된 경우</h2>
          <p class="lead">Runtime flags, PID/ExitCode, RestartCount 묶음을 전부 가린 뒤 남는 판별력이다.</p>
          <div class="cards compact">
            <div class="card"><span>Top-1</span><strong>{_pct(tamper['summary']['top1_accuracy'])}</strong></div>
            <div class="card"><span>Confirmed coverage</span><strong>{_pct(tamper['summary']['confirmed_coverage'])}</strong></div>
            <div class="card"><span>Deferred</span><strong>{len(tamper['summary']['deferred_cases'])}</strong></div>
          </div>
        </section>"""

    details = []
    for case in analysis["cases"]:
        top = next((row for row in case["candidates"] if row["state"] == case["predicted_state"]), None)
        evidence = ""
        if top:
            relevant = [
                row
                for row in top["conditions"]
                if row["result"] in {"MATCH", "UNKNOWN", "ABSENT"}
            ]
            evidence = "".join(
                f"<tr><td><code>{_e(row['condition_id'])}</code></td><td>{_e(row['artifact'])}</td>"
                f"<td>{_badge(row['result'])}</td><td>{_e(row['strength'])}</td><td>{_e(row['reason'])}</td></tr>"
                for row in relevant
            )
        joins = "".join(
            f"<tr><td><code>{_e(row['join_id'])}</code></td><td>{_e(row['name'])}</td>"
            f"<td>{_badge(row['result'])}</td><td>{_e(row['reason'])}</td></tr>"
            for row in case.get("joins", [])
        )
        details.append(
            f"""
            <details>
              <summary><span>{_e(case['case_id'])}</span><strong>{_e(case['predicted_state'])}</strong>{_badge(case['decision'])}</summary>
              <div class="detail-body">
                <h3>Top candidate evidence</h3>
                <div class="table-wrap"><table><thead><tr><th>ID</th><th>Artifact</th><th>Result</th><th>Strength</th><th>Reason</th></tr></thead><tbody>{evidence}</tbody></table></div>
                <h3>Cross-layer joins</h3>
                <div class="table-wrap"><table><thead><tr><th>Join</th><th>Comparison</th><th>Result</th><th>Reason</th></tr></thead><tbody>{joins}</tbody></table></div>
              </div>
            </details>"""
        )

    priority_section = ""
    if priority:
        priority_section = f"""
        <section>
          <div class="section-kicker">ARTIFACT PRIORITY</div>
          <h2>상태 판별 목적 우선순위</h2>
          <p class="lead">각 묶음을 통째로 제거한 ablation 손실을 먼저 보고, 동률일 때만 설계사양의 축별 평가를 사용했다. 합산 점수나 확률은 사용하지 않았다.</p>
          <div class="table-wrap"><table>
            <thead><tr><th>#</th><th>Artifact group</th><th>Layer</th><th>Tier</th><th>Measured</th><th>Accuracy loss</th><th>Coverage loss</th><th>Purpose</th><th>Tamper resistance</th><th>Changed cases</th></tr></thead>
            <tbody>{priority_rows}</tbody>
          </table></div>
        </section>
        <section>
          <div class="section-kicker">LAYER ABLATION</div>
          <h2>계층 전체를 가렸을 때</h2>
          <div class="table-wrap"><table><thead><tr><th>Layer removed</th><th>Top-1</th><th>Coverage</th><th>Accuracy loss</th><th>Coverage loss</th></tr></thead><tbody>{layer_rows}</tbody></table></div>
        </section>
        {tamper_html}
        """

    document = f"""<!doctype html>
<html lang="ko">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Container State Analyzer - Round2 Validation</title>
<style>
:root{{--ink:#111;--muted:#666;--line:#d7d7d7;--paper:#fff;--wash:#f4f4f2;--danger:#7d1212}}
*{{box-sizing:border-box}} body{{margin:0;background:var(--wash);color:var(--ink);font-family:"Pretendard","Noto Sans KR","Segoe UI",sans-serif;line-height:1.55}}
.shell{{max-width:1180px;margin:0 auto;background:var(--paper);min-height:100vh;box-shadow:0 0 0 1px #e6e6e3}}
header{{padding:72px 72px 48px;border-bottom:3px solid var(--ink)}}
.eyebrow,.section-kicker{{font-size:12px;letter-spacing:.16em;font-weight:800}} h1{{font-size:46px;line-height:1.12;margin:20px 0 12px;letter-spacing:-.04em}}
.subtitle,.lead{{color:var(--muted);max-width:820px}} main{{padding:48px 72px 80px}} section{{margin:0 0 64px}} h2{{font-size:28px;margin:8px 0 10px;letter-spacing:-.025em}} h3{{margin-top:28px}}
.cards{{display:grid;grid-template-columns:repeat(4,1fr);gap:1px;background:var(--ink);border:1px solid var(--ink);margin:26px 0}}
.card{{background:#fff;padding:22px}} .card span{{display:block;color:var(--muted);font-size:12px;text-transform:uppercase;letter-spacing:.08em}} .card strong{{display:block;font-size:28px;margin-top:5px}}
.cards.compact{{grid-template-columns:repeat(3,1fr);max-width:760px}} .table-wrap{{overflow:auto;border-top:2px solid var(--ink);border-bottom:1px solid var(--ink)}}
table{{width:100%;border-collapse:collapse;font-size:13px}} th{{text-align:left;padding:12px 10px;border-bottom:1px solid var(--ink);white-space:nowrap}} td{{padding:11px 10px;border-bottom:1px solid var(--line);vertical-align:top}} tr:last-child td{{border-bottom:0}}
code{{font-family:"Cascadia Mono","SFMono-Regular",monospace;font-size:.93em}} .badge{{display:inline-block;border:1px solid var(--ink);padding:2px 7px;font-size:10px;letter-spacing:.06em;text-transform:uppercase;white-space:nowrap}}
.badge.unknown,.badge.absent,.badge.deferred,.badge.complementary,.badge.measurement_gap{{border-color:#888;color:#555}} .badge.mismatch,.badge.excluded{{border-color:var(--danger);color:var(--danger)}} .badge.critical{{background:#111;color:#fff}}
details{{border-top:1px solid var(--ink)}} details:last-child{{border-bottom:1px solid var(--ink)}} summary{{display:grid;grid-template-columns:1fr 140px 110px;gap:12px;align-items:center;padding:16px 0;cursor:pointer}} .detail-body{{padding:4px 0 32px}}
footer{{border-top:1px solid var(--ink);padding:28px 72px;color:var(--muted);font-size:12px}}
@media(max-width:800px){{header,main,footer{{padding-left:24px;padding-right:24px}}h1{{font-size:36px}}.cards{{grid-template-columns:1fr 1fr}}summary{{grid-template-columns:1fr}}}}
</style>
</head>
<body><div class="shell">
<header><div class="eyebrow">MEMORY FORENSICS / RULESET V2</div><h1>Container State Analyzer</h1><p class="subtitle">Linux 물리 메모리에서 복원한 Runtime - Container - Kernel 아티팩트를 교차 검증하고, 확정할 수 없을 때는 보류한다.</p></header>
<main>
<section><div class="section-kicker">ROUND2 VALIDATION</div><h2>판별 결과</h2><div class="cards">{''.join(f'<div class="card"><span>{_e(label)}</span><strong>{_e(value)}</strong></div>' for label,value in cards)}</div>
<div class="table-wrap"><table><thead><tr><th>Case</th><th>Truth</th><th>Prediction</th><th>Decision</th><th>Correct</th><th>Boundary</th></tr></thead><tbody>{case_rows}</tbody></table></div></section>
{priority_section}
<section><div class="section-kicker">CASE EVIDENCE</div><h2>후보별 근거와 조인</h2>{''.join(details)}</section>
</main><footer>Generated by container-state-analyzer. Numerical probability is intentionally not reported.</footer>
</div></body></html>"""
    target.write_text(document, encoding="utf-8")
    return target

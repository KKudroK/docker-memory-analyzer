from __future__ import annotations

from typing import Any

from .model import Availability, EvidenceCase, Observation, ResultCode


def _get(index: dict[str, Observation], artifact: str) -> Observation | None:
    value = index.get(artifact)
    if value is None or value.availability is Availability.UNKNOWN:
        return None
    return value


def _row(join_id: str, name: str, result: ResultCode, reason: str, artifacts: list[str]) -> dict[str, Any]:
    return {
        "join_id": join_id,
        "name": name,
        "result": result.value,
        "reason": reason,
        "artifacts": artifacts,
    }


def evaluate_joins(case: EvidenceCase) -> list[dict[str, Any]]:
    index = case.index()
    rows: list[dict[str, Any]] = []
    container_id = str(case.subject.get("container_id") or "")

    paths = _get(index, "kernel.target_cgroup_paths")
    if paths is None:
        rows.append(_row("J1", "container ID x cgroup path", ResultCode.UNKNOWN, "cgroup 경로 수집 결과 없음", ["kernel.target_cgroup_paths"]))
    elif not paths.value:
        rows.append(_row("J1", "container ID x cgroup path", ResultCode.ABSENT, "대상 cgroup 객체가 실제로 없음", ["kernel.target_cgroup_paths"]))
    else:
        matched = any(container_id in str(path) or container_id[:12] in str(path) for path in paths.value)
        rows.append(_row("J1", "container ID x cgroup path", ResultCode.MATCH if matched else ResultCode.MISMATCH, "대상 ID 문자열과 cgroup 경로 비교", ["kernel.target_cgroup_paths"]))

    pid = _get(index, "runtime.state.pid")
    pids = _get(index, "kernel.target_task_pids")
    if pid is None or pids is None:
        rows.append(_row("J3", "runtime PID x kernel task", ResultCode.UNKNOWN, "PID 또는 task 목록 확인 불가", ["runtime.state.pid", "kernel.target_task_pids"]))
    else:
        runtime_pid = int(pid.value)
        task_pids = [int(value) for value in pids.value]
        matched = (runtime_pid == 0 and not task_pids) or runtime_pid in task_pids
        rows.append(_row("J3", "runtime PID x kernel task", ResultCode.MATCH if matched else ResultCode.MISMATCH, f"runtime PID={runtime_pid}, target task PIDs={task_pids}", ["runtime.state.pid", "kernel.target_task_pids"]))

    live = _get(index, "kernel.live_task_count")
    flags = {
        name: _get(index, f"runtime.state.{name}")
        for name in ("running", "paused", "restarting", "removal_in_progress", "dead")
    }
    if live is None or any(value is None for value in flags.values()):
        rows.append(_row("J4", "runtime flags x live task", ResultCode.UNKNOWN, "Runtime 또는 task 관측 불가", ["runtime.state.*", "kernel.live_task_count"]))
    else:
        values = {name: bool(value.value) for name, value in flags.items() if value is not None}
        count = int(live.value)
        if values["paused"]:
            expected_live = True
        elif values["restarting"]:
            expected_live = False
        elif values["dead"] or values["removal_in_progress"] or not values["running"]:
            expected_live = False
        else:
            expected_live = True
        matched = (count > 0) == expected_live
        rows.append(_row("J4", "runtime flags x live task", ResultCode.MATCH if matched else ResultCode.MISMATCH, f"flags={values}, live_task_count={count}", ["runtime.state.*", "kernel.live_task_count"]))

    paused = _get(index, "runtime.state.paused")
    frozen = _get(index, "kernel.freezer.effective")
    if paused is None or frozen is None:
        rows.append(_row("J5", "Paused x freezer effective", ResultCode.UNKNOWN, "Paused 플래그 또는 freezer 실효 상태 확인 불가", ["runtime.state.paused", "kernel.freezer.effective"]))
    else:
        matched = bool(paused.value) == bool(frozen.value)
        rows.append(_row("J5", "Paused x freezer effective", ResultCode.MATCH if matched else ResultCode.MISMATCH, f"Paused={paused.value}, effective_frozen={frozen.value}", ["runtime.state.paused", "kernel.freezer.effective"]))

    comparisons = []
    missing = False
    for name in ("running", "paused", "restarting", "dead"):
        heap = _get(index, f"runtime.state.{name}")
        config = _get(index, f"container.config.state.{name}")
        if heap is None or config is None:
            missing = True
            continue
        comparisons.append((name, heap.value, config.value))
    if missing or not comparisons:
        rows.append(_row("J16", "config state x Go heap state", ResultCode.UNKNOWN, "두 계층 중 하나가 수집되지 않음", ["runtime.state.*", "container.config.state.*"]))
    else:
        matched = all(heap == config for _, heap, config in comparisons)
        rows.append(_row("J16", "config state x Go heap state", ResultCode.MATCH if matched else ResultCode.MISMATCH, f"field comparisons={comparisons}", ["runtime.state.*", "container.config.state.*"]))
    return rows

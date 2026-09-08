from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any, Iterable

from .model import Availability, EvidenceCase, Observation


STATE_FROM_FOLDER = {
    "S01_created": "created",
    "S02_running": "running",
    "S03_paused": "paused",
    "S04_restarting": "restarting",
    "S05_exited": "exited",
    "S06_removing": "removing",
    "S07_dead": "dead",
}


GROUP_BY_ARTIFACT = {
    "runtime.container_present": "runtime_identity",
    "runtime.state.running": "runtime_flags",
    "runtime.state.paused": "runtime_flags",
    "runtime.state.restarting": "runtime_flags",
    "runtime.state.removal_in_progress": "runtime_flags",
    "runtime.state.dead": "runtime_flags",
    "runtime.state.pid": "runtime_process",
    "runtime.state.exit_code": "runtime_process",
    "runtime.restart_count": "runtime_history",
    "runtime.restart_count_delta": "runtime_history",
    "runtime.started_at_zero": "container_metadata",
    "runtime.cleanup_error_present": "cleanup_failure",
    "kernel.live_task_count": "kernel_execution",
    "kernel.target_task_pids": "kernel_execution",
    "kernel.task_mm_all_present": "kernel_execution",
    "kernel.task_exit_state_nonzero": "kernel_execution",
    "kernel.target_cgroup_present": "cgroup_membership",
    "kernel.target_cgroup_residual": "cgroup_membership",
    "kernel.target_cgroup_paths": "cgroup_membership",
    "kernel.freezer.requested": "freezer_state",
    "kernel.freezer.effective": "freezer_state",
    "kernel.freezer.all_tasks_frozen": "freezer_state",
    "kernel.target_netns_present": "network_namespace",
    "kernel.veth_present": "network_namespace",
    "kernel.overlay_mounted": "overlay_mount",
    "kernel.cleanup_list_target_anchored": "cleanup_residue",
    "kernel.slab_residue_present": "cleanup_residue",
    "container.upperdir_change_count": "overlay_mount",
    "container.metadata_present": "container_metadata",
    "container.config_parse_ok": "container_metadata",
    "container.config.state.running": "container_metadata",
    "container.config.state.paused": "container_metadata",
    "container.config.state.restarting": "container_metadata",
    "container.config.state.dead": "container_metadata",
    "container.config.state.pid": "container_metadata",
    "kernel.dentry_container_path_present": "dentry_pagecache",
    "kernel.pagecache_config_present": "dentry_pagecache",
}


def _load(path: Path, default: Any = None) -> Any:
    if not path.is_file():
        return default
    with path.open("r", encoding="utf-8") as stream:
        return json.load(stream)


def _zero_time(value: Any) -> bool | None:
    if not isinstance(value, str):
        return None
    return value.startswith("0001-01-01T00:00:00")


def _observation(
    artifact: str,
    layer: str,
    value: Any = None,
    *,
    available: bool = True,
    absent: bool = False,
    collector: str,
    source: str | None = None,
    address: str | None = None,
    note: str | None = None,
) -> Observation:
    availability = (
        Availability.ABSENT if absent else Availability.PRESENT if available else Availability.UNKNOWN
    )
    return Observation(
        artifact=artifact,
        layer=layer,
        availability=availability,
        value=value,
        collector=collector,
        source=source,
        address=address,
        note=note,
        group=GROUP_BY_ARTIFACT.get(artifact),
    )


def _unknowns(artifacts: Iterable[tuple[str, str]], collector: str, note: str) -> list[Observation]:
    return [
        _observation(artifact, layer, available=False, collector=collector, note=note)
        for artifact, layer in artifacts
    ]


def _candidate_records(verification: dict[str, Any]) -> list[dict[str, Any]]:
    if verification.get("go_state"):
        return [verification["go_state"]]
    candidate_block = verification.get("go_container_candidates") or {}
    return list(candidate_block.get("candidates") or [])


def _target_rows(rows: list[dict[str, Any]], container_id: str, key: str) -> list[dict[str, Any]]:
    short = container_id[:12]
    return [
        row
        for row in rows
        if container_id in str(row.get(key, "")) or short in str(row.get(key, ""))
    ]


def import_round2_state(folder: str | Path, *, include_live_sidecars: bool = False) -> list[EvidenceCase]:
    state_dir = Path(folder)
    validation_dir = state_dir / "validation"
    verification_path = validation_dir / "verification.json"
    verification = _load(verification_path)
    if not isinstance(verification, dict):
        raise FileNotFoundError(f"Round2 verification file not found: {verification_path}")

    tasks_path = validation_dir / "tasks.json"
    cgroups_path = validation_dir / "cgroups.json"
    networks_path = validation_dir / "networks.json"
    tasks = _load(tasks_path)
    cgroups = _load(cgroups_path)
    networks = _load(networks_path)
    tasks_ok = isinstance(tasks, list)
    cgroups_ok = isinstance(cgroups, list)
    networks_ok = isinstance(networks, list)
    candidates = _candidate_records(verification)
    cases: list[EvidenceCase] = []

    for ordinal, candidate in enumerate(candidates, start=1):
        container_id = candidate.get("container_id")
        state = candidate.get("state") or {}
        if not container_id or not isinstance(state, dict):
            continue
        target_tasks = _target_rows(tasks or [], container_id, "cgroup") if tasks_ok else []
        target_cgroups = _target_rows(cgroups or [], container_id, "path") if cgroups_ok else []
        verification_processes = verification.get("container_processes") or []
        joined_processes = _target_rows(verification_processes, container_id, "cgroup")
        processes = joined_processes or target_tasks
        observations: list[Observation] = []
        heap_source = str(validation_dir / ("go_state.json" if verification.get("go_state") else "go_container_candidates.json"))

        observations.extend(
            [
                _observation("runtime.container_present", "runtime", True, collector="r2.go_heap", source=heap_source, address=candidate.get("container_address")),
                _observation("runtime.state.running", "runtime", bool(state.get("Running")), collector="r2.go_heap", source=heap_source, address=candidate.get("state_address")),
                _observation("runtime.state.paused", "runtime", bool(state.get("Paused")), collector="r2.go_heap", source=heap_source, address=candidate.get("state_address")),
                _observation("runtime.state.restarting", "runtime", bool(state.get("Restarting")), collector="r2.go_heap", source=heap_source, address=candidate.get("state_address")),
                _observation("runtime.state.removal_in_progress", "runtime", bool(state.get("RemovalInProgress")), collector="r2.go_heap", source=heap_source, address=candidate.get("state_address")),
                _observation("runtime.state.dead", "runtime", bool(state.get("Dead")), collector="r2.go_heap", source=heap_source, address=candidate.get("state_address")),
                _observation("runtime.state.pid", "runtime", int(state.get("Pid", 0)), collector="r2.go_heap", source=heap_source, address=candidate.get("state_address")),
                _observation("runtime.state.exit_code", "runtime", int(state.get("ExitCode", 0)), collector="r2.go_heap", source=heap_source, address=candidate.get("state_address")),
                _observation("runtime.restart_count", "runtime", int(candidate.get("restart_count", 0)), collector="r2.go_heap", source=heap_source, address=candidate.get("container_address")),
            ]
        )
        observations.extend(
            _unknowns(
                [("runtime.restart_count_delta", "runtime")],
                "r2.single_dump",
                "이전 시점 덤프가 없어 증가량을 계산할 수 없음",
            )
        )

        observations.append(
            _observation(
                "kernel.live_task_count",
                "kernel",
                len(target_tasks),
                available=tasks_ok,
                collector="r2.btf_tasks",
                source=str(tasks_path),
                note="container ID가 포함된 cgroup 경로로 앵커링한 live task 수",
            )
        )
        observations.append(
            _observation(
                "kernel.target_task_pids",
                "kernel",
                [int(task.get("pid", 0)) for task in target_tasks],
                available=tasks_ok,
                collector="r2.btf_tasks",
                source=str(tasks_path),
            )
        )
        if target_tasks:
            observations.extend(
                [
                    _observation("kernel.task_mm_all_present", "kernel", all(str(task.get("mm", "0x0")) != "0x0" for task in target_tasks), collector="r2.btf_tasks", source=str(tasks_path)),
                    _observation("kernel.task_exit_state_nonzero", "kernel", any(int(task.get("exit_state", 0)) != 0 for task in target_tasks), collector="r2.btf_tasks", source=str(tasks_path)),
                ]
            )
        else:
            observations.extend(
                _unknowns(
                    [("kernel.task_mm_all_present", "kernel")],
                    "r2.btf_tasks",
                    "대상 live task가 없어 task.mm 조건은 적용 불가",
                )
            )
            observations.append(_observation("kernel.task_exit_state_nonzero", "kernel", False, available=tasks_ok, collector="r2.btf_tasks", source=str(tasks_path)))

        observations.extend(
            [
                _observation("kernel.target_cgroup_present", "kernel", bool(target_cgroups), available=cgroups_ok, collector="r2.btf_cgroups", source=str(cgroups_path)),
                _observation("kernel.target_cgroup_residual", "kernel", bool(target_cgroups) and all(int(row.get("css_flags", 0)) == 0 for row in target_cgroups), available=cgroups_ok, collector="r2.btf_cgroups", source=str(cgroups_path), note="css_flags=0인 대상 cgroup 객체를 잔존 객체로 취급"),
                _observation("kernel.target_cgroup_paths", "kernel", [row.get("path") for row in target_cgroups], available=cgroups_ok, collector="r2.btf_cgroups", source=str(cgroups_path)),
            ]
        )

        freezes = [row.get("freeze") for row in processes if row.get("freeze") is not None]
        frozen_counts = [row.get("nr_frozen_tasks") for row in processes if row.get("nr_frozen_tasks") is not None]
        freezer_available = bool(processes and freezes and frozen_counts)
        observations.extend(
            [
                _observation("kernel.freezer.requested", "kernel", all(int(value) == 1 for value in freezes), available=freezer_available, collector="r2.btf_cgroup_freezer", source=str(verification_path)),
                _observation("kernel.freezer.effective", "kernel", all(int(value) == 1 for value in freezes), available=freezer_available, collector="r2.btf_cgroup_freezer", source=str(verification_path)),
                _observation("kernel.freezer.all_tasks_frozen", "kernel", bool(frozen_counts) and max(int(value) for value in frozen_counts) == len(target_tasks), available=freezer_available, collector="r2.btf_cgroup_freezer", source=str(verification_path)),
            ]
        )

        target_netns = {
            (task.get("namespaces") or {}).get("net_ns")
            for task in target_tasks
            if (task.get("namespaces") or {}).get("net_ns") is not None
        }
        network_anchored = networks_ok and bool(target_netns)
        target_ns_rows = [row for row in (networks or []) if row.get("inum") in target_netns]
        host_rows = [row for row in (networks or []) if row.get("inum") == 4026531833]
        veth_present = any(
            str(device.get("name", "")).startswith("veth")
            for row in host_rows
            for device in row.get("devices", [])
        )
        observations.extend(
            [
                _observation("kernel.target_netns_present", "kernel", bool(target_ns_rows), available=network_anchored, collector="r2.btf_networks", source=str(networks_path), note="대상 task의 net_ns inode로 앵커링"),
                _observation("kernel.veth_present", "kernel", veth_present, available=network_anchored, collector="r2.btf_networks", source=str(networks_path), note="대상 netns 앵커가 있을 때만 평가"),
            ]
        )

        observations.extend(
            _unknowns(
                [
                    ("kernel.overlay_mounted", "kernel"),
                    ("kernel.cleanup_list_target_anchored", "kernel"),
                    ("kernel.slab_residue_present", "kernel"),
                    ("container.upperdir_change_count", "container"),
                    ("kernel.dentry_container_path_present", "kernel"),
                    ("kernel.pagecache_config_present", "kernel"),
                ],
                "r2.not_collected",
                "Round2 validation 폴더에 해당 메모리 추출 결과가 없음",
            )
        )

        config_path = state_dir / "config.v2.json"
        config = _load(config_path) if include_live_sidecars else None
        if isinstance(config, dict):
            config_state = config.get("State") or {}
            started_zero = _zero_time(config_state.get("StartedAt"))
            observations.extend(
                [
                    _observation("container.metadata_present", "container", True, collector="r2.live_sidecar", source=str(config_path), note="메모리 전용 증거가 아닌 수집 당시 디스크 sidecar"),
                    _observation("container.config_parse_ok", "container", True, collector="r2.live_sidecar", source=str(config_path)),
                    _observation("runtime.started_at_zero", "runtime", started_zero, available=started_zero is not None, collector="r2.live_sidecar", source=str(config_path)),
                    _observation("runtime.cleanup_error_present", "runtime", bool(config_state.get("Error")), collector="r2.live_sidecar", source=str(config_path)),
                    _observation("container.config.state.running", "container", bool(config_state.get("Running")), collector="r2.live_sidecar", source=str(config_path)),
                    _observation("container.config.state.paused", "container", bool(config_state.get("Paused")), collector="r2.live_sidecar", source=str(config_path)),
                    _observation("container.config.state.restarting", "container", bool(config_state.get("Restarting")), collector="r2.live_sidecar", source=str(config_path)),
                    _observation("container.config.state.dead", "container", bool(config_state.get("Dead")), collector="r2.live_sidecar", source=str(config_path)),
                    _observation("container.config.state.pid", "container", int(config_state.get("Pid", 0)), collector="r2.live_sidecar", source=str(config_path)),
                ]
            )
        else:
            observations.extend(
                _unknowns(
                    [
                        ("container.metadata_present", "container"),
                        ("container.config_parse_ok", "container"),
                        ("runtime.started_at_zero", "runtime"),
                        ("runtime.cleanup_error_present", "runtime"),
                        ("container.config.state.running", "container"),
                        ("container.config.state.paused", "container"),
                        ("container.config.state.restarting", "container"),
                        ("container.config.state.dead", "container"),
                        ("container.config.state.pid", "container"),
                    ],
                    "r2.memory_only",
                    "디스크 sidecar를 상태 판별 입력에서 제외함",
                )
            )

        case_id = state_dir.name if len(candidates) == 1 else f"{state_dir.name}-{ordinal}-{container_id[:12]}"
        cases.append(
            EvidenceCase(
                case_id=case_id,
                ground_truth=STATE_FROM_FOLDER.get(state_dir.name),
                subject={"container_id": container_id, "name": candidate.get("name")},
                environment={
                    "kernel_version": verification.get("kernel"),
                    "build_id": verification.get("build_id"),
                    "cgroup_version": "v2",
                    "source_policy": "mixed" if include_live_sidecars else "memory-only",
                },
                provenance={
                    "round": "R2",
                    "state_folder": str(state_dir),
                    "verification": str(verification_path),
                    "memory_only": not include_live_sidecars,
                },
                observations=observations,
            )
        )
    return cases


def import_round2_root(root: str | Path, *, include_live_sidecars: bool = False) -> list[EvidenceCase]:
    root_path = Path(root)
    cases: list[EvidenceCase] = []
    for name in STATE_FROM_FOLDER:
        folder = root_path / name
        if (folder / "validation" / "verification.json").is_file():
            cases.extend(import_round2_state(folder, include_live_sidecars=include_live_sidecars))
    if not cases:
        found = [path.parent.parent for path in root_path.rglob("validation/verification.json")]
        for folder in sorted(set(found)):
            if folder.name in STATE_FROM_FOLDER:
                cases.extend(import_round2_state(folder, include_live_sidecars=include_live_sidecars))
    if not cases:
        raise FileNotFoundError(
            "No Round2 state folders were found. Expected S01_created/validation/verification.json etc."
        )
    return cases


def infer_state_from_name(name: str) -> str | None:
    normalized = re.sub(r"[^a-z]+", "_", name.lower()).strip("_")
    for state in STATE_FROM_FOLDER.values():
        if state in normalized:
            return state
    return None

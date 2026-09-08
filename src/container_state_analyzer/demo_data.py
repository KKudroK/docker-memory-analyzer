from __future__ import annotations

from .model import Availability, EvidenceCase, Observation
from .r2 import GROUP_BY_ARTIFACT


CONTAINER_ID = "84aed8b6673a59696a070cc13a661e4f4c0e3617d64684b44c46ec8a5104888b"
DEAD_CONTAINER_ID = "e421e81d9cc3c98156c2681692c35d977eb530e575cb7dc92d0c5c7c444c2e86"
KERNEL = "7.0.0-31-generic"
BUILD_ID = "b9c951cf62b1cef8e0473f530b31e4012f920db0"


ROUND2 = [
    {
        "case_id": "S01_created",
        "truth": "created",
        "id": CONTAINER_ID,
        "verification_file_id": "1GZSZ6uIZ1WitsD9_h_VL7o8C8Pcd2V6t",
        "state": {"running": False, "paused": False, "restarting": False, "removal_in_progress": False, "dead": False, "pid": 0, "exit_code": 0},
        "restart_count": 0,
        "task_pids": [],
        "cgroup_paths": [],
        "cgroup_residual": False,
    },
    {
        "case_id": "S02_running",
        "truth": "running",
        "id": CONTAINER_ID,
        "verification_file_id": "1ksLVuPXu0lsZu_v7dTztRzSnriOTfUKS",
        "state": {"running": True, "paused": False, "restarting": False, "removal_in_progress": False, "dead": False, "pid": 3598, "exit_code": 0},
        "restart_count": 0,
        "task_pids": [3598, 3628, 3629, 3630],
        "cgroup_paths": [f"/system.slice/docker-{CONTAINER_ID}.scope"],
        "cgroup_residual": False,
        "freezer": False,
        "frozen_count": 0,
        "network": True,
    },
    {
        "case_id": "S03_paused",
        "truth": "paused",
        "id": CONTAINER_ID,
        "verification_file_id": "1LRjFcr6eFbzBjbKu0aEyHJAy8oaTztPU",
        "state": {"running": True, "paused": True, "restarting": False, "removal_in_progress": False, "dead": False, "pid": 3598, "exit_code": 0},
        "restart_count": 0,
        "task_pids": [3598, 3628, 3629, 3630],
        "cgroup_paths": [f"/system.slice/docker-{CONTAINER_ID}.scope"],
        "cgroup_residual": False,
        "freezer": True,
        "frozen_count": 4,
        "network": True,
    },
    {
        "case_id": "S04_restarting",
        "truth": "restarting",
        "id": CONTAINER_ID,
        "verification_file_id": "1TiTaIzP7GdeEhx152JFWUk2oX1U3Axoh",
        "state": {"running": True, "paused": False, "restarting": True, "removal_in_progress": False, "dead": False, "pid": 0, "exit_code": 42},
        "restart_count": 11,
        "task_pids": [],
        "cgroup_paths": [f"/system.slice/docker-{CONTAINER_ID}.scope"],
        "cgroup_residual": True,
    },
    {
        "case_id": "S05_exited",
        "truth": "exited",
        "id": CONTAINER_ID,
        "verification_file_id": "1TNADK7SsEEY1holouu70ErttUt8_nOBM",
        "state": {"running": False, "paused": False, "restarting": False, "removal_in_progress": False, "dead": False, "pid": 0, "exit_code": 42},
        "restart_count": 11,
        "task_pids": [],
        "cgroup_paths": [f"/system.slice/docker-{CONTAINER_ID}.scope"],
        "cgroup_residual": True,
    },
    {
        "case_id": "S06_removing",
        "truth": "removing",
        "id": CONTAINER_ID,
        "verification_file_id": "1l0i5LbrUnAOu1hj_Mnz7fHO8DT7eMsc7",
        "state": {"running": False, "paused": False, "restarting": False, "removal_in_progress": True, "dead": False, "pid": 0, "exit_code": 0},
        "restart_count": 0,
        "task_pids": [],
        "cgroup_paths": [f"/system.slice/docker-{CONTAINER_ID}.scope"],
        "cgroup_residual": True,
    },
    {
        "case_id": "S07_dead",
        "truth": "dead",
        "id": DEAD_CONTAINER_ID,
        "verification_file_id": "17Yu0mNqbj4Oul2leHDIipDf-G2GLC20r",
        "state": {"running": False, "paused": False, "restarting": False, "removal_in_progress": False, "dead": True, "pid": 0, "exit_code": 0},
        "restart_count": 0,
        "task_pids": [],
        "cgroup_paths": [f"/system.slice/docker-{DEAD_CONTAINER_ID}.scope"],
        "cgroup_residual": True,
    },
]


def _obs(artifact: str, layer: str, value: object, collector: str) -> Observation:
    return Observation(
        artifact=artifact,
        layer=layer,
        availability=Availability.PRESENT,
        value=value,
        collector=collector,
        source="Google Drive Round2 validation extraction",
        group=GROUP_BY_ARTIFACT.get(artifact),
    )


def round2_cases() -> list[EvidenceCase]:
    cases: list[EvidenceCase] = []
    for row in ROUND2:
        state = row["state"]
        task_pids = row["task_pids"]
        paths = row["cgroup_paths"]
        observations = [
            _obs("runtime.container_present", "runtime", True, "r2.go_heap"),
            _obs("runtime.state.running", "runtime", state["running"], "r2.go_heap"),
            _obs("runtime.state.paused", "runtime", state["paused"], "r2.go_heap"),
            _obs("runtime.state.restarting", "runtime", state["restarting"], "r2.go_heap"),
            _obs("runtime.state.removal_in_progress", "runtime", state["removal_in_progress"], "r2.go_heap"),
            _obs("runtime.state.dead", "runtime", state["dead"], "r2.go_heap"),
            _obs("runtime.state.pid", "runtime", state["pid"], "r2.go_heap"),
            _obs("runtime.state.exit_code", "runtime", state["exit_code"], "r2.go_heap"),
            _obs("runtime.restart_count", "runtime", row["restart_count"], "r2.go_heap"),
            _obs("kernel.live_task_count", "kernel", len(task_pids), "r2.btf_tasks"),
            _obs("kernel.target_task_pids", "kernel", task_pids, "r2.btf_tasks"),
            _obs("kernel.task_exit_state_nonzero", "kernel", False, "r2.btf_tasks"),
            _obs("kernel.target_cgroup_present", "kernel", bool(paths), "r2.btf_cgroups"),
            _obs("kernel.target_cgroup_residual", "kernel", row["cgroup_residual"], "r2.btf_cgroups"),
            _obs("kernel.target_cgroup_paths", "kernel", paths, "r2.btf_cgroups"),
        ]
        if task_pids:
            observations.append(_obs("kernel.task_mm_all_present", "kernel", True, "r2.btf_tasks"))
        if "freezer" in row:
            observations.extend(
                [
                    _obs("kernel.freezer.requested", "kernel", row["freezer"], "r2.btf_cgroup_freezer"),
                    _obs("kernel.freezer.effective", "kernel", row["freezer"], "r2.btf_cgroup_freezer"),
                    _obs("kernel.freezer.all_tasks_frozen", "kernel", row["frozen_count"] == len(task_pids), "r2.btf_cgroup_freezer"),
                ]
            )
        if row.get("network"):
            observations.extend(
                [
                    _obs("kernel.target_netns_present", "kernel", True, "r2.btf_networks"),
                    _obs("kernel.veth_present", "kernel", True, "r2.btf_networks"),
                ]
            )
        cases.append(
            EvidenceCase(
                case_id=row["case_id"],
                subject={"container_id": row["id"], "name": "forensic_multi"},
                ground_truth=row["truth"],
                environment={"kernel_version": KERNEL, "build_id": BUILD_ID, "cgroup_version": "v2", "source_policy": "memory-only"},
                provenance={
                    "round": "R2",
                    "drive_folder": "https://drive.google.com/drive/folders/13c4zDLyfYV36qiW3WxxBqoWZXGyY3tiD",
                    "verification_file_id": row["verification_file_id"],
                    "normalized_subset": True,
                },
                observations=observations,
            )
        )
    return cases

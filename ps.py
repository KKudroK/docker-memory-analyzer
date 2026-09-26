"""Task-linked Docker container summaries for stock Volatility 3 >= 2.28.0.

Run via ``vol ... -p ./plugins linux.docker.Docker --ps``. Each full container ID
has one category/value block. A representative is chosen from an observed
namespace init or attributed direct shim child; ambiguous cases remain unknown.
Only that representative's start time, effective UID and capability are read.
Configured Privileged comes from matching cached hostconfig.json, never a
PID 1 capability comparison. Cache freshness cannot be established from presence.

The reachable leader list is audited in both directions. Identity uses task
cgroups, shim arguments/direct children and conditional standard bind mounts.
Settings recovery follows verified standard bind mounts to each task-linked
container directory. It keeps only fully recovered Privileged values and
validation evidence, not general settings. The output has no lifecycle
classifier. ps_evidence.json uses schema 5.
"""

import datetime
import hashlib
import json
import logging
import re
import struct
import time

from volatility3.framework import constants, exceptions, objects, renderers
from volatility3.framework.objects import utility
from volatility3.framework.symbols import linux
from volatility3.plugins.linux import docker_artifacts
from volatility3.plugins.linux._artifacts import cgroups as cgroup_readers
from volatility3.plugins.linux._artifacts import core as artifact_core
from volatility3.plugins.linux._artifacts import credentials as credential_readers
from volatility3.plugins.linux._artifacts import mounts as mount_readers
from volatility3.plugins.linux._artifacts import namespaces as namespace_readers
from volatility3.plugins.linux._artifacts import tasks as task_readers
from volatility3.plugins.linux._artifacts import timing as timing_readers

vollog = logging.getLogger(__name__)
# This function backend has no PluginInterface class; version its evidence
# from one tuple. 2.x marks the task-linked summary replacing lifecycle output.
VERSION = (2, 0, 3)
LIMIT = 100000
FILE_LIMIT = 16 * 1024 * 1024
SETTINGS_MOUNT_LIMIT = 2048
SETTINGS_CHILD_LIMIT = 4096
SETTINGS_SECONDS = 20
CID = re.compile(r"[0-9a-f]{64}\Z")
CGROUP_ID = re.compile(r"/(?:docker/|docker-)([0-9a-f]{64})(?:\.scope)?(?=/|$)")
BIND_ID = re.compile(
    r"(?:^|/)containers/([0-9a-f]{64})/(hosts|hostname|resolv\.conf)\Z"
)
UTC = datetime.timezone.utc
STAGES = ("tasks", "identity", "selection", "details", "settings")
STAGE_SCOPES = {
    "tasks": "reachable process leaders and task-linked cgroups/PID namespaces",
    "identity": "shim arguments/direct children and conditional non-host namespace bind mounts",
    "selection": "one candidate per ID observed on a process leader",
    "details": "selected representative start time and credentials only",
    "settings": "Privileged from verified container bind-mount directories; bounded lookup",
}


class DuplicateJSONKey(ValueError):
    """Conflicting JSON keys must not become authoritative metadata."""


def utc(seconds, nanoseconds=0):
    """초·나노초 값을 UTC 시각 문자열로 변환하며, 시각이 미확인이면 None을 반환한다.

    로직: 입력 범위를 검사하고 UTC 기준 시각으로 바꾼 뒤 나노초 자릿수를 붙인다.
    """
    if seconds is None:
        return None
    if not 0 <= nanoseconds < 1000000000:
        raise ValueError("Invalid nanoseconds")
    value = datetime.datetime.fromtimestamp(seconds, UTC)
    return (
        f"{value.year:04d}-{value.month:02d}-{value.day:02d}T{value.hour:02d}:{value.minute:02d}:{value.second:02d}"
        + f".{nanoseconds:09d}Z"
    )


def unique_pairs(pairs):
    """JSON 키·값 쌍을 사전으로 만들고, 중복 키가 있으면 오류로 처리한다.

    로직: 키를 순서대로 사전에 넣고 기존 키가 다시 나타나면 예외를 발생시킨다.
    """
    result = {}
    for key, value in pairs:
        if key in result:
            raise DuplicateJSONKey("Duplicate JSON key: " + key)
        result[key] = value
    return result


def prefix_json(raw):
    """일부만 복구된 JSON의 연속된 앞부분에서 완전하게 읽힌 최상위 키·값 쌍만 추출한다.

    로직: 앞에서부터 완전하게 해석된 최상위 키·값만 보관하며 불완전한 뒤쪽 데이터에서 멈춘다.
    """
    text = raw.decode("utf-8", errors="surrogateescape")
    decoder = json.JSONDecoder(object_pairs_hook=unique_pairs)
    pos = len(text) - len(text.lstrip())
    result = {}
    if text[pos : pos + 1] != "{":
        return result
    pos += 1
    try:
        while True:
            while text[pos].isspace():
                pos += 1
            key, pos = decoder.raw_decode(text, pos)
            while text[pos].isspace():
                pos += 1
            if not isinstance(key, str) or text[pos] != ":":
                break
            pos += 1
            while text[pos].isspace():
                pos += 1
            value, pos = decoder.raw_decode(text, pos)
            while text[pos].isspace():
                pos += 1
            if text[pos] not in ",}":
                break
            if key in result:
                raise DuplicateJSONKey("Duplicate JSON key: " + key)
            result[key] = value
            if text[pos] == "}":
                break
            pos += 1
    except DuplicateJSONKey:
        raise
    except (ValueError, IndexError):
        pass
    return result


def json_object(raw):
    """중복 키를 검사하며 JSON을 해석하고, 최상위 값이 객체인지 확인한다.

    로직: 중복 키 검사기를 적용해 JSON을 읽고 결과가 사전인지 확인한다.
    """
    obj = json.loads(raw, object_pairs_hook=unique_pairs)
    if not isinstance(obj, dict):
        # The parsed JSON value violates the schema; retain parse-error handling.
        raise ValueError("Metadata is not an object")  # noqa: TRY004
    return obj


def select_representative(rows, cid):
    """ID 충돌이 없는 태스크에서 namespace PID 1 또는 직접 shim 자식으로 유일한 대표를 선정한다.

    로직: 충돌 없는 태스크를 추린 뒤 유일한 namespace PID 1을 우선하고, 필요하면 귀속된 직접 shim 자식을 사용한다. PID 크기로 고르지 않는다.
    """
    eligible = [
        r
        for r in rows
        if r.get("container_ids") == [cid] and not r.get("identity_conflicts")
    ]
    chains = [r for r in eligible if r.get("pid_chain")]
    depth = min((len(r["pid_chain"]) - 1 for r in chains), default=None)
    inits = [
        r
        for r in chains
        if depth and len(r["pid_chain"]) - 1 == depth and r["pid_chain"][-1]["nr"] == 1
    ]
    direct = [
        r for r in eligible if r.get("direct_shim", {}).get("container_id") == cid
    ]
    selected, method = None, None
    if len(inits) == 1:
        selected, method = inits[0], "PID_NAMESPACE_INIT"
    elif len(direct) == 1 and (not inits or direct[0] in inits):
        selected, method = direct[0], "SHIM_DIRECT_CHILD"
    candidates = inits or direct
    status = (
        "SELECTED" if selected else "AMBIGUOUS" if len(candidates) > 1 else "UNRESOLVED"
    )
    return selected, {
        "status": status,
        "method": method,
        "candidate_tasks": [r["address"] for r in candidates],
        "observed_min_pid_namespace_depth": depth,
        "reason": "unique evidenced representative"
        if selected
        else "no unique namespace init or attributed direct shim child",
    }


class Collector(artifact_core.CollectionSession):
    def __init__(self, context, kernel_name):
        """분석 context와 커널 계층을 연결하고, 수집 결과·출처·오류·중복 방지 저장소를 초기화한다.

        로직: 커널 모듈·메모리 계층을 조회하고 단계별 증거·오류를 담을 보고서와 조회용 사전을 만든다.
        """
        super().__init__(context, kernel_name)
        self.stage = "tasks"
        self.report = {
            "schema_version": 5,
            "method": "One summary per task-linked Docker container",
            "provenance": {
                "plugin_version": ".".join(map(str, VERSION)),
                "volatility_version": constants.PACKAGE_VERSION,
                "collection_started_utc": datetime.datetime.now(UTC).isoformat(),
                "kernel_module": kernel_name,
                "kernel_layer": self.kernel.layer_name,
                "isf_url": context.symbol_space[
                    self.kernel.symbol_table_name
                ].config.get("isf_url"),
                "input_layers": [
                    {"name": n, "location": context.layers[n].config.get("location")}
                    for n in context.layers
                    if context.layers[n].config.get("location")
                ],
            },
            "coverage": {},
            "errors": [],
            "tasks": [],
            "cgroups": [],
            "namespaces": [],
            "shims": [],
            "mounts": [],
            "cached_settings": [],
            "containers": [],
            "task_list_integrity": [],
            "limits": {
                "objects_per_traversal": LIMIT,
                "settings_file_bytes": FILE_LIMIT,
                "settings_mounts_per_container": SETTINGS_MOUNT_LIMIT,
                "settings_children_per_directory": SETTINGS_CHILD_LIMIT,
                "settings_seconds": SETTINGS_SECONDS,
            },
            "scope": "Reachable process leaders; cgroup IDs and limited identity fallback; representative credentials and cached Privileged only",
            "limitations": [
                "A task-linked candidate does not establish Docker lifecycle state.",
                "A damaged task list remains partial after reverse recovery.",
                "Missing or ambiguous representative evidence is not replaced with the lowest PID.",
                "Cached hostconfig values may be stale; missing data is unknown.",
                "Shim comm/argument forms and Docker path patterns have a bounded supported scope.",
            ],
        }
        self.tasks, self.task_rows, self.namespaces, self.cgroups, self.containers = (
            {},
            {},
            {},
            {},
            {},
        )
        self.backward_recovered_tasks = set()
        self.skipped = {}
        self.init, self.boot = None, None

    def process_start(self, task):
        if self.boot is None:
            self.boot = self.kernel_boot_ns()
        return utc(
            *divmod(timing_readers.read_process_start_ns(task, self.boot), 1000000000)
        )

    def kernel_boot_ns(self):
        source = timing_readers.read_kernel_boot(self)
        self.report["boot_time_source"] = {
            "symbol": source.symbol,
            "layout": source.layout,
            "location": self.location(source.keeper),
            "nanoseconds": source.nanoseconds,
        }
        return source.nanoseconds

    def address(self, obj):
        """Volatility 객체의 메모리 오프셋 또는 전달된 주소를 정수로 반환한다.

        로직: vol 속성이 있으면 객체 오프셋을, 없으면 전달된 값 자체를 정수로 바꾼다.
        """
        return int(obj.vol.offset) if hasattr(obj, "vol") else int(obj)

    def location(self, obj):
        """객체의 가상 주소와 계층을 기록하고, 변환 가능하면 하위 계층의 이름·오프셋도 덧붙인다.

        로직: 가상 주소를 기록한 다음 주소 변환이 성공하면 매핑된 계층과 오프셋을 추가한다.
        """
        address = self.address(obj)
        result = {"layer": self.kernel.layer_name, "virtual": hex(address)}
        try:
            _, _, physical, _, name = next(self.layer.mapping(address, 1))
            result.update(mapped_layer=name, mapped_offset=hex(physical))
        except (exceptions.InvalidAddressException, StopIteration):
            pass
        return result

    def issue(self, operation, obj, exc):
        """수집 오류를 종류별로 구분해 단계·작업·주소·예외명·상세 내용과 함께 기록한다.

        로직: 주소를 문자열로 만들고 예외 종류를 판별해 현재 단계의 errors 목록에 추가한다.
        """
        try:
            address = hex(self.address(obj))
        except (ValueError, TypeError, AttributeError):
            address = str(obj)
        kind = (
            "UNSUPPORTED"
            if isinstance(
                exc, (artifact_core.Unsupported, exceptions.SymbolError, AttributeError)
            )
            else "UNREADABLE"
            if isinstance(exc, exceptions.InvalidAddressException)
            else "INCOMPLETE"
            if isinstance(exc, artifact_core.Incomplete)
            else "ERROR"
        )
        self.report["errors"].append(
            {
                "stage": self.stage,
                "operation": operation,
                "address": address,
                "kind": kind,
                "exception": type(exc).__name__,
                "detail": artifact_core.exception_detail(exc),
            }
        )

    def read(self, operation, obj, function, default=None):
        """읽기·해석 함수를 실행하고, 처리 대상 예외가 발생하면 오류를 기록한 뒤 기본값을 반환한다.

        로직: 요청한 함수를 호출하고 지정된 예외만 잡아 issue에 남긴 뒤 기본값으로 돌아간다.
        """
        try:
            return function()
        except (
            exceptions.VolatilityException,
            ValueError,
            AttributeError,
            TypeError,
            KeyError,
            IndexError,
            OverflowError,
            UnicodeError,
            struct.error,
        ) as exc:
            self.issue(operation, obj, exc)
            return default

    def string(self, ptr):
        return artifact_core.pointer_string(ptr)

    def bounded(self, iterator):
        return artifact_core.bounded(iterator, LIMIT)

    def namespace(self, ptr, kind, entity=None):
        """네임스페이스 주소·식별 번호를 중복 없이 기록하고, 관련 태스크와의 연결을 추가한다.

        로직: 포인터를 역참조해 주소별 기록을 재사용하고, 요청된 태스크 주소를 연결한다.
        """
        if not ptr:
            return None
        obj = ptr.dereference() if isinstance(ptr, objects.Pointer) else ptr
        address = self.address(obj)
        key = (kind, address)
        if key not in self.namespaces:
            number = namespace_readers.namespace_inum(obj)
            row = {"address": hex(address), "kind": kind, "inum": number, "tasks": []}
            self.namespaces[key] = (obj, row)
            self.report["namespaces"].append(row)
        row = self.namespaces[key][1]
        if entity and entity not in row["tasks"]:
            row["tasks"].append(entity)
        return {"address": row["address"], "inum": row["inum"]}

    def pid_chain(self, task):
        return namespace_readers.inventory_pid_chain(self, task)

    def task_cgroups(self, task):
        if not task.has_member("cgroups"):
            raise artifact_core.Unsupported("task.cgroups absent")
        if not task.cgroups:
            return []
        groups = cgroup_readers.effective_cgroups(
            task.cgroups.dereference(), states=self.bounded
        )
        return [self.cgroup(group, "task") for group in groups]

    def cgroup_path(self, group):
        return cgroup_readers.effective_cgroup_path(
            group,
            self.string,
            LIMIT,
            policy=cgroup_readers.CgroupPathPolicy.INVENTORY,
            location=self.location,
        )

    def task_list(self, head, member, kind):
        """양방향에서 발견한 태스크를 합쳐 검증·반환하고, 목록 무결성과 역방향 복구 여부를 기록한다.

        로직: 목록 양방향 순회 결과를 합쳐 task_struct를 검증한다. 불일치·역방향 복구를 증거와 오류에 남긴다.
        """
        mask = self.layer.address_mask
        offset = self.kernel.get_type("task_struct").relative_child_offset(member)
        audit = docker_artifacts.DockerArtifacts.audit_task_list(
            self.context, self.kernel_name, self.address(head)
        )
        audit.update(member=member, kind=kind)
        issue_counts = {}
        for issue in audit["issues"]:
            issue_counts[issue["kind"]] = issue_counts.get(issue["kind"], 0) + 1
        self.report["task_list_integrity"].append(
            {
                "head": audit["head"],
                "member": member,
                "kind": kind,
                "status": audit["status"],
                "directions": {
                    direction: {"count": result["count"], "closed": result["closed"]}
                    for direction, result in audit["directions"].items()
                },
                "forward_only_count": len(audit["forward_only"]),
                "backward_only_count": len(audit["backward_only"]),
                "issue_counts": issue_counts,
            }
        )
        if audit["status"] != "CONSISTENT":
            vollog.warning(
                "ps: %s list integrity mismatch at %s: forward=%d, backward=%d, "
                "backward-only=%d; recovered union remains PARTIAL",
                kind,
                audit["head"],
                audit["directions"]["forward"]["count"],
                audit["directions"]["backward"]["count"],
                len(audit["backward_only"]),
            )
            self.issue(
                "task list integrity: " + kind,
                head,
                artifact_core.Incomplete(
                    f"Bidirectional list inconsistent: forward={audit['directions']['forward']['count']}, "
                    f"backward={audit['directions']['backward']['count']}, "
                    f"backward_only={len(audit['backward_only'])}; "
                    "union retained, completeness unproven (see task_list_integrity)"
                ),
            )
        forward = audit["directions"]["forward"]["nodes"]
        backward = audit["directions"]["backward"]["nodes"]
        backward_only = set(audit["backward_only"])
        for address in dict.fromkeys(forward + backward):
            task = self.obj("task_struct", (address - offset) & mask)

            def validate(*, task=task):
                """발견한 태스크의 PID·TGID·group_leader와 comm 읽기 가능 여부를 확인한다.

                로직: PID와 TGID가 양수이고 group_leader가 있으며 comm을 읽을 수 있는지 확인한다.
                """
                if int(task.pid) <= 0 or int(task.tgid) <= 0 or not task.group_leader:
                    raise artifact_core.Incomplete(
                        "Reachable task has invalid PID/TGID/group_leader"
                    )
                utility.array_to_string(task.comm)
                return True

            if not self.read("reachable task validation", task, validate, False):
                continue
            if address in backward_only:
                self.backward_recovered_tasks.add(self.address(task))
            yield task

    def argv(self, task):
        return docker_artifacts.DockerArtifacts.read_task_argv(
            self.context,
            self.kernel_name,
            int(task.vol.offset),
            policy="inventory",
            limit=FILE_LIMIT,
            layer_name=task.vol.layer_name,
            native_layer_name=task.vol.native_layer_name,
        )

    def stage_run(self, name, function):
        """수집 단계를 실행하고 결과 수·오류 수·상태·수집 범위·소요 시간을 coverage에 기록한다.

        로직: 수집 함수를 오류 격리 경로로 실행한 뒤 레코드·오류 수로 상태를 정하고 범위와 시간을 기록한다.
        """
        self.stage = name
        errors, started = len(self.report["errors"]), time.perf_counter()
        vollog.info("ps: collecting %s", name)
        self.read(name, name, function)
        fields = {
            "tasks": ("tasks",),
            "identity": ("shims", "mounts"),
            "selection": ("containers",),
            "details": (),
            "settings": ("cached_settings",),
        }[name]
        count = (
            sum(len(self.report[f]) for f in fields)
            if fields
            else sum(bool(c.get("representative")) for c in self.report["containers"])
        )
        issues = self.report["errors"][errors:]
        status = (
            "PARTIAL"
            if issues
            else "SKIPPED"
            if name in self.skipped
            else "FOUND"
            if count
            else "NOT FOUND"
        )
        self.report["coverage"][name] = {
            "status": status,
            "records": count,
            "record_collections": list(fields),
            "errors": len(issues),
            "completed_without_errors": not issues,
            "scope": self.skipped.get(name, STAGE_SCOPES[name]),
            "elapsed_seconds": round(time.perf_counter() - started, 3),
        }

    def cgroup(self, group, source):
        """cgroup 경로에서 Docker ID를 추출하고 주소·경로·메모리 위치를 중복 없이 저장한다.

        로직: 주소가 처음 발견됐을 때 경로·Docker ID·위치를 만들고 이후에는 저장된 기록을 반환한다.
        """
        address = self.address(group)
        if address not in self.cgroups:
            path, _ = self.cgroup_path(group)
            row = {
                "address": hex(address),
                "path": path,
                "container_ids": sorted(set(CGROUP_ID.findall(path))),
                "location": self.location(group),
            }
            self.cgroups[address] = (group, row)
            self.report["cgroups"].append(row)
        return self.cgroups[address][1]

    def collect_tasks(self):
        """프로세스 리더를 수집하고 PID·부모·명령·PID namespace·cgroup ID 및 충돌 정보를 기록한다.

        로직: 리더 목록을 모은 뒤 각 task의 PID·명령·namespace·cgroup을 읽고 ID 출처와 충돌을 정리한다.
        """
        self.init = self.symbol("init_task", "task_struct")

        def leaders():
            """검증된 태스크 목록에서 PID와 TGID가 같은 프로세스 리더를 주소별로 저장한다.

            로직: 양방향 목록에서 얻은 task 중 pid와 tgid가 일치하는 항목을 주소별로 저장한다.
            """
            for task in self.task_list(self.init.tasks, "tasks", "process_leaders"):
                if int(task.pid) == int(task.tgid):
                    self.tasks[self.address(task)] = task

        self.read("process leader list", self.init, leaders)
        for address, task in self.tasks.items():
            row = {
                "address": hex(address),
                "location": self.location(task),
                "container_ids": [],
                "identity_sources": [],
                "identity_conflicts": [],
                "namespaces": {},
                "recovered_from_backward": address in self.backward_recovered_tasks,
            }
            self.report["tasks"].append(row)
            self.task_rows[address] = row
            for field in ("pid", "tgid", "real_parent"):
                row[field] = self.read(
                    "task." + field,
                    task,
                    lambda f=field, task=task: int(task.member(f)),
                )
            row["comm"] = self.read(
                "task.comm", task, lambda task=task: utility.array_to_string(task.comm)
            )

            def pid_chain(*, row=row, task=task):
                """PID namespace 계층을 읽고 호스트 PID 일치 여부와 네임스페이스 누락을 검사한다.

                로직: PID 계층을 수집하고 첫 PID가 호스트 PID와 맞는지, namespace가 모두 있는지 확인한다.
                """
                chain = self.pid_chain(task)
                if chain and (
                    chain[0]["nr"] != row["pid"]
                    or any(n["namespace"] is None for n in chain)
                ):
                    raise ValueError(
                        "PID chain disagrees with task PID or lacks a namespace"
                    )
                return chain

            row["pid_chain"] = self.read("task.pid_chain", task, pid_chain, [])
            groups = self.read(
                "task.cgroups", task, lambda task=task: self.task_cgroups(task), []
            )
            row["cgroups"] = [g["address"] for g in groups]
            container_ids = set()
            for group in groups:
                container_ids.update(group["container_ids"])
            row["container_ids"] = sorted(container_ids)
            if row["container_ids"]:
                row["identity_sources"].append("cgroup")
            if len(row["container_ids"]) > 1:
                row["identity_conflicts"].append(
                    {"source": "cgroup", "ids": row["container_ids"]}
                )

    def collect_shims(self):
        """shim 이름·인자로 Docker 귀속을 확인하고, 직접 자식의 ID를 보완하거나 기존 ID와의 충돌을 기록한다.

        로직: shim 후보의 인자를 읽어 귀속 여부를 정한 뒤 직접 자식에게 ID를 연결하거나 충돌을 남긴다.
        """
        known = set()
        for row in self.report["tasks"]:
            known.update(row["container_ids"])
        shims = {}
        for address, task in self.tasks.items():
            row = self.task_rows[address]
            if not (row.get("comm") or "").startswith("containerd-shim"):
                continue

            def decode(*, address=address, row=row, task=task):
                """shim 인자에서 ID·runtime namespace를 읽고 moby 또는 기존 ID 근거에 따라 Docker 귀속 여부를 기록한다.

                로직: 인자에서 ID·namespace를 해석하고 moby 또는 이미 알려진 ID와 일치하는지 기록한다.
                """
                args = self.argv(task)
                cid, namespace = task_readers.shim_arguments(args)
                record = {
                    "task": row["address"],
                    "pid": row["pid"],
                    "container_id": cid,
                    "runtime_namespace": namespace,
                    "argv": args,
                    "attributed": namespace == "moby" or cid in known,
                    "direct_children": [],
                }
                self.report["shims"].append(record)
                if record["attributed"]:
                    shims[address] = record

            self.read("shim identity", task, decode)
        for row in self.report["tasks"]:
            shim = shims.get(row.get("real_parent"))
            if shim is None:
                continue
            cid = shim["container_id"]
            shim["direct_children"].append(row["address"])
            row["direct_shim"] = {
                "task": shim["task"],
                "pid": shim["pid"],
                "container_id": cid,
            }
            if row["container_ids"] and row["container_ids"] != [cid]:
                row["identity_conflicts"].append(
                    {
                        "source": "shim",
                        "container_id": cid,
                        "reason": "direct shim ID disagrees with cgroup IDs",
                    }
                )
            else:
                row["container_ids"] = [cid]
                row["identity_sources"].append("shim_direct_child")

    def mount_namespace(self, task, entity=None):
        """태스크의 nsproxy에서 mount namespace를 찾아 공통 네임스페이스 기록에 등록한다.

        로직: nsproxy의 mnt_ns 포인터를 확인하고 공통 namespace 수집 함수에 전달한다.
        """
        if not task.nsproxy or not task.nsproxy.mnt_ns:
            return None
        return self.namespace(task.nsproxy.mnt_ns, "mnt", entity)

    def bind_mount_record(self, mount, task, ns):
        """표준 설정 파일의 bind mount 원천 경로를 복원하고, 경로에서 확인한 컨테이너 ID를 기록한다.

        로직: 표준 /etc 파일의 마운트만 골라 원천 dentry 경로를 복원하고 ID·파일명 일치를 검사한다.
        """
        source = self.standard_bind_source(mount, task)
        if source is None:
            return
        cid, path, source_path, _ = source
        self.report["mounts"].append(
            {
                "address": hex(self.address(mount)),
                "namespace": ns,
                "path": path,
                "source_path": source_path,
                "container_id": cid,
                "location": self.location(mount),
            }
        )

    def standard_bind_source(self, mount, task):
        """표준 /etc bind mount의 원천 파일과 컨테이너 디렉터리를 검증해 반환한다.

        로직: 파일명을 먼저 확인하고, mount 경로·상위 dentry·전체 원천 경로의 ID가 일치하는지 검사한다.
        """
        root = mount.get_mnt_root().dereference()
        filename = root.d_name.name_as_str()
        if filename not in ("hosts", "hostname", "resolv.conf"):
            return None
        path = linux.LinuxUtilities.get_path_mnt(task, mount)
        if path != "/etc/" + filename:
            return None
        directory = root.d_parent.dereference()
        cid = directory.d_name.name_as_str()
        if (
            not CID.fullmatch(cid)
            or directory.d_parent.dereference().d_name.name_as_str() != "containers"
        ):
            return None
        parts, seen, current = [], set(), root
        while True:
            address = self.address(current)
            if address in seen or len(seen) >= 256:
                raise artifact_core.Incomplete("Dentry parent cycle/budget")
            seen.add(address)
            name = current.d_name.name_as_str()
            if name not in ("", "/"):
                parts.append(name)
            if int(current.d_parent) == current.vol.offset:
                break
            current = current.d_parent.dereference()
        source = "/" + "/".join(reversed(parts))
        match = BIND_ID.search(source)
        if not match or match[1] != cid or match[2] != filename:
            return None
        return cid, path, source, directory

    def collect_mount_identity(self):
        """ID 미확인 태스크의 비호스트 mount namespace를 조사하고, 오류·충돌 없이 유일한 ID가 확인되면 보완한다.

        로직: 미식별 태스크를 mount namespace별로 묶어 표준 bind 원천을 조사한다. ID가 유일하고 순회가 완전할 때만 보완한다.
        """
        unknown = [r for r in self.report["tasks"] if not r["container_ids"]]
        if not unknown or self.init is None:
            return
        host = self.read(
            "host mount namespace",
            self.init,
            lambda: self.mount_namespace(self.init, "host"),
        )
        if host is None:
            self.issue(
                "mount identity scope",
                "host",
                artifact_core.Incomplete(
                    "Host mount namespace unavailable; fallback skipped"
                ),
            )
            return
        members = {}
        for address, task in self.tasks.items():
            row = self.task_rows[address]
            ns = self.read(
                "task mount namespace", task, lambda t=task: self.mount_namespace(t)
            )
            if ns:
                row["namespaces"]["mnt"] = ns
                members.setdefault(ns["address"], []).append(row)
        for ns, rows in members.items():
            unresolved = [r for r in rows if not r["container_ids"]]
            if not unresolved or ns == host["address"]:
                continue
            prior_ids = set()
            for row in rows:
                prior_ids.update(row["container_ids"])
            if len(prior_ids) > 1:
                continue  # Shared namespace with conflicting membership is not an ID fallback.
            task = self.tasks[int(unresolved[0]["address"], 16)]
            start, errors = len(self.report["mounts"]), len(self.report["errors"])

            def scan(*, ns=ns, task=task):
                """대상 mount namespace의 마운트를 한도 내 순회하며 표준 bind mount의 ID 근거를 수집한다.

                로직: namespace의 마운트를 제한된 개수만 순회하며 각 마운트에서 bind ID 근거를 읽는다.
                """
                namespace = self.obj("mnt_namespace", int(ns, 16))
                for mnt in self.bounded(mount_readers.stock_mount_points(namespace)):
                    self.read(
                        "standard bind mount",
                        mnt,
                        lambda m=mnt, ns=ns, task=task: self.bind_mount_record(
                            m, task, ns
                        ),
                    )

            self.read("mount identity namespace", ns, scan)
            evidence = self.report["mounts"][start:]
            ids = {r["container_id"] for r in evidence}
            if not ids:
                continue
            if len(ids) != 1 or (prior_ids and ids != prior_ids):
                for row in unresolved:
                    row["identity_conflicts"].append(
                        {
                            "source": "mounts",
                            "ids": sorted(ids | prior_ids),
                            "reason": "standard bind mounts / namespace identities disagree",
                        }
                    )
                continue
            if len(self.report["errors"]) != errors:
                continue  # An incomplete namespace can conceal conflicting bind sources.
            for row in unresolved:
                row["container_ids"] = sorted(ids)
                row["identity_sources"].append("standard_bind_mount")
                row["identity_mounts"] = [r["address"] for r in evidence]

    def collect_identity(self):
        """관찰 태스크가 있으면 shim과 조건부 마운트 분석으로 컨테이너 식별 정보를 보완한다.

        로직: 태스크가 없으면 건너뛰고, 있으면 shim 수집과 조건부 mount 식별을 차례로 수행한다.
        """
        if not self.tasks:
            self.skipped["identity"] = "No observed process leaders to attribute"
            return
        self.read("direct shim discovery", "tasks", self.collect_shims)
        self.read("conditional mount identity", "tasks", self.collect_mount_identity)

    def collect_selection(self):
        """태스크를 전체 컨테이너 ID별로 묶고 대표 선정 결과·연결 태스크·출처·충돌을 후보에 저장한다.

        로직: 검증된 전체 ID로 태스크를 묶고 대표를 정해 후보별 출처·연관 태스크·충돌 상태를 저장한다.
        """
        groups = {}
        for row in self.report["tasks"]:
            for cid in row["container_ids"]:
                if CID.fullmatch(cid):
                    groups.setdefault(cid, []).append(row)
        for cid, rows in sorted(groups.items()):
            representative, selection = select_representative(rows, cid)
            conflicts = []
            sources = set()
            for row in rows:
                for conflict in row["identity_conflicts"]:
                    conflicts.append({"task": row["address"], **conflict})
                sources.update(row["identity_sources"])
            obj = {
                "id": cid,
                "task_addresses": [r["address"] for r in rows],
                "representative_task": representative["address"]
                if representative
                else None,
                "representative_selection": selection,
                "representative": None,
                "configured_privileged": None,
                "settings_refs": [],
                "sources": sorted(sources),
                "conflicts": conflicts,
                "association": "CONFLICT" if conflicts else "TASK_LINKED_CANDIDATE",
            }
            self.containers[cid] = obj
            self.report["containers"].append(obj)

    def collect_details(self):
        """대표가 선정된 컨테이너에 대해 해당 프로세스의 PID·명령·시작 시각·실행 권한을 수집한다.

        로직: 선정된 대표 주소의 task를 찾아 시각과 cred를 읽는다. 대표가 없으면 권한을 추정하지 않는다.
        """
        if not self.containers:
            self.skipped["details"] = "No task-linked container candidates"
            return
        for obj in self.containers.values():
            address = obj["representative_task"]
            if address is None:
                continue
            task, row = self.tasks[int(address, 16)], self.task_rows[int(address, 16)]
            record = {
                "address": address,
                "pid": row["pid"],
                "comm": row["comm"],
                "process_start": self.read(
                    "representative start time",
                    task,
                    lambda task=task: self.process_start(task),
                ),
                "effective_uid": None,
                "effective_caps": None,
            }
            obj["representative"] = record

            def credentials(*, record=record, task=task):
                """대표 태스크의 cred를 확인하고 credential 위치·Effective UID·effective capability를 기록한다.

                로직: cred 포인터를 역참조해 위치·euid·cap_effective를 각각 오류 격리 경로로 읽는다.
                """
                if not task.has_member("cred") or not task.cred:
                    raise artifact_core.Unsupported(
                        "Representative credentials unavailable"
                    )
                cred = task.cred.dereference()
                record["credential_location"] = self.location(cred)

                def effective_uid():
                    """euid를 val 필드가 있는 구조 또는 정수 형태에 맞춰 읽는다.

                    로직: euid에 val 멤버가 있으면 그 필드를 사용하고 아니면 값을 직접 정수로 읽는다.
                    """
                    value = cred.member("euid")
                    return credential_readers.kernel_id(value, require_member_api=True)

                record["effective_uid"] = self.read("cred.euid", cred, effective_uid)
                record["effective_caps"] = self.read(
                    "cred.cap_effective",
                    cred,
                    lambda: hex(credential_readers.capability_mask(cred.cap_effective)),
                )

            self.read("representative credentials", task, credentials)

    def collect_settings(self):
        """검증된 bind mount 원천 디렉터리에서만 hostconfig.json을 조회한다.

        로직: 컨테이너별 mount namespace에서 표준 bind 원천을 찾아 직계 자식만 제한 시간 내에 확인한다.
        """
        if not self.containers:
            self.skipped["settings"] = (
                "No task-linked IDs; hostconfig recovery not requested"
            )
            return
        scope = {
            "container_ids": sorted(self.containers),
            "source": "verified standard bind-mount source directories",
            "by_container": {},
        }
        self.report["settings_scope"] = scope
        known_roots, unresolved = {}, []
        for cid, container in self.containers.items():
            deadline = time.monotonic() + SETTINGS_SECONDS
            state = {
                "status": "UNRESOLVED",
                "mounts_examined": 0,
                "directories": [],
                "children_examined": 0,
                "search_complete": False,
            }
            scope["by_container"][cid] = state
            anchors = {}
            addresses = container["task_addresses"]
            preferred = container["representative_task"]
            if preferred in addresses:
                addresses = [preferred] + [
                    address for address in addresses if address != preferred
                ]
            examined_namespaces = set()
            for address in addresses:
                if anchors:
                    break
                task = self.tasks[int(address, 16)]
                ns = self.read(
                    "settings task mount namespace",
                    task,
                    lambda t=task: self.mount_namespace(t),
                )
                if not ns or ns["address"] in examined_namespaces:
                    continue
                examined_namespaces.add(ns["address"])
                namespace = self.read(
                    "settings mount namespace",
                    ns,
                    lambda ns=ns: self.obj("mnt_namespace", int(ns["address"], 16)),
                )
                if namespace is None:
                    state["status"] = "INCOMPLETE"
                    continue
                before = len(self.report["errors"])

                def find_anchors(
                    *,
                    anchors=anchors,
                    cid=cid,
                    deadline=deadline,
                    namespace=namespace,
                    state=state,
                    task=task,
                ):
                    """한 namespace의 마운트에서 컨테이너 ID와 일치하는 표준 bind 원천을 찾는다.

                    로직: 개수·시간 한도를 확인하고 검증된 디렉터리 주소를 중복 없이 기록한다.
                    """
                    for mount in mount_readers.stock_mount_points(namespace):
                        if (
                            time.monotonic() >= deadline
                            or state["mounts_examined"] >= SETTINGS_MOUNT_LIMIT
                        ):
                            raise artifact_core.Incomplete(
                                "Settings mount search budget"
                            )
                        state["mounts_examined"] += 1
                        source = self.read(
                            "settings standard bind mount",
                            mount,
                            lambda m=mount, task=task: self.standard_bind_source(
                                m, task
                            ),
                        )
                        if source and source[0] == cid:
                            _, _, source_path, directory = source
                            anchors[self.address(directory)] = (
                                directory,
                                source_path.rsplit("/", 1)[0],
                            )

                self.read("settings mount search", namespace, find_anchors)
                if len(self.report["errors"]) != before:
                    state["status"] = "INCOMPLETE"
            if not anchors:
                if state["status"] != "INCOMPLETE":
                    state["status"] = "NO_VERIFIED_ANCHOR"
                unresolved.append(cid)
                continue
            state["directories"] = [path for _, path in anchors.values()]
            if len(anchors) != 1:
                state["status"] = "AMBIGUOUS_ANCHOR"
                self.issue(
                    "settings directory",
                    cid,
                    artifact_core.Incomplete(
                        "Multiple source directories for one container ID"
                    ),
                )
                continue
            directory, parent_path = next(iter(anchors.values()))
            root = self.read(
                "settings peer root",
                directory,
                lambda directory=directory: directory.d_parent.dereference(),
            )
            if root is not None:
                known_roots[self.address(root)] = (root, parent_path.rsplit("/", 1)[0])
            else:
                state["status"] = "INCOMPLETE"
            self.lookup_settings_file(
                cid,
                directory,
                parent_path,
                state,
                deadline,
                source_complete=state["status"] != "INCOMPLETE",
            )
        for cid in unresolved:
            if not known_roots:
                break
            state = scope["by_container"][cid]
            deadline = time.monotonic() + SETTINGS_SECONDS
            found, complete = {}, True
            for root, root_path in known_roots.values():
                before = len(self.report["errors"])

                def find_container(
                    *,
                    cid=cid,
                    deadline=deadline,
                    found=found,
                    root=root,
                    root_path=root_path,
                    state=state,
                ):
                    """다른 컨테이너가 검증한 containers 디렉터리에서 대상 ID만 조회한다.

                    로직: 직계 자식을 제한 시간·개수 안에서 열거해 정확히 일치하는 ID를 찾는다.
                    """
                    for child in root.get_subdirs():
                        if (
                            time.monotonic() >= deadline
                            or state["children_examined"] >= SETTINGS_CHILD_LIMIT
                        ):
                            raise artifact_core.Incomplete(
                                "Settings container directory budget"
                            )
                        state["children_examined"] += 1
                        if child.d_name.name_as_str() == cid:
                            found[self.address(child)] = (child, root_path + "/" + cid)

                self.read("settings container directory", root, find_container)
                if len(self.report["errors"]) != before:
                    complete = False
            if not complete or len(found) != 1:
                if len(found) > 1:
                    state["status"] = "AMBIGUOUS_ANCHOR"
                    self.issue(
                        "settings directory",
                        cid,
                        artifact_core.Incomplete(
                            "Container ID occurs in multiple verified roots"
                        ),
                    )
                continue
            directory, parent_path = next(iter(found.values()))
            state["directories"] = [parent_path]
            state["source"] = "peer_verified_root"
            self.lookup_settings_file(
                cid,
                directory,
                parent_path,
                state,
                deadline,
                source_complete=state["status"] != "INCOMPLETE",
            )
        self.merge_settings()

    def lookup_settings_file(
        self, cid, directory, parent_path, state, deadline, source_complete
    ):
        """검증된 컨테이너 디렉터리의 직계 자식에서 hostconfig.json만 복구한다.

        로직: 자식 조회·파일 복구가 모두 끝난 경우에만 해당 ID의 설정 검색을 완료로 표시한다.
        """
        before = len(self.report["errors"])

        def find_file():
            """디렉터리 자식을 제한 시간·개수 안에서 열거하고 대상 inode를 복구한다.

            로직: 이름이 hostconfig.json인 양수 dentry만 페이지 캐시 복구로 전달한다.
            """
            for child in directory.get_subdirs():
                if (
                    time.monotonic() >= deadline
                    or state["children_examined"] >= SETTINGS_CHILD_LIMIT
                ):
                    raise artifact_core.Incomplete("Settings child lookup budget")
                state["children_examined"] += 1
                if child.d_name.name_as_str() != "hostconfig.json" or not child.d_inode:
                    continue
                inode = child.d_inode.dereference()
                self.read(
                    "hostconfig inode",
                    inode,
                    lambda i=inode: self.recover_privileged(
                        i, parent_path + "/hostconfig.json", cid
                    ),
                )

        self.read("settings file lookup", directory, find_file)
        if len(self.report["errors"]) != before or not source_complete:
            state["status"] = "INCOMPLETE"
            return
        state["search_complete"] = True
        state["status"] = (
            "FOUND"
            if any(r["container_id"] == cid for r in self.report["cached_settings"])
            else "NOT_FOUND"
        )

    def merge_settings(self):
        """복구한 Privileged 값과 ID의 충돌을 검사해 컨테이너 설정 값·출처·충돌 상태를 반영한다.

        로직: 같은 ID의 hostconfig 기록을 찾아 bool 값과 ID 충돌을 비교한다. 유일하고 충돌이 없을 때만 설정을 확정한다.
        """
        for cid, obj in self.containers.items():
            rows = [
                (i, r)
                for i, r in enumerate(self.report["cached_settings"])
                if r["container_id"] == cid
            ]
            obj["settings_refs"] = [i for i, _ in rows]
            search = (
                self.report.get("settings_scope", {})
                .get("by_container", {})
                .get(cid, {})
            )
            verified = [
                (i, r)
                for i, r in rows
                if r.get("complete") is True
                and r.get("json_parse") == "FULL"
                and not r.get("identity_conflict")
                and type(r.get("privileged")) is bool
            ]
            values = {r["privileged"] for _, r in verified}
            conflicts = [
                {"source": "hostconfig", "index": i, "reason": "Path/JSON IDs disagree"}
                for i, r in rows
                if r.get("identity_conflict")
            ]
            if len(values) > 1:
                conflicts.append(
                    {
                        "source": "hostconfig",
                        "field": "Privileged",
                        "values": sorted(values),
                        "reason": "Recovered settings disagree",
                    }
                )
            obj["configured_privileged"] = (
                next(iter(values))
                if search.get("search_complete")
                and len(verified) == len(rows)
                and len(values) == 1
                and not conflicts
                else None
            )
            obj["conflicts"].extend(conflicts)
            if rows and "hostconfig" not in obj["sources"]:
                obj["sources"].append("hostconfig")
            if obj["conflicts"]:
                obj["association"] = "CONFLICT"

    def collect(self):
        """tasks·identity·selection·details·settings 단계를 순서대로 실행하고 전체 수집 보고서를 반환한다.

        로직: 정해진 STAGES 순서로 collect_* 함수를 호출하고 누적 보고서를 반환한다.
        """
        for stage in STAGES:
            self.stage_run(stage, getattr(self, "collect_" + stage))
        return self.report

    def read_vmemmap_base(self):
        """vmemmap_base의 실제 타입을 검증해 읽고, 타입 정보가 없을 때만 대상 커널의 포인터 폭·바이트 순서를 사용한다.

        로직: 심볼 타입이 있으면 정수 폭·부호를 확인해 읽는다. 타입이 없을 때만 대상 ABI 형식으로 읽으며 타입 오류·읽기 실패에는 재시도하지 않는다.
        """
        word = self.kernel.get_type("pointer").vol.data_format
        if word.signed or word.length * 8 != self.layer.bits_per_register:
            raise artifact_core.Unsupported(
                "Native pointer layout disagrees with the kernel layer"
            )
        symbol = self.kernel.get_symbol("vmemmap_base")
        template = symbol.type
        if template is not None:
            if isinstance(template, objects.templates.ReferenceTemplate):
                template = self.context.symbol_space.get_type(template.vol.type_name)
            if (
                not issubclass(template.vol.object_class, objects.Integer)
                or issubclass(template.vol.object_class, objects.Pointer)
                or template.size != word.length
                or template.vol.data_format != word
            ):
                raise artifact_core.Unsupported(
                    "vmemmap_base is not an unsigned native-width integer"
                )
            base = int(self.kernel.object_from_symbol("vmemmap_base"))
        else:
            # Some ISFs provide global addresses without variable types. Only
            # this known address-valued global uses the native-word fallback.
            address = self.layer.canonicalize(
                self.kernel.get_absolute_symbol_address("vmemmap_base")
                & self.layer.address_mask
            )
            raw = self.layer.read(address, word.length, pad=False)
            if len(raw) != word.length:
                raise artifact_core.Incomplete("Incomplete vmemmap_base value")
            base = int.from_bytes(raw, byteorder=word.byteorder, signed=False)
        if not base or self.layer.canonicalize(base & self.layer.address_mask) != base:
            raise ValueError("Invalid vmemmap_base address")
        return base

    def recover_privileged(self, inode, path, cid):
        """hostconfig.json의 캐시 페이지를 복구해 Privileged를 읽고, 누락 범위·파싱 상태·ID 충돌을 기록한다.

        로직: inode의 캐시 페이지를 모아 연속된 데이터만 JSON으로 해석한다. 누락·중복·ID 충돌을 기록하고 bool Privileged만 채택한다.
        """
        if cid not in self.containers:
            return
        filename = "hostconfig.json"
        row = {
            "path": path,
            "container_id": cid,
            "filename": filename,
            "inode": hex(inode.vol.offset),
            "location": self.location(inode),
            "pages": [],
            "holes": [],
            "json_parse": "NOT FOUND",
        }
        self.report["cached_settings"].append(row)
        size = int(inode.i_size)
        if not 0 < size <= FILE_LIMIT:
            raise artifact_core.Incomplete("Empty/over-limit metadata inode")
        row["size"] = size
        row["mapping"] = hex(int(inode.i_mapping))
        mapping = inode.i_mapping.dereference()
        storage = linux.IDStorage.choose_id_storage(self.context, self.kernel.name)
        pieces = {}
        page_size = self.layer.page_size

        def recover():
            """inode의 페이지 캐시 항목을 한도 내 순회하고 각 페이지의 내용 읽기·검증을 수행한다.

            로직: 페이지 캐시 항목을 순회하면서 각 page의 데이터 검증 함수를 호출한다.
            """
            for page_address in self.bounded(storage.get_entries(mapping.i_pages)):
                page = self.obj("page", page_address)

                def content(*, page=page):
                    """페이지의 mapping·파일 오프셋을 검증해 바이트를 읽고, 중복 데이터 충돌을 검사하며 페이지 해시를 기록한다.

                    로직: mapping과 파일 오프셋을 검사한 뒤 실제 페이지 바이트를 읽고 해시·충돌을 기록한다.
                    """
                    if int(page.mapping) != int(inode.i_mapping):
                        raise ValueError("Cached page mapping backlink mismatch")
                    if page.has_member("index"):
                        index = int(page.index)
                    elif self.kernel.has_type("folio"):
                        folio = self.obj("folio", page.vol.offset)
                        # Both views must agree on the mapping member offset.
                        if folio.mapping.vol.offset != page.mapping.vol.offset:
                            raise artifact_core.Unsupported(
                                "folio/page mapping layout differs"
                            )
                        index = int(folio.index)
                    else:
                        raise artifact_core.Unsupported(
                            "Cached page index layout unavailable"
                        )
                    offset = index * page_size
                    if not 0 <= offset < size:
                        raise ValueError("Cached page outside inode")
                    if self.kernel.has_symbol(
                        "vmemmap_base"
                    ) and self.kernel.has_symbol("mem_section"):
                        base = self.read_vmemmap_base()
                        address = self.layer.canonicalize(page.vol.offset)
                        width = self.kernel.get_type("page").size
                        if address < base or (address - base) % width:
                            raise ValueError("Page is outside aligned vmemmap")
                        physical = (address - base) // width * page_size
                        raw = self.context.layers[
                            self.layer.config["memory_layer"]
                        ].read(physical, page_size)
                    else:
                        raw = page.get_content()
                    if not raw:
                        raise artifact_core.Incomplete("Cached page unreadable")
                    raw = raw[: min(page_size, size - offset)]
                    if offset in pieces and pieces[offset] != raw:
                        raise ValueError("Conflicting cache pages at one file offset")
                    pieces[offset] = raw
                    row["pages"].append(
                        {
                            "file_offset": offset,
                            "page": hex(page.vol.offset),
                            "length": len(raw),
                            "sha256": hashlib.sha256(raw).hexdigest(),
                        }
                    )

                self.read("cached page", page, content)

        self.read("inode pages", inode, recover)
        prefix = bytearray()
        for offset in range(0, size, page_size):
            raw = pieces.get(offset)
            expected = min(page_size, size - offset)
            if raw is None or len(raw) != expected:
                row["holes"].append({"offset": offset, "length": expected})
            if offset == len(prefix) and raw is not None:
                prefix.extend(raw)
        row["contiguous_prefix_bytes"] = len(prefix)
        row["complete"] = len(prefix) == size and not row["holes"]
        if row["holes"]:
            self.issue(
                "metadata coverage",
                inode,
                artifact_core.Incomplete("Missing cache ranges; no zero filling"),
            )
        if prefix:
            try:
                data = json_object(bytes(prefix))
                row["json_parse"] = "FULL" if row["complete"] else "PARTIAL"
            except DuplicateJSONKey:
                raise
            except ValueError as exc:
                data = prefix_json(bytes(prefix))
                row["json_parse"] = "PARTIAL"
                self.issue("metadata JSON", inode, artifact_core.Incomplete(str(exc)))
            embedded = data.get("ID")
            row["identity_conflict"] = embedded is not None and embedded != cid
            if row["identity_conflict"]:
                self.issue(
                    "metadata identity", inode, ValueError("Path and JSON ID disagree")
                )

            privileged = data.get("Privileged")
            if "Privileged" in data and type(privileged) is not bool:
                raise ValueError("hostconfig Privileged is not a boolean")
            row["privileged"] = privileged if not row["identity_conflict"] else None


def vertical_presentation(report):
    """컨테이너 요약을 ID순으로 정렬해 컨테이너당 하나의 category·value 세로 출력 블록으로 구성한다.

    로직: ID로 정렬한 컨테이너에서 대표·권한·출처 값을 추려 category/value 행을 만든다.
    """
    rows = []

    def cell(value):
        """미확인 값은 하이픈으로 표시하고, 나머지 값은 줄바꿈·탭을 이스케이프한 문자열로 변환한다.

        로직: None·빈 값은 하이픈으로 바꾸고 문자열의 탭·줄바꿈을 한 줄 표시에 맞게 이스케이프한다.
        """
        return (
            "-"
            if value is None or value == ""
            else str(value).replace("\n", "\\n").replace("\t", "\\t")
        )

    for obj in sorted(report["containers"], key=lambda c: c["id"]):
        if rows:
            rows.append(("", ""))
        process = obj.get("representative") or {}
        selection = obj["representative_selection"]
        fields = [
            ("Container ID", obj["id"]),
            ("Command", process.get("comm")),
            ("Process Start UTC", process.get("process_start")),
            ("Host PID", process.get("pid")),
            ("Effective UID", process.get("effective_uid")),
            ("Effective Caps", process.get("effective_caps")),
            ("Configured Privileged", obj.get("configured_privileged")),
            ("Representative", selection["method"] or selection["status"]),
            ("Association", obj["association"]),
            ("Sources", ",".join(obj["sources"])),
        ]
        rows.extend((name, cell(value)) for name, value in fields)
    return [("category", str), ("value", str)], rows


def run_ps(context, kernel_name, open_file):
    """통합 Docker 플러그인의 --ps 결과와 증거 파일을 생성한다.

    로직: Collector로 수집한 보고서를 JSON으로 저장하고, 오류를 경고한 뒤 세로형 TreeGrid를 반환한다.
    """
    report = Collector(context, kernel_name).collect()
    with open_file("ps_evidence.json") as output:
        output.write(json.dumps(report, ensure_ascii=False, indent=2).encode("utf-8"))
    if report["errors"]:
        vollog.warning(
            "ps: %d collection issues; review coverage in ps_evidence.json",
            len(report["errors"]),
        )
    unresolved = sum(c["representative"] is None for c in report["containers"])
    if unresolved:
        vollog.warning(
            "ps: %d container candidates have no unambiguous representative", unresolved
        )
    if not report["containers"]:
        vollog.warning(
            "ps: no task-linked Docker candidates in the searched process list; review coverage"
        )
    columns, rows = vertical_presentation(report)
    return renderers.TreeGrid(columns, ((0, row) for row in rows))

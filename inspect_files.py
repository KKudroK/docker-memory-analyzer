# SPDX-License-Identifier: MIT
"""Docker의 --inspect-files 옵션: 컨테이너의 열린 FD와 파일 경로 분석.

대상 환경: Volatility 3 2.28.0, Intel Linux, 덤프와 일치하는 kernel ISF.
linux.docker.Docker를 통해 실행하는 내부 분석 모듈이다. cgroup 소속,
마운트 목록, 파일 경로는 linux/_artifacts의 공통 판독기와 Volatility 공식 API로 읽는다.

실행 예시 (전역 옵션은 플러그인 이름 앞):
    vol -p ./plugins -s SYMBOLS -f MEMORY linux.docker.Docker --inspect-files
    vol -p ./plugins -s SYMBOLS -f MEMORY linux.docker.Docker --inspect-files --view hosts
    vol -p ./plugins -s SYMBOLS -f MEMORY linux.docker.Docker --inspect-files --view details
    vol -p ./plugins -s SYMBOLS -f MEMORY linux.docker.Docker --inspect-files --pids 4283

모든 보기는 Record / Field / Value 3열 세로형이다. Container, PID/TID,
FD도 각각 한 행으로 표시한다. 같은 FD의 항목은 같은 Record 번호로 묶는다.
Record는 실행 결과 안의 순번이며 커널 객체 ID나 실행 간 고정 식별자가 아니다.
files / hosts / details는 표시할 항목만 바꾸며 출력 방향은 동일하다.
--extended는 details 보기의 별칭이다. PID/TID는 공유 FD 테이블의 대표 태스크다.
동일 프로세스의 동일 files_struct/root/소속만 중복 제거한다. 다른 프로세스,
다른 FD 번호, 별도 파일 테이블을 가진 스레드는 합치지 않는다.
컨테이너 ID는 충돌 없는 최소 12자리로 표시하며 --full-id로 원문을 출력한다.
JSON도 같은 규칙이므로 증거용 JSON에는 --full-id를 사용한다.
JSON/CSV도 같은 3열 구조이며, Record로 묶고 Field/Value를 읽으면 된다.

UNLINKED는 d_unlinked() 형태의 이름 연결 상태이지 삭제 행위의 입증이 아니다.
익명 객체, 이름 없는 임시 파일, 읽기 실패를 구분한다. 파일 내용은 추출하지
않으며, 닫힌 FD/과거 이력/VMA에만 남은 파일/overlay backing layer는 범위 밖이다.
호스트 경로는 확인된 mount alias이며 원래 mount 명령이나 접근 권한이 아니다.
details 보기의 Read Status는 판독 상태이며 위험도/점수가 아니다.
기본 State의 *는 일부 정보 판독 실패를 뜻하며 details에서 사유를 확인한다.
NAME_ONLY는 이름만 확인된 경우다. 정상 FD가 현재 프로세스의 루트 밖을
가리키는 경우도 포함하며, 호스트 경로는 별도로 확인할 수 있다.
일부 제어문자·비UTF8 파일명은 현재 판독 범위 밖이다.
"""

import collections
import dataclasses
import logging
import re

from volatility3.framework import exceptions, renderers
from volatility3.framework.configuration import requirements
from volatility3.framework.interfaces import plugins
from volatility3.framework.objects import utility
from volatility3.framework.symbols import linux
from volatility3.plugins.linux import docker_artifacts, pslist
from volatility3.plugins.linux._artifacts import cgroups as cgroup_readers
from volatility3.plugins.linux._artifacts import core as artifact_core
from volatility3.plugins.linux._artifacts import files as file_readers
from volatility3.plugins.linux._artifacts import mounts as mount_readers
from volatility3.plugins.linux._artifacts import paths as path_readers
from volatility3.plugins.linux._artifacts import tasks as task_readers


def _runtime_from_ancestry(task):
    return task_readers.runtime_from_ancestry(task, RUNTIME_SUPERVISORS)


vollog = logging.getLogger(__name__)
MAX_TASKS = 1000000


# 실제 cgroup 소속과 런타임 조상 관계 판독.


@dataclasses.dataclass(frozen=True)
class Identity:
    runtime: str
    identifier: str
    id_kind: str
    evidence: str


@dataclasses.dataclass
class TaskObservation:
    pid: int
    task: object
    mnt_ns: object
    root_key: tuple
    cgroup_memberships: tuple
    identity: object
    runtime: str
    evidence: tuple


_CGROUP_HEX_ID = r"[0-9a-f]{64}"
_CGROUP_POD_ID = r"[0-9a-f]{8}(?:[-_][0-9a-f]{4}){3}[-_][0-9a-f]{12}"
_CGROUP_ID_PATTERNS = (
    (
        rf"(?:^|/)docker-({_CGROUP_HEX_ID})\.scope(?=/|$)",
        "docker",
        "container",
        "docker-systemd-cgroup",
    ),
    (
        rf"(?:^|/)docker/({_CGROUP_HEX_ID})(?=/|$)",
        "docker",
        "container",
        "docker-cgroupfs",
    ),
    (
        rf"(?:^|/)cri-containerd-({_CGROUP_HEX_ID})\.scope(?=/|$)",
        "containerd",
        "container",
        "containerd-systemd-cgroup",
    ),
    (
        rf"(?:^|/)crio-({_CGROUP_HEX_ID})\.scope(?=/|$)",
        "cri-o",
        "container",
        "crio-systemd-cgroup",
    ),
    (
        rf"(?:^|/)libpod-({_CGROUP_HEX_ID})\.scope(?=/|$)",
        "podman",
        "container",
        "podman-systemd-cgroup",
    ),
    (
        rf"(?:^|/)(?:crio|cri-containerd)/({_CGROUP_HEX_ID})(?=/|$)",
        "kubernetes",
        "container",
        "cri-cgroupfs",
    ),
    (
        rf"(?:^|/)kubepods(?:/(?:burstable|besteffort))?/pod{_CGROUP_POD_ID}/({_CGROUP_HEX_ID})(?=/|$)",
        "kubernetes",
        "container",
        "kubernetes-cgroupfs-container",
    ),
    (
        rf"(?:^|/)(?:kubepods(?:-[^/]+)*-)?pod({_CGROUP_POD_ID})(?:\.slice)?(?=/|$)",
        "kubernetes",
        "pod",
        "kubernetes-pod-cgroup",
    ),
)
_CGROUP_ID_PATTERNS = tuple(
    (re.compile(pattern, re.IGNORECASE), runtime, kind, source)
    for pattern, runtime, kind, source in _CGROUP_ID_PATTERNS
)

# task.comm의 15바이트 절단만 허용한다. 일반 런처 이름은 근거가 아니다.
RUNTIME_SUPERVISORS = (
    ("containerd-shim", "containerd"),
    ("conmon", "podman/cri-o"),
    ("lxc-start", "lxc"),
    ("lxc-monitord", "lxc"),
    ("systemd-nspawn", "nspawn"),
    ("runsc-sandbox", "gvisor"),
    ("kata-shim", "kata"),
)


def _cgroup_identity(memberships):
    """알려진 runtime 경로만 식별하며 중첩·계층 간 ID 충돌은 보류한다."""
    matches = []
    for membership in memberships:
        for pattern, runtime, kind, source in _CGROUP_ID_PATTERNS:
            for match in pattern.finditer(membership.path):
                identifier = match.group(1).lower()
                if kind == "pod":
                    identifier = identifier.replace("_", "-")
                matches.append(
                    (membership, Identity(runtime, identifier, kind, source))
                )
    for kind in ("container", "pod"):
        if len({item.identifier for _, item in matches if item.id_kind == kind}) > 1:
            return None, "", True
    for kind in ("container", "pod"):
        candidates = [
            (membership, identity)
            for membership, identity in matches
            if identity.id_kind == kind
        ]
        if candidates:
            candidates.sort(
                key=lambda item: (
                    item[0].version != "v2",
                    item[0].display(),
                    item[1].runtime,
                )
            )
            membership, identity = candidates[0]
            owner = ",".join(membership.controllers) or "unified"
            return identity, f"{membership.version}:{owner}", False
    return None, "", False


def _observe_task(task):
    try:
        if (
            not task
            or not task.fs
            or not artifact_core._object_readable(task.fs)
            or not task.nsproxy
            or not artifact_core._object_readable(task.nsproxy)
        ):
            return None
        mnt_ns = task.nsproxy.mnt_ns
        root_mnt, root_dentry = task.fs.get_root_mnt(), task.fs.get_root_dentry()
        if not all(
            obj and artifact_core._object_readable(obj)
            for obj in (mnt_ns, root_mnt, root_dentry)
        ):
            return None
        pid = int(task.pid)
        root_key = (
            artifact_core._object_address(root_mnt),
            artifact_core._object_address(root_dentry),
        )
    except artifact_core.READ_ERRORS:
        return None
    issues = set()
    memberships = cgroup_readers.read_link_memberships(
        task, issues_out=issues, logger=vollog
    )
    identity, source, conflict = _cgroup_identity(memberships)
    conflict = conflict or "cgroup-id-conflict" in issues
    if conflict:
        identity = None
    runtime, supervisor = _runtime_from_ancestry(task)
    evidence = []
    if conflict:
        evidence.append("cgroup-id-conflict")
    elif identity:
        evidence.append(f"cgroup:{source}:{identity.evidence}")
    if supervisor:
        evidence.append(f"supervisor:{supervisor}")
    if "cgroup-metadata-partial" in issues:
        evidence.append("cgroup-metadata-partial")
    return TaskObservation(
        pid=pid,
        task=task,
        mnt_ns=mnt_ns,
        root_key=root_key,
        cgroup_memberships=memberships,
        identity=identity,
        runtime=identity.runtime if identity else runtime,
        evidence=tuple(evidence),
    )


def _safe_text(value):
    """터미널 제어문자는 이스케이프한다. 의미 있는 공백은 삭제하지 않는다."""
    return "".join(
        f"\\x{ord(char):02x}" if ord(char) < 32 or ord(char) == 127 else char
        for char in str(value)
    )


def _display_ids(identifiers, full=False):
    """짧은 ID끼리 충돌하면 구별될 때까지 확장한다. 내부 소속 ID는 항상 원문이다."""
    identifiers = sorted({identifier for identifier in identifiers if identifier})
    if full:
        return {identifier: identifier for identifier in identifiers}
    result = {}
    for identifier in identifiers:
        size = min(12, len(identifier))
        while size < len(identifier) and any(
            other != identifier and other.startswith(identifier[:size])
            for other in identifiers
        ):
            size += 1
        result[identifier] = identifier[:size]
    return result


@dataclasses.dataclass
class TaskView:
    task: object
    tgid: int
    tid: int
    container_id: str
    observation: object
    files_address: int
    members: set = dataclasses.field(default_factory=set)
    issues: set = dataclasses.field(default_factory=set)


class InspectFiles(plugins.PluginInterface):
    """Inspect container file descriptors, file paths and unlinked-name references."""

    hidden = True
    _required_framework_version = (2, 28, 0)
    _version = (0, 3, 4)

    @classmethod
    def get_requirements(cls):
        return [
            requirements.VersionRequirement(
                name="docker_artifacts",
                component=docker_artifacts.DockerArtifacts,
                version=(1, 0, 1),
            ),
            requirements.ModuleRequirement(
                name="kernel",
                description="Linux kernel with matching ISF",
                architectures=["Intel32", "Intel64"],
            ),
            requirements.VersionRequirement(
                name="linuxutils",
                component=linux.LinuxUtilities,
                version=(2, 4, 0),
            ),
            requirements.VersionRequirement(
                name="pslist", component=pslist.PsList, version=(4, 1, 1)
            ),
            requirements.ListRequirement(
                name="pids",
                element_type=int,
                min_elements=1,
                optional=True,
                description="Explicit host process IDs (TGIDs), including their thread file tables",
            ),
            requirements.StringRequirement(
                name="container",
                optional=True,
                description="Select one unambiguous container ID prefix (6..64 hex characters)",
            ),
            requirements.ChoiceRequirement(
                name="view",
                choices=["files", "hosts", "details"],
                optional=True,
                description="All views are vertical Record/Field/Value rows; files: basic fields, hosts: host paths, details: all fields",
            ),
            requirements.BooleanRequirement(
                name="extended",
                optional=True,
                default=False,
                description="Alias for --view details (all fields, same 3-column vertical output)",
            ),
            requirements.BooleanRequirement(
                name="unlinked-only",
                optional=True,
                default=False,
                description="Only UNLINKED names, not anonymous or never-linked temporary files",
            ),
            requirements.BooleanRequirement(
                name="full-id",
                optional=True,
                default=False,
                description="Use complete container IDs (also required for full-ID JSON export)",
            ),
            requirements.IntRequirement(
                name="max-fds",
                optional=True,
                default=65536,
                description="Slots per file table (1..1048576); truncation is reported, never silently complete",
            ),
        ]

    def _options(self):
        wanted = self.config.get("pids")
        if wanted is not None and (
            not isinstance(wanted, list)
            or not wanted
            or any(type(pid) is not int or pid <= 0 for pid in wanted)
        ):
            raise exceptions.VolatilityException(
                "--pids requires positive host process IDs"
            )
        prefix = self.config.get("container")
        if prefix is not None and (
            not isinstance(prefix, str)
            or not re.fullmatch(r"[0-9a-fA-F]{6,64}", prefix)
        ):
            raise exceptions.VolatilityException(
                "--container requires a 6..64 hex ID prefix"
            )
        limit = self.config.get("max-fds", 65536)
        if type(limit) is not int or not 1 <= limit <= file_readers.MAX_FDS:
            raise exceptions.VolatilityException("--max-fds must be in 1..1048576")
        for name in ("extended", "unlinked-only", "full-id"):
            if type(self.config.get(name, False)) is not bool:
                raise exceptions.VolatilityException(f"--{name} must be a boolean")
        self._selected_view()
        return (
            set(wanted) if wanted is not None else None,
            prefix.lower() if prefix else None,
            limit,
        )

    def _selected_view(self):
        value = self.config.get("view")
        if value is not None and value not in ("files", "hosts", "details"):
            raise exceptions.VolatilityException(
                "--view must be files, hosts or details"
            )
        if self.config.get("extended", False):
            if value not in (None, "details"):
                raise exceptions.VolatilityException(
                    "--extended is an alias for --view details"
                )
            return "details"
        return value or "files"

    def _task_views(self, wanted, prefix):
        views, found, seen = {}, set(), set()
        failures = collections.Counter()
        try:
            initial = self.context.modules[self.config["kernel"]].object_from_symbol(
                "init_task"
            )
            host_namespace = initial.nsproxy.mnt_ns
            host_namespace_address = (
                artifact_core._object_address(host_namespace)
                if artifact_core._object_readable(host_namespace)
                else None
            )
        except artifact_core.READ_ERRORS:
            host_namespace_address = None
        tasks = docker_artifacts.DockerArtifacts.list_tasks(
            self.context,
            self.config["kernel"],
            include_threads=True,
        )
        try:
            for task in tasks:
                try:
                    address = artifact_core._object_address(task)
                    if address in seen:
                        continue
                    if len(seen) >= MAX_TASKS:
                        failures["task-limit"] += 1
                        break
                    seen.add(address)
                    tgid, tid = int(task.tgid), int(task.pid)
                    if wanted is not None and tgid not in wanted:
                        continue
                    if tgid <= 0 or tid <= 0:
                        continue
                    if not task.files:
                        if wanted is not None:
                            found.add(tgid)
                        continue
                    observation = _observe_task(task)
                    if observation is None and wanted is None:
                        # 자동 모드는 소속 근거를 못 읽은 host task를 컨테이너로 추측하지 않는다.
                        if task.fs and task.nsproxy:
                            failures["task-membership-or-view"] += 1
                        continue
                    related = False
                    if observation is not None:
                        related = (
                            observation.identity is not None
                            or "cgroup-id-conflict" in observation.evidence
                        )
                        if not related and host_namespace_address is not None:
                            command = utility.array_to_string(task.comm)
                            itself_supervisor = any(
                                task_readers.comm_matches(command, signature)
                                for signature, _ in RUNTIME_SUPERVISORS
                            )
                            # shim 자체의 FD를 컨테이너 내부 FD로 오인하지 않는다.
                            # 강한 cgroup 근거가 있으면 host MNT NS 공유 컨테이너도
                            # 허용하지만, supervisor 단독 근거는 분리된 NS를 요구한다.
                            related = (
                                not itself_supervisor
                                and artifact_core._object_address(observation.mnt_ns)
                                != host_namespace_address
                                and any(
                                    item.startswith("supervisor:")
                                    for item in observation.evidence
                                )
                            )
                    if wanted is None and not related:
                        continue
                    identity = observation.identity if observation is not None else None
                    container_id = (
                        identity.identifier
                        if identity and identity.id_kind == "container"
                        else ""
                    )
                    if prefix and not container_id.startswith(prefix):
                        continue
                    found.add(tgid)
                    files_address = artifact_core._object_address(task.files)
                    issues = set()
                    if observation is None:
                        issues.add("task-membership-or-view")
                        owner = ("unknown", tid)
                        view_key = (tid,)
                    else:
                        issues.update(
                            flag
                            for flag in observation.evidence
                            if flag in {"cgroup-id-conflict", "cgroup-metadata-partial"}
                        )
                        owner = container_id or (
                            tuple(
                                (m.version, m.cgroup_address)
                                for m in observation.cgroup_memberships
                            ),
                            observation.runtime,
                            tid if issues else None,
                        )
                        view_key = (
                            artifact_core._object_address(observation.mnt_ns),
                            observation.root_key,
                        )
                    # 같은 프로세스의 같은 FD table만 합친다. 다른 프로세스의
                    # 공유 FD, 스레드 전용 FD table, 다른 root/cgroup은 보존한다.
                    key = (tgid, files_address, view_key, owner)
                    if key not in views:
                        views[key] = TaskView(
                            task,
                            tgid,
                            tid,
                            container_id,
                            observation,
                            files_address,
                            {tid},
                            issues,
                        )
                    else:
                        view = views[key]
                        view.members.add(tid)
                        view.issues.update(issues)
                        if (tid != tgid, tid) < (view.tid != tgid, view.tid):
                            view.task, view.tid, view.observation = (
                                task,
                                tid,
                                observation,
                            )
                except artifact_core.READ_ERRORS:
                    failures["task-metadata"] += 1
        except artifact_core.READ_ERRORS:
            failures["task-list"] += 1
        if wanted is not None and wanted - found:
            vollog.warning(
                "Requested TGIDs not selected/readable: %s", sorted(wanted - found)
            )
        if wanted is None and host_namespace_address is None:
            vollog.warning(
                "Host MNT NS unreadable; automatic selection used cgroup evidence only"
            )
        if failures:
            vollog.warning(
                "Task collection incomplete: %s; missing rows do not prove absence",
                dict(failures),
            )
            for view in views.values():
                view.issues.add("task-list-partial")
        ids = {view.container_id for view in views.values() if view.container_id}
        if prefix and len(ids) > 1:
            raise exceptions.VolatilityException(
                "--container is ambiguous; use a longer/full ID"
            )
        return sorted(
            views.values(), key=lambda view: (view.container_id, view.tgid, view.tid)
        )

    def _read_fds(self, task, limit):
        return docker_artifacts.DockerArtifacts.read_file_descriptors(
            self.context,
            self.config["kernel"],
            int(task.vol.offset),
            limit=limit,
            layer_name=task.vol.layer_name,
            native_layer_name=task.vol.native_layer_name,
        )

    def _generator(self, output_view):
        wanted, prefix, limit = self._options()
        views = self._task_views(wanted, prefix)
        if not views:
            vollog.warning(
                "No task views selected; use --pids for an explicit known host process"
            )
            return
        id_display = _display_ids(
            (view.container_id for view in views), self.config.get("full-id", False)
        )
        kernel = self.context.modules[self.config["kernel"]]
        resolver = path_readers.FileHostMountResolver(
            kernel.object_from_symbol("init_task"), logger=vollog
        )
        table_cache, file_cache, namespace_cache = {}, {}, {}
        counts = collections.Counter()
        for view in views:
            if view.files_address not in table_cache:
                table_cache[view.files_address] = self._read_fds(view.task, limit)
            entries, table_issues = table_cache[view.files_address]
            if table_issues:
                vollog.warning(
                    "PID/TID %s/%s FD table incomplete: %s",
                    view.tgid,
                    view.tid,
                    dict(table_issues),
                )
            covering, namespace_complete = {}, False
            if view.observation is not None:
                namespace_address = artifact_core._object_address(
                    view.observation.mnt_ns
                )
                if namespace_address not in namespace_cache:
                    namespace_cache[namespace_address] = (
                        mount_readers.namespace_covering(view.observation.mnt_ns)
                    )
                covering, namespace_complete = namespace_cache[namespace_address]
            try:
                comm = _safe_text(utility.array_to_string(view.task.comm))
            except artifact_core.READ_ERRORS:
                comm = "-"
            for fd, filp in entries:
                file_address = artifact_core._object_address(filp)
                if file_address not in file_cache:
                    file_cache[file_address] = file_readers.file_facts(filp, resolver)
                facts = file_cache[file_address]
                if (
                    self.config.get("unlinked-only", False)
                    and facts.state != "UNLINKED"
                ):
                    continue
                path, path_status = file_readers.container_path(
                    view.task, facts, covering, namespace_complete
                )
                issues = set(view.issues) | set(facts.issues)
                issues.update(table_issues)
                if path_status == "PARTIAL":
                    issues.add("container-path")
                if issues:
                    counts["partial"] += 1
                counts["rows"] += 1
                counts[facts.state] += 1
                displayed_path = _safe_text(path) or "-"
                # 식별자도 가로 열로 반복하지 않고 FD 묶음 안의 세로 항목으로 둔다.
                # counts['rows']는 출력할 FD마다 한 번 증가하므로 여러 별칭이나
                # 공유 TID가 있어도 하나의 FD는 같은 Record 번호를 유지한다.
                fields = [
                    ("Container", id_display.get(view.container_id, "-")),
                    ("PID/TID", f"{view.tgid}/{view.tid}"),
                    ("FD", str(fd)),
                ]
                if output_view == "files":
                    # 상태에 별표가 있으면 해당 행의 일부 정보를 못 읽은 것이다.
                    # 임의로 경로를 자르지 않으며 details에서 그 사유를 확인한다.
                    state = facts.state + ("*" if issues else "")
                    fields.extend(
                        [
                            ("Access", facts.access),
                            ("State", state),
                            ("Path", displayed_path),
                        ]
                    )
                elif output_view == "hosts":
                    # 별칭 여러 개를 긴 셀 하나에 이어 붙이지 않고 각각 한 행으로.
                    fields.extend(
                        ("Host Path", _safe_text(alias))
                        for alias in facts.host_paths or ("-",)
                    )
                    fields.append(("Status", facts.host_status))
                else:
                    detail = (
                        "PARTIAL:" + ",".join(sorted(issues)) if issues else "COMPLETE"
                    )
                    fields.extend(
                        [
                            ("Process", comm),
                            ("Access", facts.access),
                            ("Type", facts.kind),
                            ("Name State", facts.state),
                            ("Path", displayed_path),
                        ]
                    )
                    fields.extend(
                        ("Host Path", _safe_text(alias))
                        for alias in facts.host_paths or ("-",)
                    )
                    fields.extend(
                        [
                            ("Path Status", path_status),
                            ("Host Path Status", facts.host_status),
                            ("Read Status", detail),
                            (
                                "Inode",
                                str(facts.inode_number)
                                if facts.inode_number is not None
                                else "-",
                            ),
                            (
                                "Link Count",
                                str(facts.nlink) if facts.nlink is not None else "-",
                            ),
                            (
                                "File Flags",
                                hex(facts.file_flags)
                                if facts.file_flags is not None
                                else "-",
                            ),
                            (
                                "File Mode",
                                hex(facts.raw_mode)
                                if facts.raw_mode is not None
                                else "-",
                            ),
                        ]
                    )
                    # 스레드 목록도 길게 합치지 않는다. 여러 TID가 같은 테이블을
                    # 공유할 때만 별도 행으로 나열한다.
                    if len(view.members) > 1:
                        fields.extend(
                            ("Shared TID", str(tid)) for tid in sorted(view.members)
                        )
                # 콘솔/JSON/CSV 모두 같은 구조를 사용하며 실제 값은 자르지 않는다.
                for label, value in fields:
                    yield 0, (counts["rows"], label, value)
        if counts["partial"]:
            vollog.warning(
                "%s/%s FDs have incomplete metadata (* in State); inspect --view details",
                counts["partial"],
                counts["rows"],
            )
        if not counts["rows"]:
            vollog.warning(
                "No matching readable FD rows; this does not prove there are no open/deleted files"
            )

    def run(self):
        self._options()
        output_view = self._selected_view()
        columns = [("Record", int), ("Field", str), ("Value", str)]
        return renderers.TreeGrid(columns, self._generator(output_view))

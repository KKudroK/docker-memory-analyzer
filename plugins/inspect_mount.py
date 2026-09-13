# SPDX-License-Identifier: MIT
# Copyright (c) 2026 container-mounts contributors
"""Container-aware mount analysis for Volatility 3 2.28.0.

The plugin deliberately separates three facts that are easy to conflate:

* a task lives in a non-host mount namespace;
* that namespace has evidence of being managed by a container runtime;
* a mount's source is visible at a particular path in the host namespace.

Only the second fact makes a namespace a default output candidate.  A host
source is reported as confirmed only when the mount root dentry can be mapped
through a host-namespace mount that references the same superblock.
"""

from dataclasses import dataclass
import logging
import re
from typing import Dict, Iterable, List, Optional, Sequence, Tuple

from volatility3.framework import exceptions, interfaces, renderers
from volatility3.framework.configuration import requirements
from volatility3.framework.interfaces import plugins
from volatility3.framework.objects import utility
from volatility3.framework.symbols import linux
from volatility3.plugins.linux import mountinfo, pslist


vollog = logging.getLogger(__name__)


RISK_HIGH = "HIGH"
RISK_REVIEW = "REVIEW"
RISK_INFRA = "INFRA"

DETECTION_HIGH = "HIGH"
DETECTION_MEDIUM = "MEDIUM"
DETECTION_LOW = "LOW"
DETECTION_MANUAL = "MANUAL"

SOURCE_CONFIRMED = "CONFIRMED"
SOURCE_AMBIGUOUS = "AMBIGUOUS"
SOURCE_UNKNOWN = "UNKNOWN"

_HEX64 = r"[0-9a-f]{64}"
_UUID = r"[0-9a-f]{8}(?:[-_][0-9a-f]{4}){3}[-_][0-9a-f]{12}"
_RUNTIME_ID = r"[A-Za-z0-9][A-Za-z0-9_.-]{2,127}"


@dataclass(frozen=True)
class Identity:
    runtime: str
    identifier: str
    id_kind: str
    evidence: str


@dataclass(frozen=True)
class CgroupMembership:
    """One task membership in a cgroup v1 or v2 hierarchy."""

    version: str
    controllers: Tuple[str, ...]
    path: str
    cgroup_address: int

    def display(self) -> str:
        owner = ",".join(self.controllers) if self.controllers else "unified"
        return f"{self.version}:{owner}={self.path}"


# Ordered from the most specific container ID patterns to broader pod/runtime
# identifiers.  No rule treats an arbitrary 64-hex path component as a
# container ID; it must occur in a runtime-specific path grammar.
IDENTITY_PATTERNS: Tuple[Tuple[re.Pattern, str, str, str], ...] = (
    (
        re.compile(rf"(?:^|/)docker-({_HEX64})\.scope(?:/|$)", re.IGNORECASE),
        "docker",
        "container",
        "docker-systemd-cgroup",
    ),
    (
        re.compile(rf"(?:^|/)docker/({_HEX64})(?:/|$)", re.IGNORECASE),
        "docker",
        "container",
        "docker-cgroupfs",
    ),
    (
        re.compile(
            rf"(?:^|/)cri-containerd-({_HEX64})\.scope(?:/|$)", re.IGNORECASE
        ),
        "containerd",
        "container",
        "containerd-systemd-cgroup",
    ),
    (
        re.compile(rf"(?:^|/)crio-({_HEX64})\.scope(?:/|$)", re.IGNORECASE),
        "cri-o",
        "container",
        "crio-systemd-cgroup",
    ),
    (
        re.compile(rf"(?:^|/)libpod-({_HEX64})\.scope(?:/|$)", re.IGNORECASE),
        "podman",
        "container",
        "podman-systemd-cgroup",
    ),
    (
        re.compile(
            rf"(?:^|/)(?:crio|cri-containerd)/({_HEX64})(?:/|$)", re.IGNORECASE
        ),
        "kubernetes",
        "container",
        "cri-cgroupfs",
    ),
    (
        re.compile(
            rf"(?:^|/)kubepods(?:/[^/]+)*/({_HEX64})(?:/|$)", re.IGNORECASE
        ),
        "kubernetes",
        "container",
        "kubernetes-cgroupfs-container",
    ),
    (
        re.compile(
            rf"(?:^|/)var/lib/docker/containers/({_HEX64})(?:/|$)",
            re.IGNORECASE,
        ),
        "docker",
        "container",
        "docker-storage",
    ),
    (
        re.compile(
            rf"(?:^|/)var/lib/docker/rootfs/overlayfs/({_HEX64})(?:/|$)",
            re.IGNORECASE,
        ),
        "docker",
        "container",
        "docker-rootfs-overlayfs",
    ),
    (
        re.compile(
            rf"(?:^|/)(?:var/lib|var/run)/containers/storage/"
            rf"overlay-containers/({_HEX64})(?:/|$)",
            re.IGNORECASE,
        ),
        "podman/cri-o",
        "container",
        "containers-storage",
    ),
    (
        re.compile(
            rf"(?:^|/)run/containerd/io\.containerd\.runtime\.v[12]\.task/"
            rf"[^/]+/({_RUNTIME_ID})(?:/|$)",
            re.IGNORECASE,
        ),
        "containerd",
        "container",
        "containerd-task-bundle",
    ),
    (
        re.compile(rf"(?:^|/)pod({_UUID})(?:\.slice|/|$)", re.IGNORECASE),
        "kubernetes",
        "pod",
        "kubernetes-pod-cgroup",
    ),
    (
        re.compile(
            rf"(?:^|/)var/lib/kubelet/pods/({_UUID})(?:/|$)", re.IGNORECASE
        ),
        "kubernetes",
        "pod",
        "kubelet-pod-storage",
    ),
)


# These processes remain as supervisors while the container task is alive.
# Short-lived launchers such as runc/crun and broad parents such as systemd or
# dockerd are intentionally absent: their presence alone is not container
# evidence.  Linux task comm is at most 15 visible bytes, so long signatures
# are compared with their explicit 15-byte truncation, never by reverse
# startswith matching.
RUNTIME_SUPERVISORS: Tuple[Tuple[str, str], ...] = (
    ("containerd-shim", "containerd"),
    ("conmon", "podman/cri-o"),
    ("lxc-start", "lxc"),
    ("lxc-monitord", "lxc"),
    ("systemd-nspawn", "nspawn"),
    ("runsc-sandbox", "gvisor"),
    ("kata-shim", "kata"),
)


CGROUP_RUNTIME_MARKERS: Tuple[Tuple[re.Pattern, str], ...] = (
    (re.compile(r"(?:^|/)docker(?:/|-)", re.IGNORECASE), "docker"),
    (re.compile(r"(?:^|/)cri-containerd(?:/|-)", re.IGNORECASE), "containerd"),
    (re.compile(r"(?:^|/)crio(?:/|-)", re.IGNORECASE), "cri-o"),
    (re.compile(r"(?:^|/)libpod(?:/|-)", re.IGNORECASE), "podman"),
    (re.compile(r"(?:^|/)kubepods(?:[./-]|$)", re.IGNORECASE), "kubernetes"),
    (re.compile(r"(?:^|/)lxc(?:[./-]|$)", re.IGNORECASE), "lxc"),
)


RUNTIME_STORAGE_PREFIXES: Tuple[str, ...] = (
    "/var/lib/docker/",
    "/var/lib/containers/",
    "/var/run/containers/",
    "/run/containerd/",
    "/run/docker/",
    "/var/lib/kubelet/",
    "/var/lib/rancher/",
)

RUNTIME_SOCKET_NAMES = frozenset(
    {
        "docker.sock",
        "containerd.sock",
        "crio.sock",
        "podman.sock",
        "dockershim.sock",
        "containerd-shim.sock",
    }
)

API_FSTYPES = frozenset(
    {
        "proc",
        "sysfs",
        "cgroup",
        "cgroup2",
        "devpts",
        "mqueue",
        "tmpfs",
        "devtmpfs",
        "nsfs",
        "securityfs",
        "debugfs",
        "tracefs",
        "bpf",
        "fusectl",
        "pstore",
        "configfs",
        "hugetlbfs",
        "ramfs",
        "binfmt_misc",
        "autofs",
        "efivarfs",
        "selinuxfs",
    }
)

SENSITIVE_HOST_PREFIXES: Tuple[str, ...] = (
    "/etc",
    "/root",
    "/home",
    "/boot",
    "/usr",
    "/bin",
    "/sbin",
    "/lib",
    "/lib64",
    "/var/log",
    "/var/run",
    "/run",
    "/dev",
    "/sys",
    "/proc",
    "/var/lib/docker",
    "/var/lib/kubelet",
    "/var/lib/containers",
    "/srv",
)

EXPECTED_RUNTIME_ARTIFACTS: Dict[str, Tuple[str, ...]] = {
    "/etc/hostname": ("hostname",),
    "/etc/hosts": ("hosts",),
    "/etc/resolv.conf": ("resolv.conf", "stub-resolv.conf"),
    "/dev/shm": ("shm",),
}

STANDARD_API_TARGETS: Dict[str, Tuple[str, ...]] = {
    "proc": ("/proc",),
    "sysfs": ("/sys",),
    "cgroup": ("/sys/fs/cgroup",),
    "cgroup2": ("/sys/fs/cgroup",),
    "devtmpfs": ("/dev",),
    "devpts": ("/dev/pts",),
    "mqueue": ("/dev/mqueue",),
}

INTERNAL_NAMESPACE_ROOT_FSTYPES = frozenset({"nullfs", "rootfs"})


def _clean_path(path: object) -> str:
    """Return a normalized absolute path or an empty string.

    Smeared/deleted paths are useful forensic strings but are not strong enough
    to certify a host source, so the host resolver rejects them separately.
    """

    if path is None:
        return ""
    value = str(path).strip()
    if not value or value == "none":
        return ""
    if value != "/":
        value = value.rstrip("/")
    return value


def _startswith_dir(path: str, prefix: str) -> bool:
    path = _clean_path(path)
    prefix = _clean_path(prefix)
    if not path or not prefix:
        return False
    return path == prefix or path.startswith(prefix + "/")


def _runtime_storage_path(path: str) -> bool:
    return any(_startswith_dir(path, prefix) for prefix in RUNTIME_STORAGE_PREFIXES)


def _usable_confirmed_path(path: str) -> bool:
    return bool(
        path
        and path.startswith("/")
        and "<potentially smeared>" not in path
        and "(deleted)" not in path
        and "//" not in path
    )


def _object_address(obj) -> int:
    """Return a pointer target or struct address without assuming its wrapper."""

    try:
        return int(obj)
    except (TypeError, ValueError):
        return int(obj.vol.offset)


def _dentry_under(dentry, ancestor_address: int, max_depth: int = 4096) -> bool:
    """Check dentry ancestry using normalized target addresses.

    Volatility 3 2.28.0's dentry.is_subdir accepts a pointer, but its internal
    comparisons alternate between treating that argument as an integer target
    and reading pointer.vol.offset (the pointer field's storage location).  A
    local walk avoids that ambiguity and adds cycle/depth guards for damaged
    memory images.
    """

    seen = set()
    current = dentry
    for _ in range(max_depth):
        try:
            address = _object_address(current)
            if address == ancestor_address:
                return True
            if address in seen:
                return False
            seen.add(address)

            parent = current.d_parent
            if not parent:
                return False
            parent_address = _object_address(parent)
            if parent_address == address:
                return False
            current = parent
        except (
            AttributeError,
            TypeError,
            ValueError,
            exceptions.InvalidAddressException,
        ):
            return False
    return False


def _identify_path(path: str) -> Optional[Identity]:
    value = _clean_path(path)
    if not value:
        return None
    for pattern, runtime, id_kind, evidence in IDENTITY_PATTERNS:
        match = pattern.search(value)
        if match:
            identifier = match.group(1).lower()
            if id_kind == "pod":
                identifier = identifier.replace("_", "-")
            return Identity(runtime, identifier, id_kind, evidence)
    return None


def _identify_paths(paths: Iterable[str]) -> Optional[Identity]:
    for path in paths:
        identity = _identify_path(path)
        if identity:
            return identity
    return None


def _runtime_marker(cgroup_path: str) -> str:
    for pattern, runtime in CGROUP_RUNTIME_MARKERS:
        if pattern.search(cgroup_path or ""):
            return runtime
    return ""


def _comm_matches(comm: str, signature: str) -> bool:
    if not comm:
        return False
    visible_signature = signature[:15]
    return comm == signature or comm == visible_signature


def _safe_namespace_inode(task, member: str) -> Optional[int]:
    try:
        namespace = task.nsproxy.member(member)
        if not namespace or not namespace.is_readable():
            return None
        if hasattr(namespace, "get_inode"):
            return int(namespace.get_inode())
        return int(namespace.ns.inum)
    except (AttributeError, TypeError, ValueError, exceptions.InvalidAddressException):
        return None


def _pid_namespace_values(task) -> Tuple[Optional[int], Optional[int]]:
    """Return (namespace inode, PID as seen in the innermost PID namespace)."""

    try:
        if task.has_member("thread_pid") and task.thread_pid:
            pid_pointer = task.thread_pid
        elif task.has_member("pids") and task.pids[0].pid:
            # Modern kernels commonly expose thread_pid(task) as a macro over
            # task->pids[PIDTYPE_PID].pid rather than a task_struct member.
            pid_pointer = task.pids[0].pid
        else:
            return None, None
        pid_object = pid_pointer.dereference()
        level = int(pid_object.level)
        # pid.numbers[] is a flexible-array member.  BTF/DWARF ISFs commonly
        # describe it with count 0 even though the dump contains level + 1
        # struct upid entries immediately after struct pid.  Recast it with
        # the runtime length before indexing the innermost namespace entry.
        if level < 0 or level > 32:
            return None, None
        numbers = pid_object.numbers.cast(
            "array",
            count=level + 1,
            subtype=pid_object.numbers.vol.subtype,
        )
        upid = numbers[level]
        ns_id = int(upid.ns.ns.inum)
        return ns_id, int(upid.nr)
    except (AttributeError, IndexError, TypeError, ValueError, exceptions.InvalidAddressException):
        return None, None


def _cgroup_path(cgroup) -> str:
    """Reconstruct a cgroup path from its kernfs node ancestry."""

    try:
        if (
            not cgroup
            or not cgroup.is_readable()
            or not cgroup.has_member("kn")
            or not cgroup.kn
            or not cgroup.kn.is_readable()
        ):
            return ""
        node = cgroup.kn.dereference()
    except (AttributeError, TypeError, ValueError, exceptions.InvalidAddressException):
        return ""

    parts: List[str] = []
    seen = set()
    for _ in range(256):
        try:
            address = int(node.vol.offset)
            if address in seen:
                break
            seen.add(address)
            name = utility.pointer_to_string(node.name, count=256)
            if name and name != "/":
                parts.append(name.strip("/"))
            parent = node.member("__parent")
            if not parent or not parent.is_readable():
                break
            node = parent.dereference()
        except (
            AttributeError,
            TypeError,
            exceptions.InvalidAddressException,
            ValueError,
        ):
            break
    return "/" + "/".join(reversed(parts)) if parts else "/"


def _cgroup_memberships(task) -> Tuple[CgroupMembership, ...]:
    """Collect cgroup v2, v1, or hybrid memberships from task->css_set.

    v2 stores the task's unified-hierarchy cgroup in css_set.dfl_cgrp.  v1
    stores one cgroup_subsys_state pointer per controller in css_set.subsys[].
    Controllers mounted on the same v1 hierarchy point at the same cgroup, so
    they are grouped by cgroup target address instead of emitted repeatedly.
    """

    try:
        css_set = task.cgroups
        if not css_set or not css_set.is_readable():
            return ()
    except (AttributeError, exceptions.InvalidAddressException):
        return ()

    unified: Optional[CgroupMembership] = None
    unified_address: Optional[int] = None
    try:
        if css_set.has_member("dfl_cgrp"):
            cgroup = css_set.dfl_cgrp
            path = _cgroup_path(cgroup)
            if path:
                unified_address = _object_address(cgroup)
                unified = CgroupMembership(
                    version="v2",
                    controllers=(),
                    path=path,
                    cgroup_address=unified_address,
                )
    except (
        AttributeError,
        TypeError,
        ValueError,
        exceptions.InvalidAddressException,
    ):
        unified = None
        unified_address = None

    legacy: Dict[int, Dict[str, object]] = {}
    try:
        subsystems = css_set.subsys if css_set.has_member("subsys") else ()
        subsystem_count = len(subsystems)
    except (AttributeError, TypeError, exceptions.InvalidAddressException):
        subsystems = ()
        subsystem_count = 0

    for index in range(subsystem_count):
        try:
            css_pointer = subsystems[index]
            if not css_pointer or not css_pointer.is_readable():
                continue
            css = css_pointer.dereference()
            if not css.has_member("cgroup") or not css.cgroup:
                continue
            cgroup = css.cgroup
            if not cgroup.is_readable():
                continue
            cgroup_address = _object_address(cgroup)
            if unified_address is not None and cgroup_address == unified_address:
                continue
            path = _cgroup_path(cgroup)
            if not path:
                continue

            controller = ""
            if css.has_member("ss") and css.ss and css.ss.is_readable():
                subsystem = css.ss.dereference()
                if subsystem.has_member("name") and subsystem.name:
                    controller = utility.pointer_to_string(subsystem.name, count=64)
            controller = controller.strip() if controller else f"subsys-{index}"

            entry = legacy.setdefault(
                cgroup_address,
                {"path": path, "controllers": set()},
            )
            entry["controllers"].add(controller)
        except (
            AttributeError,
            IndexError,
            TypeError,
            ValueError,
            exceptions.InvalidAddressException,
        ):
            continue

    memberships: List[CgroupMembership] = []
    # On a legacy-only host dfl_cgrp may still point at the unused v2 root.
    # A bare v2 root carries no runtime evidence, so omit it when real v1
    # memberships exist.  In a hybrid setup a non-root v2 path is retained.
    if unified and (unified.path != "/" or not legacy):
        memberships.append(unified)
    for address, entry in sorted(legacy.items()):
        memberships.append(
            CgroupMembership(
                version="v1",
                controllers=tuple(sorted(entry["controllers"])),
                path=str(entry["path"]),
                cgroup_address=address,
            )
        )
    return tuple(memberships)


def _cgroup_identity(
    memberships: Sequence[CgroupMembership],
) -> Tuple[Optional[Identity], str, bool]:
    """Choose a cgroup identity while refusing conflicting container IDs."""

    found = []
    for membership in memberships:
        identity = _identify_path(membership.path)
        if identity:
            found.append((membership, identity))

    container_ids = {
        identity.identifier
        for _membership, identity in found
        if identity.id_kind == "container"
    }
    if len(container_ids) > 1:
        return None, "", True

    for id_kind in ("container", "pod"):
        candidates = [item for item in found if item[1].id_kind == id_kind]
        if candidates:
            # A non-root v2 membership is the strongest source when both
            # hierarchies contain the same identity; otherwise use v1.
            candidates.sort(
                key=lambda item: (
                    0 if item[0].version == "v2" else 1,
                    item[0].display(),
                )
            )
            membership, identity = candidates[0]
            owner = ",".join(membership.controllers) or "unified"
            return identity, f"{membership.version}:{owner}", False
    return None, "", False


def _runtime_from_ancestry(task, max_depth: int = 8) -> Tuple[str, str]:
    seen = set()
    current = task
    for _ in range(max_depth):
        try:
            if not current:
                break
            address = int(current.vol.offset)
            if address in seen:
                break
            seen.add(address)
            comm = utility.array_to_string(current.comm)
        except (AttributeError, exceptions.InvalidAddressException):
            break

        for signature, runtime in RUNTIME_SUPERVISORS:
            if _comm_matches(comm, signature):
                return runtime, comm

        try:
            parent = current.real_parent if current.has_member("real_parent") else current.parent
            if not parent or not parent.is_readable():
                break
            current = parent
        except (AttributeError, exceptions.InvalidAddressException):
            break
    return "", ""


@dataclass
class TaskObservation:
    pid: int
    task: object
    mnt_ns: object
    mnt_ns_id: int
    pid_ns_id: Optional[int]
    ns_pid: Optional[int]
    root_key: Tuple[int, int]
    cgroup_memberships: Tuple[CgroupMembership, ...]
    identity: Optional[Identity]
    runtime: str
    evidence: Tuple[str, ...]
    score: int


@dataclass(frozen=True)
class SourceResolution:
    paths: Tuple[str, ...]
    confidence: str


@dataclass
class MountRecord:
    mnt: object
    data: object
    container_path: str
    mount_root: str
    host_sources: Tuple[str, ...]
    source_confidence: str
    writable: bool


class HostMountResolver:
    """Resolve mount-root dentries only through mounts visible to init_task."""

    def __init__(self, init_task):
        self._init_task = init_task
        self._host_root_dentry = init_task.fs.get_root_dentry()
        self._host_root_mnt = init_task.fs.get_root_mnt()
        self._by_superblock: Dict[int, List[object]] = {}

        host_namespace = init_task.nsproxy.mnt_ns
        try:
            for host_mnt in host_namespace.get_mount_points():
                try:
                    superblock = host_mnt.get_mnt_sb()
                    if superblock and superblock.is_readable():
                        self._by_superblock.setdefault(
                            _object_address(superblock), []
                        ).append(host_mnt)
                except (AttributeError, exceptions.InvalidAddressException):
                    continue
        except (
            AttributeError,
            exceptions.InvalidAddressException,
            exceptions.VolatilityException,
        ) as exc:
            vollog.warning("Host mount namespace index is incomplete: %s", exc)

    def resolve(self, mnt) -> SourceResolution:
        try:
            superblock = mnt.get_mnt_sb()
            source_dentry = mnt.get_mnt_root()
            if not (
                superblock
                and superblock.is_readable()
                and source_dentry
                and source_dentry.is_readable()
            ):
                return SourceResolution((), SOURCE_UNKNOWN)
            host_mounts = self._by_superblock.get(_object_address(superblock), ())
        except (AttributeError, exceptions.InvalidAddressException):
            return SourceResolution((), SOURCE_UNKNOWN)

        resolved = set()
        for host_mnt in host_mounts:
            try:
                host_mount_root = host_mnt.get_mnt_root()
                if not (
                    host_mount_root
                    and host_mount_root.is_readable()
                ):
                    continue
                host_root_address = _object_address(host_mount_root)
                if not _dentry_under(source_dentry, host_root_address):
                    continue
                path = linux.LinuxUtilities.do_get_path(
                    self._host_root_dentry,
                    self._host_root_mnt,
                    source_dentry,
                    host_mnt.get_vfsmnt_current(),
                )
                path = _clean_path(path)
                if _usable_confirmed_path(path):
                    resolved.add(path)
            except (
                AttributeError,
                TypeError,
                ValueError,
                exceptions.InvalidAddressException,
                exceptions.VolatilityException,
            ):
                continue

        paths = tuple(sorted(resolved))
        if not paths:
            return SourceResolution((), SOURCE_UNKNOWN)
        if len(paths) == 1:
            return SourceResolution(paths, SOURCE_CONFIRMED)
        return SourceResolution(paths, SOURCE_AMBIGUOUS)


def _mount_access(data) -> Tuple[bool, str]:
    mount_options = {str(value) for value in (data.mnt_opts or ())}
    superblock_options = {str(value) for value in (data.sb_opts or ())}
    writable = "ro" not in mount_options and "ro" not in superblock_options
    return writable, "rw" if writable else "ro"


def _expected_runtime_artifact(
    container_path: str,
    host_path: str,
    runtime: str,
    container_id: str,
    id_kind: str,
) -> bool:
    expected_names = EXPECTED_RUNTIME_ARTIFACTS.get(container_path, ())
    basename = host_path.rsplit("/", 1)[-1]
    if basename in expected_names:
        return True
    if container_path != "/":
        return False

    # Common runtime layouts end their root mount in one of these names.
    if basename in {"merged", "rootfs", "fs"}:
        return True

    # Some Docker versions expose the container root as
    # /var/lib/docker/rootfs/overlayfs/<container-id>.  Do not whitelist an
    # arbitrary runtime-storage child: require the exact Docker path grammar
    # and correlation with the namespace identity selected from cgroup/mount
    # evidence.
    identity = _identify_path(host_path)
    return bool(
        runtime == "docker"
        and id_kind == "container"
        and container_id
        and identity
        and identity.runtime == "docker"
        and identity.id_kind == "container"
        and identity.identifier == container_id.lower()
        and identity.evidence == "docker-rootfs-overlayfs"
    )


def _classify_mount(
    record: MountRecord,
    runtime: str,
    container_id: str = "",
    id_kind: str = "",
) -> Tuple[str, str]:
    """Classify one mount without promoting an unproven path to host source."""

    container_path = record.container_path
    fstype = str(record.data.mnt_type)
    access = "쓰기 가능" if record.writable else "읽기 전용"
    source_names = {path.rsplit("/", 1)[-1] for path in record.host_sources}
    target_name = container_path.rsplit("/", 1)[-1]

    if (
        int(record.data.mnt_id) == int(record.data.parent_id)
        and fstype in INTERNAL_NAMESPACE_ROOT_FSTYPES
    ):
        return RISK_INFRA, "Mount Namespace 내부 root/sentinel mount"

    if target_name in RUNTIME_SOCKET_NAMES or source_names & RUNTIME_SOCKET_NAMES:
        return RISK_HIGH, "컨테이너에 런타임 제어 소켓이 노출됨"

    if record.host_sources:
        runtime_sources = [
            path for path in record.host_sources if _runtime_storage_path(path)
        ]
        if runtime_sources and all(
            _expected_runtime_artifact(
                container_path, path, runtime, container_id, id_kind
            )
            for path in runtime_sources
        ):
            return RISK_INFRA, "런타임이 생성한 표준 컨테이너 마운트"

        if container_path in STANDARD_API_TARGETS.get(fstype, ()):
            if (
                fstype in {"sysfs", "cgroup", "cgroup2"}
                and record.writable
                and record.host_sources
            ):
                return RISK_HIGH, f"호스트 커널 제어 파일시스템이 쓰기 가능하게 노출됨 ({fstype})"
            return RISK_INFRA, f"표준 컨테이너 {fstype} 마운트"

        if "/" in record.host_sources:
            return RISK_HIGH, f"호스트 루트가 컨테이너에 노출됨 ({access})"

        # Named volumes and runtime-managed user data are important inspection
        # results, but their location below /var/lib/docker or equivalent does
        # not by itself make them a host-escape finding.
        if runtime_sources:
            return RISK_REVIEW, f"런타임 저장소의 비표준/사용자 데이터 마운트 ({access})"

        for host_path in record.host_sources:
            for prefix in SENSITIVE_HOST_PREFIXES:
                if _startswith_dir(host_path, prefix):
                    return RISK_HIGH, f"민감 호스트 경로 {prefix} 노출 ({access})"

        return RISK_REVIEW, f"확인된 호스트 경로 마운트 ({access})"

    # A container root on overlay is expected, but only after the namespace has
    # independently passed container detection.  It is not called a host root.
    if runtime and container_path == "/" and fstype in {"overlay", "fuse-overlayfs"}:
        return RISK_INFRA, "컨테이너 루트 파일시스템"

    if fstype in API_FSTYPES:
        return RISK_INFRA, "커널/메모리 기반 가상 파일시스템; 호스트 디스크 source 미확인"

    return RISK_REVIEW, "호스트 source를 증명하지 못한 비가상 파일시스템 마운트"


class ContainerMounts(plugins.PluginInterface):
    """Find container-backed mount namespaces and inspect their mounts."""

    _required_framework_version = (2, 13, 0)
    _version = (0, 3, 1)

    @classmethod
    def get_requirements(cls) -> List[interfaces.configuration.RequirementInterface]:
        return [
            requirements.ModuleRequirement(
                name="kernel",
                description="Linux kernel",
                architectures=["Intel32", "Intel64"],
            ),
            requirements.VersionRequirement(
                name="pslist", component=pslist.PsList, version=(4, 0, 0)
            ),
            requirements.VersionRequirement(
                name="mountinfo", component=mountinfo.MountInfo, version=(1, 2, 4)
            ),
            requirements.VersionRequirement(
                name="linuxutils", component=linux.LinuxUtilities, version=(2, 1, 0)
            ),
            requirements.ListRequirement(
                name="pids",
                description="Inspect these host PIDs explicitly (manual trust override)",
                element_type=int,
                optional=True,
            ),
            requirements.BooleanRequirement(
                name="include-candidates",
                description="Also show low-confidence non-host mount namespaces",
                optional=True,
                default=False,
            ),
            requirements.BooleanRequirement(
                name="all-mounts",
                description="Include expected infrastructure mounts",
                optional=True,
                default=False,
            ),
            requirements.BooleanRequirement(
                name="extended",
                description="Add cgroup v1/v2, evidence and raw mountinfo columns",
                optional=True,
                default=False,
            ),
        ]

    @staticmethod
    def _observe_task(task) -> Optional[TaskObservation]:
        try:
            if not (
                task
                and task.fs
                and task.fs.is_readable()
                and task.nsproxy
                and task.nsproxy.is_readable()
                and task.nsproxy.mnt_ns
                and task.nsproxy.mnt_ns.is_readable()
            ):
                return None
            pid = int(task.pid)
            mnt_ns = task.nsproxy.mnt_ns
            mnt_ns_id = int(mnt_ns.get_inode())
            root_key = (
                _object_address(task.fs.get_root_mnt()),
                _object_address(task.fs.get_root_dentry()),
            )
        except (
            AttributeError,
            TypeError,
            ValueError,
            exceptions.InvalidAddressException,
        ):
            return None

        cgroup_memberships = _cgroup_memberships(task)
        identity, identity_source, identity_conflict = _cgroup_identity(
            cgroup_memberships
        )
        marker_matches = [
            (membership, _runtime_marker(membership.path))
            for membership in cgroup_memberships
        ]
        marker_matches = [item for item in marker_matches if item[1]]
        marker_matches.sort(
            key=lambda item: (
                0 if item[0].version == "v2" else 1,
                item[0].display(),
            )
        )
        marker_runtime = marker_matches[0][1] if marker_matches else ""
        ancestry_runtime, supervisor_comm = _runtime_from_ancestry(task)
        pid_ns_id, ns_pid = _pid_namespace_values(task)

        evidence: List[str] = []
        score = 0
        if identity_conflict:
            score = 60
            evidence.append("cgroup-id-conflict")
        elif identity:
            score = 100 if identity.id_kind == "container" else 90
            evidence.append(f"cgroup:{identity_source}:{identity.evidence}")
        elif marker_runtime:
            score = 60
            evidence.append(f"cgroup-marker:{marker_runtime}")

        if ancestry_runtime:
            score = max(score, 70)
            evidence.append(f"supervisor:{supervisor_comm}")
        if ns_pid == 1:
            evidence.append("pid-namespace-init")

        runtime = (
            identity.runtime if identity else marker_runtime or ancestry_runtime
        )
        return TaskObservation(
            pid=pid,
            task=task,
            mnt_ns=mnt_ns,
            mnt_ns_id=mnt_ns_id,
            pid_ns_id=pid_ns_id,
            ns_pid=ns_pid,
            root_key=root_key,
            cgroup_memberships=cgroup_memberships,
            identity=identity,
            runtime=runtime,
            evidence=tuple(evidence),
            score=score,
        )

    def _collect_namespaces(
        self, tasks: Sequence[object], init_task
    ) -> Dict[int, List[TaskObservation]]:
        wanted = {int(pid) for pid in (self.config.get("pids") or ())}
        host_ns_id = _safe_namespace_inode(init_task, "mnt_ns")
        namespaces: Dict[int, List[TaskObservation]] = {}
        found_pids = set()

        for task in tasks:
            observation = self._observe_task(task)
            if observation is None:
                continue
            if wanted:
                if observation.pid not in wanted:
                    continue
                found_pids.add(observation.pid)
            elif host_ns_id is not None and observation.mnt_ns_id == host_ns_id:
                continue
            namespaces.setdefault(observation.mnt_ns_id, []).append(observation)

        missing = wanted - found_pids
        if missing:
            vollog.warning("Requested PIDs were not found/readable: %s", sorted(missing))
        if host_ns_id is None and not wanted:
            vollog.warning(
                "Host mount namespace inode is unavailable; LOW candidates remain hidden "
                "unless --include-candidates is used"
            )
        return namespaces

    @staticmethod
    def _representative(observations: Sequence[TaskObservation]) -> TaskObservation:
        # Runtime evidence dominates, then namespace PID 1, then the lowest host
        # PID.  This is more stable than selecting the lowest host PID alone.
        return sorted(
            observations,
            key=lambda item: (
                -item.score,
                0 if item.ns_pid == 1 else 1,
                item.pid,
            ),
        )[0]

    @staticmethod
    def _mount_points(mnt_ns) -> Tuple[List[object], str]:
        """Collect namespace mounts without losing every sibling to one bad RB node.

        Volatility 3's upstream extension recursively walks the kernel >= 6.8
        RB tree.  An unreadable node raises out of the generator and discards
        the rest of the walk.  The iterative guard below uses the same
        LinuxUtilities.container_of primitive but records skipped nodes and
        continues with every child pointer that was readable.
        """

        points: List[object] = []
        skipped_nodes = 0
        try:
            is_rb_tree = (
                mnt_ns.has_member("mounts")
                and str(mnt_ns.mounts.vol.type_name).endswith("!rb_root")
            )
        except (AttributeError, exceptions.InvalidAddressException):
            is_rb_tree = False

        if not is_rb_tree:
            try:
                for mnt in mnt_ns.get_mount_points():
                    points.append(mnt)
                return points, "COMPLETE"
            except (
                AttributeError,
                TypeError,
                ValueError,
                exceptions.InvalidAddressException,
                exceptions.VolatilityException,
            ) as exc:
                return points, f"PARTIAL:list-walk:{type(exc).__name__}"

        try:
            vmlinux = linux.LinuxUtilities.get_module_from_volobj_type(
                mnt_ns._context, mnt_ns
            )
            stack = [mnt_ns.mounts.rb_node]
        except (AttributeError, exceptions.InvalidAddressException) as exc:
            return points, f"PARTIAL:rb-root:{type(exc).__name__}"

        seen_nodes = set()
        while stack:
            node_pointer = stack.pop()
            try:
                node_address = int(node_pointer)
                if not node_address or node_address in seen_nodes:
                    continue
                seen_nodes.add(node_address)
                if not node_pointer.is_readable():
                    skipped_nodes += 1
                    continue
                node = node_pointer.dereference()

                # Read child pointers before decoding the containing mount so a
                # bad mount object cannot hide otherwise readable subtrees.
                left = node.rb_left
                right = node.rb_right
                if right:
                    stack.append(right)
                if left:
                    stack.append(left)

                mnt = linux.LinuxUtilities.container_of(
                    node_pointer, "mount", "mnt_node", vmlinux
                )
                points.append(mnt)
            except (
                AttributeError,
                TypeError,
                ValueError,
                exceptions.InvalidAddressException,
                exceptions.VolatilityException,
            ):
                skipped_nodes += 1
                continue

        status = "COMPLETE" if skipped_nodes == 0 else f"PARTIAL:rb-nodes={skipped_nodes}"
        return points, status

    @classmethod
    def _collect_mounts(
        cls, representative: TaskObservation, resolver: HostMountResolver
    ) -> Tuple[List[MountRecord], str]:
        records: List[MountRecord] = []
        mounts, traversal_status = cls._mount_points(representative.mnt_ns)
        decode_errors = 0
        seen_mounts = set()
        for mnt in mounts:
            try:
                mount_address = _object_address(mnt)
                if mount_address in seen_mounts:
                    continue
                seen_mounts.add(mount_address)
                data = mountinfo.MountInfo.get_mountinfo(mnt, representative.task)
                if data is None:
                    decode_errors += 1
                    continue

                is_internal_root = (
                    int(data.mnt_id) == int(data.parent_id)
                    and str(data.mnt_type) in INTERNAL_NAMESPACE_ROOT_FSTYPES
                )
                source = (
                    SourceResolution((), SOURCE_UNKNOWN)
                    if is_internal_root
                    else resolver.resolve(mnt)
                )
                writable, _ = _mount_access(data)
                records.append(
                    MountRecord(
                        mnt=mnt,
                        data=data,
                        container_path=_clean_path(data.path_root),
                        mount_root=_clean_path(data.mnt_root_path),
                        host_sources=source.paths,
                        source_confidence=source.confidence,
                        writable=writable,
                    )
                )
            except (
                AttributeError,
                TypeError,
                ValueError,
                exceptions.InvalidAddressException,
                exceptions.VolatilityException,
            ):
                decode_errors += 1
                continue

        if decode_errors:
            suffix = f"decode={decode_errors}"
            if traversal_status == "COMPLETE":
                traversal_status = f"PARTIAL:{suffix}"
            else:
                traversal_status = f"{traversal_status},{suffix}"
        return records, traversal_status

    @staticmethod
    def _mount_identity(records: Sequence[MountRecord]) -> Optional[Identity]:
        # Confirmed host-visible paths have priority.  Mount ROOT and devname
        # are fallbacks and can enrich identity, but never certify Host Source.
        confirmed_paths = [path for record in records for path in record.host_sources]
        identity = _identify_paths(confirmed_paths)
        if identity:
            return identity

        fallback_paths = []
        for record in records:
            if _runtime_storage_path(record.mount_root):
                fallback_paths.append(record.mount_root)
            devname = _clean_path(record.data.devname)
            if _runtime_storage_path(devname):
                fallback_paths.append(devname)
        return _identify_paths(fallback_paths)

    @staticmethod
    def _namespace_identity(
        observations: Sequence[TaskObservation], mount_identity: Optional[Identity]
    ) -> Optional[Identity]:
        identities = [item.identity for item in observations if item.identity]
        # A container ID is more useful than a pod ID.  Cgroup evidence remains
        # preferred over mount-path fallback within the same kind.
        for id_kind in ("container", "pod"):
            for identity in identities:
                if identity.id_kind == id_kind:
                    return identity
            if mount_identity and mount_identity.id_kind == id_kind:
                return mount_identity
        return mount_identity

    def _namespace_metadata(
        self,
        observations: Sequence[TaskObservation],
        mount_identity: Optional[Identity],
        manual: bool,
    ) -> Tuple[str, str, str, str, str, int]:
        representative = self._representative(observations)
        identity = self._namespace_identity(observations, mount_identity)
        score = max(item.score for item in observations)
        evidence = {value for item in observations for value in item.evidence}

        if mount_identity:
            score = max(score, 70)
            evidence.add(f"mount-path:{mount_identity.evidence}")

        if manual:
            detection = DETECTION_MANUAL
            evidence.add("explicit-pid-selection")
        elif score >= 90:
            detection = DETECTION_HIGH
        elif score >= 60:
            detection = DETECTION_MEDIUM
        else:
            detection = DETECTION_LOW
            evidence.add("mount-namespace-only")

        runtime = identity.runtime if identity else representative.runtime
        identifier = identity.identifier if identity else ""
        id_kind = identity.id_kind if identity else ""
        return (
            detection,
            runtime,
            identifier,
            id_kind,
            ";".join(sorted(evidence)),
            score,
        )

    def _generator(self, extended: bool):
        vmlinux = self.context.modules[self.config["kernel"]]
        init_task = vmlinux.object_from_symbol("init_task")
        tasks = list(pslist.PsList.list_tasks(self.context, self.config["kernel"]))
        namespaces = self._collect_namespaces(tasks, init_task)
        resolver = HostMountResolver(init_task)

        manual = bool(self.config.get("pids"))
        include_candidates = bool(self.config.get("include-candidates", False))
        show_all = bool(self.config.get("all-mounts", False))

        for ns_id, observations in sorted(namespaces.items()):
            representative = self._representative(observations)
            records, traversal_status = self._collect_mounts(representative, resolver)
            mount_identity = self._mount_identity(records)
            (
                detection,
                runtime,
                container_id,
                id_kind,
                evidence,
                _score,
            ) = self._namespace_metadata(observations, mount_identity, manual)

            if detection == DETECTION_LOW and not include_candidates:
                continue

            root_variants = len({item.root_key for item in observations})
            cgroup_memberships = sorted(
                {
                    membership.display()
                    for item in observations
                    for membership in item.cgroup_memberships
                }
            )
            cgroup_text = " | ".join(cgroup_memberships)

            for record in records:
                risk, reason = _classify_mount(
                    record, runtime, container_id, id_kind
                )
                if risk == RISK_INFRA and not show_all:
                    continue

                _, access = _mount_access(record.data)
                host_source = " | ".join(record.host_sources)
                base_row = (
                    representative.pid,
                    int(ns_id),
                    detection,
                    traversal_status,
                    runtime or "-",
                    container_id or "-",
                    record.container_path or "-",
                    host_source or "-",
                    record.source_confidence,
                    str(record.data.mnt_type),
                    access,
                    risk,
                    reason,
                )
                if extended:
                    row = base_row + (
                        representative.ns_pid
                        if representative.ns_pid is not None
                        else -1,
                        representative.pid_ns_id
                        if representative.pid_ns_id is not None
                        else -1,
                        cgroup_text or "-",
                        evidence or "-",
                        id_kind or "-",
                        root_variants,
                        int(record.data.mnt_id),
                        int(record.data.parent_id),
                        str(record.data.st_dev),
                        str(record.data.devname),
                        record.mount_root or "-",
                        ",".join(str(value) for value in record.data.mnt_opts),
                        " ".join(str(value) for value in record.data.fields),
                        ",".join(str(value) for value in record.data.sb_opts),
                    )
                else:
                    row = base_row
                yield 0, row

    def run(self):
        columns = [
            ("PID", int),
            ("MNT NS", int),
            ("Detection", str),
            ("Traversal", str),
            ("Runtime", str),
            ("Container ID", str),
            ("Container Path", str),
            ("Host Source", str),
            ("Source Confidence", str),
            ("FS Type", str),
            ("Access", str),
            ("Risk", str),
            ("Reason", str),
        ]
        extended = bool(self.config.get("extended", False))
        if extended:
            columns.extend(
                [
                    ("NS PID", int),
                    ("PID NS", int),
                    ("Cgroups", str),
                    ("Detection Evidence", str),
                    ("ID Kind", str),
                    ("FS Root Variants", int),
                    ("Mount ID", int),
                    ("Parent ID", int),
                    ("Device", str),
                    ("Devname", str),
                    ("Mount Root", str),
                    ("Mount Options", str),
                    ("Propagation", str),
                    ("Superblock Options", str),
                ]
            )
        return renderers.TreeGrid(columns, self._generator(extended))

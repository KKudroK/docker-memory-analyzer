# SPDX-License-Identifier: MIT
# Copyright (c) 2026 container-mounts contributors
"""Read container mount views with Volatility 3 2.28.0.

Automatic selection uses recognized task cgroup membership or a supported
runtime supervisor.  Explicit host PIDs bypass that selection.  Every decoded
mount of a selected view is returned, without risk policy, scores or path filters.
Container identity comes from task membership, not from files mounted into it.
Host paths describe aliases in the captured host topology, not the original
mount command.  Read failures and multiple aliases are preserved explicitly.
"""

from __future__ import annotations

import dataclasses
import json
import logging
import re
from collections.abc import Sequence

from volatility3.framework import exceptions, interfaces
from volatility3.framework.configuration import requirements
from volatility3.framework.interfaces import plugins
from volatility3.framework.objects import utility
from volatility3.framework.symbols import linux
from volatility3.plugins.linux import _vertical, docker_artifacts, mountinfo, pslist
from volatility3.plugins.linux._artifacts import cgroups as cgroup_readers
from volatility3.plugins.linux._artifacts import core as artifact_core
from volatility3.plugins.linux._artifacts import mounts as mount_readers
from volatility3.plugins.linux._artifacts import namespaces as namespace_readers
from volatility3.plugins.linux._artifacts import paths as path_readers

vollog = logging.getLogger(__name__)


# These states describe recovery, not risk or a probability of correctness.
PATH_SINGLE = "SINGLE"
PATH_MULTIPLE = "MULTIPLE"
PATH_UNRESOLVED = "UNRESOLVED"
PATH_PARTIAL = "PARTIAL"

_HEX64 = r"[0-9a-f]{64}"
_UUID = r"[0-9a-f]{8}(?:[-_][0-9a-f]{4}){3}[-_][0-9a-f]{12}"


@dataclasses.dataclass(frozen=True)
class Identity:
    runtime: str
    identifier: str
    id_kind: str
    evidence: str


# Parse only task cgroup naming conventions here.  A mounted runtime storage
# directory is not evidence that its ID owns the task inspecting that mount.
IDENTITY_PATTERNS: tuple[tuple[re.Pattern, str, str, str], ...] = (
    (
        re.compile(rf"(?:^|/)docker-({_HEX64})\.scope(?=/|$)", re.IGNORECASE),
        "docker",
        "container",
        "docker-systemd-cgroup",
    ),
    (
        re.compile(rf"(?:^|/)docker/({_HEX64})(?=/|$)", re.IGNORECASE),
        "docker",
        "container",
        "docker-cgroupfs",
    ),
    (
        re.compile(rf"(?:^|/)cri-containerd-({_HEX64})\.scope(?=/|$)", re.IGNORECASE),
        "containerd",
        "container",
        "containerd-systemd-cgroup",
    ),
    (
        re.compile(rf"(?:^|/)crio-({_HEX64})\.scope(?=/|$)", re.IGNORECASE),
        "cri-o",
        "container",
        "crio-systemd-cgroup",
    ),
    (
        re.compile(rf"(?:^|/)libpod-({_HEX64})\.scope(?=/|$)", re.IGNORECASE),
        "podman",
        "container",
        "podman-systemd-cgroup",
    ),
    (
        re.compile(rf"(?:^|/)(?:crio|cri-containerd)/({_HEX64})(?=/|$)", re.IGNORECASE),
        "kubernetes",
        "container",
        "cri-cgroupfs",
    ),
    (
        re.compile(
            rf"(?:^|/)kubepods(?:/(?:burstable|besteffort))?/pod{_UUID}/({_HEX64})(?=/|$)",
            re.IGNORECASE,
        ),
        "kubernetes",
        "container",
        "kubernetes-cgroupfs-container",
    ),
    (
        re.compile(
            rf"(?:^|/)(?:kubepods(?:-[^/]+)*-)?pod({_UUID})(?:\.slice)?(?=/|$)",
            re.IGNORECASE,
        ),
        "kubernetes",
        "pod",
        "kubernetes-pod-cgroup",
    ),
)


# These names can identify a runtime supervisor in a task ancestry chain.
# Short-lived launchers such as runc/crun and broad parents such as systemd or
# dockerd are intentionally absent: their presence alone is not container
# evidence.  Linux task comm is at most 15 visible bytes, so long signatures
# are compared with their explicit 15-byte truncation, never by reverse
# startswith matching.
RUNTIME_SUPERVISORS: tuple[tuple[str, str], ...] = (
    ("containerd-shim", "containerd"),
    ("conmon", "podman/cri-o"),
    ("lxc-start", "lxc"),
    ("lxc-monitord", "lxc"),
    ("systemd-nspawn", "nspawn"),
    ("runsc-sandbox", "gvisor"),
    ("kata-shim", "kata"),
)


def _read_dentry_name(dentry):
    return path_readers.read_dentry_name(dentry, policy=path_readers.MOUNT_PATH)


def _walk_mount_path(
    root_dentry,
    root_vfsmnt,
    dentry,
    vfsmnt,
    *,
    max_depth=4096,
    covering_mounts=None,
    require_live_inode=True,
    diagnostics=None,
):
    return path_readers.walk_mount_path(
        root_dentry,
        root_vfsmnt,
        dentry,
        vfsmnt,
        max_depth=max_depth,
        covering_mounts=covering_mounts,
        require_live_inode=require_live_inode,
        policy=path_readers.MOUNT_PATH,
        diagnostics=diagnostics,
    )


INTERNAL_NAMESPACE_ROOT_FSTYPES = frozenset({"nullfs", "rootfs"})


def _read_mount_devname(mnt) -> str:
    """Read the entire source label, not upstream's 255-byte prefix."""
    pointer = mnt.mnt_devname
    if not pointer:
        return "none"
    return artifact_core._read_kernel_cstring(pointer, allow_empty=True) or "none"


def _path_identities(path: str) -> tuple[Identity, ...]:
    """Parse every supported ID; nested scopes must not select the first owner."""
    value = str(path) if path else ""
    if not value:
        return ()
    found = []
    for pattern, runtime, id_kind, evidence in IDENTITY_PATTERNS:
        for match in pattern.finditer(value):
            identifier = match.group(1).lower()
            if id_kind == "pod":
                identifier = identifier.replace("_", "-")
            identity = Identity(runtime, identifier, id_kind, evidence)
            if identity not in found:
                found.append(identity)
    return tuple(found)


def _comm_matches(comm: str, signature: str) -> bool:
    if not comm:
        return False
    visible_signature = signature[:15]
    return comm == signature or comm == visible_signature


def _cgroup_identity(
    memberships: Sequence[cgroup_readers.CgroupMembership],
) -> tuple[Identity | None, str, bool]:
    """Choose a cgroup identity while refusing conflicting container IDs."""

    found = []
    for membership in memberships:
        for identity in _path_identities(membership.path):
            found.append((membership, identity))

    # Do not resolve a conflict by order of controllers or by preferring v2.
    for kind in ("container", "pod"):
        identifiers = {item.identifier for _, item in found if item.id_kind == kind}
        if len(identifiers) > 1:
            return None, "", True

    for id_kind in ("container", "pod"):
        candidates = [item for item in found if item[1].id_kind == id_kind]
        if candidates:
            # Identical IDs may occur in several hierarchies.  Pick a stable
            # description; this is not a confidence score.
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


def _runtime_from_ancestry(task, max_depth: int = 8) -> tuple[str, str]:
    seen = set()
    current = task
    for _ in range(max_depth):
        try:
            if not current:
                break
            address = artifact_core._object_address(current)
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
            parent = (
                current.real_parent
                if current.has_member("real_parent")
                else current.parent
            )
            if not parent or not artifact_core._object_readable(parent):
                break
            current = parent
        except (AttributeError, exceptions.InvalidAddressException):
            break
    return "", ""


@dataclasses.dataclass
class TaskObservation:
    pid: int
    task: object
    mnt_ns: object
    mnt_ns_id: int
    pid_ns_id: int | None
    ns_pid: int | None
    root_key: tuple[int, int]
    cgroup_memberships: tuple[cgroup_readers.CgroupMembership, ...]
    identity: Identity | None
    runtime: str
    evidence: tuple[str, ...]


@dataclasses.dataclass
class MountRecord:
    mnt: object
    data: object
    container_path: str
    mount_root: str
    host_paths: tuple[str, ...]
    host_path_status: str


class HostMountResolver:
    """Resolve complete, unshadowed host paths through init_task's namespace.

    SINGLE describes one visible alias in the collected host topology;
    it does not identify the original bind-mount command or source pathname.
    A partial index or unreadable candidate route is marked PARTIAL even
    when another complete path was found, because alternatives remain unknown.
    """

    def __init__(self, init_task, *, diagnostics=None):
        self.diagnostics = diagnostics
        self._init_task = init_task
        self._host_root_dentry = None
        self._host_root_mnt = None
        self._by_superblock: dict[int, list[object]] = {}
        self._covering_mounts: dict[tuple[int, int], set] = {}
        self._index_complete = False
        try:
            self._host_root_dentry = init_task.fs.get_root_dentry()
            self._host_root_mnt = init_task.fs.get_root_mnt()
            if not all(
                obj and artifact_core._object_readable(obj, diagnostics=diagnostics)
                for obj in (self._host_root_dentry, self._host_root_mnt)
            ):
                raise ValueError("unreadable host root")
            host_namespace = init_task.nsproxy.mnt_ns
            host_mounts, status = ContainerMounts._mount_points(
                host_namespace, diagnostics=diagnostics
            )
            self._index_complete = status == "COMPLETE"
            indexed_vfsmounts = set()
            for host_mnt in host_mounts:
                try:
                    superblock = host_mnt.get_mnt_sb()
                    host_vfsmnt = host_mnt.get_vfsmnt_current()
                    if not all(
                        obj
                        and artifact_core._object_readable(obj, diagnostics=diagnostics)
                        for obj in (superblock, host_vfsmnt)
                    ):
                        self._index_complete = False
                        continue
                    mount_address = artifact_core._object_address(host_vfsmnt)
                    if mount_address in indexed_vfsmounts:
                        continue
                    indexed_vfsmounts.add(mount_address)
                    self._by_superblock.setdefault(
                        artifact_core._object_address(superblock), []
                    ).append(host_mnt)

                    parent_vfsmnt = host_mnt.get_vfsmnt_parent()
                    if not (
                        parent_vfsmnt
                        and artifact_core._object_readable(
                            parent_vfsmnt, diagnostics=diagnostics
                        )
                    ):
                        self._index_complete = False
                        continue
                    parent_address = artifact_core._object_address(parent_vfsmnt)
                    if parent_address == mount_address:
                        continue
                    mountpoint = host_mnt.get_mnt_mountpoint()
                    if not (
                        mountpoint
                        and artifact_core._object_readable(
                            mountpoint, diagnostics=diagnostics
                        )
                    ):
                        self._index_complete = False
                        continue
                    key = (parent_address, artifact_core._object_address(mountpoint))
                    self._covering_mounts.setdefault(key, set()).add(mount_address)
                except (
                    AttributeError,
                    TypeError,
                    ValueError,
                    exceptions.InvalidAddressException,
                    exceptions.VolatilityException,
                ) as exc:
                    artifact_core.record_read_error(
                        diagnostics, "host_mount.index", exc
                    )
                    self._index_complete = False
                    continue
            if (
                artifact_core._object_address(self._host_root_mnt)
                not in indexed_vfsmounts
            ):
                self._index_complete = False
            if any(
                parent not in indexed_vfsmounts for parent, _ in self._covering_mounts
            ):
                self._index_complete = False
        except (
            AttributeError,
            TypeError,
            ValueError,
            exceptions.InvalidAddressException,
            exceptions.VolatilityException,
        ) as exc:
            artifact_core.record_read_error(diagnostics, "host_mount.setup", exc)
            vollog.warning(
                "Host mount namespace index is incomplete: %s",
                artifact_core.exception_text(exc),
            )
        if not self._index_complete:
            vollog.warning(
                "Host mount index is incomplete; host path results are PARTIAL"
            )

    def resolve(self, mnt) -> path_readers.SourceResolution:
        try:
            superblock = mnt.get_mnt_sb()
            source_dentry = mnt.get_mnt_root()
            if not (
                superblock
                and artifact_core._object_readable(
                    superblock, diagnostics=self.diagnostics
                )
                and source_dentry
                and artifact_core._object_readable(
                    source_dentry, diagnostics=self.diagnostics
                )
            ):
                return path_readers.SourceResolution((), PATH_PARTIAL)
            host_mounts = self._by_superblock.get(
                artifact_core._object_address(superblock), ()
            )
        except (
            AttributeError,
            TypeError,
            ValueError,
            exceptions.InvalidAddressException,
            exceptions.VolatilityException,
        ) as exc:
            artifact_core.record_read_error(self.diagnostics, "host_mount.resolve", exc)
            return path_readers.SourceResolution((), PATH_PARTIAL)

        resolved = set()
        complete = self._index_complete
        for host_mnt in host_mounts:
            try:
                path, status = _walk_mount_path(
                    self._host_root_dentry,
                    self._host_root_mnt,
                    source_dentry,
                    host_mnt.get_vfsmnt_current(),
                    covering_mounts=self._covering_mounts,
                    diagnostics=self.diagnostics,
                )
                if status == "COMPLETE":
                    resolved.add(path)
                elif status.startswith("INCOMPLETE:"):
                    complete = False
            except (
                AttributeError,
                TypeError,
                ValueError,
                exceptions.InvalidAddressException,
                exceptions.VolatilityException,
            ) as exc:
                artifact_core.record_read_error(
                    self.diagnostics, "host_mount.path", exc
                )
                complete = False
                continue

        paths = tuple(sorted(resolved))
        if not complete:
            return path_readers.SourceResolution(paths, PATH_PARTIAL)
        if not paths:
            return path_readers.SourceResolution((), PATH_UNRESOLVED)
        return path_readers.SourceResolution(
            paths,
            PATH_SINGLE if len(paths) == 1 else PATH_MULTIPLE,
        )


def _bounded_dentry_path(dentry, max_depth: int = 4096, *, diagnostics=None) -> str:
    """Filesystem-relative topology, not host visibility or inode liveness.

    Used only for mountinfo's root field.  Follow the complete dentry chain
    even when inode pages are missing, but never return a truncated suffix.
    """

    parts: list[str] = []
    seen = set()
    try:
        for _ in range(max_depth):
            if not (
                dentry
                and artifact_core._object_readable(dentry, diagnostics=diagnostics)
            ):
                return ""
            address = artifact_core._object_address(dentry)
            if address in seen:
                return ""
            seen.add(address)
            parent = dentry.d_parent
            if not (
                parent
                and artifact_core._object_readable(parent, diagnostics=diagnostics)
            ):
                return ""
            if artifact_core._object_address(parent) == address:
                return "/" + "/".join(reversed(parts))
            name, issue = _read_dentry_name(dentry)
            if issue:
                return ""
            parts.append(name)
            dentry = parent
    except (
        AttributeError,
        IndexError,
        TypeError,
        ValueError,
        exceptions.InvalidAddressException,
        exceptions.VolatilityException,
    ) as exc:
        artifact_core.record_read_error(diagnostics, "mount.root_path", exc)
        return ""
    return ""


def _bounded_dominating_id(
    mnt, task, max_nodes: int = 4096, *, diagnostics=None
) -> int | None:
    """Closest reachable master peer-group ID, 0 if absent, None if unknown.

    Follows fs/pnode.c's get_dominating_id ordering.  Peer links are resolved
    with upstream container_of using their *target* address, rather than the
    pointer-field offset used by Volatility 2.28.0's next_peer().  All master,
    peer and path walks are bounded; uncertainty in a closer group prevents
    claiming that a more distant group is the closest dominator.
    """

    try:
        namespace_address = artifact_core._object_address(mnt.mnt_ns)
        if not namespace_address:
            return None
        root_dentry = task.fs.get_root_dentry()
        root_vfsmnt = task.fs.get_root_mnt()
        current_master = mnt.mnt_master
        master_seen = set()
        visited_nodes = 0
        vmlinux = None
        while current_master:
            if not artifact_core._object_readable(
                current_master, diagnostics=diagnostics
            ):
                return None
            master_address = artifact_core._object_address(current_master)
            if master_address in master_seen:
                return None
            master_seen.add(master_address)
            group_id = int(current_master.mnt_group_id)
            if group_id <= 0:
                return None
            peer = current_master
            peer_seen = set()
            group_uncertain = False
            while True:
                if visited_nodes >= max_nodes or not (
                    peer
                    and artifact_core._object_readable(peer, diagnostics=diagnostics)
                ):
                    return None
                visited_nodes += 1
                peer_address = artifact_core._object_address(peer)
                if peer_address in peer_seen:
                    return None
                peer_seen.add(peer_address)
                if int(peer.mnt_group_id) != group_id:
                    return None
                if artifact_core._object_address(peer.mnt_ns) == namespace_address:
                    _path, status = _walk_mount_path(
                        root_dentry,
                        root_vfsmnt,
                        peer.get_mnt_root(),
                        peer.get_vfsmnt_current(),
                        diagnostics=diagnostics,
                    )
                    if status == "COMPLETE":
                        return group_id
                    if status.startswith("INCOMPLETE:"):
                        group_uncertain = True

                share = peer.mnt_share
                link = share.next
                if not (
                    link
                    and artifact_core._object_readable(link, diagnostics=diagnostics)
                ):
                    return None
                if artifact_core._object_address(
                    link.prev
                ) != artifact_core._object_address(share):
                    return None
                if artifact_core._object_address(link) == artifact_core._object_address(
                    share
                ):
                    if peer_address != master_address:
                        return None
                    break
                if vmlinux is None:
                    vmlinux = linux.LinuxUtilities.get_module_from_volobj_type(
                        mnt._context,
                        mnt,
                    )
                peer = linux.LinuxUtilities.container_of(
                    link, "mount", "mnt_share", vmlinux
                )
                if artifact_core._object_address(peer) == master_address:
                    break
            if group_uncertain:
                return None
            current_master = current_master.mnt_master
        return 0
    except (
        AttributeError,
        IndexError,
        TypeError,
        ValueError,
        exceptions.InvalidAddressException,
        exceptions.VolatilityException,
    ) as exc:
        artifact_core.record_read_error(diagnostics, "mount.dominating_id", exc)
        return None


def _read_mount_info(
    mnt,
    task,
    *,
    diagnostics=None,
) -> tuple[mountinfo.MountInfoData | None, tuple[str, ...]]:
    """Read upstream mountinfo fields without its unbounded path traversals.

    Kernel-specific field/flag interpretation stays in pinned upstream object
    getters.  This adapter only assembles MountInfoData and supplies bounded
    paths/propagation.  Optional failures retain readable attributes and are
    returned explicitly instead of discarding the entire mount record.
    """

    issues: list[str] = []
    try:
        superblock = mnt.get_mnt_sb()
        if not (
            superblock
            and artifact_core._object_readable(superblock, diagnostics=diagnostics)
        ):
            return None, ("decode",)
        mnt_id = int(mnt.mnt_id)
    except (
        AttributeError,
        IndexError,
        TypeError,
        ValueError,
        exceptions.InvalidAddressException,
        exceptions.VolatilityException,
    ) as exc:
        artifact_core.record_read_error(diagnostics, "mount.decode", exc)
        return None, ("decode",)

    def read_field(name, getter, default):
        try:
            return getter()
        except (
            AttributeError,
            IndexError,
            TypeError,
            ValueError,
            exceptions.InvalidAddressException,
            exceptions.VolatilityException,
        ) as exc:
            artifact_core.record_read_error(diagnostics, "mount." + name, exc)
            issues.append(name)
            return default

    # A missing device name/flag is not a reason to discard an otherwise
    # readable mount.  Keep failed flags empty so RO/RW cannot become guessed rw.
    parent_id = read_field("parent-id", lambda: int(mnt.mnt_parent.mnt_id), -1)
    st_dev = read_field(
        "device", lambda: f"{int(superblock.major)}:{int(superblock.minor)}", "-"
    )
    mnt_access = read_field("mount-access", lambda: mnt.get_flags_access(), "")
    mnt_opts = ([mnt_access] if mnt_access else []) + read_field(
        "mount-options", lambda: list(mnt.get_flags_opts()), []
    )
    mnt_type = read_field("fs-type", lambda: superblock.get_type(), "-")
    if not isinstance(mnt_type, str) or not mnt_type:
        issues.append("fs-type")
        mnt_type = "-"
    devname = read_field("devname", lambda: _read_mount_devname(mnt), "-")
    sb_access = read_field(
        "superblock-access", lambda: superblock.get_flags_access(), ""
    )
    sb_opts = ([sb_access] if sb_access else []) + read_field(
        "superblock-options", lambda: list(superblock.get_flags_opts()), []
    )

    container_path = ""
    mount_root_path = ""
    path_status = "INCOMPLETE"
    try:
        root = mnt.get_mnt_root()
        mount_root_path = _bounded_dentry_path(root, diagnostics=diagnostics)
        container_path, path_status = _walk_mount_path(
            task.fs.get_root_dentry(),
            task.fs.get_root_mnt(),
            root,
            mnt.get_vfsmnt_current(),
            require_live_inode=False,
            diagnostics=diagnostics,
        )
    except (
        AttributeError,
        IndexError,
        TypeError,
        ValueError,
        exceptions.InvalidAddressException,
        exceptions.VolatilityException,
    ) as exc:
        artifact_core.record_read_error(diagnostics, "mount.path", exc)
    # A detached self-parent namespace sentinel is intentionally outside the
    # task root.  This proven absence is not an unreadable-path failure.
    expected_internal_root = (
        path_status == "OUTSIDE_ROOT"
        and mnt_id == parent_id
        and mnt_type in INTERNAL_NAMESPACE_ROOT_FSTYPES
    )
    if not container_path and not expected_internal_root:
        issues.append("path")
    if not mount_root_path:
        issues.append("mount-root")

    fields: list[str] = []
    try:
        if mnt.is_shared():
            shared_id = int(mnt.mnt_group_id)
            if shared_id <= 0:
                issues.append("propagation")
            else:
                fields.append(f"shared:{shared_id}")
        if mnt.is_slave():
            master_id = int(mnt.mnt_master.mnt_group_id)
            if master_id <= 0:
                issues.append("propagation")
            else:
                fields.append(f"master:{master_id}")
                dominating_id = _bounded_dominating_id(
                    mnt, task, diagnostics=diagnostics
                )
                if dominating_id is None:
                    issues.append("propagation")
                elif dominating_id and dominating_id != master_id:
                    fields.append(f"propagate_from:{dominating_id}")
        if mnt.is_unbindable():
            fields.append("unbindable")
    except (
        AttributeError,
        IndexError,
        TypeError,
        ValueError,
        exceptions.InvalidAddressException,
        exceptions.VolatilityException,
    ) as exc:
        artifact_core.record_read_error(diagnostics, "mount.propagation", exc)
        issues.append("propagation")

    return mountinfo.MountInfoData(
        mnt_id,
        parent_id,
        st_dev,
        mount_root_path,
        container_path,
        mnt_opts,
        fields,
        mnt_type,
        devname,
        sb_opts,
    ), tuple(dict.fromkeys(issues))


def _mount_access(data) -> tuple[bool | None, str]:
    """Combine mount/superblock RO bits; unread flags never imply writable."""
    mount_options = {str(value) for value in (getattr(data, "mnt_opts", None) or ())}
    superblock_options = {
        str(value) for value in (getattr(data, "sb_opts", None) or ())
    }
    if "ro" in mount_options or "ro" in superblock_options:
        return False, "ro"
    if "rw" in mount_options and "rw" in superblock_options:
        return True, "rw"
    return None, "-"


class ContainerMounts(plugins.PluginInterface):
    """Find container-backed mount namespaces and inspect their mounts."""

    hidden = True  # Exposed through linux.docker.Docker --inspect-mounts.
    _required_framework_version = (2, 13, 0)
    # 1.x marks the category/value TreeGrid output contract.
    _version = (1, 1, 1)

    @classmethod
    def get_requirements(cls) -> list[interfaces.configuration.RequirementInterface]:
        return [
            requirements.VersionRequirement(
                name="docker_artifacts",
                component=docker_artifacts.DockerArtifacts,
                version=(1, 0, 1),
            ),
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
                description="Inspect these positive host PIDs without automatic target selection",
                element_type=int,
                # Also prevents Volatility's optional-list validation from
                # rewriting an omitted value to [], which would erase the
                # distinction between automatic mode and an empty --pids.
                min_elements=1,
                optional=True,
            ),
            requirements.BooleanRequirement(
                name="extended",
                description="Add Mount ID, Read Status and Host Path Status (10 columns total)",
                optional=True,
                default=False,
            ),
        ]

    @staticmethod
    def _observe_task(task, *, diagnostics=None) -> TaskObservation | None:
        try:
            if not (
                task
                and task.fs
                and artifact_core._object_readable(task.fs, diagnostics=diagnostics)
                and task.nsproxy
                and artifact_core._object_readable(
                    task.nsproxy, diagnostics=diagnostics
                )
                and task.nsproxy.mnt_ns
                and artifact_core._object_readable(
                    task.nsproxy.mnt_ns, diagnostics=diagnostics
                )
            ):
                return None
            pid = int(task.pid)
            mnt_ns = task.nsproxy.mnt_ns
            mnt_ns_id = int(mnt_ns.get_inode())
            root_key = (
                artifact_core._object_address(task.fs.get_root_mnt()),
                artifact_core._object_address(task.fs.get_root_dentry()),
            )
        except (
            AttributeError,
            TypeError,
            ValueError,
            exceptions.InvalidAddressException,
        ) as exc:
            artifact_core.record_read_error(diagnostics, "task.view", exc)
            return None

        cgroup_issues = set()
        cgroup_memberships = cgroup_readers._cgroup_memberships(
            task, issues_out=cgroup_issues
        )
        identity, identity_source, identity_conflict = _cgroup_identity(
            cgroup_memberships
        )
        identity_conflict = identity_conflict or "cgroup-id-conflict" in cgroup_issues
        if identity_conflict:
            identity = None
        ancestry_runtime, supervisor_comm = _runtime_from_ancestry(task)
        pid_ns_id, ns_pid = namespace_readers._pid_namespace_values(task)
        evidence: list[str] = []
        if identity_conflict:
            evidence.append("cgroup-id-conflict")
        elif identity:
            evidence.append(f"cgroup:{identity_source}:{identity.evidence}")
        if ancestry_runtime:
            evidence.append(f"supervisor:{supervisor_comm}")
        if "cgroup-metadata-partial" in cgroup_issues:
            evidence.append("cgroup-metadata-partial")
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
            runtime=identity.runtime if identity else ancestry_runtime,
            evidence=tuple(evidence),
        )

    def _requested_pids(self) -> set | None:
        """None means auto; an explicitly empty/invalid PID list is an error."""
        value = self.config.get("pids", None)
        if value is None:
            return None
        if not value:
            raise ValueError("--pids requires at least one positive host PID")
        if any(
            isinstance(pid, bool) or not isinstance(pid, int) or pid <= 0
            for pid in value
        ):
            raise ValueError("--pids accepts positive integer host PIDs only")
        return set(value)

    def _collect_namespaces(
        self,
        tasks: Sequence[object],
        init_task,
        *,
        diagnostics=None,
    ) -> dict[int, list[TaskObservation]]:
        wanted = self._requested_pids()
        try:
            host_namespace = init_task.nsproxy.mnt_ns
            host_address = (
                artifact_core._object_address(host_namespace)
                if artifact_core._object_readable(
                    host_namespace, diagnostics=diagnostics
                )
                else None
            )
        except (
            AttributeError,
            TypeError,
            ValueError,
            exceptions.InvalidAddressException,
        ) as exc:
            artifact_core.record_read_error(diagnostics, "host_namespace", exc)
            host_address = None
        if wanted is None and host_address is None:
            vollog.warning(
                "Host mount namespace is unreadable; automatic selection still requires "
                "recognized cgroup membership or a supervisor. Use --pids for explicit views."
            )
        namespaces: dict[int, list[TaskObservation]] = {}
        found_pids = set()
        failed = 0
        for task in tasks:
            task_address = None
            try:
                task_address = int(task.vol.offset)
                # Do not read every task's cgroups for a manually selected PID.
                pid = int(task.pid)
                if wanted is not None and pid not in wanted:
                    continue
                task_diagnostics = []
                observation = self._observe_task(task, diagnostics=task_diagnostics)
                if diagnostics is not None:
                    diagnostics.extend(
                        {**item, "task_address": task_address, "pid": pid}
                        for item in task_diagnostics
                    )
                if observation is None:
                    # Kernel threads normally have no filesystem/namespace
                    # view; that is not a damaged mount in automatic mode.
                    if wanted is not None or (task.fs and task.nsproxy):
                        failed += 1
                    continue
                namespace_address = artifact_core._object_address(observation.mnt_ns)
                if not namespace_address:
                    failed += 1
                    continue
            except (
                AttributeError,
                TypeError,
                ValueError,
                exceptions.InvalidAddressException,
            ) as exc:
                artifact_core.record_read_error(
                    diagnostics, "task.metadata", exc, task_address=task_address
                )
                failed += 1
                continue
            if wanted is not None:
                found_pids.add(observation.pid)
            else:
                if namespace_address == host_address:
                    continue
                # Selection is a declared relation, not a weighted score.
                related = (
                    observation.identity is not None
                    or "cgroup-id-conflict" in observation.evidence
                    or any(
                        item.startswith("supervisor:") for item in observation.evidence
                    )
                )
                if not related:
                    continue
            # The address identifies the object.  An inode alone can collide
            # in a damaged capture and must not merge unrelated namespaces.
            namespaces.setdefault(namespace_address, []).append(observation)
        if wanted is not None and wanted - found_pids:
            vollog.warning(
                "Requested PIDs were not found/readable: %s",
                sorted(wanted - found_pids),
            )
        if failed:
            vollog.warning(
                "%s task views could not be read (including tasks without fs/nsproxy); "
                "their absence from this output does not prove absence of mounts",
                failed,
            )
        return namespaces

    @staticmethod
    def _view_groups(
        observations: Sequence[TaskObservation],
        manual: bool = False,
    ) -> list[list[TaskObservation]]:
        """Keep ownership separate from shared namespace/root mount data."""
        ordered = sorted(observations, key=lambda item: item.pid)
        if manual:
            return [[item] for item in ordered]
        groups: dict[tuple, list[TaskObservation]] = {}
        for item in ordered:
            if item.identity and item.identity.id_kind == "container":
                owner = ("container", item.identity.runtime, item.identity.identifier)
            else:
                # A pod, an unknown ID or an unreadable hierarchy must not
                # borrow the identity of a sibling simply sharing its MNT NS.
                owner = (
                    "membership",
                    item.runtime,
                    tuple(
                        sorted(
                            (m.version, m.cgroup_address, m.path)
                            for m in item.cgroup_memberships
                        )
                    ),
                    item.identity.identifier if item.identity else "",
                    "cgroup-id-conflict" in item.evidence,
                    item.pid
                    if any(
                        flag in item.evidence
                        for flag in ("cgroup-id-conflict", "cgroup-metadata-partial")
                    )
                    else None,
                )
            key = (artifact_core._object_address(item.mnt_ns), item.root_key, owner)
            groups.setdefault(key, []).append(item)
        return list(groups.values())

    @staticmethod
    def _representative(observations: Sequence[TaskObservation]) -> TaskObservation:
        """Equivalent root/ownership views use the lowest readable host PID."""
        return min(observations, key=lambda item: item.pid)

    _list_mount_points = staticmethod(mount_readers.list_mount_points)

    _mount_points = staticmethod(mount_readers.mount_points)

    @classmethod
    def _collect_mounts(
        cls,
        representative: TaskObservation,
        resolver: HostMountResolver,
        mount_cache=None,
        path_cache=None,
        *,
        diagnostics=None,
    ) -> tuple[list[MountRecord], str]:
        """Decode a root view; namespace enumeration and host aliases are reusable."""
        mount_cache = {} if mount_cache is None else mount_cache
        path_cache = {} if path_cache is None else path_cache
        namespace_address = artifact_core._object_address(representative.mnt_ns)
        if namespace_address not in mount_cache:
            namespace_diagnostics = []
            mount_cache[namespace_address] = cls._mount_points(
                representative.mnt_ns, diagnostics=namespace_diagnostics
            )
            if diagnostics is not None:
                diagnostics.extend(
                    {**item, "namespace_address": namespace_address}
                    for item in namespace_diagnostics
                )
        mounts, traversal_status = mount_cache[namespace_address]
        records: list[MountRecord] = []
        error_counts: dict[str, int] = {}
        seen_mounts = set()
        for mnt in mounts:
            mount_address = None
            provenance = {
                "pid": representative.pid,
                "namespace_address": namespace_address,
            }
            try:
                mount_address = artifact_core._object_address(mnt)
                provenance["mount_address"] = mount_address
                if mount_address in seen_mounts:
                    continue
                seen_mounts.add(mount_address)
                mount_diagnostics = []
                data, issues = _read_mount_info(
                    mnt, representative.task, diagnostics=mount_diagnostics
                )
                if diagnostics is not None:
                    diagnostics.extend(
                        {**item, **provenance} for item in mount_diagnostics
                    )
                for issue in issues:
                    error_counts[issue] = error_counts.get(issue, 0) + 1
                if data is None:
                    continue
                internal_root_candidate = (
                    int(data.mnt_id) == int(data.parent_id)
                    and str(data.mnt_type) in INTERNAL_NAMESPACE_ROOT_FSTYPES
                )
                is_internal_root = False
                root_identity_unknown = False
                if internal_root_candidate:
                    try:
                        # Only sentinel candidates need this identity check.
                        # Path/root fields are optional: a second failed read
                        # must not discard the mount data already recovered.
                        mount_key = (
                            artifact_core._object_address(mnt.get_vfsmnt_current()),
                            artifact_core._object_address(mnt.get_mnt_root()),
                        )
                        if not all(mount_key):
                            raise ValueError("null mount root identity")
                        is_internal_root = mount_key != representative.root_key
                    except (
                        AttributeError,
                        IndexError,
                        TypeError,
                        ValueError,
                        exceptions.InvalidAddressException,
                        exceptions.VolatilityException,
                    ) as exc:
                        artifact_core.record_read_error(
                            diagnostics, "mount.root_identity", exc, **provenance
                        )
                        root_identity_unknown = True
                        error_counts["root-identity"] = (
                            error_counts.get("root-identity", 0) + 1
                        )
                if is_internal_root:
                    source = path_readers.SourceResolution((), PATH_UNRESOLVED)
                elif root_identity_unknown:
                    # Do not guess whether an unreadable root is a sentinel
                    # or the task's real root; retain its other fields.
                    source = path_readers.SourceResolution((), PATH_PARTIAL)
                else:
                    if mount_address not in path_cache:
                        path_cache[mount_address] = resolver.resolve(mnt)
                    source = path_cache[mount_address]
                records.append(
                    MountRecord(
                        mnt=mnt,
                        data=data,
                        container_path=data.path_root,
                        mount_root=data.mnt_root_path,
                        host_paths=source.paths,
                        host_path_status=source.status,
                    )
                )
            except (
                AttributeError,
                TypeError,
                ValueError,
                exceptions.InvalidAddressException,
                exceptions.VolatilityException,
            ) as exc:
                artifact_core.record_read_error(
                    diagnostics, "mount.decode", exc, **provenance
                )
                error_counts["decode"] = error_counts.get("decode", 0) + 1
                continue
        if error_counts:
            suffix = ",".join(
                f"{name}={count}" for name, count in sorted(error_counts.items())
            )
            traversal_status = (
                f"PARTIAL:{suffix}"
                if traversal_status == "COMPLETE"
                else f"{traversal_status},{suffix}"
            )
        return records, traversal_status

    @staticmethod
    def _view_metadata(
        observations: Sequence[TaskObservation],
        manual: bool = False,
    ) -> tuple[str, str, str, str]:
        """Describe actual task membership; mounted foreign IDs are not owners."""
        evidence = set()
        for item in observations:
            evidence.update(item.evidence)
        if manual:
            evidence.add("explicit-pid-selection")
        identities = [item.identity for item in observations if item.identity]
        container_ids = {
            item.identifier for item in identities if item.id_kind == "container"
        }
        pod_ids = {item.identifier for item in identities if item.id_kind == "pod"}
        # A cgroup path may contain both a pod scope and a leaf container ID.
        # Read the pod label independently without putting it in Container ID.
        for observation in observations:
            for membership in observation.cgroup_memberships:
                for identity in _path_identities(membership.path):
                    if identity.id_kind == "pod":
                        pod_ids.add(identity.identifier)
        if (
            "cgroup-id-conflict" in evidence
            or len(container_ids) > 1
            or len(pod_ids) > 1
        ):
            evidence.add("cgroup-id-conflict")
            container_ids.clear()
            pod_ids.clear()
        runtimes = {item.runtime for item in observations if item.runtime}
        runtime = next(iter(runtimes)) if len(runtimes) == 1 else ""
        return (
            runtime,
            next(iter(container_ids)) if len(container_ids) == 1 else "",
            next(iter(pod_ids)) if len(pod_ids) == 1 else "",
            ";".join(sorted(evidence)),
        )

    def _generator(self, extended: bool):
        diagnostics = []
        try:
            yield from self._generate_rows(extended, diagnostics)
        finally:
            if diagnostics:
                with self.open("containermounts-diagnostics.json") as handle:
                    handle.write(
                        json.dumps(
                            {
                                "plugin_version": self._version,
                                "diagnostics": diagnostics,
                            },
                            ensure_ascii=False,
                            indent=2,
                        ).encode("utf-8")
                    )

    def _generate_rows(self, extended: bool, diagnostics):
        manual = self._requested_pids() is not None
        vmlinux = self.context.modules[self.config["kernel"]]
        init_task = vmlinux.object_from_symbol("init_task")
        tasks = []
        task_list_partial = False
        try:
            # Extend the existing list so an iterator failure preserves its prefix.
            tasks.extend(
                docker_artifacts.DockerArtifacts.list_tasks(
                    self.context, self.config["kernel"]
                )
            )
        except artifact_core.READ_ERRORS as exc:
            task_list_partial = True
            artifact_core.record_read_error(diagnostics, "task_list", exc)
            vollog.warning(
                "Task collection incomplete: %s", artifact_core.exception_text(exc)
            )
        namespaces = self._collect_namespaces(tasks, init_task, diagnostics=diagnostics)
        resolver = HostMountResolver(init_task, diagnostics=diagnostics)
        mount_cache, path_cache, view_cache = {}, {}, {}
        emitted_views = 0
        for _namespace_address, observations in sorted(namespaces.items()):
            for group in self._view_groups(observations, manual=manual):
                representative = self._representative(group)
                view_key = (
                    artifact_core._object_address(representative.mnt_ns),
                    representative.root_key,
                )
                if view_key not in view_cache:
                    view_cache[view_key] = self._collect_mounts(
                        representative,
                        resolver,
                        mount_cache=mount_cache,
                        path_cache=path_cache,
                        diagnostics=diagnostics,
                    )
                records, read_status = view_cache[view_key]
                if task_list_partial:
                    read_status = (
                        "PARTIAL:task-list"
                        if read_status == "COMPLETE"
                        else read_status + ",task-list"
                    )
                _runtime, container_id, _pod_id, evidence = self._view_metadata(
                    group, manual
                )
                emitted_views += 1
                if read_status != "COMPLETE":
                    vollog.warning(
                        "MNT NS %s (PID %s): %s; decoded=%s. "
                        "An empty result does not establish absence of mounts.",
                        representative.mnt_ns_id,
                        representative.pid,
                        read_status,
                        len(records),
                    )
                elif not records:
                    vollog.warning(
                        "MNT NS %s (PID %s): no mount records available",
                        representative.mnt_ns_id,
                        representative.pid,
                    )
                if "cgroup-id-conflict" in evidence:
                    vollog.warning(
                        "PID %s: conflicting cgroup IDs; owner ID withheld",
                        representative.pid,
                    )
                if "cgroup-metadata-partial" in evidence:
                    vollog.warning(
                        "PID %s: cgroup membership was only partially read",
                        representative.pid,
                    )
                partial_paths = sum(r.host_path_status == PATH_PARTIAL for r in records)
                if partial_paths:
                    vollog.warning(
                        "PID %s: host path recovery incomplete for %s mounts; "
                        "reported aliases may be incomplete (see --extended)",
                        representative.pid,
                        partial_paths,
                    )
                for record in records:
                    _writable, mode = _mount_access(record.data)
                    # No per-path classifier or filtering runs here.
                    row = (
                        representative.pid,
                        int(representative.mnt_ns_id),
                        container_id or "-",
                        record.container_path or "-",
                        " | ".join(record.host_paths) or "-",
                        str(record.data.mnt_type),
                        mode,
                    )
                    if extended:
                        row += (
                            int(record.data.mnt_id),
                            read_status,
                            record.host_path_status,
                        )
                    yield 0, row
        if not emitted_views:
            vollog.warning(
                "No readable target views selected. Automatic selection is limited to "
                "supported cgroup names/supervisor relations; use --pids for a known host PID."
            )

    def run(self):
        self._requested_pids()  # Reject an empty --pids before starting dump traversal.
        columns = [
            ("PID", int),
            ("MNT NS", int),
            ("Container ID", str),
            ("Container Path", str),
            ("Host Paths", str),
            ("FS Type", str),
            ("RO/RW", str),
        ]
        extended = bool(self.config.get("extended", False))
        if extended:
            columns.extend(
                [
                    ("Mount ID", int),
                    ("Read Status", str),
                    ("Host Path Status", str),
                ]
            )
        return _vertical.vertical_grid(columns, self._generator(extended))

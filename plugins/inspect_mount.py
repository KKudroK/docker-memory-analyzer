# SPDX-License-Identifier: MIT
# Copyright (c) 2026 container-mounts contributors
"""Container-aware mount analysis for Volatility 3 2.28.0.

The plugin deliberately separates three facts that are easy to conflate:

* a task lives in a non-host mount namespace;
* that namespace has evidence of being managed by a container runtime;
* a mount's source is visible at a particular path in the host namespace.

Only the second fact makes a namespace a default output candidate.  A host
source is reported as confirmed only when a complete host index yields one
fully checked, unshadowed route through a mount sharing its superblock.
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


def _object_readable(obj) -> bool:
    """Validate pointer targets and embedded structs with their own layer APIs.

    Pointer.is_readable() checks the pointed-to object.  Embedded StructType
    objects (for example mount.mnt and list heads) do not provide that method;
    their storage range must be checked in their layer instead.  Do not treat
    an absent pointer-only method as unreadable memory.
    """

    try:
        if obj is None:
            return False
        pointer_check = getattr(obj, "is_readable", None)
        if callable(pointer_check):
            return bool(obj) and bool(pointer_check())
        return bool(obj._context.layers[obj.vol.layer_name].is_valid(
            int(obj.vol.offset), int(obj.vol.size)
        ))
    except (
        AttributeError, KeyError, IndexError, TypeError, ValueError,
        exceptions.InvalidAddressException, exceptions.VolatilityException,
    ):
        return False


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


def _read_dentry_name(dentry) -> Tuple[str, str]:
    """Bound qstr reads before decoding, preserving valid filename whitespace."""

    qname = dentry.d_name
    declared_length = int(qname.len) if qname.has_member("len") else None
    if declared_length is not None and not 1 <= declared_length <= 255:
        return "", "invalid-name"
    name = qname.name_as_str()
    if (
        not name or name in {".", ".."} or "/" in name
        or "\x00" in name or "\ufffd" in name
        or any(ord(char) < 32 or ord(char) == 127 for char in name)
        or len(name.encode("utf-8")) > 255
    ):
        return "", "invalid-name"
    if declared_length is not None and declared_length != len(name.encode("utf-8")):
        return "", "truncated-name"
    return name, ""


def _walk_mount_path(
    root_dentry,
    root_vfsmnt,
    dentry,
    vfsmnt,
    *,
    max_depth: int = 4096,
    covering_mounts=None,
    require_live_inode: bool = True,
) -> Tuple[str, str]:
    """Build a path only after reaching the exact (mount, dentry) root.

    Upstream do_get_path() can return a plausible suffix when an unreadable
    parent stops its walk.  Here an incomplete walk never becomes a path.
    Each comparison uses pointer targets, not pointer-field storage offsets.
    A namespace covering-mount index additionally rejects paths hidden by a
    different mount; without that index this proves topology, not visibility.
    The container-side mountinfo path needs topology only.  Host-source and
    propagation proofs additionally require readable, linked inodes.
    """

    parts: List[str] = []
    seen = set()
    # When leaving a child mount, its attachment at the parent dentry is the
    # one covering edge that belongs to this route rather than obscuring it.
    allowed_cover = None
    crossed_mount = False
    try:
        if not all(
            obj and _object_readable(obj)
            for obj in (root_dentry, root_vfsmnt, dentry, vfsmnt)
        ):
            return "", "INCOMPLETE:unreadable-root-or-source"
        root_key = (_object_address(root_vfsmnt), _object_address(root_dentry))
        for _ in range(max_depth):
            if not (dentry and _object_readable(dentry) and vfsmnt and _object_readable(vfsmnt)):
                return "", "INCOMPLETE:unreadable-route"
            key = (_object_address(vfsmnt), _object_address(dentry))
            if key in seen:
                return "", "INCOMPLETE:cycle"
            seen.add(key)

            if require_live_inode:
                inode = dentry.d_inode
                if not (inode and _object_readable(inode)) or int(inode.i_nlink) <= 0:
                    return "", "INCOMPLETE:missing-or-unlinked-inode"

            if covering_mounts is not None:
                covers = covering_mounts.get(key, set())
                if len(covers) > 1:
                    # Sibling attachments do not encode which stacked mount
                    # wins lookup; a different valid alias cannot settle it.
                    return "", "INCOMPLETE:stacked-attachment"
                if covers and covers != {allowed_cover}:
                    return "", "COVERED"
                if allowed_cover is not None and allowed_cover not in covers:
                    return "", "INCOMPLETE:missing-attachment"
            allowed_cover = None

            if key == root_key:
                return "/" + "/".join(reversed(parts)), "COMPLETE"

            mount_root = vfsmnt.get_mnt_root()
            if not (mount_root and _object_readable(mount_root)):
                return "", "INCOMPLETE:unreadable-mount-root"
            if key[1] == _object_address(mount_root):
                parent_mnt = vfsmnt.get_vfsmnt_parent()
                mountpoint = vfsmnt.get_mnt_mountpoint()
                if not (
                    parent_mnt and _object_readable(parent_mnt)
                    and mountpoint and _object_readable(mountpoint)
                ):
                    return "", "INCOMPLETE:unreadable-attachment"
                if _object_address(parent_mnt) == key[0]:
                    return "", "OUTSIDE_ROOT"
                allowed_cover = key[0]
                crossed_mount = True
                dentry, vfsmnt = mountpoint, parent_mnt
                continue

            parent = dentry.d_parent
            if not (parent and _object_readable(parent)):
                return "", "INCOMPLETE:unreadable-parent"
            if _object_address(parent) == key[1]:
                # A same-superblock bind mount may cover a disjoint subtree.
                # Reaching its filesystem root without its mount root proves
                # that this candidate is not an ancestor of the source.
                return "", "OUTSIDE_ROOT" if crossed_mount else "OUTSIDE_MOUNT"

            name, name_issue = _read_dentry_name(dentry)
            if name_issue:
                return "", f"INCOMPLETE:{name_issue}"
            parts.append(name)
            dentry = parent
    except (
        AttributeError, IndexError, TypeError, ValueError,
        exceptions.InvalidAddressException, exceptions.VolatilityException,
    ) as exc:
        return "", f"INCOMPLETE:{type(exc).__name__}"
    return "", "INCOMPLETE:depth-limit"


def _strict_mount_path(root_dentry, root_vfsmnt, dentry, vfsmnt, **kwargs) -> str:
    """Return a complete path to an exact root, or empty on any failed proof."""

    return _walk_mount_path(root_dentry, root_vfsmnt, dentry, vfsmnt, **kwargs)[0]


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
    identities = []
    for path in paths:
        identity = _identify_path(path)
        if identity:
            identities.append(identity)
    # A namespace can see another container's files.  Never pick an arbitrary
    # first ID if the mount evidence contains more than one container/pod.
    for kind in ("container", "pod"):
        candidates = [item for item in identities if item.id_kind == kind]
        if candidates:
            if len({item.identifier for item in candidates}) != 1:
                return None
            return sorted(candidates, key=lambda item: (item.runtime, item.evidence))[0]
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
        if not namespace or not _object_readable(namespace):
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
    """Return a full kernfs path, or no path when ancestry is incomplete.

    A NULL parent is a terminator only at cgroup.root.cgrp.kn.  In particular,
    an unreadable parent is not a root and must not turn a suffix into an
    apparently absolute path.  kernfs used ``parent`` before ``__parent``.
    """

    try:
        if (
            not cgroup
            or not _object_readable(cgroup)
            or not cgroup.has_member("kn")
            or not cgroup.kn
            or not _object_readable(cgroup.kn)
        ):
            return ""
        node = cgroup.kn.dereference()
        root_node = cgroup.root.cgrp.kn
        if not root_node or not _object_readable(root_node):
            raise ValueError("unreadable hierarchy root kernfs node")
        root_address = _object_address(root_node)
    except (AttributeError, TypeError, ValueError, exceptions.InvalidAddressException):
        vollog.warning("Incomplete cgroup path: hierarchy root/node is unavailable")
        return ""

    parts: List[str] = []
    seen = set()
    for _ in range(256):
        try:
            address = _object_address(node)
            if address in seen:
                raise ValueError("cyclic kernfs ancestry")
            seen.add(address)
            parent_member = "__parent" if node.has_member("__parent") else "parent"
            parent = node.member(parent_member)
            if address == root_address:
                if parent:
                    raise ValueError("hierarchy root has a non-NULL parent")
                return "/" + "/".join(reversed(parts))
            if not parent or not _object_readable(parent):
                raise ValueError("kernfs ancestry ended before hierarchy root")
            name = utility.pointer_to_string(node.name, count=256)
            # kernfs names are individual components, at most NAME_MAX bytes.
            # Never normalize corrupt names into a different valid path.
            if not name or len(name) >= 256 or "/" in name or name in {".", ".."}:
                raise ValueError("invalid or truncated kernfs name")
            parts.append(name)
            node = parent.dereference()
        except (
            AttributeError,
            TypeError,
            exceptions.InvalidAddressException,
            ValueError,
        ) as exc:
            vollog.warning("Incomplete cgroup path: %s", exc)
            return ""
    vollog.warning("Incomplete cgroup path: kernfs ancestry exceeds 256 nodes")
    return ""


def _cgroup_hierarchy(cgroup, default_root_address=None):
    """Identify a hierarchy by its root, never by its effective CSS address.

    The default (v2) hierarchy owns hierarchy ID 0.  All active legacy roots
    have positive IDs.  Unknown or inconsistent metadata is not called v1.
    """

    if not cgroup or not _object_readable(cgroup):
        raise ValueError("unreadable cgroup")
    root = cgroup.root
    if not root or not _object_readable(root):
        raise ValueError("unreadable cgroup hierarchy root")
    root_address = _object_address(root)
    hierarchy_id = int(root.hierarchy_id)
    if hierarchy_id < 0:
        raise ValueError("invalid cgroup hierarchy ID")
    is_default = hierarchy_id == 0
    if default_root_address is not None and (
        is_default != (root_address == default_root_address)
    ):
        raise ValueError("inconsistent cgroup default hierarchy root/ID")
    return ("v2" if is_default else "v1"), root_address, root, hierarchy_id


def _linked_cgroups(css_set, issues):
    """Walk actual cgroup memberships, including controllerless v1 roots.

    Volatility's generic list walker silently terminates on unreadable links.
    This bounded walk reports that distinction and validates link ownership.
    """

    groups = []
    try:
        head = css_set.cgrp_links
        context = head._context
        type_name = head.vol.type_name.split("!", 1)[0] + "!cgrp_cset_link"
        offset = context.symbol_space.get_type(type_name).relative_child_offset(
            "cgrp_link"
        )
        head_address = _object_address(head)
        previous = head_address
        link_pointer = head.next
        seen = {head_address}
        for _ in range(4096):
            link_address = _object_address(link_pointer)
            if link_address == head_address:
                if _object_address(head.prev) != previous:
                    raise ValueError("cgrp_links tail disagrees with forward walk")
                return groups, True
            if not link_pointer or not _object_readable(link_pointer):
                raise ValueError("unreadable cgrp_links entry")
            if link_address in seen:
                raise ValueError("cyclic cgrp_links outside list head")
            seen.add(link_address)
            link = context.object(
                type_name, layer_name=head.vol.layer_name,
                offset=link_address - offset,
            )
            if _object_address(link.cset) != _object_address(css_set):
                raise ValueError("cgrp_links entry points to another css_set")
            if _object_address(link.cgrp_link.prev) != previous:
                raise ValueError("cgrp_links backlink mismatch")
            groups.append(link.cgrp)
            previous = link_address
            link_pointer = link.cgrp_link.next
        raise ValueError("cgrp_links exceeds 4096 entries")
    except (
        AttributeError, KeyError, TypeError, ValueError,
        exceptions.SymbolError, exceptions.InvalidAddressException,
    ) as exc:
        issues.add(f"membership list incomplete ({type(exc).__name__}: {exc})")
        return groups, False


def _cgroup_memberships(task, issues_out=None) -> Tuple[CgroupMembership, ...]:
    """Read actual memberships; effective v2 ancestor CSSes are not v1.

    cgrp_links is authoritative across hierarchies, dfl_cgrp is the actual v2
    membership, and subsys[] provides legacy controller names.  A subsys-only
    fallback is accepted solely with a proven v1 root when links are missing.
    Paths are absolute in their hierarchy, not cgroup-namespace-relative.
    issues_out, when supplied, receives stable partial/conflict markers as
    well as diagnostics so callers cannot promote incomplete IDs to verified.
    """

    issues = set()

    def report_issues():
        if not issues:
            return
        issues.add("cgroup-metadata-partial")
        if issues_out is not None:
            issues_out.update(issues)
        try:
            pid = int(task.pid)
        except (AttributeError, TypeError, ValueError, exceptions.InvalidAddressException):
            pid = "?"
        vollog.warning("Incomplete cgroup metadata for PID %s: %s", pid, "; ".join(sorted(issues)))

    try:
        css_set = task.cgroups
        if not css_set or not _object_readable(css_set):
            raise ValueError("missing or unreadable css_set")
    except (AttributeError, TypeError, ValueError, exceptions.InvalidAddressException) as exc:
        issues.add(f"task cgroup metadata unavailable ({exc})")
        report_issues()
        return ()

    default_root_address = None
    groups, links_complete = _linked_cgroups(css_set, issues)
    unified_cgroup = None
    try:
        if css_set.has_member("dfl_cgrp") and css_set.dfl_cgrp:
            unified_cgroup = css_set.dfl_cgrp
            version, root_address, _, _ = _cgroup_hierarchy(unified_cgroup)
            if version != "v2":
                raise ValueError("dfl_cgrp does not belong to hierarchy 0")
            default_root_address = root_address
            groups.append(unified_cgroup)
    except (AttributeError, TypeError, ValueError, exceptions.InvalidAddressException) as exc:
        issues.add(f"default membership unavailable ({exc})")

    # One css_set must have one actual membership per hierarchy.  Reject a
    # conflicting root entirely, rather than choosing the first ID/path.
    entries: Dict[int, Dict[str, object]] = {}
    conflicting_roots = set()
    def add_group(cgroup):
        version, root_address, root, hierarchy_id = _cgroup_hierarchy(
            cgroup, default_root_address
        )
        address = _object_address(cgroup)
        if root_address in entries and entries[root_address]["address"] != address:
            conflicting_roots.add(root_address)
            issues.add("cgroup-id-conflict")
            issues.add("multiple memberships in the same hierarchy")
            return
        entries.setdefault(root_address, {
            "version": version, "root": root, "hierarchy_id": hierarchy_id,
            "address": address, "cgroup": cgroup, "controllers": set(),
        })

    for cgroup in groups:
        try:
            add_group(cgroup)
        except (AttributeError, TypeError, ValueError, exceptions.InvalidAddressException) as exc:
            issues.add(f"hierarchy unavailable ({exc})")

    try:
        subsystems = css_set.subsys if css_set.has_member("subsys") else ()
        subsystem_count = len(subsystems)
    except (AttributeError, TypeError, exceptions.InvalidAddressException):
        subsystems = ()
        subsystem_count = 0
        issues.add("controller array unreadable")
    if subsystem_count > 256:
        issues.add("controller array exceeds 256 entries")
    for index in range(min(subsystem_count, 256)):
        try:
            css_pointer = subsystems[index]
            if not css_pointer:
                continue
            if not _object_readable(css_pointer):
                raise ValueError("unreadable controller state")
            css = css_pointer.dereference()
            cgroup = css.cgroup
            version, root_address, _, _ = _cgroup_hierarchy(
                cgroup, default_root_address
            )
            # v2 effective CSS may belong to any ancestor of dfl_cgrp.  Its
            # address differs from the membership without becoming a v1 root.
            if version == "v2":
                continue
            if root_address not in entries:
                if links_complete:
                    issues.add("controller hierarchy absent from membership list")
                    continue
                add_group(cgroup)
            entry = entries[root_address]
            if entry["address"] != _object_address(cgroup):
                conflicting_roots.add(root_address)
                issues.add("cgroup-id-conflict")
                issues.add("legacy controller disagrees with actual membership")
                continue
            controller = f"subsys-{index}"
            if css.has_member("ss") and css.ss and _object_readable(css.ss):
                subsystem = css.ss.dereference()
                field = "legacy_name" if subsystem.has_member("legacy_name") and subsystem.legacy_name else "name"
                if subsystem.has_member(field) and subsystem.member(field):
                    controller = utility.pointer_to_string(subsystem.member(field), count=64)
            if not controller or len(controller) >= 64:
                raise ValueError("invalid controller name")
            entry["controllers"].add(controller)
        except (
            AttributeError,
            IndexError,
            TypeError,
            ValueError,
            exceptions.InvalidAddressException,
        ) as exc:
            issues.add(f"controller {index} unavailable ({exc})")

    memberships: List[CgroupMembership] = []
    for root_address, entry in sorted(entries.items()):
        if root_address in conflicting_roots:
            continue
        path = _cgroup_path(entry["cgroup"])
        if not path:
            issues.add("one or more hierarchy paths incomplete")
            continue
        if entry["version"] == "v1":
            try:
                root = entry["root"]
                if root.has_member("name"):
                    name = utility.array_to_string(root.name)
                    if name:
                        entry["controllers"].add("name=" + name)
            except (AttributeError, TypeError, ValueError, exceptions.InvalidAddressException):
                issues.add("legacy hierarchy name unreadable")
            if not entry["controllers"]:
                entry["controllers"].add(f"hierarchy-{entry['hierarchy_id']}")
        memberships.append(
            CgroupMembership(
                version=str(entry["version"]),
                controllers=tuple(sorted(entry["controllers"])),
                path=path,
                cgroup_address=int(entry["address"]),
            )
        )
    # Keep the internal default-root membership even alongside v1.  '/' alone
    # cannot distinguish a visible hybrid v2 root from an unused default root;
    # this output does not infer which cgroup filesystems were mounted.
    report_issues()
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
            if not parent or not _object_readable(parent):
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
    is_task_root: bool = False


class HostMountResolver:
    """Resolve complete, unshadowed host paths through init_task's namespace.

    CONFIRMED describes a single visible alias in the collected host topology;
    it does not identify the original bind-mount command or source pathname.
    A partial index or unreadable candidate route prevents confirmation even
    when another complete path was found, because alternatives remain unknown.
    """

    def __init__(self, init_task):
        self._init_task = init_task
        self._host_root_dentry = None
        self._host_root_mnt = None
        self._by_superblock: Dict[int, List[object]] = {}
        self._covering_mounts: Dict[Tuple[int, int], set] = {}
        self._index_complete = False
        try:
            self._host_root_dentry = init_task.fs.get_root_dentry()
            self._host_root_mnt = init_task.fs.get_root_mnt()
            if not all(
                obj and _object_readable(obj)
                for obj in (self._host_root_dentry, self._host_root_mnt)
            ):
                raise ValueError("unreadable host root")
            host_namespace = init_task.nsproxy.mnt_ns
            host_mounts, status = ContainerMounts._mount_points(host_namespace)
            self._index_complete = status == "COMPLETE"
            indexed_vfsmounts = set()
            for host_mnt in host_mounts:
                try:
                    superblock = host_mnt.get_mnt_sb()
                    host_vfsmnt = host_mnt.get_vfsmnt_current()
                    if not all(
                        obj and _object_readable(obj) for obj in (superblock, host_vfsmnt)
                    ):
                        self._index_complete = False
                        continue
                    mount_address = _object_address(host_vfsmnt)
                    if mount_address in indexed_vfsmounts:
                        continue
                    indexed_vfsmounts.add(mount_address)
                    self._by_superblock.setdefault(
                        _object_address(superblock), []
                    ).append(host_mnt)

                    parent_vfsmnt = host_mnt.get_vfsmnt_parent()
                    if not (parent_vfsmnt and _object_readable(parent_vfsmnt)):
                        self._index_complete = False
                        continue
                    parent_address = _object_address(parent_vfsmnt)
                    if parent_address == mount_address:
                        continue
                    mountpoint = host_mnt.get_mnt_mountpoint()
                    if not (mountpoint and _object_readable(mountpoint)):
                        self._index_complete = False
                        continue
                    key = (parent_address, _object_address(mountpoint))
                    self._covering_mounts.setdefault(key, set()).add(mount_address)
                except (
                    AttributeError, TypeError, ValueError,
                    exceptions.InvalidAddressException, exceptions.VolatilityException,
                ):
                    self._index_complete = False
                    continue
            if _object_address(self._host_root_mnt) not in indexed_vfsmounts:
                self._index_complete = False
            if any(parent not in indexed_vfsmounts for parent, _ in self._covering_mounts):
                self._index_complete = False
        except (
            AttributeError, TypeError, ValueError,
            exceptions.InvalidAddressException, exceptions.VolatilityException,
        ) as exc:
            vollog.warning("Host mount namespace index is incomplete: %s", exc)
        if not self._index_complete:
            vollog.warning("Host mount index is incomplete; source confidence is UNKNOWN")

    def resolve(self, mnt) -> SourceResolution:
        try:
            superblock = mnt.get_mnt_sb()
            source_dentry = mnt.get_mnt_root()
            if not (
                superblock
                and _object_readable(superblock)
                and source_dentry
                and _object_readable(source_dentry)
            ):
                return SourceResolution((), SOURCE_UNKNOWN)
            host_mounts = self._by_superblock.get(_object_address(superblock), ())
        except (
            AttributeError, TypeError, ValueError,
            exceptions.InvalidAddressException, exceptions.VolatilityException,
        ):
            return SourceResolution((), SOURCE_UNKNOWN)

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
            ):
                complete = False
                continue

        paths = tuple(sorted(resolved))
        if not paths or not complete:
            return SourceResolution(paths, SOURCE_UNKNOWN)
        if len(paths) == 1:
            return SourceResolution(paths, SOURCE_CONFIRMED)
        return SourceResolution(paths, SOURCE_AMBIGUOUS)


def _bounded_dentry_path(dentry, max_depth: int = 4096) -> str:
    """Filesystem-relative topology, not host visibility or inode liveness.

    Used only for mountinfo's root field.  Follow the complete dentry chain
    even when inode pages are missing, but never return a truncated suffix.
    """

    parts: List[str] = []
    seen = set()
    try:
        for _ in range(max_depth):
            if not (dentry and _object_readable(dentry)):
                return ""
            address = _object_address(dentry)
            if address in seen:
                return ""
            seen.add(address)
            parent = dentry.d_parent
            if not (parent and _object_readable(parent)):
                return ""
            if _object_address(parent) == address:
                return "/" + "/".join(reversed(parts))
            name, issue = _read_dentry_name(dentry)
            if issue:
                return ""
            parts.append(name)
            dentry = parent
    except (
        AttributeError, IndexError, TypeError, ValueError,
        exceptions.InvalidAddressException, exceptions.VolatilityException,
    ):
        return ""
    return ""


def _bounded_dominating_id(mnt, task, max_nodes: int = 4096) -> Optional[int]:
    """Closest reachable master peer-group ID, 0 if absent, None if unknown.

    Follows fs/pnode.c's get_dominating_id ordering.  Peer links are resolved
    with upstream container_of using their *target* address, rather than the
    pointer-field offset used by Volatility 2.28.0's next_peer().  All master,
    peer and path walks are bounded; uncertainty in a closer group prevents
    claiming that a more distant group is the closest dominator.
    """

    try:
        namespace_address = _object_address(mnt.mnt_ns)
        if not namespace_address:
            return None
        root_dentry = task.fs.get_root_dentry()
        root_vfsmnt = task.fs.get_root_mnt()
        current_master = mnt.mnt_master
        master_seen = set()
        visited_nodes = 0
        vmlinux = None
        while current_master:
            if not _object_readable(current_master):
                return None
            master_address = _object_address(current_master)
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
                if visited_nodes >= max_nodes or not (peer and _object_readable(peer)):
                    return None
                visited_nodes += 1
                peer_address = _object_address(peer)
                if peer_address in peer_seen:
                    return None
                peer_seen.add(peer_address)
                if int(peer.mnt_group_id) != group_id:
                    return None
                if _object_address(peer.mnt_ns) == namespace_address:
                    _path, status = _walk_mount_path(
                        root_dentry, root_vfsmnt,
                        peer.get_mnt_root(), peer.get_vfsmnt_current(),
                    )
                    if status == "COMPLETE":
                        return group_id
                    if status.startswith("INCOMPLETE:"):
                        group_uncertain = True

                share = peer.mnt_share
                link = share.next
                if not (link and _object_readable(link)):
                    return None
                if _object_address(link.prev) != _object_address(share):
                    return None
                if _object_address(link) == _object_address(share):
                    if peer_address != master_address:
                        return None
                    break
                if vmlinux is None:
                    vmlinux = linux.LinuxUtilities.get_module_from_volobj_type(
                        mnt._context, mnt,
                    )
                peer = linux.LinuxUtilities.container_of(link, "mount", "mnt_share", vmlinux)
                if _object_address(peer) == master_address:
                    break
            if group_uncertain:
                return None
            current_master = current_master.mnt_master
        return 0
    except (
        AttributeError, IndexError, TypeError, ValueError,
        exceptions.InvalidAddressException, exceptions.VolatilityException,
    ):
        return None


def _read_mount_info(
    mnt, task,
) -> Tuple[Optional[mountinfo.MountInfoData], Tuple[str, ...]]:
    """Read upstream mountinfo fields without its unbounded path traversals.

    Kernel-specific field/flag interpretation stays in pinned upstream object
    getters.  This adapter only assembles MountInfoData and supplies bounded
    paths/propagation.  Optional failures retain readable attributes and are
    returned explicitly instead of discarding the entire mount record.
    """

    issues: List[str] = []
    try:
        superblock = mnt.get_mnt_sb()
        if not (superblock and _object_readable(superblock)):
            return None, ("decode",)
        mnt_id = int(mnt.mnt_id)
        parent_id = int(mnt.mnt_parent.mnt_id)
        st_dev = f"{int(superblock.major)}:{int(superblock.minor)}"
        mnt_opts = [mnt.get_flags_access(), *mnt.get_flags_opts()]
        mnt_type = superblock.get_type()
        devname = mnt.get_devname() or "none"
        sb_opts = [superblock.get_flags_access(), *superblock.get_flags_opts()]
    except (
        AttributeError, IndexError, TypeError, ValueError,
        exceptions.InvalidAddressException, exceptions.VolatilityException,
    ):
        return None, ("decode",)

    container_path = ""
    mount_root_path = ""
    path_status = "INCOMPLETE"
    try:
        root = mnt.get_mnt_root()
        mount_root_path = _bounded_dentry_path(root)
        container_path, path_status = _walk_mount_path(
            task.fs.get_root_dentry(), task.fs.get_root_mnt(),
            root, mnt.get_vfsmnt_current(),
            require_live_inode=False,
        )
    except (
        AttributeError, IndexError, TypeError, ValueError,
        exceptions.InvalidAddressException, exceptions.VolatilityException,
    ):
        pass
    # A detached self-parent namespace sentinel is intentionally outside the
    # task root.  This proven absence is not an unreadable-path failure.
    expected_internal_root = (
        path_status == "OUTSIDE_ROOT" and mnt_id == parent_id
        and mnt_type in INTERNAL_NAMESPACE_ROOT_FSTYPES
    )
    if not container_path and not expected_internal_root:
        issues.append("path")
    if not mount_root_path:
        issues.append("mount-root")

    fields: List[str] = []
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
                dominating_id = _bounded_dominating_id(mnt, task)
                if dominating_id is None:
                    issues.append("propagation")
                elif dominating_id and dominating_id != master_id:
                    fields.append(f"propagate_from:{dominating_id}")
        if mnt.is_unbindable():
            fields.append("unbindable")
    except (
        AttributeError, IndexError, TypeError, ValueError,
        exceptions.InvalidAddressException, exceptions.VolatilityException,
    ):
        issues.append("propagation")

    return mountinfo.MountInfoData(
        mnt_id, parent_id, st_dev, mount_root_path, container_path,
        mnt_opts, fields, mnt_type, devname, sb_opts,
    ), tuple(dict.fromkeys(issues))


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
    *,
    fstype: str,
    identity_verified: bool,
    is_task_root: bool,
) -> bool:
    # The ID must come from independently read cgroup membership, not from
    # this mount path being checked against itself.  Unknown layouts remain
    # visible as REVIEW; a basename alone is never an infrastructure rule.
    if not identity_verified or id_kind != "container" or not container_id:
        return False
    identifier = re.escape(container_id)
    if runtime == "docker":
        expected_names = EXPECTED_RUNTIME_ARTIFACTS.get(container_path, ())
        if container_path.startswith("/etc/") and expected_names:
            names = "|".join(re.escape(name) for name in expected_names)
            return bool(re.fullmatch(
                rf"/var/lib/docker/containers/{identifier}/(?:{names})", host_path
            ))
    if container_path != "/" or not is_task_root:
        return False
    if fstype not in {"overlay", "fuse-overlayfs"}:
        return False
    if runtime == "docker":
        # Docker's older overlay2 layout uses a layer ID, not a container ID.
        # Its root is trusted only together with the task-root and independent
        # cgroup evidence above; do not treat arbitrary */merged as equivalent.
        return bool(re.fullmatch(
            rf"/var/lib/docker/rootfs/overlayfs/{identifier}", host_path
        ) or re.fullmatch(
            rf"/var/lib/docker/overlay2/{_HEX64}/merged", host_path
        ))
    if runtime == "containerd":
        return bool(re.fullmatch(
            rf"/run/containerd/io\.containerd\.runtime\.v[12]\.task/"
            rf"[^/]+/{identifier}/rootfs", host_path
        ))
    return False


def _classify_mount(
    record: MountRecord,
    runtime: str,
    container_id: str = "",
    id_kind: str = "",
    *,
    identity_verified: bool = False,
) -> Tuple[str, str]:
    """Classify one mount without promoting an unproven path to host source."""

    container_path = record.container_path
    fstype = str(record.data.mnt_type)
    access = "쓰기 가능" if record.writable else "읽기 전용"
    source_names = {path.rsplit("/", 1)[-1] for path in record.host_sources}
    target_name = container_path.rsplit("/", 1)[-1]

    if target_name in RUNTIME_SOCKET_NAMES or source_names & RUNTIME_SOCKET_NAMES:
        return RISK_HIGH, "런타임 제어 소켓 경로가 마운트에 포함됨; 접근 가능 여부 확인 필요"

    # Evaluate every complete host path before accepting an infrastructure
    # exception.  A benign runtime alias cannot suppress '/' or another
    # sensitive source in the same result.
    if "/" in record.host_sources:
        return RISK_HIGH, f"호스트 루트 경로가 연결됨 ({access})"

    if (
        int(record.data.mnt_id) == int(record.data.parent_id)
        and fstype in INTERNAL_NAMESPACE_ROOT_FSTYPES
        and not record.is_task_root
        and not record.host_sources
    ):
        return RISK_INFRA, "Mount Namespace 내부 root/sentinel mount"

    if record.host_sources:
        decisions = []
        for host_path in record.host_sources:
            if (
                fstype in {"sysfs", "cgroup", "cgroup2"}
                and record.writable
            ):
                decisions.append((RISK_HIGH, f"호스트와 연결된 {fstype} 마운트가 쓰기 가능함; 실제 권한 확인 필요"))
            elif record.source_confidence != SOURCE_UNKNOWN and _expected_runtime_artifact(
                container_path, host_path, runtime, container_id, id_kind,
                fstype=fstype, identity_verified=identity_verified,
                is_task_root=record.is_task_root,
            ):
                decisions.append((RISK_INFRA, "독립된 컨테이너 ID와 경로가 일치하는 런타임 마운트"))
            elif (
                record.source_confidence != SOURCE_UNKNOWN
                and container_path in STANDARD_API_TARGETS.get(fstype, ())
                and host_path == container_path
                and not record.writable
            ):
                decisions.append((RISK_INFRA, f"표준 경로의 읽기 전용 {fstype} 마운트"))
            elif _runtime_storage_path(host_path):
                decisions.append((RISK_REVIEW, f"런타임 저장소의 데이터 또는 미확인 마운트 ({access})"))
            elif any(_startswith_dir(host_path, prefix) for prefix in SENSITIVE_HOST_PREFIXES):
                decisions.append((RISK_HIGH, f"민감 호스트 경로 {host_path} 연결 ({access})"))
            else:
                decisions.append((RISK_REVIEW, f"호스트 경로 마운트 ({access})"))
        priority = {RISK_INFRA: 0, RISK_REVIEW: 1, RISK_HIGH: 2}
        return max(decisions, key=lambda item: priority[item[0]])

    # Missing source evidence is not a statement that a mount is harmless.
    # Keep unresolved overlay and virtual/control filesystems in default output.
    return RISK_REVIEW, f"호스트 경로 미확인 ({fstype}, {access}); 추가 확인 필요"


class ContainerMounts(plugins.PluginInterface):
    """Find container-backed mount namespaces and inspect their mounts."""

    _required_framework_version = (2, 13, 0)
    _version = (0, 4, 0)

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
                description="Inspect these host PIDs explicitly (manual selection)",
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
                and _object_readable(task.fs)
                and task.nsproxy
                and _object_readable(task.nsproxy)
                and task.nsproxy.mnt_ns
                and _object_readable(task.nsproxy.mnt_ns)
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

        cgroup_issues = set()
        cgroup_memberships = _cgroup_memberships(task, issues_out=cgroup_issues)
        identity, identity_source, identity_conflict = _cgroup_identity(
            cgroup_memberships
        )
        identity_conflict = identity_conflict or "cgroup-id-conflict" in cgroup_issues
        if identity_conflict:
            identity = None
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
        if "cgroup-metadata-partial" in cgroup_issues:
            evidence.append("cgroup-metadata-partial")
            score = min(score, 70)

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
    def _list_mount_points(mnt_ns, max_nodes: int = 100000) -> Tuple[List[object], str]:
        """Collect a legacy namespace list only after proving return to its head.

        Upstream list_head.to_list() silently stops at unreadable/repeated
        links.  Treating that exhaustion as success could hide a covering host
        mount, so validate both link directions and namespace ownership here.
        On corruption the already validated prefix remains available as PARTIAL.
        """

        points: List[object] = []
        try:
            if not (mnt_ns and _object_readable(mnt_ns) and mnt_ns.has_member("list")):
                raise ValueError("missing or unreadable legacy namespace list")
            head = mnt_ns.list
            if not _object_readable(head):
                raise ValueError("unreadable legacy namespace list head")
            context = head._context
            table_name = head.vol.type_name.split("!", 1)[0]
            mount_type = table_name + "!mount"
            if not context.symbol_space.has_type(mount_type):
                mount_type = table_name + "!vfsmount"
            member_offset = context.symbol_space.get_type(mount_type).relative_child_offset(
                "mnt_list"
            )
            namespace_address = _object_address(mnt_ns)
            head_address = _object_address(head)
            previous = head_address
            link_pointer = head.next
            seen = {head_address}
            while True:
                link_address = _object_address(link_pointer)
                if link_address == head_address:
                    if _object_address(head.prev) != previous:
                        raise ValueError("legacy mount-list tail disagrees with forward walk")
                    return points, "COMPLETE"
                if len(points) >= max_nodes:
                    raise ValueError("legacy mount list exceeds node limit")
                if not link_pointer or not _object_readable(link_pointer):
                    raise ValueError("unreadable legacy mount-list entry")
                if link_address in seen:
                    raise ValueError("cyclic legacy mount list outside its head")
                seen.add(link_address)
                link = link_pointer.dereference()
                if _object_address(link.prev) != previous:
                    raise ValueError("legacy mount-list backlink mismatch")
                mount_address = link_address - member_offset
                if mount_address < 0:
                    raise ValueError("invalid legacy mount container address")
                mnt = context.object(
                    mount_type, layer_name=head.vol.layer_name,
                    native_layer_name=head.vol.native_layer_name,
                    offset=mount_address,
                )
                if mnt.has_member("mnt_ns") and _object_address(mnt.mnt_ns) != namespace_address:
                    raise ValueError("legacy mount belongs to another namespace")
                points.append(mnt)
                previous = link_address
                link_pointer = link.next
        except (
            AttributeError, KeyError, IndexError, TypeError, ValueError,
            exceptions.InvalidAddressException, exceptions.VolatilityException,
        ) as exc:
            return points, f"PARTIAL:list-walk:{type(exc).__name__}:{exc}"

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
            return ContainerMounts._list_mount_points(mnt_ns)

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
                if not node_address:
                    continue
                if node_address in seen_nodes:
                    skipped_nodes += 1
                    continue
                if len(seen_nodes) >= 100000:
                    skipped_nodes += 1
                    break
                seen_nodes.add(node_address)
                if not _object_readable(node_pointer):
                    skipped_nodes += 1
                    continue
                node = node_pointer.dereference()

                # Read child pointers before decoding the containing mount so a
                # bad mount object cannot hide otherwise readable subtrees.
                for member in ("rb_right", "rb_left"):
                    try:
                        child = node.member(member)
                        if child:
                            stack.append(child)
                    except (AttributeError, exceptions.InvalidAddressException):
                        skipped_nodes += 1

                mnt = linux.LinuxUtilities.container_of(
                    node_pointer, "mount", "mnt_node", vmlinux
                )
                if mnt is None or (
                    hasattr(mnt, "has_member") and mnt.has_member("mnt_ns")
                    and _object_address(mnt.mnt_ns) != _object_address(mnt_ns)
                ):
                    # A readable RB node can still describe an unrelated mount
                    # after corruption or a bad layout interpretation.  Child
                    # pointers are already queued, so preserve those subtrees.
                    skipped_nodes += 1
                    continue
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
        error_counts: Dict[str, int] = {}
        seen_mounts = set()
        for mnt in mounts:
            try:
                mount_address = _object_address(mnt)
                if mount_address in seen_mounts:
                    continue
                seen_mounts.add(mount_address)
                data, issues = _read_mount_info(mnt, representative.task)
                for issue in issues:
                    error_counts[issue] = error_counts.get(issue, 0) + 1
                if data is None:
                    continue

                is_task_root = (
                    _object_address(mnt.get_vfsmnt_current()) == representative.root_key[0]
                    and _object_address(mnt.get_mnt_root()) == representative.root_key[1]
                )
                is_internal_root = (
                    int(data.mnt_id) == int(data.parent_id)
                    and str(data.mnt_type) in INTERNAL_NAMESPACE_ROOT_FSTYPES
                    and not is_task_root
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
                        container_path=data.path_root,
                        mount_root=data.mnt_root_path,
                        host_sources=source.paths,
                        source_confidence=source.confidence,
                        writable=writable,
                        is_task_root=is_task_root,
                    )
                )
            except (
                AttributeError,
                TypeError,
                ValueError,
                exceptions.InvalidAddressException,
                exceptions.VolatilityException,
            ):
                error_counts["decode"] = error_counts.get("decode", 0) + 1
                continue

        if error_counts:
            suffix = ",".join(f"{name}={count}" for name, count in sorted(error_counts.items()))
            if traversal_status == "COMPLETE":
                traversal_status = f"PARTIAL:{suffix}"
            else:
                traversal_status = f"{traversal_status},{suffix}"
        return records, traversal_status

    @staticmethod
    def _mount_identity(records: Sequence[MountRecord]) -> Optional[Identity]:
        # Mount paths can enrich identity but never independently certify it.
        # Consider all available evidence, so conflicting IDs cannot be hidden
        # by a first-match return or a later fallback.
        paths = [path for record in records for path in record.host_sources]
        for record in records:
            if _runtime_storage_path(record.mount_root):
                paths.append(record.mount_root)
            devname = _clean_path(record.data.devname)
            if _runtime_storage_path(devname):
                paths.append(devname)
        return _identify_paths(paths)

    @staticmethod
    def _namespace_id_conflict(observations: Sequence[TaskObservation]) -> bool:
        if any("cgroup-id-conflict" in item.evidence for item in observations):
            return True
        for kind in ("container", "pod"):
            identifiers = {
                item.identity.identifier for item in observations
                if item.identity and item.identity.id_kind == kind
            }
            if len(identifiers) > 1:
                return True
        return False

    @staticmethod
    def _namespace_identity(
        observations: Sequence[TaskObservation], mount_identity: Optional[Identity]
    ) -> Optional[Identity]:
        if ContainerMounts._namespace_id_conflict(observations):
            return None
        representative = ContainerMounts._representative(observations)
        ordered = [representative] + [item for item in observations if item is not representative]
        identities = [item.identity for item in ordered if item.identity]
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
        conflict = self._namespace_id_conflict(observations)

        if mount_identity:
            score = max(score, 70)
            evidence.add(f"mount-path:{mount_identity.evidence}")
            if identity and identity.id_kind == mount_identity.id_kind and identity.identifier != mount_identity.identifier:
                evidence.add("cgroup-mount-id-mismatch")

        if conflict:
            score = 60
            evidence.add("namespace-id-conflict")
        if "cgroup-metadata-partial" in evidence:
            score = min(score, 70)

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
        if conflict:
            runtimes = {item.runtime for item in observations if item.runtime}
            runtime = next(iter(runtimes)) if len(runtimes) == 1 else ""
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

            root_variants = len({item.root_key for item in observations})
            # Report namespace failures independently of mount-row filtering.
            # Even an empty JSON result must have a diagnostic on stderr.
            if traversal_status != "COMPLETE":
                vollog.warning(
                    "Mount namespace %s (PID %s): %s; decoded=%s. "
                    "Empty/filtered output does not establish absence of mounts.",
                    ns_id, representative.pid, traversal_status, len(records),
                )
            elif not records:
                vollog.warning(
                    "Mount namespace %s (PID %s): no mount records available",
                    ns_id, representative.pid,
                )
            if detection == DETECTION_LOW and not include_candidates:
                continue
            if root_variants > 1:
                vollog.warning(
                    "Mount namespace %s has %s task roots; paths are relative to PID %s",
                    ns_id, root_variants, representative.pid,
                )
            conflict = self._namespace_id_conflict(observations)
            if conflict:
                vollog.warning(
                    "Mount namespace %s has conflicting cgroup identities; "
                    "Container ID is withheld", ns_id,
                )
            identity_verified = bool(
                not conflict and id_kind == "container" and container_id
                and not any("cgroup-metadata-partial" in item.evidence for item in observations)
                and any(
                    item.identity and item.identity.id_kind == "container"
                    and item.identity.identifier == container_id
                    for item in observations
                )
            )
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
                    record, runtime, container_id, id_kind,
                    identity_verified=identity_verified,
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

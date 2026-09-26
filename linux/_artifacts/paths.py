# SPDX-License-Identifier: MIT
"""VFS path and host-alias readers; no container selection or display logic."""

import dataclasses
import logging

from volatility3.framework import exceptions

from . import core as artifact_core
from . import mounts as mount_readers


@dataclasses.dataclass(frozen=True)
class PathPolicy:
    require_truthy: bool = False
    errors: tuple = artifact_core.READ_ERRORS
    root_error: str = "INCOMPLETE:root-or-source"
    route_error: str = "INCOMPLETE:route"
    inode_error: str = "INCOMPLETE:inode"
    attachment_error: str = "INCOMPLETE:attachment"
    mount_root_error: str = "INCOMPLETE:mount-root"
    parent_mount_error: str = "INCOMPLETE:parent-mount"
    parent_dentry_error: str = "INCOMPLETE:parent-dentry"
    name_length_error: str = "invalid-name-length"
    name_size_error: str = "truncated-name"


FILE_PATH = PathPolicy()
MOUNT_PATH = PathPolicy(
    require_truthy=True,
    errors=(
        AttributeError,
        IndexError,
        TypeError,
        ValueError,
        exceptions.InvalidAddressException,
        exceptions.VolatilityException,
    ),
    root_error="INCOMPLETE:unreadable-root-or-source",
    route_error="INCOMPLETE:unreadable-route",
    inode_error="INCOMPLETE:missing-inode",
    attachment_error="INCOMPLETE:missing-attachment",
    mount_root_error="INCOMPLETE:unreadable-mount-root",
    parent_mount_error="INCOMPLETE:unreadable-attachment",
    parent_dentry_error="INCOMPLETE:unreadable-parent",
    name_length_error="invalid-name",
    name_size_error="invalid-name",
)


def read_dentry_name(dentry, *, policy=FILE_PATH):
    """qstr 길이와 실제 이름을 대조한다. 잘린 이름으로 경로를 확정하지 않는다."""
    qname = dentry.d_name
    length = int(qname.len) if qname.has_member("len") else None
    if length is not None and not 1 <= length <= 255:
        return "", policy.name_length_error
    name = qname.name_as_str()
    if (
        not name
        or name in {".", ".."}
        or "/" in name
        or "\ufffd" in name
        or any(ord(char) < 32 or ord(char) == 127 for char in name)
    ):
        return "", "invalid-name"
    encoded_length = len(name.encode("utf-8"))
    if encoded_length > 255:
        return "", policy.name_size_error
    if length is not None and encoded_length != length:
        return "", "truncated-name"
    return name, ""


def walk_mount_path(
    root_dentry,
    root_vfsmnt,
    dentry,
    vfsmnt,
    *,
    max_depth=4096,
    covering_mounts=None,
    require_live_inode=True,
    policy=FILE_PATH,
    diagnostics=None,
):
    """정확한 (mount, dentry) 루트까지 연결된 경로만 반환한다."""

    def readable(obj):
        return (
            not policy.require_truthy or bool(obj)
        ) and artifact_core._object_readable(obj, diagnostics=diagnostics)

    names, visited, permitted_cover = [], set(), None
    crossed_mount = False
    try:
        if not all(readable(obj) for obj in (root_dentry, root_vfsmnt, dentry, vfsmnt)):
            return "", policy.root_error
        root = (
            artifact_core._object_address(root_vfsmnt),
            artifact_core._object_address(root_dentry),
        )
        for _ in range(max_depth):
            if not (readable(dentry) and readable(vfsmnt)):
                return "", policy.route_error
            key = (
                artifact_core._object_address(vfsmnt),
                artifact_core._object_address(dentry),
            )
            if key in visited:
                return "", "INCOMPLETE:cycle"
            visited.add(key)
            if require_live_inode and not readable(dentry.d_inode):
                return "", policy.inode_error
            if covering_mounts is not None:
                covers = covering_mounts.get(key, set())
                if len(covers) > 1:
                    return "", "INCOMPLETE:stacked-attachment"
                if covers and covers != {permitted_cover}:
                    return "", "COVERED"
                if permitted_cover is not None and permitted_cover not in covers:
                    return "", policy.attachment_error
            permitted_cover = None
            if key == root:
                return "/" + "/".join(reversed(names)), "COMPLETE"
            mount_root = vfsmnt.get_mnt_root()
            if not readable(mount_root):
                return "", policy.mount_root_error
            if key[1] == artifact_core._object_address(mount_root):
                # unlink된 파일도 bind의 루트라면 그 bind 경로는 살아 있을 수 있다.
                parent_mount = vfsmnt.get_vfsmnt_parent()
                attachment = vfsmnt.get_mnt_mountpoint()
                if not (readable(parent_mount) and readable(attachment)):
                    return "", policy.parent_mount_error
                if artifact_core._object_address(parent_mount) == key[0]:
                    return "", "OUTSIDE_ROOT"
                permitted_cover, crossed_mount = key[0], True
                dentry, vfsmnt = attachment, parent_mount
                continue
            parent = dentry.d_parent
            if not readable(parent):
                return "", policy.parent_dentry_error
            if artifact_core._object_address(parent) == key[1]:
                return "", "OUTSIDE_ROOT" if crossed_mount else "OUTSIDE_MOUNT"
            if require_live_inode and not artifact_core._object_address(
                dentry.d_hash.pprev
            ):
                return "", "UNLINKED"
            name, issue = read_dentry_name(dentry, policy=policy)
            if issue:
                return "", "INCOMPLETE:" + issue
            names.append(name)
            dentry = parent
    except policy.errors as exc:
        artifact_core.record_read_error(diagnostics, "path.walk", exc)
        return "", "INCOMPLETE:" + type(exc).__name__
    return "", "INCOMPLETE:depth-limit"


@dataclasses.dataclass(frozen=True)
class SourceResolution:
    paths: tuple
    status: str


class FileHostMountResolver:
    """파일 dentry를 입력받아 캡처된 호스트 마운트의 보이는 별칭을 찾는다."""

    def __init__(self, host_task, *, logger=None, diagnostics=None):
        self.diagnostics = diagnostics
        self.root_dentry = self.root_mount = None
        self.by_superblock, self.covering = {}, {}
        self.complete = False
        try:
            self.root_dentry = host_task.fs.get_root_dentry()
            self.root_mount = host_task.fs.get_root_mnt()
            if not (
                artifact_core._object_readable(
                    self.root_dentry, diagnostics=diagnostics
                )
                and artifact_core._object_readable(
                    self.root_mount, diagnostics=diagnostics
                )
            ):
                raise ValueError("unreadable host root")
            points, state = mount_readers.file_mount_points(
                host_task.nsproxy.mnt_ns, diagnostics=diagnostics
            )
            self.complete = state == "COMPLETE"
            indexed = set()
            for mnt in points:
                try:
                    current, superblock = (
                        mount_readers.mount_current(mnt),
                        mnt.get_mnt_sb(),
                    )
                    if not (
                        artifact_core._object_readable(current, diagnostics=diagnostics)
                        and artifact_core._object_readable(
                            superblock, diagnostics=diagnostics
                        )
                    ):
                        raise ValueError("unreadable mount")
                    address = artifact_core._object_address(current)
                    if address in indexed:
                        continue
                    indexed.add(address)
                    self.by_superblock.setdefault(
                        artifact_core._object_address(superblock), []
                    ).append(current)
                    parent = mnt.get_vfsmnt_parent()
                    if not artifact_core._object_readable(
                        parent, diagnostics=diagnostics
                    ):
                        raise ValueError("unreadable parent")
                    if artifact_core._object_address(parent) != address:
                        point = mnt.get_mnt_mountpoint()
                        if not artifact_core._object_readable(
                            point, diagnostics=diagnostics
                        ):
                            raise ValueError("unreadable attachment")
                        key = (
                            artifact_core._object_address(parent),
                            artifact_core._object_address(point),
                        )
                        self.covering.setdefault(key, set()).add(address)
                except artifact_core.READ_ERRORS as exc:
                    artifact_core.record_read_error(
                        diagnostics, "host_mount.index", exc
                    )
                    self.complete = False
            if artifact_core._object_address(self.root_mount) not in indexed:
                self.complete = False
            if any(parent not in indexed for parent, _ in self.covering):
                self.complete = False
        except artifact_core.READ_ERRORS as exc:
            artifact_core.record_read_error(diagnostics, "host_mount.setup", exc)
            self.complete = False
        if not self.complete:
            (logger or logging.getLogger(__name__)).warning(
                "Host mount topology incomplete; host aliases may be PARTIAL"
            )

    def resolve(self, dentry, vfsmnt, *, diagnostics=None):
        if diagnostics is None:
            diagnostics = self.diagnostics
        try:
            if not (
                artifact_core._object_readable(dentry, diagnostics=diagnostics)
                and artifact_core._object_readable(vfsmnt, diagnostics=diagnostics)
            ):
                raise ValueError("unreadable file path")
            superblock = vfsmnt.get_mnt_sb()
            if not artifact_core._object_readable(superblock, diagnostics=diagnostics):
                raise ValueError("unreadable superblock")
            if artifact_core._object_address(
                dentry.d_sb
            ) != artifact_core._object_address(superblock):
                raise ValueError("file/mount superblock mismatch")
            candidates = self.by_superblock.get(
                artifact_core._object_address(superblock), ()
            )
        except artifact_core.READ_ERRORS as exc:
            artifact_core.record_read_error(diagnostics, "host_mount.resolve", exc)
            return SourceResolution((), "PARTIAL")
        paths, complete = set(), self.complete
        for candidate in candidates:
            path, state = walk_mount_path(
                self.root_dentry,
                self.root_mount,
                dentry,
                candidate,
                covering_mounts=self.covering,
                diagnostics=diagnostics,
            )
            if state == "COMPLETE":
                paths.add(path)
            elif state.startswith("INCOMPLETE:"):
                complete = False
        result = tuple(sorted(paths))
        if not complete:
            return SourceResolution(result, "PARTIAL")
        return SourceResolution(
            result,
            "UNRESOLVED"
            if not result
            else "SINGLE"
            if len(result) == 1
            else "MULTIPLE",
        )

"""Recover file-table slots and VFS facts for the --inspect-files analysis.
The readers isolate per-FD failures and decode access, inode, and dentry-name state.
Discovered descriptors survive incomplete path or optional metadata reads.

SPDX-License-Identifier: MIT
"""

from __future__ import annotations

import collections
import dataclasses

from . import core as artifact_core
from . import paths as path_readers

FMODE_PATH = 0x4000
O_PATH = 0x200000
O_TMPFILE_BIT = 0x400000
DCACHE_DISCONNECTED = 0x20
MAX_FDS = 1048576


def access_mode(filp, *, diagnostics=None):
    """Read this open file's access mode rather than inode.i_mode permissions."""
    try:
        mode = int(filp.f_mode)
        if mode & FMODE_PATH:
            return "PATH"
        return {0: "NONE", 1: "R", 2: "W", 3: "RW"}[mode & 3]
    except artifact_core.READ_ERRORS as exc:
        artifact_core.record_read_error(diagnostics, "file.f_mode", exc)
        try:
            flags = int(filp.f_flags)
            if flags & O_PATH:
                return "PATH"
            return {0: "R", 1: "W", 2: "RW"}.get(flags & 3, "UNKNOWN")
        except artifact_core.READ_ERRORS as exc:
            artifact_core.record_read_error(diagnostics, "file.f_flags", exc)
            return "UNKNOWN"


def name_state(dentry, inode, file_flags, fs_type, *, diagnostics=None):
    """Describe current name linkage without treating i_nlink == 0 as a deletion event."""
    if fs_type in {"sockfs", "pipefs"}:
        return "N/A"
    if fs_type == "anon_inodefs":
        return "ANONYMOUS"
    try:
        if not (
            dentry
            and artifact_core._object_readable(dentry, diagnostics=diagnostics)
            and inode
            and artifact_core._object_readable(inode, diagnostics=diagnostics)
        ):
            return "UNKNOWN"
        parent_address = artifact_core._object_address(dentry.d_parent)
        if not parent_address:
            return "UNKNOWN"
        address = artifact_core._object_address(dentry)
        hashed = bool(artifact_core._object_address(dentry.d_hash.pprev))
        if parent_address == address:


            if int(inode.i_nlink) == 0:
                return "NAMELESS"
            return "ROOT"
        if hashed:
            return "LINKED"

        if file_flags is not None and file_flags & O_TMPFILE_BIT:
            return "NAMELESS"
        if int(dentry.d_flags) & DCACHE_DISCONNECTED:
            return "NAMELESS"
        if file_flags is None:

            return "UNKNOWN"

        return "UNLINKED"
    except artifact_core.READ_ERRORS as exc:
        artifact_core.record_read_error(diagnostics, "file.name_state", exc)
        return "UNKNOWN"


def scan_fd_array(array, count, *, diagnostics=None):
    """Isolate slot reads so one page fault does not hide later file descriptors."""
    entries, issues = [], collections.Counter()
    for fd in range(count):
        try:
            filp = array[fd]


            if artifact_core._object_address(filp):
                entries.append((fd, filp))
        except artifact_core.READ_ERRORS as exc:
            issues["fd-slot-unreadable"] += 1
            artifact_core.record_read_error(diagnostics, "fd_slot", exc, fd=fd)
    return entries, issues


@dataclasses.dataclass
class FileFacts:
    """Facts read once per struct file; task-relative paths are calculated separately."""

    access: str = "UNKNOWN"
    kind: str = "UNKNOWN"
    state: str = "UNKNOWN"
    fs_type: str = ""
    dentry: object = None
    vfsmnt: object = None
    inode: object = None
    inode_number: int | None = None
    nlink: int | None = None
    file_flags: int | None = None
    raw_mode: int | None = None
    host_paths: tuple = ()
    host_status: str = "PARTIAL"
    special_name: str = ""
    issues: set = dataclasses.field(default_factory=set)
    diagnostics: list = dataclasses.field(default_factory=list)


def file_facts(filp, resolver):
    """Preserve a discovered FD even when a path or optional field is damaged."""
    result = FileFacts()
    if not artifact_core._object_readable(filp, diagnostics=result.diagnostics):
        result.issues.add("file-unreadable")
        return result
    result.access = access_mode(filp, diagnostics=result.diagnostics)
    if result.access == "UNKNOWN":
        result.issues.add("access")
    for member, target in (("f_flags", "file_flags"), ("f_mode", "raw_mode")):
        try:
            setattr(result, target, int(getattr(filp, member)))
        except artifact_core.READ_ERRORS as exc:
            result.issues.add(member)
            artifact_core.record_read_error(result.diagnostics, "file." + member, exc)
    try:
        result.inode = filp.get_inode()
        if not (
            result.inode
            and artifact_core._object_readable(
                result.inode, diagnostics=result.diagnostics
            )
        ):
            raise ValueError("unreadable inode")
        result.kind = result.inode.get_inode_type() or "UNKNOWN"
        result.inode_number = int(result.inode.i_ino)
        result.nlink = int(result.inode.i_nlink)
    except artifact_core.READ_ERRORS as exc:
        result.issues.add("inode")
        artifact_core.record_read_error(result.diagnostics, "file.inode", exc)
    try:
        result.dentry = filp.get_dentry()
        result.vfsmnt = filp.get_vfsmnt()
        if not (
            artifact_core._object_readable(
                result.dentry, diagnostics=result.diagnostics
            )
            and artifact_core._object_readable(
                result.vfsmnt, diagnostics=result.diagnostics
            )
        ):
            raise ValueError("unreadable f_path")
        superblock = result.vfsmnt.get_mnt_sb()
        if not artifact_core._object_readable(
            superblock, diagnostics=result.diagnostics
        ):
            raise ValueError("unreadable superblock")
        result.fs_type = artifact_core.read_file_cstring(superblock.s_type.name, 256)


        if artifact_core._object_address(
            result.dentry.d_sb
        ) != artifact_core._object_address(superblock):
            raise ValueError("dentry/mount superblock mismatch")
        if result.inode and (
            artifact_core._object_address(result.inode)
            != artifact_core._object_address(result.dentry.d_inode)
        ):
            raise ValueError("file/dentry inode mismatch")
    except artifact_core.READ_ERRORS as exc:
        result.issues.add("f-path-or-superblock")
        artifact_core.record_read_error(result.diagnostics, "file.f_path", exc)

        result.dentry = None
        result.vfsmnt = None

    result.state = name_state(
        result.dentry,
        result.inode,
        result.file_flags,
        result.fs_type,
        diagnostics=result.diagnostics,
    )
    if result.state == "UNKNOWN":
        result.issues.add("name-state")



    if result.fs_type in {"sockfs", "pipefs", "anon_inodefs"}:
        if result.fs_type in {"sockfs", "pipefs"}:
            prefix = "socket" if result.fs_type == "sockfs" else "pipe"
            number = result.inode_number if result.inode_number is not None else "?"
            result.special_name = f"{prefix}:[{number}]"
        else:
            if result.kind == "UNKNOWN" and "inode" not in result.issues:
                result.kind = "ANON"
            try:
                name, issue = path_readers.read_dentry_name(result.dentry)
                result.special_name = "anon_inode:" + (name if not issue else "?")
                if issue:
                    result.issues.add("anonymous-name")
            except artifact_core.READ_ERRORS as exc:
                result.special_name = "anon_inode:?"
                result.issues.add("anonymous-name")
                artifact_core.record_read_error(
                    result.diagnostics, "file.anonymous_name", exc
                )
        result.host_status = "N/A"
        return result

    if result.dentry is not None and result.vfsmnt is not None:

        resolution = resolver.resolve(
            result.dentry, result.vfsmnt, diagnostics=result.diagnostics
        )
        result.host_paths = resolution.paths
        result.host_status = resolution.status
        if resolution.status == "PARTIAL":
            result.issues.add("host-path")
    return result


def container_path(task, facts, covering, index_complete, *, diagnostics=None):
    """Keep current paths, unlinked paths, and residual basenames semantically distinct."""
    if facts.special_name:
        return facts.special_name, "N/A"
    if facts.dentry is None or facts.vfsmnt is None:
        return "", "PARTIAL"
    try:
        if facts.state == "NAMELESS":

            name, issue = path_readers.read_dentry_name(facts.dentry)
            return ("name:" + name, "NAME_ONLY") if not issue else ("", "PARTIAL")
        root_dentry, root_mnt = task.fs.get_root_dentry(), task.fs.get_root_mnt()
        path, status = path_readers.walk_mount_path(
            root_dentry,
            root_mnt,
            facts.dentry,
            facts.vfsmnt,
            covering_mounts=covering,
            diagnostics=diagnostics,
        )
        if status == "COMPLETE":
            if index_complete:
                return path, "COMPLETE"
            return path + " [visibility unknown]", "PARTIAL"
        if status == "INCOMPLETE:attachment" and index_complete:





            _, topology_status = path_readers.walk_mount_path(
                root_dentry,
                root_mnt,
                facts.dentry,
                facts.vfsmnt,
                require_live_inode=True,
                diagnostics=diagnostics,
            )
            if topology_status == "OUTSIDE_ROOT":
                status = "OUTSIDE_ROOT"


        residual, residual_status = path_readers.walk_mount_path(
            root_dentry,
            root_mnt,
            facts.dentry,
            facts.vfsmnt,
            require_live_inode=False,
            diagnostics=diagnostics,
        )
        if residual_status == "COMPLETE":
            if status == "UNLINKED":
                return residual + " [unlinked path]", "UNLINKED"
            if status == "COVERED":
                return residual + " [covered]", "COVERED"
            return residual + " [visibility unknown]", "PARTIAL"
        name, issue = path_readers.read_dentry_name(facts.dentry)
        if not issue:

            return "name:" + name, (
                "PARTIAL" if status.startswith("INCOMPLETE:") else "NAME_ONLY"
            )
        return "", "PARTIAL" if status.startswith("INCOMPLETE:") else "UNRESOLVED"
    except artifact_core.READ_ERRORS as exc:
        artifact_core.record_read_error(diagnostics, "container_path", exc)
        return "", "PARTIAL"


def read_fds(context, kernel_name, task, limit=65536, *, diagnostics=None):
    issues = collections.Counter()
    try:
        files = task.files
        if not (
            files and artifact_core._object_readable(files, diagnostics=diagnostics)
        ):
            raise ValueError("unreadable files_struct")
        descriptor_table = files.fdt if files.has_member("fdt") else files
        count = int(descriptor_table.max_fds)
        if count < 0 or count > MAX_FDS:

            raise ValueError("unsupported/corrupt max_fds")
        if count == 0:
            return [], issues
        if count > limit:
            issues["fd-limit-skipped-slots"] = count - limit
            count = limit



        base_pointer = descriptor_table.fd
        base_address = artifact_core._object_address(base_pointer)
        if not base_address:
            raise ValueError("null fd array")
        kernel = context.modules[kernel_name]
        subtype = context.symbol_space.get_type(
            kernel.symbol_table_name + "!pointer"
        ).clone()
        subtype.update_vol(
            subtype=context.symbol_space.get_type(kernel.symbol_table_name + "!file")
        )


        array = context.object(
            kernel.symbol_table_name + "!array",
            count=count,
            subtype=subtype,
            offset=base_address,
            layer_name=base_pointer.vol.native_layer_name,
            native_layer_name=base_pointer.vol.native_layer_name,
        )
        entries, slot_issues = scan_fd_array(array, count, diagnostics=diagnostics)
        issues.update(slot_issues)
        return entries, issues
    except artifact_core.READ_ERRORS as exc:
        issues["fd-table"] += 1
        artifact_core.record_read_error(diagnostics, "fd_table", exc)
        return [], issues

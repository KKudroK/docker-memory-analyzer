# SPDX-License-Identifier: MIT
"""File-table slots and VFS facts; callers own task selection, caches and output."""

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


def access_mode(filp):
    """inode.i_mode(권한)가 아닌 이 열린 file의 접근 모드를 읽는다."""
    try:
        mode = int(filp.f_mode)
        if mode & FMODE_PATH:
            return "PATH"
        return {0: "NONE", 1: "R", 2: "W", 3: "RW"}[mode & 3]
    except artifact_core.READ_ERRORS:
        try:
            flags = int(filp.f_flags)
            if flags & O_PATH:
                return "PATH"
            return {0: "R", 1: "W", 2: "RW"}.get(flags & 3, "UNKNOWN")
        except artifact_core.READ_ERRORS:
            return "UNKNOWN"


def name_state(dentry, inode, file_flags, fs_type):
    """이름의 현재 연결만 설명한다. i_nlink == 0을 삭제 사건으로 해석하지 않는다."""
    if fs_type in {"sockfs", "pipefs"}:
        return "N/A"
    if fs_type == "anon_inodefs":
        return "ANONYMOUS"
    try:
        if not (
            dentry
            and artifact_core._object_readable(dentry)
            and inode
            and artifact_core._object_readable(inode)
        ):
            return "UNKNOWN"
        parent_address = artifact_core._object_address(dentry.d_parent)
        if not parent_address:
            return "UNKNOWN"
        address = artifact_core._object_address(dentry)
        hashed = bool(artifact_core._object_address(dentry.d_hash.pprev))
        if parent_address == address:
            # memfd와 anonymous dentry도 self-parent일 수 있다. 파일시스템
            # 루트인지 여부는 경로 판독에서 확인하고 여기서는 링크 수를 함께 본다.
            if int(inode.i_nlink) == 0:
                return "NAMELESS"
            return "ROOT"
        if hashed:
            return "LINKED"
        # O_TMPFILE로 열린 후 linkat으로 연결했다면 hashed가 먼저 적용된다.
        if file_flags is not None and file_flags & O_TMPFILE_BIT:
            return "NAMELESS"
        if int(dentry.d_flags) & DCACHE_DISCONNECTED:
            return "NAMELESS"
        if file_flags is None:
            # O_TMPFILE 여부를 못 읽었다면 never-linked 파일을 배제할 수 없다.
            return "UNKNOWN"
        # 양의 i_nlink라도 해당 이름은 unlink되었을 수 있다(다른 hardlink).
        return "UNLINKED"
    except artifact_core.READ_ERRORS:
        return "UNKNOWN"


def scan_fd_array(array, count):
    """한 슬롯의 page fault 때문에 뒤쪽 FD까지 사라지지 않도록 분리해서 읽는다."""
    entries, issues = [], collections.Counter()
    for fd in range(count):
        try:
            filp = array[fd]
            # 슬롯 자체가 안 읽히면 open/closed 여부조차 알 수 없다. 가짜 FD
            # 행을 만들지 않고 누락 슬롯 수를 전체 판독 상태에 남긴다.
            if artifact_core._object_address(filp):
                entries.append((fd, filp))
        except artifact_core.READ_ERRORS:
            issues["fd-slot-unreadable"] += 1
    return entries, issues


@dataclasses.dataclass
class FileFacts:
    """동일 struct file에서 한 번만 읽는 정보. 태스크별 경로는 따로 계산한다."""

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


def file_facts(filp, resolver):
    """경로/선택 필드 하나가 손상되어도 이미 발견한 FD 행은 보존한다."""
    result = FileFacts()
    if not artifact_core._object_readable(filp):
        result.issues.add("file-unreadable")
        return result
    result.access = access_mode(filp)
    if result.access == "UNKNOWN":
        result.issues.add("access")
    for member, target in (("f_flags", "file_flags"), ("f_mode", "raw_mode")):
        try:
            setattr(result, target, int(getattr(filp, member)))
        except artifact_core.READ_ERRORS:
            result.issues.add(member)
    try:
        result.inode = filp.get_inode()
        if not (result.inode and artifact_core._object_readable(result.inode)):
            raise ValueError("unreadable inode")
        result.kind = result.inode.get_inode_type() or "UNKNOWN"
        result.inode_number = int(result.inode.i_ino)
        result.nlink = int(result.inode.i_nlink)
    except artifact_core.READ_ERRORS:
        result.issues.add("inode")
    try:
        result.dentry = filp.get_dentry()
        result.vfsmnt = filp.get_vfsmnt()
        if not (
            artifact_core._object_readable(result.dentry)
            and artifact_core._object_readable(result.vfsmnt)
        ):
            raise ValueError("unreadable f_path")
        superblock = result.vfsmnt.get_mnt_sb()
        if not artifact_core._object_readable(superblock):
            raise ValueError("unreadable superblock")
        result.fs_type = artifact_core.read_file_cstring(superblock.s_type.name, 256)
        # 동일 주소공간의 VFS 객체 관계만 비교한다. 경로 문자열 접두어를
        # 바꾸거나 overlay의 upper/lower 파일을 추측해서 만들지 않는다.
        if artifact_core._object_address(
            result.dentry.d_sb
        ) != artifact_core._object_address(superblock):
            raise ValueError("dentry/mount superblock mismatch")
        if result.inode and (
            artifact_core._object_address(result.inode)
            != artifact_core._object_address(result.dentry.d_inode)
        ):
            raise ValueError("file/dentry inode mismatch")
    except artifact_core.READ_ERRORS:
        result.issues.add("f-path-or-superblock")
        # 관계 불일치로 얻은 객체를 경로 확정에 사용하지 않는다.
        result.dentry = None
        result.vfsmnt = None

    result.state = name_state(
        result.dentry, result.inode, result.file_flags, result.fs_type
    )
    if result.state == "UNKNOWN":
        result.issues.add("name-state")

    # 소켓/파이프는 경로가 없는 FD의 일반적인 사례다. 일반 파일이 삭제된
    # 것처럼 보이지 않도록 filesystem 유형으로 구분하며 소켓 통신은 분석하지 않는다.
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
            except artifact_core.READ_ERRORS:
                result.special_name = "anon_inode:?"
                result.issues.add("anonymous-name")
        result.host_status = "N/A"
        return result

    if result.dentry is not None and result.vfsmnt is not None:
        # UNLINKED라도 살아 있는 bind mount alias가 남을 수 있다. 일괄 제외하지 않는다.
        resolution = resolver.resolve(result.dentry, result.vfsmnt)
        result.host_paths = resolution.paths
        result.host_status = resolution.status
        if resolution.status == "PARTIAL":
            result.issues.add("host-path")
    return result


def container_path(task, facts, covering, index_complete):
    """현재 경로, 이름 연결이 끊긴 경로, 잔존 basename을 혼동하지 않는다."""
    if facts.special_name:
        return facts.special_name, "N/A"
    if facts.dentry is None or facts.vfsmnt is None:
        return "", "PARTIAL"
    try:
        if facts.state == "NAMELESS":
            # 처음부터 이름 없이 열린 파일에 과거의 절대경로를 만들어 붙이지 않는다.
            name, issue = path_readers.read_dentry_name(facts.dentry)
            return ("name:" + name, "NAME_ONLY") if not issue else ("", "PARTIAL")
        root_dentry, root_mnt = task.fs.get_root_dentry(), task.fs.get_root_mnt()
        path, status = path_readers.walk_mount_path(
            root_dentry,
            root_mnt,
            facts.dentry,
            facts.vfsmnt,
            covering_mounts=covering,
        )
        if status == "COMPLETE":
            if index_complete:
                return path, "COMPLETE"
            return path + " [visibility unknown]", "PARTIAL"
        if status == "INCOMPLETE:attachment" and index_complete:
            # 다른 namespace의 FD는 정상 연결이어도 현재 namespace의 covering
            # 인덱스에 없다. 가시성 검사만 제외하고 살아 있는 inode/부모 연결을
            # 다시 따라가, 실제로 task.fs.root 밖임이 확인될 때만 구분한다.
            # require_live_inode=False인 아래 residual 결과로 정상화하면 실제
            # inode 판독 실패나 unlink를 숨길 수 있으므로 별도로 검증한다.
            _, topology_status = path_readers.walk_mount_path(
                root_dentry,
                root_mnt,
                facts.dentry,
                facts.vfsmnt,
                require_live_inode=True,
            )
            if topology_status == "OUTSIDE_ROOT":
                status = "OUTSIDE_ROOT"
        # 삭제/overmount/분리된 mount여도 FD는 남을 수 있다. 끝까지 따라간
        # 연결만 보조 표시하고 현재 열 수 있는 경로처럼 취급하지 않는다.
        residual, residual_status = path_readers.walk_mount_path(
            root_dentry,
            root_mnt,
            facts.dentry,
            facts.vfsmnt,
            require_live_inode=False,
        )
        if residual_status == "COMPLETE":
            if status == "UNLINKED":
                return residual + " [unlinked path]", "UNLINKED"
            if status == "COVERED":
                return residual + " [covered]", "COVERED"
            return residual + " [visibility unknown]", "PARTIAL"
        name, issue = path_readers.read_dentry_name(facts.dentry)
        if not issue:
            # task.fs.root를 벗어난 FD나 memfd의 이름을 임의의 절대경로로 만들지 않는다.
            return "name:" + name, (
                "PARTIAL" if status.startswith("INCOMPLETE:") else "NAME_ONLY"
            )
        return "", "PARTIAL" if status.startswith("INCOMPLETE:") else "UNRESOLVED"
    except artifact_core.READ_ERRORS:
        return "", "PARTIAL"


def read_fds(context, kernel_name, task, limit=65536):
    issues = collections.Counter()
    try:
        files = task.files
        if not (files and artifact_core._object_readable(files)):
            raise ValueError("unreadable files_struct")
        descriptor_table = files.fdt if files.has_member("fdt") else files
        count = int(descriptor_table.max_fds)
        if count < 0 or count > MAX_FDS:
            # 사용자 순회 상한 초과와 손상이 의심되는 큰 값을 구분한다.
            raise ValueError("unsupported/corrupt max_fds")
        if count == 0:
            return [], issues
        if count > limit:
            issues["fd-limit-skipped-slots"] = count - limit
            count = limit
        # fd는 file **이다. get_fds().dereference 결과를 int()로 검사하면
        # 배열 주소가 아닌 fd[0] 값을 검사하게 된다. stdin이 닫혔거나 첫
        # 슬롯 페이지가 누락되어도 뒤의 FD는 읽을 수 있어야 한다.
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
        # Array 자체를 만들 때는 슬롯을 읽지 않는다. 각 포인터의 판독은
        # _scan_fd_array에서 개별적으로 수행한다.
        array = context.object(
            kernel.symbol_table_name + "!array",
            count=count,
            subtype=subtype,
            offset=base_address,
            layer_name=base_pointer.vol.native_layer_name,
            native_layer_name=base_pointer.vol.native_layer_name,
        )
        entries, slot_issues = scan_fd_array(array, count)
        issues.update(slot_issues)
        return entries, issues
    except artifact_core.READ_ERRORS:
        issues["fd-table"] += 1
        return [], issues

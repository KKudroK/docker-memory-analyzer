# SPDX-License-Identifier: MIT
"""컨테이너의 열린 FD와 파일 경로를 읽는 Volatility 3 플러그인.

대상 환경: Volatility 3 2.28.0, Intel Linux, 덤프와 일치하는 kernel ISF.
다른 팀 플러그인을 import하지 않는 단일 파일이다. cgroup 소속, 마운트
목록, 파일 경로를 이 파일의 판독기로 읽고 Volatility 공식 API만 사용한다.

실행 예시 (전역 옵션은 플러그인 이름 앞):
    vol -p . -s SYMBOLS -f MEMORY inspect_files.InspectFiles
    vol -p . -s SYMBOLS -f MEMORY inspect_files.InspectFiles --view hosts
    vol -p . -s SYMBOLS -f MEMORY inspect_files.InspectFiles --view details
    vol -p . -s SYMBOLS -f MEMORY inspect_files.InspectFiles --pids 4283

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

from collections import Counter
from dataclasses import dataclass, field
import logging
import re
from typing import Optional

from volatility3.framework import exceptions, interfaces, renderers
from volatility3.framework.configuration import requirements
from volatility3.framework.interfaces import plugins
from volatility3.framework.objects import utility
from volatility3.framework.symbols import linux
from volatility3.plugins.linux import pslist


vollog = logging.getLogger(__name__)
READ_ERRORS = (
    AttributeError, IndexError, KeyError, TypeError, ValueError,
    exceptions.InvalidAddressException, exceptions.VolatilityException,
)
# Linux include/linux/fs.h 및 Intel asm-generic/fcntl.h의 비트 값.
FMODE_PATH = 0x4000
O_PATH = 0x200000
O_TMPFILE_BIT = 0x400000
DCACHE_DISCONNECTED = 0x20
MAX_FDS = 1048576
MAX_TASKS = 1000000


# 메모리·마운트 판독: 이 파일의 로컬 함수로 직접 처리한다.

def _object_address(obj):
    """포인터는 가리키는 주소, 구조체는 자기 주소를 반환한다."""
    try:
        return int(obj)
    except (TypeError, ValueError):
        return int(obj.vol.offset)


def _object_readable(obj):
    try:
        if obj is None:
            return False
        pointer_check = getattr(obj, "is_readable", None)
        if callable(pointer_check):
            return bool(obj) and bool(pointer_check())
        return bool(obj._context.layers[obj.vol.layer_name].is_valid(
            int(obj.vol.offset), int(obj.vol.size)
        ))
    except READ_ERRORS:
        return False


def _read_kernel_cstring(pointer, max_bytes=4096, *, allow_empty=False):
    """NUL까지 실제로 읽은 문자열만 채택한다. 누락 페이지를 0으로 채우지 않는다."""
    address = _object_address(pointer)
    if not address or max_bytes <= 0:
        raise ValueError("invalid string address/bound")
    layer = pointer._context.layers[pointer.vol.native_layer_name]
    result = bytearray()
    while len(result) < max_bytes:
        size = min(64, max_bytes - len(result))
        try:
            part = layer.read(address + len(result), size, pad=False)
        except exceptions.InvalidAddressException:
            size = 1
            part = layer.read(address + len(result), size, pad=False)
        if len(part) != size:
            raise ValueError("short string read")
        end = part.find(b"\0")
        if end >= 0:
            result.extend(part[:end])
            if not result and not allow_empty:
                raise ValueError("empty string")
            return bytes(result).decode("utf-8", errors="strict")
        result.extend(part)
    raise ValueError("unterminated string")


def _read_dentry_name(dentry):
    """qstr 길이와 실제 이름을 대조한다. 잘린 이름으로 경로를 확정하지 않는다."""
    qname = dentry.d_name
    length = int(qname.len) if qname.has_member("len") else None
    if length is not None and not 1 <= length <= 255:
        return "", "invalid-name-length"
    name = qname.name_as_str()
    if (not name or name in {".", ".."} or "/" in name or "\ufffd" in name
            or any(ord(char) < 32 or ord(char) == 127 for char in name)):
        return "", "invalid-name"
    encoded_length = len(name.encode("utf-8"))
    if encoded_length > 255 or length is not None and encoded_length != length:
        return "", "truncated-name"
    return name, ""


def _mount_current(mnt):
    """현대 커널은 mount.mnt, 옛 커널은 vfsmount 자체가 현재 마운트다."""
    if mnt.has_member("mnt"):
        return mnt.mnt
    if str(getattr(mnt.vol, "type_name", "")).endswith("!vfsmount"):
        return mnt
    return mnt.get_vfsmnt_current()


def _containing_object(owner, link, type_name, member):
    context = owner._context
    table = owner.vol.type_name.split("!", 1)[0]
    qualified = table + "!" + type_name
    displacement = context.symbol_space.get_type(qualified).relative_child_offset(member)
    address = _object_address(link) - displacement
    if address <= 0:
        raise ValueError("invalid containing object")
    return context.object(
        qualified, offset=address, layer_name=owner.vol.layer_name,
        native_layer_name=owner.vol.native_layer_name,
    )


def _mount_points(namespace, max_nodes=100000):
    """구형 연결 리스트와 6.8 이후 RB 트리를 각각 상한/순환 검사하며 읽는다."""
    result, issues = [], 0
    try:
        if not _object_readable(namespace):
            raise ValueError("unreadable namespace")
        owner_address = _object_address(namespace)
        table = namespace.vol.type_name.split("!", 1)[0]
        context = namespace._context
        if namespace.has_member("list"):
            # 리스트의 끝처럼 보이는 지점이 아니라, 정확히 head로 복귀해야 완료다.
            head = namespace.list
            if not _object_readable(head):
                raise ValueError("unreadable list head")
            head_address = _object_address(head)
            previous, seen, cursor = head_address, {head_address}, head.next
            kind = "mount" if context.symbol_space.has_type(table + "!mount") else "vfsmount"
            while _object_address(cursor) != head_address:
                address = _object_address(cursor)
                if address in seen or len(result) >= max_nodes or not _object_readable(cursor):
                    raise ValueError("incomplete mount list")
                seen.add(address)
                if _object_address(cursor.prev) != previous:
                    raise ValueError("mount list backlink mismatch")
                mnt = _containing_object(namespace, cursor, kind, "mnt_list")
                if not _object_readable(mnt):
                    raise ValueError("unreadable mount")
                if mnt.has_member("mnt_ns") and _object_address(mnt.mnt_ns) != owner_address:
                    raise ValueError("mount namespace mismatch")
                result.append(mnt)
                previous, cursor = address, cursor.next
            if _object_address(head.prev) != previous:
                raise ValueError("mount list tail mismatch")
            return result, "COMPLETE"

        if not (namespace.has_member("mounts")
                and str(namespace.mounts.vol.type_name).endswith("!rb_root")):
            raise ValueError("unsupported mount namespace layout")
        # 자식을 mount 해석보다 먼저 큐에 넣어 한 손상 객체가 형제까지 지우지 않게 한다.
        pending, seen = [namespace.mounts.rb_node], set()
        while pending:
            cursor = pending.pop()
            try:
                address = _object_address(cursor)
                if not address:
                    continue
                if address in seen:
                    issues += 1
                    continue
                if len(seen) >= max_nodes:
                    issues += 1
                    break
                seen.add(address)
                if not _object_readable(cursor):
                    issues += 1
                    continue
                node = cursor.dereference()
                for child_name in ("rb_right", "rb_left"):
                    try:
                        child = node.member(child_name)
                        if _object_address(child):
                            pending.append(child)
                    except READ_ERRORS:
                        issues += 1
                mnt = _containing_object(namespace, cursor, "mount", "mnt_node")
                if not _object_readable(mnt):
                    raise ValueError("unreadable mount")
                if mnt.has_member("mnt_ns") and _object_address(mnt.mnt_ns) != owner_address:
                    raise ValueError("mount namespace mismatch")
                result.append(mnt)
            except READ_ERRORS:
                issues += 1
        return result, "COMPLETE" if not issues else f"PARTIAL:mount-nodes={issues}"
    except READ_ERRORS as exc:
        return result, "PARTIAL:mount-list:" + type(exc).__name__


def _walk_mount_path(root_dentry, root_vfsmnt, dentry, vfsmnt, *, max_depth=4096,
                     covering_mounts=None, require_live_inode=True):
    """정확한 (mount, dentry) 루트까지 연결된 경로만 반환한다."""
    names, visited, permitted_cover = [], set(), None
    crossed_mount = False
    try:
        if not all(_object_readable(obj) for obj in (root_dentry, root_vfsmnt, dentry, vfsmnt)):
            return "", "INCOMPLETE:root-or-source"
        root = (_object_address(root_vfsmnt), _object_address(root_dentry))
        for _ in range(max_depth):
            if not (_object_readable(dentry) and _object_readable(vfsmnt)):
                return "", "INCOMPLETE:route"
            key = (_object_address(vfsmnt), _object_address(dentry))
            if key in visited:
                return "", "INCOMPLETE:cycle"
            visited.add(key)
            if require_live_inode and not _object_readable(dentry.d_inode):
                return "", "INCOMPLETE:inode"
            if covering_mounts is not None:
                covers = covering_mounts.get(key, set())
                if len(covers) > 1:
                    return "", "INCOMPLETE:stacked-attachment"
                if covers and covers != {permitted_cover}:
                    return "", "COVERED"
                if permitted_cover is not None and permitted_cover not in covers:
                    return "", "INCOMPLETE:attachment"
            permitted_cover = None
            if key == root:
                return "/" + "/".join(reversed(names)), "COMPLETE"
            mount_root = vfsmnt.get_mnt_root()
            if not _object_readable(mount_root):
                return "", "INCOMPLETE:mount-root"
            if key[1] == _object_address(mount_root):
                # unlink된 파일도 bind의 루트라면 그 bind 경로는 살아 있을 수 있다.
                parent_mount = vfsmnt.get_vfsmnt_parent()
                attachment = vfsmnt.get_mnt_mountpoint()
                if not (_object_readable(parent_mount) and _object_readable(attachment)):
                    return "", "INCOMPLETE:parent-mount"
                if _object_address(parent_mount) == key[0]:
                    return "", "OUTSIDE_ROOT"
                permitted_cover, crossed_mount = key[0], True
                dentry, vfsmnt = attachment, parent_mount
                continue
            parent = dentry.d_parent
            if not _object_readable(parent):
                return "", "INCOMPLETE:parent-dentry"
            if _object_address(parent) == key[1]:
                return "", "OUTSIDE_ROOT" if crossed_mount else "OUTSIDE_MOUNT"
            if require_live_inode and not _object_address(dentry.d_hash.pprev):
                return "", "UNLINKED"
            name, issue = _read_dentry_name(dentry)
            if issue:
                return "", "INCOMPLETE:" + issue
            names.append(name)
            dentry = parent
    except READ_ERRORS as exc:
        return "", "INCOMPLETE:" + type(exc).__name__
    return "", "INCOMPLETE:depth-limit"


@dataclass(frozen=True)
class SourceResolution:
    paths: tuple
    status: str


class HostMountResolver:
    """파일 dentry를 입력받아 캡처된 호스트 마운트의 보이는 별칭을 찾는다."""

    def __init__(self, host_task):
        self.root_dentry = self.root_mount = None
        self.by_superblock, self.covering = {}, {}
        self.complete = False
        try:
            self.root_dentry = host_task.fs.get_root_dentry()
            self.root_mount = host_task.fs.get_root_mnt()
            if not (_object_readable(self.root_dentry) and _object_readable(self.root_mount)):
                raise ValueError("unreadable host root")
            points, state = _mount_points(host_task.nsproxy.mnt_ns)
            self.complete = state == "COMPLETE"
            indexed = set()
            for mnt in points:
                try:
                    current, superblock = _mount_current(mnt), mnt.get_mnt_sb()
                    if not (_object_readable(current) and _object_readable(superblock)):
                        raise ValueError("unreadable mount")
                    address = _object_address(current)
                    if address in indexed:
                        continue
                    indexed.add(address)
                    self.by_superblock.setdefault(_object_address(superblock), []).append(current)
                    parent = mnt.get_vfsmnt_parent()
                    if not _object_readable(parent):
                        raise ValueError("unreadable parent")
                    if _object_address(parent) != address:
                        point = mnt.get_mnt_mountpoint()
                        if not _object_readable(point):
                            raise ValueError("unreadable attachment")
                        key = (_object_address(parent), _object_address(point))
                        self.covering.setdefault(key, set()).add(address)
                except READ_ERRORS:
                    self.complete = False
            if _object_address(self.root_mount) not in indexed:
                self.complete = False
            if any(parent not in indexed for parent, _ in self.covering):
                self.complete = False
        except READ_ERRORS:
            self.complete = False
        if not self.complete:
            vollog.warning("Host mount topology incomplete; host aliases may be PARTIAL")

    def resolve(self, dentry, vfsmnt):
        try:
            if not (_object_readable(dentry) and _object_readable(vfsmnt)):
                raise ValueError("unreadable file path")
            superblock = vfsmnt.get_mnt_sb()
            if not _object_readable(superblock):
                raise ValueError("unreadable superblock")
            if _object_address(dentry.d_sb) != _object_address(superblock):
                raise ValueError("file/mount superblock mismatch")
            candidates = self.by_superblock.get(_object_address(superblock), ())
        except READ_ERRORS:
            return SourceResolution((), "PARTIAL")
        paths, complete = set(), self.complete
        for candidate in candidates:
            path, state = _walk_mount_path(
                self.root_dentry, self.root_mount, dentry, candidate,
                covering_mounts=self.covering,
            )
            if state == "COMPLETE":
                paths.add(path)
            elif state.startswith("INCOMPLETE:"):
                complete = False
        result = tuple(sorted(paths))
        if not complete:
            return SourceResolution(result, "PARTIAL")
        return SourceResolution(result, "UNRESOLVED" if not result else
                                "SINGLE" if len(result) == 1 else "MULTIPLE")


# 실제 cgroup 소속과 런타임 조상 관계 판독.

@dataclass(frozen=True)
class Identity:
    runtime: str
    identifier: str
    id_kind: str
    evidence: str


@dataclass(frozen=True)
class CgroupMembership:
    version: str
    controllers: tuple
    path: str
    cgroup_address: int

    def display(self):
        owner = ",".join(self.controllers) or "unified"
        return f"{self.version}:{owner}={self.path}"


@dataclass
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
    (rf"(?:^|/)docker-({_CGROUP_HEX_ID})\.scope(?=/|$)",
     "docker", "container", "docker-systemd-cgroup"),
    (rf"(?:^|/)docker/({_CGROUP_HEX_ID})(?=/|$)",
     "docker", "container", "docker-cgroupfs"),
    (rf"(?:^|/)cri-containerd-({_CGROUP_HEX_ID})\.scope(?=/|$)",
     "containerd", "container", "containerd-systemd-cgroup"),
    (rf"(?:^|/)crio-({_CGROUP_HEX_ID})\.scope(?=/|$)",
     "cri-o", "container", "crio-systemd-cgroup"),
    (rf"(?:^|/)libpod-({_CGROUP_HEX_ID})\.scope(?=/|$)",
     "podman", "container", "podman-systemd-cgroup"),
    (rf"(?:^|/)(?:crio|cri-containerd)/({_CGROUP_HEX_ID})(?=/|$)",
     "kubernetes", "container", "cri-cgroupfs"),
    (rf"(?:^|/)kubepods(?:/(?:burstable|besteffort))?/pod{_CGROUP_POD_ID}/({_CGROUP_HEX_ID})(?=/|$)",
     "kubernetes", "container", "kubernetes-cgroupfs-container"),
    (rf"(?:^|/)(?:kubepods(?:-[^/]+)*-)?pod({_CGROUP_POD_ID})(?:\.slice)?(?=/|$)",
     "kubernetes", "pod", "kubernetes-pod-cgroup"),
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


def _comm_matches(comm, signature):
    return bool(comm) and comm in (signature, signature[:15])


def _cgroup_hierarchy(cgroup, default_root=None):
    if not cgroup or not _object_readable(cgroup):
        raise ValueError("unreadable cgroup")
    root = cgroup.root
    if not root or not _object_readable(root):
        raise ValueError("unreadable cgroup root")
    address = _object_address(root)
    hierarchy_id = int(root.hierarchy_id)
    if hierarchy_id < 0:
        raise ValueError("negative hierarchy ID")
    unified = hierarchy_id == 0
    if default_root is not None and unified != (address == default_root):
        raise ValueError("default hierarchy address/ID mismatch")
    return "v2" if unified else "v1", address, root, hierarchy_id


def _read_cgroup_path(cgroup):
    """해당 계층의 kernfs 루트에 도달한 완전한 경로만 반환한다."""
    _, _, root, _ = _cgroup_hierarchy(cgroup)
    node = cgroup.kn
    root_node = root.cgrp.kn
    if not root_node or not _object_readable(root_node):
        raise ValueError("unreadable hierarchy kernfs root")
    root_address = _object_address(root_node)
    parts, seen = [], set()
    for _ in range(256):
        if not node or not _object_readable(node):
            raise ValueError("unreadable kernfs ancestor")
        address = _object_address(node)
        if address in seen:
            raise ValueError("cyclic kernfs ancestry")
        seen.add(address)
        parent = node.member("__parent" if node.has_member("__parent") else "parent")
        if address == root_address:
            if _object_address(parent):
                raise ValueError("hierarchy root has a parent")
            return "/" + "/".join(reversed(parts))
        if not parent or not _object_readable(parent):
            raise ValueError("kernfs ancestry ended before hierarchy root")
        name = _read_kernel_cstring(node.name, max_bytes=256)
        if (not name or name in {".", ".."} or "/" in name
                or len(name.encode("utf-8")) > 255
                or any(ord(char) < 32 or ord(char) == 127 for char in name)):
            raise ValueError("invalid kernfs component")
        parts.append(name)
        node = parent
    raise ValueError("kernfs ancestry exceeds 256 nodes")


def _cgroup_path(cgroup):
    try:
        return _read_cgroup_path(cgroup)
    except READ_ERRORS:
        return ""


def _cgroup_links(css_set, issues):
    """포인터 대상, 역방향 연결, css_set 소유자를 함께 검증한다."""
    groups = []
    try:
        head = css_set.cgrp_links
        if not _object_readable(head):
            raise ValueError("unreadable membership list head")
        context = head._context
        type_name = head.vol.type_name.split("!", 1)[0] + "!cgrp_cset_link"
        field_offset = context.symbol_space.get_type(type_name).relative_child_offset("cgrp_link")
        head_address = _object_address(head)
        previous, pointer, seen = head_address, head.next, {head_address}
        for index in range(4097):
            address = _object_address(pointer)
            if address == head_address:
                if _object_address(head.prev) != previous:
                    raise ValueError("membership list tail mismatch")
                return groups
            if index == 4096:
                raise ValueError("membership list exceeds 4096 entries")
            if not pointer or not _object_readable(pointer):
                raise ValueError("unreadable membership link")
            if address in seen:
                raise ValueError("cyclic membership list")
            seen.add(address)
            link = context.object(
                type_name, layer_name=head.vol.layer_name,
                offset=address - field_offset,
            )
            if not _object_readable(link):
                raise ValueError("unreadable cgrp_cset_link")
            if _object_address(link.cset) != _object_address(css_set):
                raise ValueError("membership link belongs to another css_set")
            if _object_address(link.cgrp_link.prev) != previous:
                raise ValueError("membership backlink mismatch")
            groups.append(link.cgrp)
            previous, pointer = address, link.cgrp_link.next
    except READ_ERRORS as exc:
        issues.add(f"membership-list:{type(exc).__name__}:{exc}")
    return groups


def _cgroup_memberships(task, issues_out=None):
    """v1/v2 실제 소속을 읽고 누락·충돌을 별도 표시한다."""
    issues, entries, conflicting_roots = set(), {}, set()

    def finish(memberships):
        if issues:
            issues.add("cgroup-metadata-partial")
            if issues_out is not None:
                issues_out.update(issues)
            logging.getLogger(__name__).debug("Partial task cgroups: %s", "; ".join(sorted(issues)))
        return tuple(memberships)

    try:
        css_set = task.cgroups
        if not css_set or not _object_readable(css_set):
            raise ValueError("missing or unreadable css_set")
    except READ_ERRORS as exc:
        issues.add(f"task-cgroups:{type(exc).__name__}:{exc}")
        return finish(())

    groups = _cgroup_links(css_set, issues)
    default_root = None
    try:
        if css_set.has_member("dfl_cgrp"):
            default_cgroup = css_set.dfl_cgrp
            version, root_address, _, _ = _cgroup_hierarchy(default_cgroup)
            if version != "v2":
                raise ValueError("dfl_cgrp is not hierarchy zero")
            default_root = root_address
            groups.append(default_cgroup)
    except READ_ERRORS as exc:
        issues.add(f"default-cgroup:{type(exc).__name__}:{exc}")

    hierarchy_roots = {}
    for cgroup in groups:
        try:
            version, root_address, root, hierarchy_id = _cgroup_hierarchy(cgroup)
            address = _object_address(cgroup)
            if root_address in entries and entries[root_address]["address"] != address:
                conflicting_roots.add(root_address)
                issues.add("cgroup-id-conflict")
                continue
            if hierarchy_id in hierarchy_roots and hierarchy_roots[hierarchy_id] != root_address:
                conflicting_roots.update((root_address, hierarchy_roots[hierarchy_id]))
                issues.add("cgroup-id-conflict")
            hierarchy_roots[hierarchy_id] = root_address
            entries.setdefault(root_address, {
                "version": version, "root": root, "hierarchy_id": hierarchy_id,
                "address": address, "cgroup": cgroup, "controllers": set(),
            })
        except READ_ERRORS as exc:
            issues.add(f"cgroup-hierarchy:{type(exc).__name__}:{exc}")

    # subsys[]는 v1 컨트롤러 이름에만 사용한다. v2 effective CSS는 소속이 아니다.
    try:
        subsystems = css_set.subsys if css_set.has_member("subsys") else ()
        subsystem_count = len(subsystems)
    except READ_ERRORS as exc:
        subsystems, subsystem_count = (), 0
        issues.add(f"controller-array:{type(exc).__name__}:{exc}")
    if subsystem_count > 256:
        issues.add("controller-array-limit")
    for index in range(min(subsystem_count, 256)):
        try:
            css = subsystems[index]
            if not css:
                continue
            if not _object_readable(css):
                raise ValueError("unreadable controller state")
            version, root_address, _, _ = _cgroup_hierarchy(css.cgroup, default_root)
            if version == "v2":
                continue
            if root_address not in entries:
                issues.add("controller-without-actual-membership")
                continue
            entry = entries[root_address]
            if entry["address"] != _object_address(css.cgroup):
                conflicting_roots.add(root_address)
                issues.add("cgroup-id-conflict")
                continue
            controller = f"subsys-{index}"
            if css.has_member("ss") and css.ss:
                subsystem = css.ss
                if not _object_readable(subsystem):
                    raise ValueError("unreadable controller descriptor")
                field = ("legacy_name" if subsystem.has_member("legacy_name")
                         and subsystem.legacy_name else "name")
                controller = _read_kernel_cstring(subsystem.member(field), max_bytes=64)
            if (not controller or "/" in controller or "," in controller
                    or any(ord(char) < 32 or ord(char) == 127 for char in controller)):
                raise ValueError("invalid controller name")
            entry["controllers"].add(controller)
        except READ_ERRORS as exc:
            issues.add(f"controller-{index}:{type(exc).__name__}:{exc}")

    memberships = []
    for root_address, entry in sorted(entries.items()):
        if root_address in conflicting_roots:
            continue
        try:
            path = _cgroup_path(entry["cgroup"])
            if not path:
                raise ValueError("incomplete hierarchy kernfs path")
        except READ_ERRORS as exc:
            issues.add(f"cgroup-path:{type(exc).__name__}:{exc}")
            continue
        controllers = entry["controllers"]
        if entry["version"] == "v1":
            try:
                root = entry["root"]
                name = utility.array_to_string(root.name) if root.has_member("name") else ""
                if name:
                    if ("/" in name or "," in name or "\ufffd" in name
                            or any(ord(char) < 32 or ord(char) == 127 for char in name)):
                        raise ValueError("invalid named hierarchy")
                    controllers.add("name=" + name)
            except READ_ERRORS as exc:
                issues.add(f"hierarchy-name:{type(exc).__name__}:{exc}")
            if not controllers:
                controllers.add(f"hierarchy-{entry['hierarchy_id']}")
        memberships.append(CgroupMembership(
            entry["version"], tuple(sorted(controllers)), path, entry["address"],
        ))
    if not entries:
        issues.add("actual-memberships-unavailable")
    return finish(memberships)


def _cgroup_identity(memberships):
    """알려진 runtime 경로만 식별하며 중첩·계층 간 ID 충돌은 보류한다."""
    matches = []
    for membership in memberships:
        for pattern, runtime, kind, source in _CGROUP_ID_PATTERNS:
            for match in pattern.finditer(membership.path):
                identifier = match.group(1).lower()
                if kind == "pod":
                    identifier = identifier.replace("_", "-")
                matches.append((membership, Identity(runtime, identifier, kind, source)))
    for kind in ("container", "pod"):
        if len({item.identifier for _, item in matches if item.id_kind == kind}) > 1:
            return None, "", True
    for kind in ("container", "pod"):
        candidates = [(membership, identity) for membership, identity in matches
                      if identity.id_kind == kind]
        if candidates:
            candidates.sort(key=lambda item: (
                item[0].version != "v2", item[0].display(), item[1].runtime,
            ))
            membership, identity = candidates[0]
            owner = ",".join(membership.controllers) or "unified"
            return identity, f"{membership.version}:{owner}", False
    return None, "", False


def _runtime_from_ancestry(task):
    seen, current = set(), task
    for _ in range(8):
        try:
            if not current or not _object_readable(current):
                break
            address = _object_address(current)
            if address in seen:
                break
            seen.add(address)
            comm = utility.array_to_string(current.comm)
            for signature, runtime in RUNTIME_SUPERVISORS:
                if _comm_matches(comm, signature):
                    return runtime, comm
            current = (current.real_parent if current.has_member("real_parent")
                       else current.parent)
        except READ_ERRORS:
            break
    return "", ""


def _observe_task(task):
    try:
        if (not task or not task.fs or not _object_readable(task.fs)
                or not task.nsproxy or not _object_readable(task.nsproxy)):
            return None
        mnt_ns = task.nsproxy.mnt_ns
        root_mnt, root_dentry = task.fs.get_root_mnt(), task.fs.get_root_dentry()
        if not all(obj and _object_readable(obj) for obj in (mnt_ns, root_mnt, root_dentry)):
            return None
        pid = int(task.pid)
        root_key = (_object_address(root_mnt), _object_address(root_dentry))
    except READ_ERRORS:
        return None
    issues = set()
    memberships = _cgroup_memberships(task, issues_out=issues)
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
        pid=pid, task=task, mnt_ns=mnt_ns, root_key=root_key,
        cgroup_memberships=memberships, identity=identity,
        runtime=identity.runtime if identity else runtime, evidence=tuple(evidence),
    )



def _safe_text(value):
    """터미널 제어문자는 이스케이프한다. 의미 있는 공백은 삭제하지 않는다."""
    return "".join(
        f"\\x{ord(char):02x}" if ord(char) < 32 or ord(char) == 127 else char
        for char in str(value)
    )


def _access_mode(filp):
    """inode.i_mode(권한)가 아닌 이 열린 file의 접근 모드를 읽는다."""
    try:
        mode = int(filp.f_mode)
        if mode & FMODE_PATH:
            return "PATH"
        return {0: "NONE", 1: "R", 2: "W", 3: "RW"}[mode & 3]
    except READ_ERRORS:
        try:
            flags = int(filp.f_flags)
            if flags & O_PATH:
                return "PATH"
            return {0: "R", 1: "W", 2: "RW"}.get(flags & 3, "UNKNOWN")
        except READ_ERRORS:
            return "UNKNOWN"


def _name_state(dentry, inode, file_flags, fs_type):
    """이름의 현재 연결만 설명한다. i_nlink == 0을 삭제 사건으로 해석하지 않는다."""
    if fs_type in {"sockfs", "pipefs"}:
        return "N/A"
    if fs_type == "anon_inodefs":
        return "ANONYMOUS"
    try:
        if not (dentry and _object_readable(dentry)
                and inode and _object_readable(inode)):
            return "UNKNOWN"
        parent_address = _object_address(dentry.d_parent)
        if not parent_address:
            return "UNKNOWN"
        address = _object_address(dentry)
        hashed = bool(_object_address(dentry.d_hash.pprev))
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
    except READ_ERRORS:
        return "UNKNOWN"


def _display_ids(identifiers, full=False):
    """짧은 ID끼리 충돌하면 구별될 때까지 확장한다. 내부 소속 ID는 항상 원문이다."""
    identifiers = sorted(set(identifier for identifier in identifiers if identifier))
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


def _scan_fd_array(array, count):
    """한 슬롯의 page fault 때문에 뒤쪽 FD까지 사라지지 않도록 분리해서 읽는다."""
    entries, issues = [], Counter()
    for fd in range(count):
        try:
            filp = array[fd]
            # 슬롯 자체가 안 읽히면 open/closed 여부조차 알 수 없다. 가짜 FD
            # 행을 만들지 않고 누락 슬롯 수를 전체 판독 상태에 남긴다.
            if _object_address(filp):
                entries.append((fd, filp))
        except READ_ERRORS:
            issues["fd-slot-unreadable"] += 1
    return entries, issues


@dataclass
class FileFacts:
    """동일 struct file에서 한 번만 읽는 정보. 태스크별 경로는 따로 계산한다."""

    access: str = "UNKNOWN"
    kind: str = "UNKNOWN"
    state: str = "UNKNOWN"
    fs_type: str = ""
    dentry: object = None
    vfsmnt: object = None
    inode: object = None
    inode_number: Optional[int] = None
    nlink: Optional[int] = None
    file_flags: Optional[int] = None
    raw_mode: Optional[int] = None
    host_paths: tuple = ()
    host_status: str = "PARTIAL"
    special_name: str = ""
    issues: set = field(default_factory=set)


def _file_facts(filp, resolver):
    """경로/선택 필드 하나가 손상되어도 이미 발견한 FD 행은 보존한다."""
    result = FileFacts()
    if not _object_readable(filp):
        result.issues.add("file-unreadable")
        return result
    result.access = _access_mode(filp)
    if result.access == "UNKNOWN":
        result.issues.add("access")
    for member, target in (("f_flags", "file_flags"), ("f_mode", "raw_mode")):
        try:
            setattr(result, target, int(getattr(filp, member)))
        except READ_ERRORS:
            result.issues.add(member)
    try:
        result.inode = filp.get_inode()
        if not (result.inode and _object_readable(result.inode)):
            raise ValueError("unreadable inode")
        result.kind = result.inode.get_inode_type() or "UNKNOWN"
        result.inode_number = int(result.inode.i_ino)
        result.nlink = int(result.inode.i_nlink)
    except READ_ERRORS:
        result.issues.add("inode")
    try:
        result.dentry = filp.get_dentry()
        result.vfsmnt = filp.get_vfsmnt()
        if not (_object_readable(result.dentry)
                and _object_readable(result.vfsmnt)):
            raise ValueError("unreadable f_path")
        superblock = result.vfsmnt.get_mnt_sb()
        if not _object_readable(superblock):
            raise ValueError("unreadable superblock")
        result.fs_type = _read_kernel_cstring(superblock.s_type.name, 256)
        # 동일 주소공간의 VFS 객체 관계만 비교한다. 경로 문자열 접두어를
        # 바꾸거나 overlay의 upper/lower 파일을 추측해서 만들지 않는다.
        if _object_address(result.dentry.d_sb) != _object_address(superblock):
            raise ValueError("dentry/mount superblock mismatch")
        if result.inode and (_object_address(result.inode)
                             != _object_address(result.dentry.d_inode)):
            raise ValueError("file/dentry inode mismatch")
    except READ_ERRORS:
        result.issues.add("f-path-or-superblock")
        # 관계 불일치로 얻은 객체를 경로 확정에 사용하지 않는다.
        result.dentry = None
        result.vfsmnt = None

    result.state = _name_state(
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
                name, issue = _read_dentry_name(result.dentry)
                result.special_name = "anon_inode:" + (name if not issue else "?")
                if issue:
                    result.issues.add("anonymous-name")
            except READ_ERRORS:
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


def _namespace_covering(mnt_ns):
    """프로세스 경로 위에 다른 마운트가 덮여 있는지 확인할 인덱스."""
    result, complete, known = {}, True, set()
    mount_list, status = _mount_points(mnt_ns)
    complete = status == "COMPLETE"
    for mnt in mount_list:
        try:
            current = _object_address(_mount_current(mnt))
            parent = _object_address(mnt.get_vfsmnt_parent())
            if not current or not parent:
                raise ValueError("null mount")
            known.add(current)
            if current != parent:
                point = mnt.get_mnt_mountpoint()
                if not _object_readable(point):
                    raise ValueError("unreadable mountpoint")
                result.setdefault((parent, _object_address(point)), set()).add(current)
        except READ_ERRORS:
            complete = False
    if any(parent not in known for parent, _ in result):
        complete = False
    return result, complete


def _container_path(task, facts, covering, index_complete):
    """현재 경로, 이름 연결이 끊긴 경로, 잔존 basename을 혼동하지 않는다."""
    if facts.special_name:
        return facts.special_name, "N/A"
    if facts.dentry is None or facts.vfsmnt is None:
        return "", "PARTIAL"
    try:
        if facts.state == "NAMELESS":
            # 처음부터 이름 없이 열린 파일에 과거의 절대경로를 만들어 붙이지 않는다.
            name, issue = _read_dentry_name(facts.dentry)
            return ("name:" + name, "NAME_ONLY") if not issue else ("", "PARTIAL")
        root_dentry, root_mnt = task.fs.get_root_dentry(), task.fs.get_root_mnt()
        path, status = _walk_mount_path(
            root_dentry, root_mnt, facts.dentry, facts.vfsmnt,
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
            _, topology_status = _walk_mount_path(
                root_dentry, root_mnt, facts.dentry, facts.vfsmnt,
                require_live_inode=True,
            )
            if topology_status == "OUTSIDE_ROOT":
                status = "OUTSIDE_ROOT"
        # 삭제/overmount/분리된 mount여도 FD는 남을 수 있다. 끝까지 따라간
        # 연결만 보조 표시하고 현재 열 수 있는 경로처럼 취급하지 않는다.
        residual, residual_status = _walk_mount_path(
            root_dentry, root_mnt, facts.dentry, facts.vfsmnt,
            require_live_inode=False,
        )
        if residual_status == "COMPLETE":
            if status == "UNLINKED":
                return residual + " [unlinked path]", "UNLINKED"
            if status == "COVERED":
                return residual + " [covered]", "COVERED"
            return residual + " [visibility unknown]", "PARTIAL"
        name, issue = _read_dentry_name(facts.dentry)
        if not issue:
            # task.fs.root를 벗어난 FD나 memfd의 이름을 임의의 절대경로로 만들지 않는다.
            return "name:" + name, (
                "PARTIAL" if status.startswith("INCOMPLETE:") else "NAME_ONLY"
            )
        return "", "PARTIAL" if status.startswith("INCOMPLETE:") else "UNRESOLVED"
    except READ_ERRORS:
        return "", "PARTIAL"


@dataclass
class TaskView:
    task: object
    tgid: int
    tid: int
    container_id: str
    observation: object
    files_address: int
    members: set = field(default_factory=set)
    issues: set = field(default_factory=set)


class InspectFiles(plugins.PluginInterface):
    """Inspect container file descriptors, file paths and unlinked-name references."""

    _required_framework_version = (2, 28, 0)
    _version = (0, 3, 1)

    @classmethod
    def get_requirements(cls):
        return [
            requirements.ModuleRequirement(
                name="kernel", description="Linux kernel with matching ISF",
                architectures=["Intel32", "Intel64"],
            ),
            requirements.VersionRequirement(
                name="linuxutils", component=linux.LinuxUtilities, version=(2, 4, 0),
            ),
            requirements.VersionRequirement(name="pslist", component=pslist.PsList, version=(4, 1, 1)),
            requirements.ListRequirement(
                name="pids", element_type=int, min_elements=1, optional=True,
                description="Explicit host process IDs (TGIDs), including their thread file tables",
            ),
            requirements.StringRequirement(
                name="container", optional=True,
                description="Select one unambiguous container ID prefix (6..64 hex characters)",
            ),
            requirements.ChoiceRequirement(
                name="view", choices=["files", "hosts", "details"], optional=True,
                description="All views are vertical Record/Field/Value rows; files: basic fields, hosts: host paths, details: all fields",
            ),
            requirements.BooleanRequirement(
                name="extended", optional=True, default=False,
                description="Alias for --view details (all fields, same 3-column vertical output)",
            ),
            requirements.BooleanRequirement(
                name="unlinked-only", optional=True, default=False,
                description="Only UNLINKED names, not anonymous or never-linked temporary files",
            ),
            requirements.BooleanRequirement(
                name="full-id", optional=True, default=False,
                description="Use complete container IDs (also required for full-ID JSON export)",
            ),
            requirements.IntRequirement(
                name="max-fds", optional=True, default=65536,
                description="Slots per file table (1..1048576); truncation is reported, never silently complete",
            ),
        ]

    def _options(self):
        wanted = self.config.get("pids")
        if wanted is not None and (
            not isinstance(wanted, list) or not wanted
            or any(type(pid) is not int or pid <= 0 for pid in wanted)
        ):
            raise exceptions.VolatilityException("--pids requires positive host process IDs")
        prefix = self.config.get("container")
        if prefix is not None and (
            not isinstance(prefix, str) or not re.fullmatch(r"[0-9a-fA-F]{6,64}", prefix)
        ):
            raise exceptions.VolatilityException("--container requires a 6..64 hex ID prefix")
        limit = self.config.get("max-fds", 65536)
        if type(limit) is not int or not 1 <= limit <= MAX_FDS:
            raise exceptions.VolatilityException("--max-fds must be in 1..1048576")
        for name in ("extended", "unlinked-only", "full-id"):
            if type(self.config.get(name, False)) is not bool:
                raise exceptions.VolatilityException(f"--{name} must be a boolean")
        self._selected_view()
        return set(wanted) if wanted is not None else None, prefix.lower() if prefix else None, limit

    def _selected_view(self):
        value = self.config.get("view")
        if value is not None and value not in ("files", "hosts", "details"):
            raise exceptions.VolatilityException("--view must be files, hosts or details")
        if self.config.get("extended", False):
            if value not in (None, "details"):
                raise exceptions.VolatilityException("--extended is an alias for --view details")
            return "details"
        return value or "files"

    def _task_views(self, wanted, prefix):
        views, found, seen = {}, set(), set()
        failures = Counter()
        try:
            initial = self.context.modules[self.config["kernel"]].object_from_symbol("init_task")
            host_namespace = initial.nsproxy.mnt_ns
            host_namespace_address = (_object_address(host_namespace)
                                      if _object_readable(host_namespace) else None)
        except READ_ERRORS:
            host_namespace_address = None
        tasks = pslist.PsList.list_tasks(
            self.context, self.config["kernel"], include_threads=True,
        )
        try:
            for task in tasks:
                try:
                    address = _object_address(task)
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
                        related = (observation.identity is not None
                                   or "cgroup-id-conflict" in observation.evidence)
                        if not related and host_namespace_address is not None:
                            command = utility.array_to_string(task.comm)
                            itself_supervisor = any(
                                _comm_matches(command, signature)
                                for signature, _ in RUNTIME_SUPERVISORS
                            )
                            # shim 자체의 FD를 컨테이너 내부 FD로 오인하지 않는다.
                            # 강한 cgroup 근거가 있으면 host MNT NS 공유 컨테이너도
                            # 허용하지만, supervisor 단독 근거는 분리된 NS를 요구한다.
                            related = (
                                not itself_supervisor
                                and _object_address(observation.mnt_ns) != host_namespace_address
                                and any(item.startswith("supervisor:") for item in observation.evidence)
                            )
                    if wanted is None and not related:
                        continue
                    identity = observation.identity if observation is not None else None
                    container_id = identity.identifier if identity and identity.id_kind == "container" else ""
                    if prefix and not container_id.startswith(prefix):
                        continue
                    found.add(tgid)
                    files_address = _object_address(task.files)
                    issues = set()
                    if observation is None:
                        issues.add("task-membership-or-view")
                        owner = ("unknown", tid)
                        view_key = (tid,)
                    else:
                        issues.update(flag for flag in observation.evidence
                                      if flag in {"cgroup-id-conflict", "cgroup-metadata-partial"})
                        owner = container_id or (
                            tuple((m.version, m.cgroup_address) for m in observation.cgroup_memberships),
                            observation.runtime,
                            tid if issues else None,
                        )
                        view_key = (_object_address(observation.mnt_ns), observation.root_key)
                    # 같은 프로세스의 같은 FD table만 합친다. 다른 프로세스의
                    # 공유 FD, 스레드 전용 FD table, 다른 root/cgroup은 보존한다.
                    key = (tgid, files_address, view_key, owner)
                    if key not in views:
                        views[key] = TaskView(task, tgid, tid, container_id, observation,
                                              files_address, {tid}, issues)
                    else:
                        view = views[key]
                        view.members.add(tid)
                        view.issues.update(issues)
                        if (tid != tgid, tid) < (view.tid != tgid, view.tid):
                            view.task, view.tid, view.observation = task, tid, observation
                except READ_ERRORS:
                    failures["task-metadata"] += 1
        except READ_ERRORS:
            failures["task-list"] += 1
        if wanted is not None and wanted - found:
            vollog.warning("Requested TGIDs not selected/readable: %s", sorted(wanted - found))
        if wanted is None and host_namespace_address is None:
            vollog.warning("Host MNT NS unreadable; automatic selection used cgroup evidence only")
        if failures:
            vollog.warning("Task collection incomplete: %s; missing rows do not prove absence", dict(failures))
            for view in views.values():
                view.issues.add("task-list-partial")
        ids = {view.container_id for view in views.values() if view.container_id}
        if prefix and len(ids) > 1:
            raise exceptions.VolatilityException("--container is ambiguous; use a longer/full ID")
        return sorted(views.values(), key=lambda view: (view.container_id, view.tgid, view.tid))

    def _read_fds(self, task, limit):
        issues = Counter()
        try:
            files = task.files
            if not (files and _object_readable(files)):
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
            base_address = _object_address(base_pointer)
            if not base_address:
                raise ValueError("null fd array")
            kernel = self.context.modules[self.config["kernel"]]
            subtype = self.context.symbol_space.get_type(kernel.symbol_table_name + "!pointer").clone()
            subtype.update_vol(subtype=self.context.symbol_space.get_type(kernel.symbol_table_name + "!file"))
            # Array 자체를 만들 때는 슬롯을 읽지 않는다. 각 포인터의 판독은
            # _scan_fd_array에서 개별적으로 수행한다.
            array = self.context.object(
                kernel.symbol_table_name + "!array", count=count, subtype=subtype,
                offset=base_address, layer_name=base_pointer.vol.native_layer_name,
                native_layer_name=base_pointer.vol.native_layer_name,
            )
            entries, slot_issues = _scan_fd_array(array, count)
            issues.update(slot_issues)
            return entries, issues
        except READ_ERRORS:
            issues["fd-table"] += 1
            return [], issues

    def _generator(self, output_view):
        wanted, prefix, limit = self._options()
        views = self._task_views(wanted, prefix)
        if not views:
            vollog.warning("No task views selected; use --pids for an explicit known host process")
            return
        id_display = _display_ids((view.container_id for view in views), self.config.get("full-id", False))
        kernel = self.context.modules[self.config["kernel"]]
        resolver = HostMountResolver(kernel.object_from_symbol("init_task"))
        table_cache, file_cache, namespace_cache = {}, {}, {}
        counts = Counter()
        for view in views:
            if view.files_address not in table_cache:
                table_cache[view.files_address] = self._read_fds(view.task, limit)
            entries, table_issues = table_cache[view.files_address]
            if table_issues:
                vollog.warning("PID/TID %s/%s FD table incomplete: %s", view.tgid, view.tid, dict(table_issues))
            covering, namespace_complete = {}, False
            if view.observation is not None:
                namespace_address = _object_address(view.observation.mnt_ns)
                if namespace_address not in namespace_cache:
                    namespace_cache[namespace_address] = _namespace_covering(view.observation.mnt_ns)
                covering, namespace_complete = namespace_cache[namespace_address]
            try:
                comm = _safe_text(utility.array_to_string(view.task.comm))
            except READ_ERRORS:
                comm = "-"
            for fd, filp in entries:
                file_address = _object_address(filp)
                if file_address not in file_cache:
                    file_cache[file_address] = _file_facts(filp, resolver)
                facts = file_cache[file_address]
                if self.config.get("unlinked-only", False) and facts.state != "UNLINKED":
                    continue
                path, path_status = _container_path(view.task, facts, covering, namespace_complete)
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
                    fields.extend([
                        ("Access", facts.access), ("State", state), ("Path", displayed_path),
                    ])
                elif output_view == "hosts":
                    # 별칭 여러 개를 긴 셀 하나에 이어 붙이지 않고 각각 한 행으로.
                    fields.extend(("Host Path", _safe_text(alias)) for alias in facts.host_paths or ("-",))
                    fields.append(("Status", facts.host_status))
                else:
                    detail = "PARTIAL:" + ",".join(sorted(issues)) if issues else "COMPLETE"
                    fields.extend([
                        ("Process", comm), ("Access", facts.access), ("Type", facts.kind),
                        ("Name State", facts.state), ("Path", displayed_path),
                    ])
                    fields.extend(("Host Path", _safe_text(alias)) for alias in facts.host_paths or ("-",))
                    fields.extend([
                        ("Path Status", path_status), ("Host Path Status", facts.host_status),
                        ("Read Status", detail),
                        ("Inode", str(facts.inode_number) if facts.inode_number is not None else "-"),
                        ("Link Count", str(facts.nlink) if facts.nlink is not None else "-"),
                        ("File Flags", hex(facts.file_flags) if facts.file_flags is not None else "-"),
                        ("File Mode", hex(facts.raw_mode) if facts.raw_mode is not None else "-"),
                    ])
                    # 스레드 목록도 길게 합치지 않는다. 여러 TID가 같은 테이블을
                    # 공유할 때만 별도 행으로 나열한다.
                    if len(view.members) > 1:
                        fields.extend(("Shared TID", str(tid)) for tid in sorted(view.members))
                # 콘솔/JSON/CSV 모두 같은 구조를 사용하며 실제 값은 자르지 않는다.
                for label, value in fields:
                    yield 0, (counts["rows"], label, value)
        if counts["partial"]:
            vollog.warning("%s/%s FDs have incomplete metadata (* in State); inspect --view details", counts["partial"], counts["rows"])
        if not counts["rows"]:
            vollog.warning("No matching readable FD rows; this does not prove there are no open/deleted files")

    def run(self):
        self._options()
        output_view = self._selected_view()
        columns = [("Record", int), ("Field", str), ("Value", str)]
        return renderers.TreeGrid(columns, self._generator(output_view))

"""Task-list strategies and argv readers, with explicit legacy policies."""

import dataclasses
import re

from volatility3.framework import exceptions
from volatility3.framework.objects import utility
from volatility3.plugins.linux import pslist

from . import core as artifact_core


def audit_task_list(head, read_link, limit=100000):
    """태스크 연결 목록을 양방향으로 검사하고, 도달한 노드·연결 불일치·순회 중단 내역을 반환한다.

    로직: 정방향과 역방향을 따로 순회해 역연결을 검사하고 발견 노드를 합친다. 합집합이 완전한 목록이라는 뜻은 아니다.
    """
    result = {"head": hex(head), "directions": {}, "issues": []}
    cache = {}

    def link(address, field):
        """노드의 연결 포인터를 읽고 결과를 캐시해 같은 주소·필드의 중복 읽기를 줄인다.

        로직: 주소와 필드를 키로 읽기 결과를 저장한 뒤 재요청에는 캐시 값을 사용한다.
        """
        key = address, field
        if key not in cache:
            cache[key] = read_link(address, field)
        return cache[key]

    for direction, field, opposite in (
        ("forward", "next", "prev"),
        ("backward", "prev", "next"),
    ):
        nodes, seen, previous = [], set(), head
        closed = False
        try:
            current = link(head, field)
            while current != head:
                if not current or current in seen or len(seen) >= limit:
                    raise artifact_core.Incomplete(
                        "Null/cycle/traversal budget before returning to head"
                    )
                seen.add(current)
                nodes.append(current)
                try:
                    actual = link(current, opposite)
                    if actual != previous:
                        result["issues"].append(
                            {
                                "direction": direction,
                                "kind": "RECIPROCAL_MISMATCH",
                                "node": hex(current),
                                "field": opposite,
                                "expected": hex(previous),
                                "actual": hex(actual),
                            }
                        )
                except (
                    exceptions.VolatilityException,
                    ValueError,
                    AttributeError,
                ) as exc:
                    result["issues"].append(
                        {
                            "direction": direction,
                            "kind": "UNREADABLE_BACKLINK",
                            "node": hex(current),
                            "detail": str(exc),
                        }
                    )
                previous, current = current, link(current, field)
            closed = True
            if link(head, opposite) != previous:
                result["issues"].append(
                    {
                        "direction": direction,
                        "kind": "HEAD_TAIL_MISMATCH",
                        "expected": hex(previous),
                        "actual": hex(link(head, opposite)),
                    }
                )
        except (exceptions.VolatilityException, ValueError, AttributeError) as exc:
            result["issues"].append(
                {
                    "direction": direction,
                    "kind": "TRAVERSAL_STOPPED",
                    "detail": str(exc),
                }
            )
        result["directions"][direction] = {
            "nodes": nodes,
            "closed": closed,
            "count": len(nodes),
        }
    forward = set(result["directions"]["forward"]["nodes"])
    backward = set(result["directions"]["backward"]["nodes"])
    result["forward_only"] = sorted(forward - backward)
    result["backward_only"] = sorted(backward - forward)
    if forward != backward:
        result["issues"].append(
            {
                "kind": "DIRECTION_SET_MISMATCH",
                "forward_only": len(forward - backward),
                "backward_only": len(backward - forward),
            }
        )
    result["status"] = "PARTIAL" if result["issues"] else "CONSISTENT"
    return result


def list_tasks(context, kernel_name, *, include_threads=None):
    # None preserves the stock default used by mount views.
    if include_threads is None:
        return pslist.PsList.list_tasks(context, kernel_name)
    return pslist.PsList.list_tasks(
        context, kernel_name, include_threads=include_threads
    )


def walk_list(reader, head, typename, member, *, check_backlinks):
    """Bounded forward traversal; strict validation is opt-in, never implicit."""
    offset = reader.kernel.get_type(typename).relative_child_offset(member)
    end = previous = int(head.vol.offset)
    link, seen = int(head.next), set()
    while link != end:
        if check_backlinks:
            if not link or link in seen or len(seen) >= reader.limit:
                raise artifact_core.Incomplete(
                    "NULL link, non-head cycle or traversal limit"
                )
        else:
            if len(seen) >= reader.limit:
                raise ValueError("traversal limit reached")
            if not link or link in seen:
                raise ValueError("null link or non-head cycle")
        seen.add(link)
        obj = reader.obj(typename, link - offset)
        if check_backlinks:
            entry = obj.member(member)
            if int(entry.prev) != previous:
                raise artifact_core.Incomplete("List backlink mismatch")
        yield obj
        if check_backlinks:
            previous, link = link, int(entry.next)
        else:
            link = int(obj.member(member).next)
    if check_backlinks and int(head.prev) != previous:
        raise artifact_core.Incomplete("List tail disagrees with forward traversal")


@dataclasses.dataclass(frozen=True)
class ArgvPolicy:
    limit: int
    length_error: str
    layer_error: str
    error_type: type = ValueError
    missing_mm_error: str = ""
    require_terminator: bool = False
    strip_trailing_nuls: bool = False


PRESENCE_ARGV = ArgvPolicy(
    65536,
    "Runtime argv missing or outside byte limit",
    "Runtime process layer unavailable",
    artifact_core.Incomplete,
    "Runtime task has no userspace memory descriptor",
    require_terminator=True,
)
NETWORK_ARGV = ArgvPolicy(
    65536, "runtime argv length out of bounds", "runtime process layer unavailable"
)
INVENTORY_ARGV = ArgvPolicy(
    16 * 1024 * 1024,
    "Command line length outside budget",
    "No process address space",
    artifact_core.Incomplete,
    strip_trailing_nuls=True,
)


def read_argv(context, task, policy, *, limit=None):
    if not task.mm:
        if policy.missing_mm_error:
            raise policy.error_type(policy.missing_mm_error)
        return []
    start, end = int(task.mm.arg_start), int(task.mm.arg_end)
    maximum = policy.limit if limit is None else limit
    if not 0 <= end - start <= maximum or (
        policy.require_terminator and (not start or end == start)
    ):
        raise policy.error_type(policy.length_error)
    layer = task.add_process_layer()
    if layer is None:
        raise policy.error_type(policy.layer_error)
    if policy.require_terminator:
        raw = context.layers[layer].read(start, end - start, pad=False)
        if not raw.endswith(b"\0"):
            raise policy.error_type("Runtime argv is not NUL-terminated")
        return raw[:-1].decode("utf-8", errors="strict").split("\0")
    value = (
        context.layers[layer].read(start, end - start).decode("utf-8", errors="replace")
    )
    if policy.strip_trailing_nuls:
        value = value.rstrip("\0")
    return value.split("\0")


def shim_arguments(args):
    """shim 명령행의 분리된 ID·namespace 인자를 해석하고 누락·충돌·ID 형식을 검사한다.

    로직: ID·namespace 플래그의 다음 인자를 모아 값의 개수와 컨테이너 ID 형식을 검사한다.
    """
    ids, namespaces = set(), set()
    for index, arg in enumerate(args):
        if arg not in ("-id", "--id", "-namespace", "--namespace"):
            continue
        if index + 1 == len(args) or args[index + 1].startswith("-"):
            raise ValueError("Shim flag has no value")
        (ids if arg in ("-id", "--id") else namespaces).add(args[index + 1])
    if len(ids) != 1 or len(namespaces) > 1:
        raise ValueError("Missing or conflicting shim ID/namespace flags")
    cid = next(iter(ids))
    if not re.fullmatch(r"[0-9a-f]{64}", cid):
        raise ValueError("Invalid shim container ID")
    return cid, next(iter(namespaces), None)


def ancestor_chain(task, limit=512):
    """real_parent 포인터를 따라 init/PID 1까지 조상 체인을 복원한다.

    로직: real_parent를 거슬러 오르며 주소·PID·명령을 기록한다. NULL·자기참조·
    순환·한도 도달·PID 1에서 멈춘다. 반환은 가까운 조상부터의 순서다.
    """
    chain, seen = [], set()
    current = task
    while True:
        address = int(current.vol.offset)
        if address in seen or len(seen) >= limit:
            break
        seen.add(address)
        try:
            parent_ptr = current.real_parent
        except (exceptions.VolatilityException, AttributeError):
            break
        if not int(parent_ptr):
            break
        parent_address = int(parent_ptr)
        if parent_address == address:  # init_task는 자기 자신을 부모로 가진다.
            break
        parent = parent_ptr.dereference()
        try:
            record = {
                "address": hex(parent_address),
                "pid": int(parent.tgid),
                "tid": int(parent.pid),
                "comm": utility.array_to_string(parent.comm),
            }
        except (exceptions.VolatilityException, ValueError, AttributeError):
            chain.append(
                {
                    "address": hex(parent_address),
                    "pid": None,
                    "tid": None,
                    "comm": None,
                    "unreadable": True,
                }
            )
            break
        chain.append(record)
        if record["pid"] == 1:
            break
        current = parent
    return chain


def comm_matches(comm, signature):
    return bool(comm) and comm in (signature, signature[:15])


def runtime_from_ancestry(task, supervisors, max_depth=8):
    seen, current = set(), task
    for _ in range(max_depth):
        try:
            if not current or not artifact_core._object_readable(current):
                break
            address = artifact_core._object_address(current)
            if address in seen:
                break
            seen.add(address)
            comm = utility.array_to_string(current.comm)
            for signature, runtime in supervisors:
                if comm_matches(comm, signature):
                    return runtime, comm
            current = (
                current.real_parent
                if current.has_member("real_parent")
                else current.parent
            )
        except artifact_core.READ_ERRORS:
            break
    return "", ""

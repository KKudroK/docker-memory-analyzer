"""Task-list strategies and argv readers, with explicit legacy policies."""

from __future__ import annotations

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
                            "detail": artifact_core.exception_detail(exc),
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
                    "detail": artifact_core.exception_detail(exc),
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
    """shim의 공백형·등호형 ID/namespace를 읽고 누락·충돌·ID 형식을 검사한다.

    로직: 옵션과 값을 함께 소비하고 --에서 종료한다. 동일 값은 합치고 서로 다른 값은 충돌로 거부한다.
    """
    ids, namespaces = set(), set()
    index = 0
    while index < len(args):
        arg = args[index]
        if arg == "--":
            break
        flag, separator, value = arg.partition("=")
        index += 1
        if flag not in ("-id", "--id", "-namespace", "--namespace"):
            continue
        if not separator:
            if index >= len(args) or args[index].startswith("-"):
                raise ValueError("Shim flag has no value")
            value = args[index]
            index += 1
        if not value:
            raise ValueError("Shim flag has an empty value")
        (ids if flag in ("-id", "--id") else namespaces).add(value)
    if len(ids) != 1 or len(namespaces) > 1:
        raise ValueError("Missing or conflicting shim ID/namespace flags")
    cid = next(iter(ids))
    if not re.fullmatch(r"[0-9a-f]{64}", cid):
        raise ValueError("Invalid shim container ID")
    return cid, next(iter(namespaces), None)


@dataclasses.dataclass(frozen=True)
class AncestryError:
    """An internal traversal failure; the caller serializes the original exception."""

    operation: str
    address: int | None
    exception: Exception


@dataclasses.dataclass
class AncestryResult:
    """Recovered ancestors, nearest first, and any reason traversal stopped early."""

    records: list[dict] = dataclasses.field(default_factory=list)
    errors: list[AncestryError] = dataclasses.field(default_factory=list)


def ancestor_chain(task, limit=512):
    """Retain a readable prefix and report faults, cycles and traversal limits.

    Null/self parent pointers and a recovered PID 1 are normal endpoints.
    A known parent address is retained even if dereferencing or reading its
    fields fails. Errors remain local to this task's ancestry traversal.
    """
    result = AncestryResult()
    seen = set()
    current = task
    while True:
        address = None
        operation = "task.address"
        record = None
        try:
            address = int(current.vol.offset)
            operation = "cycle"
            if address in seen:
                raise artifact_core.Incomplete("Repeated task in ancestor chain")
            operation = "limit"
            if len(seen) >= limit:
                raise artifact_core.Incomplete(
                    f"Ancestor traversal limit reached: {limit}"
                )
            seen.add(address)
            operation = "real_parent"
            parent_ptr = current.real_parent
            operation = "real_parent.address"
            parent_address = int(parent_ptr)
            if not parent_address or parent_address == address:
                break
            record = {
                "address": hex(parent_address),
                "pid": None,
                "tid": None,
                "comm": None,
            }
            result.records.append(record)
            operation = "real_parent.dereference"
            parent = parent_ptr.dereference()
            operation = "parent.tgid"
            record["pid"] = int(parent.tgid)
            operation = "parent.pid"
            record["tid"] = int(parent.pid)
            operation = "parent.comm"
            record["comm"] = utility.array_to_string(parent.comm)
        except artifact_core.READ_ERRORS as exc:
            if record is not None:
                record["unreadable"] = True
            result.errors.append(AncestryError(operation, address, exc))
            break
        if record["pid"] == 1:
            break
        current = parent
    return result


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

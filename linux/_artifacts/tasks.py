"""Task-list strategies and argv readers, with explicit legacy policies."""
from dataclasses import dataclass
from volatility3.framework import exceptions
from volatility3.plugins.linux import pslist
from .core import Incomplete

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

    for direction, field, opposite in (("forward", "next", "prev"),
                                        ("backward", "prev", "next")):
        nodes, seen, previous = [], set(), head
        closed = False
        try:
            current = link(head, field)
            while current != head:
                if not current or current in seen or len(seen) >= limit:
                    raise Incomplete("Null/cycle/traversal budget before returning to head")
                seen.add(current)
                nodes.append(current)
                try:
                    actual = link(current, opposite)
                    if actual != previous:
                        result["issues"].append({"direction": direction, "kind": "RECIPROCAL_MISMATCH",
                            "node": hex(current), "field": opposite,
                            "expected": hex(previous), "actual": hex(actual)})
                except (exceptions.VolatilityException, ValueError, AttributeError) as exc:
                    result["issues"].append({"direction": direction, "kind": "UNREADABLE_BACKLINK",
                        "node": hex(current), "detail": str(exc)})
                previous, current = current, link(current, field)
            closed = True
            if link(head, opposite) != previous:
                result["issues"].append({"direction": direction, "kind": "HEAD_TAIL_MISMATCH",
                    "expected": hex(previous), "actual": hex(link(head, opposite))})
        except (exceptions.VolatilityException, ValueError, AttributeError) as exc:
            result["issues"].append({"direction": direction, "kind": "TRAVERSAL_STOPPED", "detail": str(exc)})
        result["directions"][direction] = {"nodes": nodes, "closed": closed, "count": len(nodes)}
    forward = set(result["directions"]["forward"]["nodes"])
    backward = set(result["directions"]["backward"]["nodes"])
    result["forward_only"] = sorted(forward - backward)
    result["backward_only"] = sorted(backward - forward)
    if forward != backward:
        result["issues"].append({"kind": "DIRECTION_SET_MISMATCH",
            "forward_only": len(forward - backward), "backward_only": len(backward - forward)})
    result["status"] = "PARTIAL" if result["issues"] else "CONSISTENT"
    return result


def list_tasks(context, kernel_name, *, include_threads=None):
    # None preserves the stock default used by mount views.
    if include_threads is None:
        return pslist.PsList.list_tasks(context, kernel_name)
    return pslist.PsList.list_tasks(context, kernel_name, include_threads=include_threads)


def walk_list(reader, head, typename, member, *, check_backlinks):
    """Bounded forward traversal; strict validation is opt-in, never implicit."""
    offset = reader.kernel.get_type(typename).relative_child_offset(member)
    end = previous = int(head.vol.offset)
    link, seen = int(head.next), set()
    while link != end:
        if check_backlinks:
            if not link or link in seen or len(seen) >= reader.limit:
                raise Incomplete('NULL link, non-head cycle or traversal limit')
        else:
            if len(seen) >= reader.limit:
                raise ValueError('traversal limit reached')
            if not link or link in seen:
                raise ValueError('null link or non-head cycle')
        seen.add(link)
        obj = reader.obj(typename, link - offset)
        if check_backlinks:
            entry = obj.member(member)
            if int(entry.prev) != previous:
                raise Incomplete('List backlink mismatch')
        yield obj
        if check_backlinks:
            previous, link = link, int(entry.next)
        else:
            link = int(obj.member(member).next)
    if check_backlinks and int(head.prev) != previous:
        raise Incomplete('List tail disagrees with forward traversal')


@dataclass(frozen=True)
class ArgvPolicy:
    limit: int
    length_error: str
    layer_error: str
    error_type: type = ValueError
    missing_mm_error: str = ''
    require_terminator: bool = False
    strip_trailing_nuls: bool = False


PRESENCE_ARGV = ArgvPolicy(65536, 'Runtime argv missing or outside byte limit',
    'Runtime process layer unavailable', Incomplete,
    'Runtime task has no userspace memory descriptor', require_terminator=True)
NETWORK_ARGV = ArgvPolicy(65536, 'runtime argv length out of bounds', 'runtime process layer unavailable')
INVENTORY_ARGV = ArgvPolicy(16 * 1024 * 1024, 'Command line length outside budget',
    'No process address space', Incomplete, strip_trailing_nuls=True)


def read_argv(context, task, policy, *, limit=None):
    if not task.mm:
        if policy.missing_mm_error:
            raise policy.error_type(policy.missing_mm_error)
        return []
    start, end = int(task.mm.arg_start), int(task.mm.arg_end)
    maximum = policy.limit if limit is None else limit
    if not 0 <= end - start <= maximum or (policy.require_terminator and (not start or end == start)):
        raise policy.error_type(policy.length_error)
    layer = task.add_process_layer()
    if layer is None:
        raise policy.error_type(policy.layer_error)
    if policy.require_terminator:
        raw = context.layers[layer].read(start, end - start, pad=False)
        if not raw.endswith(b'\0'):
            raise policy.error_type('Runtime argv is not NUL-terminated')
        return raw[:-1].decode('utf-8', errors='strict').split('\0')
    value = context.layers[layer].read(start, end - start).decode('utf-8', errors='replace')
    if policy.strip_trailing_nuls:
        value = value.rstrip('\0')
    return value.split('\0')

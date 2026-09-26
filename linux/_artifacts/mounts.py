# SPDX-License-Identifier: MIT
# Includes readers by the container-mounts contributors (c) 2026.
"""Mount namespace traversal strategies, independent of selection and display."""

from __future__ import annotations

from volatility3.framework import exceptions
from volatility3.framework.symbols import linux

from . import core as artifact_core


def list_mount_points(
    mnt_ns, max_nodes: int = 100000, *, diagnostics=None
) -> tuple[list[object], str]:
    """Collect a legacy namespace list only after proving return to its head.

    Upstream list_head.to_list() silently stops at unreadable/repeated
    links.  Treating that exhaustion as success could hide a covering host
    mount, so validate both link directions and namespace ownership here.
    On corruption the already validated prefix remains available as PARTIAL.
    """

    points: list[object] = []
    try:
        if not (
            mnt_ns
            and artifact_core._object_readable(mnt_ns, diagnostics=diagnostics)
            and mnt_ns.has_member("list")
        ):
            raise ValueError("missing or unreadable legacy namespace list")
        head = mnt_ns.list
        if not artifact_core._object_readable(head, diagnostics=diagnostics):
            raise ValueError("unreadable legacy namespace list head")
        context = head._context
        table_name = head.vol.type_name.split("!", 1)[0]
        mount_type = table_name + "!mount"
        if not context.symbol_space.has_type(mount_type):
            mount_type = table_name + "!vfsmount"
        member_offset = context.symbol_space.get_type(mount_type).relative_child_offset(
            "mnt_list"
        )
        namespace_address = artifact_core._object_address(mnt_ns)
        head_address = artifact_core._object_address(head)
        previous = head_address
        link_pointer = head.next
        seen = {head_address}
        while True:
            link_address = artifact_core._object_address(link_pointer)
            if link_address == head_address:
                if artifact_core._object_address(head.prev) != previous:
                    raise ValueError(
                        "legacy mount-list tail disagrees with forward walk"
                    )
                return points, "COMPLETE"
            if len(points) >= max_nodes:
                raise ValueError("legacy mount list exceeds node limit")
            if not link_pointer or not artifact_core._object_readable(
                link_pointer, diagnostics=diagnostics
            ):
                raise ValueError("unreadable legacy mount-list entry")
            if link_address in seen:
                raise ValueError("cyclic legacy mount list outside its head")
            seen.add(link_address)
            link = link_pointer.dereference()
            if artifact_core._object_address(link.prev) != previous:
                raise ValueError("legacy mount-list backlink mismatch")
            mount_address = link_address - member_offset
            if mount_address < 0:
                raise ValueError("invalid legacy mount container address")
            mnt = context.object(
                mount_type,
                layer_name=head.vol.layer_name,
                native_layer_name=head.vol.native_layer_name,
                offset=mount_address,
            )
            if (
                mnt.has_member("mnt_ns")
                and artifact_core._object_address(mnt.mnt_ns) != namespace_address
            ):
                raise ValueError("legacy mount belongs to another namespace")
            points.append(mnt)
            previous = link_address
            link_pointer = link.next
    except (
        AttributeError,
        KeyError,
        IndexError,
        TypeError,
        ValueError,
        exceptions.InvalidAddressException,
        exceptions.VolatilityException,
    ) as exc:
        artifact_core.record_read_error(diagnostics, "mount.list_walk", exc)
        return points, f"PARTIAL:list-walk:{type(exc).__name__}:{exc}"


def mount_points(mnt_ns, *, diagnostics=None) -> tuple[list[object], str]:
    """Collect namespace mounts without losing every sibling to one bad RB node.

    Volatility 3's upstream extension recursively walks the kernel >= 6.8
    RB tree.  An unreadable node raises out of the generator and discards
    the rest of the walk.  The iterative guard below uses the same
    LinuxUtilities.container_of primitive but records skipped nodes and
    continues with every child pointer that was readable.
    """

    points: list[object] = []
    skipped_nodes = 0
    try:
        is_rb_tree = mnt_ns.has_member("mounts") and str(
            mnt_ns.mounts.vol.type_name
        ).endswith("!rb_root")
    except (AttributeError, exceptions.InvalidAddressException) as exc:
        artifact_core.record_read_error(diagnostics, "mount.layout", exc)
        is_rb_tree = False

    if not is_rb_tree:
        return list_mount_points(mnt_ns, diagnostics=diagnostics)

    try:
        vmlinux = linux.LinuxUtilities.get_module_from_volobj_type(
            mnt_ns._context, mnt_ns
        )
        stack = [mnt_ns.mounts.rb_node]
    except (AttributeError, exceptions.InvalidAddressException) as exc:
        artifact_core.record_read_error(diagnostics, "mount.rb_root", exc)
        return points, f"PARTIAL:rb-root:{type(exc).__name__}"

    seen_nodes = set()
    while stack:
        node_pointer = stack.pop()
        node_address = None
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
            if not artifact_core._object_readable(
                node_pointer, diagnostics=diagnostics
            ):
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
                except (AttributeError, exceptions.InvalidAddressException) as exc:
                    artifact_core.record_read_error(
                        diagnostics,
                        "mount.rb_child",
                        exc,
                        node_address=node_address,
                        field=member,
                    )
                    skipped_nodes += 1

            mnt = linux.LinuxUtilities.container_of(
                node_pointer, "mount", "mnt_node", vmlinux
            )
            if mnt is None or (
                hasattr(mnt, "has_member")
                and mnt.has_member("mnt_ns")
                and artifact_core._object_address(mnt.mnt_ns)
                != artifact_core._object_address(mnt_ns)
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
        ) as exc:
            artifact_core.record_read_error(
                diagnostics, "mount.rb_node", exc, node_address=node_address
            )
            skipped_nodes += 1
            continue

    status = "COMPLETE" if skipped_nodes == 0 else f"PARTIAL:rb-nodes={skipped_nodes}"
    return points, status


def checked_mount_points(reader, namespace):
    """namespace의 RB tree나 목록에서 mount를 순회하고 소속·개수·root의 일관성을 검사한다."""
    expected = (
        reader.read("mounts.count", namespace, lambda: int(namespace.nr_mounts))
        if namespace.has_member("nr_mounts")
        else None
    )
    expected_root = (
        reader.read("mounts.root", namespace, lambda: int(namespace.root))
        if namespace.has_member("root")
        else None
    )
    observed = set()
    if namespace.has_member("mounts") and namespace.mounts.has_member("rb_node"):
        root = namespace.mounts.rb_node
        offset = reader.kernel.get_type("mount").relative_child_offset("mnt_node")
        stack, seen = [int(root)], set()
        while stack:
            address = stack.pop()
            if not address:
                continue
            if address in seen:
                reader.issue(
                    "mounts.tree",
                    namespace,
                    artifact_core.Incomplete("Repeated RB node"),
                )
                continue
            if len(seen) >= reader.limit:
                raise artifact_core.Incomplete("Mount RB tree node limit")
            seen.add(address)
            node = reader.obj("rb_node", address)
            for field in ("rb_right", "rb_left"):
                child = reader.read(
                    "mounts." + field,
                    node,
                    lambda f=field, node=node: int(node.member(f)),
                )
                if child:
                    stack.append(child)
            mount = reader.obj("mount", address - offset)
            valid = reader.read(
                "mounts.owner",
                mount,
                lambda mount=mount: int(mount.mnt_ns) == int(namespace.vol.offset),
            )
            if valid:
                observed.add(int(mount.vol.offset))
                yield mount
            elif valid is False:
                reader.issue(
                    "mounts.owner",
                    mount,
                    artifact_core.Incomplete("Mount belongs to another namespace"),
                )
    elif namespace.has_member("list"):
        typename = "mount" if reader.kernel.has_type("mount") else "vfsmount"
        for mount in reader.walk(namespace.list, typename, "mnt_list"):
            if mount.has_member("mnt_ns") and int(mount.mnt_ns) != int(
                namespace.vol.offset
            ):
                reader.issue(
                    "mounts.owner",
                    mount,
                    artifact_core.Incomplete("Mount belongs to another namespace"),
                )
                continue
            observed.add(int(mount.vol.offset))
            yield mount
    else:
        raise artifact_core.Unsupported(
            "Mount namespace has neither supported RB tree nor list"
        )
    # A NULL/truncated tree can terminate normally despite missing mounts.
    # Cross-check available namespace metadata before declaring completion.
    if expected is not None and expected != len(observed):
        reader.issue(
            "mounts.count",
            namespace,
            artifact_core.Incomplete(
                f"Namespace declares {expected} mounts, observed {len(observed)}"
            ),
        )
    if expected_root is not None:
        if expected_root and expected_root not in observed:
            reader.issue(
                "mounts.root",
                namespace,
                artifact_core.Incomplete(
                    "Namespace root mount is absent from the traversal"
                ),
            )
        elif not expected_root and observed:
            reader.issue(
                "mounts.root",
                namespace,
                artifact_core.Incomplete("Namespace has mounts but a NULL root mount"),
            )


def stock_mount_points(namespace):
    """Stock extension traversal; callers retain their own bounds and errors."""
    return namespace.get_mount_points()


# File views retain their stronger object-readability checks and status labels.
def mount_current(mnt):
    """현대 커널은 mount.mnt, 옛 커널은 vfsmount 자체가 현재 마운트다."""
    if mnt.has_member("mnt"):
        return mnt.mnt
    if str(getattr(mnt.vol, "type_name", "")).endswith("!vfsmount"):
        return mnt
    return mnt.get_vfsmnt_current()


def file_mount_points(namespace, max_nodes=100000, *, diagnostics=None):
    """구형 연결 리스트와 6.8 이후 RB 트리를 각각 상한/순환 검사하며 읽는다."""
    result, issues = [], 0
    try:
        if not artifact_core._object_readable(namespace, diagnostics=diagnostics):
            raise ValueError("unreadable namespace")
        owner_address = artifact_core._object_address(namespace)
        table = namespace.vol.type_name.split("!", 1)[0]
        context = namespace._context
        if namespace.has_member("list"):
            # 리스트의 끝처럼 보이는 지점이 아니라, 정확히 head로 복귀해야 완료다.
            head = namespace.list
            if not artifact_core._object_readable(head, diagnostics=diagnostics):
                raise ValueError("unreadable list head")
            head_address = artifact_core._object_address(head)
            previous, seen, cursor = head_address, {head_address}, head.next
            kind = (
                "mount"
                if context.symbol_space.has_type(table + "!mount")
                else "vfsmount"
            )
            while artifact_core._object_address(cursor) != head_address:
                address = artifact_core._object_address(cursor)
                if (
                    address in seen
                    or len(result) >= max_nodes
                    or not artifact_core._object_readable(
                        cursor, diagnostics=diagnostics
                    )
                ):
                    raise ValueError("incomplete mount list")
                seen.add(address)
                if artifact_core._object_address(cursor.prev) != previous:
                    raise ValueError("mount list backlink mismatch")
                mnt = artifact_core.containing_object(
                    namespace, cursor, kind, "mnt_list"
                )
                if not artifact_core._object_readable(mnt, diagnostics=diagnostics):
                    raise ValueError("unreadable mount")
                if (
                    mnt.has_member("mnt_ns")
                    and artifact_core._object_address(mnt.mnt_ns) != owner_address
                ):
                    raise ValueError("mount namespace mismatch")
                result.append(mnt)
                previous, cursor = address, cursor.next
            if artifact_core._object_address(head.prev) != previous:
                raise ValueError("mount list tail mismatch")
            return result, "COMPLETE"

        if not (
            namespace.has_member("mounts")
            and str(namespace.mounts.vol.type_name).endswith("!rb_root")
        ):
            raise ValueError("unsupported mount namespace layout")
        # 자식을 mount 해석보다 먼저 큐에 넣어 한 손상 객체가 형제까지 지우지 않게 한다.
        pending, seen = [namespace.mounts.rb_node], set()
        while pending:
            cursor = pending.pop()
            address = None
            try:
                address = artifact_core._object_address(cursor)
                if not address:
                    continue
                if address in seen:
                    issues += 1
                    continue
                if len(seen) >= max_nodes:
                    issues += 1
                    break
                seen.add(address)
                if not artifact_core._object_readable(cursor, diagnostics=diagnostics):
                    issues += 1
                    continue
                node = cursor.dereference()
                for child_name in ("rb_right", "rb_left"):
                    try:
                        child = node.member(child_name)
                        if artifact_core._object_address(child):
                            pending.append(child)
                    except artifact_core.READ_ERRORS as exc:
                        artifact_core.record_read_error(
                            diagnostics,
                            "mount.rb_child",
                            exc,
                            node_address=address,
                            field=child_name,
                        )
                        issues += 1
                mnt = artifact_core.containing_object(
                    namespace, cursor, "mount", "mnt_node"
                )
                if not artifact_core._object_readable(mnt, diagnostics=diagnostics):
                    raise ValueError("unreadable mount")
                if (
                    mnt.has_member("mnt_ns")
                    and artifact_core._object_address(mnt.mnt_ns) != owner_address
                ):
                    raise ValueError("mount namespace mismatch")
                result.append(mnt)
            except artifact_core.READ_ERRORS as exc:
                artifact_core.record_read_error(
                    diagnostics, "mount.rb_node", exc, node_address=address
                )
                issues += 1
        return result, "COMPLETE" if not issues else f"PARTIAL:mount-nodes={issues}"
    except artifact_core.READ_ERRORS as exc:
        artifact_core.record_read_error(diagnostics, "mount.enumeration", exc)
        return result, "PARTIAL:mount-list:" + type(exc).__name__


def namespace_covering(mnt_ns, *, diagnostics=None):
    """프로세스 경로 위에 다른 마운트가 덮여 있는지 확인할 인덱스."""
    result, complete, known = {}, True, set()
    mount_list, status = file_mount_points(mnt_ns, diagnostics=diagnostics)
    complete = status == "COMPLETE"
    for mnt in mount_list:
        try:
            current = artifact_core._object_address(mount_current(mnt))
            parent = artifact_core._object_address(mnt.get_vfsmnt_parent())
            if not current or not parent:
                raise ValueError("null mount")
            known.add(current)
            if current != parent:
                point = mnt.get_mnt_mountpoint()
                if not artifact_core._object_readable(point, diagnostics=diagnostics):
                    raise ValueError("unreadable mountpoint")
                result.setdefault(
                    (parent, artifact_core._object_address(point)), set()
                ).add(current)
        except artifact_core.READ_ERRORS as exc:
            artifact_core.record_read_error(diagnostics, "mount.covering", exc)
            complete = False
    if any(parent not in known for parent, _ in result):
        complete = False
    return result, complete

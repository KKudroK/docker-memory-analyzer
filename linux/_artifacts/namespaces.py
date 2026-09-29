"""Recover namespace identifiers and nested PID values for container analyses.
The readers support task attribution, PID/TID views, and mount/network grouping.
Flexible pid.numbers layouts are validated and incomplete structures remain explicit.

SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from volatility3.framework import exceptions

from . import core as artifact_core


def namespace_inum(namespace, *, member_reader=getattr, missing_error=None):
    if namespace.has_member("ns"):
        return int(member_reader(namespace.ns, "inum"))
    if missing_error is not None and not namespace.has_member("proc_inum"):
        raise missing_error
    return int(namespace.proc_inum)


def _pidtype_pid(module):
    """Use the enum when present; only a missing enum permits the known value.

    Linux's pid_link-based task layout defines PIDTYPE_PID as the first enum
    value (zero), e.g. include/linux/pid.h at Linux v4.18:
    https://github.com/torvalds/linux/blob/v4.18/include/linux/pid.h
    A present but unfamiliar enum is rejected rather than treated as absent.
    """
    try:
        enum = module.get_enumeration("pid_type")
    except (exceptions.SymbolError, KeyError):
        enum = None
    if enum is None:
        return 0, "known Linux pid_link layout: PIDTYPE_PID=0; enum absent"
    index = enum.choices.get("PIDTYPE_PID")
    if type(index) is not int or not 0 <= index < 32:
        raise artifact_core.UnsupportedLayoutError(
            "pid_namespace",
            "pid_type.PIDTYPE_PID",
            "missing or invalid enumeration value",
        )
    return index, "pid_type enumeration"


def inspect_pid_layout(module):
    """Describe one supported PID/namespace layout without reading a task."""
    feature = "pid_namespace"
    task = artifact_core.require_fields(module, "task_struct", ("pid",), feature)
    layout = {}
    if task.has_member("thread_pid"):
        layout["task_pid"] = "thread_pid"
    elif task.has_member("pids"):
        artifact_core.require_fields(module, "pid_link", ("pid",), feature)
        index, source = _pidtype_pid(module)
        layout.update(
            task_pid="pids[PIDTYPE_PID].pid", pidtype_pid=index, pidtype_source=source
        )
    else:
        raise artifact_core.UnsupportedLayoutError(
            feature, "task_struct.thread_pid|pids", "no supported PID pointer member"
        )
    pid = artifact_core.require_fields(module, "pid", ("level", "numbers"), feature)
    upid = artifact_core.require_fields(module, "upid", ("nr", "ns"), feature)
    namespace = artifact_core.require_type(module, "pid_namespace", feature)
    if namespace.has_member("ns"):
        artifact_core.require_fields(module, "ns_common", ("inum",), feature)
        layout["namespace_id"] = "ns.inum"
    elif namespace.has_member("proc_inum"):
        layout["namespace_id"] = "proc_inum"
    else:
        raise artifact_core.UnsupportedLayoutError(
            feature,
            "pid_namespace.ns.inum|proc_inum",
            "no supported namespace identifier member",
        )
    offset, size = pid.relative_child_offset("numbers"), upid.size
    if type(offset) is not int or offset < 0 or offset > pid.size:
        raise artifact_core.UnsupportedLayoutError(
            feature, "pid.numbers", "invalid flexible-array offset"
        )
    if type(size) is not int or size <= 0:
        raise artifact_core.UnsupportedLayoutError(
            feature, "upid", "invalid symbol type size"
        )
    layout.update(numbers_offset=offset, upid_size=size)

    return {"feature": feature, "status": "ok", "layout": layout}


def read_pid_chain(task, module):
    """Return host-to-inner PID namespace IDs for a task's individual TID.

    Both pid.numbers[1] and zero-length flexible ISF arrays are traversed using
    the symbol offset and upid size. A present pointer that cannot be read does
    not trigger a fallback to a different layout.
    """
    layout = inspect_pid_layout(module)["layout"]
    field = "task_struct." + layout["task_pid"]
    try:
        if layout["task_pid"] == "thread_pid":
            pointer = task.thread_pid
        else:
            pointer = task.pids[layout["pidtype_pid"]].pid
        if not int(pointer):
            raise ValueError(f"{field}: null PID pointer")
        pid = pointer.dereference()
        field = "pid.level"
        level = int(pid.level)
        if not 0 <= level <= 32:
            raise ValueError("pid.level: invalid PID namespace level")

        # ISFs may describe pid.numbers as a fixed or flexible array, so derive
        # each upid address from the validated symbol offset and element size.
        base = int(pid.vol.offset) + layout["numbers_offset"]
        result = []
        for index in range(level + 1):
            field = f"pid.numbers[{index}]"
            upid = module.object(
                "upid", offset=base + index * layout["upid_size"], absolute=True
            )
            nr = int(upid.nr)
            if nr < 0:
                raise ValueError(f"{field}.nr: negative PID")
            field += ".ns"
            if not int(upid.ns):
                raise ValueError(f"{field}: null PID namespace pointer")
            namespace = upid.ns.dereference()
            field += "." + layout["namespace_id"]
            inum = (
                int(namespace.ns.inum)
                if layout["namespace_id"] == "ns.inum"
                else int(namespace.proc_inum)
            )
            result.append({"level": index, "id": nr, "namespace": inum})
        field = "task_struct.pid"

        if result[0]["id"] != int(task.pid):
            raise ValueError(
                "task_struct.pid and pid.numbers[0].nr: Host TID and PID-object ID disagree"
            )
        return result
    except (exceptions.InvalidAddressException, AttributeError, IndexError) as exc:
        raise ValueError(
            f"{field}: could not read PID namespace evidence ({type(exc).__name__}: {exc})"
        ) from exc


def read_process_pid_chain(task, module):
    """Follow and validate group_leader before interpreting its TID as a PID."""
    tid, tgid = int(task.pid), int(task.tgid)
    pointer = task.group_leader
    address = int(pointer)
    if tid <= 0 or tgid <= 0 or not address:
        raise ValueError(
            f"group_leader={address:#x}: invalid task PID={tid} TGID={tgid} or null link"
        )
    leader = pointer.dereference()
    leader_pid, leader_tgid = int(leader.pid), int(leader.tgid)
    if leader_pid != tgid or leader_tgid != tgid:
        raise ValueError(
            f"group_leader={address:#x}: leader PID={leader_pid} TGID={leader_tgid} "
            f"does not identify task PID={tid} TGID={tgid}"
        )
    if int(leader.vol.offset) != address or int(leader.group_leader) != address:
        raise ValueError(f"group_leader={address:#x}: leader self-reference mismatch")
    if (
        tid == tgid
        and task.vol.layer_name == leader.vol.layer_name
        and int(task.vol.offset) != address
    ):
        raise ValueError(
            f"group_leader={address:#x}: process leader points to another task"
        )


    task_chain = read_pid_chain(task, module)
    leader_chain = read_pid_chain(leader, module)
    if [row["namespace"] for row in task_chain] != [
        row["namespace"] for row in leader_chain
    ]:
        raise ValueError(f"group_leader={address:#x}: PID namespace chains disagree")
    return leader_chain


def _pid_namespace_values(task) -> tuple[int | None, int | None]:
    """Return (namespace inode, PID as seen in the innermost PID namespace)."""

    try:
        if task.has_member("thread_pid") and task.thread_pid:
            pid_pointer = task.thread_pid
        elif task.has_member("pids") and task.pids[0].pid:


            pid_pointer = task.pids[0].pid
        else:
            return None, None
        pid_object = pid_pointer.dereference()
        level = int(pid_object.level)




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
    except (
        AttributeError,
        IndexError,
        TypeError,
        ValueError,
        exceptions.InvalidAddressException,
    ):
        return None, None


def inventory_pid_chain(reader, task):
    """Collect PIDs and namespace metadata across the task's PID hierarchy.

    Locate the PID through thread_pid or pids, validate hierarchy depth,
    and traverse the upid array without assuming a fixed layout.
    """
    if task.has_member("thread_pid"):
        pid = task.thread_pid
    elif task.has_member("pids"):
        pid = task.pids[0].pid
    else:
        raise artifact_core.Unsupported("task PID link unavailable")
    if not pid:
        return []
    level = int(pid.level)
    if not 0 <= level <= 32:
        raise ValueError("PID namespace depth outside bounds")
    start = pid.numbers.vol.offset
    width = reader.kernel.get_type("upid").size
    result = []
    for index in range(level + 1):
        upid = reader.obj("upid", start + index * width)
        ns = reader.namespace(upid.ns, "pid")
        result.append(
            {
                "level": index,
                "nr": int(upid.nr),
                "namespace": ns,
                "address": hex(upid.vol.offset),
            }
        )
    return result

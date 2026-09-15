"""Task-linked Docker container summaries for stock Volatility 3 >= 2.28.0.

Run ``vol ... -p ./plugins -o ./results ps.Ps --ps``. Each full container ID
has one category/value block. A representative is chosen from an observed
namespace init or attributed direct shim child; ambiguous cases remain unknown.
Only that representative's start time, effective UID and capability are read.
Configured Privileged comes from matching cached hostconfig.json, never a
PID 1 capability comparison. Cache freshness cannot be established from presence.

The reachable leader list is audited in both directions. Identity uses task
cgroups, shim arguments/direct children and conditional standard bind mounts.
Settings recovery uses host-mounted roots and filters to task-linked IDs. It
keeps only the Privileged value and validation evidence, not general settings.
The output has no lifecycle classifier. ps_evidence.json uses schema 4.
"""
import datetime
import hashlib
import json
import logging
import re
import struct
import time

from volatility3.framework import constants, exceptions, interfaces, objects, renderers
from volatility3.framework.configuration import requirements
from volatility3.framework.objects import utility
from volatility3.framework.symbols import linux

vollog = logging.getLogger(__name__)
LIMIT = 100000
FILE_LIMIT = 16 * 1024 * 1024
CID = re.compile(r"[0-9a-f]{64}\Z")
CGROUP_ID = re.compile(r"/(?:docker/|docker-)([0-9a-f]{64})(?:\.scope)?(?=/|$)")
BIND_ID = re.compile(r"(?:^|/)containers/([0-9a-f]{64})/(hosts|hostname|resolv\.conf)\Z")
SETTINGS_FILE = re.compile(r"(?:^|/)containers/([0-9a-f]{64})/hostconfig\.json\Z")
SETTINGS_DIR = re.compile(r"(?:^|/)containers/([0-9a-f]{64})(?=/|$)")
UTC = datetime.timezone.utc
STAGES = ("tasks", "identity", "selection", "details", "settings")
STAGE_SCOPES = {
    "tasks": "reachable process leaders and task-linked cgroups/PID namespaces",
    "identity": "shim arguments/direct children and conditional non-host namespace bind mounts",
    "selection": "one candidate per ID observed on a process leader",
    "details": "selected representative start time and credentials only",
    "settings": "Privileged from hostconfig.json for task-linked IDs; host-mounted roots only",
}


class Unsupported(ValueError):
    """A layout cannot be interpreted without guessing."""


class Incomplete(ValueError):
    """An otherwise supported traversal could not be completed."""


class DuplicateJSONKey(ValueError):
    """Conflicting JSON keys must not become authoritative metadata."""


def utc(seconds, nanoseconds=0):
    if seconds is None:
        return None
    if not 0 <= nanoseconds < 1000000000:
        raise ValueError("Invalid nanoseconds")
    value = datetime.datetime.fromtimestamp(seconds, UTC)
    return (f"{value.year:04d}-{value.month:02d}-{value.day:02d}T{value.hour:02d}:{value.minute:02d}:{value.second:02d}"
            + f".{nanoseconds:09d}Z")


def unique_pairs(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise DuplicateJSONKey("Duplicate JSON key: " + key)
        result[key] = value
    return result


def prefix_json(raw):
    """Only complete top-level key/value pairs in the contiguous prefix count."""
    text = raw.decode("utf-8", errors="surrogateescape")
    decoder = json.JSONDecoder(object_pairs_hook=unique_pairs)
    pos = len(text) - len(text.lstrip())
    result = {}
    if text[pos:pos + 1] != "{":
        return result
    pos += 1
    try:
        while True:
            while text[pos].isspace():
                pos += 1
            key, pos = decoder.raw_decode(text, pos)
            while text[pos].isspace():
                pos += 1
            if not isinstance(key, str) or text[pos] != ":":
                break
            pos += 1
            while text[pos].isspace():
                pos += 1
            value, pos = decoder.raw_decode(text, pos)
            while text[pos].isspace():
                pos += 1
            if text[pos] not in ",}":
                break
            if key in result:
                raise DuplicateJSONKey("Duplicate JSON key: " + key)
            result[key] = value
            if text[pos] == "}":
                break
            pos += 1
    except DuplicateJSONKey:
        raise
    except (ValueError, IndexError):
        pass
    return result


def json_object(raw):
    obj = json.loads(raw, object_pairs_hook=unique_pairs)
    if not isinstance(obj, dict):
        raise ValueError("Metadata is not an object")
    return obj


def capability_mask(value):
    """Read supported symbol-described unsigned layouts; never invent zero."""
    fields = [name for name in ("val", "cap") if value.has_member(name)]
    if len(fields) != 1:
        raise Unsupported("Capability needs one val/cap member")
    name = fields[0]
    offset, template = value.vol.members[name]
    if offset < 0 or offset + template.size > value.vol.size:
        raise Unsupported("Capability exceeds its structure")
    def unsigned(t, sizes):
        return (issubclass(t.vol.object_class, objects.Integer)
                and not issubclass(t.vol.object_class, objects.Pointer)
                and t.size in sizes and not t.vol.data_format.signed)
    if issubclass(template.vol.object_class, objects.Array):
        if name != "cap" or template.vol.count not in (1, 2) or not unsigned(template.vol.subtype, (4,)):
            raise Unsupported("Unsupported capability array")
        return sum(int(word) << (32 * i) for i, word in enumerate(value.member(name)))
    if not unsigned(template, (8,) if name == "val" else (4, 8)):
        raise Unsupported("Unsupported capability integer")
    return int(value.member(name))


def audit_task_list(head, read_link, limit=LIMIT):
    """Audit both directions independently, retaining reachable nodes on failure.

    read_link(address, field) must return a normalized list_head address.
    A union is a recovery set, never a claim that a damaged list is complete.
    """
    result = {"head": hex(head), "directions": {}, "issues": []}
    cache = {}

    def link(address, field):
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


def select_representative(rows, cid):
    """Choose an evidenced container init; PID ordering is never a criterion."""
    eligible = [r for r in rows if r.get("container_ids") == [cid]
                and not r.get("identity_conflicts")]
    chains = [r for r in eligible if r.get("pid_chain")]
    depth = min((len(r["pid_chain"]) - 1 for r in chains), default=None)
    inits = [r for r in chains if depth and len(r["pid_chain"]) - 1 == depth
             and r["pid_chain"][-1]["nr"] == 1]
    direct = [r for r in eligible if r.get("direct_shim", {}).get("container_id") == cid]
    selected, method = None, None
    if len(inits) == 1:
        selected, method = inits[0], "PID_NAMESPACE_INIT"
    elif len(direct) == 1 and (not inits or direct[0] in inits):
        selected, method = direct[0], "SHIM_DIRECT_CHILD"
    candidates = inits or direct
    status = "SELECTED" if selected else "AMBIGUOUS" if len(candidates) > 1 else "UNRESOLVED"
    return selected, {"status": status, "method": method,
        "candidate_tasks": [r["address"] for r in candidates],
        "observed_min_pid_namespace_depth": depth,
        "reason": "unique evidenced representative" if selected else
                  "no unique namespace init or attributed direct shim child"}


def shim_arguments(args):
    """Parse the supported separate-value flags; reject conflicting identities."""
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
    if not CID.fullmatch(cid):
        raise ValueError("Invalid shim container ID")
    return cid, next(iter(namespaces), None)


class Collector:
    def __init__(self, context, kernel_name):
        self.context = context
        self.kernel = context.modules[kernel_name]
        self.layer = context.layers[self.kernel.layer_name]
        self.stage = "tasks"
        self.report = {"schema_version": 4, "method": "One summary per task-linked Docker container",
            "provenance": {"plugin_version": "1.5.1", "volatility_version": constants.PACKAGE_VERSION,
                "collection_started_utc": datetime.datetime.now(UTC).isoformat(),
                "kernel_module": kernel_name, "kernel_layer": self.kernel.layer_name,
                "isf_url": context.symbol_space[self.kernel.symbol_table_name].config.get("isf_url"),
                "input_layers": [{"name": n, "location": context.layers[n].config.get("location")}
                    for n in context.layers if context.layers[n].config.get("location")]},
            "coverage": {}, "errors": [], "tasks": [], "cgroups": [], "namespaces": [],
            "shims": [], "mounts": [], "cached_settings": [], "containers": [],
            "task_list_integrity": [],
            "limits": {"objects_per_traversal": LIMIT, "settings_file_bytes": FILE_LIMIT},
            "scope": "Reachable process leaders; cgroup IDs and limited identity fallback; representative credentials and cached Privileged only",
            "limitations": ["A task-linked candidate does not establish Docker lifecycle state.",
                "A damaged task list remains partial after reverse recovery.",
                "Missing or ambiguous representative evidence is not replaced with the lowest PID.",
                "Cached hostconfig values may be stale; missing data is unknown.",
                "Shim comm/argument forms and Docker path patterns have a bounded supported scope."]}
        self.tasks, self.task_rows, self.namespaces, self.cgroups, self.containers = {}, {}, {}, {}, {}
        self.backward_recovered_tasks = set()
        self.skipped = {}
        self.init, self.boot = None, None


    def process_start(self, task):
        if self.boot is None:
            for symbol, typename in (("timekeeper_data", "tk_data"), ("tk_core", "tk_data"),
                                     ("tk_core_mono", "tk_data"), ("timekeeper", "timekeeper")):
                if self.kernel.has_symbol(symbol) and self.kernel.has_type(typename):
                    candidate = self.symbol(symbol, typename)
                    keeper = candidate.timekeeper if candidate.has_member("timekeeper") else candidate
                    if keeper.has_member("offs_real") and keeper.has_member("offs_boot"):
                        def signed_ns(field):
                            value = keeper.member(field)
                            return int(value.tv64) if value.has_member("tv64") else int(value)
                        self.boot = signed_ns("offs_real") - signed_ns("offs_boot")
                        self.report["boot_time_source"] = {"symbol": symbol, "location": self.location(keeper), "nanoseconds": self.boot}
                        break
        if self.boot is not None and task.has_member("start_boottime"):
            total = self.boot + int(task.start_boottime)
            return utc(*divmod(total, 1000000000))
        value = task.get_create_time()
        if value is None:
            raise Unsupported("Process start time has no verified clock conversion")
        return value.astimezone(UTC).isoformat()


    def address(self, obj):
        return int(obj.vol.offset) if hasattr(obj, "vol") else int(obj)


    def location(self, obj):
        address = self.address(obj)
        result = {"layer": self.kernel.layer_name, "virtual": hex(address)}
        try:
            _, _, physical, _, name = next(self.layer.mapping(address, 1))
            result.update(mapped_layer=name, mapped_offset=hex(physical))
        except (exceptions.InvalidAddressException, StopIteration):
            pass
        return result


    def issue(self, operation, obj, exc):
        try:
            address = hex(self.address(obj))
        except (ValueError, TypeError, AttributeError):
            address = str(obj)
        kind = "UNSUPPORTED" if isinstance(exc, (Unsupported, exceptions.SymbolError, AttributeError)) else "UNREADABLE" if isinstance(exc, exceptions.InvalidAddressException) else "INCOMPLETE" if isinstance(exc, Incomplete) else "ERROR"
        self.report["errors"].append({"stage": self.stage, "operation": operation,
                                     "address": address, "kind": kind,
                                     "exception": type(exc).__name__, "detail": str(exc)})


    def read(self, operation, obj, function, default=None):
        try:
            return function()
        except (exceptions.VolatilityException, ValueError, AttributeError, TypeError,
                KeyError, IndexError, OverflowError, UnicodeError, struct.error) as exc:
            self.issue(operation, obj, exc)
            return default


    def obj(self, name, address):
        return self.kernel.object(name, offset=int(address), absolute=True)


    def symbol(self, name, typename):
        sym = self.kernel.get_symbol(name)
        return self.kernel.object(typename, offset=sym.address, absolute=False)


    def string(self, ptr):
        return utility.pointer_to_string(ptr, 4096) if ptr else ""


    def bounded(self, iterator):
        for index, value in enumerate(iterator):
            if index >= LIMIT:
                raise Incomplete("Traversal budget exceeded")
            yield value


    def namespace(self, ptr, kind, entity=None):
        if not ptr:
            return None
        obj = ptr.dereference() if isinstance(ptr, objects.Pointer) else ptr
        address = self.address(obj)
        key = (kind, address)
        if key not in self.namespaces:
            number = int(obj.ns.inum) if obj.has_member("ns") else int(obj.proc_inum)
            row = {"address": hex(address), "kind": kind, "inum": number, "tasks": []}
            self.namespaces[key] = (obj, row)
            self.report["namespaces"].append(row)
        row = self.namespaces[key][1]
        if entity and entity not in row["tasks"]:
            row["tasks"].append(entity)
        return {"address": row["address"], "inum": row["inum"]}


    def pid_chain(self, task):
        if task.has_member("thread_pid"):
            pid = task.thread_pid
        elif task.has_member("pids"):
            pid = task.pids[0].pid
        else:
            raise Unsupported("task PID link unavailable")
        if not pid:
            return []
        level = int(pid.level)
        if not 0 <= level <= 32:
            raise ValueError("PID namespace depth outside bounds")
        start = pid.numbers.vol.offset
        width = self.kernel.get_type("upid").size
        result = []
        for index in range(level + 1):
            upid = self.obj("upid", start + index * width)
            ns = self.namespace(upid.ns, "pid")
            result.append({"level": index, "nr": int(upid.nr), "namespace": ns,
                           "address": hex(upid.vol.offset)})
        return result


    def task_cgroups(self, task):
        if not task.has_member("cgroups"):
            raise Unsupported("task.cgroups absent")
        if not task.cgroups:
            return []
        css = task.cgroups.dereference()
        groups = {}
        if css.has_member("dfl_cgrp") and css.dfl_cgrp:
            groups[int(css.dfl_cgrp)] = css.dfl_cgrp.dereference()
        if css.has_member("subsys"):
            for ptr in self.bounded(css.subsys):
                if ptr and ptr.cgroup:
                    groups[int(ptr.cgroup)] = ptr.cgroup.dereference()
        return [self.cgroup(group, "task") for group in groups.values()]


    def cgroup_path(self, group):
        node = group.kn.dereference() if group.has_member("kn") and group.kn else group
        if group.has_member("kn") and not group.kn:
            raise ValueError("NULL kernfs node")
        modern = group.has_member("kn")
        parts, seen, trace = [], set(), []
        while node:
            address = self.address(node)
            if address in seen or len(seen) >= LIMIT:
                raise Incomplete("cgroup parent cycle/budget")
            seen.add(address)
            if node.has_member("name"):
                parts.append(self.string(node.name))
            elif node.has_member("name_copy"):
                parts.append(self.string(node.name_copy))
            else:
                raise Unsupported("cgroup name layout unavailable")
            parent = node.member("__parent") if node.has_member("__parent") else node.parent if node.has_member("parent") else node.self.parent.cgroup if not modern and node.self.parent else None
            trace.append({"location": self.location(node), "name": parts[-1], "parent": hex(int(parent)) if parent else "0x0"})
            node = parent.dereference() if parent else None
        return "/" + "/".join(p for p in reversed(parts) if p), trace


    def task_list(self, head, member, kind):
        mask = self.layer.address_mask
        offset = self.kernel.get_type("task_struct").relative_child_offset(member)
        audit = audit_task_list(self.address(head) & mask,
            lambda address, field: int(self.obj("list_head", address).member(field)) & mask)
        audit.update(member=member, kind=kind)
        issue_counts = {}
        for issue in audit["issues"]:
            issue_counts[issue["kind"]] = issue_counts.get(issue["kind"], 0) + 1
        self.report["task_list_integrity"].append({
            "head": audit["head"], "member": member, "kind": kind, "status": audit["status"],
            "directions": {direction: {"count": result["count"], "closed": result["closed"]}
                           for direction, result in audit["directions"].items()},
            "forward_only_count": len(audit["forward_only"]),
            "backward_only_count": len(audit["backward_only"]),
            "issue_counts": issue_counts})
        if audit["status"] != "CONSISTENT":
            vollog.warning("ps: %s list integrity mismatch at %s: forward=%d, backward=%d, "
                "backward-only=%d; recovered union remains PARTIAL", kind, audit["head"],
                audit["directions"]["forward"]["count"], audit["directions"]["backward"]["count"],
                len(audit["backward_only"]))
            self.issue("task list integrity: " + kind, head, Incomplete(
                "Bidirectional list inconsistent: forward={}, backward={}, backward_only={}; "
                "union retained, completeness unproven (see task_list_integrity)".format(
                    audit["directions"]["forward"]["count"], audit["directions"]["backward"]["count"],
                    len(audit["backward_only"]))))
        forward = audit["directions"]["forward"]["nodes"]
        backward = audit["directions"]["backward"]["nodes"]
        backward_only = set(audit["backward_only"])
        for address in dict.fromkeys(forward + backward):
            task = self.obj("task_struct", (address - offset) & mask)
            def validate():
                if int(task.pid) <= 0 or int(task.tgid) <= 0 or not task.group_leader:
                    raise Incomplete("Reachable task has invalid PID/TGID/group_leader")
                utility.array_to_string(task.comm)
                return True
            if not self.read("reachable task validation", task, validate, False):
                continue
            if address in backward_only:
                self.backward_recovered_tasks.add(self.address(task))
            yield task


    def argv(self, task):
        if not task.mm:
            return []
        start, end = int(task.mm.arg_start), int(task.mm.arg_end)
        if not 0 <= end - start <= FILE_LIMIT:
            raise Incomplete("Command line length outside budget")
        layer_name = task.add_process_layer()
        if layer_name is None:
            raise Incomplete("No process address space")
        return self.context.layers[layer_name].read(start, end - start).decode("utf-8", errors="replace").rstrip("\0").split("\0")


    def stage_run(self, name, function):
        self.stage = name
        errors, started = len(self.report["errors"]), time.perf_counter()
        vollog.info("ps: collecting %s", name)
        self.read(name, name, function)
        fields = {"tasks": ("tasks",), "identity": ("shims", "mounts"),
                  "selection": ("containers",), "details": (), "settings": ("cached_settings",)}[name]
        count = sum(len(self.report[f]) for f in fields) if fields else sum(
            bool(c.get("representative")) for c in self.report["containers"])
        issues = self.report["errors"][errors:]
        status = "PARTIAL" if issues else "SKIPPED" if name in self.skipped else "FOUND" if count else "NOT FOUND"
        self.report["coverage"][name] = {"status": status, "records": count,
            "record_collections": list(fields), "errors": len(issues),
            "completed_without_errors": not issues,
            "scope": self.skipped.get(name, STAGE_SCOPES[name]),
            "elapsed_seconds": round(time.perf_counter() - started, 3)}


    def cgroup(self, group, source):
        address = self.address(group)
        if address not in self.cgroups:
            path, _ = self.cgroup_path(group)
            row = {"address": hex(address), "path": path,
                   "container_ids": sorted(set(CGROUP_ID.findall(path))), "location": self.location(group)}
            self.cgroups[address] = (group, row)
            self.report["cgroups"].append(row)
        return self.cgroups[address][1]


    def collect_tasks(self):
        self.init = self.symbol("init_task", "task_struct")
        def leaders():
            for task in self.task_list(self.init.tasks, "tasks", "process_leaders"):
                if int(task.pid) == int(task.tgid):
                    self.tasks[self.address(task)] = task
        self.read("process leader list", self.init, leaders)
        for address, task in self.tasks.items():
            row = {"address": hex(address), "location": self.location(task), "container_ids": [],
                "identity_sources": [], "identity_conflicts": [], "namespaces": {},
                "recovered_from_backward": address in self.backward_recovered_tasks}
            self.report["tasks"].append(row)
            self.task_rows[address] = row
            for field in ("pid", "tgid", "real_parent"):
                row[field] = self.read("task." + field, task, lambda f=field: int(task.member(f)))
            row["comm"] = self.read("task.comm", task, lambda: utility.array_to_string(task.comm))
            def pid_chain():
                chain = self.pid_chain(task)
                if chain and (chain[0]["nr"] != row["pid"] or any(n["namespace"] is None for n in chain)):
                    raise ValueError("PID chain disagrees with task PID or lacks a namespace")
                return chain
            row["pid_chain"] = self.read("task.pid_chain", task, pid_chain, [])
            groups = self.read("task.cgroups", task, lambda: self.task_cgroups(task), [])
            row["cgroups"] = [g["address"] for g in groups]
            row["container_ids"] = sorted({cid for g in groups for cid in g["container_ids"]})
            if row["container_ids"]:
                row["identity_sources"].append("cgroup")
            if len(row["container_ids"]) > 1:
                row["identity_conflicts"].append({"source": "cgroup", "ids": row["container_ids"]})


    def collect_shims(self):
        known = {cid for row in self.report["tasks"] for cid in row["container_ids"]}
        shims = {}
        for address, task in self.tasks.items():
            row = self.task_rows[address]
            if not (row.get("comm") or "").startswith("containerd-shim"):
                continue
            def decode():
                args = self.argv(task)
                cid, namespace = shim_arguments(args)
                record = {"task": row["address"], "pid": row["pid"], "container_id": cid,
                    "runtime_namespace": namespace, "argv": args,
                    "attributed": namespace == "moby" or cid in known, "direct_children": []}
                self.report["shims"].append(record)
                if record["attributed"]:
                    shims[address] = record
            self.read("shim identity", task, decode)
        for row in self.report["tasks"]:
            shim = shims.get(row.get("real_parent"))
            if shim is None:
                continue
            cid = shim["container_id"]
            shim["direct_children"].append(row["address"])
            row["direct_shim"] = {"task": shim["task"], "pid": shim["pid"], "container_id": cid}
            if row["container_ids"] and row["container_ids"] != [cid]:
                row["identity_conflicts"].append({"source": "shim", "container_id": cid,
                    "reason": "direct shim ID disagrees with cgroup IDs"})
            else:
                row["container_ids"] = [cid]
                row["identity_sources"].append("shim_direct_child")


    def mount_namespace(self, task, entity=None):
        if not task.nsproxy or not task.nsproxy.mnt_ns:
            return None
        return self.namespace(task.nsproxy.mnt_ns, "mnt", entity)


    def bind_mount_record(self, mount, task, ns):
        path = linux.LinuxUtilities.get_path_mnt(task, mount)
        if path not in ("/etc/hosts", "/etc/hostname", "/etc/resolv.conf"):
            return
        root = mount.get_mnt_root().dereference()
        parts, seen, current = [], set(), root
        while True:
            address = self.address(current)
            if address in seen or len(seen) >= LIMIT:
                raise Incomplete("Dentry parent cycle/budget")
            seen.add(address)
            name = current.d_name.name_as_str()
            if name not in ("", "/"):
                parts.append(name)
            if int(current.d_parent) == current.vol.offset:
                break
            current = current.d_parent.dereference()
        source = "/" + "/".join(reversed(parts))
        match = BIND_ID.search(source)
        if not match or match[2] != path.rsplit("/", 1)[-1]:
            return
        self.report["mounts"].append({"address": hex(self.address(mount)), "namespace": ns,
            "path": path, "source_path": source, "container_id": match[1], "location": self.location(mount)})


    def collect_mount_identity(self):
        unknown = [r for r in self.report["tasks"] if not r["container_ids"]]
        if not unknown or self.init is None:
            return
        host = self.read("host mount namespace", self.init, lambda: self.mount_namespace(self.init, "host"))
        if host is None:
            self.issue("mount identity scope", "host", Incomplete("Host mount namespace unavailable; fallback skipped"))
            return
        members = {}
        for address, task in self.tasks.items():
            row = self.task_rows[address]
            ns = self.read("task mount namespace", task, lambda t=task: self.mount_namespace(t))
            if ns:
                row["namespaces"]["mnt"] = ns
                members.setdefault(ns["address"], []).append(row)
        for ns, rows in members.items():
            unresolved = [r for r in rows if not r["container_ids"]]
            if not unresolved or ns == host["address"]:
                continue
            prior_ids = {cid for r in rows for cid in r["container_ids"]}
            if len(prior_ids) > 1:
                continue  # Shared namespace with conflicting membership is not an ID fallback.
            task = self.tasks[int(unresolved[0]["address"], 16)]
            start, errors = len(self.report["mounts"]), len(self.report["errors"])
            def scan():
                namespace = self.obj("mnt_namespace", int(ns, 16))
                for mnt in self.bounded(namespace.get_mount_points()):
                    self.read("standard bind mount", mnt, lambda m=mnt: self.bind_mount_record(m, task, ns))
            self.read("mount identity namespace", ns, scan)
            evidence = self.report["mounts"][start:]
            ids = {r["container_id"] for r in evidence}
            if not ids:
                continue
            if len(ids) != 1 or (prior_ids and ids != prior_ids):
                for row in unresolved:
                    row["identity_conflicts"].append({"source": "mounts", "ids": sorted(ids | prior_ids),
                        "reason": "standard bind mounts / namespace identities disagree"})
                continue
            if len(self.report["errors"]) != errors:
                continue  # An incomplete namespace can conceal conflicting bind sources.
            for row in unresolved:
                row["container_ids"] = sorted(ids)
                row["identity_sources"].append("standard_bind_mount")
                row["identity_mounts"] = [r["address"] for r in evidence]


    def collect_identity(self):
        if not self.tasks:
            self.skipped["identity"] = "No observed process leaders to attribute"
            return
        self.read("direct shim discovery", "tasks", self.collect_shims)
        self.read("conditional mount identity", "tasks", self.collect_mount_identity)


    def collect_selection(self):
        groups = {}
        for row in self.report["tasks"]:
            for cid in row["container_ids"]:
                if CID.fullmatch(cid):
                    groups.setdefault(cid, []).append(row)
        for cid, rows in sorted(groups.items()):
            representative, selection = select_representative(rows, cid)
            conflicts = [{"task": r["address"], **conflict}
                         for r in rows for conflict in r["identity_conflicts"]]
            obj = {"id": cid, "task_addresses": [r["address"] for r in rows],
                "representative_task": representative["address"] if representative else None,
                "representative_selection": selection, "representative": None,
                "configured_privileged": None, "settings_refs": [],
                "sources": sorted({source for r in rows for source in r["identity_sources"]}),
                "conflicts": conflicts, "association": "CONFLICT" if conflicts else "TASK_LINKED_CANDIDATE"}
            self.containers[cid] = obj
            self.report["containers"].append(obj)


    def collect_details(self):
        if not self.containers:
            self.skipped["details"] = "No task-linked container candidates"
            return
        for obj in self.containers.values():
            address = obj["representative_task"]
            if address is None:
                continue
            task, row = self.tasks[int(address, 16)], self.task_rows[int(address, 16)]
            record = {"address": address, "pid": row["pid"], "comm": row["comm"],
                "process_start": self.read("representative start time", task, lambda: self.process_start(task)),
                "effective_uid": None, "effective_caps": None}
            obj["representative"] = record
            def credentials():
                if not task.has_member("cred") or not task.cred:
                    raise Unsupported("Representative credentials unavailable")
                cred = task.cred.dereference()
                record["credential_location"] = self.location(cred)
                def effective_uid():
                    value = cred.member("euid")
                    return int(value.val) if value.has_member("val") else int(value)
                record["effective_uid"] = self.read("cred.euid", cred, effective_uid)
                record["effective_caps"] = self.read("cred.cap_effective", cred,
                    lambda: hex(capability_mask(cred.cap_effective)))
            self.read("representative credentials", task, credentials)


    def settings_roots(self):
        """Mounted filesystems reachable from the host; no global VFS/hash scan."""
        if self.init is None:
            raise Incomplete("Host task unavailable for settings")
        ns = self.mount_namespace(self.init, "host")
        if ns is None:
            raise Incomplete("Host mount namespace unavailable for settings")
        roots = {}
        namespace = self.obj("mnt_namespace", int(ns["address"], 16))
        def scan():
            for mount in self.bounded(namespace.get_mount_points()):
                def root():
                    sb = mount.get_mnt_sb().dereference()
                    if sb.s_root:
                        roots[self.address(sb)] = sb.s_root.dereference()
                self.read("settings filesystem root", mount, root)
        self.read("settings mount namespace", namespace, scan)
        return list(roots.values())


    def collect_settings(self):
        if not self.containers:
            self.skipped["settings"] = "No task-linked IDs; hostconfig recovery not requested"
            return
        seen, files = set(), set()
        scope = {"container_ids": sorted(self.containers), "dentries_visited": 0,
                 "source": "host-mounted filesystem roots; matching hostconfig.json only",
                 "roots": 0}
        self.report["settings_scope"] = scope
        roots = self.read("settings roots", "host", self.settings_roots, [])
        scope["roots"] = len(roots)
        for root in roots:
            def scan():
                pending = [(root, "")]
                while pending:
                    dentry, path = pending.pop()
                    address = self.address(dentry)
                    if address in seen:
                        continue
                    if len(seen) >= LIMIT:
                        raise Incomplete("Settings dentry traversal budget")
                    seen.add(address)
                    scope["dentries_visited"] = len(seen)
                    directory_id = SETTINGS_DIR.search(path)
                    if directory_id and directory_id[1] not in self.containers:
                        continue
                    match = SETTINGS_FILE.search(path)
                    if match and match[1] in self.containers and dentry.d_inode:
                        inode = dentry.d_inode.dereference()
                        key = (int(dentry.d_inode), path)
                        if key not in files:
                            files.add(key)
                            self.read("hostconfig inode", inode,
                                lambda: self.recover_privileged(inode, path, match[1]))
                        continue
                    def children():
                        for child in self.bounded(dentry.get_subdirs()):
                            name = self.read("settings dentry name", child, lambda ch=child: ch.d_name.name_as_str())
                            if name and name not in (".", ".."):
                                if directory_id and "/" not in path[directory_id.end():] and name != "hostconfig.json":
                                    continue
                                pending.append((child, path + "/" + name))
                    self.read("settings dentries", dentry, children)
            self.read("hostconfig search", root, scan)
        self.merge_settings()


    def merge_settings(self):
        for cid, obj in self.containers.items():
            rows = [(i, r) for i, r in enumerate(self.report["cached_settings"]) if r["container_id"] == cid]
            obj["settings_refs"] = [i for i, _ in rows]
            values = {r["privileged"] for _, r in rows
                      if type(r.get("privileged")) is bool and not r.get("identity_conflict")}
            conflicts = [{"source": "hostconfig", "index": i, "reason": "Path/JSON IDs disagree"}
                         for i, r in rows if r.get("identity_conflict")]
            if len(values) > 1:
                conflicts.append({"source": "hostconfig", "field": "Privileged", "values": sorted(values),
                                  "reason": "Recovered settings disagree"})
            obj["configured_privileged"] = next(iter(values)) if len(values) == 1 and not conflicts else None
            obj["conflicts"].extend(conflicts)
            if rows and "hostconfig" not in obj["sources"]:
                obj["sources"].append("hostconfig")
            if obj["conflicts"]:
                obj["association"] = "CONFLICT"


    def collect(self):
        for stage in STAGES:
            self.stage_run(stage, getattr(self, "collect_" + stage))
        return self.report


    def read_vmemmap_base(self):
        """Read the declared unsigned word, or its ABI layout if untyped.

        The framework's native pointer format supplies width and byte order;
        compiler-specific C integer type names are never looked up. An invalid
        declared type or an unreadable value must not trigger the untyped path.
        """
        word = self.kernel.get_type("pointer").vol.data_format
        if word.signed or word.length * 8 != self.layer.bits_per_register:
            raise Unsupported("Native pointer layout disagrees with the kernel layer")
        symbol = self.kernel.get_symbol("vmemmap_base")
        template = symbol.type
        if template is not None:
            if isinstance(template, objects.templates.ReferenceTemplate):
                template = self.context.symbol_space.get_type(template.vol.type_name)
            if (not issubclass(template.vol.object_class, objects.Integer)
                    or issubclass(template.vol.object_class, objects.Pointer)
                    or template.size != word.length or template.vol.data_format != word):
                raise Unsupported("vmemmap_base is not an unsigned native-width integer")
            base = int(self.kernel.object_from_symbol("vmemmap_base"))
        else:
            # Some ISFs provide global addresses without variable types. Only
            # this known address-valued global uses the native-word fallback.
            address = self.layer.canonicalize(
                self.kernel.get_absolute_symbol_address("vmemmap_base") & self.layer.address_mask)
            raw = self.layer.read(address, word.length, pad=False)
            if len(raw) != word.length:
                raise Incomplete("Incomplete vmemmap_base value")
            base = int.from_bytes(raw, byteorder=word.byteorder, signed=False)
        if not base or self.layer.canonicalize(base & self.layer.address_mask) != base:
            raise ValueError("Invalid vmemmap_base address")
        return base


    def recover_privileged(self, inode, path, cid):
        if cid not in self.containers:
            return
        filename = "hostconfig.json"
        row = {"path": path, "container_id": cid, "filename": filename, "inode": hex(inode.vol.offset),
               "location": self.location(inode), "pages": [], "holes": [], "json_parse": "NOT FOUND"}
        self.report["cached_settings"].append(row)
        size = int(inode.i_size)
        if not 0 < size <= FILE_LIMIT:
            raise Incomplete("Empty/over-limit metadata inode")
        row["size"] = size
        row["mapping"] = hex(int(inode.i_mapping))
        mapping = inode.i_mapping.dereference()
        storage = linux.IDStorage.choose_id_storage(self.context, self.kernel.name)
        pieces = {}
        page_size = self.layer.page_size
        def recover():
            for page_address in self.bounded(storage.get_entries(mapping.i_pages)):
                page = self.obj("page", page_address)
                def content():
                    if int(page.mapping) != int(inode.i_mapping):
                        raise ValueError("Cached page mapping backlink mismatch")
                    if page.has_member("index"):
                        index = int(page.index)
                    elif self.kernel.has_type("folio"):
                        folio = self.obj("folio", page.vol.offset)
                        # Both views must agree on the mapping member offset.
                        if folio.mapping.vol.offset != page.mapping.vol.offset:
                            raise Unsupported("folio/page mapping layout differs")
                        index = int(folio.index)
                    else:
                        raise Unsupported("Cached page index layout unavailable")
                    offset = index * page_size
                    if not 0 <= offset < size:
                        raise ValueError("Cached page outside inode")
                    if self.kernel.has_symbol("vmemmap_base") and self.kernel.has_symbol("mem_section"):
                        base = self.read_vmemmap_base()
                        address = self.layer.canonicalize(page.vol.offset)
                        width = self.kernel.get_type("page").size
                        if address < base or (address - base) % width:
                            raise ValueError("Page is outside aligned vmemmap")
                        physical = (address - base) // width * page_size
                        raw = self.context.layers[self.layer.config["memory_layer"]].read(physical, page_size)
                    else:
                        raw = page.get_content()
                    if not raw:
                        raise Incomplete("Cached page unreadable")
                    raw = raw[:min(page_size, size - offset)]
                    if offset in pieces and pieces[offset] != raw:
                        raise ValueError("Conflicting cache pages at one file offset")
                    pieces[offset] = raw
                    row["pages"].append({"file_offset": offset, "page": hex(page.vol.offset),
                        "length": len(raw), "sha256": hashlib.sha256(raw).hexdigest()})
                self.read("cached page", page, content)
        self.read("inode pages", inode, recover)
        prefix = bytearray()
        for offset in range(0, size, page_size):
            raw = pieces.get(offset)
            expected = min(page_size, size - offset)
            if raw is None or len(raw) != expected:
                row["holes"].append({"offset": offset, "length": expected})
            if offset == len(prefix) and raw is not None:
                prefix.extend(raw)
        row["contiguous_prefix_bytes"] = len(prefix)
        row["complete"] = len(prefix) == size and not row["holes"]
        if row["holes"]:
            self.issue("metadata coverage", inode, Incomplete("Missing cache ranges; no zero filling"))
        if prefix:
            try:
                data = json_object(bytes(prefix))
                row["json_parse"] = "FULL" if row["complete"] else "PARTIAL"
            except DuplicateJSONKey:
                raise
            except ValueError as exc:
                data = prefix_json(bytes(prefix))
                row["json_parse"] = "PARTIAL"
                self.issue("metadata JSON", inode, Incomplete(str(exc)))
            embedded = data.get("ID")
            row["identity_conflict"] = embedded is not None and embedded != cid
            if row["identity_conflict"]:
                self.issue("metadata identity", inode, ValueError("Path and JSON ID disagree"))

            privileged = data.get("Privileged")
            if "Privileged" in data and type(privileged) is not bool:
                raise ValueError("hostconfig Privileged is not a boolean")
            row["privileged"] = privileged if not row["identity_conflict"] else None


def vertical_presentation(report):
    """One category/value block per container, with raw values only."""
    rows = []
    def cell(value):
        return "-" if value is None or value == "" else str(value).replace("\n", "\\n").replace("\t", "\\t")
    for obj in sorted(report["containers"], key=lambda c: c["id"]):
        if rows:
            rows.append(("", ""))
        process = obj.get("representative") or {}
        selection = obj["representative_selection"]
        fields = [("Container ID", obj["id"]), ("Command", process.get("comm")),
            ("Process Start UTC", process.get("process_start")), ("Host PID", process.get("pid")),
            ("Effective UID", process.get("effective_uid")), ("Effective Caps", process.get("effective_caps")),
            ("Configured Privileged", obj.get("configured_privileged")),
            ("Representative", selection["method"] or selection["status"]),
            ("Association", obj["association"]), ("Sources", ",".join(obj["sources"]))]
        rows.extend((name, cell(value)) for name, value in fields)
    return [("category", str), ("value", str)], rows


class Ps(interfaces.plugins.PluginInterface):
    """Summarize task-linked Docker containers and representative credentials."""
    _required_framework_version = (2, 28, 0)
    _version = (1, 5, 1)

    @classmethod
    def get_requirements(cls):
        return [requirements.ModuleRequirement(name="kernel", description="Linux kernel", architectures=["Intel32", "Intel64"]),
                requirements.BooleanRequirement(name="ps", description="One summary per task-linked Docker container", optional=True, default=False)]

    def run(self):
        if not self.config.get("ps", False):
            raise exceptions.VolatilityException("Select --ps to run the container summary")
        report = Collector(self.context, self.config["kernel"]).collect()
        with self.open("ps_evidence.json") as output:
            output.write(json.dumps(report, ensure_ascii=False, indent=2).encode("utf-8"))
        if report["errors"]:
            vollog.warning("ps: %d collection issues; review coverage in ps_evidence.json", len(report["errors"]))
        unresolved = sum(c["representative"] is None for c in report["containers"])
        if unresolved:
            vollog.warning("ps: %d container candidates have no unambiguous representative", unresolved)
        if not report["containers"]:
            vollog.warning("ps: no task-linked Docker candidates in the searched process list; review coverage")
        columns, rows = vertical_presentation(report)
        return renderers.TreeGrid(columns, ((0, row) for row in rows))

"""Build container inventory and representative-process summaries from memory.
The --ps option correlates cgroups, shim arguments, namespaces, and verified mounts.
It reports representative PID, start time, credentials, attribution, and cached
Privileged configuration while keeping ambiguity explicit in ps_evidence.json.
"""

import datetime
import hashlib
import json
import logging
import re
import struct
import time

from volatility3.framework import constants, exceptions, objects, renderers
from volatility3.framework.objects import utility
from volatility3.framework.symbols import linux
from volatility3.plugins.linux import docker_artifacts
from volatility3.plugins.linux._artifacts import cgroups as cgroup_readers
from volatility3.plugins.linux._artifacts import core as artifact_core
from volatility3.plugins.linux._artifacts import credentials as credential_readers
from volatility3.plugins.linux._artifacts import mounts as mount_readers
from volatility3.plugins.linux._artifacts import namespaces as namespace_readers
from volatility3.plugins.linux._artifacts import tasks as task_readers
from volatility3.plugins.linux._artifacts import timing as timing_readers

vollog = logging.getLogger(__name__)


VERSION = (2, 1, 1)
LIMIT = 100000
FILE_LIMIT = 16 * 1024 * 1024
SETTINGS_MOUNT_LIMIT = 2048
SETTINGS_CHILD_LIMIT = 4096
SETTINGS_SECONDS = 20
CID = re.compile(r"[0-9a-f]{64}\Z")
CGROUP_ID = re.compile(r"/(?:docker/|docker-)([0-9a-f]{64})(?:\.scope)?(?=/|$)")
BIND_ID = re.compile(
    r"(?:^|/)containers/([0-9a-f]{64})/(hosts|hostname|resolv\.conf)\Z"
)
UTC = datetime.timezone.utc
STAGES = ("tasks", "identity", "selection", "details", "settings")
STAGE_SCOPES = {
    "tasks": "reachable process leaders and task-linked cgroups/PID namespaces",
    "identity": "shim arguments/direct children and conditional non-host namespace bind mounts",
    "selection": "one candidate per ID observed on a process leader",
    "details": "selected representative start time and credentials only",
    "settings": "Privileged from verified container bind-mount directories; bounded lookup",
}


class DuplicateJSONKey(ValueError):
    """Conflicting JSON keys must not become authoritative metadata."""


def utc(seconds, nanoseconds=0):
    """Convert seconds and nanoseconds to a UTC timestamp, or return None.

    Validate the input range, convert the epoch seconds, and append nanoseconds.
    """
    if seconds is None:
        return None
    if not 0 <= nanoseconds < 1000000000:
        raise ValueError("Invalid nanoseconds")
    value = datetime.datetime.fromtimestamp(seconds, UTC)
    return (
        f"{value.year:04d}-{value.month:02d}-{value.day:02d}T{value.hour:02d}:{value.minute:02d}:{value.second:02d}"
        + f".{nanoseconds:09d}Z"
    )


def unique_pairs(pairs):
    """Build a dictionary from JSON pairs and reject duplicate keys.

    Insert keys in order and raise when an existing key appears again.
    """
    result = {}
    for key, value in pairs:
        if key in result:
            raise DuplicateJSONKey("Duplicate JSON key: " + key)
        result[key] = value
    return result


def prefix_json(raw):
    """Recover complete top-level pairs from the contiguous prefix of partial JSON.

    Retain fully decoded pairs from the start and stop at incomplete trailing data.
    """
    text = raw.decode("utf-8", errors="surrogateescape")
    decoder = json.JSONDecoder(object_pairs_hook=unique_pairs)
    pos = len(text) - len(text.lstrip())
    result = {}
    if text[pos : pos + 1] != "{":
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
    """Decode JSON with duplicate-key detection and require a top-level object.

    Apply the pair validator and verify that the decoded result is a dictionary.
    """
    obj = json.loads(raw, object_pairs_hook=unique_pairs)
    if not isinstance(obj, dict):

        raise ValueError("Metadata is not an object")
    return obj


def select_representative(rows, cid):
    """Select one evidenced namespace init or direct shim child as representative.

    Consider only conflict-free tasks, prefer a unique namespace PID 1, and use
    an attributed direct shim child when appropriate. Never select by lowest PID.
    """
    eligible = [
        r
        for r in rows
        if r.get("container_ids") == [cid] and not r.get("identity_conflicts")
    ]
    chains = [r for r in eligible if r.get("pid_chain")]
    depth = min((len(r["pid_chain"]) - 1 for r in chains), default=None)
    inits = [
        r
        for r in chains
        if depth and len(r["pid_chain"]) - 1 == depth and r["pid_chain"][-1]["nr"] == 1
    ]
    direct = [
        r for r in eligible if r.get("direct_shim", {}).get("container_id") == cid
    ]
    selected, method = None, None
    if len(inits) == 1:
        selected, method = inits[0], "PID_NAMESPACE_INIT"
    elif len(direct) == 1 and (not inits or direct[0] in inits):
        selected, method = direct[0], "SHIM_DIRECT_CHILD"
    candidates = inits or direct
    status = (
        "SELECTED" if selected else "AMBIGUOUS" if len(candidates) > 1 else "UNRESOLVED"
    )
    return selected, {
        "status": status,
        "method": method,
        "candidate_tasks": [r["address"] for r in candidates],
        "observed_min_pid_namespace_depth": depth,
        "reason": "unique evidenced representative"
        if selected
        else "no unique namespace init or attributed direct shim child",
    }


class Collector(artifact_core.CollectionSession):
    def __init__(self, context, kernel_name):
        """Initialize kernel access, evidence, errors, provenance, and lookup stores.

        Resolve the kernel module and layer, then create the staged report and
        address-indexed collections used throughout inventory generation.
        """
        super().__init__(context, kernel_name)
        self.stage = "tasks"
        self.report = {
            "schema_version": 5,
            "method": "One summary per task-linked Docker container",
            "provenance": {
                "plugin_version": ".".join(map(str, VERSION)),
                "volatility_version": constants.PACKAGE_VERSION,
                "collection_started_utc": datetime.datetime.now(UTC).isoformat(),
                "kernel_module": kernel_name,
                "kernel_layer": self.kernel.layer_name,
                "isf_url": context.symbol_space[
                    self.kernel.symbol_table_name
                ].config.get("isf_url"),
                "input_layers": [
                    {"name": n, "location": context.layers[n].config.get("location")}
                    for n in context.layers
                    if context.layers[n].config.get("location")
                ],
            },
            "coverage": {},
            "errors": [],
            "tasks": [],
            "cgroups": [],
            "namespaces": [],
            "shims": [],
            "mounts": [],
            "cached_settings": [],
            "containers": [],
            "task_list_integrity": [],
            "limits": {
                "objects_per_traversal": LIMIT,
                "settings_file_bytes": FILE_LIMIT,
                "settings_mounts_per_container": SETTINGS_MOUNT_LIMIT,
                "settings_children_per_directory": SETTINGS_CHILD_LIMIT,
                "settings_seconds": SETTINGS_SECONDS,
            },
            "scope": "Reachable process leaders; cgroup IDs and limited identity fallback; representative credentials and cached Privileged only",
            "limitations": [
                "A task-linked candidate does not establish Docker lifecycle state.",
                "A damaged task list remains partial after reverse recovery.",
                "Missing or ambiguous representative evidence is not replaced with the lowest PID.",
                "Cached hostconfig values may be stale; missing data is unknown.",
                "Shim comm/argument forms and Docker path patterns have a bounded supported scope.",
            ],
        }
        self.tasks, self.task_rows, self.namespaces, self.cgroups, self.containers = (
            {},
            {},
            {},
            {},
            {},
        )
        self.backward_recovered_tasks = set()
        self.runtime_scopes = {}
        self.skipped = {}
        self.init, self.boot = None, None

    def process_start(self, task):
        if self.boot is None:
            self.boot = self.kernel_boot_ns()
        return utc(
            *divmod(timing_readers.read_process_start_ns(task, self.boot), 1000000000)
        )

    def kernel_boot_ns(self):
        source = timing_readers.read_kernel_boot(self)
        self.report["boot_time_source"] = {
            "symbol": source.symbol,
            "layout": source.layout,
            "location": self.location(source.keeper),
            "nanoseconds": source.nanoseconds,
        }
        return source.nanoseconds

    def address(self, obj):
        """Return a Volatility object's memory offset or a supplied address as int.

        Prefer obj.vol.offset when present; otherwise convert the value directly.
        """
        return int(obj.vol.offset) if hasattr(obj, "vol") else int(obj)

    def location(self, obj):
        """Record an object's virtual location and mapped lower-layer location.

        Always retain the virtual address and add mapping details when translation succeeds.
        """
        address = self.address(obj)
        result = {"layer": self.kernel.layer_name, "virtual": hex(address)}
        try:
            _, _, physical, _, name = next(self.layer.mapping(address, 1))
            result.update(mapped_layer=name, mapped_offset=hex(physical))
        except (exceptions.InvalidAddressException, StopIteration):
            pass
        return result

    def issue(self, operation, obj, exc):
        """Classify and record a collection error with stage, address, and detail.

        Normalize the address, classify the exception, and append it to the current stage.
        """
        try:
            address = hex(self.address(obj))
        except (ValueError, TypeError, AttributeError):
            address = str(obj)
        kind = (
            "UNSUPPORTED"
            if isinstance(
                exc, (artifact_core.Unsupported, exceptions.SymbolError, AttributeError)
            )
            else "UNREADABLE"
            if isinstance(exc, exceptions.InvalidAddressException)
            else "INCOMPLETE"
            if isinstance(exc, artifact_core.Incomplete)
            else "ERROR"
        )
        self.report["errors"].append(
            {
                "stage": self.stage,
                "operation": operation,
                "address": address,
                "kind": kind,
                "exception": type(exc).__name__,
                "detail": artifact_core.exception_detail(exc),
            }
        )

    def read(self, operation, obj, function, default=None):
        """Run a read or decode operation and isolate expected failures.

        Record supported exception types through issue and return the supplied default.
        """
        try:
            return function()
        except (
            exceptions.VolatilityException,
            ValueError,
            AttributeError,
            TypeError,
            KeyError,
            IndexError,
            OverflowError,
            UnicodeError,
            struct.error,
        ) as exc:
            self.issue(operation, obj, exc)
            return default

    def string(self, ptr):
        return artifact_core.pointer_string(ptr)

    def bounded(self, iterator):
        return artifact_core.bounded(iterator, LIMIT)

    def namespace(self, ptr, kind, entity=None):
        """Record each namespace once and associate it with referencing tasks.

        Dereference the pointer, reuse the address-indexed record, and append the entity.
        """
        if not ptr:
            return None
        obj = ptr.dereference() if isinstance(ptr, objects.Pointer) else ptr
        address = self.address(obj)
        key = (kind, address)
        if key not in self.namespaces:
            number = namespace_readers.namespace_inum(obj)
            row = {"address": hex(address), "kind": kind, "inum": number, "tasks": []}
            self.namespaces[key] = (obj, row)
            self.report["namespaces"].append(row)
        row = self.namespaces[key][1]
        if entity and entity not in row["tasks"]:
            row["tasks"].append(entity)
        return {"address": row["address"], "inum": row["inum"]}

    def pid_chain(self, task):
        return namespace_readers.inventory_pid_chain(self, task)

    def task_cgroups(self, task):
        if not task.has_member("cgroups"):
            raise artifact_core.Unsupported("task.cgroups absent")
        if not task.cgroups:
            return []
        groups = cgroup_readers.effective_cgroups(
            task.cgroups.dereference(), states=self.bounded
        )
        return [self.cgroup(group, "task") for group in groups]

    def cgroup_path(self, group):
        return cgroup_readers.effective_cgroup_path(
            group,
            self.string,
            LIMIT,
            policy=cgroup_readers.CgroupPathPolicy.INVENTORY,
            location=self.location,
        )

    def task_list(self, head, member, kind):
        """Merge and validate tasks found by bidirectional list traversal.

        Validate recovered task_struct objects and retain integrity mismatches and
        backward-only recovery as explicit evidence.
        """
        mask = self.layer.address_mask
        offset = self.kernel.get_type("task_struct").relative_child_offset(member)
        audit = docker_artifacts.DockerArtifacts.audit_task_list(
            self.context, self.kernel_name, self.address(head)
        )
        audit.update(member=member, kind=kind)
        issue_counts = {}
        for issue in audit["issues"]:
            issue_counts[issue["kind"]] = issue_counts.get(issue["kind"], 0) + 1
        self.report["task_list_integrity"].append(
            {
                "head": audit["head"],
                "member": member,
                "kind": kind,
                "status": audit["status"],
                "directions": {
                    direction: {"count": result["count"], "closed": result["closed"]}
                    for direction, result in audit["directions"].items()
                },
                "forward_only_count": len(audit["forward_only"]),
                "backward_only_count": len(audit["backward_only"]),
                "issue_counts": issue_counts,
            }
        )
        if audit["status"] != "CONSISTENT":
            vollog.warning(
                "ps: %s list integrity mismatch at %s: forward=%d, backward=%d, "
                "backward-only=%d; recovered union remains PARTIAL",
                kind,
                audit["head"],
                audit["directions"]["forward"]["count"],
                audit["directions"]["backward"]["count"],
                len(audit["backward_only"]),
            )
            self.issue(
                "task list integrity: " + kind,
                head,
                artifact_core.Incomplete(
                    f"Bidirectional list inconsistent: forward={audit['directions']['forward']['count']}, "
                    f"backward={audit['directions']['backward']['count']}, "
                    f"backward_only={len(audit['backward_only'])}; "
                    "union retained, completeness unproven (see task_list_integrity)"
                ),
            )
        forward = audit["directions"]["forward"]["nodes"]
        backward = audit["directions"]["backward"]["nodes"]
        backward_only = set(audit["backward_only"])
        for address in dict.fromkeys(forward + backward):
            task = self.obj("task_struct", (address - offset) & mask)

            def validate(*, task=task):
                """Validate PID, TGID, group_leader, and comm for a reachable task.

                Require positive IDs, a group leader, and a readable command name.
                """
                if int(task.pid) <= 0 or int(task.tgid) <= 0 or not task.group_leader:
                    raise artifact_core.Incomplete(
                        "Reachable task has invalid PID/TGID/group_leader"
                    )
                utility.array_to_string(task.comm)
                return True

            if not self.read("reachable task validation", task, validate, False):
                continue
            if address in backward_only:
                self.backward_recovered_tasks.add(self.address(task))
            yield task

    def argv(self, task):
        return docker_artifacts.DockerArtifacts.read_task_argv(
            self.context,
            self.kernel_name,
            int(task.vol.offset),
            policy="inventory",
            limit=FILE_LIMIT,
            layer_name=task.vol.layer_name,
            native_layer_name=task.vol.native_layer_name,
        )

    def stage_run(self, name, function):
        """Run one collection stage and record count, errors, scope, status, and time.

        Execute through the isolated read path and derive coverage from collected
        records and new errors.
        """
        self.stage = name
        errors, started = len(self.report["errors"]), time.perf_counter()
        vollog.info("ps: collecting %s", name)
        self.read(name, name, function)
        fields = {
            "tasks": ("tasks",),
            "identity": ("shims", "mounts"),
            "selection": ("containers",),
            "details": (),
            "settings": ("cached_settings",),
        }[name]
        count = (
            sum(len(self.report[f]) for f in fields)
            if fields
            else sum(bool(c.get("representative")) for c in self.report["containers"])
        )
        issues = self.report["errors"][errors:]
        status = (
            "PARTIAL"
            if issues
            else "SKIPPED"
            if name in self.skipped
            else "FOUND"
            if count
            else "NOT FOUND"
        )
        self.report["coverage"][name] = {
            "status": status,
            "records": count,
            "record_collections": list(fields),
            "errors": len(issues),
            "completed_without_errors": not issues,
            "scope": self.skipped.get(name, STAGE_SCOPES[name]),
            "elapsed_seconds": round(time.perf_counter() - started, 3),
        }

    def cgroup(self, group, source):
        """Extract Docker IDs and store each cgroup once by address.

        Create its path, IDs, and memory location on first observation, then reuse the record.
        """
        address = self.address(group)
        if address not in self.cgroups:
            path, _ = self.cgroup_path(group)
            row = {
                "address": hex(address),
                "path": path,
                "container_ids": sorted(set(CGROUP_ID.findall(path))),
                "location": self.location(group),
            }
            self.cgroups[address] = (group, row)
            self.report["cgroups"].append(row)
        return self.cgroups[address][1]

    def collect_tasks(self):
        """Collect process leaders and their PID, parent, command, namespace, and cgroup evidence.

        Record identity sources and conflicts after reading each reachable leader.
        """
        self.init = self.symbol("init_task", "task_struct")

        def leaders():
            """Store process leaders whose PID equals TGID from the validated task list.

            Index qualifying tasks by address after bidirectional traversal.
            """
            for task in self.task_list(self.init.tasks, "tasks", "process_leaders"):
                if int(task.pid) == int(task.tgid):
                    self.tasks[self.address(task)] = task

        self.read("process leader list", self.init, leaders)
        for address, task in self.tasks.items():
            row = {
                "address": hex(address),
                "location": self.location(task),
                "container_ids": [],
                "identity_sources": [],
                "identity_conflicts": [],
                "namespaces": {},
                "recovered_from_backward": address in self.backward_recovered_tasks,
            }
            self.report["tasks"].append(row)
            self.task_rows[address] = row
            for field in ("pid", "tgid", "real_parent"):
                row[field] = self.read(
                    "task." + field,
                    task,
                    lambda f=field, task=task: int(task.member(f)),
                )
            row["comm"] = self.read(
                "task.comm", task, lambda task=task: utility.array_to_string(task.comm)
            )

            def pid_chain(*, row=row, task=task):
                """Read the PID namespace chain and validate its host PID and namespaces.

                Require the first PID to match the task and every level to name a namespace.
                """
                chain = self.pid_chain(task)
                if chain and (
                    chain[0]["nr"] != row["pid"]
                    or any(n["namespace"] is None for n in chain)
                ):
                    raise ValueError(
                        "PID chain disagrees with task PID or lacks a namespace"
                    )
                return chain

            row["pid_chain"] = self.read("task.pid_chain", task, pid_chain, [])
            groups = self.read(
                "task.cgroups", task, lambda task=task: self.task_cgroups(task), []
            )
            row["cgroups"] = [g["address"] for g in groups]
            container_ids = set()
            for group in groups:
                container_ids.update(group["container_ids"])
            row["container_ids"] = sorted(container_ids)
            if row["container_ids"]:
                row["identity_sources"].append("cgroup")
            if len(row["container_ids"]) > 1:
                row["identity_conflicts"].append(
                    {"source": "cgroup", "ids": row["container_ids"]}
                )

    def collect_shims(self):
        """Attribute Docker shims and enrich direct children without hiding conflicts.

        Decode shim arguments, decide attribution, and attach or dispute the ID on direct children.
        """
        known = set()
        for row in self.report["tasks"]:
            known.update(row["container_ids"])
        shims = {}
        for address, task in self.tasks.items():
            row = self.task_rows[address]
            if not (row.get("comm") or "").startswith("containerd-shim"):
                continue

            def decode(*, address=address, row=row, task=task):
                """Keep explicit runtime scope even when the ID is not a Docker ID."""
                args = self.argv(task)
                identity = task_readers.shim_metadata(args)
                cid = identity["container_id"]
                namespace = identity["runtime_namespace"]
                record = {
                    "task": row["address"],
                    "pid": row["pid"],
                    "container_id": cid,
                    "runtime_namespace": namespace,
                    "argv": args,
                    "raw_id": identity["raw_id"],
                    "errors": identity["errors"],
                    "attributed": cid is not None
                    and (namespace == "moby" or (namespace is None and cid in known)),
                    "direct_children": [],
                }
                self.report["shims"].append(record)
                shims[address] = record

            self.read("shim identity", task, decode)
        for row in self.report["tasks"]:


            node, seen = row, set()
            while node.get("real_parent") in self.task_rows:
                parent = node["real_parent"]
                if parent in seen or len(seen) >= LIMIT:
                    self.issue(
                        "shim ancestry",
                        row["address"],
                        ValueError("parent cycle/limit"),
                    )
                    break
                seen.add(parent)
                ancestor = shims.get(parent)
                if ancestor is not None:
                    namespace = ancestor["runtime_namespace"]
                    row["runtime_namespace"] = namespace
                    self.runtime_scopes[row["address"]] = ancestor
                    self.check_runtime_scope(row)
                    break
                node = self.task_rows[parent]
            shim = shims.get(row.get("real_parent"))
            if shim is None:
                continue
            cid = shim["container_id"]
            shim["direct_children"].append(row["address"])
            if not shim["attributed"]:
                continue
            row["direct_shim"] = {
                "task": shim["task"],
                "pid": shim["pid"],
                "container_id": cid,
            }
            if row["container_ids"] and row["container_ids"] != [cid]:
                row["identity_conflicts"].append(
                    {
                        "source": "shim",
                        "container_id": cid,
                        "reason": "direct shim ID disagrees with cgroup IDs",
                    }
                )
            else:
                row["container_ids"] = [cid]
                row["identity_sources"].append("shim_direct_child")

    def check_runtime_scope(self, row):
        """Apply retained namespace counterevidence after any ID enrichment."""
        shim = self.runtime_scopes.get(row["address"])
        if (
            shim is None
            or shim["runtime_namespace"] in (None, "moby")
            or not row["container_ids"]
        ):
            return
        conflict = {
            "source": "shim_namespace",
            "runtime_namespace": shim["runtime_namespace"],
            "shim_task": shim["task"],
            "reason": "Docker ID conflicts with explicit non-moby runtime namespace",
        }
        if conflict not in row["identity_conflicts"]:
            row["identity_conflicts"].append(conflict)

    def mount_namespace(self, task, entity=None):
        """Read a task's mount namespace and register it in the shared namespace store.

        Validate nsproxy.mnt_ns before passing it to the common namespace collector.
        """
        if not task.nsproxy or not task.nsproxy.mnt_ns:
            return None
        return self.namespace(task.nsproxy.mnt_ns, "mnt", entity)

    def bind_mount_record(self, mount, task, ns):
        """Recover a standard settings bind source and record its container ID.

        Restrict the check to standard /etc files and validate both ID and filename.
        """
        source = self.standard_bind_source(mount, task)
        if source is None:
            return
        cid, path, source_path, _ = source
        self.report["mounts"].append(
            {
                "address": hex(self.address(mount)),
                "namespace": ns,
                "path": path,
                "source_path": source_path,
                "container_id": cid,
                "location": self.location(mount),
            }
        )

    def standard_bind_source(self, mount, task):
        """Validate and return the source file and directory of a standard /etc bind.

        Check the filename, visible mount path, parent dentry, and source-path ID together.
        """
        root = mount.get_mnt_root().dereference()
        filename = root.d_name.name_as_str()
        if filename not in ("hosts", "hostname", "resolv.conf"):
            return None
        path = linux.LinuxUtilities.get_path_mnt(task, mount)
        if path != "/etc/" + filename:
            return None
        directory = root.d_parent.dereference()
        cid = directory.d_name.name_as_str()
        if (
            not CID.fullmatch(cid)
            or directory.d_parent.dereference().d_name.name_as_str() != "containers"
        ):
            return None
        parts, seen, current = [], set(), root
        while True:
            address = self.address(current)
            if address in seen or len(seen) >= 256:
                raise artifact_core.Incomplete("Dentry parent cycle/budget")
            seen.add(address)
            name = current.d_name.name_as_str()
            if name not in ("", "/"):
                parts.append(name)
            if int(current.d_parent) == current.vol.offset:
                break
            current = current.d_parent.dereference()
        source = "/" + "/".join(reversed(parts))
        match = BIND_ID.search(source)
        if not match or match[1] != cid or match[2] != filename:
            return None
        return cid, path, source, directory

    def collect_mount_identity(self):
        """Use non-host mount namespaces to enrich otherwise unidentified tasks.

        Group tasks by namespace and accept a standard-bind ID only when it is unique,
        conflict-free, and obtained from a complete traversal.
        """
        unknown = [r for r in self.report["tasks"] if not r["container_ids"]]
        if not unknown or self.init is None:
            return
        host = self.read(
            "host mount namespace",
            self.init,
            lambda: self.mount_namespace(self.init, "host"),
        )
        if host is None:
            self.issue(
                "mount identity scope",
                "host",
                artifact_core.Incomplete(
                    "Host mount namespace unavailable; fallback skipped"
                ),
            )
            return
        members = {}
        for address, task in self.tasks.items():
            row = self.task_rows[address]
            ns = self.read(
                "task mount namespace", task, lambda t=task: self.mount_namespace(t)
            )
            if ns:
                row["namespaces"]["mnt"] = ns
                members.setdefault(ns["address"], []).append(row)
        for ns, rows in members.items():
            unresolved = [r for r in rows if not r["container_ids"]]
            if not unresolved or ns == host["address"]:
                continue
            prior_ids = set()
            for row in rows:
                prior_ids.update(row["container_ids"])
            if len(prior_ids) > 1:
                continue
            task = self.tasks[int(unresolved[0]["address"], 16)]
            start, errors = len(self.report["mounts"]), len(self.report["errors"])

            def scan(*, ns=ns, task=task):
                """Collect standard-bind identity evidence from a bounded namespace traversal.

                Inspect each reachable mount for a validated bind-source ID.
                """
                namespace = self.obj("mnt_namespace", int(ns, 16))
                for mnt in self.bounded(mount_readers.stock_mount_points(namespace)):
                    self.read(
                        "standard bind mount",
                        mnt,
                        lambda m=mnt, ns=ns, task=task: self.bind_mount_record(
                            m, task, ns
                        ),
                    )

            self.read("mount identity namespace", ns, scan)
            evidence = self.report["mounts"][start:]
            ids = {r["container_id"] for r in evidence}
            if not ids:
                continue
            if len(ids) != 1 or (prior_ids and ids != prior_ids):
                for row in unresolved:
                    row["identity_conflicts"].append(
                        {
                            "source": "mounts",
                            "ids": sorted(ids | prior_ids),
                            "reason": "standard bind mounts / namespace identities disagree",
                        }
                    )
                continue
            if len(self.report["errors"]) != errors:
                continue
            for row in unresolved:
                row["container_ids"] = sorted(ids)
                row["identity_sources"].append("standard_bind_mount")
                row["identity_mounts"] = [r["address"] for r in evidence]
                self.check_runtime_scope(row)

    def collect_identity(self):
        """Enrich observed tasks through shim evidence and conditional mount analysis.

        Skip when no leaders were observed; otherwise run both identity sources in order.
        """
        if not self.tasks:
            self.skipped["identity"] = "No observed process leaders to attribute"
            return
        self.read("direct shim discovery", "tasks", self.collect_shims)
        self.read("conditional mount identity", "tasks", self.collect_mount_identity)

    def collect_selection(self):
        """Group tasks by full container ID and store representative-selection evidence.

        Preserve linked tasks, sources, and conflicts for every validated candidate ID.
        """
        groups = {}
        for row in self.report["tasks"]:
            for cid in row["container_ids"]:
                if CID.fullmatch(cid):
                    groups.setdefault(cid, []).append(row)
        for cid, rows in sorted(groups.items()):
            representative, selection = select_representative(rows, cid)
            conflicts = []
            sources = set()
            for row in rows:
                for conflict in row["identity_conflicts"]:
                    conflicts.append({"task": row["address"], **conflict})
                sources.update(row["identity_sources"])
            obj = {
                "id": cid,
                "task_addresses": [r["address"] for r in rows],
                "representative_task": representative["address"]
                if representative
                else None,
                "representative_selection": selection,
                "representative": None,
                "configured_privileged": None,
                "settings_refs": [],
                "sources": sorted(sources),
                "conflicts": conflicts,
                "association": "CONFLICT" if conflicts else "TASK_LINKED_CANDIDATE",
            }
            self.containers[cid] = obj
            self.report["containers"].append(obj)

    def collect_details(self):
        """Collect PID, command, start time, and credentials for selected representatives.

        Resolve the selected task and read timing and cred; never infer credentials without one.
        """
        if not self.containers:
            self.skipped["details"] = "No task-linked container candidates"
            return
        for obj in self.containers.values():
            address = obj["representative_task"]
            if address is None:
                continue
            task, row = self.tasks[int(address, 16)], self.task_rows[int(address, 16)]
            record = {
                "address": address,
                "pid": row["pid"],
                "comm": row["comm"],
                "process_start": self.read(
                    "representative start time",
                    task,
                    lambda task=task: self.process_start(task),
                ),
                "effective_uid": None,
                "effective_caps": None,
            }
            obj["representative"] = record

            def credentials(*, record=record, task=task):
                """Read a representative task's credential location, EUID, and capabilities.

                Dereference cred and isolate failures for each credential field.
                """
                if not task.has_member("cred") or not task.cred:
                    raise artifact_core.Unsupported(
                        "Representative credentials unavailable"
                    )
                cred = task.cred.dereference()
                record["credential_location"] = self.location(cred)

                def effective_uid():
                    """Read euid from either a val-wrapped structure or an integer.

                    Use the val member when present and otherwise convert the value directly.
                    """
                    value = cred.member("euid")
                    return credential_readers.kernel_id(value, require_member_api=True)

                record["effective_uid"] = self.read("cred.euid", cred, effective_uid)
                record["effective_caps"] = self.read(
                    "cred.cap_effective",
                    cred,
                    lambda: hex(credential_readers.capability_mask(cred.cap_effective)),
                )

            self.read("representative credentials", task, credentials)

    def collect_settings(self):
        """Search hostconfig.json only under verified bind-source directories.

        Find standard bind sources per container namespace and inspect direct children
        within explicit time and count limits.
        """
        if not self.containers:
            self.skipped["settings"] = (
                "No task-linked IDs; hostconfig recovery not requested"
            )
            return
        scope = {
            "container_ids": sorted(self.containers),
            "source": "verified standard bind-mount source directories",
            "by_container": {},
        }
        self.report["settings_scope"] = scope
        known_roots, unresolved = {}, []
        for cid, container in self.containers.items():
            deadline = time.monotonic() + SETTINGS_SECONDS
            state = {
                "status": "UNRESOLVED",
                "mounts_examined": 0,
                "directories": [],
                "children_examined": 0,
                "search_complete": False,
            }
            scope["by_container"][cid] = state
            anchors = {}
            addresses = container["task_addresses"]
            preferred = container["representative_task"]
            if preferred in addresses:
                addresses = [preferred] + [
                    address for address in addresses if address != preferred
                ]
            examined_namespaces = set()
            for address in addresses:
                if anchors:
                    break
                task = self.tasks[int(address, 16)]
                ns = self.read(
                    "settings task mount namespace",
                    task,
                    lambda t=task: self.mount_namespace(t),
                )
                if not ns or ns["address"] in examined_namespaces:
                    continue
                examined_namespaces.add(ns["address"])
                namespace = self.read(
                    "settings mount namespace",
                    ns,
                    lambda ns=ns: self.obj("mnt_namespace", int(ns["address"], 16)),
                )
                if namespace is None:
                    state["status"] = "INCOMPLETE"
                    continue
                before = len(self.report["errors"])

                def find_anchors(
                    *,
                    anchors=anchors,
                    cid=cid,
                    deadline=deadline,
                    namespace=namespace,
                    state=state,
                    task=task,
                ):
                    """Find standard bind sources matching a container ID in one namespace.

                    Enforce count and time limits and retain unique verified directories.
                    """
                    for mount in mount_readers.stock_mount_points(namespace):
                        if (
                            time.monotonic() >= deadline
                            or state["mounts_examined"] >= SETTINGS_MOUNT_LIMIT
                        ):
                            raise artifact_core.Incomplete(
                                "Settings mount search budget"
                            )
                        state["mounts_examined"] += 1
                        source = self.read(
                            "settings standard bind mount",
                            mount,
                            lambda m=mount, task=task: self.standard_bind_source(
                                m, task
                            ),
                        )
                        if source and source[0] == cid:
                            _, _, source_path, directory = source
                            anchors[self.address(directory)] = (
                                directory,
                                source_path.rsplit("/", 1)[0],
                            )

                self.read("settings mount search", namespace, find_anchors)
                if len(self.report["errors"]) != before:
                    state["status"] = "INCOMPLETE"
            if not anchors:
                if state["status"] != "INCOMPLETE":
                    state["status"] = "NO_VERIFIED_ANCHOR"
                unresolved.append(cid)
                continue
            state["directories"] = [path for _, path in anchors.values()]
            if len(anchors) != 1:
                state["status"] = "AMBIGUOUS_ANCHOR"
                self.issue(
                    "settings directory",
                    cid,
                    artifact_core.Incomplete(
                        "Multiple source directories for one container ID"
                    ),
                )
                continue
            directory, parent_path = next(iter(anchors.values()))
            root = self.read(
                "settings peer root",
                directory,
                lambda directory=directory: directory.d_parent.dereference(),
            )
            if root is not None:
                known_roots[self.address(root)] = (root, parent_path.rsplit("/", 1)[0])
            else:
                state["status"] = "INCOMPLETE"
            self.lookup_settings_file(
                cid,
                directory,
                parent_path,
                state,
                deadline,
                source_complete=state["status"] != "INCOMPLETE",
            )
        for cid in unresolved:
            if not known_roots:
                break
            state = scope["by_container"][cid]
            deadline = time.monotonic() + SETTINGS_SECONDS
            found, complete = {}, True
            for root, root_path in known_roots.values():
                before = len(self.report["errors"])

                def find_container(
                    *,
                    cid=cid,
                    deadline=deadline,
                    found=found,
                    root=root,
                    root_path=root_path,
                    state=state,
                ):
                    """Look up one target ID under a containers directory verified by a peer.

                    Enumerate direct children within time and count limits for an exact match.
                    """
                    for child in root.get_subdirs():
                        if (
                            time.monotonic() >= deadline
                            or state["children_examined"] >= SETTINGS_CHILD_LIMIT
                        ):
                            raise artifact_core.Incomplete(
                                "Settings container directory budget"
                            )
                        state["children_examined"] += 1
                        if child.d_name.name_as_str() == cid:
                            found[self.address(child)] = (child, root_path + "/" + cid)

                self.read("settings container directory", root, find_container)
                if len(self.report["errors"]) != before:
                    complete = False
            if not complete or len(found) != 1:
                if len(found) > 1:
                    state["status"] = "AMBIGUOUS_ANCHOR"
                    self.issue(
                        "settings directory",
                        cid,
                        artifact_core.Incomplete(
                            "Container ID occurs in multiple verified roots"
                        ),
                    )
                continue
            directory, parent_path = next(iter(found.values()))
            state["directories"] = [parent_path]
            state["source"] = "peer_verified_root"
            self.lookup_settings_file(
                cid,
                directory,
                parent_path,
                state,
                deadline,
                source_complete=state["status"] != "INCOMPLETE",
            )
        self.merge_settings()

    def lookup_settings_file(
        self, cid, directory, parent_path, state, deadline, source_complete
    ):
        """Recover only hostconfig.json from direct children of a verified directory.

        Mark the settings search complete only after child lookup and recovery both finish.
        """
        before = len(self.report["errors"])

        def find_file():
            """Enumerate bounded directory children and recover the target inode.

            Pass only positive hostconfig.json dentries to page-cache recovery.
            """
            for child in directory.get_subdirs():
                if (
                    time.monotonic() >= deadline
                    or state["children_examined"] >= SETTINGS_CHILD_LIMIT
                ):
                    raise artifact_core.Incomplete("Settings child lookup budget")
                state["children_examined"] += 1
                if child.d_name.name_as_str() != "hostconfig.json" or not child.d_inode:
                    continue
                inode = child.d_inode.dereference()
                self.read(
                    "hostconfig inode",
                    inode,
                    lambda i=inode: self.recover_privileged(
                        i, parent_path + "/hostconfig.json", cid
                    ),
                )

        self.read("settings file lookup", directory, find_file)
        if len(self.report["errors"]) != before or not source_complete:
            state["status"] = "INCOMPLETE"
            return
        state["search_complete"] = True
        state["status"] = (
            "FOUND"
            if any(r["container_id"] == cid for r in self.report["cached_settings"])
            else "NOT_FOUND"
        )

    def merge_settings(self):
        """Merge recovered Privileged values while preserving identity conflicts.

        Compare Boolean values and IDs across hostconfig records, accepting a setting
        only when the result is unique, complete, and conflict-free.
        """
        for cid, obj in self.containers.items():
            rows = [
                (i, r)
                for i, r in enumerate(self.report["cached_settings"])
                if r["container_id"] == cid
            ]
            obj["settings_refs"] = [i for i, _ in rows]
            search = (
                self.report.get("settings_scope", {})
                .get("by_container", {})
                .get(cid, {})
            )
            verified = [
                (i, r)
                for i, r in rows
                if r.get("complete") is True
                and r.get("json_parse") == "FULL"
                and not r.get("identity_conflict")
                and type(r.get("privileged")) is bool
            ]
            values = {r["privileged"] for _, r in verified}
            conflicts = [
                {"source": "hostconfig", "index": i, "reason": "Path/JSON IDs disagree"}
                for i, r in rows
                if r.get("identity_conflict")
            ]
            if len(values) > 1:
                conflicts.append(
                    {
                        "source": "hostconfig",
                        "field": "Privileged",
                        "values": sorted(values),
                        "reason": "Recovered settings disagree",
                    }
                )
            obj["configured_privileged"] = (
                next(iter(values))
                if search.get("search_complete")
                and len(verified) == len(rows)
                and len(values) == 1
                and not conflicts
                else None
            )
            obj["conflicts"].extend(conflicts)
            if rows and "hostconfig" not in obj["sources"]:
                obj["sources"].append("hostconfig")
            if obj["conflicts"]:
                obj["association"] = "CONFLICT"

    def collect(self):
        """Run tasks, identity, selection, details, and settings in order.

        Invoke each collect_* method in STAGES order and return the accumulated report.
        """
        for stage in STAGES:
            self.stage_run(stage, getattr(self, "collect_" + stage))
        return self.report

    def read_vmemmap_base(self):
        """Read vmemmap_base after validating its concrete symbol type.

        Validate integer width and signedness when type data exists; otherwise use
        the target kernel pointer width and byte order without masking type errors.
        """
        word = self.kernel.get_type("pointer").vol.data_format
        if word.signed or word.length * 8 != self.layer.bits_per_register:
            raise artifact_core.Unsupported(
                "Native pointer layout disagrees with the kernel layer"
            )
        symbol = self.kernel.get_symbol("vmemmap_base")
        template = symbol.type
        if template is not None:
            if isinstance(template, objects.templates.ReferenceTemplate):
                template = self.context.symbol_space.get_type(template.vol.type_name)
            if (
                not issubclass(template.vol.object_class, objects.Integer)
                or issubclass(template.vol.object_class, objects.Pointer)
                or template.size != word.length
                or template.vol.data_format != word
            ):
                raise artifact_core.Unsupported(
                    "vmemmap_base is not an unsigned native-width integer"
                )
            base = int(self.kernel.object_from_symbol("vmemmap_base"))
        else:


            address = self.layer.canonicalize(
                self.kernel.get_absolute_symbol_address("vmemmap_base")
                & self.layer.address_mask
            )
            raw = self.layer.read(address, word.length, pad=False)
            if len(raw) != word.length:
                raise artifact_core.Incomplete("Incomplete vmemmap_base value")
            base = int.from_bytes(raw, byteorder=word.byteorder, signed=False)
        if not base or self.layer.canonicalize(base & self.layer.address_mask) != base:
            raise ValueError("Invalid vmemmap_base address")
        return base

    def recover_privileged(self, inode, path, cid):
        """Recover cached hostconfig.json pages and read the Privileged field.

        Parse only contiguous recovered bytes, record holes, duplicates, and ID
        conflicts, and accept Privileged only when it is Boolean.
        """
        if cid not in self.containers:
            return
        filename = "hostconfig.json"
        row = {
            "path": path,
            "container_id": cid,
            "filename": filename,
            "inode": hex(inode.vol.offset),
            "location": self.location(inode),
            "pages": [],
            "holes": [],
            "json_parse": "NOT FOUND",
        }
        self.report["cached_settings"].append(row)
        size = int(inode.i_size)
        if not 0 < size <= FILE_LIMIT:
            raise artifact_core.Incomplete("Empty/over-limit metadata inode")
        row["size"] = size
        row["mapping"] = hex(int(inode.i_mapping))
        mapping = inode.i_mapping.dereference()
        storage = linux.IDStorage.choose_id_storage(self.context, self.kernel.name)
        pieces = {}
        page_size = self.layer.page_size

        def recover():
            """Traverse bounded inode cache entries and validate each page's content.

            Invoke the isolated content reader for every reachable cache page.
            """
            for page_address in self.bounded(storage.get_entries(mapping.i_pages)):
                page = self.obj("page", page_address)

                def content(*, page=page):
                    """Validate page mapping and offset, then read, hash, and compare bytes.

                    Reject conflicting duplicate data at the same file offset.
                    """
                    if int(page.mapping) != int(inode.i_mapping):
                        raise ValueError("Cached page mapping backlink mismatch")
                    if page.has_member("index"):
                        index = int(page.index)
                    elif self.kernel.has_type("folio"):
                        folio = self.obj("folio", page.vol.offset)

                        if folio.mapping.vol.offset != page.mapping.vol.offset:
                            raise artifact_core.Unsupported(
                                "folio/page mapping layout differs"
                            )
                        index = int(folio.index)
                    else:
                        raise artifact_core.Unsupported(
                            "Cached page index layout unavailable"
                        )
                    offset = index * page_size
                    if not 0 <= offset < size:
                        raise ValueError("Cached page outside inode")
                    if self.kernel.has_symbol(
                        "vmemmap_base"
                    ) and self.kernel.has_symbol("mem_section"):
                        base = self.read_vmemmap_base()
                        address = self.layer.canonicalize(page.vol.offset)
                        width = self.kernel.get_type("page").size
                        if address < base or (address - base) % width:
                            raise ValueError("Page is outside aligned vmemmap")
                        physical = (address - base) // width * page_size
                        raw = self.context.layers[
                            self.layer.config["memory_layer"]
                        ].read(physical, page_size)
                    else:
                        raw = page.get_content()
                    if not raw:
                        raise artifact_core.Incomplete("Cached page unreadable")
                    raw = raw[: min(page_size, size - offset)]
                    if offset in pieces and pieces[offset] != raw:
                        raise ValueError("Conflicting cache pages at one file offset")
                    pieces[offset] = raw
                    row["pages"].append(
                        {
                            "file_offset": offset,
                            "page": hex(page.vol.offset),
                            "length": len(raw),
                            "sha256": hashlib.sha256(raw).hexdigest(),
                        }
                    )

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
            self.issue(
                "metadata coverage",
                inode,
                artifact_core.Incomplete("Missing cache ranges; no zero filling"),
            )
        if prefix:
            try:
                data = json_object(bytes(prefix))
                row["json_parse"] = "FULL" if row["complete"] else "PARTIAL"
            except DuplicateJSONKey:
                raise
            except ValueError as exc:
                data = prefix_json(bytes(prefix))
                row["json_parse"] = "PARTIAL"
                self.issue("metadata JSON", inode, artifact_core.Incomplete(str(exc)))
            embedded = data.get("ID")
            row["identity_conflict"] = embedded is not None and embedded != cid
            if row["identity_conflict"]:
                self.issue(
                    "metadata identity", inode, ValueError("Path and JSON ID disagree")
                )

            privileged = data.get("Privileged")
            if "Privileged" in data and type(privileged) is not bool:
                raise ValueError("hostconfig Privileged is not a boolean")
            row["privileged"] = privileged if not row["identity_conflict"] else None


def vertical_presentation(report):
    """Render one category/value block per container, sorted by ID.

    Select representative, credential, and provenance fields for vertical output.
    """
    rows = []

    def cell(value):
        """Render unknown values as hyphens and escape tabs and newlines.

        Keep every value on one display line without inventing missing data.
        """
        return (
            "-"
            if value is None or value == ""
            else str(value).replace("\n", "\\n").replace("\t", "\\t")
        )

    for obj in sorted(report["containers"], key=lambda c: c["id"]):
        if rows:
            rows.append(("", ""))
        process = obj.get("representative") or {}
        selection = obj["representative_selection"]
        fields = [
            ("Container ID", obj["id"]),
            ("Command", process.get("comm")),
            ("Process Start UTC", process.get("process_start")),
            ("Host PID", process.get("pid")),
            ("Effective UID", process.get("effective_uid")),
            ("Effective Caps", process.get("effective_caps")),
            ("Configured Privileged", obj.get("configured_privileged")),
            ("Representative", selection["method"] or selection["status"]),
            ("Association", obj["association"]),
            ("Sources", ",".join(obj["sources"])),
        ]
        rows.extend((name, cell(value)) for name, value in fields)
    return [("category", str), ("value", str)], rows


def run_ps(context, kernel_name, open_file):
    """Generate --ps output and its evidence file for the unified Docker plugin.

    Save the Collector report as JSON, warn about errors, and return a vertical TreeGrid.
    """
    report = Collector(context, kernel_name).collect()
    with open_file("ps_evidence.json") as output:
        output.write(json.dumps(report, ensure_ascii=False, indent=2).encode("utf-8"))
    if report["errors"]:
        vollog.warning(
            "ps: %d collection issues; review coverage in ps_evidence.json",
            len(report["errors"]),
        )
    unresolved = sum(c["representative"] is None for c in report["containers"])
    if unresolved:
        vollog.warning(
            "ps: %d container candidates have no unambiguous representative", unresolved
        )
    if not report["containers"]:
        vollog.warning(
            "ps: no task-linked Docker candidates in the searched process list; review coverage"
        )
    columns, rows = vertical_presentation(report)
    return renderers.TreeGrid(columns, ((0, row) for row in rows))

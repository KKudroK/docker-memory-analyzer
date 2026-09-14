"""Evidence-based Docker detection for stock Volatility 3 2.28.0.

Run: vol -p /path/to/plugins -f memory.lime detector.Detector
No additional --detector switch or sibling plugin is required. The normal
Volatility -s, --cache-path and -o options select symbols, cache and output.

The detector inspects reachable tasks (including threads), cgroup v1/v2
membership, mount namespaces and network namespaces. Docker-labelled evidence
is distinguished from generic container hints. FOUND means an observation,
not authenticated Docker identity or proof that a container is running.
NOT_OBSERVED is scoped to completed traversals; failed or unsupported reads
produce UNKNOWN when there is no positive observation. All observations and
coverage are saved through Volatility's file handler as detector_evidence.json.

Kernel layouts are selected by symbol members. No framework file is replaced,
no capability field is read, and no mount hash table symbol is required.
"""

import datetime
import json
import logging
import re
import time

from volatility3.framework import constants, exceptions, interfaces, objects, renderers
from volatility3.framework.configuration import requirements


vollog = logging.getLogger(__name__)
VERSION = (1, 0, 0)
DOCKER_SCOPE = re.compile(r"^docker-([0-9a-f]{64})\.scope$")
BRIDGE_NAME = re.compile(r"^br-[0-9a-f]{12}$")
READ_ERRORS = (exceptions.VolatilityException, AttributeError, ValueError,
               TypeError, KeyError, IndexError, OverflowError, UnicodeError)
STAGES = ("tasks", "runtime", "cgroups", "mounts", "network")
# key, description, interpretation, prerequisite coverage
CHECKS = (
    ("docker_process", "Docker daemon / proxy", "DOCKER_LABEL", ("tasks", "runtime")),
    ("docker_cgroup", "Docker container cgroup", "DOCKER_LABEL", ("tasks", "cgroups")),
    ("docker_shim", "Shim with namespace=moby", "DOCKER_LABEL", ("tasks", "runtime")),
    ("containerd_shim", "Containerd shim process", "GENERIC_HINT", ("tasks", "runtime")),
    ("docker_interface", "Docker-like interface name", "NAME_HINT", ("network",)),
    ("veth", "Veth device (link kind)", "GENERIC_HINT", ("network",)),
    ("overlay", "Overlay filesystem", "GENERIC_HINT", ("tasks", "mounts")),
    ("legacy_mac", "Legacy 02:42 MAC prefix", "MAC_HINT", ("network",)),
)


class Unsupported(ValueError):
    """The ISF does not describe a supported layout."""


class Incomplete(ValueError):
    """A traversal could not prove that it reached its natural end."""


def docker_ids(path):
    """Accept Docker-labelled complete IDs, never arbitrary 64-hex cgroups."""
    parts = path.split("/")
    found = set()
    for index, part in enumerate(parts):
        scope = DOCKER_SCOPE.fullmatch(part)
        if scope:
            found.add(scope[1])
        if part == "docker" and index + 1 < len(parts):
            candidate = parts[index + 1]
            if re.fullmatch(r"[0-9a-f]{64}", candidate):
                found.add(candidate)
    return sorted(found)


def argv_flags(argv):
    """Preserve conflicting duplicate values instead of choosing one silently."""
    result = {}
    for index, arg in enumerate(argv[1:], 1):
        if arg == "--":
            break
        if not arg.startswith("-"):
            continue
        flag, separator, value = arg.lstrip("-").partition("=")
        if flag not in ("namespace", "id"):
            continue
        if not separator:
            if index + 1 >= len(argv) or argv[index + 1].startswith("-"):
                continue
            value = argv[index + 1]
        result.setdefault(flag, set()).add(value)
    return {key: sorted(values) for key, values in result.items()}


def runtime_checks(comm, argv=None):
    found = []
    if comm in ("dockerd", "docker-proxy"):
        found.append("docker_process")
    # Linux comm is only TASK_COMM_LEN bytes; the full shim name is truncated.
    if comm and comm.startswith("containerd-shim"):
        found.append("containerd_shim")
        if argv is not None and argv_flags(argv).get("namespace") == ["moby"]:
            found.append("docker_shim")
    return found


def network_checks(name, kind, mac):
    found = []
    if name and (name.startswith("docker") or BRIDGE_NAME.fullmatch(name)):
        found.append("docker_interface")
    if kind == "veth":
        found.append("veth")
    if mac and mac.lower().startswith("02:42:"):
        found.append("legacy_mac")
    return found


def summarize(report):
    checks = []
    for key, label, interpretation, prerequisites in CHECKS:
        evidence = [i for i, item in enumerate(report["evidence"]) if item["check"] == key]
        complete = all(report["coverage"].get(stage, {}).get("status") == "COMPLETE"
                       for stage in prerequisites)
        checks.append({"key": key, "check": label, "interpretation": interpretation,
                       "status": "FOUND" if evidence else "NOT_OBSERVED" if complete else "UNKNOWN",
                       "coverage": "COMPLETE" if complete else "PARTIAL",
                       "evidence_indices": evidence, "count": len(evidence)})
    if any(c["count"] and c["interpretation"] == "DOCKER_LABEL" for c in checks):
        verdict = "DOCKER_EVIDENCE"
    elif any(c["count"] for c in checks):
        verdict = "HINTS_ONLY"
    elif any(c["status"] == "UNKNOWN" for c in checks):
        verdict = "UNKNOWN"
    else:
        verdict = "NOT_OBSERVED"
    report["checks"] = checks
    report["summary"] = {
        "status": verdict,
        "coverage": "COMPLETE" if all(c["coverage"] == "COMPLETE" for c in checks) else "PARTIAL",
        "meaning": {
            "DOCKER_EVIDENCE": "Docker-labelled process, cgroup or moby shim evidence observed; review sources.",
            "HINTS_ONLY": "Container/network hints observed; Docker identity is not established.",
            "UNKNOWN": "No positive indicators in available data; one or more searches were incomplete.",
            "NOT_OBSERVED": "No configured indicators in the completed reachable-object searches.",
        }[verdict],
    }
    return report


class Collector:
    """Collect from the supplied Volatility context; never launch another CLI."""

    def __init__(self, context, kernel_name, limit=100000, progress_callback=None):
        if not 1 <= limit <= 1000000:
            raise ValueError("limit must be in 1..1000000")
        self.context = context
        self.kernel = context.modules[kernel_name]
        self.layer = context.layers[self.kernel.layer_name]
        self.limit = limit
        self.progress_callback = progress_callback
        self.stage = "tasks"
        self.tasks = {}
        self.mount_namespaces = {}
        self.net_namespaces = {}
        self.css_cache = {}
        self.group_cache = {}
        self.report = {
            "schema_version": 1,
            "metadata": {"plugin": "detector.Detector", "plugin_version": ".".join(map(str, VERSION)),
                         "volatility_version": constants.PACKAGE_VERSION,
                         "started_utc": datetime.datetime.now(datetime.timezone.utc).isoformat(),
                         "kernel_module": kernel_name, "kernel_layer": self.kernel.layer_name,
                         "symbol_table": self.kernel.symbol_table_name,
                         "isf_url": context.symbol_space[self.kernel.symbol_table_name].config.get("isf_url")},
            "limits": {"nodes_per_traversal": limit, "argv_bytes": 65536,
                       "path_components": min(limit, 4096), "string_bytes": 4096},
            "coverage": {}, "errors": [], "evidence": [], "tasks": [],
            "cgroups": [], "mounts": [], "interfaces": [],
            "limitations": [
                "Reachable kernel objects and selected runtime argv only; no carving, page-cache or heap scan.",
                "Task names, cgroup labels and the moby namespace can be imitated; they are evidence, not authentication.",
                "Overlay, veth, interface names and MAC prefixes are not exclusive to Docker.",
                "A daemon or residual mount does not establish that a Docker container is currently running.",
                "Missing objects, unsupported layouts, traversal limits and acquisition smear can hide evidence.",
                "Mount paths are relative to the mount namespace root, not necessarily the host or a task chroot.",
            ],
        }

    def obj(self, typename, address):
        return self.kernel.object(typename, offset=int(address), absolute=True)

    def symbol(self, name, typename):
        # ISF symbols may have addresses but no type metadata (e.g. some BTF ISFs).
        return self.kernel.object(typename, offset=self.kernel.get_symbol(name).address, absolute=False)

    def issue(self, operation, obj, exc):
        address = hex(int(obj.vol.offset)) if hasattr(obj, "vol") else str(obj)
        kind = ("UNSUPPORTED" if isinstance(exc, (Unsupported, AttributeError, exceptions.SymbolError))
                else "UNREADABLE" if isinstance(exc, exceptions.InvalidAddressException)
                else "INCOMPLETE" if isinstance(exc, Incomplete) else "ERROR")
        self.report["errors"].append({"stage": self.stage, "operation": operation,
                                      "address": address, "kind": kind,
                                      "exception": type(exc).__name__, "detail": str(exc)})

    def read(self, operation, obj, function, default=None):
        try:
            return function()
        except READ_ERRORS as exc:
            self.issue(operation, obj, exc)
            return default

    def evidence(self, check, obj, detail):
        self.report["evidence"].append({"check": check, "stage": self.stage,
                                        "address": hex(int(obj.vol.offset)),
                                        "layer": self.kernel.layer_name, "detail": detail})

    def string(self, pointer, maximum=4096):
        if not pointer:
            raise Incomplete("NULL string pointer")
        address, data = int(pointer), bytearray()
        # Require a real terminator. Some generic string helpers return a
        # readable prefix when a later page is absent; that is not a full name.
        while len(data) < maximum:
            cursor = address + len(data)
            size = min(32, maximum - len(data), 4096 - (cursor & 4095))
            block = self.layer.read(cursor, size, pad=False)
            end = block.find(b"\0")
            if end >= 0:
                data.extend(block[:end])
                return data.decode("utf-8", errors="strict")
            data.extend(block)
        raise Incomplete("Unterminated or over-limit string")

    def array_string(self, array):
        if not isinstance(array, objects.Array) or not 0 < array.vol.count <= 4096:
            raise Unsupported("Name is not a bounded character array")
        raw = self.layer.read(int(array.vol.offset), array.vol.count, pad=False)
        end = raw.find(b"\0")
        if end < 0:
            raise Incomplete("Unterminated character array")
        return raw[:end].decode("utf-8", errors="strict")

    def walk(self, head, typename, member):
        """Validate termination and backlinks; never silently exhaust a bad list."""
        offset = self.kernel.get_type(typename).relative_child_offset(member)
        end, previous = int(head.vol.offset), int(head.vol.offset)
        link, seen = int(head.next), set()
        while link != end:
            if not link or link in seen or len(seen) >= self.limit:
                raise Incomplete("NULL link, non-head cycle or traversal limit")
            seen.add(link)
            node = self.obj(typename, link - offset)
            entry = node.member(member)
            if int(entry.prev) != previous:
                raise Incomplete("List backlink mismatch")
            yield node
            previous, link = link, int(entry.next)
        if int(head.prev) != previous:
            raise Incomplete("List tail disagrees with forward traversal")

    def namespace(self, namespace, kind, task_row=None):
        address = int(namespace.vol.offset)
        target = self.mount_namespaces if kind == "mount" else self.net_namespaces
        if address not in target:
            def inode():
                if namespace.has_member("ns"):
                    return int(namespace.ns.inum)
                if namespace.has_member("proc_inum"):
                    return int(namespace.proc_inum)
                raise Unsupported("Namespace inode layout unavailable")
            target[address] = {"object": namespace, "address": hex(address),
                               "inode": self.read(kind + ".namespace_inode", namespace, inode),
                               "tids": [], "container_ids": []}
        record = target[address]
        if task_row is not None:
            record["tids"].append(task_row["tid"])
            task_row[kind + "_namespace"] = hex(address)
        return record

    def collect_tasks(self):
        init = self.symbol("init_task", "task_struct")
        self.tasks[int(init.vol.offset)] = init

        def leaders():
            for task in self.walk(init.tasks, "task_struct", "tasks"):
                self.tasks[int(task.vol.offset)] = task
        self.read("tasks.list", init, leaders)
        for leader in list(self.tasks.values()):
            def threads():
                if not leader.signal:
                    return
                if leader.has_member("thread_node") and leader.signal.has_member("thread_head"):
                    head, member = leader.signal.thread_head, "thread_node"
                elif leader.has_member("thread_group"):
                    head, member = leader.thread_group, "thread_group"
                else:
                    raise Unsupported("Thread list layout unavailable")
                for task in self.walk(head, "task_struct", member):
                    self.tasks[int(task.vol.offset)] = task
            self.read("tasks.threads", leader, threads)
        proxies = {}
        for task in self.tasks.values():
            row = {"address": hex(int(task.vol.offset)), "container_ids": []}
            for field, source in (("tid", "pid"), ("pid", "tgid")):
                row[field] = self.read("task." + source, task, lambda s=source: int(task.member(s)))
            row["comm"] = self.read("task.comm", task, lambda: self.array_string(task.comm))
            self.report["tasks"].append(row)

            def namespaces():
                if not task.nsproxy:
                    return  # NULL is valid for exiting tasks and some kernel tasks.
                address = int(task.nsproxy)
                if address not in proxies:
                    proxy = task.nsproxy.dereference()
                    proxies[address] = {}
                    for kind, member in (("mount", "mnt_ns"), ("net", "net_ns")):
                        def get_namespace(m=member):
                            ptr = proxy.member(m)
                            if not ptr:
                                raise Incomplete("NULL namespace in non-NULL nsproxy")
                            return ptr.dereference()
                        proxies[address][kind] = self.read("task." + member, task, get_namespace)
                for kind, ns in proxies[address].items():
                    if ns is not None:
                        self.namespace(ns, kind, row)
            self.read("task.namespaces", task, namespaces)

    def argv(self, task):
        if not task.mm:
            raise Incomplete("Runtime task has no userspace memory descriptor")
        start, end = int(task.mm.arg_start), int(task.mm.arg_end)
        if not start or not 0 < end - start <= 65536:
            raise Incomplete("Runtime argv missing or outside byte limit")
        layer = task.add_process_layer()
        if layer is None:
            raise Incomplete("Runtime process layer unavailable")
        raw = self.context.layers[layer].read(start, end - start, pad=False)
        if not raw.endswith(b"\0"):
            raise Incomplete("Runtime argv is not NUL-terminated")
        return raw[:-1].decode("utf-8", errors="strict").split("\0")

    def collect_runtime(self):
        for row in self.report["tasks"]:
            # One argv observation per process; names themselves remain observable
            # even if a process's argv pages are not resident.
            if row["tid"] != row["pid"] or row["comm"] is None:
                continue
            task = self.tasks[int(row["address"], 16)]
            for check in runtime_checks(row["comm"]):
                self.evidence(check, task, {"pid": row["pid"], "comm": row["comm"], "source": "task_struct.comm"})
            if row["comm"].startswith("containerd-shim"):
                args = self.read("runtime.argv", task, lambda: self.argv(task))
                if args is None:
                    continue
                flags = argv_flags(args)
                row["runtime_argv"] = args
                row["runtime_flags"] = flags
                if len(flags.get("namespace", [])) > 1 or len(flags.get("id", [])) > 1:
                    self.issue("runtime.flags", task, Incomplete("Conflicting duplicate shim flags"))
                if "docker_shim" in runtime_checks(row["comm"], args):
                    ids = [value for value in flags.get("id", []) if re.fullmatch(r"[0-9a-f]{64}", value)]
                    self.evidence("docker_shim", task, {"pid": row["pid"], "comm": row["comm"],
                                                      "argv": args, "container_id_candidates": ids})

    def cgroup_path(self, group):
        modern = group.has_member("kn")
        if modern and not group.kn:
            raise Incomplete("Cgroup has NULL kernfs node")
        node = group.kn.dereference() if modern else group
        parts, seen = [], set()
        while True:
            address = int(node.vol.offset)
            if address in seen or len(seen) >= min(self.limit, 4096):
                raise Incomplete("Cgroup ancestry cycle or depth limit")
            seen.add(address)
            parent = node.parent if node.has_member("parent") else node.member("__parent")
            if not parent:
                return "/" + "/".join(reversed(parts))
            if node.has_member("name"):
                name = self.string(node.name)
            elif not modern and node.has_member("name_copy") and node.name_copy:
                name = self.array_string(node.name_copy.name)
            else:
                raise Unsupported("Cgroup name layout unavailable")
            if not name or "/" in name:
                raise Incomplete("Invalid cgroup path component")
            parts.append(name)
            node = parent.dereference()

    def css_groups(self, css):
        groups, supported = {}, False
        if css.has_member("dfl_cgrp"):
            supported = True
            def default_group():
                if css.dfl_cgrp:
                    groups[int(css.dfl_cgrp)] = css.dfl_cgrp.dereference()
            self.read("cgroup.default", css, default_group)
        if css.has_member("subsys"):
            supported = True
            array = css.subsys
            if not isinstance(array, objects.Array) or not 0 <= array.vol.count <= 256:
                raise Unsupported("css_set.subsys is not a bounded array")
            for index in range(array.vol.count):
                def state_group():
                    state = array[index]
                    if state and state.cgroup:
                        groups[int(state.cgroup)] = state.cgroup.dereference()
                self.read("cgroup.subsys", css, state_group)
        if not supported:
            raise Unsupported("Neither cgroup v1 subsystem array nor v2 default group is described")
        return groups

    def collect_cgroups(self):
        for row in self.report["tasks"]:
            task = self.tasks[int(row["address"], 16)]

            def membership():
                if not task.has_member("cgroups"):
                    raise Unsupported("task_struct.cgroups is not described")
                if not task.cgroups:
                    return
                css_address = int(task.cgroups)
                if css_address not in self.css_cache:
                    self.css_cache[css_address] = self.css_groups(task.cgroups.dereference())
                paths, ids = [], set()
                for address, group in self.css_cache[css_address].items():
                    if address not in self.group_cache:
                        path = self.read("cgroup.path", group, lambda: self.cgroup_path(group))
                        record = {"address": hex(address), "path": path,
                                  "container_ids": docker_ids(path) if path is not None else [], "tids": []}
                        self.group_cache[address] = record
                        self.report["cgroups"].append(record)
                        if record["container_ids"]:
                            self.evidence("docker_cgroup", group, {"path": path, "container_ids": record["container_ids"]})
                    record = self.group_cache[address]
                    record["tids"].append(row["tid"])
                    if record["path"] is not None:
                        paths.append(record["path"])
                    ids.update(record["container_ids"])
                row["cgroup_paths"] = sorted(set(paths))
                row["container_ids"] = sorted(ids)
                # Namespace membership is context, not proof that every object
                # in a shared namespace belongs to this Docker container.
                for kind, mapping in (("mount", self.mount_namespaces), ("net", self.net_namespaces)):
                    address = row.get(kind + "_namespace")
                    if address:
                        ns = mapping[int(address, 16)]
                        ns["container_ids"] = sorted(set(ns["container_ids"]) | ids)
            self.read("task.cgroups", task, membership)

    def mount_points(self, namespace):
        if namespace.has_member("mounts") and namespace.mounts.has_member("rb_node"):
            root = namespace.mounts.rb_node
            offset = self.kernel.get_type("mount").relative_child_offset("mnt_node")
            stack, seen = [int(root)], set()
            while stack:
                address = stack.pop()
                if not address:
                    continue
                if address in seen:
                    self.issue("mounts.tree", namespace, Incomplete("Repeated RB node"))
                    continue
                if len(seen) >= self.limit:
                    raise Incomplete("Mount RB tree node limit")
                seen.add(address)
                node = self.obj("rb_node", address)
                for field in ("rb_right", "rb_left"):
                    child = self.read("mounts." + field, node, lambda f=field: int(node.member(f)))
                    if child:
                        stack.append(child)
                mount = self.obj("mount", address - offset)
                valid = self.read("mounts.owner", mount,
                                  lambda: int(mount.mnt_ns) == int(namespace.vol.offset))
                if valid:
                    yield mount
                elif valid is False:
                    self.issue("mounts.owner", mount, Incomplete("Mount belongs to another namespace"))
        elif namespace.has_member("list"):
            typename = "mount" if self.kernel.has_type("mount") else "vfsmount"
            for mount in self.walk(namespace.list, typename, "mnt_list"):
                if mount.has_member("mnt_ns") and int(mount.mnt_ns) != int(namespace.vol.offset):
                    self.issue("mounts.owner", mount, Incomplete("Mount belongs to another namespace"))
                    continue
                yield mount
        else:
            raise Unsupported("Mount namespace has neither supported RB tree nor list")

    def mount_path(self, mount):
        """Bounded namespace-root path, independent of mount hash tables."""
        current = mount
        vfsmount = current.mnt if current.has_member("mnt") else current
        dentry = vfsmount.mnt_root.dereference()
        parts, seen = [], set()
        for _ in range(min(self.limit, 4096)):
            pair = (int(current.vol.offset), int(dentry.vol.offset))
            if pair in seen:
                raise Incomplete("Mount/dentry path cycle")
            seen.add(pair)
            vfsmount = current.mnt if current.has_member("mnt") else current
            if int(dentry.vol.offset) == int(vfsmount.mnt_root):
                if not current.mnt_parent:
                    raise Incomplete("NULL mount parent")
                if int(current.mnt_parent) == int(current.vol.offset):
                    return "/" + "/".join(reversed(parts))
                dentry = current.mnt_mountpoint.dereference()
                current = current.mnt_parent.dereference()
                continue
            length = int(dentry.d_name.len)
            if not 0 < length <= 255 or not dentry.d_name.name:
                raise Incomplete("Invalid dentry name")
            name = self.layer.read(int(dentry.d_name.name), length, pad=False).decode("utf-8", errors="strict")
            if "/" in name or "\0" in name:
                raise Incomplete("Invalid dentry component")
            parts.append(name)
            if not dentry.d_parent:
                raise Incomplete("NULL dentry parent")
            dentry = dentry.d_parent.dereference()
        raise Incomplete("Mount path depth limit")

    def collect_mounts(self):
        if not self.mount_namespaces:
            raise Incomplete("No reachable mount namespace")
        for ns in self.mount_namespaces.values():
            def scan():
                for mount in self.mount_points(ns["object"]):
                    def fs_type():
                        vf = mount.mnt if mount.has_member("mnt") else mount
                        return self.string(vf.mnt_sb.s_type.name, 256)
                    fstype = self.read("mounts.fs_type", mount, fs_type)
                    row = {"address": hex(int(mount.vol.offset)), "namespace": ns["address"],
                           "namespace_inode": ns["inode"], "fstype": fstype,
                           "namespace_container_id_candidates": ns["container_ids"]}
                    self.report["mounts"].append(row)
                    if fstype in ("overlay", "overlayfs", "fuse.overlayfs"):
                        # Path failure does not erase a successful type read.
                        row["path"] = self.read("mounts.path", mount, lambda: self.mount_path(mount))
                        row["path_scope"] = "mount_namespace_root"
                        self.evidence("overlay", mount, dict(row))
            self.read("mounts.namespace", ns["object"], scan)

    def collect_network(self):
        if self.kernel.has_symbol("init_net"):
            self.read("network.init_net", "init_net", lambda: self.namespace(self.symbol("init_net", "net"), "net"))

        def global_namespaces():
            head = self.symbol("net_namespace_list", "list_head")
            for ns in self.walk(head, "net", "list"):
                self.namespace(ns, "net")
        self.read("network.namespace_list", "net_namespace_list", global_namespaces)
        if not self.net_namespaces:
            raise Incomplete("No reachable network namespace")
        for ns in self.net_namespaces.values():
            def devices():
                for dev in self.walk(ns["object"].dev_base_head, "net_device", "dev_list"):
                    name = self.read("network.name", dev, lambda: self.array_string(dev.name))

                    def kind():
                        if not dev.has_member("rtnl_link_ops"):
                            raise Unsupported("net_device.rtnl_link_ops is not described")
                        return self.string(dev.rtnl_link_ops.kind, 256) if dev.rtnl_link_ops else ""

                    def mac():
                        length = int(dev.addr_len)
                        if not 0 <= length <= 32:
                            raise Incomplete("Hardware address length outside 0..32")
                        if length == 0:
                            return ""
                        addr = dev.dev_addr
                        if isinstance(addr, objects.Array):
                            address = int(addr.vol.offset)
                        elif isinstance(addr, objects.Pointer) and addr:
                            address = int(addr)
                        else:
                            raise Unsupported("Hardware address storage is unavailable")
                        return ":".join(f"{byte:02x}" for byte in self.layer.read(address, length, pad=False))

                    link_kind = self.read("network.kind", dev, kind)
                    mac_addr = self.read("network.mac", dev, mac)
                    row = {"address": hex(int(dev.vol.offset)), "namespace": ns["address"],
                           "namespace_inode": ns["inode"], "name": name, "kind": link_kind,
                           "mac": mac_addr, "namespace_container_id_candidates": ns["container_ids"]}
                    self.report["interfaces"].append(row)
                    for check in network_checks(name, link_kind, mac_addr):
                        self.evidence(check, dev, dict(row))
            self.read("network.devices", ns["object"], devices)

    def collect(self):
        for index, stage in enumerate(STAGES):
            self.stage = stage
            started, errors = time.monotonic(), len(self.report["errors"])
            if self.progress_callback:
                self.progress_callback(index * 100 / len(STAGES), "Detector: " + stage)
            self.read(stage, stage, getattr(self, "collect_" + stage))
            count = len(self.report["errors"]) - errors
            self.report["coverage"][stage] = {"status": "PARTIAL" if count else "COMPLETE",
                                               "errors": count, "seconds": round(time.monotonic() - started, 6)}
        self.report["namespaces"] = {
            kind: [{key: value for key, value in ns.items() if key != "object"} for ns in mapping.values()]
            for kind, mapping in (("mount", self.mount_namespaces), ("net", self.net_namespaces))}
        if self.progress_callback:
            self.progress_callback(100, "Detector: completed")
        return summarize(self.report)


def presentation(report):
    columns = [("Check", str), ("Status", str), ("Interpretation", str),
               ("Coverage", str), ("Count", int), ("Evidence", str)]
    summary = report["summary"]
    rows = [("Overall", summary["status"], "ASSESSMENT", summary["coverage"],
             len(report["evidence"]), summary["meaning"])]
    for check in report["checks"]:
        samples = []
        for index in check["evidence_indices"][:3]:
            item = report["evidence"][index]
            detail = item["detail"]
            sample = {key: detail[key] for key in ("pid", "comm", "path", "namespace_inode", "name", "kind", "mac")
                      if key in detail}
            if check["key"] == "docker_shim":
                sample["namespace"] = "moby"
            samples.append(json.dumps(sample, ensure_ascii=False, separators=(",", ":")))
        text = "; ".join(samples)
        if check["count"] > 3:
            text += f"; +{check['count'] - 3} (detector_evidence.json)"
        if not text:
            text = "No match in completed searches" if check["status"] == "NOT_OBSERVED" else "See coverage/errors in detector_evidence.json"
        rows.append((check["check"], check["status"], check["interpretation"],
                     check["coverage"], check["count"], text))
    return columns, rows


class Detector(interfaces.plugins.PluginInterface):
    """Detect Docker-labelled evidence and distinguish generic container hints."""

    _required_framework_version = (2, 28, 0)
    _version = VERSION

    @classmethod
    def get_requirements(cls):
        return [
            requirements.ModuleRequirement(name="kernel", description="Linux kernel with matching ISF",
                                           architectures=["Intel32", "Intel64"]),
            requirements.IntRequirement(name="limit", description="Maximum nodes per traversal (1..1000000)",
                                        optional=True, default=100000),
        ]

    def run(self):
        limit = self.config.get("limit", 100000)
        if not 1 <= limit <= 1000000:
            raise exceptions.VolatilityException("--limit must be in 1..1000000")
        report = Collector(self.context, self.config["kernel"], limit, self._progress_callback).collect()
        with self.open("detector_evidence.json") as handle:
            handle.write(json.dumps(report, ensure_ascii=False, indent=2).encode("utf-8"))
        if report["errors"]:
            vollog.warning("Detector completed with %d collection issues; review detector_evidence.json", len(report["errors"]))
        columns, rows = presentation(report)
        return renderers.TreeGrid(columns, ((0, row) for row in rows))

"""Detect Docker-related runtime, mount, and network traces in Linux memory.
The --detector option checks shim processes, moby argv evidence, Overlay mounts,
and container-style interfaces while separating negative results from read failures.
It records bounded evidence and coverage without claiming identity or lifecycle state.
"""

import datetime
import json
import logging
import re

from volatility3.framework import constants, exceptions, interfaces
from volatility3.framework.configuration import requirements
from volatility3.plugins.linux import _vertical, docker_artifacts
from volatility3.plugins.linux._artifacts import core as artifact_core
from volatility3.plugins.linux._artifacts import mounts as mount_readers
from volatility3.plugins.linux._artifacts import namespaces as namespace_readers
from volatility3.plugins.linux._artifacts import network as network_readers
from volatility3.plugins.linux._artifacts import tasks as task_readers

vollog = logging.getLogger(__name__)

VERSION = (4, 0, 3)
EVIDENCE_SAMPLES = 3
ERROR_SAMPLES_PER_STAGE = 3
BRIDGE_NAME = re.compile(r"^br-[0-9a-f]{12}$")
READ_ERRORS = (
    exceptions.VolatilityException,
    AttributeError,
    ValueError,
    TypeError,
    KeyError,
    IndexError,
    OverflowError,
    UnicodeError,
)
STAGES = ("tasks", "runtime", "mounts", "network")

CHECKS = (
    ("docker_interface", "Docker-like interface name", "NAME_HINT", ("network",)),
    ("veth", "Veth device (link kind)", "GENERIC_HINT", ("network",)),
    ("overlay", "Overlay filesystem", "GENERIC_HINT", ("tasks", "mounts")),
    (
        "containerd_shim",
        "Containerd shim process",
        "GENERIC_HINT",
        ("tasks", "runtime"),
    ),
    ("docker_shim", "Shim with namespace=moby", "DOCKER_LABEL", ("tasks", "runtime")),
)


def argv_flags(argv):
    """Extract runtime namespace flags from argv and reject missing or empty values."""
    result = {}
    for index, arg in enumerate(argv[1:], 1):
        if arg == "--":
            break
        if not arg.startswith("-"):
            continue
        flag, separator, value = arg.lstrip("-").partition("=")
        if flag != "namespace":
            continue
        if not separator:
            if index + 1 >= len(argv) or argv[index + 1].startswith("-"):
                raise artifact_core.Incomplete("Runtime namespace option has no value")
            value = argv[index + 1]
        if not value:
            raise artifact_core.Incomplete(
                "Runtime namespace option has an empty value"
            )
        result.setdefault(flag, set()).add(value)
    return {key: sorted(values) for key, values in result.items()}


def runtime_checks(comm, argv=None):
    """Identify shims by process name and record a moby runtime namespace when present."""
    found = []

    if comm and comm.startswith("containerd-shim"):
        found.append("containerd_shim")
        if argv is not None and argv_flags(argv).get("namespace") == ["moby"]:
            found.append("docker_shim")
    return found


def network_checks(name, kind):
    """Evaluate device names and link kinds as independent network indicators."""
    found = []
    if name and (name.startswith("docker") or BRIDGE_NAME.fullmatch(name)):
        found.append("docker_interface")
    if kind == "veth":
        found.append("veth")
    return found


def summarize(report):
    """Derive check status, omitted evidence counts, and the overall assessment."""
    checks = report["checks"]
    prerequisites_by_key = {key: prerequisites for key, _, _, prerequisites in CHECKS}
    for check in checks:
        complete = all(
            report["coverage"].get(stage, {}).get("status") == "COMPLETE"
            for stage in prerequisites_by_key[check["key"]]
        )
        check["status"] = (
            "FOUND" if check["count"] else "NOT_OBSERVED" if complete else "UNKNOWN"
        )
        check["coverage"] = "COMPLETE" if complete else "PARTIAL"
        check["omitted_evidence"] = check["count"] - len(check["evidence_indices"])
    if any(c["count"] and c["interpretation"] == "DOCKER_LABEL" for c in checks):
        verdict = "DOCKER_EVIDENCE"
    elif any(c["count"] for c in checks):
        verdict = "HINTS_ONLY"
    elif any(c["status"] == "UNKNOWN" for c in checks):
        verdict = "UNKNOWN"
    else:
        verdict = "NOT_OBSERVED"
    report["summary"] = {
        "status": verdict,
        "coverage": "COMPLETE"
        if all(c["coverage"] == "COMPLETE" for c in checks)
        else "PARTIAL",
        "meaning": {
            "DOCKER_EVIDENCE": "A shim with runtime namespace=moby was observed; this is a Docker-related hint, not running-state proof.",
            "HINTS_ONLY": "Container/network hints observed; Docker identity is not established.",
            "UNKNOWN": "No positive indicators in available data; one or more searches were incomplete.",
            "NOT_OBSERVED": "No configured indicators in the completed reachable-object searches.",
        }[verdict],
    }
    return report


class Collector(artifact_core.CollectionSession):
    """Collect from the supplied Volatility context; never launch another CLI."""

    def __init__(self, context, kernel_name, limit=100000, progress_callback=None):
        """Initialize kernel access, traversal bounds, coverage, and evidence storage."""
        if not 1 <= limit <= 1000000:
            raise ValueError("limit must be in 1..1000000")
        super().__init__(context, kernel_name)
        self.limit = limit
        self.progress_callback = progress_callback
        self.stage = "tasks"
        self.tasks = {}
        self.leaders = []
        self.mount_namespaces = {}
        self.net_namespaces = {}
        self.error_counts = {stage: 0 for stage in STAGES}
        self.report = {
            "schema_version": 2,
            "metadata": {
                "plugin": "linux.docker.Docker",
                "option": "--detector",
                "plugin_version": ".".join(map(str, VERSION)),
                "volatility_version": constants.PACKAGE_VERSION,
                "started_utc": datetime.datetime.now(datetime.timezone.utc).isoformat(),
                "kernel_module": kernel_name,
                "kernel_layer": self.kernel.layer_name,
                "symbol_table": self.kernel.symbol_table_name,
                "isf_url": context.symbol_space[
                    self.kernel.symbol_table_name
                ].config.get("isf_url"),
            },
            "limits": {
                "nodes_per_traversal": limit,
                "argv_bytes": 65536,
                "string_bytes": 4096,
                "evidence_samples_per_check": EVIDENCE_SAMPLES,
                "error_samples_per_stage": ERROR_SAMPLES_PER_STAGE,
            },
            "checks": [
                {
                    "key": key,
                    "check": label,
                    "interpretation": interpretation,
                    "count": 0,
                    "evidence_indices": [],
                }
                for key, label, interpretation, _ in CHECKS
            ],
            "coverage": {},
            "errors": [],
            "evidence": [],
            "limitations": [
                "Presence checks only; no cgroup/ID attribution, process inventory, cache or heap recovery.",
                "Task names and the moby namespace can be imitated; they are evidence, not authentication.",
                "Overlay, veth and interface names are not exclusive to Docker.",
                "A shim or residual mount does not establish that a Docker container is currently running.",
                "Missing objects, unsupported layouts, traversal limits and acquisition smear can hide evidence.",
                "Evidence and error entries are bounded examples; counts include omitted entries.",
            ],
        }
        self.checks = {check["key"]: check for check in self.report["checks"]}

    def issue(self, operation, obj, exc):
        """Classify stage errors, count all occurrences, and retain bounded examples."""
        self.error_counts[self.stage] += 1
        if self.error_counts[self.stage] > ERROR_SAMPLES_PER_STAGE:
            return
        address = hex(int(obj.vol.offset)) if hasattr(obj, "vol") else str(obj)
        kind = (
            "UNSUPPORTED"
            if isinstance(
                exc, (artifact_core.Unsupported, AttributeError, exceptions.SymbolError)
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
        """Run a read operation, record expected failures, and return its default."""
        try:
            return function()
        except READ_ERRORS as exc:
            self.issue(operation, obj, exc)
            return default

    def evidence(self, check, obj, detail):
        """Count an observation and retain a bounded object-address evidence sample."""
        result = self.checks[check]
        result["count"] += 1
        if len(result["evidence_indices"]) >= EVIDENCE_SAMPLES:
            return
        result["evidence_indices"].append(len(self.report["evidence"]))
        self.report["evidence"].append(
            {
                "check": check,
                "stage": self.stage,
                "address": hex(int(obj.vol.offset)),
                "layer": self.kernel.layer_name,
                "detail": detail,
            }
        )

    def string(self, pointer, maximum=4096):
        return artifact_core.strict_string(self.layer, pointer, maximum)

    def array_string(self, array):
        return artifact_core.strict_array_string(self.layer, array)

    def walk(self, head, typename, member):
        return task_readers.walk_list(
            self, head, typename, member, check_backlinks=True
        )

    def namespace(self, namespace, kind):
        """Register a namespace once by address and retain its decoded inode."""
        address = int(namespace.vol.offset)
        target = self.mount_namespaces if kind == "mount" else self.net_namespaces
        if address not in target:

            def inode():
                """Read ns.inum or proc_inum according to the available layout."""
                return namespace_readers.namespace_inum(
                    namespace,
                    missing_error=artifact_core.Unsupported(
                        "Namespace inode layout unavailable"
                    ),
                )

            target[address] = {
                "object": namespace,
                "address": hex(address),
                "inode": self.read(kind + ".namespace_inode", namespace, inode),
            }
        return target[address]

    def collect_tasks(self):
        """Collect processes and threads from init_task, then discover their namespaces."""
        init = self.symbol("init_task", "task_struct")
        self.tasks[int(init.vol.offset)] = init

        def leaders():
            """Walk the init_task process list and retain leaders by address."""
            for task in self.walk(init.tasks, "task_struct", "tasks"):
                self.tasks[int(task.vol.offset)] = task

        self.read("tasks.list", init, leaders)
        self.leaders = list(self.tasks.values())


        for leader in self.leaders:

            def threads(*, leader=leader):
                """Select the available thread-list layout and add the leader's threads."""
                if not leader.signal:
                    return
                if leader.has_member("thread_node") and leader.signal.has_member(
                    "thread_head"
                ):
                    head, member = leader.signal.thread_head, "thread_node"
                elif leader.has_member("thread_group"):
                    head, member = leader.thread_group, "thread_group"
                else:
                    raise artifact_core.Unsupported("Thread list layout unavailable")
                for task in self.walk(head, "task_struct", member):
                    self.tasks[int(task.vol.offset)] = task

            self.read("tasks.threads", leader, threads)
        proxies = set()
        for task in self.tasks.values():

            def namespaces(*, task=task):
                """Register unique mount and network namespaces from a task's nsproxy."""
                if not task.nsproxy:
                    return
                address = int(task.nsproxy)
                if address in proxies:
                    return
                proxy = task.nsproxy.dereference()
                proxies.add(address)
                for kind, member in (("mount", "mnt_ns"), ("net", "net_ns")):

                    def get_namespace(m=member):
                        """Validate the selected nsproxy pointer before dereferencing it."""
                        ptr = proxy.member(m)
                        if not ptr:
                            raise artifact_core.Incomplete(
                                "NULL namespace in non-NULL nsproxy"
                            )
                        return ptr.dereference()

                    ns = self.read("task." + member, task, get_namespace)
                    if ns is not None:
                        self.namespace(ns, kind)

            self.read("task.namespaces", task, namespaces)

    def argv(self, task):
        return docker_artifacts.DockerArtifacts.read_task_argv(
            self.context,
            self.kernel_name,
            int(task.vol.offset),
            policy="presence",
            layer_name=task.vol.layer_name,
            native_layer_name=task.vol.native_layer_name,
        )

    def collect_runtime(self):
        """Find shims among leaders and validate moby namespace evidence from argv."""
        for task in self.leaders:
            comm = self.read(
                "runtime.comm", task, lambda task=task: self.array_string(task.comm)
            )
            if "containerd_shim" not in runtime_checks(comm):
                continue
            pid = self.read("runtime.pid", task, lambda task=task: int(task.tgid))
            tid = self.read("runtime.tid", task, lambda task=task: int(task.pid))
            if pid is not None and tid is not None and pid != tid:
                self.issue(
                    "runtime.leader",
                    task,
                    artifact_core.Incomplete("Task list entry is not a process leader"),
                )
                continue

            self.evidence("containerd_shim", task, {"pid": pid, "comm": comm})
            args = self.read("runtime.argv", task, lambda task=task: self.argv(task))
            if args is None:
                continue
            flags = self.read(
                "runtime.namespace", task, lambda args=args: argv_flags(args)
            )
            if flags is None:
                continue
            namespaces = flags.get("namespace", [])
            if len(namespaces) > 1:
                self.issue(
                    "runtime.namespace",
                    task,
                    artifact_core.Incomplete("Conflicting runtime namespaces"),
                )
            if namespaces == ["moby"]:
                self.evidence(
                    "docker_shim",
                    task,
                    {"pid": pid, "comm": comm, "runtime_namespace": "moby"},
                )

    def mount_points(self, namespace):
        return mount_readers.checked_mount_points(self, namespace)

    def collect_mounts(self):
        """Inspect discovered mount namespaces for Overlay-family filesystems."""
        if not self.mount_namespaces:
            raise artifact_core.Incomplete("No reachable mount namespace")
        for ns in self.mount_namespaces.values():

            def scan(*, ns=ns):
                """Read each mount's filesystem type and record Overlay observations."""
                for mount in self.mount_points(ns["object"]):

                    def fs_type(*, mount=mount):
                        """Read the superblock filesystem name and append a FUSE subtype."""
                        vf = mount.mnt if mount.has_member("mnt") else mount
                        sb = vf.mnt_sb
                        name = self.string(sb.s_type.name, 256)
                        if name in ("fuse", "fuseblk"):


                            def subtype():
                                """Validate the FUSE subtype member and read a non-NULL string."""
                                if not sb.has_member("s_subtype"):
                                    raise artifact_core.Unsupported(
                                        "FUSE superblock subtype is not described"
                                    )
                                return (
                                    self.string(sb.s_subtype, 256)
                                    if sb.s_subtype
                                    else ""
                                )

                            suffix = self.read("mounts.fs_subtype", mount, subtype)
                            if suffix:
                                name += "." + suffix
                        return name

                    fstype = self.read("mounts.fs_type", mount, fs_type)
                    if fstype in ("overlay", "overlayfs", "fuse.overlayfs"):
                        self.evidence(
                            "overlay",
                            mount,
                            {"namespace_inode": ns["inode"], "fstype": fstype},
                        )

            self.read("mounts.namespace", ns["object"], scan)

    def collect_network(self):
        """Discover network namespaces globally and from tasks, then inspect devices."""
        if self.kernel.has_symbol("init_net"):
            self.read(
                "network.init_net",
                "init_net",
                lambda: self.namespace(self.symbol("init_net", "net"), "net"),
            )

        def global_namespaces():
            """Walk net_namespace_list and register global namespaces by address."""
            head = self.symbol("net_namespace_list", "list_head")
            for ns in self.walk(head, "net", "list"):
                self.namespace(ns, "net")

        self.read("network.namespace_list", "net_namespace_list", global_namespaces)
        if not self.net_namespaces:
            raise artifact_core.Incomplete("No reachable network namespace")
        for ns in self.net_namespaces.values():

            def devices(*, ns=ns):
                """Walk devices in one namespace and record name and link-kind indicators."""
                for dev in network_readers.devices(self, ns["object"]):
                    name = self.read(
                        "network.name", dev, lambda dev=dev: self.array_string(dev.name)
                    )

                    def kind(*, dev=dev):
                        """Read the rtnl_link_ops kind and return an empty string for NULL."""
                        return network_readers.link_kind(
                            dev,
                            lambda ptr: self.string(ptr, 256),
                            missing_error=artifact_core.Unsupported(
                                "net_device.rtnl_link_ops is not described"
                            ),
                        )

                    link_kind = self.read("network.kind", dev, kind)
                    for check in network_checks(name, link_kind):
                        self.evidence(
                            check,
                            dev,
                            {
                                "namespace_inode": ns["inode"],
                                "name": name,
                                "kind": link_kind,
                            },
                        )

            self.read("network.devices", ns["object"], devices)

    def collect(self):
        """Run collection stages, derive coverage from errors, and summarize checks."""
        for index, stage in enumerate(STAGES):
            self.stage = stage
            if self.progress_callback:
                self.progress_callback(index * 100 / len(STAGES), "Detector: " + stage)
            self.read(stage, stage, getattr(self, "collect_" + stage))
            count = self.error_counts[stage]
            self.report["coverage"][stage] = {
                "status": "PARTIAL" if count else "COMPLETE",
                "errors": count,
                "omitted_errors": max(0, count - ERROR_SAMPLES_PER_STAGE),
            }
        if self.progress_callback:
            self.progress_callback(100, "Detector: completed")
        return summarize(self.report)


def presentation(report):
    """Build TreeGrid rows for each check, with the overall assessment first."""
    columns = [
        ("Check", str),
        ("Status", str),
        ("Interpretation", str),
        ("Coverage", str),
        ("Count", int),
        ("Evidence", str),
    ]
    summary = report["summary"]
    rows = [
        (
            "Overall",
            summary["status"],
            "ASSESSMENT",
            summary["coverage"],
            sum(check["count"] for check in report["checks"]),
            summary["meaning"],
        )
    ]
    for check in report["checks"]:
        samples = []
        for index in check["evidence_indices"]:
            item = report["evidence"][index]
            detail = item["detail"]
            sample = {
                key: detail[key]
                for key in (
                    "pid",
                    "comm",
                    "namespace_inode",
                    "name",
                    "kind",
                    "fstype",
                    "runtime_namespace",
                )
                if key in detail
            }
            samples.append(
                json.dumps(sample, ensure_ascii=False, separators=(",", ":"))
            )
        text = "; ".join(samples)
        if check["omitted_evidence"]:
            text += f"; +{check['omitted_evidence']} observations (examples omitted)"
        if not text:
            text = (
                "No match in completed searches"
                if check["status"] == "NOT_OBSERVED"
                else "See coverage/errors in detector_evidence.json"
            )
        rows.append(
            (
                check["check"],
                check["status"],
                check["interpretation"],
                check["coverage"],
                check["count"],
                text,
            )
        )
    return columns, rows


class Detector(interfaces.plugins.PluginInterface):
    """Backend for linux.docker.Docker --detector; presence checks only."""



    hidden = True
    _required_framework_version = (2, 28, 0)
    _version = VERSION

    @classmethod
    def get_requirements(cls):
        """Declare the Linux kernel module and traversal-limit requirements."""
        return [
            requirements.VersionRequirement(
                name="docker_artifacts",
                component=docker_artifacts.DockerArtifacts,
                version=(1, 0, 1),
            ),
            requirements.ModuleRequirement(
                name="kernel",
                description="Linux kernel with matching ISF",
                architectures=["Intel32", "Intel64"],
            ),
            requirements.IntRequirement(
                name="limit",
                description="Maximum nodes per traversal (1..1000000)",
                optional=True,
                default=100000,
            ),
        ]

    def run(self):
        """Validate the traversal limit, save evidence JSON, and return a TreeGrid."""
        limit = self.config.get("limit", 100000)
        if not 1 <= limit <= 1000000:
            raise exceptions.VolatilityException("--limit must be in 1..1000000")
        report = Collector(
            self.context, self.config["kernel"], limit, self._progress_callback
        ).collect()
        with self.open("detector_evidence.json") as handle:
            handle.write(
                json.dumps(report, ensure_ascii=False, indent=2).encode("utf-8")
            )
        errors = sum(stage["errors"] for stage in report["coverage"].values())
        if errors:
            vollog.warning(
                "Detector completed with %d collection issues; review bounded examples in detector_evidence.json",
                errors,
            )
        columns, rows = presentation(report)
        return _vertical.vertical_grid(columns, ((0, row) for row in rows))

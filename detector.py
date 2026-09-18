"""Presence checks for the unified Docker plugin's --detector option.

Run: vol -p /path/to/plugins -f memory.lime linux.docker.Docker --detector
This module is an internal backend, not a separately advertised CLI plugin.

Inspect network interfaces, Overlay mounts and containerd-shim processes.
The moby runtime namespace refines a shim observation; no container IDs,
cgroup membership, process inventory or lifecycle information are collected.
Threads are traversed only to reach their mount/network namespaces.

FOUND is an observation, not authenticated Docker identity or running state.
NOT_OBSERVED is limited to completed searches; incomplete reads without a
positive observation produce UNKNOWN. detector_evidence.json (schema 2) keeps
counts, coverage and bounded examples, not full object inventories or argv.
No Volatility core files, capability fields or mount hash symbols are needed.
"""

import datetime
import json
import logging
import re

from volatility3.framework import constants, exceptions, interfaces, objects
from volatility3.framework.configuration import requirements
from volatility3.plugins.linux._vertical import vertical_grid

from volatility3.plugins.linux._artifacts import mounts as mount_readers, network as network_readers
from volatility3.plugins.linux._artifacts.core import (
    CollectionSession,
    strict_string,
    strict_array_string,
    Unsupported,
    Incomplete,
)
from volatility3.plugins.linux._artifacts.namespaces import namespace_inum
from volatility3.plugins.linux._artifacts.tasks import walk_list, read_argv, PRESENCE_ARGV


vollog = logging.getLogger(__name__)
VERSION = (2, 0, 0)
EVIDENCE_SAMPLES = 3
ERROR_SAMPLES_PER_STAGE = 3
BRIDGE_NAME = re.compile(r"^br-[0-9a-f]{12}$")
READ_ERRORS = (exceptions.VolatilityException, AttributeError, ValueError,
               TypeError, KeyError, IndexError, OverflowError, UnicodeError)
STAGES = ("tasks", "runtime", "mounts", "network")
# key, description, interpretation, prerequisite coverage
CHECKS = (
    ("docker_interface", "Docker-like interface name", "NAME_HINT", ("network",)),
    ("veth", "Veth device (link kind)", "GENERIC_HINT", ("network",)),
    ("overlay", "Overlay filesystem", "GENERIC_HINT", ("tasks", "mounts")),
    ("containerd_shim", "Containerd shim process", "GENERIC_HINT", ("tasks", "runtime")),
    ("docker_shim", "Shim with namespace=moby", "DOCKER_LABEL", ("tasks", "runtime")),
)


def argv_flags(argv):
    """명령행에서 runtime namespace 값을 추출한다. 두 옵션 표기를 처리하고 빈 값은 오류로 알린다."""
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
                raise Incomplete("Runtime namespace option has no value")
            value = argv[index + 1]
        if not value:
            raise Incomplete("Runtime namespace option has an empty value")
        result.setdefault(flag, set()).add(value)
    return {key: sorted(values) for key, values in result.items()}


def runtime_checks(comm, argv=None):
    """프로세스 이름으로 shim을 찾고, 인자의 namespace가 moby이면 해당 검사 항목을 추가한다."""
    found = []
    # Linux comm is only TASK_COMM_LEN bytes; the full shim name is truncated.
    if comm and comm.startswith("containerd-shim"):
        found.append("containerd_shim")
        if argv is not None and argv_flags(argv).get("namespace") == ["moby"]:
            found.append("docker_shim")
    return found


def network_checks(name, kind):
    """장치 이름과 link kind를 각각 검사해 일치하는 네트워크 항목을 반환한다."""
    found = []
    if name and (name.startswith("docker") or BRIDGE_NAME.fullmatch(name)):
        found.append("docker_interface")
    if kind == "veth":
        found.append("veth")
    return found


def summarize(report):
    """관찰 수와 단계 완전성으로 항목별 상태를 정하고, 생략된 근거 수와 전체 요약을 계산한다."""
    checks = report["checks"]
    prerequisites_by_key = {key: prerequisites for key, _, _, prerequisites in CHECKS}
    for check in checks:
        complete = all(report["coverage"].get(stage, {}).get("status") == "COMPLETE"
                       for stage in prerequisites_by_key[check["key"]])
        check["status"] = "FOUND" if check["count"] else "NOT_OBSERVED" if complete else "UNKNOWN"
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
        "coverage": "COMPLETE" if all(c["coverage"] == "COMPLETE" for c in checks) else "PARTIAL",
        "meaning": {
            "DOCKER_EVIDENCE": "A shim with runtime namespace=moby was observed; this is a Docker-related hint, not running-state proof.",
            "HINTS_ONLY": "Container/network hints observed; Docker identity is not established.",
            "UNKNOWN": "No positive indicators in available data; one or more searches were incomplete.",
            "NOT_OBSERVED": "No configured indicators in the completed reachable-object searches.",
        }[verdict],
    }
    return report


class Collector(CollectionSession):
    """Collect from the supplied Volatility context; never launch another CLI."""

    def __init__(self, context, kernel_name, limit=100000, progress_callback=None):
        """커널 접근 환경과 순회 한도를 설정하고, 단계별 오류와 관측 결과의 저장 공간을 준비한다."""
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
            "metadata": {"plugin": "linux.docker.Docker", "option": "--detector",
                         "plugin_version": ".".join(map(str, VERSION)),
                         "volatility_version": constants.PACKAGE_VERSION,
                         "started_utc": datetime.datetime.now(datetime.timezone.utc).isoformat(),
                         "kernel_module": kernel_name, "kernel_layer": self.kernel.layer_name,
                         "symbol_table": self.kernel.symbol_table_name,
                         "isf_url": context.symbol_space[self.kernel.symbol_table_name].config.get("isf_url")},
            "limits": {"nodes_per_traversal": limit, "argv_bytes": 65536,
                       "string_bytes": 4096, "evidence_samples_per_check": EVIDENCE_SAMPLES,
                       "error_samples_per_stage": ERROR_SAMPLES_PER_STAGE},
            "checks": [{"key": key, "check": label, "interpretation": interpretation,
                        "count": 0, "evidence_indices": []} for key, label, interpretation, _ in CHECKS],
            "coverage": {}, "errors": [], "evidence": [],
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
        """현재 단계의 오류를 유형별로 기록한다. 전체 수를 세되 예시 저장 수는 제한한다."""
        self.error_counts[self.stage] += 1
        if self.error_counts[self.stage] > ERROR_SAMPLES_PER_STAGE:
            return
        address = hex(int(obj.vol.offset)) if hasattr(obj, "vol") else str(obj)
        kind = ("UNSUPPORTED" if isinstance(exc, (Unsupported, AttributeError, exceptions.SymbolError))
                else "UNREADABLE" if isinstance(exc, exceptions.InvalidAddressException)
                else "INCOMPLETE" if isinstance(exc, Incomplete) else "ERROR")
        self.report["errors"].append({"stage": self.stage, "operation": operation,
                                      "address": address, "kind": kind,
                                      "exception": type(exc).__name__, "detail": str(exc)})

    def read(self, operation, obj, function, default=None):
        """읽기 함수를 실행하고 예상한 예외가 나면 오류를 기록한 뒤 기본값을 반환한다."""
        try:
            return function()
        except READ_ERRORS as exc:
            self.issue(operation, obj, exc)
            return default

    def evidence(self, check, obj, detail):
        """검사 항목의 관찰 수를 늘리고, 정해진 개수까지 객체 주소와 상세 근거를 저장한다."""
        result = self.checks[check]
        result["count"] += 1
        if len(result["evidence_indices"]) >= EVIDENCE_SAMPLES:
            return
        result["evidence_indices"].append(len(self.report["evidence"]))
        self.report["evidence"].append({"check": check, "stage": self.stage,
                                        "address": hex(int(obj.vol.offset)),
                                        "layer": self.kernel.layer_name, "detail": detail})

    def string(self, pointer, maximum=4096):
        return strict_string(self.layer, pointer, maximum)

    def array_string(self, array):
        return strict_array_string(self.layer, array)

    def walk(self, head, typename, member):
        return walk_list(self, head, typename, member, check_backlinks=True)

    def namespace(self, namespace, kind):
        """namespace를 주소별로 중복 없이 등록하고 inode를 읽어 저장된 항목을 반환한다."""
        address = int(namespace.vol.offset)
        target = self.mount_namespaces if kind == "mount" else self.net_namespaces
        if address not in target:
            def inode():
                """namespace 레이아웃에 따라 ns.inum 또는 proc_inum을 읽는다."""
                return namespace_inum(namespace, missing_error=Unsupported("Namespace inode layout unavailable"))
            target[address] = {"object": namespace, "address": hex(address),
                               "inode": self.read(kind + ".namespace_inode", namespace, inode)}
        return target[address]

    def collect_tasks(self):
        """init_task에서 프로세스와 스레드를 모은 뒤 각 task의 mount/net namespace를 찾는다."""
        init = self.symbol("init_task", "task_struct")
        self.tasks[int(init.vol.offset)] = init

        def leaders():
            """init_task의 process 목록을 순회해 leader를 주소별로 저장한다."""
            for task in self.walk(init.tasks, "task_struct", "tasks"):
                self.tasks[int(task.vol.offset)] = task
        self.read("tasks.list", init, leaders)
        self.leaders = list(self.tasks.values())
        # A thread may expose a namespace its leader does not use. This is
        # internal discovery only; no thread inventory or membership is saved.
        for leader in self.leaders:
            def threads():
                """사용 가능한 스레드 목록 레이아웃을 선택해 leader의 스레드를 추가한다."""
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
        proxies = set()
        for task in self.tasks.values():
            def namespaces():
                """task의 nsproxy에서 중복 주소를 제외하고 mount/net namespace를 등록한다."""
                if not task.nsproxy:
                    return  # NULL is valid for exiting tasks and some kernel tasks.
                address = int(task.nsproxy)
                if address in proxies:
                    return
                proxy = task.nsproxy.dereference()
                proxies.add(address)
                for kind, member in (("mount", "mnt_ns"), ("net", "net_ns")):
                    def get_namespace(m=member):
                        """선택한 nsproxy 멤버의 포인터를 확인한 뒤 namespace 객체를 역참조한다."""
                        ptr = proxy.member(m)
                        if not ptr:
                            raise Incomplete("NULL namespace in non-NULL nsproxy")
                        return ptr.dereference()
                    ns = self.read("task." + member, task, get_namespace)
                    if ns is not None:
                        self.namespace(ns, kind)
            self.read("task.namespaces", task, namespaces)

    def argv(self, task):
        return read_argv(self.context, task, PRESENCE_ARGV)

    def collect_runtime(self):
        """leader의 이름으로 shim을 찾는다. 이름 근거를 저장하고 argv의 moby namespace를 확인한다."""
        for task in self.leaders:
            comm = self.read("runtime.comm", task, lambda: self.array_string(task.comm))
            if "containerd_shim" not in runtime_checks(comm):
                continue
            pid = self.read("runtime.pid", task, lambda: int(task.tgid))
            tid = self.read("runtime.tid", task, lambda: int(task.pid))
            if pid is not None and tid is not None and pid != tid:
                self.issue("runtime.leader", task, Incomplete("Task list entry is not a process leader"))
                continue
            # Preserve the name observation even when argv cannot be read.
            self.evidence("containerd_shim", task, {"pid": pid, "comm": comm})
            args = self.read("runtime.argv", task, lambda: self.argv(task))
            if args is None:
                continue
            flags = self.read("runtime.namespace", task, lambda: argv_flags(args))
            if flags is None:
                continue
            namespaces = flags.get("namespace", [])
            if len(namespaces) > 1:
                self.issue("runtime.namespace", task, Incomplete("Conflicting runtime namespaces"))
            if namespaces == ["moby"]:
                self.evidence("docker_shim", task, {"pid": pid, "comm": comm, "runtime_namespace": "moby"})

    def mount_points(self, namespace):
        return mount_readers.checked_mount_points(self, namespace)

    def collect_mounts(self):
        """발견한 mount namespace를 조사하고 Overlay 계열 파일시스템의 관측 근거를 수집한다."""
        if not self.mount_namespaces:
            raise Incomplete("No reachable mount namespace")
        for ns in self.mount_namespaces.values():
            def scan():
                """현재 namespace의 mount별 파일시스템 유형을 읽어 Overlay이면 근거를 기록한다."""
                for mount in self.mount_points(ns["object"]):
                    def fs_type():
                        """superblock의 파일시스템 이름을 읽고 FUSE subtype이 있으면 이어 붙인다."""
                        vf = mount.mnt if mount.has_member("mnt") else mount
                        sb = vf.mnt_sb
                        name = self.string(sb.s_type.name, 256)
                        if name in ("fuse", "fuseblk"):
                            # /proc/mounts joins s_type->name and s_subtype;
                            # the kernel type name itself is only "fuse".
                            def subtype():
                                """FUSE subtype 멤버를 확인하고 포인터가 유효하면 문자열을 읽는다."""
                                if not sb.has_member("s_subtype"):
                                    raise Unsupported("FUSE superblock subtype is not described")
                                return self.string(sb.s_subtype, 256) if sb.s_subtype else ""
                            suffix = self.read("mounts.fs_subtype", mount, subtype)
                            if suffix:
                                name += "." + suffix
                        return name
                    fstype = self.read("mounts.fs_type", mount, fs_type)
                    if fstype in ("overlay", "overlayfs", "fuse.overlayfs"):
                        self.evidence("overlay", mount, {"namespace_inode": ns["inode"], "fstype": fstype})
            self.read("mounts.namespace", ns["object"], scan)

    def collect_network(self):
        """전역 및 task 참조로 net namespace를 확보하고 각 장치의 이름과 종류를 검사한다."""
        if self.kernel.has_symbol("init_net"):
            self.read("network.init_net", "init_net", lambda: self.namespace(self.symbol("init_net", "net"), "net"))

        def global_namespaces():
            """net_namespace_list를 따라 전역 net namespace를 주소별로 등록한다."""
            head = self.symbol("net_namespace_list", "list_head")
            for ns in self.walk(head, "net", "list"):
                self.namespace(ns, "net")
        self.read("network.namespace_list", "net_namespace_list", global_namespaces)
        if not self.net_namespaces:
            raise Incomplete("No reachable network namespace")
        for ns in self.net_namespaces.values():
            def devices():
                """현재 net namespace의 장치를 순회하고 이름·link kind 검사 결과를 근거로 저장한다."""
                for dev in network_readers.devices(self, ns["object"]):
                    name = self.read("network.name", dev, lambda: self.array_string(dev.name))

                    def kind():
                        """rtnl_link_ops에서 link kind를 읽고 포인터가 NULL이면 빈 문자열을 반환한다."""
                        return network_readers.link_kind(dev, lambda ptr: self.string(ptr, 256),
                            missing_error=Unsupported("net_device.rtnl_link_ops is not described"))

                    link_kind = self.read("network.kind", dev, kind)
                    for check in network_checks(name, link_kind):
                        self.evidence(check, dev, {"namespace_inode": ns["inode"], "name": name, "kind": link_kind})
            self.read("network.devices", ns["object"], devices)

    def collect(self):
        """수집 단계를 차례로 실행한다. 오류 수로 단계 완전성을 기록한 뒤 검사별 결과를 요약한다."""
        for index, stage in enumerate(STAGES):
            self.stage = stage
            if self.progress_callback:
                self.progress_callback(index * 100 / len(STAGES), "Detector: " + stage)
            self.read(stage, stage, getattr(self, "collect_" + stage))
            count = self.error_counts[stage]
            self.report["coverage"][stage] = {"status": "PARTIAL" if count else "COMPLETE",
                                               "errors": count,
                                               "omitted_errors": max(0, count - ERROR_SAMPLES_PER_STAGE)}
        if self.progress_callback:
            self.progress_callback(100, "Detector: completed")
        return summarize(self.report)


def presentation(report):
    """검사별 상태와 근거 예시를 TreeGrid 칼럼의 행으로 구성한다. 전체 요약을 첫 행에 둔다."""
    columns = [("Check", str), ("Status", str), ("Interpretation", str),
               ("Coverage", str), ("Count", int), ("Evidence", str)]
    summary = report["summary"]
    rows = [("Overall", summary["status"], "ASSESSMENT", summary["coverage"],
             sum(check["count"] for check in report["checks"]), summary["meaning"])]
    for check in report["checks"]:
        samples = []
        for index in check["evidence_indices"]:
            item = report["evidence"][index]
            detail = item["detail"]
            sample = {key: detail[key] for key in ("pid", "comm", "namespace_inode", "name", "kind", "fstype", "runtime_namespace")
                      if key in detail}
            samples.append(json.dumps(sample, ensure_ascii=False, separators=(",", ":")))
        text = "; ".join(samples)
        if check["omitted_evidence"]:
            text += f"; +{check['omitted_evidence']} observations (examples omitted)"
        if not text:
            text = "No match in completed searches" if check["status"] == "NOT_OBSERVED" else "See coverage/errors in detector_evidence.json"
        rows.append((check["check"], check["status"], check["interpretation"],
                     check["coverage"], check["count"], text))
    return columns, rows


class Detector(interfaces.plugins.PluginInterface):
    """Backend for linux.docker.Docker --detector; presence checks only."""

    # Volatility's discovery skips hidden classes. The Docker dispatcher loads
    # this backend directly and supplies its context, settings and file handler.
    hidden = True
    _required_framework_version = (2, 28, 0)
    _version = VERSION

    @classmethod
    def get_requirements(cls):
        """Linux 커널 모듈과 순회 한도에 필요한 Volatility 실행 설정을 선언한다."""
        return [
            requirements.ModuleRequirement(name="kernel", description="Linux kernel with matching ISF",
                                           architectures=["Intel32", "Intel64"]),
            requirements.IntRequirement(name="limit", description="Maximum nodes per traversal (1..1000000)",
                                        optional=True, default=100000),
        ]

    def run(self):
        """순회 한도를 검증하고 근거를 수집한다. JSON 파일을 저장한 뒤 TreeGrid를 반환한다."""
        limit = self.config.get("limit", 100000)
        if not 1 <= limit <= 1000000:
            raise exceptions.VolatilityException("--limit must be in 1..1000000")
        report = Collector(self.context, self.config["kernel"], limit, self._progress_callback).collect()
        with self.open("detector_evidence.json") as handle:
            handle.write(json.dumps(report, ensure_ascii=False, indent=2).encode("utf-8"))
        errors = sum(stage["errors"] for stage in report["coverage"].values())
        if errors:
            vollog.warning("Detector completed with %d collection issues; review bounded examples in detector_evidence.json", errors)
        columns, rows = presentation(report)
        return vertical_grid(columns, ((0, row) for row in rows))

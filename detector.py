"""Presence checks for the unified Docker plugin's --detector option.

Run: vol -p /path/to/plugins -f memory.lime -r pretty linux.docker.Docker --detector
This module is an internal backend, not a separately advertised CLI plugin.

Inspect network interfaces, Overlay mounts and containerd-shim processes.
The moby runtime namespace refines a shim observation; no container IDs,
cgroup membership, process inventory or lifecycle information are collected.
Threads are traversed only to reach their mount/network namespaces.

FOUND is an observation, not authenticated Docker identity or running state.
NOT_OBSERVED is limited to completed searches; incomplete reads without a
positive observation produce UNKNOWN. detector_evidence.json (schema 3) keeps
counts, coverage and bounded examples, not full object inventories or argv.
Output contains per-check observations without an overall Docker assessment.
Status definitions, sampling limits and interpretation notes are in README.md.
No Volatility core files, capability fields or mount hash symbols are needed.
"""

import datetime
import json
import logging
import re

from volatility3.framework import constants, exceptions, interfaces, objects, renderers
from volatility3.framework.configuration import requirements


vollog = logging.getLogger(__name__)
VERSION = (3, 1, 0)
EVIDENCE_SAMPLES = 3
ERROR_SAMPLES_PER_STAGE = 3
BRIDGE_NAME = re.compile(r"^br-[0-9a-f]{12}$")
READ_ERRORS = (exceptions.VolatilityException, AttributeError, ValueError,
               TypeError, KeyError, IndexError, OverflowError, UnicodeError)
STAGES = ("tasks", "runtime", "mounts", "network")
# key, description, prerequisite coverage
CHECKS = (
    ("docker_interface", "Docker-like interface name", ("network",)),
    ("veth", "Veth device (link kind)", ("network",)),
    ("overlay", "Overlay filesystem", ("tasks", "mounts")),
    ("containerd_shim", "Containerd shim process", ("tasks", "runtime")),
    ("docker_shim", "Shim with namespace=moby", ("tasks", "runtime")),
)


class Unsupported(ValueError):
    """The ISF does not describe a supported layout."""


class Incomplete(ValueError):
    """A traversal could not prove that it reached its natural end."""


def argv_flags(argv):
    # 명령행 인자에서 namespace 값을 모아 중복을 정리하고, 값이 누락되면 오류를 발생시킨다.
    """Read only runtime namespace flags; never extract container IDs."""
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
    # 프로세스 이름과 namespace 인자를 확인해 일치하는 shim 검사 항목을 반환한다.
    found = []
    # Linux comm is only TASK_COMM_LEN bytes; the full shim name is truncated.
    if comm and comm.startswith("containerd-shim"):
        found.append("containerd_shim")
        if argv is not None and argv_flags(argv).get("namespace") == ["moby"]:
            found.append("docker_shim")
    return found


def network_checks(name, kind):
    # 인터페이스 이름과 link kind를 각각 검사해 일치하는 네트워크 검사 항목을 반환한다.
    found = []
    if name and (name.startswith("docker") or BRIDGE_NAME.fullmatch(name)):
        found.append("docker_interface")
    if kind == "veth":
        found.append("veth")
    return found


def summarize(report):
    # 관찰 수와 선행 단계의 수집 상태로 항목별 Status, Coverage, 생략된 근거 수를 계산한다.
    """Record each check's observation status and collection coverage."""
    checks = report["checks"]
    prerequisites_by_key = {key: prerequisites for key, _, prerequisites in CHECKS}
    for check in checks:
        complete = all(report["coverage"].get(stage, {}).get("status") == "COMPLETE"
                       for stage in prerequisites_by_key[check["key"]])
        check["status"] = "FOUND" if check["count"] else "NOT_OBSERVED" if complete else "UNKNOWN"
        check["coverage"] = "COMPLETE" if complete else "PARTIAL"
        check["omitted_evidence"] = check["count"] - len(check["evidence_indices"])
    return report


class Collector:
    """Collect from the supplied Volatility context; never launch another CLI."""

    def __init__(self, context, kernel_name, limit=100000, progress_callback=None):
        # 커널 접근 환경과 순회 한도를 설정하고 관측값, 오류, 결과 보고서의 저장 공간을 초기화한다.
        if not 1 <= limit <= 1000000:
            raise ValueError("limit must be in 1..1000000")
        self.context = context
        self.kernel = context.modules[kernel_name]
        self.layer = context.layers[self.kernel.layer_name]
        self.limit = limit
        self.progress_callback = progress_callback
        self.stage = "tasks"
        self.tasks = {}
        self.leaders = []
        self.mount_namespaces = {}
        self.net_namespaces = {}
        self.error_counts = {stage: 0 for stage in STAGES}
        self.report = {
            "schema_version": 3,
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
            "checks": [{"key": key, "check": label,
                        "count": 0, "evidence_indices": []} for key, label, _ in CHECKS],
            "coverage": {}, "errors": [], "evidence": [],
        }
        self.checks = {check["key"]: check for check in self.report["checks"]}

    def obj(self, typename, address):
        # 커널 메모리의 절대 주소에서 지정한 타입의 객체를 생성한다.
        return self.kernel.object(typename, offset=int(address), absolute=True)

    def symbol(self, name, typename):
        # 심볼 주소에 명시한 타입을 적용해 커널 모듈 기준의 객체를 생성한다.
        # ISF symbols may have addresses but no type metadata (e.g. some BTF ISFs).
        return self.kernel.object(typename, offset=self.kernel.get_symbol(name).address, absolute=False)

    def issue(self, operation, obj, exc):
        # 현재 단계의 전체 오류 수를 늘리고, 저장 한도 안에서 오류 종류와 발생 위치를 기록한다.
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
        # 읽기 함수를 실행하고, 처리 대상 예외가 발생하면 오류를 기록한 뒤 기본값을 반환한다.
        try:
            return function()
        except READ_ERRORS as exc:
            self.issue(operation, obj, exc)
            return default

    def evidence(self, check, obj, detail):
        # 검사 항목의 관찰 수를 늘리고, 저장 한도 안에서 객체 주소와 관측 근거를 보관한다.
        result = self.checks[check]
        result["count"] += 1
        if len(result["evidence_indices"]) >= EVIDENCE_SAMPLES:
            return
        result["evidence_indices"].append(len(self.report["evidence"]))
        self.report["evidence"].append({"check": check, "stage": self.stage,
                                        "address": hex(int(obj.vol.offset)),
                                        "layer": self.kernel.layer_name, "detail": detail})

    def string(self, pointer, maximum=4096):
        # 포인터 위치에서 길이 한도 안의 NUL 종료 문자열을 읽고 엄격한 UTF-8로 해석한다.
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
        # 크기가 유효한 문자 배열인지 확인하고 NUL로 끝나는 UTF-8 문자열을 반환한다.
        if not isinstance(array, objects.Array) or not 0 < array.vol.count <= 4096:
            raise Unsupported("Name is not a bounded character array")
        raw = self.layer.read(int(array.vol.offset), array.vol.count, pad=False)
        end = raw.find(b"\0")
        if end < 0:
            raise Incomplete("Unterminated character array")
        return raw[:end].decode("utf-8", errors="strict")

    def walk(self, head, typename, member):
        # 연결 목록의 종료, 역방향 연결, 반복 방문과 순회 한도를 검사하며 객체를 차례로 반환한다.
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

    def namespace(self, namespace, kind):
        # namespace를 메모리 주소별로 등록하고 객체, 주소, inode 정보를 반환한다.
        address = int(namespace.vol.offset)
        target = self.mount_namespaces if kind == "mount" else self.net_namespaces
        if address not in target:
            def inode():
                # namespace 구조에 따라 ns.inum 또는 proc_inum에서 inode 값을 읽는다.
                if namespace.has_member("ns"):
                    return int(namespace.ns.inum)
                if namespace.has_member("proc_inum"):
                    return int(namespace.proc_inum)
                raise Unsupported("Namespace inode layout unavailable")
            target[address] = {"object": namespace, "address": hex(address),
                               "inode": self.read(kind + ".namespace_inode", namespace, inode)}
        return target[address]

    def collect_tasks(self):
        # process leader와 thread를 수집하고 각 task의 mount 및 net namespace를 확보한다.
        init = self.symbol("init_task", "task_struct")
        self.tasks[int(init.vol.offset)] = init

        def leaders():
            # init_task의 연결 목록을 순회하여 process leader 객체를 주소별로 저장한다.
            for task in self.walk(init.tasks, "task_struct", "tasks"):
                self.tasks[int(task.vol.offset)] = task
        self.read("tasks.list", init, leaders)
        self.leaders = list(self.tasks.values())
        # A thread may expose a namespace its leader does not use. This is
        # internal discovery only; no thread inventory or membership is saved.
        for leader in self.leaders:
            def threads():
                # 현재 leader의 thread 목록 구조를 선택해 같은 프로세스의 task 객체를 모은다.
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
                # 현재 task의 nsproxy를 확인하고 아직 처리하지 않은 proxy의 mount 및 net namespace를 등록한다.
                if not task.nsproxy:
                    return  # NULL is valid for exiting tasks and some kernel tasks.
                address = int(task.nsproxy)
                if address in proxies:
                    return
                proxy = task.nsproxy.dereference()
                proxies.add(address)
                for kind, member in (("mount", "mnt_ns"), ("net", "net_ns")):
                    def get_namespace(m=member):
                        # 선택한 nsproxy 멤버의 포인터를 검사하고 namespace 객체를 역참조해 반환한다.
                        ptr = proxy.member(m)
                        if not ptr:
                            raise Incomplete("NULL namespace in non-NULL nsproxy")
                        return ptr.dereference()
                    ns = self.read("task." + member, task, get_namespace)
                    if ns is not None:
                        self.namespace(ns, kind)
            self.read("task.namespaces", task, namespaces)

    def argv(self, task):
        # 프로세스의 argv 메모리를 읽고 길이, NUL 종료, UTF-8을 확인해 명령행 인자 목록을 반환한다.
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
        # leader의 shim 이름과 runtime namespace를 검사하고 PID, comm 등의 관측값을 저장한다.
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
        # namespace의 RB tree나 연결 목록에서 mount를 순회하고 소속, 개수, root의 일관성을 확인한다.
        expected = (self.read("mounts.count", namespace, lambda: int(namespace.nr_mounts))
                    if namespace.has_member("nr_mounts") else None)
        expected_root = (self.read("mounts.root", namespace, lambda: int(namespace.root))
                         if namespace.has_member("root") else None)
        observed = set()
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
                    observed.add(int(mount.vol.offset))
                    yield mount
                elif valid is False:
                    self.issue("mounts.owner", mount, Incomplete("Mount belongs to another namespace"))
        elif namespace.has_member("list"):
            typename = "mount" if self.kernel.has_type("mount") else "vfsmount"
            for mount in self.walk(namespace.list, typename, "mnt_list"):
                if mount.has_member("mnt_ns") and int(mount.mnt_ns) != int(namespace.vol.offset):
                    self.issue("mounts.owner", mount, Incomplete("Mount belongs to another namespace"))
                    continue
                observed.add(int(mount.vol.offset))
                yield mount
        else:
            raise Unsupported("Mount namespace has neither supported RB tree nor list")
        # A NULL/truncated tree can terminate normally despite missing mounts.
        # Cross-check available namespace metadata before declaring completion.
        if expected is not None and expected != len(observed):
            self.issue("mounts.count", namespace, Incomplete(
                f"Namespace declares {expected} mounts, observed {len(observed)}"))
        if expected_root is not None:
            if expected_root and expected_root not in observed:
                self.issue("mounts.root", namespace, Incomplete(
                    "Namespace root mount is absent from the traversal"))
            elif not expected_root and observed:
                self.issue("mounts.root", namespace, Incomplete(
                    "Namespace has mounts but a NULL root mount"))

    def collect_mounts(self):
        # 확보한 mount namespace를 순회하여 Overlay 계열 파일시스템의 관측값을 수집한다.
        if not self.mount_namespaces:
            raise Incomplete("No reachable mount namespace")
        for ns in self.mount_namespaces.values():
            def scan():
                # 현재 namespace의 mount별 파일시스템 유형을 읽고 Overlay 조건에 일치하는 근거를 저장한다.
                for mount in self.mount_points(ns["object"]):
                    def fs_type():
                        # mount의 superblock에서 파일시스템 이름을 읽고 FUSE이면 subtype을 조합한다.
                        vf = mount.mnt if mount.has_member("mnt") else mount
                        sb = vf.mnt_sb
                        name = self.string(sb.s_type.name, 256)
                        if name in ("fuse", "fuseblk"):
                            # /proc/mounts joins s_type->name and s_subtype;
                            # the kernel type name itself is only "fuse".
                            def subtype():
                                # FUSE subtype을 읽으며, 멤버가 없으면 오류를 발생시키고 NULL이면 빈 문자열을 반환한다.
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
        # 전역 목록, init_net, task에서 확보한 net namespace의 장치를 조사해 이름과 link kind 관측값을 수집한다.
        if self.kernel.has_symbol("init_net"):
            self.read("network.init_net", "init_net", lambda: self.namespace(self.symbol("init_net", "net"), "net"))

        def global_namespaces():
            # net_namespace_list를 순회하여 발견한 네트워크 namespace를 등록한다.
            head = self.symbol("net_namespace_list", "list_head")
            for ns in self.walk(head, "net", "list"):
                self.namespace(ns, "net")
        self.read("network.namespace_list", "net_namespace_list", global_namespaces)
        if not self.net_namespaces:
            raise Incomplete("No reachable network namespace")
        for ns in self.net_namespaces.values():
            def devices():
                # 현재 net namespace의 장치 이름과 종류를 각각 읽고 일치하는 검사 항목의 근거를 저장한다.
                for dev in self.walk(ns["object"].dev_base_head, "net_device", "dev_list"):
                    name = self.read("network.name", dev, lambda: self.array_string(dev.name))

                    def kind():
                        # 장치의 rtnl_link_ops에서 link kind를 읽고 포인터가 NULL이면 빈 문자열을 반환한다.
                        if not dev.has_member("rtnl_link_ops"):
                            raise Unsupported("net_device.rtnl_link_ops is not described")
                        return self.string(dev.rtnl_link_ops.kind, 256) if dev.rtnl_link_ops else ""

                    link_kind = self.read("network.kind", dev, kind)
                    for check in network_checks(name, link_kind):
                        self.evidence(check, dev, {"namespace_inode": ns["inode"], "name": name, "kind": link_kind})
            self.read("network.devices", ns["object"], devices)

    def collect(self):
        # 수집 단계를 차례로 실행해 진행률, 오류 수와 완전성을 기록하고 항목별 결과를 정리한다.
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
    # 관측 근거를 여덟 칼럼의 표로 변환하고 검사 항목의 첫 행과 추가 관측값의 하위 행을 구성한다.
    """Render each observation in columns under its check's count and status."""
    columns = [("Check", str), ("Status", str), ("Coverage", str),
               ("Count", int), ("PID", int), ("Name", str),
               ("Kind", str), ("Namespace", str)]
    rows = []

    def value(detail, *keys, as_text=False):
        # 관측 필드의 표시 값을 선택하고 미적용 필드와 읽지 못한 값을 구분하며 필요하면 문자열로 변환한다.
        for key in keys:
            if key in detail:
                observed = detail[key]
                if observed is None:
                    return renderers.NotAvailableValue()
                return str(observed) if as_text else observed
        return renderers.NotApplicableValue()

    for check in report["checks"]:
        samples = [report["evidence"][index]["detail"] for index in check["evidence_indices"]]
        # A check with no observations still needs a status/coverage row.
        for index, detail in enumerate(samples or [{}]):
            header = ((check["check"], check["status"], check["coverage"], check["count"])
                      if index == 0 else ("", "", "", renderers.NotApplicableValue()))
            observation = (value(detail, "pid"), value(detail, "name", "comm"),
                           value(detail, "kind", "fstype"),
                           value(detail, "namespace_inode", "runtime_namespace", as_text=True))
            rows.append((0 if index == 0 else 1, header + observation))
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
        # Linux 커널 모듈, 지원 아키텍처와 순회 한도 등 플러그인 실행에 필요한 설정을 선언한다.
        return [
            requirements.ModuleRequirement(name="kernel", description="Linux kernel with matching ISF",
                                           architectures=["Intel32", "Intel64"]),
            requirements.IntRequirement(name="limit", description="Maximum nodes per traversal (1..1000000)",
                                        optional=True, default=100000),
        ]

    def run(self):
        # 순회 한도를 확인한 뒤 관측값을 수집하고 JSON 근거 파일과 TreeGrid 출력 표를 생성한다.
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
        return renderers.TreeGrid(columns, iter(rows))

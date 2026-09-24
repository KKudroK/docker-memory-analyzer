# SPDX-License-Identifier: MIT
"""컨테이너 태스크·스레드 상세와 shim 계보·소속 교차 검증을 하나로 통합한 단일 플러그인.

이 파일 하나만 추가하면 동작한다. 저장소의 다른 파일은 수정하지 않으며,
linux.docker.Docker 디스패처에도 편입하지 않는다. 무거운 판독기는 새로 만들지
않고 저장소의 공유 패키지(linux/_artifacts)의 검증된 판독기를 그대로 재사용한다.

실행:
    vol -p ./plugins -s ./symbols -f memory.lime linux.container_tasks.ContainerTasks

통합한 두 기능:

- (구 9번) 컨테이너 내부 프로세스·스레드 상세
  컨테이너 ID 필터, Host PID, NS PID, 부모 PID, 명령행, 시작 시각, Effective UID,
  capability, cgroup 경로. 소속 PID/TID 연결과 스레드 상세 조회를 제공한다.

- (구 10번) 전체 shim 계보·소속 교차 검증
  태스크의 조상 체인을 real_parent로 추적해 shim 후손을 연결하고, shim ID,
  runtime namespace, cgroup ID를 비교하여 소속 근거와 충돌을 기록한다.

태스크·shim 수집 결과는 두 기능이 공유한다(1차 순회에서 한 번만 수집).

옵션:
    --container 접두사: 특정 컨테이너만 표시한다. 6에서 64자리 16진수 고유
    접두사 하나를 받는다.
    --triage: 소속 근거의 불일치가 기록된 태스크만 한 행씩 표시한다.
    cgroup ID와 shim ID를 나란히 비교하고 계보는 audit JSON에 보존한다.
    옵션이 없으면 핵심 요약 표, --details는 기존 상세 표를 보여준다.
    전체 수집 근거는 화면과 무관하게 언제나 containertasks-audit.json에 남긴다.
    표는 표시용이며, 소속 불일치가 곧 악성 행위를 뜻하지는 않는다.

지원 정책은 저장소의 다른 분석과 같다. 커널 버전 번호가 아니라 심볼 구조로
판독기를 선택하며, 미지원 구조는 임의로 채우지 않고 명시적으로 남긴다.
"""
import datetime
import json
import logging
import re

from volatility3.framework import constants, exceptions, interfaces, objects, renderers
from volatility3.framework.configuration import requirements
from volatility3.framework.objects import utility
from volatility3.plugins.linux import pslist

# 저장소 공유 패키지(linux/_artifacts)의 검증된 판독기 재사용. 이 파일은 이들을
# 호출만 하며 수정하지 않는다.
from volatility3.plugins.linux._artifacts.core import CollectionSession, Unsupported
from volatility3.plugins.linux._artifacts.cgroups import membership_resolver
from volatility3.plugins.linux._artifacts.credentials import SecurityReader, CAP_FIELDS
from volatility3.plugins.linux._artifacts.namespaces import read_pid_chain, inspect_pid_layout
from volatility3.plugins.linux._artifacts.tasks import read_argv, INVENTORY_ARGV


LOG = logging.getLogger(__name__)
VERSION_INFO = (1, 4, 1)
VERSION = ".".join(map(str, VERSION_INFO))
UTC = datetime.timezone.utc

ANCESTRY_LIMIT = 512
SHIM_PREFIX = "containerd-shim"
CID = re.compile(r"[0-9a-f]{64}\Z")
SCOPE = re.compile(r"docker-([0-9a-fA-F]{64})\.scope\Z")
FULL_ID = re.compile(r"[0-9a-fA-F]{64}\Z")
HEX64 = re.compile(r"[0-9a-fA-F]{64}")
SHORT_ID_LEN = 12
CMDLINE_MAX = 48


def read_error_text(feature, task_address, exc):
    """Keep the failed layer and address even when the exception message is empty."""
    reason = f"{feature} task={task_address:#x}: {type(exc).__name__}: {exc}"
    if isinstance(exc, exceptions.InvalidAddressException):
        reason += f" layer_name={exc.layer_name} invalid_address={exc.invalid_address:#x}"
    return reason


def short_id(value):
    """64자리 컨테이너 ID를 표시용으로 앞 12자리만 남긴다.

    로직: 64자리 16진수면 앞 12자리로 줄이고, 아니면 원래 값을 그대로 둔다.
    필터와 audit JSON은 전체 ID를 쓰므로 표시에만 영향을 준다.
    """
    if isinstance(value, str) and FULL_ID.fullmatch(value):
        return value[:SHORT_ID_LEN]
    return value


def abbrev_path(value):
    """경로 문자열 안의 64자리 해시를 앞 12자리로 축약한다.

    로직: cgroup 경로 등에 박힌 64자리 컨테이너 ID를 짧게 줄여 한 줄에 들어오게 한다.
    """
    if isinstance(value, str):
        return HEX64.sub(lambda m: m.group(0)[:SHORT_ID_LEN], value)
    return value


def truncate(value, limit=CMDLINE_MAX):
    """긴 문자열을 표시용으로 자르고 끝에 생략 표시를 붙인다."""
    if isinstance(value, str) and len(value) > limit:
        return value[:limit] + "…"
    return value


def utc(seconds, nanoseconds=0):
    """부팅 기준 초·나노초를 UTC datetime으로 바꾼다.

    로직: epoch 기준 초를 UTC로 변환한 뒤 나노초를 마이크로초로 더한다.
    """
    return datetime.datetime.fromtimestamp(seconds, UTC) + datetime.timedelta(
        microseconds=nanoseconds // 1000)


def identify_docker(chain):
    """루트→말단 cgroup 체인에서 가장 가까운 Docker 표식 조상을 고른다.

    로직: docker-<id>.scope 또는 docker/<id> 형태를 찾아 가장 나중(가장 가까운)
    표식을 컨테이너 ID로 삼는다. 표식이 없으면 None을 반환한다. inspect-caps의
    동일 함수를 그대로 옮긴 것으로, 소속 판독기에 그대로 전달한다.
    """
    found = None
    for index, node in enumerate(chain):
        name = node["name"]
        match = SCOPE.fullmatch(name)
        cid = match.group(1).lower() if match else None
        if cid is None and index and chain[index - 1]["name"] == "docker" and FULL_ID.fullmatch(name):
            cid = name.lower()
        if cid is not None:
            found = {
                "id": cid, "root_address": node["address"],
                "root_path": "/" + "/".join(x["name"] for x in chain[:index + 1] if x["name"]),
            }
    return found


def shim_arguments(args):
    """shim 명령행에서 컨테이너 ID와 runtime namespace를 해석한다.

    로직: -id/-namespace 플래그의 다음 인자를 모아 개수와 ID 형식을 검사한다.
    ps.py의 동일 함수를 그대로 옮긴 것이다.
    """
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


class _Timing(CollectionSession):
    """프로세스 시작 시각 판독(구 9번의 시작 시각 항목).

    로직: 커널 timekeeper 심볼로 부팅 기준 UTC를 구하고 태스크 시작 필드를 더한다.
    ps.py의 process_start/kernel_boot_ns를 그대로 옮긴 것이며, 보고서 부작용만 뺐다.
    """

    def __init__(self, context, kernel_name):
        super().__init__(context, kernel_name)
        self.boot = None

    def process_start(self, task):
        if self.boot is None:
            self.boot = self.kernel_boot_ns()
        for field in ("start_boottime", "real_start_time", "start_time"):
            if not task.has_member(field):
                continue
            value = task.member(field)
            if value.has_member("tv_sec") and value.has_member("tv_nsec"):
                start_ns = int(value.tv_sec) * 1000000000 + int(value.tv_nsec)
            elif issubclass(type(value), objects.Integer) and value.vol.size == 8:
                start_ns = int(value)
            else:
                raise Unsupported("Unsupported process start field: " + field)
            if start_ns < 0:
                raise Unsupported("Negative process start time")
            return utc(*divmod(self.boot + start_ns, 1000000000))
        raise Unsupported("No supported process start field")

    def kernel_boot_ns(self):
        for symbol_name in ("timekeeper_data", "tk_core", "tk_core_mono", "timekeeper"):
            if not self.kernel.has_symbol(symbol_name):
                continue
            if symbol_name == "timekeeper" and self.kernel.has_type("timekeeper"):
                type_name = "timekeeper"
            elif self.kernel.has_type("tk_data") and self.kernel.get_type("tk_data").has_member("timekeeper"):
                type_name = "tk_data"
            else:
                candidates = []
                table = self.context.symbol_space[self.kernel.symbol_table_name]
                for candidate_name in table.types:
                    if candidate_name == "timekeeper":
                        continue
                    template = self.kernel.get_type(candidate_name)
                    if not template.has_member("timekeeper"):
                        continue
                    child = template.child_template("timekeeper")
                    if child.vol.type_name.split(constants.BANG)[-1] == "timekeeper":
                        candidates.append(candidate_name)
                if len(candidates) != 1:
                    raise Unsupported("No unique tk_core timekeeper layout")
                type_name = candidates[0]
            container = self.symbol(symbol_name, type_name)
            keeper = container if type_name == "timekeeper" else container.timekeeper
            if not keeper.has_member("offs_real") or not keeper.has_member("offs_boot"):
                raise Unsupported("Timekeeper has no boot offsets")

            def offset_ns(field):
                value = keeper.member(field)
                if value.has_member("tv64"):
                    value = value.tv64
                if not issubclass(type(value), objects.Integer) or value.vol.size != 8:
                    raise Unsupported("Unsupported timekeeper offset: " + field)
                return int(value)

            boot = offset_ns("offs_real") - offset_ns("offs_boot")
            if boot <= 0:
                raise Unsupported("Invalid kernel boot time")
            return boot
        raise Unsupported("No supported timekeeper symbol")


class ContainerTasks(interfaces.plugins.PluginInterface):
    """Inspect container tasks and cross-check cgroup membership against shim ancestry."""

    _required_framework_version = (2, 13, 0)
    _version = VERSION_INFO

    @classmethod
    def get_requirements(cls):
        return [
            requirements.ModuleRequirement(
                name="kernel", description="Linux x86-64 kernel with matching symbols",
                architectures=["Intel64"]),
            requirements.VersionRequirement(name="pslist", component=pslist.PsList, version=(4, 0, 0)),
            requirements.StringRequirement(
                name="container", description="Docker ID or unique hex prefix (6-64 characters)",
                optional=True),
            requirements.BooleanRequirement(
                name="details", description="Show the full task table (ignored with --triage)",
                default=False, optional=True),
            requirements.BooleanRequirement(
                name="triage",
                description="Show membership mismatches only; report Normal when none are detected",
                default=False, optional=True),
        ]

    # ---- 공유 판독기 준비 ----------------------------------------------------

    def _readers(self, module):
        """소속·보안·시작시각·PID 판독기를 구성한다.

        로직: 소속 판독기와 보안 판독기, 시작시각 판독기, PID namespace 레이아웃을
        각각 준비한다. 하나가 실패해도 나머지 계층은 독립적으로 사용한다.
        """
        readers = {"layout": {}}
        try:
            readers["resolver"] = membership_resolver(module, identify_docker)
            readers["layout"]["membership"] = readers["resolver"].compatibility
        except Exception as exc:  # noqa: BLE001 - 계층 독립 실행을 위해 광범위하게 잡는다.
            readers["resolver"] = None
            readers["layout"]["membership"] = {"feature": "container_membership",
                                               "status": "unsupported", "reason": str(exc)}
        readers["security"] = SecurityReader(self.context, module)
        try:
            readers["timing"] = _Timing(self.context, self.config["kernel"])
        except Exception as exc:  # noqa: BLE001
            readers["timing"] = None
            readers["layout"]["timing"] = {"feature": "process_timing", "status": "read_error",
                                           "reason": str(exc)}
        try:
            readers["layout"]["pid_namespace"] = inspect_pid_layout(module)
        except Exception as exc:  # noqa: BLE001
            readers["layout"]["pid_namespace"] = getattr(exc, "compatibility", {
                "feature": "pid_namespace", "status": "unsupported", "reason": str(exc)})
        return readers

    # ---- 조상 체인 추적 (구 10번) --------------------------------------------

    @staticmethod
    def _ancestors(task, limit=ANCESTRY_LIMIT):
        """real_parent 포인터를 따라 init/PID 1까지 조상 체인을 복원한다.

        로직: real_parent를 거슬러 오르며 주소·PID·명령을 기록한다. NULL·자기참조·
        순환·한도 도달·PID 1에서 멈춘다. 반환은 가까운 조상부터의 순서다.
        """
        chain, seen = [], set()
        current = task
        while True:
            address = int(current.vol.offset)
            if address in seen or len(seen) >= limit:
                break
            seen.add(address)
            try:
                parent_ptr = current.real_parent
            except (exceptions.VolatilityException, AttributeError):
                break
            if not int(parent_ptr):
                break
            parent_address = int(parent_ptr)
            if parent_address == address:  # init_task는 자기 자신을 부모로 가진다.
                break
            parent = parent_ptr.dereference()
            try:
                record = {"address": hex(parent_address), "pid": int(parent.tgid),
                          "tid": int(parent.pid),
                          "comm": utility.array_to_string(parent.comm)}
            except (exceptions.VolatilityException, ValueError, AttributeError):
                chain.append({"address": hex(parent_address), "pid": None, "tid": None,
                              "comm": None, "unreadable": True})
                break
            chain.append(record)
            if record["pid"] == 1:
                break
            current = parent
        return chain

    def _cgroup_container_id(self, task, readers, *, errors):
        """태스크 cgroup의 Docker 소속 ID만 뽑는다(없으면 None).

        로직: 소속 판독기로 태스크 cgroup을 해석해 표식 ID를 반환한다. 읽기 실패는 errors에 기록하고,
        실패 또는 표식 부재 시 None을 반환한다.
        """
        if readers["resolver"] is None:
            return None
        try:
            _cset, _cgroup, _chain, group = readers["resolver"].resolve(task)
        except Exception as exc:  # noqa: BLE001
            errors.append(read_error_text("container_membership", task.vol.offset, exc))
            return None
        return group["id"] if group else None

    # ---- shim 신원 (구 10번, 1차 순회에서 공유 수집) --------------------------

    def _shim_identity(self, task, readers, address, *, errors):
        """shim 후보의 명령행에서 컨테이너 ID·runtime namespace를 해석한다.

        로직: 인자를 shim_arguments로 해석해 ID·namespace를 얻고 shim 자신의 cgroup
        ID도 함께 읽어, 소속 교차 검증의 근거로 보존한다.
        """
        try:
            argv = read_argv(self.context, task, INVENTORY_ARGV)
        except (exceptions.VolatilityException, ValueError, AttributeError, TypeError) as exc:
            reason = read_error_text("shim_argv", address, exc)
            errors.append(reason)
            return {"task": hex(address), "pid": int(task.tgid), "container_id": None,
                    "runtime_namespace": None, "argv": [], "cgroup_id": None,
                    "attributed": False, "error": reason}
        try:
            cid, namespace = shim_arguments(argv)
        except ValueError as exc:
            return {"task": hex(address), "pid": int(task.tgid), "container_id": None,
                    "runtime_namespace": None, "argv": argv, "cgroup_id": None,
                    "attributed": False, "error": str(exc)}
        return {"task": hex(address), "pid": int(task.tgid), "container_id": cid,
                "runtime_namespace": namespace, "argv": argv,
                "cgroup_id": self._cgroup_container_id(task, readers, errors=errors),
                "attributed": namespace == "moby" or cid is not None, "error": None}

    # ---- 태스크 상세 (구 9번) + 교차 검증 (구 10번) --------------------------

    def _task_detail(self, task, readers, module, shims):
        """한 태스크의 상세 값과 조상·shim 계보·소속 교차 검증 결과를 모은다.

        로직: 호스트/네임스페이스 PID, 부모 PID, 명령행, 시작 시각, EUID, capability,
        cgroup 경로를 읽고, 조상 체인에서 가까운 shim을 찾아 소속 근거를 대조한다.
        """
        address = int(task.vol.offset)
        detail = {
            "TaskAddress": hex(address), "HostPID": int(task.tgid), "HostTID": int(task.pid),
            "PPID": None, "Name": None, "Cmdline": None, "StartUTC": None,
            "NSPID": None, "NSTID": None, "PIDNS": None, "EUID": None, "UserNS": None,
            "CapabilityScope": None, "CgroupPath": None, "ContainerID": None, "ContainerRoot": None,
            "cap_effective": None, "capabilities": {}, "Status": "ok",
            "ancestry": [], "shim_lineage": None,
            "membership": {}, "conflicts": [], "observations": [],
        }

        try:
            detail["Name"] = utility.array_to_string(task.comm)
        except (exceptions.VolatilityException, ValueError, AttributeError):
            detail["Status"] = "partial"

        try:
            if int(task.real_parent):
                detail["PPID"] = int(task.real_parent.dereference().tgid)
        except (exceptions.VolatilityException, ValueError, AttributeError):
            detail["Status"] = "partial"

        # 명령행·시작 시각 (구 9번)
        try:
            detail["Cmdline"] = " ".join(read_argv(self.context, task, INVENTORY_ARGV))
        except (exceptions.VolatilityException, ValueError, AttributeError, TypeError):
            detail["Status"] = "partial"
        if readers["timing"] is not None:
            try:
                detail["StartUTC"] = readers["timing"].process_start(task).isoformat()
            except (exceptions.VolatilityException, ValueError, AttributeError, TypeError):
                detail["Status"] = "partial"

        # PID namespace 계층 (구 9번, 소속 PID/TID 연결)
        try:
            chain = read_pid_chain(task, module)
            leader_chain = read_pid_chain(task.group_leader.dereference(), module)
            detail["PIDNS"] = chain[-1]["namespace"]
            detail["NSTID"] = chain[-1]["id"]
            detail["NSPID"] = next(x["id"] for x in leader_chain if x["namespace"] == detail["PIDNS"])
        except Exception as exc:  # noqa: BLE001
            detail["Status"] = "partial"
            detail["observations"].append({"feature": "pid_namespace", "status": "read_error",
                                           "reason": str(exc)})

        # EUID·capability·user namespace (구 9번)
        security = readers["security"]
        try:
            if int(task.cred):
                cred = task.cred.dereference()
                credentials = security.credentials(cred)
                try:
                    security.enrich_identity(credentials, cred)
                except Exception:  # noqa: BLE001 - 보강 실패가 capability 판독을 버리지 않는다.
                    pass
                detail["EUID"] = credentials.get("ids_kernel", {}).get("euid")
                detail["capabilities"] = credentials.get("capabilities", {})
                detail["cap_effective"] = detail["capabilities"].get("cap_effective")
                scope = credentials.get("user_namespace") or {}
                detail["CapabilityScope"] = scope.get("scope", "unknown")
                ns_chain = scope.get("chain_leaf_to_initial") or []
                if ns_chain:
                    detail["UserNS"] = ns_chain[0].get("inum")
                if any(item.get("status") != "ok" for item in credentials.get("observations", [])):
                    detail["Status"] = "partial"
        except Exception as exc:  # noqa: BLE001
            detail["Status"] = "partial"
            detail["observations"].append({"feature": "credentials", "status": "read_error",
                                           "reason": str(exc)})

        # cgroup 경로·소속 ID (구 9번 경로 + 구 10번 cgroup 근거)
        cgroup_cid = None
        if readers["resolver"] is not None:
            try:
                _cset, _cgroup, cchain, group = readers["resolver"].resolve(task)
                detail["CgroupPath"] = ("/" + "/".join(x["name"] for x in cchain if x["name"])) if cchain else None
                if group:
                    cgroup_cid = group["id"]
                    detail["ContainerID"] = group["id"]
                    detail["ContainerRoot"] = group["root_address"]
            except Exception as exc:  # noqa: BLE001
                detail["Status"] = "partial"
                detail["observations"].append({"feature": "container_membership",
                                               "status": "read_error", "reason": str(exc)})

        # 조상 체인·shim 계보 (구 10번)
        ancestry = self._ancestors(task)
        detail["ancestry"] = ancestry
        shim_lineage = None
        for depth, node in enumerate(ancestry):
            shim = shims.get(node["address"])
            if shim is not None:
                shim_lineage = {"shim_task": shim["task"], "shim_pid": shim["pid"],
                                "depth": depth + 1, "container_id": shim["container_id"],
                                "runtime_namespace": shim["runtime_namespace"],
                                "shim_cgroup_id": shim["cgroup_id"],
                                "attributed": shim["attributed"]}
                break
        detail["shim_lineage"] = shim_lineage

        detail["membership"], detail["conflicts"] = self._cross_verify(cgroup_cid, shim_lineage)
        if detail["ContainerID"] is None and shim_lineage and shim_lineage["container_id"]:
            detail["ContainerID"] = shim_lineage["container_id"]
        return detail

    @staticmethod
    def _cross_verify(cgroup_cid, shim_lineage):
        """독립 소속 근거를 대조해 근거 종류·상태·충돌 목록을 만든다(구 10번).

        로직: cgroup ID와 shim 계보 ID의 존재·일치, runtime namespace가 moby인지,
        shim 인자 ID와 shim 자신의 cgroup ID가 맞는지 비교한다. 상태는
        confirmed_agree, single_source, conflict, unresolved로 나눈다.
        """
        shim_cid = shim_lineage["container_id"] if shim_lineage else None
        runtime_ns = shim_lineage["runtime_namespace"] if shim_lineage else None
        shim_cgroup_cid = shim_lineage["shim_cgroup_id"] if shim_lineage else None
        sources = {}
        if cgroup_cid is not None:
            sources["cgroup"] = cgroup_cid
        if shim_cid is not None:
            sources["shim_lineage"] = shim_cid
        conflicts = []

        if cgroup_cid and shim_cid and cgroup_cid != shim_cid:
            conflicts.append({"kind": "CGROUP_SHIM_ID_MISMATCH",
                              "reason": "cgroup container ID and shim-lineage container ID disagree",
                              "cgroup_id": cgroup_cid, "shim_lineage_id": shim_cid})
        if shim_lineage and runtime_ns is not None and runtime_ns != "moby":
            conflicts.append({"kind": "NON_MOBY_RUNTIME_NAMESPACE",
                              "reason": "shim runtime namespace is not the Docker 'moby' namespace",
                              "runtime_namespace": runtime_ns})
        if shim_cid and shim_cgroup_cid and shim_cid != shim_cgroup_cid:
            conflicts.append({"kind": "SHIM_ID_CGROUP_MISMATCH",
                              "reason": "shim argument ID and the shim's own cgroup ID disagree",
                              "shim_id": shim_cid, "shim_cgroup_id": shim_cgroup_cid})

        if not sources:
            status = "unresolved"
        elif conflicts:
            status = "conflict"
        elif len(sources) >= 2:
            status = "confirmed_agree"
        else:
            status = "single_source"

        return {"status": status, "sources": sources, "runtime_namespace": runtime_ns,
                "basis": ContainerTasks._basis_text(status, sources)}, conflicts

    @staticmethod
    def _basis_text(status, sources):
        """근거 상태를 표에 넣을 짧은 문자열로 만든다.

        로직: 상태와 관측 근거 집합을 사람이 읽기 쉬운 한 단어 형태로 요약한다.
        """
        if status == "confirmed_agree":
            return "cgroup+shim(agree)"
        if status == "conflict":
            return "conflict"
        if status == "single_source":
            return next(iter(sources)) + "-only"
        return "unresolved"

    # ---- 실행 ----------------------------------------------------------------

    def run(self):
        module = self.context.modules[self.config["kernel"]]
        readers = self._readers(module)

        prefix = (self.config.get("container") or "").lower()
        if prefix and not re.fullmatch(r"[0-9a-fA-F]{6,64}", prefix):
            raise ValueError("Container prefix must be 6-64 hexadecimal characters")
        triage = self.config.get("triage", False)
        # 모든 태스크를 수집하고 표시 방식만 바꾼다. triage는 검토 대상과 관계를 표시한다.
        conflicts_only = triage
        include_threads = True

        audit = {
            "created_utc": datetime.datetime.now(UTC).isoformat(),
            "plugin_version": VERSION,
            "method": "Merged task/thread detail (former #9) with shim-lineage cross-verification (former #10)",
            "scope": "Container-candidate tasks: Docker-marked cgroup membership or a shim ancestor. "
                     "Full evidence retained here regardless of the display filter.",
            "include_threads": include_threads,
            "display_filter": "mismatches_only" if triage else "all_container_candidates",
            "display_view": "triage" if triage else "details" if self.config.get("details", False) else "summary",
            "selected_prefix": prefix,
            "compatibility": readers["layout"],
            "limitations": [
                "A shim-lineage or cgroup marker does not by itself establish container lifecycle state.",
                "A membership conflict flags a task for review; it is not proof of malicious activity.",
                "Ancestor tracing follows real_parent; a broken or reparented chain is left partial.",
                "Threads are enumerated by the official API; hidden/unlinked tasks are not recovered.",
            ],
            "shims": [], "tasks": [], "containers": [],
            "enumerated_tasks": 0, "candidate_tasks": 0, "conflict_tasks": 0,
            "traversal_errors": [],
        }

        # 1차 순회: 전체 태스크 열거 + shim 등록(태스크·shim 수집 결과 공유)
        tasks, shims, seen = [], {}, set()
        try:
            for task in pslist.PsList.list_tasks(
                    self.context, self.config["kernel"], include_threads=include_threads):
                address = int(task.vol.offset)
                if address in seen:
                    continue
                seen.add(address)
                tasks.append(task)
                try:
                    comm = utility.array_to_string(task.comm)
                except (exceptions.VolatilityException, ValueError, AttributeError):
                    comm = ""
                if comm.startswith(SHIM_PREFIX):
                    record = self._shim_identity(task, readers, address, errors=audit["traversal_errors"])
                    shims[hex(address)] = record
                    audit["shims"].append(record)
        except Exception as exc:  # noqa: BLE001
            audit["traversal_errors"].append(str(exc))
        audit["enumerated_tasks"] = len(seen)

        # 2차 순회: 컨테이너 후보(태스크의 cgroup Docker 소속 또는 shim 조상)만 상세 수집
        for task in tasks:
            has_shim_ancestor = any(node["address"] in shims for node in self._ancestors(task))
            cgroup_cid = self._cgroup_container_id(task, readers, errors=audit["traversal_errors"])
            if cgroup_cid is None and not has_shim_ancestor:
                continue  # 호스트 태스크: 컨테이너 후보가 아니다.
            audit["tasks"].append(self._task_detail(task, readers, module, shims))
        audit["candidate_tasks"] = len(audit["tasks"])
        audit["conflict_tasks"] = sum(
            1 for t in audit["tasks"] if t["membership"]["status"] in ("conflict", "unresolved"))

        # 접두사 고유성 검증
        observed_ids = {t["ContainerID"] for t in audit["tasks"] if t["ContainerID"]}
        if prefix and len({cid for cid in observed_ids if cid.startswith(prefix)}) > 1:
            raise ValueError("Container prefix is ambiguous; supply more characters")

        # 컨테이너 단위 요약
        containers = {}
        for detail in audit["tasks"]:
            cid = detail["ContainerID"]
            if cid is None:
                continue
            entry = containers.setdefault(cid, {"container_id": cid, "task_count": 0,
                                                "conflict_count": 0, "roots": set(),
                                                "runtime_namespaces": set()})
            entry["task_count"] += 1
            if detail["membership"]["status"] in ("conflict", "unresolved"):
                entry["conflict_count"] += 1
            if detail["ContainerRoot"]:
                entry["roots"].add(detail["ContainerRoot"])
            rns = detail["membership"].get("runtime_namespace")
            if rns:
                entry["runtime_namespaces"].add(rns)
        audit["containers"] = [
            {**e, "roots": sorted(e["roots"]), "runtime_namespaces": sorted(e["runtime_namespaces"])}
            for e in sorted(containers.values(), key=lambda x: x["container_id"])]

        # 표시 대상 선택
        displayed = audit["tasks"]
        if prefix:
            displayed = [t for t in displayed if t["ContainerID"] and t["ContainerID"].startswith(prefix)]
        audit["selected_tasks"] = len(displayed)
        if conflicts_only:
            displayed = [t for t in displayed if self._is_mismatch(t)]
        displayed = sorted(displayed, key=lambda t: (t["ContainerID"] or "", t["HostPID"], t["HostTID"]))
        audit["displayed_tasks"] = len(displayed)

        # 근거 JSON 저장. self.open은 Volatility 출력 디렉터리(-o)를 따른다.
        with self.open("containertasks-audit.json") as handle:
            handle.write(json.dumps(audit, ensure_ascii=False, indent=2, default=str).encode("utf-8"))
        if audit["traversal_errors"]:
            LOG.warning("ContainerTasks: task collection incomplete; see containertasks-audit.json")
        if triage and displayed:
            LOG.warning("ContainerTasks: membership mismatches=%d; see containertasks-audit.json", len(displayed))

        if triage:
            return self._triage_grid(audit, displayed)
        if self.config.get("details", False) and displayed:
            return self._raw_grid(displayed)
        return self._summary_grid(audit, displayed)

    # ---- 출력 ----------------------------------------------------------------

    @staticmethod
    def _cell(value):
        """표 셀 값을 정리한다(제어문자 제거, 미확인 값은 N/A).

        로직: None은 Volatility 미확인 값으로, 문자열은 제어문자를 공백으로 바꿔
        반환한다. 정수·불리언은 그대로 둔다.
        """
        if value is None:
            return renderers.NotAvailableValue()
        if isinstance(value, str):
            return "".join(ch if ch.isprintable() else " " for ch in value)
        return value

    def _raw_grid(self, displayed):
        """태스크별 상세 raw 표(구 9번 항목 + 구 10번 근거)."""
        columns = [
            ("ContainerID", str), ("CgroupPath", str), ("HostPID", int), ("HostTID", int),
            ("PPID", int), ("Name", str), ("NSPID", int), ("NSTID", int), ("PIDNS", int),
            ("EUID", int), ("UserNS", int), ("StartUTC", str), ("Cmdline", str),
            ("ShimPID", int), ("ShimID", str), ("RuntimeNS", str),
            ("Basis", str), ("Conflict", str), ("Effective", str), ("Status", str)]

        def rows():
            for t in displayed:
                shim = t["shim_lineage"] or {}
                values = {
                    "ContainerID": short_id(t["ContainerID"]), "CgroupPath": abbrev_path(t["CgroupPath"]),
                    "HostPID": t["HostPID"], "HostTID": t["HostTID"], "PPID": t["PPID"],
                    "Name": t["Name"], "NSPID": t["NSPID"], "NSTID": t["NSTID"],
                    "PIDNS": t["PIDNS"], "EUID": t["EUID"], "UserNS": t["UserNS"],
                    "StartUTC": t["StartUTC"], "Cmdline": truncate(t["Cmdline"]),
                    "ShimPID": shim.get("shim_pid"), "ShimID": short_id(shim.get("container_id")),
                    "RuntimeNS": t["membership"].get("runtime_namespace"),
                    "Basis": t["membership"]["basis"],
                    "Conflict": "; ".join(c["kind"] for c in t["conflicts"]) or "-",
                    "Effective": t["cap_effective"], "Status": t["Status"]}
                yield 0, tuple(self._cell(values[name]) for name, _kind in columns)

        return renderers.TreeGrid(columns, rows())

    @staticmethod
    def _membership_label(detail):
        return {
            "confirmed_agree": "Sources agree",
            "single_source": "Single source",
            "conflict": "Review: mismatch",
            "unresolved": "Review: unknown",
        }[detail["membership"]["status"]]

    @staticmethod
    def _review_reason(detail):
        reasons = [c["reason"] for c in detail["conflicts"]]
        if detail["membership"]["status"] == "unresolved":
            reasons.append("No usable container ID from cgroup or shim")
        if not reasons:
            sources = detail["membership"]["sources"]
            reasons.append("Cgroup and shim IDs agree" if len(sources) == 2 else
                           "Only {} evidence available".format(" and ".join(sources)))
        if detail["Status"] != "ok":
            reasons.append("Some task fields could not be read; see audit JSON")
        return "; ".join(reasons)

    @staticmethod
    def _empty_message(audit):
        prefix = audit["selected_prefix"]
        if not audit["candidate_tasks"]:
            message = "No container-candidate tasks recovered"
        elif prefix and not any(t["ContainerID"] and t["ContainerID"].startswith(prefix)
                                for t in audit["tasks"]):
            message = "No container matches prefix {}".format(prefix)
        else:
            message = "No conflicting or unresolved membership in the selected tasks"
        return message + ". This does not prove complete recovery or safety; see containertasks-audit.json."

    def _summary_grid(self, audit, displayed):
        """Compact, flat task view; full evidence remains in the audit file."""
        columns = [("Container", str), ("Host PID", int), ("Host TID", int),
                   ("Name", str), ("Membership", str), ("Evidence / next step", str)]

        def rows():
            if not displayed:
                yield 0, tuple(self._cell(v) for v in
                               (None, None, None, None, "No results", self._empty_message(audit)))
            for task in displayed:
                yield 0, tuple(self._cell(v) for v in (
                    short_id(task["ContainerID"]), task["HostPID"], task["HostTID"],
                    task["Name"], self._membership_label(task), self._review_reason(task)))
        return renderers.TreeGrid(columns, rows())

    @staticmethod
    def _is_mismatch(task):
        # A recorded runtime conflict can coexist with an unresolved ID status.
        return bool(task["conflicts"])

    def _triage_empty_result(self, audit):
        selected = audit["tasks"]
        prefix = audit.get("selected_prefix", "")
        if prefix:
            selected = [t for t in selected if t["ContainerID"] and t["ContainerID"].startswith(prefix)]
        if audit.get("traversal_errors"):
            return "Incomplete", "No membership mismatches detected; task collection was incomplete. See audit JSON."
        if not selected:
            return "No results", self._empty_message(audit)
        reason = "Normal: no membership mismatches detected in the selected tasks."
        limited = sum(t["membership"]["status"] != "confirmed_agree" or t["Status"] != "ok"
                      for t in selected)
        if limited:
            reason += " {} task(s) have limited evidence; this is not confirmation of their membership. See audit JSON.".format(limited)
        return "Normal", reason

    def _triage_grid(self, audit, displayed):
        """One row per mismatch; missing evidence alone is not a mismatch."""
        columns = [("PID / TID", str), ("Name", str), ("Cgroup ID", str),
                   ("Shim PID", int), ("Shim ID", str), ("Runtime NS", str),
                   ("Shim Cgroup ID", str), ("Result", str), ("Reason", str)]
        mismatches = [task for task in displayed if self._is_mismatch(task)]

        def rows():
            if not mismatches:
                result, reason = self._triage_empty_result(audit)
                yield 0, tuple(self._cell(v) for v in
                               (None, None, None, None, None, None, None, result, reason))
            for task in mismatches:
                lineage = task["shim_lineage"] or {}
                # Do not substitute a fallback shim ID for missing cgroup evidence.
                cgroup_id = task["membership"]["sources"].get("cgroup")
                yield 0, tuple(self._cell(v) for v in (
                    "{} / {}".format(task["HostPID"], task["HostTID"]), task["Name"],
                    short_id(cgroup_id), lineage.get("shim_pid"),
                    short_id(lineage.get("container_id")), lineage.get("runtime_namespace"),
                    short_id(lineage.get("shim_cgroup_id")), "Mismatch", self._review_reason(task)))
        return renderers.TreeGrid(columns, rows())

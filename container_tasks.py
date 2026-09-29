"""Analyze container processes, threads, and Docker membership evidence.
The --container-tasks option reports host/namespace PIDs, credentials, and cgroups.
It compares cgroup attribution with runtime shim ancestry and preserves conflicts.
Summary, detail, triage, and audit views use the same collected task evidence.

SPDX-License-Identifier: MIT
"""

import datetime
import json
import logging
import re

from volatility3.framework import exceptions, interfaces, renderers
from volatility3.framework.configuration import requirements
from volatility3.framework.objects import utility
from volatility3.plugins.linux import docker_artifacts, pslist
from volatility3.plugins.linux._artifacts import cgroups as cgroup_readers


from volatility3.plugins.linux._artifacts import core as artifact_core
from volatility3.plugins.linux._artifacts import credentials as credential_readers
from volatility3.plugins.linux._artifacts import tasks as task_readers
from volatility3.plugins.linux._artifacts import timing as timing_readers

LOG = logging.getLogger(__name__)

VERSION_INFO = (2, 1, 1)
VERSION = ".".join(map(str, VERSION_INFO))
UTC = datetime.timezone.utc

ANCESTRY_LIMIT = 512
SHIM_PREFIX = "containerd-shim"
SCOPE = re.compile(r"docker-([0-9a-fA-F]{64})\.scope\Z")
FULL_ID = re.compile(r"[0-9a-fA-F]{64}\Z")
HEX64 = re.compile(r"[0-9a-fA-F]{64}")
SHORT_ID_LEN = 12
CMDLINE_MAX = 48


def read_error_text(feature, task_address, exc):
    """Preserve read diagnostics; use None when no failing task is known."""
    location = feature
    if task_address is not None:
        location += f" task={task_address:#x}"
    return f"{location}: {artifact_core.exception_text(exc)}"


def short_id(value):
    """Shorten a 64-character container ID to twelve characters for display.

    Non-container values remain unchanged. Filtering and audit JSON retain the
    complete ID, so this transformation affects presentation only.
    """
    if isinstance(value, str) and FULL_ID.fullmatch(value):
        return value[:SHORT_ID_LEN]
    return value


def abbrev_path(value):
    """Abbreviate 64-character hashes embedded in paths to twelve characters.

    This keeps cgroup and related paths readable in single-line output.
    """
    if isinstance(value, str):
        return HEX64.sub(lambda m: m.group(0)[:SHORT_ID_LEN], value)
    return value


def truncate(value, limit=CMDLINE_MAX):
    """Truncate long display strings and append an ellipsis."""
    if isinstance(value, str) and len(value) > limit:
        return value[:limit] + "…"
    return value


def utc(seconds, nanoseconds=0):
    """Convert epoch seconds and nanoseconds into a UTC datetime.

    Convert seconds first, then add nanoseconds at microsecond precision.
    """
    return datetime.datetime.fromtimestamp(seconds, UTC) + datetime.timedelta(
        microseconds=nanoseconds // 1000
    )


def identify_docker(chain):
    """Select the nearest Docker marker in a root-to-leaf cgroup chain.

    Recognize docker-<id>.scope and docker/<id>, keeping the deepest match as
    the container ID. Return None when no supported marker is present.
    """
    found = None
    for index, node in enumerate(chain):
        name = node["name"]
        match = SCOPE.fullmatch(name)
        cid = match.group(1).lower() if match else None
        if (
            cid is None
            and index
            and chain[index - 1]["name"] == "docker"
            and FULL_ID.fullmatch(name)
        ):
            cid = name.lower()
        if cid is not None:
            found = {
                "id": cid,
                "root_address": node["address"],
                "root_path": "/"
                + "/".join(x["name"] for x in chain[: index + 1] if x["name"]),
            }
    return found


class _Timing(artifact_core.CollectionSession):
    """Adapt shared timing-reader results to this analysis's UTC datetime format."""

    def __init__(self, context, kernel_name):
        super().__init__(context, kernel_name)
        self.boot = None

    def process_start(self, task):
        if self.boot is None:
            self.boot = self.kernel_boot_ns()
        return utc(
            *divmod(timing_readers.read_process_start_ns(task, self.boot), 1000000000)
        )

    def kernel_boot_ns(self):
        return timing_readers.read_kernel_boot(self).nanoseconds


class ContainerTasks(interfaces.plugins.PluginInterface):
    """Inspect container tasks and cross-check cgroup membership against shim ancestry."""

    hidden = True
    _required_framework_version = (2, 13, 0)
    _version = VERSION_INFO

    @classmethod
    def get_requirements(cls):
        return [
            requirements.VersionRequirement(
                name="docker_artifacts",
                component=docker_artifacts.DockerArtifacts,
                version=(1, 3, 0),
            ),
            requirements.ModuleRequirement(
                name="kernel",
                description="Linux x86-64 kernel with matching symbols",
                architectures=["Intel64"],
            ),
            requirements.VersionRequirement(
                name="pslist", component=pslist.PsList, version=(4, 0, 0)
            ),
            requirements.StringRequirement(
                name="container",
                description="Docker ID or unique hex prefix (6-64 characters)",
                optional=True,
            ),
            requirements.BooleanRequirement(
                name="details",
                description="Show the full task table (ignored with --triage)",
                default=False,
                optional=True,
            ),
            requirements.BooleanRequirement(
                name="triage",
                description="Show membership mismatches only; report Normal when none are detected",
                default=False,
                optional=True,
            ),
        ]



    def _readers(self, module):
        """Construct membership, security, timing, and PID namespace readers.

        Initialize each reader independently so one unsupported layer does not
        prevent the remaining evidence sources from being used.
        """
        readers = {"layout": {}}
        try:
            readers["resolver"] = cgroup_readers.membership_resolver(
                module, identify_docker
            )
            readers["layout"]["membership"] = readers["resolver"].compatibility
        except Exception as exc:
            readers["resolver"] = None
            readers["layout"]["membership"] = {
                "feature": "container_membership",
                "status": "unsupported",
                "reason": read_error_text("container_membership.layout", None, exc),
            }
        readers["security"] = credential_readers.SecurityReader(self.context, module)
        security_observations = [
            dict(item)
            for item in readers["security"].observations
            if item.get("status") != "ok"
        ]
        if security_observations:
            readers["layout"]["security"] = security_observations
        try:
            readers["timing"] = _Timing(self.context, self.config["kernel"])
        except Exception as exc:
            readers["timing"] = None
            readers["layout"]["timing"] = {
                "feature": "process_timing",
                "status": "read_error",
                "reason": read_error_text("process_timing.layout", None, exc),
            }
        try:
            readers["layout"]["pid_namespace"] = (
                docker_artifacts.DockerArtifacts.inspect_pid_layout(
                    self.context, self.config["kernel"]
                )
            )
        except Exception as exc:
            compatibility = dict(
                getattr(
                    exc,
                    "compatibility",
                    {"feature": "pid_namespace", "status": "unsupported"},
                )
            )
            compatibility["reason"] = read_error_text("pid_namespace.layout", None, exc)
            readers["layout"]["pid_namespace"] = compatibility
        return readers



    @staticmethod
    def _ancestors(task, limit=ANCESTRY_LIMIT):
        return task_readers.ancestor_chain(task, limit=limit)

    @staticmethod
    def _ancestry_observations(task_address, ancestry):
        """Attribute traversal errors without losing the failed parent or layer."""
        observations = []
        for error in ancestry.errors:
            feature = f"ancestry.{error.operation}"
            if error.address is not None:
                feature += f" node={error.address:#x}"
            observations.append(
                {
                    "feature": "ancestry",
                    "status": "incomplete"
                    if isinstance(error.exception, artifact_core.Incomplete)
                    else "read_error",
                    "reason": read_error_text(feature, task_address, error.exception),
                }
            )
        return observations

    def _cgroup_container_id(self, task, readers, *, errors):
        """Return the Docker membership ID decoded from a task cgroup, if any.

        Record resolution failures in the audit error list so evidence lost
        before candidate selection remains visible.
        """
        if readers["resolver"] is None:
            return None
        try:
            _cset, _cgroup, _chain, group = readers["resolver"].resolve(task)
        except Exception as exc:
            errors.append(read_error_text("container_membership", task.vol.offset, exc))
            return None
        return group["id"] if group else None



    def _shim_identity(self, task, readers, address, *, errors):
        """Decode container ID and runtime namespace from a shim candidate's argv.

        Read both fields independently through the shared API, retain validation
        diagnostics, and cross-check valid IDs against the shim's own cgroup ID.
        """
        pid = None
        try:
            pid = int(task.tgid)
        except artifact_core.READ_ERRORS as exc:
            errors.append(read_error_text("shim_pid", address, exc))
        try:
            identity = docker_artifacts.DockerArtifacts.read_shim_identity(
                self.context,
                self.config["kernel"],
                int(task.vol.offset),
                policy="inventory",
                layer_name=task.vol.layer_name,
                native_layer_name=task.vol.native_layer_name,
            )
        except (
            exceptions.VolatilityException,
            ValueError,
            AttributeError,
            TypeError,
        ) as exc:


            reason = read_error_text("shim_argv", address, exc)
            errors.append(reason)
            return {
                "task": hex(address),
                "pid": pid,
                "container_id": None,
                "raw_id": None,
                "runtime_namespace": None,
                "argv": [],
                "cgroup_id": None,
                "attributed": False,
                "error": reason,
            }
        cid = identity["container_id"]
        namespace = identity["runtime_namespace"]
        return {
            "task": hex(address),
            "pid": pid,
            "container_id": cid,
            "raw_id": identity["raw_id"],
            "runtime_namespace": namespace,
            "argv": identity["argv"],
            "cgroup_id": self._cgroup_container_id(task, readers, errors=errors)
            if cid is not None
            else None,
            "attributed": cid is not None,
            "error": "; ".join(identity["errors"]) or None,
        }



    def _task_detail(self, task, readers, module, shims, *, ancestry=None):
        """Collect task details and cross-check membership against shim ancestry.

        Read host and namespace PIDs, parent, argv, timing, credentials, capabilities,
        and cgroups, then compare the nearest shim lineage with cgroup attribution.
        """
        address = int(task.vol.offset)
        detail = {
            "TaskAddress": hex(address),
            "HostPID": None,
            "HostTID": None,
            "PPID": None,
            "Name": None,
            "Cmdline": None,
            "StartUTC": None,
            "NSPID": None,
            "NSTID": None,
            "PIDNS": None,
            "EUID": None,
            "UserNS": None,
            "CapabilityScope": None,
            "CgroupPath": None,
            "ContainerID": None,
            "ContainerRoot": None,
            "cap_effective": None,
            "capabilities": {},
            "Status": "ok",
            "ancestry": [],
            "shim_lineage": None,
            "membership": {},
            "conflicts": [],
            "observations": [],
        }

        def record_error(feature, exc):
            """Keep independent fields while recording why this task is partial."""
            detail["Status"] = "partial"
            detail["observations"].append(
                {
                    "feature": feature,
                    "status": "read_error",
                    "reason": read_error_text(feature, address, exc),
                }
            )

        for field, member in (("HostPID", "tgid"), ("HostTID", "pid")):
            try:
                detail[field] = int(getattr(task, member))
            except artifact_core.READ_ERRORS as exc:
                record_error(field, exc)

        try:
            detail["Name"] = utility.array_to_string(task.comm)
        except (exceptions.VolatilityException, ValueError, AttributeError) as exc:
            record_error("task_name", exc)

        try:
            if int(task.real_parent):
                detail["PPID"] = int(task.real_parent.dereference().tgid)
        except (exceptions.VolatilityException, ValueError, AttributeError) as exc:
            record_error("parent_pid", exc)


        try:
            detail["Cmdline"] = " ".join(
                docker_artifacts.DockerArtifacts.read_task_argv(
                    self.context,
                    self.config["kernel"],
                    int(task.vol.offset),
                    policy="inventory",
                    layer_name=task.vol.layer_name,
                    native_layer_name=task.vol.native_layer_name,
                )
            )
        except (
            exceptions.VolatilityException,
            ValueError,
            AttributeError,
            TypeError,
        ) as exc:
            record_error("task_argv", exc)
        if readers["timing"] is not None:
            try:
                detail["StartUTC"] = readers["timing"].process_start(task).isoformat()
            except (
                exceptions.VolatilityException,
                ValueError,
                AttributeError,
                TypeError,
            ) as exc:
                record_error("process_start", exc)


        try:
            chain = docker_artifacts.DockerArtifacts.read_pid_chain(
                self.context,
                self.config["kernel"],
                int(task.vol.offset),
                layer_name=task.vol.layer_name,
                native_layer_name=task.vol.native_layer_name,
            )
            detail["PIDNS"] = chain[-1]["namespace"]
            detail["NSTID"] = chain[-1]["id"]
            leader_chain = docker_artifacts.DockerArtifacts.read_process_pid_chain(
                self.context,
                self.config["kernel"],
                int(task.vol.offset),
                layer_name=task.vol.layer_name,
                native_layer_name=task.vol.native_layer_name,
            )
            detail["NSPID"] = next(
                x["id"] for x in leader_chain if x["namespace"] == detail["PIDNS"]
            )
        except Exception as exc:
            record_error("pid_namespace", exc)


        security = readers["security"]
        try:
            if int(task.cred):
                cred = task.cred.dereference()
                credentials = security.credentials(cred)
                try:
                    security.enrich_identity(credentials, cred)
                except Exception as exc:
                    record_error("credentials.identity", exc)
                detail["EUID"] = credentials.get("ids_kernel", {}).get("euid")
                detail["capabilities"] = credentials.get("capabilities", {})
                detail["cap_effective"] = detail["capabilities"].get("cap_effective")
                scope = credentials.get("user_namespace") or {}
                detail["CapabilityScope"] = scope.get("scope", "unknown")
                ns_chain = scope.get("chain_leaf_to_initial") or []
                if ns_chain:
                    detail["UserNS"] = ns_chain[0].get("inum")
                for item in credentials.get("observations", []):
                    if item.get("status") == "ok":
                        continue
                    observation = dict(item, source="credentials")
                    if observation not in detail["observations"]:
                        detail["observations"].append(observation)
                    detail["Status"] = "partial"
        except Exception as exc:
            record_error("credentials", exc)


        cgroup_cid = None
        if readers["resolver"] is not None:
            try:
                _cset, _cgroup, cchain, group = readers["resolver"].resolve(task)
                detail["CgroupPath"] = (
                    ("/" + "/".join(x["name"] for x in cchain if x["name"]))
                    if cchain
                    else None
                )
                if group:
                    cgroup_cid = group["id"]
                    detail["ContainerID"] = group["id"]
                    detail["ContainerRoot"] = group["root_address"]
            except Exception as exc:
                record_error("container_membership", exc)


        if ancestry is None:
            ancestry = self._ancestors(task)
        detail["ancestry"] = ancestry.records
        if ancestry.errors:
            detail["Status"] = "partial"
            detail["observations"].extend(
                self._ancestry_observations(address, ancestry)
            )
        shim_lineage = None
        for depth, node in enumerate(ancestry.records):
            shim = shims.get(node["address"])
            if shim is not None:
                shim_lineage = {
                    "shim_task": shim["task"],
                    "shim_pid": shim["pid"],
                    "depth": depth + 1,
                    "container_id": shim["container_id"],
                    "runtime_namespace": shim["runtime_namespace"],
                    "shim_cgroup_id": shim["cgroup_id"],
                    "attributed": shim["attributed"],
                    "raw_id": shim.get("raw_id"),
                    "error": shim.get("error"),
                }
                if shim.get("error"):
                    detail["observations"].append(
                        {
                            "source": "shim_identity",
                            "status": "unresolved",
                            "shim_task": shim["task"],
                            "raw_id": shim.get("raw_id"),
                            "runtime_namespace": shim["runtime_namespace"],
                            "reason": shim["error"],
                        }
                    )
                break
        detail["shim_lineage"] = shim_lineage

        # Cgroup membership and shim ancestry are independent evidence; preserve
        # disagreements as conflicts instead of selecting one source as authoritative.
        detail["membership"], detail["conflicts"] = self._cross_verify(
            cgroup_cid, shim_lineage
        )
        if (
            detail["ContainerID"] is None
            and shim_lineage
            and shim_lineage["container_id"]
        ):
            detail["ContainerID"] = shim_lineage["container_id"]
        return detail

    @staticmethod
    def _cross_verify(cgroup_cid, shim_lineage):
        """Compare independent membership evidence and report conflicts.

        Compare cgroup and shim-lineage IDs, the moby runtime namespace, and the
        shim argv ID against its cgroup. Classify the result as confirmed_agree,
        single_source, conflict, or unresolved.
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
            conflicts.append(
                {
                    "kind": "CGROUP_SHIM_ID_MISMATCH",
                    "reason": "cgroup container ID and shim-lineage container ID disagree",
                    "cgroup_id": cgroup_cid,
                    "shim_lineage_id": shim_cid,
                }
            )
        if sources and runtime_ns is not None and runtime_ns != "moby":
            conflicts.append(
                {
                    "kind": "NON_MOBY_RUNTIME_NAMESPACE",
                    "reason": "shim runtime namespace is not the Docker 'moby' namespace",
                    "runtime_namespace": runtime_ns,
                }
            )
        if shim_cid and shim_cgroup_cid and shim_cid != shim_cgroup_cid:
            conflicts.append(
                {
                    "kind": "SHIM_ID_CGROUP_MISMATCH",
                    "reason": "shim argument ID and the shim's own cgroup ID disagree",
                    "shim_id": shim_cid,
                    "shim_cgroup_id": shim_cgroup_cid,
                }
            )

        if not sources:
            status = "unresolved"
        elif conflicts:
            status = "conflict"
        elif len(sources) >= 2:
            status = "confirmed_agree"
        else:
            status = "single_source"

        return {
            "status": status,
            "sources": sources,
            "runtime_namespace": runtime_ns,
            "basis": ContainerTasks._basis_text(status, sources),
        }, conflicts

    @staticmethod
    def _basis_text(status, sources):
        """Convert evidence status and sources into a compact table label.

        The label summarizes the source set without replacing the detailed audit data.
        """
        if status == "confirmed_agree":
            return "cgroup+shim(agree)"
        if status == "conflict":
            return "conflict"
        if status == "single_source":
            return next(iter(sources)) + "-only"
        return "unresolved"



    def run(self):
        module = self.context.modules[self.config["kernel"]]
        readers = self._readers(module)

        prefix = (self.config.get("container") or "").lower()
        if prefix and not re.fullmatch(r"[0-9a-fA-F]{6,64}", prefix):
            raise ValueError("Container prefix must be 6-64 hexadecimal characters")
        triage = self.config.get("triage", False)

        conflicts_only = triage
        include_threads = True

        audit = {
            "created_utc": datetime.datetime.now(UTC).isoformat(),
            "plugin_version": VERSION,
            "method": "Merged task/thread detail (former #9) with shim-lineage cross-verification (former #10)",
            "scope": "Container-candidate tasks: Docker-marked cgroup membership or a shim ancestor. "
            "Full evidence retained here regardless of the display filter.",
            "include_threads": include_threads,
            "display_filter": "mismatches_only"
            if triage
            else "all_container_candidates",
            "display_view": "triage"
            if triage
            else "details"
            if self.config.get("details", False)
            else "summary",
            "selected_prefix": prefix,
            "compatibility": readers["layout"],
            "limitations": [
                "A shim-lineage or cgroup marker does not by itself establish container lifecycle state.",
                "A membership conflict flags a task for review; it is not proof of malicious activity.",
                "Ancestor tracing follows real_parent; a broken or reparented chain is left partial.",
                "Threads are enumerated by the official API; hidden/unlinked tasks are not recovered.",
            ],
            "shims": [],
            "tasks": [],
            "containers": [],
            "enumerated_tasks": 0,
            "candidate_tasks": 0,
            "conflict_tasks": 0,
            "traversal_errors": [],
        }


        tasks, shims, seen = [], {}, set()
        try:
            for task in docker_artifacts.DockerArtifacts.list_tasks(
                self.context, self.config["kernel"], include_threads=include_threads
            ):
                address = int(task.vol.offset)
                if address in seen:
                    continue
                seen.add(address)
                tasks.append(task)
                try:
                    comm = utility.array_to_string(task.comm)
                except (
                    exceptions.VolatilityException,
                    ValueError,
                    AttributeError,
                ) as exc:
                    comm = ""
                    audit["traversal_errors"].append(
                        read_error_text("task_name", address, exc)
                    )
                if comm.startswith(SHIM_PREFIX):
                    record = self._shim_identity(
                        task, readers, address, errors=audit["traversal_errors"]
                    )
                    shims[hex(address)] = record
                    audit["shims"].append(record)
        except Exception as exc:
            audit["traversal_errors"].append(
                read_error_text("task_enumeration", None, exc)
            )
        audit["enumerated_tasks"] = len(seen)


        for task in tasks:
            ancestry = self._ancestors(task)
            audit["traversal_errors"].extend(
                item["reason"]
                for item in self._ancestry_observations(int(task.vol.offset), ancestry)
            )
            has_shim_ancestor = any(
                node["address"] in shims for node in ancestry.records
            )
            cgroup_cid = self._cgroup_container_id(
                task, readers, errors=audit["traversal_errors"]
            )
            if cgroup_cid is None and not has_shim_ancestor:
                continue
            audit["tasks"].append(
                self._task_detail(task, readers, module, shims, ancestry=ancestry)
            )
        audit["candidate_tasks"] = len(audit["tasks"])
        audit["conflict_tasks"] = sum(
            1
            for t in audit["tasks"]
            if t["membership"]["status"] in ("conflict", "unresolved")
        )


        observed_ids = {t["ContainerID"] for t in audit["tasks"] if t["ContainerID"]}
        if prefix and len({cid for cid in observed_ids if cid.startswith(prefix)}) > 1:
            raise ValueError("Container prefix is ambiguous; supply more characters")


        containers = {}
        for detail in audit["tasks"]:
            cid = detail["ContainerID"]
            if cid is None:
                continue
            entry = containers.setdefault(
                cid,
                {
                    "container_id": cid,
                    "task_count": 0,
                    "conflict_count": 0,
                    "roots": set(),
                    "runtime_namespaces": set(),
                },
            )
            entry["task_count"] += 1
            if detail["membership"]["status"] in ("conflict", "unresolved"):
                entry["conflict_count"] += 1
            if detail["ContainerRoot"]:
                entry["roots"].add(detail["ContainerRoot"])
            rns = detail["membership"].get("runtime_namespace")
            if rns:
                entry["runtime_namespaces"].add(rns)
        audit["containers"] = [
            {
                **e,
                "roots": sorted(e["roots"]),
                "runtime_namespaces": sorted(e["runtime_namespaces"]),
            }
            for e in sorted(containers.values(), key=lambda x: x["container_id"])
        ]


        displayed = audit["tasks"]
        if prefix:
            displayed = [
                t
                for t in displayed
                if t["ContainerID"] and t["ContainerID"].startswith(prefix)
            ]
        audit["selected_tasks"] = len(displayed)
        if conflicts_only:
            displayed = [t for t in displayed if self._is_mismatch(t)]
        displayed = sorted(
            displayed,
            key=lambda t: (
                t["ContainerID"] or "",
                t["HostPID"] is None,
                t["HostPID"] or 0,
                t["HostTID"] is None,
                t["HostTID"] or 0,
            ),
        )
        audit["displayed_tasks"] = len(displayed)


        with self.open("containertasks-audit.json") as handle:
            handle.write(
                json.dumps(audit, ensure_ascii=False, indent=2, default=str).encode(
                    "utf-8"
                )
            )
        if audit["traversal_errors"]:
            LOG.warning(
                "ContainerTasks: task collection incomplete; see containertasks-audit.json"
            )
        if triage and displayed:
            LOG.warning(
                "ContainerTasks: membership mismatches=%d; see containertasks-audit.json",
                len(displayed),
            )

        if triage:
            return self._triage_grid(audit, displayed)
        if self.config.get("details", False) and displayed:
            return self._raw_grid(displayed)
        return self._summary_grid(audit, displayed)



    @staticmethod
    def _cell(value):
        """Normalize table cells by replacing controls and marking unavailable values.

        Convert None into Volatility's unavailable value, sanitize strings, and
        preserve integer and Boolean values.
        """
        if value is None:
            return renderers.NotAvailableValue()
        if isinstance(value, str):
            return "".join(ch if ch.isprintable() else " " for ch in value)
        return value

    def _raw_grid(self, displayed):
        """Build the detailed per-task table with membership evidence."""
        columns = [
            ("ContainerID", str),
            ("CgroupPath", str),
            ("HostPID", int),
            ("HostTID", int),
            ("PPID", int),
            ("Name", str),
            ("NSPID", int),
            ("NSTID", int),
            ("PIDNS", int),
            ("EUID", int),
            ("UserNS", int),
            ("StartUTC", str),
            ("Cmdline", str),
            ("ShimPID", int),
            ("ShimID", str),
            ("RuntimeNS", str),
            ("Basis", str),
            ("Conflict", str),
            ("Effective", str),
            ("Status", str),
        ]

        def rows():
            for t in displayed:
                shim = t["shim_lineage"] or {}
                values = {
                    "ContainerID": short_id(t["ContainerID"]),
                    "CgroupPath": abbrev_path(t["CgroupPath"]),
                    "HostPID": t["HostPID"],
                    "HostTID": t["HostTID"],
                    "PPID": t["PPID"],
                    "Name": t["Name"],
                    "NSPID": t["NSPID"],
                    "NSTID": t["NSTID"],
                    "PIDNS": t["PIDNS"],
                    "EUID": t["EUID"],
                    "UserNS": t["UserNS"],
                    "StartUTC": t["StartUTC"],
                    "Cmdline": truncate(t["Cmdline"]),
                    "ShimPID": shim.get("shim_pid"),
                    "ShimID": short_id(shim.get("container_id")),
                    "RuntimeNS": t["membership"].get("runtime_namespace"),
                    "Basis": t["membership"]["basis"],
                    "Conflict": "; ".join(c["kind"] for c in t["conflicts"]) or "-",
                    "Effective": t["cap_effective"],
                    "Status": t["Status"],
                }
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
            reasons.append(
                "Cgroup and shim IDs agree"
                if len(sources) == 2
                else f"Only {' and '.join(sources)} evidence available"
            )
        if detail["Status"] != "ok":
            reasons.append("Some task fields could not be read; see audit JSON")
        return "; ".join(reasons)

    @staticmethod
    def _empty_message(audit):
        prefix = audit["selected_prefix"]
        if not audit["candidate_tasks"]:
            message = "No container-candidate tasks recovered"
        elif prefix and not any(
            t["ContainerID"] and t["ContainerID"].startswith(prefix)
            for t in audit["tasks"]
        ):
            message = f"No container matches prefix {prefix}"
        else:
            message = "No conflicting or unresolved membership in the selected tasks"
        return (
            message
            + ". This does not prove complete recovery or safety; see containertasks-audit.json."
        )

    def _summary_grid(self, audit, displayed):
        """Compact, flat task view; full evidence remains in the audit file."""
        columns = [
            ("Container", str),
            ("Host PID", int),
            ("Host TID", int),
            ("Name", str),
            ("Membership", str),
            ("Evidence / next step", str),
        ]

        def rows():
            if not displayed:
                yield (
                    0,
                    tuple(
                        self._cell(v)
                        for v in (
                            None,
                            None,
                            None,
                            None,
                            "No results",
                            self._empty_message(audit),
                        )
                    ),
                )
            for task in displayed:
                yield (
                    0,
                    tuple(
                        self._cell(v)
                        for v in (
                            short_id(task["ContainerID"]),
                            task["HostPID"],
                            task["HostTID"],
                            task["Name"],
                            self._membership_label(task),
                            self._review_reason(task),
                        )
                    ),
                )

        return renderers.TreeGrid(columns, rows())

    @staticmethod
    def _is_mismatch(task):

        return bool(task["conflicts"])

    def _triage_empty_result(self, audit):
        selected = audit["tasks"]
        prefix = audit.get("selected_prefix", "")
        if prefix:
            selected = [
                t
                for t in selected
                if t["ContainerID"] and t["ContainerID"].startswith(prefix)
            ]
        if audit.get("traversal_errors"):
            return (
                "Incomplete",
                "No membership mismatches detected; task collection was incomplete. See audit JSON.",
            )
        if not selected:
            return "No results", self._empty_message(audit)
        reason = "Normal: no membership mismatches detected in the selected tasks."
        limited = sum(
            t["membership"]["status"] != "confirmed_agree" or t["Status"] != "ok"
            for t in selected
        )
        if limited:
            reason += f" {limited} task(s) have limited evidence; this is not confirmation of their membership. See audit JSON."
        return "Normal", reason

    def _triage_grid(self, audit, displayed):
        """One row per mismatch; missing evidence alone is not a mismatch."""
        columns = [
            ("PID / TID", str),
            ("Name", str),
            ("Cgroup ID", str),
            ("Shim PID", int),
            ("Shim ID", str),
            ("Runtime NS", str),
            ("Shim Cgroup ID", str),
            ("Result", str),
            ("Reason", str),
        ]
        mismatches = [task for task in displayed if self._is_mismatch(task)]

        def rows():
            if not mismatches:
                result, reason = self._triage_empty_result(audit)
                yield (
                    0,
                    tuple(
                        self._cell(v)
                        for v in (
                            None,
                            None,
                            None,
                            None,
                            None,
                            None,
                            None,
                            result,
                            reason,
                        )
                    ),
                )
            for task in mismatches:
                lineage = task["shim_lineage"] or {}

                cgroup_id = task["membership"]["sources"].get("cgroup")
                yield (
                    0,
                    tuple(
                        self._cell(v)
                        for v in (
                            " / ".join(
                                str(task[field]) if task[field] is not None else "N/A"
                                for field in ("HostPID", "HostTID")
                            ),
                            task["Name"],
                            short_id(cgroup_id),
                            lineage.get("shim_pid"),
                            short_id(lineage.get("container_id")),
                            lineage.get("runtime_namespace"),
                            short_id(lineage.get("shim_cgroup_id")),
                            "Mismatch",
                            self._review_reason(task),
                        )
                    ),
                )

        return renderers.TreeGrid(columns, rows())

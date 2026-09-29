"""Analyze open file descriptors owned by container tasks in Linux memory.
The --inspect-files option reports paths, access modes, host aliases, inode facts,
and unlinked-name state through files, hosts, and details views.
It describes current open files, not closed descriptors, history, or file contents.

SPDX-License-Identifier: MIT
"""

import collections
import dataclasses
import json
import logging
import re

from volatility3.framework import exceptions, renderers
from volatility3.framework.configuration import requirements
from volatility3.framework.interfaces import plugins
from volatility3.framework.objects import utility
from volatility3.framework.symbols import linux
from volatility3.plugins.linux import docker_artifacts, pslist
from volatility3.plugins.linux._artifacts import cgroups as cgroup_readers
from volatility3.plugins.linux._artifacts import core as artifact_core
from volatility3.plugins.linux._artifacts import files as file_readers
from volatility3.plugins.linux._artifacts import mounts as mount_readers
from volatility3.plugins.linux._artifacts import paths as path_readers
from volatility3.plugins.linux._artifacts import tasks as task_readers


def _runtime_from_ancestry(task):
    return task_readers.runtime_from_ancestry(task, RUNTIME_SUPERVISORS)


vollog = logging.getLogger(__name__)
MAX_TASKS = 1000000





@dataclasses.dataclass(frozen=True)
class Identity:
    runtime: str
    identifier: str
    id_kind: str
    evidence: str


@dataclasses.dataclass
class TaskObservation:
    pid: int
    task: object
    mnt_ns: object
    root_key: tuple
    cgroup_memberships: tuple
    identity: object
    runtime: str
    evidence: tuple


_CGROUP_HEX_ID = r"[0-9a-f]{64}"
_CGROUP_POD_ID = r"[0-9a-f]{8}(?:[-_][0-9a-f]{4}){3}[-_][0-9a-f]{12}"
_CGROUP_ID_PATTERNS = (
    (
        rf"(?:^|/)docker-({_CGROUP_HEX_ID})\.scope(?=/|$)",
        "docker",
        "container",
        "docker-systemd-cgroup",
    ),
    (
        rf"(?:^|/)docker/({_CGROUP_HEX_ID})(?=/|$)",
        "docker",
        "container",
        "docker-cgroupfs",
    ),
    (
        rf"(?:^|/)cri-containerd-({_CGROUP_HEX_ID})\.scope(?=/|$)",
        "containerd",
        "container",
        "containerd-systemd-cgroup",
    ),
    (
        rf"(?:^|/)crio-({_CGROUP_HEX_ID})\.scope(?=/|$)",
        "cri-o",
        "container",
        "crio-systemd-cgroup",
    ),
    (
        rf"(?:^|/)libpod-({_CGROUP_HEX_ID})\.scope(?=/|$)",
        "podman",
        "container",
        "podman-systemd-cgroup",
    ),
    (
        rf"(?:^|/)(?:crio|cri-containerd)/({_CGROUP_HEX_ID})(?=/|$)",
        "kubernetes",
        "container",
        "cri-cgroupfs",
    ),
    (
        rf"(?:^|/)kubepods(?:/(?:burstable|besteffort))?/pod{_CGROUP_POD_ID}/({_CGROUP_HEX_ID})(?=/|$)",
        "kubernetes",
        "container",
        "kubernetes-cgroupfs-container",
    ),
    (
        rf"(?:^|/)(?:kubepods(?:-[^/]+)*-)?pod({_CGROUP_POD_ID})(?:\.slice)?(?=/|$)",
        "kubernetes",
        "pod",
        "kubernetes-pod-cgroup",
    ),
)
_CGROUP_ID_PATTERNS = tuple(
    (re.compile(pattern, re.IGNORECASE), runtime, kind, source)
    for pattern, runtime, kind, source in _CGROUP_ID_PATTERNS
)


RUNTIME_SUPERVISORS = (
    ("containerd-shim", "containerd"),
    ("conmon", "podman/cri-o"),
    ("lxc-start", "lxc"),
    ("lxc-monitord", "lxc"),
    ("systemd-nspawn", "nspawn"),
    ("runsc-sandbox", "gvisor"),
    ("kata-shim", "kata"),
)


def _cgroup_identity(memberships):
    """Recognize known runtime paths and defer nested or cross-level ID conflicts."""
    matches = []
    for membership in memberships:
        for pattern, runtime, kind, source in _CGROUP_ID_PATTERNS:
            for match in pattern.finditer(membership.path):
                identifier = match.group(1).lower()
                if kind == "pod":
                    identifier = identifier.replace("_", "-")
                matches.append(
                    (membership, Identity(runtime, identifier, kind, source))
                )
    for kind in ("container", "pod"):
        if len({item.identifier for _, item in matches if item.id_kind == kind}) > 1:
            return None, "", True
    for kind in ("container", "pod"):
        candidates = [
            (membership, identity)
            for membership, identity in matches
            if identity.id_kind == kind
        ]
        if candidates:
            candidates.sort(
                key=lambda item: (
                    item[0].version != "v2",
                    item[0].display(),
                    item[1].runtime,
                )
            )
            membership, identity = candidates[0]
            owner = ",".join(membership.controllers) or "unified"
            return identity, f"{membership.version}:{owner}", False
    return None, "", False


def _observe_task(task, *, diagnostics=None):
    try:
        if (
            not task
            or not task.fs
            or not artifact_core._object_readable(task.fs, diagnostics=diagnostics)
            or not task.nsproxy
            or not artifact_core._object_readable(task.nsproxy, diagnostics=diagnostics)
        ):
            return None
        mnt_ns = task.nsproxy.mnt_ns
        root_mnt, root_dentry = task.fs.get_root_mnt(), task.fs.get_root_dentry()
        if not all(
            obj and artifact_core._object_readable(obj, diagnostics=diagnostics)
            for obj in (mnt_ns, root_mnt, root_dentry)
        ):
            return None
        pid = int(task.pid)
        root_key = (
            artifact_core._object_address(root_mnt),
            artifact_core._object_address(root_dentry),
        )
    except artifact_core.READ_ERRORS as exc:
        artifact_core.record_read_error(diagnostics, "task.view", exc)
        return None
    issues = set()
    memberships = cgroup_readers.read_link_memberships(
        task, issues_out=issues, logger=vollog
    )
    identity, source, conflict = _cgroup_identity(memberships)
    conflict = conflict or "cgroup-id-conflict" in issues
    if conflict:
        identity = None
    runtime, supervisor = _runtime_from_ancestry(task)
    evidence = []
    if conflict:
        evidence.append("cgroup-id-conflict")
    elif identity:
        evidence.append(f"cgroup:{source}:{identity.evidence}")
    if supervisor:
        evidence.append(f"supervisor:{supervisor}")
    if "cgroup-metadata-partial" in issues:
        evidence.append("cgroup-metadata-partial")
    return TaskObservation(
        pid=pid,
        task=task,
        mnt_ns=mnt_ns,
        root_key=root_key,
        cgroup_memberships=memberships,
        identity=identity,
        runtime=identity.runtime if identity else runtime,
        evidence=tuple(evidence),
    )


def _safe_text(value):
    """Escape terminal control characters without removing meaningful whitespace."""
    return "".join(
        f"\\x{ord(char):02x}" if ord(char) < 32 or ord(char) == 127 else char
        for char in str(value)
    )


def _display_ids(identifiers, full=False):
    """Extend colliding short IDs until unique while retaining full internal IDs."""
    identifiers = sorted({identifier for identifier in identifiers if identifier})
    if full:
        return {identifier: identifier for identifier in identifiers}
    result = {}
    for identifier in identifiers:
        size = min(12, len(identifier))
        while size < len(identifier) and any(
            other != identifier and other.startswith(identifier[:size])
            for other in identifiers
        ):
            size += 1
        result[identifier] = identifier[:size]
    return result


@dataclasses.dataclass
class TaskView:
    task: object
    tgid: int
    tid: int
    container_id: str
    observation: object
    files_address: int
    members: set = dataclasses.field(default_factory=set)
    issues: set = dataclasses.field(default_factory=set)


class InspectFiles(plugins.PluginInterface):
    """Inspect container file descriptors, file paths and unlinked-name references."""

    hidden = True
    _required_framework_version = (2, 28, 0)
    _version = (0, 4, 1)

    @classmethod
    def get_requirements(cls):
        return [
            requirements.VersionRequirement(
                name="docker_artifacts",
                component=docker_artifacts.DockerArtifacts,
                version=(1, 1, 0),
            ),
            requirements.ModuleRequirement(
                name="kernel",
                description="Linux kernel with matching ISF",
                architectures=["Intel32", "Intel64"],
            ),
            requirements.VersionRequirement(
                name="linuxutils",
                component=linux.LinuxUtilities,
                version=(2, 4, 0),
            ),
            requirements.VersionRequirement(
                name="pslist", component=pslist.PsList, version=(4, 1, 1)
            ),
            requirements.ListRequirement(
                name="pids",
                element_type=int,
                min_elements=1,
                optional=True,
                description="Explicit host process IDs (TGIDs), including their thread file tables",
            ),
            requirements.StringRequirement(
                name="container",
                optional=True,
                description="Select one unambiguous container ID prefix (6..64 hex characters)",
            ),
            requirements.ChoiceRequirement(
                name="view",
                choices=["files", "hosts", "details"],
                optional=True,
                description="All views are vertical Record/Field/Value rows; files: basic fields, hosts: host paths, details: all fields",
            ),
            requirements.BooleanRequirement(
                name="extended",
                optional=True,
                default=False,
                description="Alias for --view details (all fields, same 3-column vertical output)",
            ),
            requirements.BooleanRequirement(
                name="unlinked-only",
                optional=True,
                default=False,
                description="Only UNLINKED names, not anonymous or never-linked temporary files",
            ),
            requirements.BooleanRequirement(
                name="full-id",
                optional=True,
                default=False,
                description="Use complete container IDs (also required for full-ID JSON export)",
            ),
            requirements.IntRequirement(
                name="max-fds",
                optional=True,
                default=65536,
                description="Slots per file table (1..1048576); truncation is reported, never silently complete",
            ),
        ]

    def _options(self):
        wanted = self.config.get("pids")
        if wanted is not None and (
            not isinstance(wanted, list)
            or not wanted
            or any(type(pid) is not int or pid <= 0 for pid in wanted)
        ):
            raise exceptions.VolatilityException(
                "--pids requires positive host process IDs"
            )
        prefix = self.config.get("container")
        if prefix is not None and (
            not isinstance(prefix, str)
            or not re.fullmatch(r"[0-9a-fA-F]{6,64}", prefix)
        ):
            raise exceptions.VolatilityException(
                "--container requires a 6..64 hex ID prefix"
            )
        limit = self.config.get("max-fds", 65536)
        if type(limit) is not int or not 1 <= limit <= file_readers.MAX_FDS:
            raise exceptions.VolatilityException("--max-fds must be in 1..1048576")
        for name in ("extended", "unlinked-only", "full-id"):
            if type(self.config.get(name, False)) is not bool:
                raise exceptions.VolatilityException(f"--{name} must be a boolean")
        self._selected_view()
        return (
            set(wanted) if wanted is not None else None,
            prefix.lower() if prefix else None,
            limit,
        )

    def _selected_view(self):
        value = self.config.get("view")
        if value is not None and value not in ("files", "hosts", "details"):
            raise exceptions.VolatilityException(
                "--view must be files, hosts or details"
            )
        if self.config.get("extended", False):
            if value not in (None, "details"):
                raise exceptions.VolatilityException(
                    "--extended is an alias for --view details"
                )
            return "details"
        return value or "files"

    def _task_views(self, wanted, prefix, *, diagnostics=None):
        views, found, seen = {}, set(), set()
        failures = collections.Counter()
        try:
            initial = self.context.modules[self.config["kernel"]].object_from_symbol(
                "init_task"
            )
            host_namespace = initial.nsproxy.mnt_ns
            host_namespace_address = (
                artifact_core._object_address(host_namespace)
                if artifact_core._object_readable(
                    host_namespace, diagnostics=diagnostics
                )
                else None
            )
        except artifact_core.READ_ERRORS as exc:
            artifact_core.record_read_error(diagnostics, "host_namespace", exc)
            host_namespace_address = None
        try:
            tasks = docker_artifacts.DockerArtifacts.list_tasks(
                self.context,
                self.config["kernel"],
                include_threads=True,
            )
            for task in tasks:
                address = None
                try:
                    address = artifact_core._object_address(task)
                    if address in seen:
                        continue
                    if len(seen) >= MAX_TASKS:
                        failures["task-limit"] += 1
                        break
                    seen.add(address)
                    tgid, tid = int(task.tgid), int(task.pid)
                    if wanted is not None and tgid not in wanted:
                        continue
                    if tgid <= 0 or tid <= 0:
                        continue
                    if not task.files:
                        if wanted is not None:
                            found.add(tgid)
                        continue
                    task_diagnostics = []
                    observation = _observe_task(task, diagnostics=task_diagnostics)
                    if diagnostics is not None:
                        diagnostics.extend(
                            {**item, "task_address": address, "pid": tgid, "tid": tid}
                            for item in task_diagnostics
                        )
                    if observation is None and wanted is None:

                        if task.fs and task.nsproxy:
                            failures["task-membership-or-view"] += 1
                        continue
                    related = False
                    if observation is not None:
                        related = (
                            observation.identity is not None
                            or "cgroup-id-conflict" in observation.evidence
                        )
                        if not related and host_namespace_address is not None:
                            command = utility.array_to_string(task.comm)
                            itself_supervisor = any(
                                task_readers.comm_matches(command, signature)
                                for signature, _ in RUNTIME_SUPERVISORS
                            )



                            related = (
                                not itself_supervisor
                                and artifact_core._object_address(observation.mnt_ns)
                                != host_namespace_address
                                and any(
                                    item.startswith("supervisor:")
                                    for item in observation.evidence
                                )
                            )
                    if wanted is None and not related:
                        continue
                    identity = observation.identity if observation is not None else None
                    container_id = (
                        identity.identifier
                        if identity and identity.id_kind == "container"
                        else ""
                    )
                    if prefix and not container_id.startswith(prefix):
                        continue
                    found.add(tgid)
                    files_address = artifact_core._object_address(task.files)
                    issues = set()
                    if observation is None:
                        issues.add("task-membership-or-view")
                        owner = ("unknown", tid)
                        view_key = (tid,)
                    else:
                        issues.update(
                            flag
                            for flag in observation.evidence
                            if flag in {"cgroup-id-conflict", "cgroup-metadata-partial"}
                        )
                        owner = container_id or (
                            tuple(
                                (m.version, m.cgroup_address)
                                for m in observation.cgroup_memberships
                            ),
                            observation.runtime,
                            tid if issues else None,
                        )
                        view_key = (
                            artifact_core._object_address(observation.mnt_ns),
                            observation.root_key,
                        )


                    key = (tgid, files_address, view_key, owner)
                    if key not in views:
                        views[key] = TaskView(
                            task,
                            tgid,
                            tid,
                            container_id,
                            observation,
                            files_address,
                            {tid},
                            issues,
                        )
                    else:
                        view = views[key]
                        view.members.add(tid)
                        view.issues.update(issues)
                        if (tid != tgid, tid) < (view.tid != tgid, view.tid):
                            view.task, view.tid, view.observation = (
                                task,
                                tid,
                                observation,
                            )
                except artifact_core.READ_ERRORS as exc:
                    artifact_core.record_read_error(
                        diagnostics, "task_metadata", exc, task_address=address
                    )
                    failures["task-metadata"] += 1
        except artifact_core.READ_ERRORS as exc:
            artifact_core.record_read_error(diagnostics, "task_list", exc)
            failures["task-list"] += 1
        if wanted is not None and wanted - found:
            vollog.warning(
                "Requested TGIDs not selected/readable: %s", sorted(wanted - found)
            )
        if wanted is None and host_namespace_address is None:
            vollog.warning(
                "Host MNT NS unreadable; automatic selection used cgroup evidence only"
            )
        if failures:
            vollog.warning(
                "Task collection incomplete: %s; missing rows do not prove absence",
                dict(failures),
            )
            for view in views.values():
                view.issues.add("task-list-partial")
        ids = {view.container_id for view in views.values() if view.container_id}
        if prefix and len(ids) > 1:
            raise exceptions.VolatilityException(
                "--container is ambiguous; use a longer/full ID"
            )
        return sorted(
            views.values(), key=lambda view: (view.container_id, view.tgid, view.tid)
        )

    def _read_fds(self, task, limit):
        return docker_artifacts.DockerArtifacts.read_file_descriptor_evidence(
            self.context,
            self.config["kernel"],
            int(task.vol.offset),
            limit=limit,
            layer_name=task.vol.layer_name,
            native_layer_name=task.vol.native_layer_name,
        )

    def _generator(self, output_view):
        diagnostics = []
        try:
            yield from self._generate_rows(output_view, diagnostics)
        finally:
            if diagnostics:
                with self.open("containerfiles-diagnostics.json") as handle:
                    handle.write(
                        json.dumps(
                            {
                                "plugin_version": self._version,
                                "diagnostics": diagnostics,
                            },
                            ensure_ascii=False,
                            indent=2,
                        ).encode("utf-8")
                    )

    def _generate_rows(self, output_view, diagnostics):
        wanted, prefix, limit = self._options()
        views = self._task_views(wanted, prefix, diagnostics=diagnostics)
        if not views:
            vollog.warning(
                "No task views selected; use --pids for an explicit known host process"
            )
            return
        id_display = _display_ids(
            (view.container_id for view in views), self.config.get("full-id", False)
        )
        kernel = self.context.modules[self.config["kernel"]]
        resolver = path_readers.FileHostMountResolver(
            kernel.object_from_symbol("init_task"),
            logger=vollog,
            diagnostics=diagnostics,
        )
        table_cache, file_cache, namespace_cache = {}, {}, {}
        counts = collections.Counter()
        for view in views:
            if view.files_address not in table_cache:
                table_cache[view.files_address] = self._read_fds(view.task, limit)
            table = table_cache[view.files_address]
            entries, table_issues = table["entries"], table["issues"]
            provenance = {
                "pid": view.tgid,
                "tid": view.tid,
                "task_address": int(view.task.vol.offset),
                "files_address": view.files_address,
            }
            diagnostics.extend({**item, **provenance} for item in table["diagnostics"])
            if table_issues:
                vollog.warning(
                    "PID/TID %s/%s FD table incomplete: %s",
                    view.tgid,
                    view.tid,
                    dict(table_issues),
                )
            covering, namespace_complete = {}, False
            if view.observation is not None:
                namespace_address = artifact_core._object_address(
                    view.observation.mnt_ns
                )
                if namespace_address not in namespace_cache:
                    namespace_diagnostics = []
                    namespace_cache[namespace_address] = (
                        mount_readers.namespace_covering(
                            view.observation.mnt_ns, diagnostics=namespace_diagnostics
                        )
                    )
                    diagnostics.extend(
                        {**item, "namespace_address": namespace_address}
                        for item in namespace_diagnostics
                    )
                covering, namespace_complete = namespace_cache[namespace_address]
            try:
                comm = _safe_text(utility.array_to_string(view.task.comm))
            except artifact_core.READ_ERRORS as exc:
                artifact_core.record_read_error(
                    diagnostics, "task_name", exc, **provenance
                )
                comm = "-"
            for fd, filp in entries:
                file_address = artifact_core._object_address(filp)
                if file_address not in file_cache:
                    file_cache[file_address] = file_readers.file_facts(filp, resolver)
                facts = file_cache[file_address]
                file_provenance = {**provenance, "fd": fd, "file_address": file_address}
                diagnostics.extend(
                    {**item, **file_provenance} for item in facts.diagnostics
                )
                if (
                    self.config.get("unlinked-only", False)
                    and facts.state != "UNLINKED"
                ):
                    continue
                path_diagnostics = []
                path, path_status = file_readers.container_path(
                    view.task,
                    facts,
                    covering,
                    namespace_complete,
                    diagnostics=path_diagnostics,
                )
                diagnostics.extend(
                    {**item, **file_provenance} for item in path_diagnostics
                )
                issues = set(view.issues) | set(facts.issues)
                issues.update(table_issues)
                if path_status == "PARTIAL":
                    issues.add("container-path")
                if issues:
                    counts["partial"] += 1
                counts["rows"] += 1
                counts[facts.state] += 1
                displayed_path = _safe_text(path) or "-"



                fields = [
                    ("Container", id_display.get(view.container_id, "-")),
                    ("PID/TID", f"{view.tgid}/{view.tid}"),
                    ("FD", str(fd)),
                ]
                if output_view == "files":


                    state = facts.state + ("*" if issues else "")
                    fields.extend(
                        [
                            ("Access", facts.access),
                            ("State", state),
                            ("Path", displayed_path),
                        ]
                    )
                elif output_view == "hosts":

                    fields.extend(
                        ("Host Path", _safe_text(alias))
                        for alias in facts.host_paths or ("-",)
                    )
                    fields.append(("Status", facts.host_status))
                else:
                    detail = (
                        "PARTIAL:" + ",".join(sorted(issues)) if issues else "COMPLETE"
                    )
                    fields.extend(
                        [
                            ("Process", comm),
                            ("Access", facts.access),
                            ("Type", facts.kind),
                            ("Name State", facts.state),
                            ("Path", displayed_path),
                        ]
                    )
                    fields.extend(
                        ("Host Path", _safe_text(alias))
                        for alias in facts.host_paths or ("-",)
                    )
                    fields.extend(
                        [
                            ("Path Status", path_status),
                            ("Host Path Status", facts.host_status),
                            ("Read Status", detail),
                            (
                                "Inode",
                                str(facts.inode_number)
                                if facts.inode_number is not None
                                else "-",
                            ),
                            (
                                "Link Count",
                                str(facts.nlink) if facts.nlink is not None else "-",
                            ),
                            (
                                "File Flags",
                                hex(facts.file_flags)
                                if facts.file_flags is not None
                                else "-",
                            ),
                            (
                                "File Mode",
                                hex(facts.raw_mode)
                                if facts.raw_mode is not None
                                else "-",
                            ),
                        ]
                    )


                    if len(view.members) > 1:
                        fields.extend(
                            ("Shared TID", str(tid)) for tid in sorted(view.members)
                        )

                for label, value in fields:
                    yield 0, (counts["rows"], label, value)
        if counts["partial"]:
            vollog.warning(
                "%s/%s FDs have incomplete metadata (* in State); inspect --view details",
                counts["partial"],
                counts["rows"],
            )
        if not counts["rows"]:
            vollog.warning(
                "No matching readable FD rows; this does not prove there are no open/deleted files"
            )

    def run(self):
        self._options()
        output_view = self._selected_view()
        columns = [("Record", int), ("Field", str), ("Value", str)]
        return renderers.TreeGrid(columns, self._generator(output_view))

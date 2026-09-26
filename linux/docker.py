"""Unified entry point for the volatility-docker-v2 analyses.

Usage: vol -p plugins -s symbols -f memory.lime linux.docker.Docker --detector
Select exactly one of --detector, --ps, --inspect-mounts, --inspect-networks,
--inspect-caps, --container-tasks or --inspect-files. Analysis-specific settings
are accepted only with their corresponding selector. Native collectors, defaults, TreeGrid schemas and
evidence files are preserved. The analysis modules are internal backends;
linux.docker.Docker is the only public entry point for these seven analyses.
The official Volatility framework and core Linux plugins are not replaced.
"""

import copy
import importlib
import logging
import re

from volatility3.framework import exceptions, interfaces
from volatility3.framework.configuration import requirements
from volatility3.plugins.linux import docker_artifacts

vollog = logging.getLogger(__name__)

# Import only the selected backend here. Volatility itself still discovers
# all .py plugin files at startup, so this is not isolation from every possible
# import-time error in another plugin in the search path.
BACKENDS = {
    "detector": ("detector", "Detector"),
    "ps": ("ps", "run_ps"),
    "inspect-mounts": ("inspect_mount", "ContainerMounts"),
    "inspect-networks": ("inspect_networks", "InspectNetworks"),
    # Keep the existing filename; importlib can load its hyphenated name.
    "inspect-caps": ("inspect-caps", "ContainerCaps"),
    "container-tasks": ("container_tasks", "ContainerTasks"),
    "inspect-files": ("inspect_files", "InspectFiles"),
}

# Public option -> {analysis selector: native backend setting}.
SETTINGS = {
    "limit": {"detector": "limit"},
    "pids": {"inspect-mounts": "pids", "inspect-files": "pids"},
    "extended": {"inspect-mounts": "extended", "inspect-files": "extended"},
    "mounts-extended": {"inspect-mounts": "extended"},
    "dump-evidence": {"inspect-networks": "dump-evidence"},
    "container": {
        "inspect-networks": "container",
        "inspect-caps": "container",
        "container-tasks": "container",
        "inspect-files": "container",
    },
    "leaders": {"inspect-caps": "leaders"},
    "unresolved": {"inspect-caps": "unresolved"},
    "view": {
        "inspect-networks": "view",
        "inspect-caps": "view",
        "inspect-files": "view",
    },
    "triage": {"container-tasks": "triage"},
    "details": {"container-tasks": "details"},
    "unlinked-only": {"inspect-files": "unlinked-only"},
    "full-id": {"inspect-files": "full-id"},
    "max-fds": {"inspect-files": "max-fds"},
}

VIEWS = {
    "inspect-networks": [
        "sockets",
        "relations",
        "containers",
        "interfaces",
        "conntrack",
        "diagnostics",
    ],
    "inspect-caps": ["raw", "analyst"],
    "inspect-files": ["files", "hosts", "details"],
}


class Docker(interfaces.plugins.PluginInterface):
    """Analyze container presence, inventory, mounts, networks, capabilities, tasks or files.

    Select exactly one analysis. --container accepts several prefixes for
    networks and one for capabilities, tasks or files. --extended adds mount
    fields or selects the files details view. Tasks show a summary by default;
    --details selects the full task table and --triage shows membership mismatches
    (takes precedence over --details). Task evidence is always saved to
    containertasks-audit.json. Evidence files use Volatility's -o directory.
    """

    _required_framework_version = (2, 28, 0)
    # MAJOR: incompatible inputs/output; MINOR: compatible additions; PATCH:
    # internal fixes. Reset lower components when bumping MAJOR or MINOR.
    # 3.x accounts for category/value output and the revised task views.
    _version = (3, 1, 0)

    @classmethod
    def get_requirements(cls):
        result = [
            requirements.VersionRequirement(
                name="docker_artifacts",
                component=docker_artifacts.DockerArtifacts,
                version=(1, 0, 1),
            ),
            requirements.ModuleRequirement(
                name="kernel",
                description="Linux kernel with matching symbols",
                architectures=["Intel32", "Intel64"],
            ),
        ]
        descriptions = {
            "detector": "Observe runtime, mount and network presence checks",
            "ps": "Summarize task-linked Docker containers and representative credentials",
            "inspect-mounts": "Inspect container mount paths, host aliases and access modes",
            "inspect-networks": "Inspect container sockets, sharing relations and network context (Intel64)",
            "inspect-caps": "Inspect Docker task capabilities and security context (Intel64)",
            "container-tasks": "Inspect container tasks/threads and cross-check cgroup membership with shim ancestry (Intel64)",
            "inspect-files": "Inspect container open file descriptors, file paths and unlinked names",
        }
        result.extend(
            requirements.BooleanRequirement(
                name=name,
                description=description,
                optional=True,
                default=False,
            )
            for name, description in descriptions.items()
        )
        view_choices = []
        for choices in VIEWS.values():
            for view in choices:
                if view not in view_choices:
                    view_choices.append(view)
        # None distinguishes an omitted setting from an explicitly supplied
        # False/0/empty value (including JSON config). Backend defaults are
        # obtained from that backend's requirements, not duplicated here.
        result.extend(
            [
                requirements.IntRequirement(
                    name="limit",
                    optional=True,
                    default=None,
                    description="[detector] Nodes per traversal (1..1000000); default 100000",
                ),
                requirements.ListRequirement(
                    name="pids",
                    element_type=int,
                    min_elements=1,
                    optional=True,
                    default=None,
                    description="[mounts, files] Inspect these host PIDs; files selects TGIDs and includes their thread file tables",
                ),
                requirements.BooleanRequirement(
                    name="extended",
                    optional=True,
                    default=None,
                    description="[mounts] Add mount status fields; [files] Alias for --view details",
                ),
                requirements.BooleanRequirement(
                    name="mounts-extended",
                    optional=True,
                    default=None,
                    description="[mounts] Alias for --extended",
                ),
                requirements.BooleanRequirement(
                    name="dump-evidence",
                    optional=True,
                    default=None,
                    description="[networks] Save evidence for the selected --view to network_evidence.json",
                ),
                requirements.ListRequirement(
                    name="container",
                    element_type=str,
                    min_elements=1,
                    optional=True,
                    default=None,
                    description="[networks, caps, tasks, files] ID prefix(es); caps/tasks/files accept one 6-64 hex prefix",
                ),
                requirements.BooleanRequirement(
                    name="leaders",
                    optional=True,
                    default=None,
                    description="[caps] Collect process leaders only; default includes threads",
                ),
                requirements.BooleanRequirement(
                    name="unresolved",
                    optional=True,
                    default=None,
                    description="[caps] Show unresolved task membership; cannot combine with --container",
                ),
                requirements.ChoiceRequirement(
                    name="view",
                    choices=view_choices,
                    optional=True,
                    default=None,
                    description="[networks, caps, files] Output view; defaults: networks=sockets, caps=raw, files=files",
                ),
                requirements.BooleanRequirement(
                    name="triage",
                    optional=True,
                    default=None,
                    description="[tasks] Show membership mismatches only; report Normal when none are detected",
                ),
                requirements.BooleanRequirement(
                    name="details",
                    optional=True,
                    default=None,
                    description="[tasks] Show the full task table instead of the summary; ignored with --triage",
                ),
                requirements.BooleanRequirement(
                    name="unlinked-only",
                    optional=True,
                    default=None,
                    description="[files] Show only UNLINKED names; excludes anonymous/never-linked temporary files",
                ),
                requirements.BooleanRequirement(
                    name="full-id",
                    optional=True,
                    default=None,
                    description="[files] Show complete container IDs, including in JSON output",
                ),
                requirements.IntRequirement(
                    name="max-fds",
                    optional=True,
                    default=None,
                    description="[files] Slots per file table (1..1048576); default 65536; truncation is reported",
                ),
            ]
        )
        return result

    @staticmethod
    def resolve_options(config):
        selected = [name for name in BACKENDS if config.get(name, False)]
        if len(selected) != 1:
            choices = ", ".join("--" + name for name in BACKENDS)
            raise exceptions.VolatilityException(
                "Select exactly one analysis: " + choices
            )
        action = selected[0]
        overrides = {}
        for public_name, routes in SETTINGS.items():
            value = config.get(public_name)
            if value is None:
                continue
            if action not in routes:
                allowed = ", ".join("--" + name for name in routes)
                raise exceptions.VolatilityException(
                    f"--{public_name} is only valid with {allowed}; selected --{action}"
                )
            native_name = routes[action]
            if native_name in overrides and overrides[native_name] != value:
                raise exceptions.VolatilityException(
                    "--extended and --mounts-extended disagree"
                )
            overrides[native_name] = value
        if "limit" in overrides:
            limit = overrides["limit"]
            if type(limit) is not int or not 1 <= limit <= 1000000:
                raise exceptions.VolatilityException("--limit must be in 1..1000000")
        if "pids" in overrides:
            pids = overrides["pids"]
            if (
                not isinstance(pids, list)
                or not pids
                or any(type(pid) is not int or pid <= 0 for pid in pids)
            ):
                raise exceptions.VolatilityException(
                    "--pids requires one or more positive host PIDs"
                )
        if "max-fds" in overrides:
            limit = overrides["max-fds"]
            if type(limit) is not int or not 1 <= limit <= 1048576:
                raise exceptions.VolatilityException("--max-fds must be in 1..1048576")
        if "view" in overrides and overrides["view"] not in VIEWS[action]:
            raise exceptions.VolatilityException(
                f"--view for --{action} must be one of: " + ", ".join(VIEWS[action])
            )
        if (
            action == "inspect-files"
            and overrides.get("extended")
            and overrides.get("view") not in (None, "details")
        ):
            raise exceptions.VolatilityException(
                "--extended for --inspect-files is an alias for --view details"
            )
        if "container" in overrides:
            prefixes = overrides["container"]
            # Accept the earlier single-string JSON configuration as well.
            if isinstance(prefixes, str):
                prefixes = [prefixes]
            if (
                not isinstance(prefixes, list)
                or not prefixes
                or any(not isinstance(p, str) or not p for p in prefixes)
            ):
                raise exceptions.VolatilityException(
                    "--container requires one or more ID prefixes"
                )
            if action in ("inspect-caps", "container-tasks", "inspect-files"):
                if len(prefixes) != 1 or not re.fullmatch(
                    r"[0-9a-fA-F]{6,64}", prefixes[0]
                ):
                    raise exceptions.VolatilityException(
                        f"--{action} accepts one --container prefix of 6-64 hex characters"
                    )
                if overrides.get("unresolved"):
                    raise exceptions.VolatilityException(
                        "--unresolved cannot be combined with --container"
                    )
                overrides["container"] = prefixes[0]
            else:
                overrides["container"] = list(prefixes)
        return action, overrides

    def run(self):
        try:
            action, overrides = self.resolve_options(self.config)
        except exceptions.VolatilityException as exc:
            # The CLI hides generic VolatilityException messages. Log only
            # option validation failures here, then preserve failure semantics.
            vollog.error("Invalid Docker options: %s", exc)
            raise
        module_name, entry_name = BACKENDS[action]
        try:
            module = importlib.import_module("volatility3.plugins." + module_name)
            backend = getattr(module, entry_name)
        except (ImportError, AttributeError) as exc:
            raise exceptions.VolatilityException(
                f"Cannot load --{action}: {module_name}.py and its dependencies must be in the plugin path: {exc}"
            ) from exc
        if action == "ps":
            return backend(self.context, self.config["kernel"], self.open)
        backend_class = backend
        native_requirements = backend_class.get_requirements()
        native_names = {requirement.name for requirement in native_requirements}
        unknown = set(overrides) - native_names
        if unknown:
            raise exceptions.VolatilityException(
                f"--{action} backend does not support settings: "
                + ", ".join(sorted(unknown))
            )
        config_path = interfaces.configuration.path_join(
            self.config_path, "analysis", action
        )
        overrides["kernel"] = self.config["kernel"]
        # Reinitialize native defaults on every invocation, even when the same
        # context/plugin instance is reused by a non-CLI caller.
        for requirement in native_requirements:
            if isinstance(requirement, requirements.VersionRequirement):
                continue
            value = overrides.get(requirement.name, copy.deepcopy(requirement.default))
            self.context.config[
                interfaces.configuration.path_join(config_path, requirement.name)
            ] = value
        # Only this analysis's component versions / architecture are required.
        failures = backend_class.unsatisfied(self.context, config_path)
        if failures:
            raise exceptions.VolatilityException(
                f"Requirements for --{action} are not satisfied: "
                + ", ".join(sorted(failures))
            )
        backend = backend_class(
            self.context, config_path, progress_callback=self._progress_callback
        )
        backend.set_open_method(self.open)
        return backend.run()

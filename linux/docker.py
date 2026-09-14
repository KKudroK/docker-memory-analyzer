"""Unified entry point for the standalone volatility-docker-v2 analyses.

Usage: vol -p plugins -s symbols -f memory.lime linux.docker.Docker --detector
Select exactly one of --detector, --ps, --inspect-mounts, --inspect-networks,
or --inspect-caps. Analysis-specific settings are accepted only with their
corresponding selector. Native collectors, defaults, TreeGrid schemas and
evidence files are preserved, as are the existing standalone entry points.
The official Volatility framework and core Linux plugins are not replaced.
"""

import copy
import importlib

from volatility3.framework import exceptions, interfaces
from volatility3.framework.configuration import requirements


# Import only the selected backend here. Volatility itself still discovers
# all .py plugin files at startup, so this is not isolation from every possible
# import-time error in another plugin in the search path.
BACKENDS = {
    "detector": ("detector", "Detector"),
    "ps": ("ps", "Ps"),
    "inspect-mounts": ("inspect_mount", "ContainerMounts"),
    "inspect-networks": ("inspect_networks", "InspectNetworks"),
    # importlib supports this original module name. Do not rename it and break
    # the user's standalone CLI / saved-report launcher.
    "inspect-caps": ("inspect-caps", "ContainerCaps"),
}

# Public option -> {analysis selector: native backend setting}.
SETTINGS = {
    "limit": {"detector": "limit", "inspect-networks": "limit"},
    "pids": {"inspect-mounts": "pids"},
    "include-candidates": {"inspect-mounts": "include-candidates"},
    "all-mounts": {"inspect-mounts": "all-mounts"},
    "mounts-extended": {"inspect-mounts": "extended"},
    "identity-mode": {"inspect-networks": "identity-mode"},
    "disable-cgroup-cache": {"inspect-networks": "disable-cgroup-cache"},
    "identity-only": {"inspect-networks": "identity-only"},
    "include-host": {"inspect-networks": "include-host"},
    "containers-only": {"inspect-networks": "containers-only"},
    "dump-evidence": {"inspect-networks": "dump-evidence"},
    "dump-metrics": {"inspect-networks": "dump-metrics"},
    "container": {"inspect-caps": "container"},
    "leaders": {"inspect-caps": "leaders"},
    "view": {"inspect-caps": "view"},
}


class Docker(interfaces.plugins.PluginInterface):
    """Docker v2: detector, process inventory, mounts, networks or capabilities.

    Select exactly one analysis. Use --mounts-extended with --inspect-mounts
    for its additional columns; --ps already provides the v2 combined view.
    --container/--leaders/--view apply to capabilities only. Network
    --dump-evidence also enables its optional evidence collectors. All JSON
    evidence files use the normal Volatility -o directory.
    """

    _required_framework_version = (2, 28, 0)
    _version = (2, 0, 0)

    @classmethod
    def get_requirements(cls):
        result = [requirements.ModuleRequirement(
            name="kernel", description="Linux kernel with matching symbols",
            architectures=["Intel32", "Intel64"],
        )]
        descriptions = {
            "detector": "Detect Docker-labelled evidence and generic container hints",
            "ps": "Inventory container processes and residual evidence (all six stages)",
            "inspect-mounts": "Inspect container mounts, host sources and exposure indicators",
            "inspect-networks": "Inspect network namespaces, interfaces, topology and sockets",
            "inspect-caps": "Inspect Docker cgroup-v2 task capabilities and security context (Intel64)",
        }
        result.extend(requirements.BooleanRequirement(
            name=name, description=description, optional=True, default=False,
        ) for name, description in descriptions.items())
        # None distinguishes an omitted setting from an explicitly supplied
        # False/0/empty value (including JSON config). Backend defaults are
        # obtained from that backend's requirements, not duplicated here.
        result.extend([
            requirements.IntRequirement(name="limit", optional=True, default=None,
                description="[detector, networks] Nodes per traversal; backend default 100000"),
            requirements.ListRequirement(name="pids", element_type=int, min_elements=1,
                optional=True, default=None, description="[mounts] Inspect these host PIDs"),
            requirements.BooleanRequirement(name="include-candidates", optional=True, default=None,
                description="[mounts] Include low-confidence namespace candidates"),
            requirements.BooleanRequirement(name="all-mounts", optional=True, default=None,
                description="[mounts] Include expected infrastructure mounts"),
            requirements.BooleanRequirement(name="mounts-extended", optional=True, default=None,
                description="[mounts] Add evidence and raw mountinfo columns"),
            requirements.ChoiceRequirement(name="identity-mode", choices=["combined", "cgroup", "shim"],
                optional=True, default=None, description="[networks] Container identity strategy"),
            requirements.BooleanRequirement(name="disable-cgroup-cache", optional=True, default=None,
                description="[networks] Recompute cgroup paths (benchmark setting)"),
            requirements.BooleanRequirement(name="identity-only", optional=True, default=None,
                description="[networks] Skip socket and optional evidence collectors"),
            requirements.BooleanRequirement(name="include-host", optional=True, default=None,
                description="[networks] Include host and unattributed namespaces"),
            requirements.BooleanRequirement(name="containers-only", optional=True, default=None,
                description="[networks] Explicitly select the default attributed-namespace scope"),
            requirements.BooleanRequirement(name="dump-evidence", optional=True, default=None,
                description="[networks] Collect all supported evidence and save network_evidence.json"),
            requirements.BooleanRequirement(name="dump-metrics", optional=True, default=None,
                description="[networks] Save traversal/timing metrics"),
            requirements.StringRequirement(name="container", optional=True, default=None,
                description="[caps] Docker ID or unique 6-64 hex prefix"),
            requirements.BooleanRequirement(name="leaders", optional=True, default=None,
                description="[caps] Collect process leaders only; default includes threads"),
            requirements.ChoiceRequirement(name="view", choices=["raw", "analyst"],
                optional=True, default=None, description="[caps] Output view; backend default raw"),
        ])
        return result

    @staticmethod
    def resolve_options(config):
        selected = [name for name in BACKENDS if config.get(name, False)]
        if len(selected) != 1:
            choices = ", ".join("--" + name for name in BACKENDS)
            raise exceptions.VolatilityException("Select exactly one analysis: " + choices)
        action = selected[0]
        overrides = {"ps": True} if action == "ps" else {}
        for public_name, routes in SETTINGS.items():
            value = config.get(public_name)
            if value is None:
                continue
            if action not in routes:
                allowed = ", ".join("--" + name for name in routes)
                raise exceptions.VolatilityException(
                    f"--{public_name} is only valid with {allowed}; selected --{action}")
            overrides[routes[action]] = value
        if "limit" in overrides and not 1 <= overrides["limit"] <= 1000000:
            raise exceptions.VolatilityException("--limit must be in 1..1000000")
        return action, overrides

    def run(self):
        action, overrides = self.resolve_options(self.config)
        module_name, class_name = BACKENDS[action]
        try:
            module = importlib.import_module("volatility3.plugins." + module_name)
        except ImportError as exc:
            raise exceptions.VolatilityException(
                f"Cannot load --{action}: {module_name}.py and its dependencies must be in the plugin path: {exc}"
            ) from exc
        backend_class = getattr(module, class_name)
        config_path = interfaces.configuration.path_join(self.config_path, "analysis", action)
        overrides["kernel"] = self.config["kernel"]
        # Reinitialize native defaults on every invocation, even when the same
        # context/plugin instance is reused by a non-CLI caller.
        for requirement in backend_class.get_requirements():
            if isinstance(requirement, requirements.VersionRequirement):
                continue
            value = overrides.get(requirement.name, copy.deepcopy(requirement.default))
            self.context.config[interfaces.configuration.path_join(config_path, requirement.name)] = value
        # Only this analysis's component versions / architecture are required.
        failures = backend_class.unsatisfied(self.context, config_path)
        if failures:
            raise exceptions.VolatilityException(
                f"Requirements for --{action} are not satisfied: " + ", ".join(sorted(failures)))
        backend = backend_class(self.context, config_path, progress_callback=self._progress_callback)
        backend.set_open_method(self.open)
        return backend.run()

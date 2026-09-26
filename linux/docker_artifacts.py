"""Versioned collection API for Docker analyses and other Linux plugins.

Depend on ``DockerArtifacts`` with a ``VersionRequirement`` and call its
classmethods without constructing a plugin. Inputs identify one context,
kernel module and address space; callers never pass readers or kernel objects.
Addresses are absolute, not offsets relative to the relocated kernel module.

Task/FD iterators return Volatility objects owned by that same context, like
PsList. Other results contain ordinary Python values. No method renders output,
writes evidence, assigns a container identity or keeps a cross-call cache.
Single reads propagate failures. Traversals that retain partial results also
return their diagnostics; an empty partial result is not evidence of absence.
The private ``_artifacts`` package implements the individual reading policies.
"""

from __future__ import annotations

from collections.abc import Iterator
from typing import Any

from volatility3 import framework
from volatility3.framework import interfaces
from volatility3.framework.configuration import requirements
from volatility3.plugins.linux import pslist
from volatility3.plugins.linux._artifacts import cgroups as cgroup_readers
from volatility3.plugins.linux._artifacts import core as artifact_core
from volatility3.plugins.linux._artifacts import credentials as credential_readers
from volatility3.plugins.linux._artifacts import files as file_readers
from volatility3.plugins.linux._artifacts import namespaces as namespace_readers
from volatility3.plugins.linux._artifacts import tasks as task_readers


class DockerArtifacts(
    interfaces.configuration.VersionableInterface,
    interfaces.configuration.ConfigurableInterface,
):
    """Shared readers with a version independent of CLI/reporting backends.

    Changing method signatures, return structures or documented reading policies
    incompatibly requires a MAJOR bump. Compatible new methods require MINOR;
    implementation fixes require PATCH. Underscored helpers are not public API.
    """

    _version = (1, 1, 1)
    _required_framework_version = (2, 28, 0)

    @classmethod
    def get_requirements(cls) -> list[interfaces.configuration.RequirementInterface]:
        # VersionRequirement traverses dependencies only for ConfigurableInterface
        # components. This remains a collection API, not a discoverable plugin.
        return [
            requirements.VersionRequirement(
                name="pslist", component=pslist.PsList, version=(4, 0, 0)
            )
        ]

    @classmethod
    def _kernel(cls, context, kernel_module_name):
        # Classmethod users do not instantiate VersionableInterface, whose
        # constructor normally performs the framework compatibility check.
        framework.require_interface_version(*cls._required_framework_version)
        if not isinstance(kernel_module_name, str) or not kernel_module_name:
            raise ValueError("kernel_module_name must be a nonempty string")
        return context.modules[kernel_module_name]

    @classmethod
    def _positive_integer(cls, value, name):
        if type(value) is not int or value <= 0:
            raise ValueError(f"{name} must be a positive integer")

    @classmethod
    def _object(
        cls,
        context,
        kernel_module_name,
        type_name,
        address,
        layer_name=None,
        native_layer_name=None,
    ):
        cls._positive_integer(address, "address")
        for name, value in (
            ("layer_name", layer_name),
            ("native_layer_name", native_layer_name),
        ):
            if value is not None and (not isinstance(value, str) or not value):
                raise ValueError(f"{name} must be a nonempty string or None")
        kernel = cls._kernel(context, kernel_module_name)
        if layer_name is None and native_layer_name is None:
            return kernel.object(type_name, offset=address, absolute=True)
        # A scan can locate a task in a physical layer while its pointers still
        # refer to kernel virtual memory. Preserve both layers independently.
        return context.object(
            kernel.symbol_table_name + "!" + type_name,
            offset=address,
            layer_name=kernel.layer_name if layer_name is None else layer_name,
            native_layer_name=(
                kernel.layer_name if native_layer_name is None else native_layer_name
            ),
        )

    @classmethod
    def list_tasks(
        cls,
        context: interfaces.context.ContextInterface,
        kernel_module_name: str,
        *,
        include_threads: bool | None = None,
    ) -> Iterator[interfaces.objects.ObjectInterface]:
        """Use PsList discovery; None preserves its default thread policy.

        Does not scan for unlinked tasks, deduplicate by PID or suppress iterator
        failures. Consumers retain already yielded objects and record failures
        at their own collection boundary.
        """
        cls._kernel(context, kernel_module_name)
        if include_threads is not None and type(include_threads) is not bool:
            raise ValueError("include_threads must be bool or None")
        return task_readers.list_tasks(
            context, kernel_module_name, include_threads=include_threads
        )

    @classmethod
    def read_task_argv(
        cls,
        context: interfaces.context.ContextInterface,
        kernel_module_name: str,
        task_address: int,
        *,
        policy: str,
        limit: int | None = None,
        layer_name: str | None = None,
        native_layer_name: str | None = None,
    ) -> list[str]:
        """Read argv using an explicitly selected existing collection policy.

        presence: 64 KiB, strict UTF-8 and final NUL; missing mm is an error.
        network: 64 KiB, replacement decoding; missing mm returns an empty list.
        inventory: 16 MiB, replacement decoding and trailing NUL removal;
        missing mm returns an empty list. ``limit`` overrides only the byte cap.
        Unknown policies and nonpositive limits raise ValueError before reading.
        """
        if policy == "presence":
            selected = task_readers.PRESENCE_ARGV
        elif policy == "network":
            selected = task_readers.NETWORK_ARGV
        elif policy == "inventory":
            selected = task_readers.INVENTORY_ARGV
        else:
            raise ValueError("Unknown argv policy: " + str(policy))
        if limit is not None:
            cls._positive_integer(limit, "limit")
        task = cls._object(
            context,
            kernel_module_name,
            "task_struct",
            task_address,
            layer_name,
            native_layer_name,
        )
        return task_readers.read_argv(context, task, selected, limit=limit)

    @classmethod
    def inspect_pid_layout(
        cls,
        context: interfaces.context.ContextInterface,
        kernel_module_name: str,
    ) -> dict[str, Any]:
        """Describe the symbol-selected PID layout without reading a task.

        Returns feature/status/layout. Missing or inconsistent symbols raise a
        VolatilityException; no guessed PID field is selected.
        """
        return namespace_readers.inspect_pid_layout(
            cls._kernel(context, kernel_module_name)
        )

    @classmethod
    def read_pid_chain(
        cls,
        context: interfaces.context.ContextInterface,
        kernel_module_name: str,
        task_address: int,
        *,
        layer_name: str | None = None,
        native_layer_name: str | None = None,
    ) -> list[dict[str, int]]:
        """Return host-to-inner records containing level, id and namespace.

        id is the task's TID, not its process TGID. Flexible PID arrays and the
        host TID are validated; faults/inconsistent data raise rather than
        returning a shorter chain as though it were complete.
        """
        task = cls._object(
            context,
            kernel_module_name,
            "task_struct",
            task_address,
            layer_name,
            native_layer_name,
        )
        return namespace_readers.read_pid_chain(
            task, cls._kernel(context, kernel_module_name)
        )

    @classmethod
    def audit_task_list(
        cls,
        context: interfaces.context.ContextInterface,
        kernel_module_name: str,
        head_address: int,
        *,
        limit: int = 100000,
    ) -> dict[str, Any]:
        """Audit a kernel-virtual list_head in both directions, masking links.

        Returns head, directions, issues, forward_only, backward_only and
        status (CONSISTENT/PARTIAL). Direction records hold nodes, closed and
        count. Node addresses refer to list links, not containing task_structs.
        Readable prefixes and reverse-only links survive traversal faults.
        """
        cls._positive_integer(head_address, "head_address")
        cls._positive_integer(limit, "limit")
        kernel = cls._kernel(context, kernel_module_name)
        mask = context.layers[kernel.layer_name].address_mask

        def read_link(address, field):
            link = kernel.object("list_head", offset=address, absolute=True)
            return int(link.member(field)) & mask

        return task_readers.audit_task_list(head_address & mask, read_link, limit=limit)

    @classmethod
    def read_cgroup_memberships(
        cls,
        context: interfaces.context.ContextInterface,
        kernel_module_name: str,
        task_address: int,
        *,
        layer_name: str | None = None,
        native_layer_name: str | None = None,
    ) -> tuple[tuple[dict[str, Any], ...], tuple[str, ...]]:
        """Return (memberships, issues) from actual v1/v2 task membership.

        Each record has version, controllers, path and cgroup_address. Issues
        are sorted diagnostic strings; any issue means partial recovery.
        Effective subsystem references alone are not authoritative membership.
        Container ID recognition and conflict decisions remain with consumers.
        """
        task = cls._object(
            context,
            kernel_module_name,
            "task_struct",
            task_address,
            layer_name,
            native_layer_name,
        )
        issues = set()
        memberships = cgroup_readers.read_link_memberships(task, issues)
        records = tuple(
            {
                "version": member.version,
                "controllers": member.controllers,
                "path": member.path,
                "cgroup_address": member.cgroup_address,
            }
            for member in memberships
        )
        return records, tuple(sorted(issues))

    @classmethod
    def read_cgroup_chain(
        cls,
        context: interfaces.context.ContextInterface,
        kernel_module_name: str,
        cgroup_address: int,
        *,
        limit: int = 128,
        parent_field: str | None = None,
    ) -> list[dict[str, Any]]:
        """Return the root-to-leaf cgroup chain, without Docker attribution.

        cgroup_address is kernel-virtual. Cycles, unreadable names and budget
        exhaustion raise; a truncated path must not become an identity source.
        parent_field is None (layout selection), 'parent' or '__parent'.
        """
        cls._positive_integer(limit, "limit")
        if parent_field not in (None, "parent", "__parent"):
            raise ValueError("Unsupported kernfs parent field")
        group = cls._object(context, kernel_module_name, "cgroup", cgroup_address)
        return cgroup_readers.read_cgroup_chain(
            group, limit=limit, parent_field=parent_field
        )

    @classmethod
    def read_file_descriptors(
        cls,
        context: interfaces.context.ContextInterface,
        kernel_module_name: str,
        task_address: int,
        *,
        limit: int = 65536,
        layer_name: str | None = None,
        native_layer_name: str | None = None,
    ) -> tuple[list[tuple[int, interfaces.objects.ObjectInterface]], dict[str, int]]:
        """Return (fd/file-pointer pairs, issue counts), preserving partial tables.

        The cap counts slots, not open descriptors. Closed/unreadable first slots
        do not hide later descriptors. Issues include skipped slots and unreadable
        tables; consumers must retain them even when the entries list is empty.
        """
        evidence = cls.read_file_descriptor_evidence(
            context,
            kernel_module_name,
            task_address,
            limit=limit,
            layer_name=layer_name,
            native_layer_name=native_layer_name,
        )
        return evidence["entries"], evidence["issues"]

    @classmethod
    def read_file_descriptor_evidence(
        cls,
        context: interfaces.context.ContextInterface,
        kernel_module_name: str,
        task_address: int,
        *,
        limit: int = 65536,
        layer_name: str | None = None,
        native_layer_name: str | None = None,
    ) -> dict[str, Any]:
        """Return entries, issue counts and diagnostics with FD/fault provenance.

        Diagnostic messages retain causal exceptions and memory layer/addresses.
        A failed slot is omitted from entries and does not stop later slots.
        """
        cls._positive_integer(limit, "limit")
        if limit > file_readers.MAX_FDS:
            raise ValueError("limit exceeds the supported FD table bound")
        task = cls._object(
            context,
            kernel_module_name,
            "task_struct",
            task_address,
            layer_name,
            native_layer_name,
        )
        diagnostics = []
        entries, issues = file_readers.read_fds(
            context, kernel_module_name, task, limit=limit, diagnostics=diagnostics
        )
        return {"entries": entries, "issues": dict(issues), "diagnostics": diagnostics}

    @classmethod
    def read_credentials(
        cls,
        context: interfaces.context.ContextInterface,
        kernel_module_name: str,
        credential_address: int,
        *,
        include_identity: bool = False,
    ) -> dict[str, Any]:
        """Read a kernel-virtual cred into credentials and reader_observations.

        Field observations preserve unsupported/partial reads. Setting
        include_identity adds UID/GID mappings and groups. This reads one cred;
        it neither infers configured Docker privileges nor scans task memory.
        An identity-enrichment failure is recorded without discarding already
        read credentials. A private reader/cache exists only for this call.
        """
        if type(include_identity) is not bool:
            raise ValueError("include_identity must be bool")
        kernel = cls._kernel(context, kernel_module_name)
        cred = cls._object(context, kernel_module_name, "cred", credential_address)
        reader = credential_readers.SecurityReader(context, kernel)
        result = reader.credentials(cred)
        if include_identity:
            try:
                reader.enrich_identity(result, cred)
            except Exception as exc:  # noqa: BLE001 - Record the failure and preserve independent evidence.
                result["observations"].append(
                    {
                        "feature": "credentials.identity",
                        "status": "read_error",
                        "reason": artifact_core.exception_text(exc),
                    }
                )
        return {"credentials": result, "reader_observations": reader.observations}

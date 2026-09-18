# SPDX-License-Identifier: MIT
# Includes readers by the container-mounts contributors (c) 2026.
"""Cgroup readers with separate effective-CSS and membership-link strategies.

These strategies intentionally retain different coverage and error contracts.
Marker interpretation is supplied by the caller, not inferred by a reader.
"""
from dataclasses import dataclass
from enum import Enum
import logging
from typing import Dict, List, Tuple
from volatility3.framework import exceptions
from volatility3.framework.objects import utility
from .core import (Unsupported, Incomplete, UnsupportedLayoutError, require_fields,
                   _object_address, _object_readable, _read_kernel_cstring)

# Preserve the diagnostic channel consumed by existing mount logs.
vollog = logging.getLogger('volatility3.plugins.inspect_mount')

@dataclass(frozen=True)
class CgroupMembership:
    """One task membership in a cgroup v1 or v2 hierarchy."""

    version: str
    controllers: Tuple[str, ...]
    path: str
    cgroup_address: int

    def display(self) -> str:
        owner = ",".join(self.controllers) if self.controllers else "unified"
        return f"{self.version}:{owner}={self.path}"


def _cgroup_path(cgroup) -> str:
    """Return a full kernfs path, or no path when ancestry is incomplete.

    A NULL parent is a terminator only at cgroup.root.cgrp.kn.  In particular,
    an unreadable parent is not a root and must not turn a suffix into an
    apparently absolute path.  kernfs used ``parent`` before ``__parent``.
    """

    try:
        if (
            not cgroup
            or not _object_readable(cgroup)
            or not cgroup.has_member("kn")
            or not cgroup.kn
            or not _object_readable(cgroup.kn)
        ):
            return ""
        node = cgroup.kn.dereference()
        root_node = cgroup.root.cgrp.kn
        if not root_node or not _object_readable(root_node):
            raise ValueError("unreadable hierarchy root kernfs node")
        root_address = _object_address(root_node)
    except (AttributeError, TypeError, ValueError, exceptions.InvalidAddressException):
        vollog.warning("Incomplete cgroup path: hierarchy root/node is unavailable")
        return ""

    parts: List[str] = []
    seen = set()
    for _ in range(256):
        try:
            address = _object_address(node)
            if address in seen:
                raise ValueError("cyclic kernfs ancestry")
            seen.add(address)
            parent_member = "__parent" if node.has_member("__parent") else "parent"
            parent = node.member(parent_member)
            if address == root_address:
                if parent:
                    raise ValueError("hierarchy root has a non-NULL parent")
                return "/" + "/".join(reversed(parts))
            if not parent or not _object_readable(parent):
                raise ValueError("kernfs ancestry ended before hierarchy root")
            name = _read_kernel_cstring(node.name, max_bytes=256)
            # kernfs names are individual components, at most NAME_MAX bytes.
            # Never normalize corrupt names into a different valid path.
            if not name or len(name) >= 256 or "/" in name or name in {".", ".."}:
                raise ValueError("invalid or truncated kernfs name")
            parts.append(name)
            node = parent.dereference()
        except (
            AttributeError,
            TypeError,
            exceptions.InvalidAddressException,
            ValueError,
        ) as exc:
            vollog.warning("Incomplete cgroup path: %s", exc)
            return ""
    vollog.warning("Incomplete cgroup path: kernfs ancestry exceeds 256 nodes")
    return ""


def _cgroup_hierarchy(cgroup, default_root_address=None):
    """Identify a hierarchy by its root, never by its effective CSS address.

    The default (v2) hierarchy owns hierarchy ID 0.  All active legacy roots
    have positive IDs.  Unknown or inconsistent metadata is not called v1.
    """

    if not cgroup or not _object_readable(cgroup):
        raise ValueError("unreadable cgroup")
    root = cgroup.root
    if not root or not _object_readable(root):
        raise ValueError("unreadable cgroup hierarchy root")
    root_address = _object_address(root)
    hierarchy_id = int(root.hierarchy_id)
    if hierarchy_id < 0:
        raise ValueError("invalid cgroup hierarchy ID")
    is_default = hierarchy_id == 0
    if default_root_address is not None and (
        is_default != (root_address == default_root_address)
    ):
        raise ValueError("inconsistent cgroup default hierarchy root/ID")
    return ("v2" if is_default else "v1"), root_address, root, hierarchy_id


def _linked_cgroups(css_set, issues):
    """Walk actual cgroup memberships, including controllerless v1 roots.

    Volatility's generic list walker silently terminates on unreadable links.
    This bounded walk reports that distinction and validates link ownership.
    """

    groups = []
    try:
        head = css_set.cgrp_links
        context = head._context
        type_name = head.vol.type_name.split("!", 1)[0] + "!cgrp_cset_link"
        offset = context.symbol_space.get_type(type_name).relative_child_offset(
            "cgrp_link"
        )
        head_address = _object_address(head)
        previous = head_address
        link_pointer = head.next
        seen = {head_address}
        for _ in range(4096):
            link_address = _object_address(link_pointer)
            if link_address == head_address:
                if _object_address(head.prev) != previous:
                    raise ValueError("cgrp_links tail disagrees with forward walk")
                return groups, True
            if not link_pointer or not _object_readable(link_pointer):
                raise ValueError("unreadable cgrp_links entry")
            if link_address in seen:
                raise ValueError("cyclic cgrp_links outside list head")
            seen.add(link_address)
            link = context.object(
                type_name, layer_name=head.vol.layer_name,
                offset=link_address - offset,
            )
            if _object_address(link.cset) != _object_address(css_set):
                raise ValueError("cgrp_links entry points to another css_set")
            if _object_address(link.cgrp_link.prev) != previous:
                raise ValueError("cgrp_links backlink mismatch")
            groups.append(link.cgrp)
            previous = link_address
            link_pointer = link.cgrp_link.next
        raise ValueError("cgrp_links exceeds 4096 entries")
    except (
        AttributeError, KeyError, TypeError, ValueError,
        exceptions.SymbolError, exceptions.InvalidAddressException,
    ) as exc:
        issues.add(f"membership list incomplete ({type(exc).__name__}: {exc})")
        return groups, False


def _cgroup_memberships(task, issues_out=None) -> Tuple[CgroupMembership, ...]:
    """Read actual memberships; effective v2 ancestor CSSes are not v1.

    cgrp_links is authoritative across hierarchies, dfl_cgrp is the actual v2
    membership, and subsys[] provides legacy controller names.  A subsys-only
    fallback is accepted solely with a proven v1 root when links are missing.
    Paths are absolute in their hierarchy, not cgroup-namespace-relative.
    issues_out, when supplied, receives stable partial/conflict markers as
    well as diagnostics so callers cannot promote incomplete IDs to verified.
    """

    issues = set()

    def report_issues():
        if not issues:
            return
        issues.add("cgroup-metadata-partial")
        if issues_out is not None:
            issues_out.update(issues)
        try:
            pid = int(task.pid)
        except (AttributeError, TypeError, ValueError, exceptions.InvalidAddressException):
            pid = "?"
        vollog.warning("Incomplete cgroup metadata for PID %s: %s", pid, "; ".join(sorted(issues)))

    try:
        css_set = task.cgroups
        if not css_set or not _object_readable(css_set):
            raise ValueError("missing or unreadable css_set")
    except (AttributeError, TypeError, ValueError, exceptions.InvalidAddressException) as exc:
        issues.add(f"task cgroup metadata unavailable ({exc})")
        report_issues()
        return ()

    default_root_address = None
    groups, links_complete = _linked_cgroups(css_set, issues)
    unified_cgroup = None
    try:
        if css_set.has_member("dfl_cgrp") and css_set.dfl_cgrp:
            unified_cgroup = css_set.dfl_cgrp
            version, root_address, _, _ = _cgroup_hierarchy(unified_cgroup)
            if version != "v2":
                raise ValueError("dfl_cgrp does not belong to hierarchy 0")
            default_root_address = root_address
            groups.append(unified_cgroup)
    except (AttributeError, TypeError, ValueError, exceptions.InvalidAddressException) as exc:
        issues.add(f"default membership unavailable ({exc})")

    # One css_set must have one actual membership per hierarchy.  Reject a
    # conflicting root entirely, rather than choosing the first ID/path.
    entries: Dict[int, Dict[str, object]] = {}
    conflicting_roots = set()
    def add_group(cgroup):
        version, root_address, root, hierarchy_id = _cgroup_hierarchy(
            cgroup, default_root_address
        )
        address = _object_address(cgroup)
        if root_address in entries and entries[root_address]["address"] != address:
            conflicting_roots.add(root_address)
            issues.add("cgroup-id-conflict")
            issues.add("multiple memberships in the same hierarchy")
            return
        entries.setdefault(root_address, {
            "version": version, "root": root, "hierarchy_id": hierarchy_id,
            "address": address, "cgroup": cgroup, "controllers": set(),
        })

    for cgroup in groups:
        try:
            add_group(cgroup)
        except (AttributeError, TypeError, ValueError, exceptions.InvalidAddressException) as exc:
            issues.add(f"hierarchy unavailable ({exc})")

    try:
        subsystems = css_set.subsys if css_set.has_member("subsys") else ()
        subsystem_count = len(subsystems)
    except (AttributeError, TypeError, exceptions.InvalidAddressException):
        subsystems = ()
        subsystem_count = 0
        issues.add("controller array unreadable")
    if subsystem_count > 256:
        issues.add("controller array exceeds 256 entries")
    for index in range(min(subsystem_count, 256)):
        try:
            css_pointer = subsystems[index]
            if not css_pointer:
                continue
            if not _object_readable(css_pointer):
                raise ValueError("unreadable controller state")
            css = css_pointer.dereference()
            cgroup = css.cgroup
            version, root_address, _, _ = _cgroup_hierarchy(
                cgroup, default_root_address
            )
            # v2 effective CSS may belong to any ancestor of dfl_cgrp.  Its
            # address differs from the membership without becoming a v1 root.
            if version == "v2":
                continue
            if root_address not in entries:
                if links_complete:
                    issues.add("controller hierarchy absent from membership list")
                    continue
                add_group(cgroup)
            entry = entries[root_address]
            if entry["address"] != _object_address(cgroup):
                conflicting_roots.add(root_address)
                issues.add("cgroup-id-conflict")
                issues.add("legacy controller disagrees with actual membership")
                continue
            controller = f"subsys-{index}"
            if css.has_member("ss") and css.ss and _object_readable(css.ss):
                subsystem = css.ss.dereference()
                field = "legacy_name" if subsystem.has_member("legacy_name") and subsystem.legacy_name else "name"
                if subsystem.has_member(field) and subsystem.member(field):
                    controller = _read_kernel_cstring(subsystem.member(field), max_bytes=64)
            if not controller or len(controller) >= 64:
                raise ValueError("invalid controller name")
            entry["controllers"].add(controller)
        except (
            AttributeError,
            IndexError,
            TypeError,
            ValueError,
            exceptions.InvalidAddressException,
        ) as exc:
            issues.add(f"controller {index} unavailable ({exc})")

    memberships: List[CgroupMembership] = []
    for root_address, entry in sorted(entries.items()):
        if root_address in conflicting_roots:
            continue
        path = _cgroup_path(entry["cgroup"])
        if not path:
            issues.add("one or more hierarchy paths incomplete")
            continue
        if entry["version"] == "v1":
            try:
                root = entry["root"]
                if root.has_member("name"):
                    name = utility.array_to_string(root.name)
                    if name:
                        entry["controllers"].add("name=" + name)
            except (AttributeError, TypeError, ValueError, exceptions.InvalidAddressException):
                issues.add("legacy hierarchy name unreadable")
            if not entry["controllers"]:
                entry["controllers"].add(f"hierarchy-{entry['hierarchy_id']}")
        memberships.append(
            CgroupMembership(
                version=str(entry["version"]),
                controllers=tuple(sorted(entry["controllers"])),
                path=path,
                cgroup_address=int(entry["address"]),
            )
        )
    # Keep the internal default-root membership even alongside v1.  '/' alone
    # cannot distinguish a visible hybrid v2 root from an unused default root;
    # this output does not infer which cgroup filesystems were mounted.
    report_issues()
    return tuple(memberships)


def read_cgroup_chain(start, limit=128, parent_field=None):
    """Follow CSS parents and cross-check every kernfs parent link."""
    # CSS와 kernfs의 부모 연결을 함께 대조해 경로 복원의 모순을 드러낸다.
    # 깨진 연결·순환을 만나면 불완전한 경로로 컨테이너를 추정하지 않는다.
    current, seen, chain = start, set(), []
    while current is not None:
        address = int(current.vol.offset)
        if address in seen:
            raise ValueError('Cycle in cgroup parent chain')
        if len(seen) >= limit:
            raise ValueError('cgroup parent chain exceeds limit')
        seen.add(address)
        if not int(current.kn):
            raise ValueError('cgroup.kn: null kernfs node')
        node = current.kn.dereference()
        if int(current.self.cgroup) != address:
            raise ValueError('cgroup.self.cgroup and containing cgroup disagree')
        css_parent = current.self.parent
        parent = None
        if int(css_parent):
            parent_css = css_parent.dereference()
            if not int(parent_css.cgroup):
                raise ValueError('Parent CSS has a null cgroup pointer')
            parent = parent_css.cgroup.dereference()
        name = utility.pointer_to_string(node.name, 256, errors='strict') if int(node.name) else ''
        if parent is None and name == '/':
            name = ''
        if '/' in name or '\x00' in name or len(name.encode('utf-8')) > 255:
            raise ValueError('Invalid or truncated cgroup component name')
        if parent is not None and not name:
            raise ValueError('Empty non-root cgroup component')
        selected_parent = parent_field
        if selected_parent is None:
            selected_parent = 'parent' if node.has_member('parent') else '__parent' if node.has_member('__parent') else None
        if selected_parent is None or not node.has_member(selected_parent):
            raise ValueError('kernfs_node.parent|__parent: unsupported kernfs parent layout')
        expected_parent = int(parent.kn) if parent is not None else 0
        if int(node.member(selected_parent)) != expected_parent:
            raise ValueError('cgroup CSS parent and kernfs parent disagree')
        chain.append({'address': hex(address), 'kernfs': hex(int(node.vol.offset)), 'name': name})
        current = parent
    # 순회는 말단→루트지만 반환은 루트→말단이다. 경로 조립과 표식 선택은 이 순서를 쓴다.
    return list(reversed(chain))


class CgroupV2Resolver:
    """Resolve task membership for reuse by capabilities/state/file plugins.

    Offsets come from the supplied kernel symbols. Failed reads raise errors;
    a successfully read path without a supported marker returns group=None.
    """
    def __init__(self, kernel_module, identify):
        self.identify = identify
        feature = 'container_membership'
        required = {
            'task_struct': ('cgroups',),
            'css_set': ('dfl_cgrp',),
            'cgroup': ('kn', 'self'),
            'cgroup_subsys_state': ('parent', 'cgroup'),
            'kernfs_node': ('name',),
        }
        templates = {name: require_fields(kernel_module, name, fields, feature)
                     for name, fields in required.items()}
        node = templates['kernfs_node']
        self.parent_field = 'parent' if node.has_member('parent') else '__parent' if node.has_member('__parent') else None
        if self.parent_field is None:
            raise UnsupportedLayoutError(feature, 'kernfs_node.parent|__parent', 'no supported kernfs parent member')
        self.compatibility = {
            'feature': feature, 'status': 'ok',
            'layout': {
                'hierarchy': 'cgroup-v2',
                'task_cgroups': 'task_struct.cgroups',
                'default_cgroup': 'css_set.dfl_cgrp',
                'css_parent': 'cgroup.self.parent.cgroup',
                'kernfs_parent': 'kernfs_node.' + self.parent_field,
            },
        }
        self.cache = {}

    def resolve(self, task):
        if not int(task.cgroups):
            raise ValueError('task_struct.cgroups: null css_set pointer')
        cset = task.cgroups.dereference()
        if not int(cset.dfl_cgrp):
            raise ValueError('css_set.dfl_cgrp: null default cgroup pointer')
        cgroup = cset.dfl_cgrp.dereference()
        address = int(cgroup.vol.offset)
        # 경로 문자열이나 컨테이너 ID가 같아도 서로 다른 cgroup 객체의 결과를 섞지 않는다.
        if address not in self.cache:
            # 전체 경로를 성공적으로 읽은 뒤에만 캐시해 일시적인 읽기 실패를 숨기지 않는다.
            chain = read_cgroup_chain(cgroup, parent_field=self.parent_field)
            self.cache[address] = (chain, self.identify(chain))
        chain, group = self.cache[address]
        # 앞의 두 값은 Volatility 객체, chain/group은 보고서용 값이다. 표식이 없으면 group=None.
        return cset, cgroup, chain, group


class CgroupLinksResolver:
    """Read actual memberships across known kernfs-based v1/v2 hierarchies.

    css_set.subsys can point to ancestors and omits controller-less hierarchies.
    Use cgrp_links instead, validating ownership and both directions of the list.
    """
    def __init__(self, module, identify):
        self.identify = identify
        feature = 'container_membership'
        fields = {'task_struct': ('cgroups',), 'css_set': ('cgrp_links',),
                  'cgrp_cset_link': ('cgrp', 'cset', 'cgrp_link'),
                  'cgroup': ('kn', 'self', 'root'), 'cgroup_root': ('hierarchy_id',),
                  'cgroup_subsys_state': ('parent', 'cgroup'),
                  'kernfs_node': ('name',), 'list_head': ('next', 'prev')}
        types = {name: require_fields(module, name, names, feature) for name, names in fields.items()}
        node = types['kernfs_node']
        self.parent_field = 'parent' if node.has_member('parent') else '__parent' if node.has_member('__parent') else None
        if self.parent_field is None:
            raise UnsupportedLayoutError(feature, 'kernfs_node.parent|__parent', 'unsupported parent layout')
        self.link_offset = types['cgrp_cset_link'].relative_child_offset('cgrp_link')
        if not 0 <= self.link_offset < types['cgrp_cset_link'].size:
            raise ValueError('Invalid cgrp_cset_link.cgrp_link offset in symbols')
        self.module, self.cache = module, {}
        self.compatibility = {'feature': feature, 'status': 'ok', 'layout': {
            'hierarchy': 'cgroup-v1/v2-kernfs', 'task_cgroups': 'task_struct.cgroups',
            'membership_links': 'css_set.cgrp_links -> cgrp_cset_link.cgrp',
            'css_parent': 'cgroup.self.parent.cgroup',
            'kernfs_parent': 'kernfs_node.' + self.parent_field}}

    def resolve(self, task):
        if not int(task.cgroups):
            raise ValueError('task_struct.cgroups: null css_set pointer')
        cset = task.cgroups.dereference()
        address = int(cset.vol.offset)
        if address not in self.cache:
            head = cset.cgrp_links
            head_address = int(head.vol.offset)
            previous, current = head_address, int(head.next)
            seen, entries, evidence = set(), [], []
            while current != head_address:
                if not current or current in seen or len(seen) >= 256:
                    raise ValueError('Broken, cyclic or oversized css_set.cgrp_links list')
                seen.add(current)
                link = self.module.object('cgrp_cset_link', offset=current - self.link_offset, absolute=True)
                if int(link.cgrp_link.vol.offset) != current or int(link.cgrp_link.prev) != previous:
                    raise ValueError('cgrp_links forward/backward links disagree')
                if int(link.cset) != address or not int(link.cgrp):
                    raise ValueError('cgrp_cset_link owner or cgroup pointer disagrees')
                cgroup = link.cgrp.dereference()
                chain = read_cgroup_chain(cgroup, parent_field=self.parent_field)
                if not int(cgroup.root):
                    raise ValueError('cgroup.root: null hierarchy pointer')
                hierarchy = int(cgroup.root.dereference().hierarchy_id)
                if hierarchy < 0:
                    raise ValueError('Negative cgroup hierarchy ID')
                group = self.identify(chain)
                evidence.append({'hierarchy_id': hierarchy, 'hierarchy': 'v2' if hierarchy == 0 else 'v1',
                                 'cgroup_address': hex(int(cgroup.vol.offset)),
                                 'chain': chain, 'docker_marker': group})
                entries.append((hierarchy, cgroup, chain, group))
                previous, current = current, int(link.cgrp_link.next)
            if int(head.prev) != previous or not entries:
                raise ValueError('Incomplete or empty css_set.cgrp_links list')
            if len({entry[0] for entry in entries}) != len(entries):
                raise ValueError('Multiple cgroup memberships in the same hierarchy')
            matches = [entry for entry in entries if entry[3] is not None]
            if len({entry[3]['id'] for entry in matches}) > 1:
                error = ValueError('Docker markers disagree across cgroup hierarchies')
                error.membership_evidence = evidence
                raise error
            # 같은 Docker ID라도 각 계층의 근거는 모두 보존한다. 기본 계층(0)을 우선해
            # 기존 v2의 루트 주소를 유지하고, v1-only에서는 계층 ID 순서로 대표를 고른다.
            _, cgroup, chain, group = min(matches or entries, key=lambda entry: entry[0])
            if group is not None:
                group = dict(group, membership_evidence=evidence)
            self.cache[address] = (cgroup, chain, group)
        cgroup, chain, group = self.cache[address]
        return cset, cgroup, chain, group


def membership_resolver(module, identify):
    # 두 판독기는 심볼 구조로 선택한다. 타입이 없는 경우만 대안을 시도하며,
    # 선택한 판독기의 실제 메모리 오류를 다른 경로의 성공으로 덮지 않는다.
    try:
        return CgroupLinksResolver(module, identify)
    except (UnsupportedLayoutError, AttributeError, KeyError) as exc:
        resolver = CgroupV2Resolver(module, identify)
        if resolver.compatibility.get('layout', {}).get('hierarchy') == 'cgroup-v2':
            resolver.compatibility['coverage'] = 'default_hierarchy_only'
            resolver.compatibility['unavailable_reader'] = str(exc)
        return resolver


def effective_cgroups(css, *, states=iter, read=None):
    """Read dfl_cgrp/subsys references; these are not all authoritative memberships.

The caller chooses fail-fast iteration or per-field diagnostic isolation.
Order and address-based deduplication match the original readers.
"""
    groups = {}

    def default_group():
        if css.has_member('dfl_cgrp') and css.dfl_cgrp:
            groups[int(css.dfl_cgrp)] = css.dfl_cgrp.dereference()

    if read is None:
        default_group()
    else:
        read('cgroup.default', css, default_group)
    if css.has_member('subsys'):
        for index, state in enumerate(states(css.subsys)):
            def subsystem():
                if state and state.cgroup:
                    groups[int(state.cgroup)] = state.cgroup.dereference()
            if read is None:
                subsystem()
            else:
                read('cgroup.subsys.' + str(index), css, subsystem)
    return list(groups.values())


class CgroupPathPolicy(Enum):
    INVENTORY = 'inventory'
    NETWORK = 'network'


def effective_cgroup_path(group, string, limit, *, policy, location=None):
    """Follow legacy/kernfs ancestry with the caller's established path policy.

    Inventory paths retain address traces and the legacy CSS parent fallback.
    Network paths retain their own name_copy and parent precedence semantics.
"""
    inventory = policy is CgroupPathPolicy.INVENTORY
    if policy not in (CgroupPathPolicy.INVENTORY, CgroupPathPolicy.NETWORK):
        raise ValueError('Unknown cgroup path policy')
    if inventory and location is None:
        raise ValueError('Inventory paths require a location reader')
    modern = group.has_member('kn')
    if modern and not group.kn:
        if inventory:
            raise ValueError('NULL kernfs node')
        raise ValueError('cgroup has NULL kernfs node')
    node = group.kn.dereference() if modern else group
    parts, seen, trace = [], set(), []
    while node or not inventory:
        address = int(node.vol.offset)
        if inventory:
            if address in seen or len(seen) >= limit:
                raise Incomplete('cgroup parent cycle/budget')
        else:
            if address in seen:
                raise ValueError('cgroup parent cycle')
            if len(seen) >= limit:
                raise ValueError('cgroup path budget exceeded')
        seen.add(address)
        if modern and not inventory:
            parts.append(string(node.name))
        elif node.has_member('name'):
            parts.append(string(node.name))
        elif node.has_member('name_copy') and (inventory or node.name_copy):
            parts.append(string(node.name_copy) if inventory else utility.array_to_string(node.name_copy.name))
        else:
            raise (Unsupported if inventory else NotImplementedError)('cgroup name layout unavailable')
        if inventory:
            parent = node.member('__parent') if node.has_member('__parent') else node.parent if node.has_member('parent') else node.self.parent.cgroup if not modern and node.self.parent else None
            trace.append({'location': location(node), 'name': parts[-1], 'parent': hex(int(parent)) if parent else '0x0'})
        else:
            parent = node.parent if node.has_member('parent') else node.member('__parent')
        if not parent:
            break
        node = parent.dereference()
    return '/' + '/'.join(p for p in reversed(parts) if p), trace

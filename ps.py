"""Docker process and residual-artifact inventory for stock Volatility 3.

Deploy this file in a plugin directory and run ``ps.Ps --ps``. No files in
Volatility's installation are replaced. All six ANALYSIS.md discovery paths
run regardless of whether a container task was found. ps_evidence.json keeps
raw observations, addresses, conflicts, coverage, and the artifact vector.

Runtime heap results are structurally validated candidates, not proof that a
ContainerStore/GC root still owns the object. Docker lifecycle labels are not
inferred from scheduler or cgroup flags. Bounds are reported as partial scans.

Usage (stock Volatility 3 >= 2.28.0; use a matching, schema-valid Linux ISF):
    vol --offline -p /path/to/plugins -s /path/to/symbols -f memory.lime \
        -o /path/to/results ps.Ps --ps

Console rows pair each host PID with its namespace PID. A container with only
residual evidence has no process PID. Complete command lines, threads, raw
cache pages/Go objects, field addresses, and 102 artifact statuses are kept in
ps_evidence.json. Configured Privileged is recovered Docker configuration;
effective capabilities are independently observed, never a privileged verdict.
Overlay layer paths use verified ISF/live BTF types and retain their path scope.
Task and thread lists are audited in both directions; damaged lists stay partial.
Heap scanning supports verified little-endian Go 64-bit reflection layouts;
other layouts and nonresident memory are explicitly partial/unsupported.
"""

import base64
import bisect
import datetime
import hashlib
import json
import logging
import re
import struct
import time

from volatility3.framework import constants, exceptions, interfaces, objects, renderers
from volatility3.framework.configuration import requirements
from volatility3.framework.objects import utility
from volatility3.framework.symbols import linux

vollog = logging.getLogger(__name__)
LIMIT = 100000
FILE_LIMIT = 16 * 1024 * 1024
HEAP_LIMIT = 512 * 1024 * 1024
CID = re.compile(r"[0-9a-f]{64}\Z")
CGROUP_ID = re.compile(r"/(?:docker/|docker-)([0-9a-f]{64})(?:\.scope)?(?=/|$)")
FILE_ID = re.compile(r"(?:^|/)containers/([0-9a-f]{64})/(config\.v2\.json|hostconfig\.json)\Z")
UTC = datetime.timezone.utc
STAGES = ("tasks", "namespaces", "cgroups", "mounts", "page_cache", "runtime")


ARTIFACT_CATALOG = [
    (1, 'task_struct', 'tasks'),
    (2, 'task_struct.pid', 'tasks'),
    (3, 'task_struct.tgid', 'tasks'),
    (4, 'task_struct.comm', 'tasks'),
    (5, 'task_struct.__state', 'tasks'),
    (6, 'task_struct.exit_state', 'tasks'),
    (7, 'task_struct.exit_code', 'tasks'),
    (8, 'task_struct.flags', 'tasks'),
    (9, 'task_struct.mm', 'tasks'),
    (10, 'task_struct.group_leader', 'tasks'),
    (11, 'task_struct.parent', 'tasks'),
    (12, 'task_struct.real_parent', 'tasks'),
    (13, 'thread_pid', 'tasks'),
    (14, 'struct pid', 'tasks'),
    (15, 'pid.level', 'tasks'),
    (16, 'pid.numbers[]', 'tasks'),
    (17, 'numbers[0].nr', 'tasks'),
    (18, 'numbers[level].nr', 'tasks'),
    (19, 'numbers[level].ns', 'tasks'),
    (20, 'nsproxy', 'namespaces'),
    (21, 'mnt_ns', 'namespaces'),
    (22, 'Mount Namespace ID', 'namespaces'),
    (23, 'uts_ns', 'namespaces'),
    (24, 'UTS Namespace ID', 'namespaces'),
    (25, 'ipc_ns', 'namespaces'),
    (26, 'IPC Namespace ID', 'namespaces'),
    (27, 'net_ns', 'namespaces'),
    (28, 'Network Namespace ID', 'namespaces'),
    (29, 'cgroup_ns', 'namespaces'),
    (30, 'Cgroup Namespace ID', 'namespaces'),
    (31, 'PID Namespace ID', 'namespaces'),
    (32, 'Namespace 공유 관계', 'namespaces'),
    (33, 'Default Cgroup Root', 'cgroups'),
    (34, 'struct cgroup', 'cgroups'),
    (35, 'populated 관련 값', 'cgroups'),
    (36, 'frozen 관련 값', 'cgroups'),
    (37, 'dying 관련 값', 'cgroups'),
    (38, 'self/css', 'cgroups'),
    (39, 'kernfs_node', 'cgroups'),
    (40, 'kernfs_node.name', 'cgroups'),
    (41, 'kernfs_node.__parent', 'cgroups'),
    (42, 'Parent Chain', 'cgroups'),
    (43, 'Cgroup Path', 'cgroups'),
    (44, 'Container ID', 'cgroups'),
    (45, 'Task-Cgroup association', 'cgroups'),
    (46, 'Task 없는 Cgroup 여부', 'cgroups'),
    (47, 'Mount Namespace / Mount Tree', 'mounts'),
    (48, 'struct mount', 'mounts'),
    (49, 'vfsmount', 'mounts'),
    (50, 'mount root', 'mounts'),
    (51, 'super_block', 'mounts'),
    (52, 'filesystem type', 'mounts'),
    (53, 'dentry', 'mounts'),
    (54, 'Dentry Path', 'mounts'),
    (55, 'inode', 'mounts'),
    (56, 'Overlay FS', 'mounts'),
    (57, 'Overlay 관련 경로', 'mounts'),
    (58, 'rootfs', 'mounts'),
    (59, 'Container Path', 'mounts'),
    (60, 'Layer 정보', 'mounts'),
    (61, 'Cached Docker File', 'page_cache'),
    (62, 'config.v2.json', 'page_cache'),
    (63, 'hostconfig.json', 'page_cache'),
    (64, 'Cached file path', 'page_cache'),
    (65, 'Cached file inode', 'page_cache'),
    (66, 'address_space', 'page_cache'),
    (67, 'Cached Page', 'page_cache'),
    (68, 'Recovered File Content', 'page_cache'),
    (69, 'JSON Parsing 상태', 'page_cache'),
    (70, 'Container ID', 'page_cache'),
    (71, 'State 관련 값', 'page_cache'),
    (72, 'PID 관련 값', 'page_cache'),
    (73, 'Timestamp', 'page_cache'),
    (74, '기타 설정값', 'page_cache'),
    (75, 'dockerd process', 'runtime'),
    (76, 'containerd process', 'runtime'),
    (77, 'containerd-shim-runc-v2', 'runtime'),
    (78, 'Container Process', 'runtime'),
    (79, 'PID', 'runtime'),
    (80, 'PPID', 'runtime'),
    (81, 'comm', 'runtime'),
    (82, 'Process Tree', 'runtime'),
    (83, 'Command Line', 'runtime'),
    (84, 'Runtime Path', 'runtime'),
    (85, 'shim cmdline', 'runtime'),
    (86, 'Container ID from shim/path', 'runtime'),
    (87, 'Process Address Space', 'runtime'),
    (88, 'VMA', 'runtime'),
    (89, 'Heap Region', 'runtime'),
    (90, 'Go Runtime Object', 'runtime'),
    (91, 'Container 관련 구조체', 'runtime'),
    (92, 'Structure Parse 상태', 'runtime'),
    (93, 'State 구조', 'runtime'),
    (94, 'Boolean Flags', 'runtime'),
    (95, 'PID', 'runtime'),
    (96, 'ExitCode', 'runtime'),
    (97, 'StartedAt', 'runtime'),
    (98, 'FinishedAt', 'runtime'),
    (99, 'Container ID from Heap', 'runtime'),
    (100, 'Container ID 일치 여부', 'runtime'),
    (101, 'PID 일치 여부', 'runtime'),
    (102, 'Process 관계 일치 여부', 'runtime'),
]


class Unsupported(ValueError):
    """A layout cannot be interpreted without guessing."""


class Incomplete(ValueError):
    """An otherwise supported traversal could not be completed."""


class DuplicateJSONKey(ValueError):
    """Conflicting JSON keys must not become authoritative metadata."""


def utc(seconds, nanoseconds=0):
    if seconds is None:
        return None
    if not 0 <= nanoseconds < 1000000000:
        raise ValueError("Invalid nanoseconds")
    value = datetime.datetime.fromtimestamp(seconds, UTC)
    return (f"{value.year:04d}-{value.month:02d}-{value.day:02d}T{value.hour:02d}:{value.minute:02d}:{value.second:02d}"
            + f".{nanoseconds:09d}Z")


def unique_pairs(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise DuplicateJSONKey("Duplicate JSON key: " + key)
        result[key] = value
    return result


def prefix_json(raw):
    """Only complete top-level key/value pairs in the contiguous prefix count."""
    text = raw.decode("utf-8", errors="surrogateescape")
    decoder = json.JSONDecoder(object_pairs_hook=unique_pairs)
    pos = len(text) - len(text.lstrip())
    result = {}
    if text[pos:pos + 1] != "{":
        return result
    pos += 1
    try:
        while True:
            while text[pos].isspace():
                pos += 1
            key, pos = decoder.raw_decode(text, pos)
            while text[pos].isspace():
                pos += 1
            if not isinstance(key, str) or text[pos] != ":":
                break
            pos += 1
            while text[pos].isspace():
                pos += 1
            value, pos = decoder.raw_decode(text, pos)
            while text[pos].isspace():
                pos += 1
            if text[pos] not in ",}":
                break
            if key in result:
                raise DuplicateJSONKey("Duplicate JSON key: " + key)
            result[key] = value
            if text[pos] == "}":
                break
            pos += 1
    except DuplicateJSONKey:
        raise
    except (ValueError, IndexError):
        pass
    return result


def json_object(raw):
    obj = json.loads(raw, object_pairs_hook=unique_pairs)
    if not isinstance(obj, dict):
        raise ValueError("Metadata is not an object")
    return obj


def capability_mask(value):
    """Read supported symbol-described unsigned layouts; never invent zero."""
    fields = [name for name in ("val", "cap") if value.has_member(name)]
    if len(fields) != 1:
        raise Unsupported("Capability needs one val/cap member")
    name = fields[0]
    offset, template = value.vol.members[name]
    if offset < 0 or offset + template.size > value.vol.size:
        raise Unsupported("Capability exceeds its structure")
    def unsigned(t, sizes):
        return (issubclass(t.vol.object_class, objects.Integer)
                and not issubclass(t.vol.object_class, objects.Pointer)
                and t.size in sizes and not t.vol.data_format.signed)
    if issubclass(template.vol.object_class, objects.Array):
        if name != "cap" or template.vol.count not in (1, 2) or not unsigned(template.vol.subtype, (4,)):
            raise Unsupported("Unsupported capability array")
        return sum(int(word) << (32 * i) for i, word in enumerate(value.member(name)))
    if not unsigned(template, (8,) if name == "val" else (4, 8)):
        raise Unsupported("Unsupported capability integer")
    return int(value.member(name))


class ProcessImage:
    """Bounded resident VMA inventory backed by stock Volatility layers."""
    def __init__(self, collector, task):
        self.collector, self.context = collector, collector.context
        if collector.kernel.get_type("pointer").size != 8:
            raise Unsupported("Go reflection decoder currently supports little-endian 64-bit processes")
        name = task.add_process_layer()
        if name is None or not task.mm:
            raise Incomplete("No dockerd process layer")
        self.layer = self.context.layers[name]
        self.vmas, self.chunks, self.gaps = [], [], []
        for obj in collector.bounded(task.mm.get_vma_iter()):
            start, end, flags = int(obj.vm_start), int(obj.vm_end), int(obj.vm_flags)
            if not 0 < start < end or int(obj.vm_mm) != int(task.mm):
                raise ValueError("Invalid VMA bounds/mm backlink")
            self.vmas.append({"address": hex(obj.vol.offset), "start": start, "end": end,
                              "flags": flags, "file_va": hex(int(obj.vm_file))})
        self.vmas.sort(key=lambda v: v["start"])
        if any(a["end"] > b["start"] for a, b in zip(self.vmas, self.vmas[1:])):
            raise ValueError("Overlapping VMAs")
        if len(self.vmas) != int(task.mm.map_count):
            collector.issue("VMA inventory", task.mm, Incomplete("VMA count differs from mm.map_count"))
        self.starts = [v["start"] for v in self.vmas]
        self.resident_bytes = 0
        self.truncated = False
        for v in self.vmas:
            if not v["flags"] & 1:
                continue
            position, chunk_start, chunk = v["start"], None, bytearray()
            for va, length, pa, _, physical in self.layer.mapping(v["start"], v["end"] - v["start"], ignore_errors=True):
                if va != position:
                    self.gaps.append({"start": hex(position), "end": hex(va)})
                    if chunk:
                        self.chunks.append((chunk_start, bytes(chunk)))
                    chunk_start, chunk = None, bytearray()
                if self.resident_bytes + length > HEAP_LIMIT:
                    self.truncated = True
                    break
                try:
                    raw = self.context.layers[physical].read(pa, length)
                except exceptions.InvalidAddressException as exc:
                    collector.issue("resident process range", va, exc)
                    if chunk:
                        self.chunks.append((chunk_start, bytes(chunk)))
                    chunk_start, chunk = None, bytearray()
                    position = va + length
                    continue
                if chunk_start is None:
                    chunk_start = va
                chunk.extend(raw)
                self.resident_bytes += len(raw)
                position = va + length
            if chunk:
                self.chunks.append((chunk_start, bytes(chunk)))
            if position < v["end"]:
                self.gaps.append({"start": hex(position), "end": hex(v["end"])})
            if self.truncated:
                collector.issue("process memory scan", task, Incomplete("Resident-memory scan budget exceeded"))
                break
        # Nonresident pages are never zero filled or treated as searched content.
        if self.gaps:
            collector.issue("process memory coverage", task, Incomplete("Nonresident/unreadable VMA ranges excluded; see runtime_address_spaces.gaps"))

    def vma(self, address):
        index = bisect.bisect_right(self.starts, address) - 1
        return self.vmas[index] if index >= 0 and address < self.vmas[index]["end"] else None

    def read(self, address, size):
        if not 0 <= size <= FILE_LIMIT:
            raise ValueError("Process read exceeds bounds")
        try:
            return self.layer.read(address, size)
        except exceptions.InvalidAddressException as exc:
            raise Incomplete(str(exc)) from exc

    def num(self, address, size=8, signed=False):
        return int.from_bytes(self.read(address, size), "little", signed=signed)

    def loc(self, address):
        result = {"va": hex(address), "layer": self.layer.name}
        try:
            _, _, pa, _, name = next(self.layer.mapping(address, 1))
            result.update(mapped_layer=name, mapped_offset=hex(pa))
        except (exceptions.InvalidAddressException, StopIteration):
            pass
        return result

    def find(self, needle, writable=None):
        count = 0
        for start, raw in self.chunks:
            vma = self.vma(start)
            if writable is not None and bool(vma["flags"] & 2) != writable:
                continue
            pos = raw.find(needle)
            while pos != -1:
                if count >= LIMIT:
                    raise Incomplete("Pattern candidate budget exceeded")
                yield start + pos
                count += 1
                pos = raw.find(needle, pos + 1)

    def go_name(self, address):
        length = shift = 0
        for index in range(1, 9):
            char = self.num(address + index, 1)
            length |= (char & 127) << shift
            if char < 128:
                if not 0 < length <= 65536:
                    raise ValueError("Go name length outside bounds")
                return self.read(address + index + 1, length).decode()
            shift += 7
        raise Unsupported("Unsupported Go name encoding")

    def go_string(self, address, maximum=65536):
        pointer, length = struct.unpack("<QQ", self.read(address, 16))
        if length > maximum or length and not self.vma(pointer):
            raise ValueError("Invalid Go string")
        return self.read(pointer, length).decode() if length else ""


def go_time(pm, address, fields):
    wall, ext = pm.num(address + fields["wall"]), pm.num(address + fields["ext"], signed=True)
    nanos, monotonic = wall & ((1 << 30) - 1), bool(wall >> 63)
    seconds = ((wall >> 30) & ((1 << 33) - 1)) + 59453308800 if monotonic else ext
    epoch = seconds - 62135596800
    return {**pm.loc(address), "wall": hex(wall), "ext": ext,
            "loc": hex(pm.num(address + fields["loc"])), "has_monotonic": monotonic,
            "unix_seconds": epoch, "nanoseconds": nanos, "unset": wall == 0 and ext == 0,
            "utc": utc(epoch, nanos)}


def collect_heap(collector, task):
    """Discover Go layouts in this dump, then validate Container/State candidates."""
    pm = ProcessImage(collector, task)
    entity = "task:" + hex(task.vol.offset)
    space = {"pid": int(task.pid), "task": hex(task.vol.offset), "layer": pm.layer.name,
             "mm": hex(int(task.mm)), "pgd": hex(int(task.mm.pgd)), "vmas": pm.vmas,
             "resident_bytes": pm.resident_bytes, "gaps": pm.gaps, "truncated": pm.truncated}
    collector.report.setdefault("runtime_address_spaces", []).append(space)
    for number, value in ((87, {k: v for k, v in space.items() if k != "vmas"}), (88, pm.vmas),
                          (89, [v for v in pm.vmas if v["flags"] & 2 and v["file_va"] == "0x0"])):
        collector.evidence(number, value, task, entity)

    def discover(first_field, required):
        names, descriptors = set(), {}
        for va in pm.find(bytes([len(first_field)]) + first_field.encode(), writable=False):
            try:
                if pm.go_name(va - 1) == first_field:
                    names.add(va - 1)
            except (ValueError, UnicodeError):
                continue
        for name in sorted(names):
            for arr in pm.find(struct.pack("<Q", name), writable=False):
                if arr % 8:
                    continue
                for ref in pm.find(struct.pack("<Q", arr), writable=False):
                    desc = ref - 56
                    try:
                        size, kind = pm.num(desc), pm.num(desc + 23, 1) & 31
                        count, capacity = pm.num(ref + 8), pm.num(ref + 16)
                        if kind != 25 or not 1 <= count <= 128 or capacity != count or not 1 <= size <= 65536:
                            continue
                        fields = {}
                        for index in range(count):
                            n, t, offset = struct.unpack("<QQQ", pm.read(arr + index * 24, 24))
                            field_name, width, field_kind = pm.go_name(n), pm.num(t), pm.num(t + 23, 1) & 31
                            if offset + width > size or not 0 < field_kind <= 26 or field_name in fields:
                                raise ValueError("Go field constraints")
                            fields[field_name] = {"offset": offset, "type_va": hex(t), "size": width,
                                                  "kind": field_kind, "record_va": hex(arr + index * 24)}
                        if required.issubset(fields):
                            descriptors[desc] = {**pm.loc(desc), "size": size, "fields": fields,
                                "type_name_offset": pm.num(desc + 40, 4, signed=True), "tflag": pm.num(desc + 20, 1)}
                    except (ValueError, UnicodeError, struct.error):
                        continue
        return list(descriptors.values())

    states = discover("Mutex", {"Running", "Paused", "Restarting", "RemovalInProgress", "Dead", "Pid", "ExitCode", "StartedAt", "FinishedAt"})
    containers = discover("StreamConfig", {"State", "Root", "ID", "Name", "HasBeenStartedBefore"})
    if len(states) != 1 or len(containers) != 1:
        raise Unsupported(f"Go Container/State layout unverified or ambiguous: {len(containers)}/{len(states)} descriptors")
    st, ct = states[0], containers[0]
    bases = []
    for name, descriptor in (("container.State", st), ("container.Container", ct)):
        candidates = set()
        for rawname in (name, "*" + name):
            for va in pm.find(bytes([len(rawname)]) + rawname.encode(), writable=False):
                try:
                    if pm.go_name(va - 1) == rawname:
                        candidates.add(va - 1 - descriptor["type_name_offset"])
                except (ValueError, UnicodeError):
                    continue
        bases.append(candidates)
    common = bases[0] & bases[1]
    if len(common) != 1:
        raise Unsupported("Go type-name base cannot be uniquely verified")
    base = common.pop()
    for desc in (ct, st):
        desc["types_base_va"] = hex(base)
        desc["encoded_type_name"] = pm.go_name(base + desc["type_name_offset"])
    sf, cf = st["fields"], ct["fields"]
    pointer_type = int(cf["State"]["type_va"], 16)
    if cf["State"]["kind"] != 22 or pm.num(pointer_type + 48) != int(st["va"], 16):
        raise Unsupported("Container.State does not point to the discovered State type")
    for name in ("ID", "Root", "Name"):
        if cf[name]["kind"] != 24 or cf[name]["size"] != 16:
            raise Unsupported("Container identity is not a Go string")
    time_type = int(sf["StartedAt"]["type_va"], 16)
    if time_type != int(sf["FinishedAt"]["type_va"], 16) or pm.num(time_type) != 24 or pm.num(time_type + 23, 1) & 31 != 25:
        raise Unsupported("Unsupported Go time.Time fields")
    arr, count = pm.num(time_type + 56), pm.num(time_type + 64)
    if count != 3:
        raise Unsupported("Unsupported Go time.Time layout")
    time_fields = {pm.go_name(pm.num(arr + i * 24)): pm.num(arr + i * 24 + 16) for i in range(count)}
    if set(time_fields) != {"wall", "ext", "loc"} or set(time_fields.values()) != {0, 8, 16}:
        raise Unsupported("Unsupported Go time.Time members")
    collector.report.setdefault("runtime_go_types", []).append({"pid": int(task.pid), "container": ct,
        "state": st, "time": {"va": hex(time_type), "fields": time_fields}})
    ids = {cid for row in collector.report["cgroups"] for cid in row["container_ids"]}
    ids.update(row["container_id"] for row in collector.report["cached_files"])
    for _, raw in pm.chunks:
        ids.update(match[1].decode() for match in re.finditer(rb"/containers/([0-9a-f]{64})(?:[^0-9a-f]|$)", raw))
    rejected, seen = [], set()
    for cid in sorted(ids):
        strings = set(pm.find(cid.encode(), writable=True))
        if not strings:
            continue
        for length_va in pm.find(struct.pack("<Q", 64), writable=True):
            header = length_va - 8
            if header % 8:
                continue
            try:
                if pm.num(header) not in strings:
                    continue
            except ValueError:
                continue
            va = header - cf["ID"]["offset"]
            if va in seen:
                continue
            seen.add(va)
            try:
                vma = pm.vma(va)
                if not vma or not vma["flags"] & 2 or vma["file_va"] != "0x0":
                    continue
                root, name = pm.go_string(va + cf["Root"]["offset"]), pm.go_string(va + cf["Name"]["offset"], 256)
                if not root.startswith("/") or not root.endswith("/containers/" + cid) or not name.startswith("/"):
                    continue
                state = pm.num(va + cf["State"]["offset"])
                rec = {"process_pid": int(task.pid), "container_id": cid, "container": pm.loc(va),
                       "name": name, "root": root, "state": {}, "lifecycle": {}, "field_evidence": {},
                       "parse_errors": [], "raw_objects": {}, "attribution": "structurally validated candidate; GC/ContainerStore reachability unverified"}
                collector.report["runtime_heap"].append(rec)
                if not pm.vma(state) or not pm.vma(state)["flags"] & 2:
                    rec["parse_errors"].append({"field": "State", "reason": "Outside writable VMA"})
                else:
                    rec["state_object"] = pm.loc(state)
                    def scalar(address, fields, field, owner):
                        desc = fields[field]
                        if desc["kind"] not in (1, 2, 3, 4, 5, 6) or desc["size"] not in (1, 2, 4, 8):
                            raise Unsupported("Unexpected Go scalar type")
                        if field not in ("Pid", "ExitCode", "RestartCount") and (desc["kind"], desc["size"]) != (1, 1):
                            raise Unsupported("State flag is not a Go bool")
                        pos = address + desc["offset"]
                        raw = pm.read(pos, desc["size"])
                        value = int.from_bytes(raw, "little", signed=desc["kind"] != 1)
                        rec["field_evidence"][owner + "." + field] = {**pm.loc(pos), "raw_hex": raw.hex(), "value": value}
                        if desc["kind"] == 1:
                            if value not in (0, 1):
                                raise ValueError("Nonboolean Go field")
                            return bool(value)
                        return value
                    for field in ("Running", "Paused", "Restarting", "OOMKilled", "RemovalInProgress", "Dead", "removed", "Pid", "ExitCode"):
                        if field not in sf:
                            continue
                        try:
                            rec["state"][field] = scalar(state, sf, field, "State")
                        except ValueError as exc:
                            rec["parse_errors"].append({"field": field, "reason": str(exc)})
                    for field in ("StartedAt", "FinishedAt"):
                        try:
                            observed = go_time(pm, state + sf[field]["offset"], time_fields)
                            rec["field_evidence"]["State." + field] = observed
                            rec["state"][field] = observed["utc"]
                        except (ValueError, OverflowError) as exc:
                            rec["parse_errors"].append({"field": field, "reason": str(exc)})
                    for field in ("HasBeenStartedBefore", "HasBeenManuallyStopped", "HasBeenManuallyRestarted", "RestartCount"):
                        if field in cf:
                            try:
                                rec["lifecycle"][field] = scalar(va, cf, field, "Container")
                            except ValueError as exc:
                                rec["parse_errors"].append({"field": field, "reason": str(exc)})
                    for label, pos, size in (("container", va, ct["size"]), ("state", state, st["size"])):
                        try:
                            raw = pm.read(pos, size)
                            rec["raw_objects"][label] = {**pm.loc(pos), "length": size,
                                "base64": base64.b64encode(raw).decode(), "sha256": hashlib.sha256(raw).hexdigest()}
                        except ValueError as exc:
                            rec["parse_errors"].append({"field": label, "reason": str(exc)})
                rec["parse_status"] = "PARTIAL" if rec["parse_errors"] else "FOUND"
                if rec["parse_errors"]:
                    collector.issue("Go candidate fields", task, Incomplete(str(rec["parse_errors"])))
                heap_entity = "heap:" + str(int(task.pid)) + ":" + hex(va)
                values = ((90, rec["container"]), (91, {"id": cid, "root": root, "name": name}),
                    (92, rec["parse_status"]), (93, rec.get("state_object")), (94, {k: v for k, v in rec["state"].items() if isinstance(v, bool)}),
                    (95, rec["state"].get("Pid")), (96, rec["state"].get("ExitCode")),
                    (97, rec["field_evidence"].get("State.StartedAt")), (98, rec["field_evidence"].get("State.FinishedAt")), (99, cid))
                for number, value in values:
                    collector.evidence(number, value, task, heap_entity, [cid], "dockerd Go heap candidate")
                    if value is not None:
                        collector.report["evidence"][-1]["location"] = pm.loc(state if 93 <= number <= 98 else va)
            except (ValueError, UnicodeError, struct.error) as exc:
                if len(rejected) < LIMIT:
                    rejected.append({"candidate": pm.loc(va), "reason": str(exc)})
    collector.report.setdefault("runtime_rejected", []).append({"pid": int(task.pid), "candidates": rejected})


def memory_string(layer, address, limit=4096):
    """Read a bounded NUL-terminated string without padding missing pages."""
    if not address:
        return None
    data = bytearray()
    while len(data) < limit:
        position = (address + len(data)) & layer.address_mask
        size = min(64, 4096 - position % 4096, limit - len(data))
        block = layer.read(position, size, pad=False)
        if b"\0" in block:
            data.extend(block.split(b"\0", 1)[0])
            return data.decode("utf-8", errors="strict")
        data.extend(block)
    raise Incomplete("String exceeds bounded NUL-terminated read")


class OverlayLayout:
    """Describe only required fields, using the ISF or the live module BTF.

    Live btf.types already uses the running kernel's relocated base type IDs;
    raw split/module BTF IDs must not be interpreted against an arbitrary ISF.
    No guessed offsets or global symbol-table changes are used.
    """
    NAMES = ("ovl_fs", "ovl_layer", "ovl_config")
    TYPE_LIMIT = 1000000

    def __init__(self, collector, sb):
        self.c, self.k, self.layer = collector, collector.kernel, collector.layer
        self.pointer_size = self.k.get_type("pointer").size
        self.byteorder = self.k.get_type("unsigned int").vol.data_format[1]
        self.structures, self.records = {}, {}
        self.source = {"kind": "ISF", "structures": self.structures}
        if all(self.k.has_type(n) for n in self.NAMES):
            for name in self.NAMES:
                template = self.k.get_type(name)
                self.structures[name] = {"size": template.size, "fields": {
                    field: {"offset": template.relative_child_offset(field), **self.native_type(template.child_template(field))}
                    for field in self.needed_fields(name) if template.has_member(field)}}
        else:
            self.btf = self.find_btf(sb)
            self.source.update(kind="LIVE_BTF", btf=hex(self.c.address(self.btf)),
                               name=utility.array_to_string(self.btf.name),
                               base_btf=hex(int(self.btf.base_btf)), start_id=int(self.btf.start_id))
            start, count = int(self.btf.start_id), int(self.btf.nr_types)
            self.validate_btf(self.btf)
            for tid in range(max(1, start), start + count):
                record = self.record(tid)
                if record["kind"] == 4 and record["name"] in self.NAMES:
                    name = record["name"]
                    if name in self.structures:
                        raise Unsupported("Ambiguous overlay struct name in BTF: " + name)
                    fields = {}
                    for member in range(record["vlen"]):
                        off, subtype, bit_offset = self.words(record["address"] + 12 + 12 * member, 3)
                        field = self.btf_string(off)
                        if field not in self.needed_fields(name):
                            continue
                        if (record["kflag"] and bit_offset >> 24) or bit_offset % 8:
                            raise Unsupported("Required overlay member is a bitfield")
                        fields[field] = {"offset": bit_offset // 8, **self.btf_type(subtype)}
                    self.structures[name] = {"size": record["size"], "type_id": tid, "fields": fields}
            if any(n not in self.structures for n in self.NAMES):
                raise Unsupported("Required overlay structs absent from live BTF")
        for name, desc in self.structures.items():
            if not 0 < desc["size"] <= 1048576:
                raise Unsupported("Invalid overlay struct size: " + name)
            for field in desc["fields"].values():
                if field["offset"] < 0 or field["offset"] + field["size"] > desc["size"]:
                    raise Unsupported("Overlay member outside its containing struct")

    @staticmethod
    def needed_fields(name):
        return {"ovl_fs": ("numlayer", "numdatalayer", "layers", "workbasedir", "workdir", "config"),
                "ovl_layer": ("mnt", "idx"),
                "ovl_config": ("upperdir", "workdir", "lowerdirs", "lowerdir")}[name]

    def native_type(self, template, depth=0):
        if depth > 16:
            raise Unsupported("ISF pointer/type depth exceeded")
        cls = template.vol.object_class
        if issubclass(cls, objects.Pointer):
            return {"kind": "pointer", "size": template.size,
                    "target": self.native_type(template.vol.subtype, depth + 1)}
        if issubclass(cls, objects.Integer):
            return {"kind": "int", "size": template.size, "name": template.vol.type_name.split("!")[-1]}
        if issubclass(cls, objects.StructType):
            return {"kind": "struct", "size": template.size, "name": template.vol.type_name.split("!")[-1]}
        raise Unsupported("Unsupported required overlay ISF field type")

    def find_btf(self, sb):
        owner = sb.s_type.owner
        wanted = utility.array_to_string(owner.name) if owner else "vmlinux"
        if not owner and self.k.has_symbol("btf_vmlinux"):
            pointer = self.c.symbol("btf_vmlinux", "pointer")
            if pointer:
                return self.c.obj("btf", int(pointer))
        if not self.k.has_symbol("btf_idr") or not self.k.has_type("btf"):
            raise Unsupported("Overlay ISF types and live BTF registry unavailable")
        root = self.c.symbol("btf_idr", "idr").idr_rt
        if not root.has_member("xa_head"):
            raise Unsupported("Live BTF discovery requires an XArray IDR layout")
        # Bounded XArray walk: do not silently skip unreadable registry nodes.
        pending, seen, matches = [(int(root.xa_head), None)], set(), []
        slots = self.k.get_type("xa_node").child_template("slots").count
        if slots < 2 or slots > 256 or slots & (slots - 1):
            raise Unsupported("Invalid XArray slot count")
        shift_step = slots.bit_length() - 1
        while pending:
            raw, parent_shift = pending.pop()
            address = raw & self.layer.address_mask
            if not address:
                continue
            if address & 3 == 2:
                address &= ~3
                if address < 4096 or address in seen or len(seen) >= 4096:
                    raise Incomplete("Invalid/cyclic/over-limit BTF registry")
                seen.add(address)
                node = self.c.obj("xa_node", address)
                shift = int(node.shift)
                if shift % shift_step or shift >= self.pointer_size * 8 or (parent_shift is not None and shift != parent_shift - shift_step):
                    raise Incomplete("Invalid BTF registry XArray shift")
                pending.extend((int(node.slots[i]), shift) for i in range(slots))
            elif not address & 3:
                btf = self.c.obj("btf", address)
                if bool(btf.kernel_btf) and utility.array_to_string(btf.name) == wanted:
                    matches.append(btf)
        if len(matches) != 1:
            raise Unsupported("Expected one owner-matched live BTF, found {} for {}".format(len(matches), wanted))
        return matches[0]

    def validate_btf(self, btf):
        if int(btf.hdr.magic) != 0xEB9F or int(btf.hdr.version) != 1:
            raise Unsupported("Invalid BTF header")
        if not 0 < int(btf.nr_types) <= self.TYPE_LIMIT or not 0 < int(btf.hdr.str_len) <= 32 * 1024 * 1024:
            raise Unsupported("BTF metadata exceeds bounds")
        if not 24 <= int(btf.hdr.hdr_len) <= 4096 or not 0 < int(btf.hdr.type_len) <= 64 * 1024 * 1024:
            raise Unsupported("Invalid BTF type section")

    def base_for(self, value, field):
        btf, seen = self.btf, set()
        while value < int(btf.member(field)):
            address = self.c.address(btf)
            if address in seen or len(seen) >= 16 or not btf.base_btf:
                raise Unsupported("Invalid BTF base chain")
            seen.add(address)
            btf = btf.base_btf.dereference()
        self.validate_btf(btf)
        return btf

    def words(self, address, count):
        data = self.layer.read(address & self.layer.address_mask, 4 * count, pad=False)
        return [int.from_bytes(data[i:i + 4], self.byteorder) for i in range(0, len(data), 4)]

    def btf_string(self, offset):
        btf = self.base_for(offset, "start_str_off")
        offset -= int(btf.start_str_off)
        if not 0 <= offset < int(btf.hdr.str_len):
            raise Unsupported("BTF string offset out of bounds")
        return memory_string(self.layer, int(btf.strings) + offset, min(4096, int(btf.hdr.str_len) - offset))

    def record(self, tid):
        if tid not in self.records:
            btf = self.base_for(tid, "start_id")
            index = tid - int(btf.start_id)
            if tid == 0 or not 0 <= index < int(btf.nr_types):
                raise Unsupported("BTF type ID out of bounds")
            data = self.layer.read((int(btf.types) + index * self.pointer_size) & self.layer.address_mask, self.pointer_size, pad=False)
            address = int.from_bytes(data, self.byteorder) & self.layer.address_mask
            start = (int(btf.data) + int(btf.hdr.hdr_len) + int(btf.hdr.type_off)) & self.layer.address_mask
            if not start <= address <= start + int(btf.hdr.type_len) - 12:
                raise Unsupported("BTF type pointer outside type section")
            name, info, size = self.words(address, 3)
            vlen, kind = info & 0xffff, (info >> 24) & 31
            extra = 12 * vlen if kind in (4, 5) else 4 if kind == 1 else 0
            if address + 12 + extra > start + int(btf.hdr.type_len):
                raise Unsupported("BTF type record extends outside section")
            self.records[tid] = {"name": self.btf_string(name), "kind": kind, "vlen": vlen,
                "kflag": bool(info >> 31), "size": size, "address": address}
        return self.records[tid]

    def btf_type(self, tid, depth=0):
        if depth > 16:
            raise Unsupported("BTF modifier/pointer depth exceeded")
        t = self.record(tid)
        if t["kind"] in (8, 9, 10, 11, 18):
            return self.btf_type(t["size"], depth + 1)
        if t["kind"] == 2:
            return {"kind": "pointer", "size": self.pointer_size, "target": self.btf_type(t["size"], depth + 1)}
        if t["kind"] == 1:
            encoding = self.words(t["address"] + 12, 1)[0]
            if (encoding >> 16) & 255 or encoding & 255 != t["size"] * 8:
                raise Unsupported("Non-regular integer in overlay layout")
            return {"kind": "int", "size": t["size"], "name": t["name"]}
        if t["kind"] == 4:
            return {"kind": "struct", "size": t["size"], "name": t["name"]}
        raise Unsupported("Required overlay field has unsupported BTF kind {}".format(t["kind"]))

    def field(self, name, field, kind, target=None):
        desc = self.structures[name]["fields"].get(field)
        if desc is None or desc["kind"] != kind:
            raise Unsupported("Unsupported overlay layout: {}.{} requires {}".format(name, field, kind))
        if kind == "pointer" and (desc["size"] != self.pointer_size or
                (target and (desc["target"]["kind"] != "struct" or desc["target"]["name"] != target))):
            raise Unsupported("Overlay pointer target mismatch")
        return desc

    def value(self, address, name, field, kind="int", target=None):
        desc = self.field(name, field, kind, target)
        if desc["size"] not in (1, 2, 4, 8):
            raise Unsupported("Invalid overlay scalar width")
        return int.from_bytes(self.layer.read((address + desc["offset"]) & self.layer.address_mask, desc["size"], pad=False), self.byteorder)

    def string_pointer(self, address, name, field, index=None):
        desc = self.field(name, field, "pointer")
        target = desc["target"]
        pointer = self.value(address, name, field, "pointer")
        if index is not None:
            if target["kind"] != "pointer" or target["size"] != self.pointer_size:
                raise Unsupported("Overlay lowerdirs requires char **")
            target = target["target"]
            if not pointer:
                raise Incomplete("Null overlay lowerdirs array")
            pointer = int.from_bytes(self.layer.read((pointer + index * self.pointer_size) & self.layer.address_mask,
                self.pointer_size, pad=False), self.byteorder)
        if target["kind"] != "int" or target["size"] != 1:
            raise Unsupported("Overlay path requires a character pointer")
        return memory_string(self.layer, pointer)


def audit_task_list(head, read_link, limit=LIMIT):
    """Audit both directions independently, retaining reachable nodes on failure.

    read_link(address, field) must return a normalized list_head address.
    A union is a recovery set, never a claim that a damaged list is complete.
    """
    result = {"head": hex(head), "directions": {}, "issues": []}
    cache = {}

    def link(address, field):
        key = address, field
        if key not in cache:
            cache[key] = read_link(address, field)
        return cache[key]

    for direction, field, opposite in (("forward", "next", "prev"),
                                        ("backward", "prev", "next")):
        nodes, seen, previous = [], set(), head
        closed = False
        try:
            current = link(head, field)
            while current != head:
                if not current or current in seen or len(seen) >= limit:
                    raise Incomplete("Null/cycle/traversal budget before returning to head")
                seen.add(current)
                nodes.append(current)
                try:
                    actual = link(current, opposite)
                    if actual != previous:
                        result["issues"].append({"direction": direction, "kind": "RECIPROCAL_MISMATCH",
                            "node": hex(current), "field": opposite,
                            "expected": hex(previous), "actual": hex(actual)})
                except (exceptions.VolatilityException, ValueError, AttributeError) as exc:
                    result["issues"].append({"direction": direction, "kind": "UNREADABLE_BACKLINK",
                        "node": hex(current), "detail": str(exc)})
                previous, current = current, link(current, field)
            closed = True
            if link(head, opposite) != previous:
                result["issues"].append({"direction": direction, "kind": "HEAD_TAIL_MISMATCH",
                    "expected": hex(previous), "actual": hex(link(head, opposite))})
        except (exceptions.VolatilityException, ValueError, AttributeError) as exc:
            result["issues"].append({"direction": direction, "kind": "TRAVERSAL_STOPPED", "detail": str(exc)})
        result["directions"][direction] = {"nodes": nodes, "closed": closed, "count": len(nodes)}
    forward = set(result["directions"]["forward"]["nodes"])
    backward = set(result["directions"]["backward"]["nodes"])
    result["forward_only"] = sorted(forward - backward)
    result["backward_only"] = sorted(backward - forward)
    if forward != backward:
        result["issues"].append({"kind": "DIRECTION_SET_MISMATCH",
            "forward_only": len(forward - backward), "backward_only": len(backward - forward)})
    result["status"] = "PARTIAL" if result["issues"] else "CONSISTENT"
    return result


class Collector:
    def __init__(self, context, kernel_name):
        self.context = context
        self.kernel = context.modules[kernel_name]
        self.layer = context.layers[self.kernel.layer_name]
        self.stage = "tasks"
        self.report = {"schema_version": 1, "method": "ANALYSIS.md six independent discovery paths",
                       "provenance": {"plugin_version": "1.1.0", "volatility_version": constants.PACKAGE_VERSION,
                           "collection_started_utc": datetime.datetime.now(UTC).isoformat(),
                           "kernel_module": kernel_name, "kernel_layer": self.kernel.layer_name,
                           "isf_url": context.symbol_space[self.kernel.symbol_table_name].config.get("isf_url"),
                           "input_layers": [{"name": name, "location": context.layers[name].config.get("location")}
                                            for name in context.layers if context.layers[name].config.get("location")]},
                       "coverage": {}, "errors": [], "evidence": [], "tasks": [],
                       "namespaces": [], "cgroups": [], "mounts": [], "cached_files": [],
                       "runtime_processes": [], "runtime_heap": [], "containers": [],
                       "limits": {"objects_per_traversal": LIMIT, "metadata_file_bytes": FILE_LIMIT,
                                  "resident_heap_bytes_per_daemon": HEAP_LIMIT},
                       "limitations": ["Reachable objects only; absence is scoped to completed traversals.",
                           "Live acquisition may smear objects across time.",
                           "Cache and heap observations can be stale; no lifecycle classifier is applied.",
                           "Namespace sharing or ancestry alone does not establish Docker identity."]}
        self.tasks = {}
        self.task_rows = {}
        self.namespaces = {}
        self.cgroups = {}
        self.mounts = {}
        self.superblocks = {}
        self.containers = {}
        self.host_ns = {}
        self.init = None
        self.boot = None
        self.stage_counts = {}
        self.enum_constants = None
        self.task_discovery = {}
        self.report["task_list_integrity"] = []
        self.overlay_cache = {}
        self.overlay_layout = None

    def process_start(self, task):
        if self.boot is None:
            for symbol, typename in (("timekeeper_data", "tk_data"), ("tk_core", "tk_data"),
                                     ("tk_core_mono", "tk_data"), ("timekeeper", "timekeeper")):
                if self.kernel.has_symbol(symbol) and self.kernel.has_type(typename):
                    candidate = self.symbol(symbol, typename)
                    keeper = candidate.timekeeper if candidate.has_member("timekeeper") else candidate
                    if keeper.has_member("offs_real") and keeper.has_member("offs_boot"):
                        def signed_ns(field):
                            value = keeper.member(field)
                            return int(value.tv64) if value.has_member("tv64") else int(value)
                        self.boot = signed_ns("offs_real") - signed_ns("offs_boot")
                        self.report["boot_time_source"] = {"symbol": symbol, "location": self.location(keeper), "nanoseconds": self.boot}
                        break
        if self.boot is not None and task.has_member("start_boottime"):
            total = self.boot + int(task.start_boottime)
            return utc(*divmod(total, 1000000000))
        value = task.get_create_time()
        if value is None:
            raise Unsupported("Process start time has no verified clock conversion")
        return value.astimezone(UTC).isoformat()

    def address(self, obj):
        return int(obj.vol.offset) if hasattr(obj, "vol") else int(obj)

    def location(self, obj):
        address = self.address(obj)
        result = {"layer": self.kernel.layer_name, "virtual": hex(address)}
        try:
            _, _, physical, _, name = next(self.layer.mapping(address, 1))
            result.update(mapped_layer=name, mapped_offset=hex(physical))
        except (exceptions.InvalidAddressException, StopIteration):
            pass
        return result

    def issue(self, operation, obj, exc):
        try:
            address = hex(self.address(obj))
        except (ValueError, TypeError, AttributeError):
            address = str(obj)
        kind = "UNSUPPORTED" if isinstance(exc, (Unsupported, exceptions.SymbolError, AttributeError)) else "UNREADABLE" if isinstance(exc, exceptions.InvalidAddressException) else "INCOMPLETE" if isinstance(exc, Incomplete) else "ERROR"
        self.report["errors"].append({"stage": self.stage, "operation": operation,
                                     "address": address, "kind": kind,
                                     "exception": type(exc).__name__, "detail": str(exc)})

    def read(self, operation, obj, function, default=None):
        try:
            return function()
        except (exceptions.VolatilityException, ValueError, AttributeError, TypeError,
                KeyError, IndexError, OverflowError, UnicodeError, struct.error) as exc:
            self.issue(operation, obj, exc)
            return default

    def evidence(self, number, value, obj, entity, ids=(), source=None):
        if value is None:
            return
        entry = {"artifact": number, "stage": self.stage, "value": value,
                 "location": self.location(obj), "entity": entity,
                 "container_ids": sorted(set(ids)), "source": source or self.stage}
        self.report["evidence"].append(entry)

    def obj(self, name, address):
        return self.kernel.object(name, offset=int(address), absolute=True)

    def symbol(self, name, typename):
        sym = self.kernel.get_symbol(name)
        return self.kernel.object(typename, offset=sym.address, absolute=False)

    def string(self, ptr):
        return utility.pointer_to_string(ptr, 4096) if ptr else ""

    def walk(self, head, typename, member, hlist=False):
        offset = self.kernel.get_type(typename).relative_child_offset(member)
        end = 0 if hlist else self.address(head)
        link = int(head.first if hlist else head.next)
        seen = set()
        while link != end:
            if not link or link in seen or len(seen) >= LIMIT:
                raise Incomplete("Null/cyclic/over-limit linked list")
            seen.add(link)
            node = self.obj(typename, link - offset)
            yield node
            link = int(node.member(member).next)

    def bounded(self, iterator):
        for index, value in enumerate(iterator):
            if index >= LIMIT:
                raise Incomplete("Traversal budget exceeded")
            yield value

    def stage_run(self, name, function):
        self.stage = name
        errors = len(self.report["errors"])
        started = time.perf_counter()
        vollog.info("ps: collecting %s", name)
        self.read(name, name, function)
        count = sum(1 for e in self.report["evidence"] if e["stage"] == name)
        issues = self.report["errors"][errors:]
        self.report["coverage"][name] = {"status": "PARTIAL" if issues else "FOUND" if count else "NOT FOUND",
            "completed_without_errors": not issues, "observations": count, "errors": len(issues),
            "elapsed_seconds": round(time.perf_counter() - started, 3)}

    def namespace(self, ptr, kind, entity=None):
        if not ptr:
            return None
        obj = ptr.dereference() if isinstance(ptr, objects.Pointer) else ptr
        address = self.address(obj)
        key = (kind, address)
        if key not in self.namespaces:
            number = int(obj.ns.inum) if obj.has_member("ns") else int(obj.proc_inum)
            row = {"address": hex(address), "kind": kind, "inum": number, "tasks": []}
            self.namespaces[key] = (obj, row)
            self.report["namespaces"].append(row)
        row = self.namespaces[key][1]
        if entity and entity not in row["tasks"]:
            row["tasks"].append(entity)
        return {"address": row["address"], "inum": row["inum"]}

    def pid_chain(self, task):
        if task.has_member("thread_pid"):
            pid = task.thread_pid
        elif task.has_member("pids"):
            pid = task.pids[0].pid
        else:
            raise Unsupported("task PID link unavailable")
        if not pid:
            return []
        level = int(pid.level)
        if not 0 <= level <= 32:
            raise ValueError("PID namespace depth outside bounds")
        start = pid.numbers.vol.offset
        width = self.kernel.get_type("upid").size
        result = []
        for index in range(level + 1):
            upid = self.obj("upid", start + index * width)
            ns = self.namespace(upid.ns, "pid")
            result.append({"level": index, "nr": int(upid.nr), "namespace": ns,
                           "address": hex(upid.vol.offset)})
        return result

    def task_cgroups(self, task):
        if not task.has_member("cgroups"):
            raise Unsupported("task.cgroups absent")
        if not task.cgroups:
            return []
        css = task.cgroups.dereference()
        groups = {}
        if css.has_member("dfl_cgrp") and css.dfl_cgrp:
            groups[int(css.dfl_cgrp)] = css.dfl_cgrp.dereference()
        if css.has_member("subsys"):
            for ptr in self.bounded(css.subsys):
                if ptr and ptr.cgroup:
                    groups[int(ptr.cgroup)] = ptr.cgroup.dereference()
        return [self.cgroup(group, "task") for group in groups.values()]

    def cgroup(self, group, source):
        address = self.address(group)
        if address in self.cgroups:
            row = self.cgroups[address][1]
            if source not in row["sources"]:
                row["sources"].append(source)
            return row
        path, trace = self.cgroup_path(group)
        ids = sorted(set(CGROUP_ID.findall(path)))
        row = {"address": hex(address), "path": path, "parent_trace": trace, "container_ids": ids, "sources": [source]}
        self.cgroups[address] = (group, row)
        self.report["cgroups"].append(row)
        return row

    def cgroup_path(self, group):
        node = group.kn.dereference() if group.has_member("kn") and group.kn else group
        if group.has_member("kn") and not group.kn:
            raise ValueError("NULL kernfs node")
        modern = group.has_member("kn")
        parts, seen, trace = [], set(), []
        while node:
            address = self.address(node)
            if address in seen or len(seen) >= LIMIT:
                raise Incomplete("cgroup parent cycle/budget")
            seen.add(address)
            if node.has_member("name"):
                parts.append(self.string(node.name))
            elif node.has_member("name_copy"):
                parts.append(self.string(node.name_copy))
            else:
                raise Unsupported("cgroup name layout unavailable")
            parent = node.member("__parent") if node.has_member("__parent") else node.parent if node.has_member("parent") else node.self.parent.cgroup if not modern and node.self.parent else None
            trace.append({"location": self.location(node), "name": parts[-1], "parent": hex(int(parent)) if parent else "0x0"})
            node = parent.dereference() if parent else None
        return "/" + "/".join(p for p in reversed(parts) if p), trace

    def task_list(self, head, member, kind):
        mask = self.layer.address_mask
        offset = self.kernel.get_type("task_struct").relative_child_offset(member)
        audit = audit_task_list(self.address(head) & mask,
            lambda address, field: int(self.obj("list_head", address).member(field)) & mask)
        audit.update(member=member, kind=kind)
        self.report["task_list_integrity"].append(audit)
        if audit["status"] != "CONSISTENT":
            vollog.warning("ps: %s list integrity mismatch at %s: forward=%d, backward=%d, "
                "backward-only=%d; recovered union remains PARTIAL", kind, audit["head"],
                audit["directions"]["forward"]["count"], audit["directions"]["backward"]["count"],
                len(audit["backward_only"]))
            self.issue("task list integrity: " + kind, head, Incomplete(
                "Bidirectional list inconsistent: forward={}, backward={}, backward_only={}; "
                "union retained, completeness unproven (see task_list_integrity)".format(
                    audit["directions"]["forward"]["count"], audit["directions"]["backward"]["count"],
                    len(audit["backward_only"]))))
        forward = audit["directions"]["forward"]["nodes"]
        backward = audit["directions"]["backward"]["nodes"]
        sets = {"forward": set(forward), "backward": set(backward)}
        for address in dict.fromkeys(forward + backward):
            task = self.obj("task_struct", (address - offset) & mask)
            def validate():
                if int(task.pid) <= 0 or int(task.tgid) <= 0 or not task.group_leader:
                    raise Incomplete("Reachable task has invalid PID/TGID/group_leader")
                utility.array_to_string(task.comm)
                return True
            if not self.read("reachable task validation", task, validate, False):
                continue
            self.task_discovery.setdefault(self.address(task), []).append({
                "list_head": audit["head"], "member": member, "kind": kind,
                "directions": [d for d, nodes in sets.items() if address in nodes],
                "list_status": audit["status"]})
            yield task

    def collect_tasks(self):
        self.init = self.symbol("init_task", "task_struct")
        def leaders():
            for task in self.task_list(self.init.tasks, "tasks", "process_leaders"):
                self.tasks[self.address(task)] = task
        self.read("task list", self.init, leaders)
        for task in list(self.tasks.values()):
            def threads():
                if task.has_member("thread_node") and task.signal and task.signal.has_member("thread_head"):
                    head, member = task.signal.thread_head, "thread_node"
                elif task.has_member("thread_group"):
                    head, member = task.thread_group, "thread_group"
                else:
                    raise Unsupported("Thread list layout unavailable")
                for thread in self.task_list(head, member, "threads"):
                    self.tasks[self.address(thread)] = thread
            self.read("thread list", task, threads)
        for address, task in self.tasks.items():
            entity = "task:" + hex(address)
            row = {"address": hex(address), "entity": entity, "namespaces": {}, "container_ids": [],
                   "discovery": self.task_discovery.get(address, [])}
            self.report["tasks"].append(row)
            self.task_rows[address] = row
            self.evidence(1, True, task, entity)
            fields = {"pid": 2, "tgid": 3, "__state": 5, "exit_state": 6, "exit_code": 7,
                      "flags": 8, "mm": 9, "group_leader": 10, "parent": 11, "real_parent": 12}
            for field, number in fields.items():
                actual = "state" if field == "__state" and not task.has_member(field) else field
                value = self.read("task." + actual, task, lambda f=actual: int(task.member(f)))
                row[field] = value
                self.evidence(number, value, task, entity, source="task." + actual)
            row["comm"] = self.read("task.comm", task, lambda: utility.array_to_string(task.comm))
            self.evidence(4, row["comm"], task, entity)
            chain = self.read("task.pid_chain", task, lambda: self.pid_chain(task), [])
            row["pid_chain"] = chain
            if chain:
                pid_address = hex(int(task.thread_pid if task.has_member("thread_pid") else task.pids[0].pid))
                self.evidence(13, pid_address, task, entity)
                for number, value in ((14, pid_address), (15, len(chain) - 1), (16, chain),
                                      (17, chain[0]["nr"]), (18, chain[-1]["nr"]), (19, chain[-1]["namespace"])):
                    self.evidence(number, value, task, entity)
                row["namespace_tid"] = chain[-1]["nr"]
                row["namespaces"]["pid"] = chain[-1]["namespace"]
            groups = self.read("task.cgroups", task, lambda: self.task_cgroups(task), [])
            row["cgroups"] = [g["address"] for g in groups]
            row["container_ids"] = sorted({cid for group in groups for cid in group["container_ids"]})
            row["process_start"] = self.read("task.start_time", task, lambda: self.process_start(task))
            # Optional values cannot abort task discovery.
            if task.has_member("cred") and task.cred:
                cred = self.read("task.cred", task, lambda: task.cred.dereference())
                if cred is not None:
                    def effective_uid():
                        value = cred.member("euid")
                        return int(value.val) if value.has_member("val") else int(value)
                    row["effective_uid"] = self.read("cred.euid", cred, effective_uid)
                    row["effective_caps"] = self.read("cred.cap_effective", cred, lambda: hex(capability_mask(cred.cap_effective)))

    def collect_namespaces(self):
        host = self.init or self.symbol("init_task", "task_struct")
        all_tasks = [(host, None)] + [(t, self.task_rows[a]) for a, t in self.tasks.items()]
        mapping = {"mnt": (21, 22), "uts": (23, 24), "ipc": (25, 26), "net": (27, 28), "cgroup": (29, 30)}
        for task, row in all_tasks:
            entity = row["entity"] if row else "host"
            proxy = self.read("nsproxy", task, lambda: task.nsproxy.dereference() if task.nsproxy else None)
            if proxy is None:
                continue
            self.evidence(20, hex(proxy.vol.offset), proxy, entity)
            for kind, numbers in mapping.items():
                ns = self.read(kind + " namespace", proxy, lambda k=kind: self.namespace(proxy.member(k + "_ns"), k, entity))
                if ns is None:
                    continue
                if row is None:
                    self.host_ns[kind] = ns
                else:
                    row["namespaces"][kind] = ns
                self.evidence(numbers[0], ns["address"], proxy, entity)
                self.evidence(numbers[1], ns["inum"], int(ns["address"], 16), entity)
            if row is None:
                chain = self.read("host PID namespace", task, lambda: self.pid_chain(task), [])
                if chain:
                    self.host_ns["pid"] = chain[-1]["namespace"]
            elif row.get("pid_chain"):
                self.evidence(31, row["pid_chain"][-1]["namespace"], task, entity)
        for row in self.report["tasks"]:
            row["namespace_relations"] = {kind: ("host_shared" if ns["address"] == self.host_ns[kind]["address"] else "different")
                for kind, ns in row["namespaces"].items() if kind in self.host_ns}
            self.evidence(32, row["namespace_relations"], int(row["address"], 16), row["entity"])

    def enum(self, name):
        # Constants may be masks or bit indices; the caller chooses per enum.
        if self.enum_constants is None:
            table = self.context.symbol_space[self.kernel.symbol_table_name]
            self.enum_constants = {}
            for enum_name in table.enumerations:
                self.enum_constants.update(table.get_enumeration(enum_name).choices)
        if name in self.enum_constants:
            return int(self.enum_constants[name])
        raise Unsupported("Missing enum constant " + name)

    def collect_cgroups(self):
        roots = []
        if self.kernel.has_symbol("cgrp_dfl_root"):
            roots.append(self.symbol("cgrp_dfl_root", "cgroup_root"))
        if self.kernel.has_symbol("cgroup_roots"):
            def additional_roots():
                roots.extend(self.walk(self.symbol("cgroup_roots", "list_head"), "cgroup_root", "root_list"))
            self.read("cgroup roots", "cgroup_roots", additional_roots)
        if not roots:
            raise Unsupported("No supported global cgroup root symbol")
        pending = []
        for root in roots:
            self.evidence(33, hex(root.vol.offset), root, "global_cgroup_root")
            pending.append(root.cgrp)
        seen = set()
        while pending:
            group = pending.pop()
            address = self.address(group)
            if address in seen:
                continue
            if len(seen) >= LIMIT:
                raise Incomplete("Global cgroup traversal budget")
            seen.add(address)
            self.read("global cgroup", group, lambda g=group: self.cgroup(g, "global"))
            def children():
                for child in self.walk(group.self.children, "cgroup_subsys_state", "sibling"):
                    if child.cgroup:
                        pending.append(child.cgroup.dereference())
            self.read("cgroup children", group, children)
        for address, (group, row) in self.cgroups.items():
            entity, ids = "cgroup:" + hex(address), row["container_ids"]
            self.evidence(34, row["address"], group, entity, ids)
            self.evidence(43, row["path"], group, entity, ids)
            for cid in ids:
                self.evidence(44, cid, group, entity, ids)
            raw = {}
            for field in ("nr_populated_csets", "nr_populated_domain_children", "nr_populated_threaded_children", "flags"):
                if group.has_member(field):
                    raw[field] = self.read("cgroup." + field, group, lambda f=field: int(group.member(f)))
            row["raw_state"] = raw
            pop = [v for k, v in raw.items() if k != "flags"]
            row["populated"] = any(v != 0 for v in pop) if pop and all(v is not None for v in pop) else None
            row["frozen"] = self.read("cgroup frozen", group, lambda: bool(int(group.flags) & (1 << self.enum("CGRP_FROZEN"))))
            row["dying"] = self.read("cgroup dying", group, lambda: bool(int(group.self.flags) & self.enum("CSS_DYING")))
            for number, value in ((35, row["populated"]), (36, row["frozen"]), (37, row["dying"]), (38, hex(group.self.vol.offset))):
                self.evidence(number, value, group, entity, ids)
            if group.has_member("kn") and group.kn:
                self.evidence(39, hex(int(group.kn)), group, entity, ids)
                self.evidence(40, self.read("kernfs name", group.kn, lambda: self.string(group.kn.name)), group.kn.dereference(), entity, ids)
                self.evidence(41, self.read("kernfs parent", group.kn, lambda: hex(int(group.kn.member("__parent") if group.kn.has_member("__parent") else group.kn.parent))), group.kn.dereference(), entity, ids)
                self.evidence(42, row["parent_trace"], group.kn.dereference(), entity, ids, "kernfs parent traversal")
            members = [t["address"] for t in self.report["tasks"] if row["address"] in t.get("cgroups", [])]
            row["task_members"] = members
            self.evidence(45, members, group, entity, ids)
            self.evidence(46, not members, group, entity, ids, "no task association in observed task inventory; not an exited verdict")

    def backing_path(self, dentry, sb):
        """Path relative to the backing superblock root, not a host-absolute path."""
        parts, seen = [], set()
        current = dentry
        while True:
            address = self.address(current)
            if address in seen or len(seen) >= LIMIT:
                raise Incomplete("Backing dentry parent cycle/budget")
            seen.add(address)
            if int(current.d_sb) != self.address(sb):
                raise Incomplete("Backing dentry superblock mismatch")
            if address == int(sb.s_root):
                return "/" + "/".join(reversed(parts))
            if not current.d_parent or int(current.d_parent) == address:
                raise Incomplete("Backing dentry disconnected from superblock root")
            name = current.d_name.name_as_str()
            if not name or name in (".", "..") or "/" in name:
                raise Incomplete("Invalid backing dentry name")
            parts.append(name)
            current = current.d_parent.dereference()

    def overlay_info(self, sb):
        address = self.address(sb)
        if address in self.overlay_cache:
            return self.overlay_cache[address]
        result = {"superblock": hex(address), "scope": "OVERLAY_SUPERBLOCK_LAYERS",
                  "status": "UNRESOLVED", "layers": [], "workdirs": []}
        self.overlay_cache[address] = result
        first_error = len(self.report["errors"])
        def decode():
            if self.overlay_layout is None:
                self.overlay_layout = OverlayLayout(self, sb)
                self.report["overlay_type_source"] = self.overlay_layout.source
            layout = self.overlay_layout
            ofs = int(sb.s_fs_info)
            if not ofs:
                raise Incomplete("Null overlay s_fs_info")
            result["fs_info"] = hex(ofs & self.layer.address_mask)
            result["type_source"] = layout.source["kind"]
            count = layout.value(ofs, "ovl_fs", "numlayer")
            data_count = layout.value(ofs, "ovl_fs", "numdatalayer") if "numdatalayer" in layout.structures["ovl_fs"]["fields"] else 0
            if not 1 <= count <= 4096 or not 0 <= data_count < count:
                raise Incomplete("Overlay layer counts outside bounds")
            result.update(numlayer=count, numdatalayer=data_count)
            layers = layout.value(ofs, "ovl_fs", "layers", "pointer", "ovl_layer")
            if not layers:
                raise Incomplete("Null overlay layers array")
            config_desc = layout.field("ovl_fs", "config", "struct")
            if config_desc["name"] != "ovl_config" or config_desc["size"] != layout.structures["ovl_config"]["size"]:
                raise Unsupported("Overlay configuration layout mismatch")
            config = ofs + config_desc["offset"]
            upper_sb = None
            for index in range(count):
                record = {"index": index, "role": "upper" if index == 0 else
                          "lower_data" if index >= count - data_count else "lower",
                          "status": "UNRESOLVED", "path_scope": "BACKING_SUPERBLOCK_ROOT"}
                result["layers"].append(record)
                layer_address = layers + index * layout.structures["ovl_layer"]["size"]
                record["layer_address"] = hex(layer_address & self.layer.address_mask)
                before = len(self.report["errors"])
                def backing():
                    if layout.value(layer_address, "ovl_layer", "idx") != index:
                        raise Incomplete("Overlay layer index mismatch")
                    ptr = layout.value(layer_address, "ovl_layer", "mnt", "pointer", "vfsmount")
                    if not ptr and index == 0:
                        record["status"] = "ABSENT"  # Valid lower-only/read-only overlay.
                        return None
                    if not ptr:
                        raise Incomplete("Null lower layer mount")
                    mount = self.obj("vfsmount", ptr)
                    root, backing_sb = mount.mnt_root.dereference(), mount.mnt_sb.dereference()
                    record.update(mount=hex(self.address(mount)), root_dentry=hex(self.address(root)),
                                  backing_superblock=hex(self.address(backing_sb)),
                                  path=self.backing_path(root, backing_sb), status="RESOLVED")
                    return backing_sb
                backing_sb = self.read("overlay backing layer {}".format(index), layer_address, backing)
                if index == 0:
                    upper_sb = backing_sb
                    record["configured_path"] = self.read("overlay upperdir", config,
                        lambda: layout.string_pointer(config, "ovl_config", "upperdir"))
                elif "lowerdirs" in layout.structures["ovl_config"]["fields"]:
                    record["configured_path"] = self.read("overlay lowerdir {}".format(index), config,
                        lambda: layout.string_pointer(config, "ovl_config", "lowerdirs", index))
                # Older colon-separated lowerdir strings are retained as a raw
                # option below: escaped ':' must not be guessed into layer IDs.
                if len(self.report["errors"]) > before:
                    record["status"] = "PARTIAL" if record.get("path") else "UNRESOLVED"
            if "lowerdirs" in layout.structures["ovl_config"]["fields"]:
                # Linux reserves index 0 for the original colon-separated option;
                # per-layer strings have the same index as ofs.layers[].
                result["lowerdir_option"] = self.read("overlay raw lowerdir option", config,
                    lambda: layout.string_pointer(config, "ovl_config", "lowerdirs", 0))
            if "lowerdir" in layout.structures["ovl_config"]["fields"]:
                result["lowerdir_option"] = self.read("overlay lowerdir option", config,
                    lambda: layout.string_pointer(config, "ovl_config", "lowerdir"))
            result["configured_workdir"] = self.read("overlay workdir option", config,
                lambda: layout.string_pointer(config, "ovl_config", "workdir"))
            for field in ("workbasedir", "workdir"):
                def work():
                    ptr = layout.value(ofs, "ovl_fs", field, "pointer", "dentry")
                    if not ptr:
                        if upper_sb is not None and not (int(sb.s_flags) & 1):  # SB_RDONLY
                            raise Incomplete("Missing work directory on a writable upper layer")
                        result["workdirs"].append({"role": field, "status": "ABSENT"})
                        return
                    if upper_sb is None:
                        raise Incomplete("Work directory without a verified upper superblock")
                    root = self.obj("dentry", ptr)
                    result["workdirs"].append({"role": field, "dentry": hex(self.address(root)),
                        "backing_superblock": hex(self.address(upper_sb)),
                        "path_scope": "BACKING_SUPERBLOCK_ROOT", "path": self.backing_path(root, upper_sb)})
                self.read("overlay " + field, ofs, work)
            result["status"] = "RESOLVED"
        self.read("overlay layout and layers", sb, decode)
        result["error_indices"] = list(range(first_error, len(self.report["errors"])))
        if result["error_indices"]:
            result["status"] = "PARTIAL" if any(l.get("path") for l in result["layers"]) else "UNRESOLVED"
        return result

    def mount_record(self, mount, task=None):
        address = self.address(mount)
        if address in self.mounts:
            return
        ns = int(mount.mnt_ns) if mount.has_member("mnt_ns") else 0
        row = {"address": hex(address), "namespace": hex(ns), "task": hex(task.vol.offset) if task is not None else None}
        self.mounts[address] = (mount, task, row)
        self.report["mounts"].append(row)
        root = mount.get_mnt_root().dereference()
        sb = mount.get_mnt_sb().dereference()
        self.superblocks[sb.vol.offset] = sb
        row["id"] = int(mount.mnt_id) if mount.has_member("mnt_id") else None
        row["fstype"] = self.string(sb.s_type.name)
        row["host_path"] = self.read("host mount path", mount, lambda: linux.LinuxUtilities.get_path_mnt(self.init, mount)) if self.init is not None else None
        row["path"] = self.read("namespace mount path", mount, lambda: linux.LinuxUtilities.get_path_mnt(task, mount)) if task is not None else None
        row["root_dentry"], row["superblock"] = hex(root.vol.offset), hex(sb.vol.offset)
        row["root_inode"] = hex(int(root.d_inode))
        def root_path():
            current, parts, seen = root, [], set()
            while True:
                if current.vol.offset in seen or len(seen) >= LIMIT:
                    raise Incomplete("Dentry parent cycle/budget")
                seen.add(current.vol.offset)
                name = current.d_name.name_as_str()
                if name not in ("", "/"):
                    parts.append(name)
                if int(current.d_parent) == current.vol.offset:
                    return "/" + "/".join(reversed(parts))
                current = current.d_parent.dereference()
        row["root_path"] = self.read("mount root dentry path", root, root_path)
        row["layer_paths"] = [p for p in (row["root_path"], row["host_path"]) if p and re.search(r"/(?:overlay2/[^/]+|snapshots/[0-9]+)(?:/|$)", p)]
        row["layer_resolution"] = "PATH_OBSERVED" if row["layer_paths"] else "UNRESOLVED" if "overlay" in row["fstype"] else "N/A"
        if row["fstype"] == "overlay":
            row["overlay"] = self.overlay_info(sb)
            recovered = [item["path"] for item in row["overlay"]["layers"] if item.get("path")]
            row["layer_paths"] = sorted(set(row["layer_paths"] + recovered))
            row["layer_resolution"] = ("BACKING_PATHS_RESOLVED" if row["overlay"]["status"] == "RESOLVED"
                                       else row["overlay"]["status"])
        row["container_ids"] = sorted({cid for path in (row["host_path"], row["path"], row["root_path"]) if path
            for cid in re.findall(r"/containers/([0-9a-f]{64})(?=/|$)", path)})
        entity, ids = "mount:" + hex(address), row["container_ids"]
        for number, value in ((47, {"namespace": row["namespace"], "mount": row["address"], "parent": hex(int(mount.mnt_parent))}),
                              (48, row["address"]), (49, hex(mount.mnt.vol.offset) if mount.has_member("mnt") else row["address"]),
                              (50, row["root_dentry"]), (51, row["superblock"]), (52, row["fstype"]),
                              (53, row["root_dentry"]), (54, {"host": row["host_path"], "namespace": row["path"]}),
                              (55, row["root_inode"]), (56, "overlay" in row["fstype"]),
                              (57, row["host_path"] if "overlay" in row["fstype"] else None),
                              (58, {"root_dentry": row["root_dentry"], "path": row["root_path"]} if "overlay" in row["fstype"] else None),
                              (59, ids if ids else None), (60, row["layer_paths"] if row["layer_paths"] else None)):
            self.evidence(number, value, mount, entity, ids)

    def collect_mounts(self):
        if self.init is None:
            self.init = self.read("init_task for VFS", "init_task", lambda: self.symbol("init_task", "task_struct"))
        ns_tasks = {}
        for address, task in self.tasks.items():
            row = self.task_rows[address]
            ns = row.get("namespaces", {}).get("mnt")
            if ns:
                ns_tasks.setdefault(int(ns["address"], 16), task)
        # Independent of finding a container task.
        if self.init is not None and self.init.nsproxy and self.init.nsproxy.mnt_ns:
            ns_tasks.setdefault(int(self.init.nsproxy.mnt_ns), self.init)
        if self.kernel.has_symbol("init_nsproxy"):
            proxy = self.symbol("init_nsproxy", "nsproxy")
            if proxy.mnt_ns:
                ns_tasks.setdefault(int(proxy.mnt_ns), self.init)
        for address, task in ns_tasks.items():
            ns = self.obj("mnt_namespace", address)
            def mounts():
                for mount in self.bounded(ns.get_mount_points()):
                    self.read("mount", mount, lambda m=mount: self.mount_record(m, task))
            self.read("mount namespace", ns, mounts)
        # The global hash path can reach mounts not associated with observed tasks.
        if self.kernel.has_symbol("mount_hashtable"):
            def global_mounts():
                hlist = self.kernel.has_symbol("m_hash_mask")
                count = int(self.symbol("m_hash_mask", "unsigned int")) + 1 if hlist else self.layer.page_size // self.kernel.get_type("list_head").size
                if not 0 < count <= LIMIT or count & (count - 1):
                    raise Incomplete("Invalid/over-limit mount hash size")
                address = int(self.symbol("mount_hashtable", "pointer"))
                if not address:
                    raise ValueError("NULL mount hash pointer")
                typename = "mount" if self.kernel.has_type("mount") else "vfsmount"
                bucket_type = "hlist_head" if hlist else "list_head"
                width = self.kernel.get_type(bucket_type).size
                for index in range(count):
                    head = self.obj(bucket_type, address + index * width)
                    def bucket():
                        for mount in self.walk(head, typename, "mnt_hash", hlist=hlist):
                            self.read("global mount", mount, lambda m=mount: self.mount_record(m))
                    self.read("mount hash bucket", head, bucket)
            self.read("global mount table", "mount_hashtable", global_mounts)
        # Global superblocks are an independent VFS/page-cache entry point.
        if self.kernel.has_symbol("super_blocks"):
            def superblocks():
                for sb in self.walk(self.symbol("super_blocks", "list_head"), "super_block", "s_list"):
                    self.superblocks[sb.vol.offset] = sb
            self.read("super_blocks", "super_blocks", superblocks)

    def recover_file(self, inode, path, cid, filename):
        entity = "inode:" + hex(inode.vol.offset)
        row = {"path": path, "container_id": cid, "filename": filename, "inode": hex(inode.vol.offset),
               "pages": [], "holes": [], "json_parse": "NOT FOUND"}
        self.report["cached_files"].append(row)
        size = int(inode.i_size)
        if not 0 < size <= FILE_LIMIT:
            raise Incomplete("Empty/over-limit metadata inode")
        row["size"] = size
        for number, value in ((61, True), (62 if filename == "config.v2.json" else 63, True),
                              (64, path), (65, row["inode"]), (66, hex(int(inode.i_mapping)))):
            self.evidence(number, value, inode, entity, [cid])
        mapping = inode.i_mapping.dereference()
        storage = linux.IDStorage.choose_id_storage(self.context, self.kernel.name)
        pieces = {}
        page_size = self.layer.page_size
        def recover():
            for page_address in self.bounded(storage.get_entries(mapping.i_pages)):
                page = self.obj("page", page_address)
                def content():
                    if int(page.mapping) != int(inode.i_mapping):
                        raise ValueError("Cached page mapping backlink mismatch")
                    if page.has_member("index"):
                        index = int(page.index)
                    elif self.kernel.has_type("folio"):
                        folio = self.obj("folio", page.vol.offset)
                        # Both views must agree on the mapping member offset.
                        if folio.mapping.vol.offset != page.mapping.vol.offset:
                            raise Unsupported("folio/page mapping layout differs")
                        index = int(folio.index)
                    else:
                        raise Unsupported("Cached page index layout unavailable")
                    offset = index * page_size
                    if not 0 <= offset < size:
                        raise ValueError("Cached page outside inode")
                    if self.kernel.has_symbol("vmemmap_base") and self.kernel.has_symbol("mem_section"):
                        # BTF ISFs can omit global variable types. Read the verified
                        # pointer-sized vmemmap base explicitly, without patching core.
                        base = int(self.symbol("vmemmap_base", "unsigned long"))
                        address = self.layer.canonicalize(page.vol.offset)
                        width = self.kernel.get_type("page").size
                        if address < base or (address - base) % width:
                            raise ValueError("Page is outside aligned vmemmap")
                        physical = (address - base) // width * page_size
                        raw = self.context.layers[self.layer.config["memory_layer"]].read(physical, page_size)
                    else:
                        raw = page.get_content()
                    if not raw:
                        raise Incomplete("Cached page unreadable")
                    raw = raw[:min(page_size, size - offset)]
                    if offset in pieces and pieces[offset] != raw:
                        raise ValueError("Conflicting cache pages at one file offset")
                    pieces[offset] = raw
                    row["pages"].append({"file_offset": offset, "page": hex(page.vol.offset),
                        "length": len(raw), "sha256": hashlib.sha256(raw).hexdigest(),
                        "base64": base64.b64encode(raw).decode()})
                    self.evidence(67, row["pages"][-1], page, entity, [cid])
                self.read("cached page", page, content)
        self.read("inode pages", inode, recover)
        prefix = bytearray()
        for offset in range(0, size, page_size):
            raw = pieces.get(offset)
            expected = min(page_size, size - offset)
            if raw is None or len(raw) != expected:
                row["holes"].append({"offset": offset, "length": expected})
            if offset == len(prefix) and raw is not None:
                prefix.extend(raw)
        row["complete"] = len(prefix) == size and not row["holes"]
        if row["holes"]:
            self.issue("metadata coverage", inode, Incomplete("Missing cache ranges; no zero filling"))
        if prefix:
            try:
                data = json_object(bytes(prefix))
                row["json_parse"] = "FULL" if row["complete"] else "PARTIAL"
            except DuplicateJSONKey:
                raise
            except ValueError as exc:
                data = prefix_json(bytes(prefix))
                row["json_parse"] = "PARTIAL"
                self.issue("metadata JSON", inode, Incomplete(str(exc)))
            row["object"] = data
            embedded = data.get("ID")
            row["identity_conflict"] = embedded is not None and embedded != cid
            if row["identity_conflict"]:
                self.issue("metadata identity", inode, ValueError("Path and JSON ID disagree"))
            self.evidence(68, {"contiguous_prefix_bytes": len(prefix), "complete": row["complete"]}, inode, entity, [cid])
            self.evidence(69, row["json_parse"], inode, entity, [cid])
            self.evidence(70, embedded, inode, entity, [cid])
            state = data.get("State")
            if isinstance(state, dict):
                self.evidence(71, state, inode, entity, [cid], "cached config State; freshness unverified")
                self.evidence(72, state.get("Pid"), inode, entity, [cid])
                self.evidence(73, {k: state[k] for k in ("StartedAt", "FinishedAt") if k in state}, inode, entity, [cid])
            self.evidence(74, data, inode, entity, [cid])

    def collect_page_cache(self):
        if not self.superblocks and self.kernel.has_symbol("super_blocks"):
            for sb in self.walk(self.symbol("super_blocks", "list_head"), "super_block", "s_list"):
                self.superblocks[sb.vol.offset] = sb
        seen, metadata = set(), set()
        for sb in self.superblocks.values():
            def scan():
                if not sb.s_root:
                    return
                pending = [(sb.s_root.dereference(), "")]
                while pending:
                    dentry, path = pending.pop()
                    address = self.address(dentry)
                    if address in seen:
                        continue
                    if len(seen) >= LIMIT:
                        raise Incomplete("Global dentry budget")
                    seen.add(address)
                    match = FILE_ID.search(path)
                    if match and dentry.d_inode:
                        inode = dentry.d_inode.dereference()
                        key = (int(dentry.d_inode), path)
                        if key not in metadata:
                            metadata.add(key)
                            self.read("metadata inode", inode, lambda: self.recover_file(inode, path, match[1], match[2]))
                    def children():
                        for child in self.bounded(dentry.get_subdirs()):
                            name = self.read("dentry name", child, lambda ch=child: ch.d_name.name_as_str())
                            if name and name not in (".", ".."):
                                pending.append((child, path + "/" + name))
                    self.read("dentry children", dentry, children)
            self.read("superblock dentries", sb, scan)
        self.report["page_cache_scope"] = {"dentries_visited": len(seen), "superblocks": len(self.superblocks),
                                          "path_scope": "relative to each superblock root; data-root is not hardcoded"}

    def argv(self, task):
        if not task.mm:
            return []
        start, end = int(task.mm.arg_start), int(task.mm.arg_end)
        if not 0 <= end - start <= FILE_LIMIT:
            raise Incomplete("Command line length outside budget")
        layer_name = task.add_process_layer()
        if layer_name is None:
            raise Incomplete("No process address space")
        return self.context.layers[layer_name].read(start, end - start).decode("utf-8", errors="replace").rstrip("\0").split("\0")

    def collect_runtime(self):
        process_error_start = len(self.report["errors"])
        shims = {}
        for address, task in self.tasks.items():
            row = self.task_rows[address]
            if row.get("pid") != row.get("tgid"):
                continue
            comm = row.get("comm") or ""
            if not (comm in ("dockerd", "containerd") or comm.startswith("containerd-shim") or row["container_ids"]):
                continue
            args = self.read("runtime argv", task, lambda t=task: self.argv(t), [])
            row["argv"] = args
            ppid = self.task_rows.get(row.get("real_parent"), {}).get("pid")
            record = {"task": row["address"], "pid": row["pid"], "comm": comm, "argv": args,
                      "parent": row.get("real_parent"), "ppid": ppid, "container_ids": list(row["container_ids"])}
            self.report["runtime_processes"].append(record)
            entity = row["entity"]
            self.evidence(75 if comm == "dockerd" else 76 if comm == "containerd" else 77 if comm.startswith("containerd-shim") else 78, record, task, entity, row["container_ids"])
            for number, value in ((79, row["pid"]), (80, ppid), (81, comm),
                                  (82, {"task": row["address"], "parent": row.get("real_parent")}), (83, args), (84, [a for a in args if a.startswith("/")])):
                self.evidence(number, value, task, entity, row["container_ids"])
            if comm.startswith("containerd-shim"):
                flags = {a: args[i + 1] for i, a in enumerate(args[:-1]) if a in ("-id", "--id", "-namespace", "--namespace")}
                cid = flags.get("-id", flags.get("--id"))
                namespace = flags.get("-namespace", flags.get("--namespace"))
                record.update(runtime_namespace=namespace, shim_id=cid if cid and CID.fullmatch(cid) else None)
                if record["shim_id"]:
                    shims[address] = (cid, namespace)
                    self.evidence(85, args, task, entity, [cid])
                    self.evidence(86, cid, task, entity, [cid], "shim argv; Docker attribution additionally requires moby namespace or other Docker evidence")
        known = {cid for row in self.report["tasks"] for cid in row["container_ids"]}
        known.update(r["container_id"] for r in self.report["cached_files"] if not r.get("identity_conflict"))
        for record in self.report["runtime_processes"]:
            cid = record.get("shim_id")
            if cid and (record.get("runtime_namespace") == "moby" or cid in known):
                record["container_ids"] = sorted(set(record["container_ids"] + [cid]))
                record["docker_attribution"] = "moby namespace" if record.get("runtime_namespace") == "moby" else "matching independent Docker evidence"
        for row in self.report["tasks"]:
            parent, seen = row.get("real_parent"), set()
            while parent in self.task_rows and parent not in seen and len(seen) < LIMIT:
                seen.add(parent)
                if parent in shims:
                    cid, namespace = shims[parent]
                    row["shim_candidate"] = cid
                    if namespace == "moby" or cid in known:
                        if row["container_ids"] and cid not in row["container_ids"]:
                            row["identity_conflict"] = True
                        else:
                            row["container_ids"] = sorted(set(row["container_ids"] + [cid]))
                    break
                parent = self.task_rows[parent].get("real_parent")
        recorded = {r["task"] for r in self.report["runtime_processes"]}
        for address, row in self.task_rows.items():
            if row["container_ids"] and row.get("pid") == row.get("tgid") and row["address"] not in recorded:
                task = self.tasks[address]
                row["argv"] = self.read("associated process argv", task, lambda t=task: self.argv(t), [])
                record = {"task": row["address"], "pid": row["pid"], "comm": row.get("comm"), "argv": row["argv"],
                          "parent": row.get("real_parent"), "ppid": self.task_rows.get(row.get("real_parent"), {}).get("pid"),
                          "container_ids": row["container_ids"], "association": "shim ancestry candidate"}
                self.report["runtime_processes"].append(record)
                for number, value in ((78, record), (79, row["pid"]), (80, record["ppid"]), (81, row.get("comm")),
                                      (82, {"task": row["address"], "parent": row.get("real_parent")}), (83, row["argv"]),
                                      (84, [a for a in row["argv"] if a.startswith("/")])):
                    self.evidence(number, value, task, row["entity"], row["container_ids"])
        self.report["runtime_process_coverage"] = {
            "completed_without_errors": len(self.report["errors"]) == process_error_start and self.report["coverage"]["tasks"]["completed_without_errors"],
            "scope": "reachable task inventory and selected runtime command lines; excludes heap scan"}
        for address, task in self.tasks.items():
            row = self.task_rows[address]
            if row.get("comm") == "dockerd" and row.get("pid") == row.get("tgid"):
                self.read("dockerd heap", task, lambda t=task: collect_heap(self, t))

    def correlate(self):
        def entry(cid):
            if not CID.fullmatch(cid):
                raise ValueError("Invalid container ID")
            return self.containers.setdefault(cid, {"id": cid, "tasks": [], "cgroups": [], "mounts": [], "shims": [],
                "cached_files": [], "heap_candidates": [], "conflicts": [], "sources": []})
        mount_ids = {}
        for row in self.report["mounts"]:
            ns = row.get("namespace")
            if ns and ns != self.host_ns.get("mnt", {}).get("address"):
                members = [t for t in self.report["tasks"] if t["namespaces"].get("mnt", {}).get("address") == ns]
                ids = {cid for t in members for cid in t["container_ids"]}
                row["namespace_container_candidates"] = sorted(ids)
                row["container_ids"] = sorted(set(row.get("container_ids", [])) | ids)
            mount_ids["mount:" + row["address"]] = row.get("container_ids", [])
        for field, rows, id_field in (("tasks", self.report["tasks"], "container_ids"),
                                     ("cgroups", self.report["cgroups"], "container_ids"),
                                     ("mounts", self.report["mounts"], "container_ids")):
            for row in rows:
                for cid in row.get(id_field, []):
                    obj = entry(cid)
                    obj[field].append(row["address"])
                    if field not in obj["sources"]:
                        obj["sources"].append(field)
                    if row.get("identity_conflict"):
                        obj["conflicts"].append({"source": field, "address": row["address"], "reason": "cgroup/ancestry IDs differ"})
        for index, row in enumerate(self.report["cached_files"]):
            obj = entry(row["container_id"])
            obj["cached_files"].append(index)
            if "page_cache" not in obj["sources"]:
                obj["sources"].append("page_cache")
            if row.get("identity_conflict"):
                obj["conflicts"].append({"source": "page_cache", "inode": row["inode"], "reason": "path/JSON IDs differ"})
        for index, row in enumerate(self.report["runtime_heap"]):
            obj = entry(row["container_id"])
            obj["heap_candidates"].append(index)
            if "runtime_heap" not in obj["sources"]:
                obj["sources"].append("runtime_heap")
        for index, row in enumerate(self.report["runtime_processes"]):
            if row.get("shim_id") and row.get("docker_attribution"):
                obj = entry(row["shim_id"])
                obj["shims"].append(index)
                if "shim" not in obj["sources"]:
                    obj["sources"].append("shim")
        for cid, obj in self.containers.items():
            tasks = [self.task_rows[int(a, 16)] for a in obj["tasks"]]
            leaders = [t for t in tasks if t.get("pid") == t.get("tgid")]
            obj["processes"] = [{k: t.get(k) for k in ("address", "pid", "tgid", "namespace_tid", "comm", "argv", "process_start", "effective_uid", "effective_caps", "identity_conflict")} for t in leaders]
            states, metadata = [], []
            for index in obj["cached_files"]:
                r = self.report["cached_files"][index]
                if r.get("object") and not r.get("identity_conflict"):
                    metadata.append({"source": "page_cache", "index": index, "value": r["object"], "complete": r.get("complete", False)})
                    if isinstance(r["object"].get("State"), dict):
                        states.append({"source": "page_cache", "index": index, "value": r["object"]["State"]})
            for index in obj["heap_candidates"]:
                r = self.report["runtime_heap"][index]
                states.append({"source": "heap_candidate", "index": index, "value": r["state"]})
            obj["metadata"], obj["state_observations"] = metadata, states
            for name in ("Running", "Paused", "Restarting", "Dead", "RemovalInProgress", "Pid", "ExitCode"):
                values = {json.dumps(s["value"][name], sort_keys=True) for s in states if s["value"].get(name) is not None}
                if len(values) > 1:
                    obj["conflicts"].append({"field": name, "values": sorted(values), "reason": "metadata sources disagree"})
            observed_pids = {t["pid"] for t in leaders if t.get("pid") is not None}
            obj["pid_comparisons"] = [{"source": s["source"], "index": s["index"], "runtime_pid": s["value"].get("Pid"),
                "matches_observed_task": s["value"]["Pid"] in observed_pids if s["value"]["Pid"] > 0 else None,
                "comparison": "observed task PID" if s["value"]["Pid"] > 0 else "N/A: runtime PID is zero/nonpositive"}
                for s in states if type(s["value"].get("Pid")) is int]
            obj["association"] = "CONFLICT" if obj["conflicts"] else "TASK_LINKED_CANDIDATE" if leaders else "ARTIFACT_ONLY_CANDIDATE"
            anchor = int(obj["tasks"][0], 16) if obj["tasks"] else self.address(self.init) if self.init is not None else 0
            entity = "container:" + cid
            self.evidence(100, {"id": cid, "sources": obj["sources"], "conflicts": obj["conflicts"]}, anchor, entity, [cid], "full-ID correlation")
            if obj["pid_comparisons"]:
                self.evidence(101, obj["pid_comparisons"], anchor, entity, [cid], "runtime PID versus observed task PID")
            ancestry = [{"task": t["address"], "shim_id": t.get("shim_candidate"),
                         "matches_container_id": t.get("shim_candidate") == cid} for t in leaders if t.get("shim_candidate")]
            if ancestry:
                self.evidence(102, ancestry, anchor, entity, [cid], "real_parent chain and shim argv")
        entity_ids = {r["entity"]: r["container_ids"] for r in self.report["tasks"]}
        entity_ids.update(mount_ids)
        runtime_entities = {"task:" + r["task"]: r["container_ids"] for r in self.report["runtime_processes"] if r.get("docker_attribution")}
        for e in self.report["evidence"]:
            e["container_ids"] = sorted(set(e["container_ids"] + entity_ids.get(e["entity"], [])))
            if e["stage"] == "runtime":
                e["container_ids"] = sorted(set(e["container_ids"] + runtime_entities.get(e["entity"], [])))
        self.report["containers"] = list(self.containers.values())
        self.report["correlation_policy"] = "Full IDs group evidence for display; duplicate/stale heap instances and conflicts remain separate observations. PID/ns/ancestry alone is not a Docker verdict."

    def collect(self):
        for stage, fn in zip(STAGES, (self.collect_tasks, self.collect_namespaces, self.collect_cgroups,
                                     self.collect_mounts, self.collect_page_cache, self.collect_runtime)):
            self.stage_run(stage, fn)
        self.stage = "correlation"
        self.correlate()
        self.report["artifact_catalog"] = ARTIFACT_CATALOG
        self.report["artifact_vector"] = artifact_vectors(self.report)
        return self.report


def artifact_vectors(report):
    """Per-container presence, not a state classifier or a truth label."""
    vectors = {}
    for container in report["containers"]:
        cid = container["id"]
        observed = {}
        for index, evidence in enumerate(report["evidence"]):
            if cid in evidence["container_ids"]:
                observed.setdefault(evidence["artifact"], []).append(index)
        vector = []
        for number, name, stage in ARTIFACT_CATALOG:
            refs = observed.get(number, [])
            context_refs = [i for i, e in enumerate(report["evidence"]) if e["artifact"] == number] if number in (33, 75, 76, 87, 88, 89) else []
            coverage = report["coverage"][stage]
            if 75 <= number <= 86 or number == 102:
                coverage = report.get("runtime_process_coverage", coverage)
            if refs or context_refs:
                status = "FOUND"
            elif stage in ("tasks", "namespaces") and not container["tasks"]:
                status = "N/A" if stage == "namespaces" else "NOT FOUND" if coverage["completed_without_errors"] else "PARTIAL"
            else:
                status = "NOT FOUND" if coverage["completed_without_errors"] else "PARTIAL"
            vector.append({"artifact": number, "name": name, "status": status, "evidence_indices": refs,
                           "context_evidence_indices": context_refs,
                           "feature_value": {"presence": True if status == "FOUND" else False if status == "NOT FOUND" else None},
                           "reason": "observed; raw values and addresses are referenced" if status == "FOUND" else "no attributed task for namespace analysis" if status == "N/A" else "no observation within completed search scope" if status == "NOT FOUND" else "search or interpretation incomplete; see stage errors",
                           "relation": "container-linked" if refs else "global context; attribution not established" if context_refs else "not observed",
                           "search_stage": stage, "stage_complete": coverage["completed_without_errors"]})
        vectors[cid] = vector
    return vectors


def presentation(report):
    columns = ["Container ID", "Name", "Host PID", "NS PID", "Command", "Process Start UTC",
               "Created UTC", "Runtime State Evidence", "Configured Privileged", "Effective UID",
               "Effective Caps", "Association", "Sources"]
    rows = []
    def joined(values):
        values = sorted({str(v) for v in values if v is not None and v != ""})
        return "; ".join(values) if values else "-"
    for obj in sorted(report["containers"], key=lambda r: r["id"]):
        processes = obj["processes"]
        states = []
        for evidence in obj["state_observations"]:
            fields = evidence["value"]
            pairs = [f"{k}={fields[k]}" for k in ("Running", "Paused", "Restarting", "Dead", "RemovalInProgress", "Pid", "ExitCode", "StartedAt", "FinishedAt") if fields.get(k) is not None]
            states.append(evidence["source"] + ": " + ",".join(pairs))
        names = [m["value"].get("Name") for m in obj["metadata"]]
        names.extend(report["runtime_heap"][i].get("name") for i in obj["heap_candidates"])
        for process in sorted(processes, key=lambda p: p["pid"] or 0) or [{}]:
            rows.append((obj["id"], joined(names), joined([process.get("pid")]), joined([process.get("namespace_tid")]),
                joined([process.get("comm")]), joined([process.get("process_start")]),
                joined(m["value"].get("Created") for m in obj["metadata"]),
                joined(states), joined(m["value"].get("Privileged") for m in obj["metadata"] if isinstance(m["value"].get("Privileged"), bool)),
                joined([process.get("effective_uid")]), joined([process.get("effective_caps")]),
                obj["association"], ",".join(obj["sources"])))
    return [(name, str) for name in columns], [tuple(v.replace("\n", "\\n").replace("\t", "\\t") for v in row) for row in rows]


class Ps(interfaces.plugins.PluginInterface):
    """Inventory Docker process associations and residual evidence (--ps)."""
    _required_framework_version = (2, 28, 0)
    _version = (1, 1, 0)

    @classmethod
    def get_requirements(cls):
        return [requirements.ModuleRequirement(name="kernel", description="Linux kernel", architectures=["Intel32", "Intel64"]),
                requirements.BooleanRequirement(name="ps", description="Collect all six analysis layers and list container candidates", optional=True, default=False)]

    def run(self):
        if not self.config.get("ps", False):
            raise exceptions.VolatilityException("Select --ps to run the container inventory")
        report = Collector(self.context, self.config["kernel"]).collect()
        with self.open("ps_evidence.json") as output:
            output.write(json.dumps(report, ensure_ascii=False, indent=2).encode("utf-8"))
        if report["errors"]:
            vollog.warning("ps: %d collection issues; review coverage and evidence in ps_evidence.json", len(report["errors"]))
        if not report["containers"]:
            vollog.warning("ps: no attributed candidates in searched memory; see coverage in ps_evidence.json")
        columns, rows = presentation(report)
        return renderers.TreeGrid(columns, ((0, row) for row in rows))

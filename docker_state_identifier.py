#!/usr/bin/env python3
"""Docker/containerd container state identification from case artifacts and RAM.

The tool is intentionally dependency-free.  It treats daemon metadata as the
primary source, validates it against cgroup/proc observations, and uses a raw or
LiME memory image only as corroborating evidence.  Memory strings can be stale,
so they never override contradictory live metadata on their own.
"""

from __future__ import annotations

import argparse
import bisect
import datetime as dt
import hashlib
import json
import math
import os
import re
import struct
import sys
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Sequence, Tuple


STATES = ("created", "running", "paused", "restarting", "exited", "dead", "removing")
ACTIVE_STATES = {"running", "paused", "restarting"}
LIME_MAGIC = 0x4C694D45
LIME_HEADER = struct.Struct("<IIQQQ")
ZERO_TIME_PREFIXES = ("0001-01-01", "0000-00-00", "")


@dataclass
class Evidence:
    source: str
    category: str
    observed: str
    claim: Optional[str]
    weight: int
    reliability: str
    detail: str
    location: str


@dataclass
class MemoryHit:
    kind: str
    matched: str
    file_offset: int
    physical_address: Optional[int]
    context: str


@dataclass
class ContainerResult:
    container_id: str
    name: str = ""
    pid: Optional[int] = None
    scores: Dict[str, int] = field(default_factory=lambda: {s: 0 for s in STATES})
    evidence: List[Evidence] = field(default_factory=list)
    memory_hits: List[MemoryHit] = field(default_factory=list)
    warnings: List[str] = field(default_factory=list)
    state: str = "unknown"
    confidence: int = 0
    confidence_label: str = "LOW"

    def add(self, evidence: Evidence) -> None:
        self.evidence.append(evidence)
        if evidence.claim in self.scores:
            self.scores[evidence.claim] += evidence.weight


def read_text(path: Path) -> str:
    try:
        return path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return ""


def load_json_flexible(path: Path) -> List[Any]:
    text = read_text(path).strip()
    if not text:
        return []
    try:
        value = json.loads(text)
        return value if isinstance(value, list) else [value]
    except json.JSONDecodeError:
        values: List[Any] = []
        for line in text.splitlines():
            try:
                values.append(json.loads(line))
            except json.JSONDecodeError:
                continue
        return values


def normalize_state(value: Any) -> Optional[str]:
    if not isinstance(value, str):
        return None
    state = value.strip().lower()
    aliases = {"stopped": "exited", "stop": "exited", "remove": "removing"}
    state = aliases.get(state, state)
    return state if state in STATES else None


def full_container_id(value: Any) -> Optional[str]:
    if not isinstance(value, str):
        return None
    match = re.search(r"(?<![0-9a-f])([0-9a-f]{64})(?![0-9a-f])", value.lower())
    return match.group(1) if match else None


def short_container_id(value: Any) -> Optional[str]:
    if not isinstance(value, str):
        return None
    match = re.search(r"(?<![0-9a-f])([0-9a-f]{12,63})(?![0-9a-f])", value.lower())
    return match.group(1) if match else None


def parse_key_values(text: str) -> Dict[str, str]:
    result: Dict[str, str] = {}
    for line in text.splitlines():
        if ":" in line:
            key, value = line.split(":", 1)
            result[key.strip().lower()] = value.strip()
    return result


def parse_space_values(text: str) -> Dict[str, str]:
    result: Dict[str, str] = {}
    for line in text.splitlines():
        parts = line.strip().split(None, 1)
        if len(parts) == 2:
            result[parts[0].lower()] = parts[1].strip()
    return result


def is_zero_time(value: Any) -> bool:
    if value is None:
        return True
    text = str(value).strip()
    return any(text.startswith(prefix) for prefix in ZERO_TIME_PREFIXES)


class CaseAnalyzer:
    def __init__(self, case_root: Path, max_memory_hits: int = 6) -> None:
        self.case_root = case_root.resolve()
        self.max_memory_hits = max_memory_hits
        self.results: Dict[str, ContainerResult] = {}
        self.short_id_map: Dict[str, str] = {}
        self.case_warnings: List[str] = []
        self.memory_info: Dict[str, Any] = {}

    def get_result(self, cid: Optional[str], name: str = "") -> ContainerResult:
        key = cid or "unknown"
        if cid and len(cid) < 64:
            matches = [known for known in self.results if known != "unknown" and known.startswith(cid)]
            if len(matches) == 1:
                key = matches[0]
        if key not in self.results:
            self.results[key] = ContainerResult(container_id=key, name=name.lstrip("/"))
        elif name and not self.results[key].name:
            self.results[key].name = name.lstrip("/")
        if cid:
            self.short_id_map[cid[:12]] = key
        return self.results[key]

    def add_evidence(
        self,
        result: ContainerResult,
        source: str,
        category: str,
        observed: str,
        claim: Optional[str],
        weight: int,
        reliability: str,
        detail: str,
        location: Path | str,
    ) -> None:
        result.add(Evidence(source, category, observed, claim, weight, reliability, detail, str(location)))

    def collect(self) -> None:
        self._collect_docker_inspect()
        self._collect_docker_ps()
        self._collect_system_info()
        self._collect_cgroup()
        self._collect_proc()
        self._collect_host_processes()
        self._merge_unknown_if_possible()

    def _root_files(self, pattern: str) -> List[Path]:
        return sorted(p for p in self.case_root.glob(pattern) if p.is_file())

    def _collect_docker_inspect(self) -> None:
        files = self._root_files("*inspect*.json")
        for path in files:
            for obj in load_json_flexible(path):
                if not isinstance(obj, dict):
                    continue
                cid = full_container_id(obj.get("Id") or obj.get("ID"))
                if not cid:
                    continue
                result = self.get_result(cid, str(obj.get("Name", "")))
                state_obj = obj.get("State") if isinstance(obj.get("State"), dict) else {}
                status = normalize_state(state_obj.get("Status"))
                if status:
                    self.add_evidence(
                        result, "docker_inspect", "daemon_metadata", f"State.Status={status}", status,
                        100, "authoritative", "Docker daemon's persisted lifecycle state", path,
                    )
                paused = state_obj.get("Paused")
                running = state_obj.get("Running")
                restarting = state_obj.get("Restarting")
                dead = state_obj.get("Dead")
                pid = state_obj.get("Pid")
                if isinstance(pid, int):
                    result.pid = pid
                bool_claim: Optional[str] = None
                bool_observed = f"Running={running}, Paused={paused}, Restarting={restarting}, Dead={dead}, Pid={pid}"
                if paused is True:
                    bool_claim = "paused"
                elif restarting is True:
                    bool_claim = "restarting"
                elif dead is True:
                    bool_claim = "dead"
                elif running is True:
                    bool_claim = "running"
                elif status == "created" or (is_zero_time(state_obj.get("StartedAt")) and is_zero_time(state_obj.get("FinishedAt"))):
                    bool_claim = "created"
                elif not is_zero_time(state_obj.get("FinishedAt")):
                    bool_claim = "exited"
                if bool_claim:
                    self.add_evidence(
                        result, "docker_inspect", "daemon_flags", bool_observed, bool_claim,
                        80, "high", "Lifecycle flags and timestamps interpreted together", path,
                    )
                if status == "paused" and paused is not True:
                    result.warnings.append("docker inspect Status=paused but Paused is not true")
                if status == "created" and isinstance(pid, int) and pid != 0:
                    result.warnings.append("created state conflicts with a non-zero container PID")

    def _collect_docker_ps(self) -> None:
        files = self._root_files("*ps*.json")
        for path in files:
            for obj in load_json_flexible(path):
                if not isinstance(obj, dict):
                    continue
                raw_id = str(obj.get("ID") or obj.get("Id") or "").lower()
                cid = full_container_id(raw_id) or short_container_id(raw_id)
                state = normalize_state(obj.get("State"))
                if not cid or not state:
                    continue
                result = self.get_result(cid, str(obj.get("Names") or obj.get("Name") or ""))
                self.add_evidence(
                    result, "docker_ps", "daemon_listing", f"State={state}; Status={obj.get('Status', '')}", state,
                    90, "high", "Docker list output at acquisition time", path,
                )

    def _collect_system_info(self) -> None:
        for path in self._root_files("*system*info*.txt"):
            values = parse_key_values(read_text(path))
            cid = full_container_id(values.get("container_id", "")) or short_container_id(values.get("container_id", ""))
            state = normalize_state(values.get("container_state"))
            if not cid and not state:
                continue
            result = self.get_result(cid)
            try:
                pid = int(values.get("container_pid", ""))
                if result.pid is None:
                    result.pid = pid
            except ValueError:
                pass
            if state:
                self.add_evidence(
                    result, "case_manifest", "collector_label", f"container_state={state}", state,
                    45, "medium", "Collector-supplied label; useful but not independent ground truth", path,
                )

    def _container_from_cgroup_text(self, text: str) -> Optional[str]:
        match = re.search(r"docker[-/]([0-9a-f]{12,64})(?:\.scope|/|$)", text, re.I)
        return match.group(1).lower() if match else None

    def _collect_cgroup(self) -> None:
        cgroup_dir = self.case_root / "cgroup"
        if not cgroup_dir.is_dir():
            return
        proc_cgroup = read_text(self.case_root / "proc" / "cgroup")
        cid = self._container_from_cgroup_text(proc_cgroup)
        result = self.get_result(cid)
        freeze_path = cgroup_dir / "cgroup.freeze"
        events_path = cgroup_dir / "cgroup.events"
        procs_path = cgroup_dir / "cgroup.procs"
        freeze = read_text(freeze_path).strip()
        events = parse_space_values(read_text(events_path))
        procs = [line.strip() for line in read_text(procs_path).splitlines() if line.strip().isdigit()]
        frozen = events.get("frozen")
        populated = events.get("populated")
        if freeze == "1" or frozen == "1":
            self.add_evidence(
                result, "cgroup_v2", "kernel_control", f"cgroup.freeze={freeze or '?'}; frozen={frozen or '?'}",
                "paused", 95, "authoritative", "Kernel cgroup freezer reports the workload frozen", events_path,
            )
        elif freeze == "0" or frozen == "0":
            self.add_evidence(
                result, "cgroup_v2", "kernel_control", f"cgroup.freeze={freeze or '?'}; frozen={frozen or '?'}",
                None, 0, "high", "Kernel cgroup freezer reports not frozen", events_path,
            )
        if populated == "1" or procs:
            self.add_evidence(
                result, "cgroup_v2", "process_presence", f"populated={populated or '?'}; procs={','.join(procs) or '-'}",
                None, 0, "high", "Container cgroup has live tasks (supports an active lifecycle state)", procs_path,
            )
        elif populated == "0":
            self.add_evidence(
                result, "cgroup_v2", "process_absence", "populated=0; procs=-",
                None, 0, "high", "Container cgroup has no live tasks", events_path,
            )

    def _collect_proc(self) -> None:
        proc_dir = self.case_root / "proc"
        if not proc_dir.is_dir():
            return
        cgroup_text = read_text(proc_dir / "cgroup")
        cid = self._container_from_cgroup_text(cgroup_text)
        status_path = proc_dir / "status"
        status = parse_key_values(read_text(status_path))
        if not status:
            return
        result = self.get_result(cid)
        try:
            pid = int(status.get("pid", ""))
            if result.pid is None:
                result.pid = pid
        except ValueError:
            pass
        observed = f"Name={status.get('name', '?')}; State={status.get('state', '?')}; Pid={status.get('pid', '?')}; NSpid={status.get('nspid', '?')}"
        self.add_evidence(
            result, "procfs", "process_presence", observed, None, 0, "high",
            "Container init process existed; task sleep state alone does not distinguish running from paused", status_path,
        )

    def _collect_host_processes(self) -> None:
        candidates = self._root_files("*host*ps*.txt") + self._root_files("*container*top*.txt")
        if not candidates:
            return
        for result in list(self.results.values()):
            if not result.pid:
                continue
            pattern = re.compile(rf"(?m)^.*?\b{result.pid}\b.*$")
            for path in candidates:
                match = pattern.search(read_text(path))
                if match:
                    line = re.sub(r"\s+", " ", match.group(0)).strip()
                    self.add_evidence(
                        result, "process_listing", "process_presence", line[:300], None, 0, "medium",
                        "Snapshot process listing contains the container PID", path,
                    )
                    break

    def _merge_unknown_if_possible(self) -> None:
        unknown = self.results.get("unknown")
        known = [r for key, r in self.results.items() if key != "unknown"]
        if unknown and len(known) == 1:
            target = known[0]
            for evidence in unknown.evidence:
                target.add(evidence)
            target.warnings.extend(unknown.warnings)
            if target.pid is None:
                target.pid = unknown.pid
            del self.results["unknown"]

    def attach_memory_hits(self, hits: Sequence[MemoryHit]) -> None:
        result_list = list(self.results.values())
        single_container = len(result_list) == 1
        for result in result_list:
            identity_kinds = {"container_id", "container_short_id", "container_name", "docker_scope"}
            cid = result.container_id.lower()
            short_id = cid[:12]
            name = result.name.lower()

            def belongs(hit: MemoryHit) -> bool:
                matched = hit.matched.lower()
                context = hit.context.lower()
                if hit.kind == "container_id":
                    return cid != "unknown" and matched == cid
                if hit.kind == "container_short_id":
                    return cid != "unknown" and matched == short_id
                if hit.kind == "docker_scope":
                    return cid != "unknown" and cid in matched
                if hit.kind == "container_name":
                    return bool(name) and matched == name
                if hit.kind.startswith("state_") or hit.kind == "frozen_1":
                    return single_container or (cid != "unknown" and (cid in context or short_id in context)) or (name and name in context)
                return False

            relevant_hits = [hit for hit in hits if belongs(hit)]
            result.memory_hits.extend([h for h in relevant_hits if h.kind in identity_kinds or h.kind.startswith("state_") or h.kind == "frozen_1"])
            state_hit_counts: Dict[str, int] = {s: 0 for s in STATES}
            for hit in relevant_hits:
                if hit.kind.startswith("state_"):
                    state = hit.kind.split("_", 1)[1]
                    if state in state_hit_counts:
                        state_hit_counts[state] += 1
            if single_container:
                global_counts = self.memory_info.get("hit_counts", {})
                for state in STATES:
                    state_hit_counts[state] = int(global_counts.get(f"state_{state}", state_hit_counts[state]))
            for state, count in state_hit_counts.items():
                if count:
                    self.add_evidence(
                        result, "memory_image", "resident_string", f"structured {state} state signature x{count}", state,
                        min(25, 15 + count), "corroborative", "Potentially stale daemon/API data in RAM; never decisive alone",
                        self.memory_info.get("path", "memory image"),
                    )
            frozen_count = sum(1 for h in relevant_hits if h.kind == "frozen_1")
            if single_container:
                frozen_count = int(self.memory_info.get("hit_counts", {}).get("frozen_1", frozen_count))
            if frozen_count:
                self.add_evidence(
                    result, "memory_image", "resident_string", f"cgroup frozen=1 signature x{frozen_count}", "paused",
                    min(20, 10 + frozen_count), "corroborative", "Resident cgroup text consistent with a frozen workload",
                    self.memory_info.get("path", "memory image"),
                )

    def decide(self) -> None:
        for result in self.results.values():
            ordered = sorted(result.scores.items(), key=lambda item: item[1], reverse=True)
            top_state, top_score = ordered[0]
            if top_score <= 0:
                result.state = "unknown"
                result.confidence = 0
                result.confidence_label = "LOW"
                result.warnings.append("No state-bearing artifact was found")
                continue
            result.state = top_state
            state_sources: Dict[str, set] = {s: set() for s in STATES}
            for ev in result.evidence:
                if ev.claim in state_sources and ev.weight > 0:
                    state_sources[ev.claim].add(ev.source)
            competing = [(s, score) for s, score in ordered[1:] if score > 0]
            direct_states = {
                ev.claim for ev in result.evidence
                if ev.claim and ev.source in {"docker_inspect", "docker_ps", "cgroup_v2"} and ev.weight >= 80
            }
            confidence = 45
            if any(ev.claim == top_state and ev.weight >= 100 for ev in result.evidence):
                confidence = 82
            elif any(ev.claim == top_state and ev.weight >= 90 for ev in result.evidence):
                confidence = 78
            elif any(ev.claim == top_state and ev.weight >= 70 for ev in result.evidence):
                confidence = 70
            confidence += min(15, 5 * max(0, len(state_sources[top_state]) - 1))
            confidence += min(4, int(math.log2(max(1, top_score / 50))) * 2)
            if competing:
                runner_score = competing[0][1]
                confidence -= min(35, round(30 * runner_score / max(1, top_score)))
            if len(direct_states) > 1:
                result.warnings.append("Authoritative sources disagree: " + ", ".join(sorted(direct_states)))
                confidence -= 25
            self._consistency_checks(result)
            confidence -= min(20, 5 * len(result.warnings))
            result.confidence = max(1, min(99, confidence))
            result.confidence_label = "HIGH" if result.confidence >= 80 else "MEDIUM" if result.confidence >= 60 else "LOW"

    def _consistency_checks(self, result: ContainerResult) -> None:
        observations = "\n".join(ev.observed.lower() for ev in result.evidence)
        has_process = any(ev.category == "process_presence" for ev in result.evidence)
        no_process = any(ev.category == "process_absence" for ev in result.evidence)
        frozen = "frozen=1" in observations or "cgroup.freeze=1" in observations
        unfrozen = "frozen=0" in observations or "cgroup.freeze=0" in observations
        if result.state == "paused" and unfrozen:
            result.warnings.append("paused decision conflicts with cgroup freezer reporting 0")
        if result.state == "paused" and not has_process:
            result.warnings.append("paused state lacks a process/cgroup-presence observation")
        if result.state == "running" and frozen:
            result.warnings.append("running decision conflicts with cgroup frozen=1")
        if result.state in {"created", "exited", "dead"} and has_process:
            result.warnings.append(f"{result.state} decision conflicts with a live process observation")
        if result.state in ACTIVE_STATES and no_process:
            result.warnings.append(f"{result.state} decision conflicts with an empty cgroup")


def parse_lime_segments(path: Path) -> Tuple[List[Dict[str, int]], List[str]]:
    segments: List[Dict[str, int]] = []
    warnings: List[str] = []
    size = path.stat().st_size
    offset = 0
    try:
        with path.open("rb") as handle:
            while offset + LIME_HEADER.size <= size:
                handle.seek(offset)
                raw = handle.read(LIME_HEADER.size)
                if len(raw) != LIME_HEADER.size:
                    break
                magic, version, start, end, _reserved = LIME_HEADER.unpack(raw)
                if magic != LIME_MAGIC:
                    if not segments:
                        return [], ["Image does not begin with a LiME header; treating it as flat raw memory"]
                    warnings.append(f"Invalid LiME header at file offset 0x{offset:x}")
                    break
                if end < start:
                    warnings.append(f"Invalid LiME range at file offset 0x{offset:x}")
                    break
                data_start = offset + LIME_HEADER.size
                data_length = end - start + 1
                data_end = data_start + data_length
                if data_end > size:
                    warnings.append(f"Truncated LiME segment at file offset 0x{offset:x}")
                    data_end = size
                segments.append({
                    "version": version,
                    "physical_start": start,
                    "physical_end": start + (data_end - data_start) - 1,
                    "file_data_start": data_start,
                    "file_data_end": data_end,
                })
                offset = data_end
                if offset >= size:
                    break
    except OSError as exc:
        warnings.append(f"Unable to parse LiME layout: {exc}")
    return segments, warnings


def redact_context(text: str) -> str:
    text = re.sub(
        r'''(?i)((?:password|passwd|secret(?:[_-]?key)?|token|api[_-]?key|private[_-]?key)\s*[=:]\s*)[^\s,;\]\}"']+''',
        r"\1<redacted>", text,
    )
    return text


def printable_context(data: bytes) -> str:
    text = "".join(chr(byte) if 32 <= byte <= 126 else "." for byte in data)
    text = re.sub(r"\.{4,}", "...", text)
    return redact_context(text).strip(".")[:500]


def compile_memory_anchors(results: Iterable[ContainerResult]) -> Tuple[re.Pattern[bytes], Dict[bytes, str]]:
    """Build a literal-only regex and classify structure in small hit windows.

    Running a whitespace-heavy, case-insensitive alternation over multi-gigabyte
    images is unnecessarily expensive.  A lower-cased chunk plus literal anchors
    lets the regex engine use its fast prefix search; tiny local regexes then
    validate whether a state word is actually a JSON field/value.
    """
    definitions: List[Tuple[str, bytes]] = []
    for state in STATES:
        definitions.append((f"state_word_{state}", b'"' + state.encode() + b'"'))
    definitions.append(("frozen_word", b"frozen"))
    for result in results:
        if result.container_id != "unknown":
            cid = result.container_id.encode("ascii", errors="ignore").lower()
            definitions.append(("docker_scope", b"docker-" + cid + b".scope"))
            definitions.append(("container_id", cid))
            if len(cid) >= 12:
                definitions.append(("container_short_id", cid[:12]))
        if result.name:
            definitions.append(("container_name", result.name.encode("utf-8").lower()))
    # Longest first prevents a short ID from consuming the beginning of a full ID.
    definitions.sort(key=lambda item: len(item[1]), reverse=True)
    kind_by_anchor: Dict[bytes, str] = {}
    for kind, anchor in definitions:
        kind_by_anchor.setdefault(anchor, kind)
    alternatives = [re.escape(anchor) for anchor in kind_by_anchor]
    return re.compile(b"|".join(alternatives)), kind_by_anchor


def classify_memory_anchor(kind: str, lower_window: bytes, start: int, end: int) -> Optional[str]:
    if kind.startswith("state_word_"):
        state = kind.removeprefix("state_word_")
        prefix = lower_window[max(0, start - 80):start]
        suffix = lower_window[end:min(len(lower_window), end + 40)]
        value_form = re.search(rb'"(?:status|state)"\s*:\s*$', prefix) is not None
        flag_form = state in {"paused", "restarting", "dead"} and re.match(rb"\s*:\s*true\b", suffix) is not None
        return f"state_{state}" if value_form or flag_form else None
    if kind == "frozen_word":
        suffix = lower_window[end:min(len(lower_window), end + 24)]
        return "frozen_1" if re.match(rb"\s+1\b", suffix) else None
    return kind


def scan_memory(
    path: Path,
    results: Iterable[ContainerResult],
    max_hits: int,
    chunk_size: int = 32 * 1024 * 1024,
) -> Tuple[Dict[str, Any], List[MemoryHit], List[str]]:
    segments, warnings = parse_lime_segments(path)
    segment_starts = [s["file_data_start"] for s in segments]
    pattern, kind_by_anchor = compile_memory_anchors(results)
    counts: Dict[str, int] = {}
    hits: List[MemoryHit] = []
    seen: set[Tuple[str, int]] = set()
    digest = hashlib.sha256()
    overlap_size = 1024
    carry = b""
    file_pos = 0

    def physical_for(file_offset: int) -> Optional[int]:
        if not segments:
            return file_offset
        index = bisect.bisect_right(segment_starts, file_offset) - 1
        if index < 0:
            return None
        segment = segments[index]
        if file_offset >= segment["file_data_end"]:
            return None
        return segment["physical_start"] + file_offset - segment["file_data_start"]

    with path.open("rb") as handle:
        while True:
            block = handle.read(chunk_size)
            if not block:
                break
            digest.update(block)
            window = carry + block
            lower_window = window.lower()
            base_offset = file_pos - len(carry)
            for match in pattern.finditer(lower_window):
                absolute = base_offset + match.start()
                absolute_end = base_offset + match.end()
                if absolute_end <= file_pos:
                    continue
                anchor_kind = kind_by_anchor.get(match.group(0), "unknown")
                kind = classify_memory_anchor(anchor_kind, lower_window, match.start(), match.end())
                if kind is None:
                    continue
                key = (kind, absolute)
                if key in seen:
                    continue
                seen.add(key)
                counts[kind] = counts.get(kind, 0) + 1
                if counts[kind] <= max_hits:
                    left = max(0, match.start() - 120)
                    right = min(len(window), match.end() + 180)
                    matched = match.group(0).decode("utf-8", errors="replace")
                    hits.append(MemoryHit(kind, matched, absolute, physical_for(absolute), printable_context(window[left:right])))
            carry = window[-overlap_size:]
            file_pos += len(block)
    info: Dict[str, Any] = {
        "path": str(path.resolve()),
        "size_bytes": path.stat().st_size,
        "sha256": digest.hexdigest(),
        "format": "LiME" if segments else "raw/unknown",
        "lime_segments": segments,
        "hit_counts": counts,
    }
    return info, hits, warnings


def discover_memory(case_root: Path) -> Optional[Path]:
    suffixes = {".lime", ".raw", ".mem", ".bin", ".img", ".dump", ".dmp"}
    candidates = [p for p in case_root.iterdir() if p.is_file() and p.suffix.lower() in suffixes]
    if not candidates:
        return None
    return max(candidates, key=lambda p: p.stat().st_size)


def escape_md(value: Any) -> str:
    return str(value).replace("|", "\\|").replace("\n", " ")


def generate_markdown(analyzer: CaseAnalyzer, generated_at: str) -> str:
    lines = [
        "# Docker 컨테이너 상태 식별 보고서",
        "",
        f"- 생성 시각: `{generated_at}`",
        f"- 케이스 경로: `{analyzer.case_root}`",
    ]
    if analyzer.memory_info:
        info = analyzer.memory_info
        lines.extend([
            f"- 메모리 이미지: `{info.get('path')}`",
            f"- 이미지 형식/크기: `{info.get('format')}` / `{info.get('size_bytes', 0):,}` bytes",
            f"- SHA-256: `{info.get('sha256', '-')}`",
        ])
    lines.append("")
    for result in analyzer.results.values():
        cid_display = result.container_id if result.container_id != "unknown" else "미식별"
        lines.extend([
            f"## 컨테이너 `{cid_display}`",
            "",
            f"**최종 판정: `{result.state.upper()}` — 신뢰도 {result.confidence}% ({result.confidence_label})**",
            "",
            f"- 이름: `{result.name or '-'}`",
            f"- 호스트 PID: `{result.pid if result.pid is not None else '-'}`",
            "",
            "### 상태별 점수",
            "",
            "| 상태 | 점수 |",
            "|---|---:|",
        ])
        for state, score in sorted(result.scores.items(), key=lambda item: item[1], reverse=True):
            lines.append(f"| {state} | {score} |")
        lines.extend([
            "",
            "### 판정 증거",
            "",
            "| 신뢰성 | 출처 | 관측값 | 지지 상태 | 설명 |",
            "|---|---|---|---|---|",
        ])
        for ev in sorted(result.evidence, key=lambda item: item.weight, reverse=True):
            lines.append(
                f"| {escape_md(ev.reliability)} | {escape_md(ev.source)} | {escape_md(ev.observed)} | "
                f"{escape_md(ev.claim or '-')} | {escape_md(ev.detail)} |"
            )
        if result.warnings:
            lines.extend(["", "### 불일치/주의", ""])
            lines.extend(f"- {warning}" for warning in result.warnings)
        if result.memory_hits:
            lines.extend([
                "",
                "### 메모리 교차증거 (최대 표본)",
                "",
                "| 종류 | 파일 오프셋 | 물리주소 | 일치값 | 마스킹된 문맥 |",
                "|---|---:|---:|---|---|",
            ])
            for hit in result.memory_hits:
                phys = f"0x{hit.physical_address:x}" if hit.physical_address is not None else "-"
                lines.append(
                    f"| {escape_md(hit.kind)} | 0x{hit.file_offset:x} | {phys} | "
                    f"`{escape_md(hit.matched[:100])}` | `{escape_md(hit.context)}` |"
                )
        lines.append("")
    if analyzer.case_warnings:
        lines.extend(["## 케이스 주의사항", ""] + [f"- {w}" for w in analyzer.case_warnings] + [""])
    lines.extend([
        "## 해석 원칙",
        "",
        "메모리 문자열은 해제되지 않은 객체·명령 기록·페이지 캐시 때문에 과거 상태가 남을 수 있습니다. "
        "따라서 이 도구는 Docker daemon 메타데이터와 cgroup 커널 상태를 우선하며, RAM 문자열은 교차증거로만 가중합니다. "
        "`proc/status`의 `S (sleeping)`도 일반 수면과 cgroup freeze를 구분하지 못하므로 단독으로 PAUSED를 뜻하지 않습니다.",
        "",
    ])
    return "\n".join(lines)


def result_to_dict(analyzer: CaseAnalyzer, generated_at: str) -> Dict[str, Any]:
    return {
        "schema_version": 1,
        "generated_at": generated_at,
        "case_root": str(analyzer.case_root),
        "memory": analyzer.memory_info,
        "case_warnings": analyzer.case_warnings,
        "containers": [asdict(result) for result in analyzer.results.values()],
    }


def console_summary(analyzer: CaseAnalyzer, json_path: Path, md_path: Path) -> str:
    lines = ["Docker 컨테이너 상태 식별 완료"]
    for result in analyzer.results.values():
        label = result.name or result.container_id[:12]
        lines.append(f"- {label}: {result.state.upper()} / {result.confidence}% ({result.confidence_label})")
        strongest = sorted((e for e in result.evidence if e.claim == result.state), key=lambda e: e.weight, reverse=True)[:3]
        for ev in strongest:
            lines.append(f"  · {ev.source}: {ev.observed}")
        if result.warnings:
            lines.append(f"  · 주의 {len(result.warnings)}건: {result.warnings[0]}")
    lines.extend([f"- JSON: {json_path}", f"- 보고서: {md_path}"])
    return "\n".join(lines)


def parse_args(argv: Optional[Sequence[str]] = None) -> argparse.Namespace:
    script_dir = Path(__file__).resolve().parent
    parser = argparse.ArgumentParser(
        description="Identify Docker container lifecycle state from collected metadata, cgroup/proc snapshots, and RAM.",
    )
    parser.add_argument("case", nargs="?", type=Path, default=script_dir.parent, help="Case directory (default: parent of this tool)")
    parser.add_argument("--memory", type=Path, help="Explicit .lime/.raw memory image")
    parser.add_argument("--no-memory", action="store_true", help="Skip memory image scanning")
    parser.add_argument("--max-memory-hits", type=int, default=6, help="Maximum saved hit samples per signature (default: 6)")
    parser.add_argument("--output", type=Path, default=script_dir / "결과", help="Output directory (default: 상태식별/결과)")
    return parser.parse_args(argv)


def main(argv: Optional[Sequence[str]] = None) -> int:
    args = parse_args(argv)
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
        sys.stderr.reconfigure(encoding="utf-8", errors="replace")
    case_root = args.case.resolve()
    if not case_root.is_dir():
        print(f"오류: 케이스 폴더가 없습니다: {case_root}", file=sys.stderr)
        return 2
    analyzer = CaseAnalyzer(case_root, max(1, args.max_memory_hits))
    analyzer.collect()
    if not analyzer.results:
        analyzer.get_result(None).warnings.append("No container identity could be derived from case artifacts")
    memory_path: Optional[Path] = None
    if not args.no_memory:
        memory_path = args.memory.resolve() if args.memory else discover_memory(case_root)
        if memory_path:
            print(f"메모리 스캔 중: {memory_path.name} ({memory_path.stat().st_size:,} bytes)", file=sys.stderr)
            try:
                info, hits, warnings = scan_memory(memory_path, analyzer.results.values(), analyzer.max_memory_hits)
                analyzer.memory_info = info
                analyzer.case_warnings.extend(warnings)
                analyzer.attach_memory_hits(hits)
            except OSError as exc:
                analyzer.case_warnings.append(f"Memory scan failed: {exc}")
        else:
            analyzer.case_warnings.append("No memory image was discovered")
    analyzer.decide()
    generated_at = dt.datetime.now(dt.timezone.utc).astimezone().isoformat(timespec="seconds")
    output = args.output.resolve()
    output.mkdir(parents=True, exist_ok=True)
    json_path = output / "상태식별_결과.json"
    md_path = output / "상태식별_보고서.md"
    json_path.write_text(json.dumps(result_to_dict(analyzer, generated_at), ensure_ascii=False, indent=2), encoding="utf-8")
    md_path.write_text(generate_markdown(analyzer, generated_at), encoding="utf-8")
    print(console_summary(analyzer, json_path, md_path))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

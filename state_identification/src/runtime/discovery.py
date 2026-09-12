"""Multi-strategy Docker container discovery from cached process memory.

Architecture: instead of "find string data → scan for header pointing to it"
(which requires one full memory scan per candidate address), we use:

  "scan for Go string headers with known lengths → validate pointed-to data"

This reduces discovery from hundreds of scans to just 2-3 total scans,
regardless of how many containers exist.

Strategies:
  1. Root header scan: find all 16-byte patterns where len=91 (exact root path length)
  2. PID-based: find container PIDs → State structs → backref to Container
  3. ID header scan: find all 16-byte patterns where len=64 (container ID length)
"""
import struct
from .structs import (
    CONTAINER, CONTAINER_SIZE, STATE, STATE_SIZE,
    ROOT_PREFIX, ROOT_PREFIX_LEN, CID_LEN, EXACT_ROOT_LEN,
    HEX_BYTES, StructReader
)


def _is_hex64(data):
    return len(data) == 64 and all(b in HEX_BYTES for b in data)


def validate_container(reader, cbase, strict_bools=True):
    """Validate a candidate Container struct at cbase.
    Returns info dict if valid, None otherwise.

    strict_bools=False allows containers whose State booleans are
    uninitialized (e.g. just-created containers with stale heap data).
    """
    cid = reader.read_string(cbase, CONTAINER['ID'][0])
    if not cid or len(cid) != CID_LEN:
        return None
    if not all(c in '0123456789abcdef' for c in cid):
        return None

    name = reader.read_string(cbase, CONTAINER.get('Name', (0,0))[0])
    state_ptr = reader.read_ptr(cbase, CONTAINER['State'][0])
    if not state_ptr or state_ptr < 0x10000:
        return None

    bools_valid = True
    bools_raw = reader.read_bytes(state_ptr + 0x08, 6)
    if bools_raw is None or not all(b in (0, 1) for b in bools_raw):
        if strict_bools:
            return None
        bools_valid = False

    if bools_valid:
        pid = reader.read_int(state_ptr, STATE['Pid'][0])
        # Since Pid offset might not be calibrated, we can't reliably reject based on it.
        # if pid is None or pid < 0 or pid > 1_000_000:
        #     return None

    # Try to read Root if it is still at the default offset, otherwise ignore
    root = reader.read_string(cbase, CONTAINER.get('Root', (0, 0))[0]) if 'Root' in CONTAINER else ""
    # A hex digest followed by zero bytes is not sufficient container evidence.
    rooted = root == ROOT_PREFIX.decode() + cid
    config_ptr = reader.read_ptr(cbase, CONTAINER['Config'][0])
    named = bool(name and name.startswith('/') and name.count('/') == 1 and len(name) > 1)
    if not rooted and not (named and config_ptr and config_ptr > 0x10000):
        return None
    if bools_valid:
        pid = reader.read_int(state_ptr, STATE['Pid'][0])
        if pid is None or not 0 <= pid <= 4194304:
            bools_valid = False

    return {
        'cbase': cbase,
        'cid': cid,
        'name': name,
        'root': root,
        'state_ptr': state_ptr,
        'state_valid': bools_valid,
        'strategy': None,
    }


def _pick_best(existing, new):
    """Choose the better Container struct when we have duplicates for one CID."""
    candidates = [dict(c) for c in [existing, *existing.get('_alternatives', []), new, *new.get('_alternatives', [])]]
    unique = {}
    for candidate in candidates:
        candidate.pop('_alternatives', None)
        unique[candidate['cbase']] = candidate
    best = max(unique.values(), key=lambda c: (bool(c.get('state_valid')), bool(c.get('root')), bool(c.get('name'))))
    best = dict(best)
    best['_alternatives'] = [c for addr, c in unique.items() if addr != best['cbase']]
    return best


def discover_via_root_headers(mem, reader, log):
    """Strategy 1: Scan for Go string headers where len == EXACT_ROOT_LEN (91).

    One full scan of cached memory. For each hit, read the pointer and
    check if it points to a valid /var/lib/docker/containers/<CID> string.
    """
    len_bytes = struct.pack('<Q', EXACT_ROOT_LEN)
    len_hits = mem.find_all(len_bytes)
    log(f"    len=91 occurrences: {len(len_hits)}")

    results = {}
    checked = 0
    for len_addr in len_hits:
        ptr_bytes = mem.read_safe(len_addr - 8, 8)
        if ptr_bytes is None:
            continue
        ptr = struct.unpack('<Q', ptr_bytes)[0]
        if ptr < 0x10000:
            continue

        data = mem.read_safe(ptr, EXACT_ROOT_LEN)
        if data is None or not data.startswith(ROOT_PREFIX):
            continue
        cid_part = data[ROOT_PREFIX_LEN:]
        if not _is_hex64(cid_part):
            continue

        checked += 1
        cid = cid_part.decode()
        header_addr = len_addr - 8
        cbase = header_addr - CONTAINER['Root'][0]
        if cbase < 0x10000:
            continue

        v = validate_container(reader, cbase, strict_bools=False)
        if v and v['cid'] == cid:
            v['strategy'] = 'root_header'
            if cid not in results:
                results[cid] = v
            else:
                results[cid] = _pick_best(results[cid], v)

    log(f"    Validated {checked} root headers, found {len(results)} containers")
    return results


def discover_via_id_headers(mem, reader, exclude_cids, log):
    """Strategy 3: Scan for Go string headers where len == CID_LEN (64).

    One full scan. For each hit, check if the pointer target is 64 hex chars.
    Extra validation: Root must be a valid Docker path (not system paths).
    """
    len_bytes = struct.pack('<Q', CID_LEN)
    len_hits = mem.find_all(len_bytes)
    log(f"    len=64 occurrences: {len(len_hits)}")

    results = {}
    for len_addr in len_hits:
        ptr_bytes = mem.read_safe(len_addr - 8, 8)
        if ptr_bytes is None:
            continue
        ptr = struct.unpack('<Q', ptr_bytes)[0]
        if ptr < 0x10000:
            continue

        data = mem.read_safe(ptr, CID_LEN)
        if data is None or not _is_hex64(data):
            continue

        cid = data.decode()
        if cid in exclude_cids:
            continue

        header_addr = len_addr - 8
        cbase = header_addr - CONTAINER['ID'][0]
        if cbase < 0x10000:
            continue

        v = validate_container(reader, cbase)
        if v and v['cid'] == cid:
            root = v.get('root')
            if root and not root.startswith('/var/lib/docker'):
                continue
            name = v.get('name') or ''
            if name.startswith('/proc/') or name.startswith('/sys/') or name.startswith('/dev/'):
                continue
            v['strategy'] = 'id_header'
            if cid not in results:
                results[cid] = v
            else:
                results[cid] = _pick_best(results[cid], v)

    log(f"    Validated ID headers, found {len(results)} new containers")
    return results


def discover_via_pids(mem, reader, container_pids, already_found, log):
    """Strategy 2: Find container PIDs in State.Pid, backref to Container.

    Optimized: skips PIDs already resolved by other strategies, filters
    State candidates by Running=True, uses batch pointer search.
    """
    skip_pids = set()
    for cid, info in already_found.items():
        state_ptr = info.get('state_ptr')
        if state_ptr:
            pid_raw = mem.read_safe(state_ptr + STATE['Pid'][0], 8)
            if pid_raw:
                skip_pids.add(struct.unpack('<q', pid_raw)[0])

    search_pids = container_pids - skip_pids
    if not search_pids:
        log(f"    All PIDs already resolved by earlier strategies")
        return {}

    log(f"    Searching {len(search_pids)} PIDs (skipped {len(skip_pids)} already found)")

    all_valid_states = {}
    for pid_val in sorted(search_pids):
        pid_bytes = struct.pack('<q', pid_val)
        hits = mem.find_all(pid_bytes)
        valid_states = []

        for off in hits:
            state_base = off - STATE['Pid'][0]
            if state_base < 0x10000:
                continue
            bools_raw = mem.read_safe(state_base + 0x08, 6)
            if bools_raw is None or not all(b in (0, 1) for b in bools_raw):
                continue
            running = bools_raw[0]
            if not running:
                continue
            exit_code = mem.read_safe(state_base + STATE['ExitCode'][0], 8)
            if exit_code is None:
                continue
            ec = struct.unpack('<q', exit_code)[0]
            if ec < -1000 or ec > 1000:
                continue
            valid_states.append(state_base)

        log(f"    PID {pid_val}: {len(hits)} raw hits, {len(valid_states)} active State structs")
        for s in valid_states:
            all_valid_states[s] = pid_val

    if not all_valid_states:
        return {}

    log(f"    Batch searching for pointers to {len(all_valid_states)} State structs...")
    ptr_hits = mem.find_any_pointer_to(set(all_valid_states.keys()))
    log(f"    Found {len(ptr_hits)} pointer hits")

    results = {}
    for p_addr, state_base in ptr_hits:
        cbase = p_addr - CONTAINER['State'][0]
        if cbase < 0x10000:
            continue
        v = validate_container(reader, cbase)
        if v:
            v['strategy'] = 'pid'
            cid = v['cid']
            if cid not in results:
                results[cid] = v
            else:
                results[cid] = _pick_best(results[cid], v)

    return results


def discover_all_containers(mem, reader, processes, name_hints=None, log=print):
    """Run all discovery strategies and merge results.

    Performance: typically 3-8 full scans of cached memory total,
    regardless of container count. Each scan takes ~2s on 3.4 GB.
    """
    all_found = {}

    # Strategy 1: Root header scan (1 full scan)
    log("  Strategy 1: Root header scan (len=91)...")
    s1 = discover_via_root_headers(mem, reader, log)
    log(f"    → {len(s1)} container(s)")
    all_found.update(s1)

    # Strategy 2: PID-based (1 scan per PID + 1 per valid State)
    container_pids = set()
    proc_list = processes.values() if isinstance(processes, dict) else (processes or [])
    shim_pids = set()
    for p in proc_list:
        comm = getattr(p, 'comm', None) or (p.get('comm') or p.get('name') if isinstance(p, dict) else '')
        pid = getattr(p, 'pid', None) or (p.get('pid') if isinstance(p, dict) else None)
        if pid is not None and 'containerd-shim' in str(comm):
            shim_pids.add(pid)
    for p in proc_list:
        comm = getattr(p, 'comm', None) or (p.get('comm') or p.get('name') if isinstance(p, dict) else '')
        pid = getattr(p, 'pid', None) or (p.get('pid') if isinstance(p, dict) else None)
        ppid = getattr(p, 'ppid', None) or (p.get('ppid') if isinstance(p, dict) else None)
        if pid is not None and ppid in shim_pids and 'containerd-shim' not in str(comm):
            container_pids.add(pid)

    if container_pids:
        log(f"  Strategy 2: PID-based (PIDs: {sorted(container_pids)})...")
        s2 = discover_via_pids(mem, reader, container_pids, all_found, log)
        new_pids = {c: v for c, v in s2.items() if c not in all_found}
        log(f"    → {len(s2)} container(s) ({len(new_pids)} new)")
        for cid, v in s2.items():
            if cid not in all_found:
                all_found[cid] = v
            else:
                all_found[cid] = _pick_best(all_found[cid], v)

    # Strategy 3: ID header scan (1 full scan, skip already-found CIDs)
    log(f"  Strategy 3: ID header scan (len=64, excluding {len(all_found)} found)...")
    s3 = discover_via_id_headers(mem, reader, set(), log)
    log(f"    → {len(s3)} new container(s)")
    for cid, v in s3.items():
        if cid not in all_found:
            all_found[cid] = v
        else:
            all_found[cid] = _pick_best(all_found[cid], v)

    # Count total unique CIDs from root paths for reporting
    root_hits = mem.find_all(ROOT_PREFIX)
    total_cids = set()
    for addr in root_hits:
        after = mem.read_safe(addr + ROOT_PREFIX_LEN, CID_LEN)
        if after and _is_hex64(after):
            total_cids.add(after.decode())

    log(f"\n  Discovery complete: {len(all_found)}/{len(total_cids)} containers resolved")

    unresolved = total_cids - set(all_found.keys())
    if unresolved:
        log(f"  Unresolved CIDs ({len(unresolved)}):")
        for cid in sorted(unresolved):
            log(f"    {cid[:12]}...")
            all_found[cid] = {'cbase': 0, 'cid': cid, 'strategy': 'root_path_residue',
                              'state_valid': False, 'confidence': 'low'}

    return all_found

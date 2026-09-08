#!/usr/bin/env python3
"""Docker Container Memory Forensics Analyzer v4

Analyzes Linux memory dumps to discover Docker containers and reconstruct
their lifecycle state from dockerd's Go heap structures.

Architecture:
  1. Volatility3 extracts dockerd's full virtual memory ONCE (~50s)
  2. All pattern matching runs on cached in-memory data (<5s total)
  3. Multi-strategy container discovery with struct-level validation
  4. Event ring buffer extraction for lifecycle reconstruction

Usage:
  python -m src.analyze <dump_path> [options]
  python -m src.analyze dump2_multi/multi_containers.raw
  python -m src.analyze dump1/round1_basic/S02_running/S02_running.lime
  python -m src.analyze dump1/round1_basic   (scans S0X subdirs)
"""
import sys
import os
import json
import time
import argparse
import datetime

sys.stdout.reconfigure(encoding='utf-8', errors='replace')


def log(msg=''):
    print(msg, flush=True)


SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
PROJECT_DIR = os.path.dirname(SCRIPT_DIR)
sys.path.insert(0, PROJECT_DIR)

from src.memory import VolatilityLoader, ProcessInfo
from src.structs import (
    StructReader, CONTAINER, STATE, CONFIG, HOSTCONFIG,
    state_to_status, CONTAINER_SIZE
)
from src.discovery import discover_all_containers
from src.events import extract_events

DEFAULT_SYMBOL_PATHS = [os.path.join(PROJECT_DIR, 'dump1')]
DEFAULT_VENV = r'C:\Users\gksgm\AppData\Local\AndroidLab\.venv\Lib\site-packages'

EXPECTED_STATES = {
    'S00': 'baseline', 'S01': 'created', 'S02': 'running', 'S03': 'paused',
    'S04': 'restarting', 'S05': 'exited', 'S06': 'removing', 'S07': 'dead',
    'T0': 'destroyed', 'T1': 'destroyed', 'T2': 'destroyed', 'T3': 'destroyed',
}


def find_dump_files(input_path):
    """Find memory dump files from input path.

    Supports:
      - Single file (*.raw, *.lime)
      - Directory with S0X subdirs (round1_basic format)
      - Flat directory with dump files
    """
    entries = []
    if os.path.isfile(input_path):
        label = os.path.splitext(os.path.basename(input_path))[0]
        entries.append((label, input_path, None))
        return entries

    if not os.path.isdir(input_path):
        print(f"Error: '{input_path}' is not a file or directory")
        sys.exit(1)

    subdirs = sorted(os.listdir(input_path))
    for d in subdirs:
        full = os.path.join(input_path, d)
        if not os.path.isdir(full):
            continue
        prefix = d.split('_')[0]
        expected = EXPECTED_STATES.get(prefix)
        for f in os.listdir(full):
            if f.endswith('.lime') or f.endswith('.raw'):
                entries.append((d, os.path.join(full, f), expected))
                break

    if not entries:
        for f in sorted(os.listdir(input_path)):
            fp = os.path.join(input_path, f)
            if os.path.isfile(fp) and (f.endswith('.lime') or f.endswith('.raw')):
                label = os.path.splitext(f)[0]
                entries.append((label, fp, None))

    return entries


def get_shim_child_pids(processes):
    """Identify container process PIDs (children of containerd-shim)."""
    shim_pids = {p.pid for p in processes if 'containerd-shim' in p.comm}
    child_pids = set()
    for p in processes:
        if p.ppid in shim_pids and 'containerd-shim' not in p.comm:
            child_pids.add(p.pid)
    return child_pids


def analyze_single_dump(dump_path, label, expected_state=None,
                        skip_events=False, name_hints=None, verbose=False):
    """Analyze one memory dump file. Returns dict with results."""
    t_total = time.time()

    log(f"\n{'='*60}")
    log(f"  [{label}] {os.path.basename(dump_path)}")
    log(f"{'='*60}")

    loader = VolatilityLoader(
        dump_path,
        symbol_paths=DEFAULT_SYMBOL_PATHS,
        venv_path=DEFAULT_VENV,
    )
    log("  Loading...")
    loader.initialize()

    processes = loader.list_processes()
    dockerd = [p for p in processes if p.comm == 'dockerd']
    containerd = [p for p in processes if p.comm == 'containerd']
    shims = [p for p in processes if 'containerd-shim' in p.comm]

    if not dockerd:
        log("  ERROR: dockerd process not found!")
        return {'label': label, 'error': 'no_dockerd', 'containers': []}

    noop = (lambda *a: None) if not verbose else log
    mem, extract_time = loader.extract_process_memory('dockerd')
    mb = mem.total_bytes / (1024*1024)
    log(f"  Memory: {mb:.0f} MB ({extract_time:.1f}s)")

    reader = StructReader(mem)

    t0 = time.time()
    containers = discover_all_containers(mem, reader, processes, name_hints=name_hints, log=noop)
    discover_time = time.time() - t0
    log(f"  Found {len(containers)} container(s) ({discover_time:.1f}s)")

    results = []
    for cid, info in sorted(containers.items(), key=lambda x: x[1].get('name', '')):
        cbase = info['cbase']
        c = reader.parse_container(cbase)
        c['_cbase'] = cbase
        c['_strategy'] = info['strategy']

        state_ptr = c.get('State_ptr')
        state_data = None
        if state_ptr and state_ptr > 0x10000:
            state_data = reader.parse_state(state_ptr)

        config_data = None
        config_ptr = c.get('Config_ptr')
        if config_ptr and config_ptr > 0x10000:
            config_data = reader.parse_config(config_ptr)

        hc_data = None
        hc_ptr = c.get('HostConfig_ptr')
        if hc_ptr and hc_ptr > 0x10000:
            hc_data = reader.parse_hostconfig(hc_ptr)

        if state_data:
            state_data['HasBeenStartedBefore'] = c.get('HasBeenStartedBefore')
            if info.get('state_valid', True):
                status = state_to_status(state_data)
            else:
                status = 'created' if not c.get('HasBeenStartedBefore') else 'unknown'
        else:
            status = 'unknown'

        is_removed = (state_data and state_data.get('Dead') and state_data.get('Removed'))

        entry = {
            'container_id': cid,
            'container_name': c.get('Name', ''),
            'status': status,
            'strategy': info['strategy'],
            'is_removed': is_removed,
            'state_valid': info.get('state_valid', True),
            'container': c,
            'state': state_data,
            'config': config_data,
            'hostconfig': hc_data,
        }
        results.append(entry)

        tag = ' [Removed]' if is_removed else ''
        status_display = status.upper() + tag
        sv = info.get('state_valid', True)
        if not sv:
            status_display += ' (state uninitialized)'
        log(f"\n  ── Container [{cid[:12]}] {c.get('Name', '?')} ──")
        log(f"     Status:       {status_display}")
        if config_data and config_data.get('Image'):
            log(f"     Image:        {config_data['Image']}")
        if state_data and sv:
            log(f"     PID:          {state_data.get('Pid', '-')}")
            log(f"     ExitCode:     {state_data.get('ExitCode', '-')}")
            flags = (f"R={int(state_data.get('Running') or 0)} "
                     f"Pa={int(state_data.get('Paused') or 0)} "
                     f"Re={int(state_data.get('Restarting') or 0)} "
                     f"D={int(state_data.get('Dead') or 0)} "
                     f"RI={int(state_data.get('RemovalInProgress') or 0)} "
                     f"Rm={int(state_data.get('Removed') or 0)}")
            log(f"     State Flags:  {flags}")
            sa = state_data.get('StartedAt')
            fa = state_data.get('FinishedAt')
            log(f"     StartedAt:    {sa if sa else '-'}")
            log(f"     FinishedAt:   {fa if fa else '-'}")
        elif state_data and not sv:
            log(f"     State Flags:  (unreadable - stale heap data)")
        log(f"     RestartCount: {c.get('RestartCount', 0)}")
        log(f"     Strategy:     {info['strategy']}")

    events_list = []
    if not skip_events and results:
        t0 = time.time()
        target_cids = {r['container_id'] for r in results}
        events_list = extract_events(mem, reader, target_cids=target_cids, log=noop)
        evt_time = time.time() - t0
        if events_list:
            log(f"\n  Events: {len(events_list)} found ({evt_time:.1f}s)")
            for cid in sorted(target_cids):
                cid_events = [e for e in events_list if e['container_id'] == cid]
                if cid_events:
                    log(f"    [{cid[:12]}] {len(cid_events)} events:")
                    for ev in cid_events[-10:]:
                        ts = ev['timestamp'].strftime('%H:%M:%S') if ev.get('timestamp') else '?'
                        log(f"      {ts} {ev['action']}")

            destroy_cids = {e['container_id'] for e in events_list
                            if e.get('action') == 'destroy'}
            for r in results:
                if r['status'] == 'dead' and r['container_id'] in destroy_cids:
                    r['status'] = 'destroyed'
                    cid_short = r['container_id'][:12]
                    log(f"\n  >> [{cid_short}] DEAD -> DESTROYED (destroy event detected)")

    total_time = time.time() - t_total
    log(f"\n  Total: {total_time:.1f}s")

    return {
        'label': label,
        'dump_path': dump_path,
        'expected_state': expected_state,
        'containers': results,
        'events': events_list,
        'timing': {
            'total': total_time,
            'extract': extract_time,
            'discover': discover_time,
        },
        'process_info': {
            'dockerd_pid': dockerd[0].pid if dockerd else None,
            'shim_count': len(shims),
            'container_pids': sorted(get_shim_child_pids(processes)),
        },
    }


def print_summary(all_results):
    """Print summary table across all analyzed dumps."""
    log(f"\n{'='*60}")
    log("  SUMMARY")
    log(f"{'='*60}")

    log(f"  {'Dump':<15} {'CID':<14} {'Name':<18} {'Status':<14} {'Time':>5}")
    log(f"  {'-'*15} {'-'*14} {'-'*18} {'-'*14} {'-'*5}")

    match_count = 0
    total_count = 0

    for r in all_results:
        label = r['label'][:15]
        expected = r.get('expected_state')
        t = r['timing']['total']

        if not r['containers']:
            log(f"  {label:<15} {'-':<14} {'':<18} {'N/A':<14} {t:>4.0f}s")
            continue

        for c in r['containers']:
            cid = c['container_id'][:12]
            name = (c.get('container_name') or '?')[:18]
            status = c['status'].upper()
            if c.get('is_removed'):
                status += '*'

            match_str = ''
            if expected:
                total_count += 1
                if c['status'] == expected:
                    match_str = ' OK'
                    match_count += 1
                else:
                    match_str = f' !=({expected})'

            log(f"  {label:<15} {cid:<14} {name:<18} {status:<14} {t:>4.0f}s{match_str}")

    if total_count > 0:
        log(f"\n  Accuracy: {match_count}/{total_count} ({100*match_count/total_count:.0f}%)")
    log(f"  * = Removed flag set (Dead+Removed)")


def serialize_results(all_results, output_path):
    """Save results to JSON."""
    def default(obj):
        if isinstance(obj, datetime.datetime):
            return obj.isoformat()
        if isinstance(obj, set):
            return list(obj)
        if isinstance(obj, bytes):
            return obj.hex()
        return str(obj)

    serializable = []
    for r in all_results:
        entry = {
            'label': r['label'],
            'dump_path': r['dump_path'],
            'expected_state': r.get('expected_state'),
            'timing': r['timing'],
            'process_info': r['process_info'],
            'containers': [],
            'events': [],
        }
        for c in r['containers']:
            ce = {
                'container_id': c['container_id'],
                'container_name': c.get('container_name'),
                'status': c['status'],
                'strategy': c['strategy'],
            }
            if c.get('state'):
                ce['state'] = {k: v for k, v in c['state'].items()
                               if not k.endswith('_raw')}
            if c.get('config'):
                ce['config'] = c['config']
            if c.get('container'):
                ct = c['container']
                ce['meta'] = {
                    'Root': ct.get('Root'),
                    'Path': ct.get('Path'),
                    'ImageID': ct.get('ImageID'),
                    'Driver': ct.get('Driver'),
                    'OS': ct.get('OS'),
                    'Created': ct.get('Created'),
                    'RestartCount': ct.get('RestartCount'),
                    'HasBeenStartedBefore': ct.get('HasBeenStartedBefore'),
                    'HasBeenManuallyStopped': ct.get('HasBeenManuallyStopped'),
                    'HasBeenManuallyRestarted': ct.get('HasBeenManuallyRestarted'),
                }
            entry['containers'].append(ce)

        for ev in r.get('events', []):
            entry['events'].append({
                'action': ev['action'],
                'container_id': ev['container_id'],
                'timestamp': ev.get('timestamp'),
                'time_unix': ev.get('time_unix'),
            })
        serializable.append(entry)

    with open(output_path, 'w', encoding='utf-8') as f:
        json.dump(serializable, f, indent=2, default=default, ensure_ascii=False)
    log(f"\n Results saved to {output_path}")


def main():
    parser = argparse.ArgumentParser(
        description='Docker Container Memory Forensics Analyzer v4')
    parser.add_argument('input', help='Memory dump file or directory')
    parser.add_argument('--no-events', action='store_true',
                        help='Skip event extraction')
    parser.add_argument('--names', nargs='*',
                        help='Container name hints for discovery (e.g., multi_ test_)')
    parser.add_argument('--output', '-o', help='Output JSON path')
    parser.add_argument('--verbose', '-v', action='store_true')
    args = parser.parse_args()

    input_path = os.path.abspath(args.input)
    entries = find_dump_files(input_path)

    if not entries:
        log(f"No dump files found in '{input_path}'")
        sys.exit(1)

    log(f"Docker Container Memory Forensics Analyzer v4")
    log(f"Analyzing {len(entries)} dump(s).")

    all_results = []
    for label, dump_path, expected in entries:
        result = analyze_single_dump(
            dump_path, label,
            expected_state=expected,
            skip_events=args.no_events,
            name_hints=args.names,
            verbose=args.verbose,
        )
        all_results.append(result)

    if len(all_results) > 0:
        print_summary(all_results)

    output_path = args.output
    if not output_path:
        base = os.path.basename(input_path)
        if os.path.isfile(input_path):
            base = os.path.splitext(base)[0]
        output_path = os.path.join(PROJECT_DIR, f'{base}_results.json')

    serialize_results(all_results, output_path)


if __name__ == '__main__':
    main()

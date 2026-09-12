"""Shared collection; state and reconstruction consume the same evidence."""
import time
from pathlib import Path
from .memory import VolatilityLoader
from .structs import StructReader, CONTAINER, STATE, CONFIG, HOSTCONFIG
from .structs_containerd import ContainerdStructReader
from .discovery import discover_all_containers
from .discovery_containerd import discover_containerd_containers, discover_containerd_images
from .discovery_shim import discover_shim_processes
from .events import extract_events
from .state_identification import identify, select_candidate
from .evidence import ROOT, source_manifest


def collect(dump_path, reconstruct=False, skip_events=False, symbol_paths=None, log=print):
    started = time.monotonic()
    initial_sources = source_manifest()
    loader = VolatilityLoader(str(dump_path), symbol_paths=symbol_paths or [str(ROOT / 'symbols' / 'linux'), str(ROOT / 'dumps' / 'dump1')])
    loader.log = log
    log(f'Loading {Path(dump_path).name}')
    loader.initialize()
    processes = loader.list_processes()
    kernel = loader.discover_containers_via_kernel() if reconstruct else {}
    memories = loader.extract_target_processes(['dockerd', 'containerd', 'containerd-shim'] if reconstruct else ['dockerd'])
    log('Parsing dockerd heap' if not reconstruct else 'Correlating user-space and kernel evidence')
    containers, events, runtime_profiles, read_ledger = {}, [], {}, []
    diagnostics = loader.diagnostics

    def entry(cid):
        return containers.setdefault(cid, {'container_id': cid, 'dockerd_candidates': [],
                    'containerd_candidates': [], 'containerd_image_candidates': [],
                    'shim_candidates': [], 'events': [], 'parsing_errors': []})

    for cid, value in kernel.items():
        entry(cid)['kernel'] = value
    for pid, value in memories.items():
        mem, comm = value['mem'], value['comm']
        if comm != 'dockerd':
            continue
        reader = StructReader(mem)
        from .runtime_types import bind_layouts
        profile = bind_layouts(mem, ROOT / 'tools' / 'binaries' / 'dockerd',
                               {'container.Container', 'container.State', 'container.Config', 'container.HostConfig'})
        runtime_profiles[str(pid)] = profile
        # Discovery also uses legacy offsets directly. Only apply richer RTTI
        # layouts when every discovery/parser offset remains compatible.
        definitions = {'container.Container': CONTAINER, 'container.State': STATE,
                       'container.Config': CONFIG, 'container.HostConfig': HOSTCONFIG}
        for name, definition in definitions.items():
            layout = profile.get('layouts', {}).get(name)
            if not layout:
                continue
            fields = layout['fields']
            mismatches = [key for key, spec in definition.items()
                          if spec[2] != 'mutex' and (key not in fields or fields[key][0] != spec[0])]
            layout['legacy_offset_mismatches'] = mismatches
            layout['applied'] = not mismatches
            if not mismatches:
                reader.layouts[id(definition)] = fields
        for cid, candidate in discover_all_containers(mem, reader, processes if reconstruct else [], log=log).items():
            address = candidate.get('cbase')
            item = {**candidate, 'source_pid': pid, 'source': 'dockerd.heap'}
            if address:
                before = len(reader.diagnostics)
                c = reader.parse_container(address)
                item['container'] = c
                for pointer, key, parser in [('State_ptr', 'state', reader.parse_state),
                        ('Config_ptr', 'config', reader.parse_config), ('HostConfig_ptr', 'hostconfig', reader.parse_hostconfig)]:
                    ptr = c.get(pointer)
                    if ptr and ptr > 0x10000:
                        item[key] = parser(ptr)
                if item.get('state'):
                    item['state']['HasBeenStartedBefore'] = c.get('HasBeenStartedBefore')
                item['parsing_errors'] = reader.diagnostics[before:]
            entry(cid)['dockerd_candidates'].append(item)
            for alternative in candidate.get('_alternatives', []):
                address = alternative['cbase']
                parsed = reader.parse_container(address)
                other = {**alternative, 'container': parsed, 'source_pid': pid, 'source': 'dockerd.heap'}
                for pointer, key, parser in [('State_ptr', 'state', reader.parse_state),
                        ('Config_ptr', 'config', reader.parse_config), ('HostConfig_ptr', 'hostconfig', reader.parse_hostconfig)]:
                    ptr = parsed.get(pointer)
                    if ptr and ptr > 0x10000:
                        other[key] = parser(ptr)
                if other.get('state'):
                    other['state']['HasBeenStartedBefore'] = parsed.get('HasBeenStartedBefore')
                entry(cid)['dockerd_candidates'].append(other)
        if not skip_events:
            for event in extract_events(mem, reader, target_cids=None, log=log):
                event['source_pid'], event['source'] = pid, 'dockerd.event_carving'
                events.append(event)
                entry(event['container_id'])['events'].append(event)
        read_ledger.extend(dict(record, source='dockerd.heap', source_pid=pid) for record in reader.field_reads)
    for pid, value in memories.items():
        mem, comm = value['mem'], value['comm']
        if comm == 'dockerd':
            continue
        reader = ContainerdStructReader(mem)
        if comm == 'containerd':
            discovered = discover_containerd_containers(mem, reader, None, log=log)
            key = 'containerd_candidates'
        else:
            discovered = discover_shim_processes(mem, reader, list(containers), log=log,
                            child_pids=[p.pid for p in processes if p.ppid == pid])
            key = 'shim_candidates'
        for cid, item in discovered.items():
            item['source_pid'] = pid
            entry(cid)[key].append(item)
        if comm == 'containerd':
            image_names = set()
            for item in discovered.values():
                for candidate in [item] + item.get('_alternatives', []):
                    if candidate.get('Image'):
                        image_names.add(candidate['Image'])
            images = discover_containerd_images(mem, reader, image_names, log=log)
            for cid, item in discovered.items():
                for image in images.get(item.get('Image'), []):
                    entry(cid)['containerd_image_candidates'].append(
                        dict(image, source_pid=pid, source='containerd.heap'))
        diagnostics.extend(reader.diagnostics)
        read_ledger.extend(dict(record, source=comm + '.heap', source_pid=pid) for record in reader.field_reads)
    events.sort(key=lambda e: e.get('time_nano') or e['time_unix'] * 1000000000)
    for cid, item in containers.items():
        item['events'].sort(key=lambda e: e.get('time_nano') or e['time_unix'] * 1000000000)
        best = select_candidate(item['dockerd_candidates'])
        for key in ('container', 'state', 'config', 'hostconfig'):
            item[key] = best.get(key)
        item['container_name'] = (item.get('container') or {}).get('Name')
        item['strategy'] = best.get('strategy', 'multi_tier')
        item.update(identify(item.get('state'), best.get('state_valid', False), item['events']))
        item['state_source'] = 'dockerd.heap'
        item['decision_factors'] = [str(e) for e in item['evidence']]
        item['parsing_errors'].extend(best.get('parsing_errors', []))
        observed_states = {identify(c.get('state'), c.get('state_valid', False), [], None)['status']
                           for c in item['dockerd_candidates']}
        observed_states.discard('Unknown')
        if len(observed_states) > 1:
            item['state_conflicts'] = sorted(observed_states)
            item['selected_allocation_status'] = item['status']
            item['candidate_states'] = sorted(s.lower() for s in observed_states)
            item['confidence'] = 'medium'
            item['limitations'].append('Conflicting heap allocations; selected state is not proof of current state')
        if item['containerd_candidates']:
            item['containerd'] = max(item['containerd_candidates'], key=lambda c: bool(c.get('OciSpec')))
        if item['containerd_image_candidates']:
            item['containerd_image'] = max(item['containerd_image_candidates'], key=lambda image: (
                bool(image.get('Target.Digest')), bool(image.get('Target.MediaType')),
                str(image.get('UpdatedAt') or ''), str(image.get('CreatedAt') or ''),
                int(image.get('_address') or 0)))
        if item['shim_candidates']:
            item['shim'] = item['shim_candidates'][0]
    result = {'schema_version': 2, 'label': Path(dump_path).stem, 'dump_path': str(Path(dump_path).resolve()),
              'input_size': Path(dump_path).stat().st_size, 'source_hashes': initial_sources,
              'containers': list(containers.values()), 'events': events, 'coverage': loader.coverage,
              'parsing_errors': diagnostics, 'timing': {},
              'analysis_mode': 'reconstruction' if reconstruct else 'dockerd_heap_state',
              'field_reads': read_ledger,
              'process_info': [{'pid': p.pid, 'ppid': p.ppid, 'comm': p.comm} for p in processes if reconstruct or p.comm == 'dockerd']}
    result['layout_profile'] = {'name': 'legacy_amd64', 'version_binding': 'not_binary_verified',
        'runtime_profiles': runtime_profiles,
        'automatic_calibration': False, 'structures': {'Container': CONTAINER, 'State': STATE, 'Config': CONFIG, 'HostConfig': HOSTCONFIG},
        'unsupported': ['Go map contents (pointers retained)', 'arbitrary protobuf Any encodings', 'unlisted fields']}
    if reconstruct:
        from .kernel_artifacts import reconstruct as reconstruct_kernel
        from .config_v2_json import recover_configs
        from .provenance import kernel_members
        with kernel_members(loader._ctx, read_ledger):
            reconstruct_kernel(loader, result)
            result['persisted_configs'] = recover_configs(loader)
        from .artifact_inventory import inventory
        from .semantic_artifacts import correlate
        correlate(result)
        for container in result['containers']:
            container['artifact_inventory'] = inventory(container)
    result['timing']['total'] = time.monotonic() - started
    result['source_consistency'] = 'unchanged' if initial_sources == source_manifest() else 'changed_during_analysis'
    return result

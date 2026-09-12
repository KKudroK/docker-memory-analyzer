def discover_shim_processes(mem, reader, known_cids=None, log=print, child_pids=None):
    """
    Search containerd-shim memory for process.Init structures.
    Can discover either by matching known_cids or by scanning for the moby bundle path prefix.
    Returns a dict mapping parsed ID -> parsed SHIM_INIT struct.
    """
    results = {}
    if not mem:
        return results

    cids_to_check = set(cid for cid in (known_cids or []) if len(cid) == 64)

    # Autonomous discovery: scan for bundle prefix in shim memory
    bundle_prefix = b"/run/containerd/io.containerd.runtime.v2.task/moby/"
    prefix_locs = mem.find_all(bundle_prefix)
    for loc in prefix_locs:
        cid_bytes = mem.read_safe(loc + len(bundle_prefix), 64)
        if cid_bytes and len(cid_bytes) == 64 and all(b in b'0123456789abcdef' for b in cid_bytes):
            cids_to_check.add(cid_bytes.decode('ascii'))

    for cid in cids_to_check:
            
        # The Bundle string in process.Init looks like this:
        bundle_str = f"/run/containerd/io.containerd.runtime.v2.task/moby/{cid}"
        raw_bytes = bundle_str.encode('utf-8')
        
        # 1. Find where this string data is stored
        str_offsets = mem.find_all(raw_bytes)
        if not str_offsets:
            continue
            
        # 2. Find pointers to this string data
        ptr_hits = mem.find_any_pointer_to(str_offsets)
        
        for ptr_loc, target_addr in ptr_hits:
            len_bytes = mem.read_safe(ptr_loc + 8, 8)
            if len_bytes:
                length = __import__('struct').unpack('<Q', len_bytes)[0]
                if length == len(raw_bytes):
                    # Found the Bundle Go string.
                    # In process.Init, Bundle string is at offset 0x0050.
                    base_addr = ptr_loc - 0x0050
                    
                    try:
                        init_struct = reader.parse_shim_init(base_addr)
                        parsed_id = init_struct.get('id', '')
                        if parsed_id == cid and init_struct.get('Bundle') == bundle_str:
                            init_struct['_address'] = base_addr
                            init_struct['_layout'] = 'legacy_amd64_unverified'
                            pid = init_struct.get('pid')
                            closers = init_struct.get('closers')
                            valid = isinstance(pid, int) and 0 <= pid <= 4194304
                            valid = valid and bool(closers and 0 <= closers[1] <= closers[2] <= 1048576)
                            if valid:
                                init_struct['_pid_corroborated'] = pid in (child_pids or [])
                                previous = results.get(cid)
                                if previous is None or init_struct['_pid_corroborated']:
                                    results[cid] = init_struct
                                log(f"  [shim] Candidate process.Init for {cid[:12]} at 0x{base_addr:x}")
                    except Exception as e:
                        reader.diagnostics.append({'stage': 'shim.parse', 'address': base_addr, 'error': str(e)})
            
        if cid not in results and str_offsets:
            results[cid] = {'id': cid, 'Bundle': bundle_str, 'pid': None,
                            '_source': 'bundle_string_residue', '_addresses': str_offsets,
                            '_layout': 'no_validated_init_object',
                            'limitations': ['bundle string does not prove a live Init allocation']}
                
    return results

import re
import struct

def _parse_spec(c):
    """Parse OCI Spec JSON from the SpecValue bytes extracted from Any struct."""
    if c.get('OciSpec'):
        proc = c['OciSpec'].get('process', {})
        c['ProcessArgs'] = proc.get('args', [])
        c['ProcessEnv'] = proc.get('env', [])
        c['ProcessCwd'] = proc.get('cwd', '')
        c['ProcessUser'] = proc.get('user', {})


def discover_containerd_containers(mem, reader, known_cids, log=print):
    """
    Search containerd memory for Container structs via runtime signature.
    
    Strategy:
      1. Find all occurrences of "io.containerd.runc.v2" in memory.
      2. Single-pass scan to find all pointers to those string locations.
      3. For each pointer, check if it's part of a Go string header with correct length.
      4. If so, it's the Runtime.Name field at offset 0x28 in a Container struct.
      5. Parse the Container struct and extract OCI Spec data.
    
    Returns a dict mapping cid -> parsed CONTAINER struct.
    """
    results = {}
    if not mem:
        return results

    sig_bytes = b"io.containerd.runc.v2"
    sig_locs = mem.find_all(sig_bytes)
    if not sig_locs:
        return results
    
    log(f"  [containerd] Found {len(sig_locs)} runtime signature locations, scanning pointers...")
    
    # Single-pass: find all 8-byte values in memory that match any of the sig_locs
    # This is O(N) regardless of how many sig_locs there are
    ptr_hits = mem.find_any_8byte_value(sig_locs)
    log(f"  [containerd] Found {len(ptr_hits)} pointer candidates")
    
    seen_ids = set()
    for ptr_loc, target_addr in ptr_hits:
        # Verify the Go string length field (next 8 bytes must be len(sig_bytes))
        len_bytes = mem.read_safe(ptr_loc + 8, 8)
        if not len_bytes:
            continue
        length = struct.unpack('<Q', len_bytes)[0]
        if length != len(sig_bytes):
            continue
        
        # This is a Runtime.Name Go string at offset 0x28 in Container
        base_addr = ptr_loc - 0x28
        try:
            c = reader.parse_containerd_container(base_addr)
            parsed_id = c.get('ID', '')
            if parsed_id and len(parsed_id) == 64:
                if all(ch in '0123456789abcdef' for ch in parsed_id):
                    _parse_spec(c)
                    c['_address'] = base_addr
                    if parsed_id not in results:
                        results[parsed_id] = c
                    else:
                        previous = results[parsed_id]
                        candidates = previous.pop('_alternatives', [])
                        if c.get('OciSpec') and not previous.get('OciSpec'):
                            c['_alternatives'] = candidates + [previous]
                            results[parsed_id] = c
                        else:
                            previous['_alternatives'] = candidates + [c]
                    seen_ids.add(parsed_id)
                    log(f"  [containerd] Found Container: {parsed_id[:12]}... Image={c.get('Image', '?')}")
        except Exception as e:
            import traceback
            log(f"  [containerd] Error parsing container at 0x{base_addr:x}: {e}")
            traceback.print_exc()
            
    return results


def discover_containerd_images(mem, reader, image_names, log=print):
    """Find containerd Image structs anchored by names used by recovered containers.

    A matching Name alone is insufficient because the same Go string also appears
    inside Container objects.  Require a plausible OCI media type, digest and size
    before retaining an Image candidate.
    """
    names = sorted({name for name in image_names if isinstance(name, str) and 0 < len(name.encode('utf-8')) <= 4096})
    if not mem or not names:
        return {}
    locations = {}
    for name in names:
        for address in mem.find_all(name.encode('utf-8')):
            locations.setdefault(address, set()).add(name)
    hits = mem.find_any_pointer_to(locations)
    digest_pattern = re.compile(r'^[a-z0-9]+(?:[+._-][a-z0-9]+)*:[0-9a-f]{32,}$')
    results, seen = {}, set()
    for header, data_address in hits:
        if header in seen:
            continue
        length_raw = mem.read_safe(header + 8, 8)
        if length_raw is None:
            continue
        length = struct.unpack('<Q', length_raw)[0]
        matched = next((name for name in locations[data_address] if len(name.encode('utf-8')) == length), None)
        if matched is None:
            continue
        try:
            image = reader.parse_containerd_image(header)
            media_type = image.get('Target.MediaType')
            digest = image.get('Target.Digest')
            size = image.get('Target.Size')
            if (image.get('Name') != matched or not isinstance(media_type, str) or
                    not media_type.startswith('application/') or not isinstance(digest, str) or
                    not digest_pattern.fullmatch(digest) or not isinstance(size, int) or size < 0):
                continue
            image['_address'] = header
            image['_validation'] = ['Name matched recovered Container.Image',
                                    'Target.MediaType starts with application/',
                                    'Target.Digest has algorithm:hex form', 'Target.Size is non-negative']
            results.setdefault(matched, []).append(image)
            seen.add(header)
        except Exception as exc:
            reader.diagnostics.append({'stage': 'containerd.image', 'address': header,
                                       'reason': type(exc).__name__, 'message': str(exc)})
    log(f'  [containerd] Validated {sum(map(len, results.values()))} Image object candidates')
    return results

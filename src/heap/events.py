"""Docker event extraction from cached process memory.

Searches for the Events ring buffer (up to 256 Message entries)
by finding known event action strings and validating the surrounding struct.
"""
import struct
import datetime
from .structs import EVENT_MESSAGE, EVENT_MESSAGE_SIZE, StructReader

CONTAINER_ACTIONS = [
    b'create', b'start', b'stop', b'die', b'kill',
    b'pause', b'unpause', b'restart', b'destroy',
    b'rename', b'attach', b'detach', b'resize',
    b'commit', b'copy', b'export', b'exec_create',
    b'exec_start', b'exec_die', b'health_status',
]

LIFECYCLE_ACTIONS = {b'create', b'start', b'stop', b'die', b'kill',
                     b'pause', b'unpause', b'restart', b'destroy'}


def extract_events(mem, reader, target_cids=None, log=print):
    """Extract Docker events from cached memory.

    Optimized: Searches for Go string headers with length 64 (CID length).
    Validates if the pointed string is a target CID, then parses the
    surrounding Event Message struct.

    Args:
        mem: CachedProcessMemory
        reader: StructReader
        target_cids: optional set of CIDs to filter for
        log: logging function

    Returns:
        list of event dicts, sorted by timestamp
    """
    events = []
    seen_addrs = set()

    if not target_cids:
        return events

    # Strategy: Find all Go string headers where length == 64
    len_bytes = struct.pack('<Q', 64)
    len_hits = mem.find_all(len_bytes)

    for len_addr in len_hits:
        ptr_bytes = mem.read_safe(len_addr - 8, 8)
        if not ptr_bytes:
            continue
        ptr = struct.unpack('<Q', ptr_bytes)[0]
        if ptr < 0x10000:
            continue

        data = mem.read_safe(ptr, 64)
        if not data:
            continue

        try:
            cid = data.decode()
        except Exception:
            continue

        if cid not in target_cids:
            continue

        # This header belongs to an Actor.ID field
        msg_base = (len_addr - 8) - EVENT_MESSAGE['Actor.ID'][0]
        if msg_base < 0x10000 or msg_base in seen_addrs:
            continue

        evt = reader.parse_event(msg_base)
        if not evt:
            continue

        if evt.get('Type') != 'container':
            continue

        seen_addrs.add(msg_base)
        time_val = evt.get('Time')
        time_nano = evt.get('TimeNano')
        if not time_val or time_val <= 0:
            continue

        try:
            ts = datetime.datetime.fromtimestamp(time_val, tz=datetime.timezone.utc)
        except (OSError, ValueError):
            ts = None

        events.append({
            'action': evt.get('Action'),
            'container_id': cid,
            'timestamp': ts,
            'time_unix': time_val,
            'time_nano': time_nano,
            'from_image': evt.get('From'),
            'status': evt.get('Status'),
            'addr': msg_base,
        })

    events.sort(key=lambda e: e.get('time_nano') or e.get('time_unix') or 0)
    return events

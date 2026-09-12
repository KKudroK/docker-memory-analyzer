"""Evidence-first inventory: discovery, content coverage and uncollected classes."""
from collections import Counter


def inventory(container):
    processes = container.get('processes', [])
    fds = [f for p in processes for f in p.get('files', [])]
    categories = Counter()
    for f in fds:
        path = f.get('path', '')
        categories['socket' if 'socket' in f else 'pipe' if path.startswith('pipe:') else
                   'memfd' if 'memfd:' in path else 'deleted_open' if '(deleted)' in path else
                   'fifo' if f.get('mode', 0) & 0o170000 == 0o010000 else 'file_or_device'] += 1
    contents = [f['content'] for f in fds if 'content' in f]
    cached = [f['content'] for f in container.get('cached_files', []) if 'content' in f]
    return {'processes': len(processes), 'fd_entries': len(fds), 'fd_categories': dict(categories),
            'memory_maps': sum(len(p.get('memory_maps', [])) for p in processes),
            'mounts': len(container.get('mounts', [])), 'cached_paths': len(container.get('cached_files', [])),
            'content_fd_entries': len(contents), 'complete_content_fd_entries': sum(c.get('complete', False) for c in contents),
            'partial_content_fd_entries': sum(not c.get('complete', False) for c in contents),
            'missing_bytes_fd_weighted': sum(end - start for c in contents for start, end in c.get('missing_ranges', [])),
            'content_errors': sum(len(c.get('errors', [])) for c in contents),
            'cached_content_complete': sum(bool(c.get('complete')) for c in cached),
            'cached_content_partial': sum(not c.get('complete', False) for c in cached),
            'counting_note': 'FD-weighted coverage; duplicated descriptors are not distinct files',
            'ipc_collection_errors': sum(len(f.get('pipe', {}).get('errors', [])) + len(f.get('locks', {}).get('errors', []))
                + sum(len(q.get('errors', [])) for q in f.get('socket', {}).get('queues', {}).values()) for f in fds),
            'pipe_payload_bytes_fd_weighted': sum(f.get('pipe', {}).get('recovered_bytes', 0) for f in fds),
            'socket_payload_bytes_fd_weighted': sum(q.get('recovered_bytes', 0) for f in fds for q in f.get('socket', {}).get('queues', {}).values()),
            'lock_entries_fd_weighted': sum(len(f.get('locks', {}).get('entries', [])) for f in fds),
            'not_collected': ['all deleted filesystem entries', 'arbitrary Go map/protobuf payloads',
                              'chained skb frag_list and TCP retransmit tree', 'device-backed netmem payloads',
                              'arbitrary application heap semantics', 'lossless raw payload export']}

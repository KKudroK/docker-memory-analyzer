"""Resident IPC queues and locks, decoded using the loaded kernel symbols."""
import hashlib
from .evidence import error, redact


def member(obj, name, depth=0):
    """Resolve named fields through ISF anonymous unions without fixed offsets."""
    from volatility3.framework.objects import Pointer
    if isinstance(obj, Pointer):
        obj = obj.dereference()
    if obj.has_member(name):
        return getattr(obj, name)
    if depth < 4:
        for key in obj.vol.members:
            if key.startswith('unnamed_'):
                child = getattr(obj, key)
                if hasattr(child, 'has_member'):
                    try:
                        return member(child, name, depth + 1)
                    except AttributeError:
                        pass
    raise AttributeError(f'{obj.vol.type_name}.{name} not present in loaded symbols')


def payload(data):
    return {'length': len(data), 'sha256': hashlib.sha256(data).hexdigest(),
            'text': redact(data.decode('utf-8', errors='replace')),
            'encoding': 'redacted_utf8_preview_not_lossless'}


def pipe_info(inode, limit=16 * 1024 * 1024):
    result = {'source': 'kernel.pipe_inode_info', 'buffers': [], 'errors': [], 'complete': False}
    try:
        pipe = member(inode, 'i_pipe')
        if not pipe:
            result.update(complete=True, reason='no_pipe_object')
            return result
        result['address'] = int(pipe)
        pipe = pipe.dereference()
        head, tail, ring = int(member(pipe, 'head')), int(member(pipe, 'tail')), int(pipe.ring_size)
        count = (head - tail) & 0xffffffff
        result.update(head=head, tail=tail, ring_size=ring, readers=int(pipe.readers), writers=int(pipe.writers))
        if ring < 1 or ring & (ring - 1) or count > ring or ring > 1048576:
            raise ValueError('Invalid pipe ring bounds')
        recovered = 0
        for index in range(count):
            template = pipe.bufs.dereference()
            buf = pipe._context.object(template.vol.type_name, layer_name=template.vol.layer_name,
                offset=int(pipe.bufs) + ((tail + index) & (ring - 1)) * template.vol.size)
            item = {'address': int(buf.vol.offset), 'page_address': int(buf.page),
                    'offset': int(buf.offset), 'length': int(buf.len), 'flags': int(buf.flags)}
            result['buffers'].append(item)
            try:
                if recovered + item['length'] > limit:
                    raise ValueError('Pipe payload safety limit reached')
                raw = buf.page.get_content()
                if raw is None or item['offset'] + item['length'] > len(raw):
                    raise ValueError('Pipe page payload unavailable or spans unsupported compound page')
                item['payload'] = payload(raw[item['offset']:item['offset'] + item['length']])
                recovered += item['length']
            except Exception as exc:
                result['errors'].append(error('pipe.buffer', exc, address=item['address']))
        result.update(recovered_bytes=recovered, complete=not result['errors'])
    except Exception as exc:
        result['errors'].append(error('pipe', exc))
    return result


def lock_info(inode, kernel):
    result = {'source': 'kernel.file_lock_context', 'entries': [], 'errors': [], 'complete': False}
    try:
        context = inode.i_flctx
        if not context:
            result.update(complete=True, reason='no_lock_context')
            return result
        from volatility3.framework.symbols.linux import LinuxUtilities
        result['address'] = int(context)
        for name in ('flc_flock', 'flc_posix', 'flc_lease'):
            head = getattr(context, name)
            # New kernels embed file_lock_core; older kernels use fl_list.
            modern = kernel.get_type('file_lock').has_member('c')
            typename, link = ('file_lock_core', 'flc_list') if modern else ('file_lock', 'fl_list')
            for i, core in enumerate(head.to_list(kernel.symbol_table_name + '!' + typename, link)):
                if i >= 65536:
                    raise ValueError('Lock traversal safety limit reached')
                lock = LinuxUtilities.container_of(int(core.vol.offset), 'file_lock', 'c', kernel) if modern else core
                prefix = 'flc_' if modern else 'fl_'
                item = {'address': int(lock.vol.offset), 'kind': name,
                        'pid': int(getattr(core, prefix + 'pid')), 'type': int(getattr(core, prefix + 'type')),
                        'flags': int(getattr(core, prefix + 'flags')), 'owner_address': int(getattr(core, prefix + 'owner')),
                        'file_address': int(getattr(core, prefix + 'file'))}
                # Leases are file_lease, not file_lock; do not reinterpret range fields.
                if name != 'flc_lease':
                    item.update(start=int(lock.fl_start), end=int(lock.fl_end))
                result['entries'].append(item)
        result['complete'] = True
    except Exception as exc:
        result['errors'].append(error('file_locks', exc))
    return result


def socket_queues(sock, kernel, limit=16 * 1024 * 1024):
    result = {}
    for name in ('sk_receive_queue', 'sk_write_queue', 'sk_error_queue'):
        queue = {'source': 'kernel.sock.' + name, 'packets': [], 'errors': [], 'complete': False}
        result[name] = queue
        try:
            head = getattr(sock, name)
            queue.update(address=int(head.vol.offset), expected_packets=int(head.qlen))
            pointer, seen, total = int(head.next), set(), 0
            while pointer != int(head.vol.offset):
                if not pointer or pointer in seen or len(seen) >= 65536:
                    raise ValueError('Invalid/cyclic socket queue or traversal limit')
                seen.add(pointer)
                skb = kernel.object('sk_buff', offset=pointer, absolute=True)
                size, nonlinear = int(skb.len), int(skb.data_len)
                linear = size - nonlinear
                if linear < 0 or total + linear > limit:
                    raise ValueError('Invalid skb length or payload safety limit')
                item = {'address': pointer, 'length': size, 'nonlinear_bytes': nonlinear,
                        'data_address': int(skb.data), 'linear_bytes': linear}
                queue['packets'].append(item)
                try:
                    raw = sock._context.layers[sock.vol.layer_name].read(int(skb.data), linear, pad=False) if linear else b''
                    item['payload'] = payload(raw)
                    total += len(raw)
                except Exception as exc:
                    queue['errors'].append(error('skb.payload', exc, address=pointer))
                if nonlinear:
                    try:
                        shared = kernel.object('skb_shared_info', offset=int(skb.head) + int(skb.end), absolute=True)
                        item['shared_info_address'] = int(shared.vol.offset)
                        nr = int(shared.nr_frags)
                        if nr > len(shared.frags):
                            raise ValueError('Invalid skb fragment count')
                        item['fragments'] = []
                        recovered_frags = 0
                        for n in range(nr):
                            frag = shared.frags[n]
                            if frag.has_member('netmem'):
                                page_address, offset, length = int(frag.netmem), int(frag.offset), int(frag.len)
                                if page_address & 1:
                                    raise ValueError('Device netmem fragment is not a struct page')
                            else:
                                page_address, offset, length = int(frag.bv_page), int(frag.bv_offset), int(frag.bv_len)
                            if length < 0 or total + length > limit or recovered_frags + length > nonlinear:
                                raise ValueError('Invalid skb fragment length or payload safety limit')
                            part = {'address': int(frag.vol.offset), 'page_address': page_address,
                                    'offset': offset, 'length': length}
                            item['fragments'].append(part)
                            page_size = kernel.get_type('page').size
                            chunks, cursor = [], offset
                            while cursor < offset + length:
                                page = kernel.object('page', offset=page_address + (cursor // 4096) * page_size, absolute=True)
                                data = page.get_content()
                                take = min(4096 - cursor % 4096, offset + length - cursor)
                                if data is None or len(data) < cursor % 4096 + take:
                                    raise ValueError('Fragment page unavailable')
                                chunks.append(data[cursor % 4096:cursor % 4096 + take])
                                cursor += take
                            part['payload'] = payload(b''.join(chunks))
                            recovered_frags += length
                            total += length
                        if shared.frag_list or recovered_frags != nonlinear:
                            raise ValueError('Chained skb frag_list or unmatched nonlinear bytes remain')
                    except Exception as exc:
                        queue['errors'].append(error('skb.fragments', exc, address=pointer))
                pointer = int(member(skb, 'next'))
            if len(seen) != queue['expected_packets']:
                raise ValueError('Queue length differs from traversed packets (possible capture smear)')
            queue.update(recovered_bytes=total, complete=not queue['errors'])
        except Exception as exc:
            queue['errors'].append(error('socket_queue', exc))
    return result

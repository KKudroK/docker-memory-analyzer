"""Read Go amd64 RTTI field offsets from the running image, bound to local ELF.

Layout definitions follow internal/abi/type.go (Type/StructType/StructField).
The ELF build-id and code bytes must match before any offsets are applied.
"""
import struct
from pathlib import Path


class RuntimeTypes:
    def __init__(self, mem, types_base):
        self.mem, self.base, self.cache = mem, types_base, {}

    def raw(self, address, size):
        value = self.mem.read_safe(address, size)
        if value is None or len(value) != size:
            raise ValueError(f'RTTI bytes unavailable at {address:#x} ({size})')
        return value

    def word(self, address):
        return struct.unpack('<Q', self.raw(address, 8))[0]

    def name(self, address):
        length, shift, cursor = 0, 0, address + 1
        for _ in range(5):
            byte = self.raw(cursor, 1)[0]
            cursor += 1
            length |= (byte & 127) << shift
            if byte < 128:
                break
            shift += 7
        if not 0 < length < 65536:
            raise ValueError('Invalid Go ABI name length')
        return self.raw(cursor, length).decode('utf-8')

    def describe(self, address):
        if address in self.cache:
            return self.cache[address]
        raw = self.raw(address, 48)
        size = struct.unpack_from('<Q', raw)[0]
        kind, flags = raw[23] & 31, raw[20]
        name_offset = struct.unpack_from('<i', raw, 40)[0]
        name = self.name(self.base + name_offset)
        if flags & 2 and name.startswith('*'):
            name = name[1:]
        info = {'name': name, 'size': size, 'kind': kind, 'address': address}
        self.cache[address] = info
        if kind in (22, 23):
            info['element'] = self.word(address + 48)
        if kind == 25:
            pkg = self.word(address + 48)
            info['package'] = self.name(pkg) if pkg else ''
            pointer, count, capacity = struct.unpack('<QQQ', self.raw(address + 56, 24))
            if count > capacity or count > 4096:
                raise ValueError('Invalid Go struct field slice')
            fields = []
            for index in range(count):
                n, t, offset = struct.unpack('<QQQ', self.raw(pointer + index * 24, 24))
                if offset > size:
                    raise ValueError('Go field extends beyond struct')
                fields.append({'name': self.name(n), 'type_address': t, 'offset': offset})
            info['fields'] = fields
        return info

    def fields(self, address, prefix='', origin=0, depth=0):
        if depth > 5:
            raise ValueError('RTTI inline nesting exceeds limit')
        info = self.describe(address)
        result = {}
        for field in info.get('fields', []):
            t = self.describe(field['type_address'])
            name = prefix + field['name']
            offset = origin + field['offset']
            kind = {1: 'bool', 2: 'int', 6: 'int64', 7: 'uint64', 11: 'uint64',
                    12: 'ptr', 18: 'chan', 20: 'interface', 21: 'map', 22: 'ptr',
                    23: 'slice', 24: 'string'}.get(t['kind'])
            if t['kind'] == 23 and self.describe(t['element'])['kind'] == 24:
                kind = 'string_slice'
            if t['name'] == 'time.Time':
                kind = 'time'
            if kind:
                result[name] = (offset, t['size'], kind)
            elif t['kind'] == 25:
                result.update(self.fields(field['type_address'], name + '.', offset, depth + 1))
        return result


def bind_layouts(mem, binary_path, wanted):
    """Return validated live RTTI layouts or an explicit reason for fallback."""
    from elftools.elf.elffile import ELFFile
    path = Path(binary_path)
    report = {'binary': path.name, 'status': 'unavailable', 'layouts': {}, 'errors': []}
    if not path.is_file():
        report['errors'].append('local_binary_missing')
        return report
    try:
        with path.open('rb') as stream:
            elf = ELFFile(stream)
            if elf.elfclass != 64 or not elf.little_endian:
                raise ValueError('Only little-endian amd64 RTTI supported')
            symbols = elf.get_section_by_name('.symtab')
            if symbols is None:
                raise ValueError('ELF runtime symbols unavailable')
            wanted_symbols = {}
            for symbol in symbols.iter_symbols():
                if symbol.name in ('runtime.types', 'runtime.typelink'):
                    wanted_symbols[symbol.name] = (int(symbol['st_value']), int(symbol['st_size']))
            if len(wanted_symbols) != 2:
                raise ValueError('runtime.types/typelink symbols unavailable')
            stream.seek(0)
            header = stream.read(64)
            first_load = next(s for s in elf.iter_segments() if s['p_type'] == 'PT_LOAD' and s['p_offset'] == 0)
            text = elf.get_section_by_name('.text')
            note = elf.get_section_by_name('.note.go.buildid')
            if note is None:
                raise ValueError('Go build-id section unavailable')
            bias = None
            for hit in mem.find_all(header):
                candidate = hit - int(first_load['p_vaddr'])
                if mem.read_safe(candidate + int(note['sh_addr']), note['sh_size']) != note.data():
                    continue
                if mem.read_safe(candidate + int(text['sh_addr']), 128) != text.data()[:128]:
                    continue
                bias = candidate
                break
            if bias is None:
                raise ValueError('ELF header/build-id/text do not match resident image')
            base = wanted_symbols['runtime.types'][0] + bias
            links, length = wanted_symbols['runtime.typelink']
            reader = RuntimeTypes(mem, base)
            found = {}
            for index in range(length // 4):
                try:
                    off = struct.unpack('<i', reader.raw(links + bias + index * 4, 4))[0]
                    address = base + off
                    info = reader.describe(address)
                    if info['kind'] == 22:
                        address = info['element']
                        info = reader.describe(address)
                    if info['name'] in wanted:
                        fields = reader.fields(address)
                        if info['name'] == 'container.HostConfig' and 'RestartPolicy.MaximumRetryCount' in fields:
                            fields['RestartPolicy.MaxRetryCount'] = fields['RestartPolicy.MaximumRetryCount']
                        required = {'container.State': {'RemovalInProgress', 'removed'},
                                    'container.Container': {'ID', 'State', 'Config'},
                                    'container.Config': {'Hostname', 'Env', 'Image'},
                                    'container.HostConfig': {'NetworkMode', 'Privileged'}}.get(info['name'], set())
                        if required <= fields.keys():
                            found[info['name']] = {'address': address, 'size': info['size'],
                                'package': info.get('package'), 'fields': fields,
                                'field_types': {f['name']: f['type_address'] for f in info.get('fields', [])}}
                        elif info['name'] == 'container.State':
                            report.setdefault('rejected_state_types', {})[str(address)] = {'fields': fields, 'package': info.get('package')}
                except (ValueError, UnicodeError, struct.error) as exc:
                    if len(report['errors']) < 20:
                        report['errors'].append(str(exc))
            # Follow the actual Container.State edge: public API and daemon
            # types share the same short name, so name matching is insufficient.
            container = found.get('container.Container')
            if container:
                pointer = reader.describe(container['field_types']['State'])
                info = reader.describe(pointer['element'])
                fields = reader.fields(info['address'])
                if {'Running', 'RemovalInProgress', 'removed'} <= fields.keys():
                    fields['Removed'] = fields.pop('removed')
                    found['container.State'] = {'address': info['address'], 'size': info['size'],
                        'package': info.get('package'), 'fields': fields,
                        'binding': 'container.Container.State pointer element'}
            report.pop('rejected_state_types', None)
            report.update(status='bound' if found else 'unavailable', load_bias=bias, types_base=base, layouts=found,
                          binding='ELF header + Go build-id + text bytes + live RTTI')
    except (OSError, ValueError, KeyError, StopIteration) as exc:
        report['errors'].append(str(exc))
    return report

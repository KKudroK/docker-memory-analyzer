"""Confirmed conntrack tuples (observed flows, not firewall configuration)."""
import socket
from volatility3.framework.objects import utility


def symbols(c, names):
    found = {n: c.kernel.object_from_symbol(n).vol.offset for n in names if c.kernel.has_symbol(n)}
    if len(found) == len(names):
        return found
    def modules():
        for mod in c.walk(c.kernel.object_from_symbol('modules'), 'module', 'list'):
            if utility.array_to_string(mod.name) != 'nf_conntrack':
                continue
            ks = mod.kallsyms.dereference()
            sym_type = ks.symtab.vol.subtype.vol.type_name.split('!')[-1]
            for sym in c.array(int(ks.symtab), sym_type, int(ks.num_symtab)):
                offset = int(sym.st_name)
                name = c.layer.read(int(ks.strtab) + offset, 128).split(b'\0', 1)[0].decode('ascii', errors='replace')
                if name in names:
                    found[name] = int(sym.st_value) & c.layer.address_mask
    c.read('conntrack.module_symbols', 'modules', modules)
    return found


def tuple_data(c, value):
    family, protocol = int(value.src.l3num), int(value.dst.protonum)
    if family not in (2, 10):
        return {'family': family, 'protocol': protocol}
    size, af = (4, socket.AF_INET) if family == 2 else (16, socket.AF_INET6)
    row = {'family': family, 'protocol': protocol,
           'source_ip': socket.inet_ntop(af, c.layer.read(value.src.u3.vol.offset, size)),
           'destination_ip': socket.inet_ntop(af, c.layer.read(value.dst.u3.vol.offset, size))}
    if protocol in (6, 17, 33, 132, 136):
        row['source_port'] = int.from_bytes(c.layer.read(value.src.u.vol.offset, 2), 'big')
        row['destination_port'] = int.from_bytes(c.layer.read(value.dst.u.vol.offset, 2), 'big')
    return row


def collect(c, unsupported):
    rows = []
    names = ('nf_conntrack_hash', 'nf_conntrack_htable_size')
    found = symbols(c, names)
    if any(n not in found for n in names):
        unsupported.append({'feature': 'conntrack', 'reason': 'hash symbols absent in kernel/module kallsyms'})
        return rows
    def scan():
        address = int(c.obj('pointer', found[names[0]]))
        count = int(c.obj('unsigned int', found[names[1]]))
        heads = c.array(address, 'hlist_nulls_head', count)
        entry_offset = c.kernel.get_type('nf_conntrack_tuple_hash').relative_child_offset('hnnode')
        tuples_offset = c.kernel.get_type('nf_conn').relative_child_offset('tuplehash')
        tuple_size = c.kernel.get_type('nf_conntrack_tuple_hash').size
        all_seen = set()
        for head in heads:
            def bucket():
                link, seen = int(head.first), set()
                while link and not link & 1:
                    if link in seen or len(seen) >= c.limit:
                        raise ValueError('conntrack cycle or limit')
                    seen.add(link)
                    entry = c.obj('nf_conntrack_tuple_hash', link - entry_offset)
                    direction = int(entry.tuple.dst.dir)
                    if direction not in (0, 1):
                        raise ValueError('invalid conntrack direction')
                    ct = c.obj('nf_conn', entry.vol.offset - tuples_offset - direction * tuple_size)
                    link = int(entry.hnnode.next)
                    if ct.vol.offset in all_seen:
                        continue
                    all_seen.add(ct.vol.offset)
                    def record():
                        status = int(ct.status)
                        rows.append({'address': hex(ct.vol.offset), 'namespace': hex(int(ct.ct_net.net)),
                                     'original': tuple_data(c, ct.tuplehash[0].tuple), 'reply': tuple_data(c, ct.tuplehash[1].tuple),
                                     'status': status, 'snat': bool(status & (1 << 4)), 'dnat': bool(status & (1 << 5)),
                                     'source': 'nf_conntrack_hash -> tuplehash -> nf_conn', 'confidence': 'hashed_flow_object',
                                     'limitation': 'flow state; does not enumerate configured NAT rules'})
                    c.read('conntrack.entry', ct, record)
            c.read('conntrack.bucket', head, bucket)
    c.read('conntrack.hash', found, scan)
    return rows

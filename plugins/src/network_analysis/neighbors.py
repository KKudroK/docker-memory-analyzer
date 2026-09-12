"""ARP/NDP entries, including failed/incomplete states, not just MAC hits."""
import socket


def collect(c, unsupported):
    rows = []
    for name in ('arp_tbl', 'nd_tbl'):
        if not c.kernel.has_symbol(name):
            unsupported.append({'feature': name, 'reason': 'symbol absent'})
            continue
        def table():
            tbl = c.kernel.object_from_symbol(name)
            family = int(tbl.family)
            nht = tbl.nht.dereference()
            shift = int(nht.hash_shift)
            if not 0 <= shift <= 20:
                raise ValueError('invalid neighbor hash_shift')
            heads = c.array(int(nht.hash_heads), 'hlist_head', 1 << shift)
            for head in heads:
                def bucket():
                    for n in c.hlist(head, 'neighbour', 'hash'):
                        def entry():
                            dev = n.dev.dereference()
                            size = int(tbl.key_len)
                            if size != (4 if family == 2 else 16):
                                raise ValueError('neighbor key length mismatch')
                            addr_len = int(dev.addr_len)
                            if not 0 <= addr_len <= 32:
                                raise ValueError('invalid MAC length')
                            rows.append({'address': hex(n.vol.offset), 'namespace': hex(int(dev.nd_net.net)),
                                         'interface': hex(int(n.dev)), 'ifindex': int(dev.ifindex),
                                         'family': family, 'ip': socket.inet_ntop(socket.AF_INET if family == 2 else socket.AF_INET6, c.layer.read(n.primary_key.vol.offset, size)),
                                         'mac': ':'.join(f'{b:02x}' for b in c.layer.read(n.ha.vol.offset, addr_len)),
                                         'nud_state': int(n.nud_state), 'dead': int(n.dead),
                                         'source': name + '.nht.hash_heads', 'confidence': 'direct_pointer'})
                        c.read('neighbor.entry', n, entry)
                c.read('neighbor.bucket', head, bucket)
        c.read('neighbor.table', name, table)
    return rows

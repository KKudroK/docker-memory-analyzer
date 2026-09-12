"""Interface IPv4 IGMP and IPv6 MLD memberships (not multicast routes)."""
import socket


def collect(c):
    rows = []
    for dev, interface in c.devices.values():
        for family in (4, 6):
            def scan():
                ptr = dev.ip_ptr if family == 4 else dev.ip6_ptr
                if not ptr:
                    return
                ipdev = ptr.dereference().cast('in_device' if family == 4 else 'inet6_dev')
                ptr, seen = ipdev.mc_list, set()
                while ptr:
                    if int(ptr) in seen or len(seen) >= c.limit:
                        raise ValueError('multicast list cycle or limit')
                    seen.add(int(ptr))
                    entry = ptr.dereference()
                    value = entry.multiaddr if family == 4 else entry.mca_addr
                    rows.append({'address': hex(entry.vol.offset), 'namespace': interface['namespace'],
                                 'interface': interface['address'], 'family': family,
                                 'group': socket.inet_ntop(socket.AF_INET if family == 4 else socket.AF_INET6, c.layer.read(value.vol.offset, 4 if family == 4 else 16)),
                                 'users': int(entry.users if family == 4 else entry.mca_users),
                                 'source': 'net_device.ip_ptr/ip6_ptr.mc_list', 'confidence': 'direct_pointer'})
                    ptr = entry.next
            c.read('multicast.list', dev, scan)
    return rows

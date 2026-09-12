"""Direct adjacency and separately labelled private-data peer candidates."""
from volatility3.framework import objects


def collect(c):
    edges, unsupported = [], []
    for dev, row in c.devices.values():
        def adjacent():
            if not dev.has_member('adj_list'):
                unsupported.append({'feature': 'upper_adjacency', 'interface': row['address'],
                                    'reason': 'net_device.adj_list absent'})
                return
            for adj in c.walk(dev.adj_list.upper, 'netdev_adjacent', 'list'):
                target = int(adj.dev)
                edges.append({'kind': 'upper', 'source': row['address'], 'target': hex(target),
                              'master': bool(adj.master), 'evidence': hex(adj.vol.offset), 'confidence': 'direct_pointer'})
                other = c.devices.get(target)
                if (other and other[1].get('kind') == 'bridge' and
                        c.kernel.has_type('net_bridge_port') and
                        dev.has_member('rx_handler_data') and dev.rx_handler_data):
                    port = c.obj('net_bridge_port', int(dev.rx_handler_data))
                    if int(port.dev) != dev.vol.offset or int(port.br.dev) != target:
                        raise ValueError('bridge port backlink mismatch')
                    edges.append({'kind': 'bridge_port', 'source': row['address'], 'target': hex(target),
                                  'port_no': int(port.port_no), 'state': int(port.state),
                                  'evidence': hex(port.vol.offset), 'confidence': 'validated_backlinks'})
        c.read('topology.upper', dev, adjacent)
        if row.get('kind') == 'veth':
            def peer():
                if not dev.has_member('priv'):
                    unsupported.append({'feature': 'veth_peer', 'interface': row['address'], 'reason': 'no symbol-described private pointer; inline alignment not assumed'})
                    return
                private_address = dev.priv.vol.offset if isinstance(dev.priv, objects.Array) else int(dev.priv)
                if not c.kernel.has_type('veth_priv'):
                    unsupported.append({'feature': 'typed_veth_peer', 'interface': row['address'], 'reason': 'veth_priv absent; reciprocal private-data references are candidates, not typed peer proof'})
                    if not isinstance(dev.priv, objects.Array) or not dev.has_member('priv_len'):
                        return
                    size = int(dev.priv_len)
                    if not 0 <= size <= 65536:
                        raise ValueError('invalid netdev private length')
                    width = c.kernel.get_type('pointer').size
                    matches = []
                    for offset in range(0, size - width + 1, width):
                        target = int(c.obj('pointer', private_address + offset)) & c.layer.address_mask
                        other = c.devices.get(target)
                        if not other or target == dev.vol.offset or other[1].get('kind') != 'veth':
                            continue
                        peer_dev = other[0]
                        if not peer_dev.has_member('priv') or not isinstance(peer_dev.priv, objects.Array):
                            continue
                        if not peer_dev.has_member('priv_len') or offset + width > int(peer_dev.priv_len):
                            continue
                        back = int(c.obj('pointer', peer_dev.priv.vol.offset + offset)) & c.layer.address_mask
                        if back == dev.vol.offset:
                            matches.append((target, offset))
                    for target, offset in matches:
                        edges.append({'kind': 'veth_peer_candidate', 'source': row['address'], 'target': hex(target),
                                      'evidence': hex(private_address + offset), 'private_relative_offset': offset,
                                      'confidence': 'reciprocal_private_reference' if len(matches) == 1 else 'ambiguous',
                                      'limitation': 'not a symbol-typed veth_priv.peer field'})
                    return
                priv = c.obj('veth_priv', private_address)
                edges.append({'kind': 'veth_peer', 'source': row['address'], 'target': hex(int(priv.peer)),
                              'evidence': hex(priv.vol.offset), 'confidence': 'direct_pointer'})
            c.read('topology.veth', dev, peer)
    return edges, unsupported


def bridge_fdb(c, unsupported):
    rows = []
    for dev, interface in c.devices.values():
        if interface.get('kind') != 'bridge':
            continue
        def scan():
            if not dev.has_member('priv') or not isinstance(dev.priv, objects.Array):
                unsupported.append({'feature': 'bridge_fdb', 'interface': interface['address'], 'reason': 'no symbol-described inline private storage'})
                return
            bridge = c.obj('net_bridge', dev.priv.vol.offset)
            if int(bridge.dev) != dev.vol.offset:
                raise ValueError('bridge private dev backlink mismatch')
            for entry in c.hlist(bridge.fdb_list, 'net_bridge_fdb_entry', 'fdb_node'):
                def record():
                    rows.append({'address': hex(entry.vol.offset), 'namespace': interface['namespace'],
                                 'bridge': interface['address'], 'interface': hex(int(entry.dst.dev)) if entry.dst else None,
                                 'mac': ':'.join(f'{b:02x}' for b in c.layer.read(entry.key.addr.vol.offset, 6)),
                                 'vlan': int(entry.key.vlan_id), 'flags': int(entry.flags),
                                 'source': 'net_device.priv -> net_bridge.fdb_list -> net_bridge_fdb_entry', 'confidence': 'validated_bridge_backlink'})
                c.read('bridge.fdb.entry', entry, record)
        c.read('bridge.fdb', dev, scan)
    return rows

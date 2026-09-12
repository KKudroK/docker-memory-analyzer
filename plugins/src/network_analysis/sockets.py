"""FD sockets identified with each socket's own network namespace."""
import socket
from volatility3.framework.objects import utility
from volatility3.framework.symbols.linux import network


def fd_table(files, limit):
    """Select symbol-described layouts and validate bounds before allocation."""
    if files.has_member('fdt'):
        if not files.fdt:
            raise ValueError('NULL fdtable')
        table = files.fdt.dereference()
    elif files.has_member('fd') and files.has_member('max_fds'):
        table = files
    else:
        raise NotImplementedError('files_struct FD layout unavailable')
    count = int(table.max_fds)
    if not 0 <= count <= limit:
        raise ValueError(f'max_fds={count} outside safety budget 0..{limit}')
    if count and not table.fd:
        raise ValueError('NULL fd pointer with nonempty fdtable')
    return table, count


def collect(c):
    network.NetSymbols.apply(c.context.symbol_space[c.kernel.symbol_table_name])
    rows = []
    files_cache = {}
    socket_fops = c.kernel.object_from_symbol('socket_file_ops').vol.offset
    inode_offset = c.kernel.get_type('socket_alloc').relative_child_offset('vfs_inode')
    for task in c.tasks:
        def task_fds():
            if not task.files:
                return
            files_key = int(task.files)
            if files_key in files_cache:
                rows.extend(dict(row, pid=int(task.pid)) for row in files_cache[files_key])
                return
            start_row = len(rows)
            fdt, count = fd_table(task.files.dereference(), c.limit)
            if not count:
                files_cache[files_key] = []
                return
            fds = utility.array_of_pointers(fdt.fd.dereference(), count, c.kernel.symbol_table_name + '!file', c.context)
            for fd in range(count):
                def entry():
                    filp = fds[fd]
                    if not filp or int(filp.f_op) != socket_fops:
                        return
                    inode = filp.f_path.dentry.d_inode
                    alloc = c.obj('socket_alloc', int(inode) - inode_offset)
                    if not alloc.socket.sk:
                        return
                    sk = alloc.socket.sk.dereference()
                    common = sk.member('__sk_common')
                    ns = common.skc_net.net
                    row = {'pid': int(task.pid), 'fd': fd, 'file': hex(int(filp)), 'socket': hex(sk.vol.offset),
                           'namespace': hex(int(ns)), 'family': int(common.skc_family), 'source': 'task.files.fdt.fd -> socket_alloc.socket.sk',
                           'receive_queue_packets': int(sk.sk_receive_queue.qlen), 'state': int(common.skc_state)}
                    row['confidence'] = 'fd_reachable_socket_object'
                    row['socket_type'] = int(sk.sk_type)
                    row['protocol_number'] = int(sk.sk_protocol)
                    if row['family'] in (2, 10):
                        inet = sk.cast('inet_sock')
                        row['protocol'] = str(inet.get_protocol())
                        row['source_port'] = int(inet.get_src_port())
                        row['destination_port'] = int(inet.get_dst_port())
                        if row['family'] == 10:
                            row['source_ip'] = socket.inet_ntop(socket.AF_INET6, c.layer.read(common.skc_v6_rcv_saddr.vol.offset, 16))
                            row['destination_ip'] = socket.inet_ntop(socket.AF_INET6, c.layer.read(common.skc_v6_daddr.vol.offset, 16))
                        else:
                            row['source_ip'] = str(inet.get_src_addr())
                            row['destination_ip'] = str(inet.get_dst_addr())
                    elif row['family'] == 1:
                        unix = sk.cast('unix_sock')
                        row['path'] = None
                        if unix.addr:
                            length = int(unix.addr.len)
                            path_offset = c.kernel.get_type('sockaddr_un').relative_child_offset('sun_path')
                            if not path_offset <= length <= c.kernel.get_type('sockaddr_un').size:
                                raise ValueError('invalid sockaddr_un length')
                            raw = c.layer.read(unix.addr.name.vol.offset + path_offset, length - path_offset)
                            row['path_bytes_hex'] = raw.hex()
                            row['abstract'] = raw.startswith(b'\0')
                            row['path'] = '@' + raw[1:].decode('utf-8', errors='backslashreplace') if row['abstract'] else raw.rstrip(b'\0').decode('utf-8', errors='backslashreplace')
                        row['peer'] = hex(int(unix.peer))
                    rows.append(row)
                c.read('socket.fd', task, entry)
            files_cache[files_key] = rows[start_row:]
        c.read('socket.task', task, task_fds)
    unique = {}
    for row in rows:
        owner = {key: row[key] for key in ('pid', 'fd', 'file')}
        if row['socket'] not in unique:
            unique[row['socket']] = dict({key: value for key, value in row.items()
                                         if key not in ('pid', 'fd', 'file')}, holders=[])
        if owner not in unique[row['socket']]['holders']:
            unique[row['socket']]['holders'].append(owner)
    return list(unique.values())

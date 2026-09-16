"""FD ownership and bounded reciprocal UNIX peer discovery."""
import socket
from volatility3.framework.objects import utility
from volatility3.framework.symbols.linux import network
from volatility3.framework.symbols import linux
from . import identity


def fd_table(files, limit):
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


def file_dentry(filp):
    if filp.has_member('f_path'):
        return filp.get_dentry()
    if filp.has_member('f_dentry'):
        return filp.f_dentry
    raise NotImplementedError('file dentry layout unavailable')


def read_sock(c, sk, source):
    """Parse a socket independently from the FD(s) that reference it."""
    common = sk.member('__sk_common')
    ns = c.net_pointer(common.skc_net)
    if not ns:
        raise ValueError('NULL socket namespace')
    c.read('socket.namespace', sk, lambda: c.namespace(c.obj('net', ns), 'sock.__sk_common.skc_net'))
    row = {'socket':hex(sk.vol.offset), 'namespace':hex(int(ns)),
           'family':int(common.skc_family), 'source':source,
           'receive_queue_packets':int(sk.sk_receive_queue.qlen),
           'state':int(common.skc_state), 'socket_type':int(sk.sk_type),
           'protocol_number':int(sk.sk_protocol)}
    if row['family'] in (2,10):
        inet=sk.cast('inet_sock')
        row.update(protocol=str(inet.get_protocol()), source_port=int(inet.get_src_port()),
                   destination_port=int(inet.get_dst_port()))
        if row['family']==10:
            row['source_ip']=socket.inet_ntop(socket.AF_INET6,c.layer.read(common.skc_v6_rcv_saddr.vol.offset,16))
            row['destination_ip']=socket.inet_ntop(socket.AF_INET6,c.layer.read(common.skc_v6_daddr.vol.offset,16))
        else:
            row['source_ip']=str(inet.get_src_addr())
            row['destination_ip']=str(inet.get_dst_addr())
    elif row['family']==1:
        unix=sk.cast('unix_sock')
        row['path']=None
        if unix.addr:
            length=int(unix.addr.len)
            path_offset=c.kernel.get_type('sockaddr_un').relative_child_offset('sun_path')
            if not path_offset <= length <= c.kernel.get_type('sockaddr_un').size:
                raise ValueError('invalid sockaddr_un length')
            raw=c.layer.read(unix.addr.name.vol.offset+path_offset,length-path_offset)
            row['path_bytes_hex']=raw.hex()
            row['abstract']=raw.startswith(b'\0')
            row['path']='@'+raw[1:].decode('utf-8',errors='backslashreplace') if row['abstract'] else raw.rstrip(b'\0').decode('utf-8',errors='backslashreplace')
        row['peer']=hex(int(unix.peer))
        if sk.sk_socket:
            row['state_name']=unix.get_state()
    return row


def merge_holders(rows):
    unique={}
    for row in rows:
        holder={key:row[key] for key in ('pid','fd','file')}
        if row['socket'] not in unique:
            unique[row['socket']]=dict({key:value for key,value in row.items()
                                       if key not in ('pid','fd','file')},holders=[])
        if holder not in unique[row['socket']]['holders']:
            unique[row['socket']]['holders'].append(holder)
    return unique


def record_cached_holders(errors, indices, pid):
    """A failed immutable FD slot is scanned once; all affected tasks are recorded."""
    for index in indices:
        affected=errors[index].setdefault('affected_holders',[])
        holder={'pid':pid,'fd':errors[index].get('fd')}
        if holder not in affected:
            affected.append(holder)


def expand_unix_peers(c, unique, selected_pids):
    """One hop only, with family and reciprocal backlink validation."""
    seeds=[row for row in unique.values() if row['family']==1 and
           any(h['pid'] in selected_pids for h in row['holders'])]
    for row in seeds:
        peer=row.get('peer')
        if peer in (None,'0x0',row['socket']) or peer in unique:
            continue
        def read_peer():
            sk=c.obj('sock',int(peer,16))
            result=read_sock(c,sk,'unix_sock.peer')
            if result['family']!=1 or result.get('peer')!=row['socket']:
                raise ValueError('UNIX peer family/backlink mismatch')
            result.update(holders=[],confidence='reciprocal_kernel_peer',discovery='unix_peer')
            unique[result['socket']]=result
        c.read('socket.unix_peer',peer,read_peer)


def collect(c, task_records=None):
    network.NetSymbols.apply(c.context.symbol_space[c.kernel.symbol_table_name])
    socket_fops=c.kernel.object_from_symbol('socket_file_ops').vol.offset
    rows=[]
    files_cache={}
    file_cache={}
    for task in c.tasks:
        def task_fds():
            if not task.files:
                return
            files_key=int(task.files)
            pid=int(task.pid)
            if files_key in files_cache:
                cached,indices=files_cache[files_key]
                rows.extend(dict(row,pid=pid) for row in cached)
                record_cached_holders(c.errors,indices,pid)
                return
            start_row=len(rows)
            indices=[]
            fdt,count=fd_table(task.files.dereference(),c.limit)
            fds=utility.array_of_pointers(fdt.fd.dereference(),count,c.kernel.symbol_table_name+'!file',c.context) if count else []
            for fd in range(count):
                def entry():
                    filp=fds[fd]
                    if not filp:
                        return
                    address=int(filp)
                    if address in file_cache:
                        result=file_cache[address]
                        if result is not None:
                            rows.append(dict(result,pid=pid,fd=fd,file=hex(address)))
                        return
                    if int(filp.f_op)!=socket_fops:
                        file_cache[address]=None
                        return
                    dentry=file_dentry(filp)
                    inode=dentry.d_inode
                    if not inode:
                        raise ValueError(f'socket file {hex(address)} has NULL d_inode')
                    alloc=linux.LinuxUtilities.container_of(int(inode),'socket_alloc','vfs_inode',c.kernel)
                    if alloc is None:
                        if inode:
                            offset=c.kernel.get_type('socket_alloc').relative_child_offset('vfs_inode')
                            # Retain the actual layer exception; container_of's
                            # is_valid guard otherwise returns only None.
                            c.layer.read(int(inode)-offset,1)
                        raise ValueError('socket_alloc container_of unavailable')
                    if not alloc.socket.sk:
                        return
                    sk=alloc.socket.sk.dereference()
                    if sk.sk_socket and int(sk.sk_socket)!=alloc.socket.vol.offset:
                        raise ValueError('socket.sk -> sk_socket backlink mismatch')
                    result=read_sock(c,sk,'task.files -> fd -> file -> socket_alloc.socket.sk')
                    result.update(confidence='fd_reachable_socket_object',discovery='fd')
                    file_cache[address]=result
                    rows.append(dict(result,pid=pid,fd=fd,file=hex(address)))
                before=len(c.errors)
                c.read('socket.fd',task,entry)
                for index in range(before,len(c.errors)):
                    c.errors[index].update(pid=pid,fd=fd,files_struct=hex(files_key))
                    indices.append(index)
            files_cache[files_key]=(rows[start_row:],indices)
            record_cached_holders(c.errors,indices,pid)
        c.read('socket.task',task,task_fds)
    unique=merge_holders(rows)
    selected_pids={t['pid'] for t in (task_records or []) if identity.member_id(t)}
    expand_unix_peers(c,unique,selected_pids)
    return list(unique.values())


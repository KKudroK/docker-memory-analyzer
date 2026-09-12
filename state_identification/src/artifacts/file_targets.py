"""Resolve open-file objects to namespace paths, mount and backing inode."""
from .evidence import error


def dentry_chain(dentry, max_nodes=4096):
    names, nodes, seen = [], [], set()
    while dentry:
        address = int(dentry)
        if address in seen or len(seen) >= max_nodes:
            raise ValueError('Dentry parent cycle or safety limit')
        seen.add(address)
        name = dentry.d_name.name_as_str()
        parent = int(dentry.d_parent)
        nodes.append({'address': address, 'name': name, 'parent_address': parent})
        if parent == address:
            return {'filesystem_relative_path': '/' + '/'.join(reversed(names)), 'dentry_chain': nodes,
                    'scope': 'd_parent ancestry to filesystem root; not necessarily host mount path'}
        if name not in ('', '/'):
            names.append(name)
        dentry = dentry.d_parent
    raise ValueError('Dentry ancestry terminated before filesystem root')


def resolve_file(filp, kernel, context, task, host_task=None):
    from volatility3.framework.symbols.linux import LinuxUtilities
    result = {'source': 'kernel.file.f_path/f_mapping', 'errors': []}
    try:
        path = filp.f_path
        dentry, inode = path.dentry, path.dentry.d_inode
        result.update(file_address=int(filp), path_address=int(path.vol.offset),
            dentry_address=int(dentry), vfsmount_address=int(path.mnt), inode_address=int(inode),
            inode_number=int(inode.i_ino), device=int(inode.i_sb.s_dev),
            filesystem=inode.i_sb.s_type.name.dereference().cast('string', max_length=64, errors='replace'),
            size=int(inode.i_size), uid=int(inode.i_uid.val), gid=int(inode.i_gid.val))
        mount = LinuxUtilities.container_of(int(path.mnt), 'mount', 'mnt', kernel)
        result.update(mount_address=int(mount.vol.offset), mount_id=int(mount.mnt_id),
                      mount_root_dentry=int(path.mnt.mnt_root), mount_parent=int(mount.mnt_parent))
        if filp.f_mapping and filp.f_mapping.host:
            backing = filp.f_mapping.host
            result['backing'] = {'mapping_address': int(filp.f_mapping), 'inode_address': int(backing),
                'inode_number': int(backing.i_ino), 'device': int(backing.i_sb.s_dev),
                'filesystem': backing.i_sb.s_type.name.dereference().cast('string', max_length=64, errors='replace'),
                'different_from_path_inode': int(backing) != int(inode)}
        result.update(dentry_chain(dentry))
        if host_task is not None:
            result['host_root_view'] = str(LinuxUtilities.path_for_file(context, host_task, filp))
            result['host_view_note'] = 'Path rendered against PID 1 root; not proof of a recoverable host disk pathname'
    except Exception as exc:
        result['errors'].append(error('file.target', exc))
    return result

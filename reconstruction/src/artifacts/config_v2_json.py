"""Recover persisted Docker configuration from resident VFS pages.

This source is historical disk-cache evidence, not the live daemon state.
"""
import json
from .kernel_artifacts import cached_content
from .evidence import error


def recover_configs(loader):
    result = {'containers': [], 'errors': [], 'source': 'kernel.page_cache.config_v2',
              'limitations': ['persisted configuration can lag live daemon state', 'resident dentries only; no mount crossing']}
    for task in loader._pslist.list_tasks(loader._ctx, loader._kernel.name):
        if task.comm.cast('string', max_length=16, errors='replace') != 'dockerd':
            continue
        try:
            current = task.fs.root.dentry.dereference()
            for component in ('var', 'lib', 'docker', 'containers'):
                current = next((child for child in current.get_subdirs() if child.d_name.name_as_str() == component), None)
                if current is None:
                    result['errors'].append({'stage': 'config_v2.path', 'reason': 'not_in_resident_dcache', 'component': component})
                    break
            if current is None:
                continue
            for directory in current.get_subdirs():
                cid = directory.d_name.name_as_str()
                if len(cid) != 64 or any(c not in '0123456789abcdef' for c in cid):
                    continue
                for dentry in directory.get_subdirs():
                    if dentry.d_name.name_as_str() != 'config.v2.json':
                        continue
                    content = cached_content(dentry.d_inode, include_raw=True)
                    item = {'container_id': cid, 'dentry_address': int(dentry.vol.offset), 'content_coverage': content,
                            'confidence': 'medium', 'source': result['source']}
                    if content['complete']:
                        try:
                            # Parse original bytes, before redaction and before
                            # UTF-8 decoding at arbitrary page boundaries.
                            document = json.loads(b''.join(s['raw'] for s in content['segments']))
                            if document.get('ID') != cid:
                                raise ValueError('Directory CID does not match JSON ID')
                            item['document'] = document
                        except (ValueError, TypeError) as exc:
                            item['parse_error'] = error('config_v2.json', exc)
                    for segment in content['segments']:
                        segment.pop('raw', None)
                    result['containers'].append(item)
        except Exception as exc:
            result['errors'].append(error('config_v2', exc, pid=int(task.pid)))
    return result

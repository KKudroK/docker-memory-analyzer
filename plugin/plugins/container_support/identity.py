"""Container membership evidence, independent of capability extraction.

The current recognizer supports Docker-marked cgroup-v2 paths. A path marker
identifies a cgroup convention, not an authenticated Docker runtime record.
"""
# 이름이 containerd-shim인 프로세스의 자식만 고르는 방식이 아니라, 각 태스크의
# cgroup v2 소속과 Docker 경로 표식을 확인한다. 표식은 런타임 신원 인증이 아니다.
import re

from volatility3.framework.objects import utility
from volatility3.plugins.container_support.layouts import UnsupportedLayoutError, require_fields

SCOPE = re.compile(r'docker-([0-9a-fA-F]{64})\.scope\Z')
FULL_ID = re.compile(r'[0-9a-fA-F]{64}\Z')


def identify_docker(chain):
    """Select the nearest Docker-marked ancestor of a root-to-leaf chain."""
    found = None
    for index, node in enumerate(chain):
        name = node['name']
        match = SCOPE.fullmatch(name)
        cid = match.group(1).lower() if match else None
        if cid is None and index and chain[index - 1]['name'] == 'docker' and FULL_ID.fullmatch(name):
            cid = name.lower()
        if cid is not None:
            # 루트에서 태스크 쪽으로 읽으므로 나중의 표식이 가장 가까운 컨테이너다.
            # root_address는 태스크의 말단 cgroup이 아니라 Docker 표식이 붙은 객체 주소다.
            found = {
                'id': cid, 'root_address': node['address'],
                'root_path': '/' + '/'.join(x['name'] for x in chain[:index + 1] if x['name']),
            }
    return found


def read_cgroup_chain(start, limit=128, parent_field=None):
    """Follow CSS parents and cross-check every kernfs parent link."""
    # CSS와 kernfs의 부모 연결을 함께 대조해 경로 복원의 모순을 드러낸다.
    # 깨진 연결·순환을 만나면 불완전한 경로로 컨테이너를 추정하지 않는다.
    current, seen, chain = start, set(), []
    while current is not None:
        address = int(current.vol.offset)
        if address in seen:
            raise ValueError('Cycle in cgroup parent chain')
        if len(seen) >= limit:
            raise ValueError('cgroup parent chain exceeds limit')
        seen.add(address)
        if not int(current.kn):
            raise ValueError('cgroup.kn: null kernfs node')
        node = current.kn.dereference()
        if int(current.self.cgroup) != address:
            raise ValueError('cgroup.self.cgroup and containing cgroup disagree')
        css_parent = current.self.parent
        parent = None
        if int(css_parent):
            parent_css = css_parent.dereference()
            if not int(parent_css.cgroup):
                raise ValueError('Parent CSS has a null cgroup pointer')
            parent = parent_css.cgroup.dereference()
        name = utility.pointer_to_string(node.name, 256, errors='strict') if int(node.name) else ''
        if parent is None and name == '/':
            name = ''
        if '/' in name or '\x00' in name or len(name.encode('utf-8')) > 255:
            raise ValueError('Invalid or truncated cgroup component name')
        if parent is not None and not name:
            raise ValueError('Empty non-root cgroup component')
        selected_parent = parent_field
        if selected_parent is None:
            selected_parent = 'parent' if node.has_member('parent') else '__parent' if node.has_member('__parent') else None
        if selected_parent is None or not node.has_member(selected_parent):
            raise ValueError('kernfs_node.parent|__parent: unsupported kernfs parent layout')
        expected_parent = int(parent.kn) if parent is not None else 0
        if int(node.member(selected_parent)) != expected_parent:
            raise ValueError('cgroup CSS parent and kernfs parent disagree')
        chain.append({'address': hex(address), 'kernfs': hex(int(node.vol.offset)), 'name': name})
        current = parent
    # 순회는 말단→루트지만 반환은 루트→말단이다. 경로 조립과 표식 선택은 이 순서를 쓴다.
    return list(reversed(chain))


class CgroupV2Resolver:
    """Resolve task membership for reuse by capabilities/state/file plugins.

    Offsets come from the supplied kernel symbols. Failed reads raise errors;
    a successfully read path without a supported marker returns group=None.
    """
    def __init__(self, kernel_module):
        feature = 'container_membership'
        required = {
            'task_struct': ('cgroups',),
            'css_set': ('dfl_cgrp',),
            'cgroup': ('kn', 'self'),
            'cgroup_subsys_state': ('parent', 'cgroup'),
            'kernfs_node': ('name',),
        }
        templates = {name: require_fields(kernel_module, name, fields, feature)
                     for name, fields in required.items()}
        node = templates['kernfs_node']
        self.parent_field = 'parent' if node.has_member('parent') else '__parent' if node.has_member('__parent') else None
        if self.parent_field is None:
            raise UnsupportedLayoutError(feature, 'kernfs_node.parent|__parent', 'no supported kernfs parent member')
        self.compatibility = {
            'feature': feature, 'status': 'ok',
            'layout': {
                'hierarchy': 'cgroup-v2',
                'task_cgroups': 'task_struct.cgroups',
                'default_cgroup': 'css_set.dfl_cgrp',
                'css_parent': 'cgroup.self.parent.cgroup',
                'kernfs_parent': 'kernfs_node.' + self.parent_field,
            },
        }
        self.cache = {}

    def resolve(self, task):
        if not int(task.cgroups):
            raise ValueError('task_struct.cgroups: null css_set pointer')
        cset = task.cgroups.dereference()
        if not int(cset.dfl_cgrp):
            raise ValueError('css_set.dfl_cgrp: null default cgroup pointer')
        cgroup = cset.dfl_cgrp.dereference()
        address = int(cgroup.vol.offset)
        # 경로 문자열이나 컨테이너 ID가 같아도 서로 다른 cgroup 객체의 결과를 섞지 않는다.
        if address not in self.cache:
            # 전체 경로를 성공적으로 읽은 뒤에만 캐시해 일시적인 읽기 실패를 숨기지 않는다.
            chain = read_cgroup_chain(cgroup, parent_field=self.parent_field)
            self.cache[address] = (chain, identify_docker(chain))
        chain, group = self.cache[address]
        # 앞의 두 값은 Volatility 객체, chain/group은 보고서용 값이다. 표식이 없으면 group=None.
        return cset, cgroup, chain, group

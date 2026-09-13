"""Select known Linux layouts using supplied symbols, never fixed offsets."""

# 커널 버전 문자열 대신 일치하는 ISF의 타입·멤버로 알려진 구조를 선택한다.
# 새 구조는 명시적으로 지원해야 하며, 심볼 제공만으로 모든 커널 호환이 보장되지는 않는다.
from volatility3.framework import exceptions


class UnsupportedLayoutError(exceptions.VolatilityException):
    """A required type or field is absent from the supplied kernel symbols."""

    def __init__(self, feature, field, reason):
        self.feature, self.field = feature, field
        self.message = f'{feature}: {field}: {reason}'
        self.compatibility = {
            'feature': feature, 'status': 'unsupported',
            'field': field, 'message': self.message,
        }
        super().__init__(self.message)


def require_type(module, name, feature):
    try:
        template = module.get_type(name)
    except (exceptions.SymbolError, KeyError) as exc:
        raise UnsupportedLayoutError(feature, name, 'required symbol type is missing') from exc
    if template is None:
        raise UnsupportedLayoutError(feature, name, 'required symbol type is missing')
    return template


def require_fields(module, name, fields, feature):
    # 메모리를 읽기 전에 ISF 타입에 필수 멤버가 있는지 검사하고, 같은 타입 템플릿을 돌려준다.
    template = require_type(module, name, feature)
    for field in fields:
        if not template.has_member(field):
            raise UnsupportedLayoutError(feature, f'{name}.{field}', 'required symbol field is missing')
    return template


def _pidtype_pid(module):
    """Use the enum when present; only a missing enum permits the known value.

    Linux's pid_link-based task layout defines PIDTYPE_PID as the first enum
    value (zero), e.g. include/linux/pid.h at Linux v4.18:
    https://github.com/torvalds/linux/blob/v4.18/include/linux/pid.h
    A present but unfamiliar enum is rejected rather than treated as absent.
    """
    try:
        enum = module.get_enumeration('pid_type')
    except (exceptions.SymbolError, KeyError):
        enum = None
    if enum is None:
        return 0, 'known Linux pid_link layout: PIDTYPE_PID=0; enum absent'
    index = enum.choices.get('PIDTYPE_PID')
    if type(index) is not int or not 0 <= index < 32:
        raise UnsupportedLayoutError('pid_namespace', 'pid_type.PIDTYPE_PID', 'missing or invalid enumeration value')
    return index, 'pid_type enumeration'


def inspect_pid_layout(module):
    """Describe one supported PID/namespace layout without reading a task."""
    feature = 'pid_namespace'
    task = require_fields(module, 'task_struct', ('pid',), feature)
    layout = {}
    if task.has_member('thread_pid'):
        layout['task_pid'] = 'thread_pid'
    elif task.has_member('pids'):
        require_fields(module, 'pid_link', ('pid',), feature)
        index, source = _pidtype_pid(module)
        layout.update(task_pid='pids[PIDTYPE_PID].pid', pidtype_pid=index, pidtype_source=source)
    else:
        raise UnsupportedLayoutError(feature, 'task_struct.thread_pid|pids', 'no supported PID pointer member')
    pid = require_fields(module, 'pid', ('level', 'numbers'), feature)
    upid = require_fields(module, 'upid', ('nr', 'ns'), feature)
    namespace = require_type(module, 'pid_namespace', feature)
    if namespace.has_member('ns'):
        require_fields(module, 'ns_common', ('inum',), feature)
        layout['namespace_id'] = 'ns.inum'
    elif namespace.has_member('proc_inum'):
        layout['namespace_id'] = 'proc_inum'
    else:
        raise UnsupportedLayoutError(feature, 'pid_namespace.ns.inum|proc_inum', 'no supported namespace identifier member')
    offset, size = pid.relative_child_offset('numbers'), upid.size
    if type(offset) is not int or offset < 0 or offset > pid.size:
        raise UnsupportedLayoutError(feature, 'pid.numbers', 'invalid flexible-array offset')
    if type(size) is not int or size <= 0:
        raise UnsupportedLayoutError(feature, 'upid', 'invalid symbol type size')
    layout.update(numbers_offset=offset, upid_size=size)
    # 이 layout은 아래 판독기의 주소 계산과 외부 호환성 보고에 함께 쓰이는 선택 결과다.
    return {'feature': feature, 'status': 'ok', 'layout': layout}


def read_pid_chain(task, module):
    """Return host-to-inner PID namespace IDs for a task's individual TID.

    Both pid.numbers[1] and zero-length flexible ISF arrays are traversed using
    the symbol offset and upid size. A present pointer that cannot be read does
    not trigger a fallback to a different layout.
    """
    layout = inspect_pid_layout(module)['layout']
    field = 'task_struct.' + layout['task_pid']
    try:
        if layout['task_pid'] == 'thread_pid':
            pointer = task.thread_pid
        else:
            pointer = task.pids[layout['pidtype_pid']].pid
        if not int(pointer):
            raise ValueError(f'{field}: null PID pointer')
        pid = pointer.dereference()
        field = 'pid.level'
        level = int(pid.level)
        if not 0 <= level <= 32:
            raise ValueError('pid.level: invalid PID namespace level')
        # 가변 배열의 실제 원소 수는 pid.level에서, 주소 간격은 심볼의 upid 크기에서 얻는다.
        base = int(pid.vol.offset) + layout['numbers_offset']
        result = []
        for index in range(level + 1):
            field = f'pid.numbers[{index}]'
            upid = module.object('upid', offset=base + index * layout['upid_size'], absolute=True)
            nr = int(upid.nr)
            if nr < 0:
                raise ValueError(f'{field}.nr: negative PID')
            field += '.ns'
            if not int(upid.ns):
                raise ValueError(f'{field}: null PID namespace pointer')
            namespace = upid.ns.dereference()
            field += '.' + layout['namespace_id']
            inum = int(namespace.ns.inum) if layout['namespace_id'] == 'ns.inum' else int(namespace.proc_inum)
            result.append({'level': index, 'id': nr, 'namespace': inum})
        field = 'task_struct.pid'
        # numbers[0]과 task.pid는 태스크의 호스트 TID다. 프로세스 대표 ID인 tgid와 대조하지 않는다.
        if result[0]['id'] != int(task.pid):
            raise ValueError('task_struct.pid and pid.numbers[0].nr: Host TID and PID-object ID disagree')
        return result
    except (exceptions.InvalidAddressException, AttributeError, IndexError) as exc:
        raise ValueError(f'{field}: could not read PID namespace evidence ({type(exc).__name__}: {exc})') from exc

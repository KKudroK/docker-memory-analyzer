"""Evidence-derived analyst presentation. No live Docker state or risk score.

This module uses only the recorded audit. Missing masks remain unknown, and
capability sets are never merged into a purported container-wide authority.
"""
import json
import unicodedata

REPORT_VERSION = '1.0'
CAPS = ('cap_inheritable', 'cap_permitted', 'cap_effective', 'cap_bounding', 'cap_ambient')
LABELS = dict(zip(CAPS, ('I / 상속 후보', 'P / 보유', 'E / 현재 유효', 'B / exec 제한', 'A / ambient')))
REVIEW_CAPS = {
    'sys_admin': '시스템 관리 작업 범위', 'sys_module': '커널 모듈 관련 작업',
    'sys_ptrace': '다른 프로세스 조사·접근 범위', 'sys_rawio': '원시 I/O 접근 범위',
    'dac_read_search': '파일 읽기·디렉터리 검색 검사 우회 범위',
    'net_admin': '대상 network namespace의 네트워크 설정',
    'bpf': '특권 BPF 작업과 추가 권한·seccomp 조건',
    'perfmon': '성능 관측 작업과 대상 범위',
    'checkpoint_restore': 'PID 설정·복원 관련 작업과 대상 범위',
}
STATUS = {'ok': '확인', 'not_present': '필드 없음', 'unsupported': '미지원',
          'read_error': '읽기 실패', 'inconsistent': '불일치', 'not_evaluated': '미평가'}


def clean(value):
    """Render memory-sourced strings as data, including terminal controls."""
    if value is None:
        return '확인 불가'
    return ''.join(c if not unicodedata.category(c).startswith('C') else repr(c)[1:-1]
                   for c in str(value))


def number(value):
    try:
        if value is None or isinstance(value, bool):
            return None
        result = int(value, 0) if isinstance(value, str) else int(value)
        return result if 0 <= result < (1 << 64) else None
    except (ValueError, TypeError, OverflowError):
        return None


def cap_entry(member, field):
    evidence = (member.get('capability_evidence') or {}).get(field) or {}
    # 과거 감사 파일의 권한 이름만으로 마스크를 역산하지 않는다. None은 미기록, 0은 빈 집합이다.
    mask = number(evidence.get('raw_mask'))
    names = evidence.get('names')
    value = member.get(field)
    if mask == 0:
        names = []
    elif not isinstance(names, list):
        names = None if value is None or value == 'all' else [s.strip() for s in value.split(',') if s.strip()]
    if names is not None:
        names = [str(s).lower().removeprefix('cap_') if not str(s).startswith('CAP_BIT_') else str(s) for s in names]
    states = [o for o in member.get('observations', []) if o.get('source') == 'credentials'
              and o.get('feature') == field and o.get('status') != 'ok']
    state = STATUS.get(states[0]['status'], states[0]['status']) if states else '원시 마스크 미기록'
    text = ('없음' if mask == 0 else ', '.join(names) if names else clean(value))
    if mask is None:
        text = (clean(value) if value is not None else state) + ' [마스크 확인 불가]'
    return {'mask': mask, 'names': names, 'text': text, 'evidence': evidence}


def task_report(member):
    # 이름 문자열이 아닌 보존된 원시 마스크로 집합 차이를 계산한다. 미기록 값은 미확인이다.
    # Bounding은 exec 시 취득 제한이므로 E가 B 밖에 있다는 이유만으로 불일치로 분류하지 않는다.
    sets = {field: cap_entry(member, field) for field in CAPS}
    # i/p/e/b/a는 각각 상속 후보·보유·현재 유효·exec 취득 제한·ambient 집합의 비트마스크다.
    i, p, e, b, a = (sets[field]['mask'] for field in CAPS)
    deltas = {
        'permitted_not_effective': p & ~e if p is not None and e is not None else None,
        'effective_not_permitted': e & ~p if e is not None and p is not None else None,
        'ambient_outside_pi': a & ~(p & i) if all(v is not None for v in (a, p, i)) else None,
    }
    checks = []
    def add(code, kind, text):
        checks.append({'code': code, 'kind': kind, 'text': text})
    if e == 0:
        add('EFFECTIVE_EMPTY', '관측', '현재 Effective 권한 없음. 일반 UID/GID 기반 접근은 별도.')
    if deltas['permitted_not_effective']:
        add('PERMITTED_INACTIVE', '검토', 'P-E=' + hex(deltas['permitted_not_effective']) + ': 보유하지만 현재 비활성인 권한.')
    if deltas['effective_not_permitted']:
        add('EFFECTIVE_OUTSIDE_PERMITTED', '일관성', 'E-P=' + hex(deltas['effective_not_permitted']) + ': 집합 관계 불일치. 원시 바이트·수집 일관성 확인.')
    if deltas['ambient_outside_pi']:
        add('AMBIENT_OUTSIDE_PI', '일관성', 'A-(P&I)=' + hex(deltas['ambient_outside_pi']) + ': ambient 집합 관계 불일치 확인.')
    if a:
        add('AMBIENT_PRESENT', '검토', 'Ambient가 관측됨. exec 시 권한 전달 조건 확인.')
    for key, code in (('unknown_bits', 'UNKNOWN_BITS'), ('out_of_range_bits', 'OUT_OF_RANGE_BITS')):
        affected = [field + '=' + hex(number(sets[field]['evidence'].get(key))) for field in CAPS
                    if number(sets[field]['evidence'].get(key))]
        if affected:
            add(code, '일관성', ('이름 미상 비트: ' if key == 'unknown_bits' else '커널 유효 범위 밖 비트: ') + ', '.join(affected))
    if any(sets[field]['mask'] is None for field in CAPS):
        add('MASKS_UNAVAILABLE', '미확인', '일부 원시 마스크가 없어 집합 연산·전체 권한 여부를 확정하지 않음.')
    names = sets['cap_effective']['names']
    review = [name for name in (names or []) if name in REVIEW_CAPS]
    if review:
        add('CAP_REVIEW', '검토', '; '.join(name.upper() + ': ' + REVIEW_CAPS[name] for name in review))
    if member.get('CredsDiffer') is True:
        add('CREDS_DIFFER', '검토', 'task.cred와 real_cred 주소가 다름. 일시적 자격 증명 전환도 가능하며 상승 이력의 증거는 아님.')
    current, real = member.get('credentials') or {}, member.get('real_credentials') or {}
    diffs = []
    for field in CAPS:
        left = number((current.get('capability_evidence', {}).get(field) or {}).get('raw_mask'))
        right = number((real.get('capability_evidence', {}).get(field) or {}).get('raw_mask'))
        if left is not None and right is not None and left != right:
            diffs.append(field)
    if diffs:
        add('CRED_VALUES_DIFFER', '검토', '현재/객관 자격 증명의 관측 마스크 차이: ' + ', '.join(diffs))
    if member.get('SeccompMode') == 0:
        add('SECCOMP_OFF', '검토', 'seccomp mode=0 관측. syscall 필터에 의한 제한은 비활성.')
    bad = [o for o in member.get('observations', []) if o.get('status') != 'ok']
    if bad or member.get('Status') == 'partial':
        detail = '; '.join(str(o.get('source')) + '.' + str(o.get('feature')) + '=' +
                           STATUS.get(o.get('status'), str(o.get('status'))) for o in bad)
        add('PARTIAL_DATA', '미확인', '부분 관측: ' + (detail or '상세 감사 JSON 확인'))
    return {'pid': member['PID'], 'tid': member['TID'], 'name': member.get('Name'),
            'source': member, 'sets': sets, 'effective_names': names, 'deltas': deltas, 'checks': checks}


def compare(tasks):
    # 동일 프로세스의 스레드도 권한·제한이 다를 수 있다. 관측 차이와 비교 불가를 따로 기록한다.
    # 필터 객체의 차이는 규칙별 동작 차이나 접근 성공의 증거로 해석하지 않는다.
    fields = CAPS + ('UserNS', 'CapabilityScope', 'EUID', 'UserEUID', 'NoNewPrivs',
                     'SeccompMode', 'SeccompFilters', 'Securebits', 'MountNS', 'NetNS')
    different, unknown = [], []
    for field in fields:
        values = [t['sets'][field]['mask'] if field in CAPS else t['source'].get(field) for t in tasks]
        if any(v is None or (field == 'CapabilityScope' and v == 'unknown') for v in values):
            unknown.append(field)
        # 일부 태스크가 미확인이어도 나머지 관측값끼리 차이가 있으면 두 상태를 함께 남긴다.
        if len({json.dumps(v, sort_keys=True) for v in values if v is not None and v != 'unknown'}) > 1:
            different.append(field)
    def ids(m):
        value = (m.get('credentials') or {}).get('ids_kernel')
        return value if value and all(v is not None for v in value.values()) else None
    def filters(m):
        sec = m.get('seccomp') or {}
        return sec.get('filters') if sec.get('chain_complete') is True else None
    def root(m):
        mounts = m.get('mounts') or {}
        values = (mounts.get('task_root_mount'), mounts.get('task_root_dentry'))
        return values if all(v is not None for v in values) else None
    for field, getter in (
        ('credential_ids', ids),
        ('supplementary_groups', lambda m: (m.get('credentials') or {}).get('supplementary_gids_kernel')),
        ('seccomp_filter_chain', filters), ('filesystem_root', root),
    ):
        values = [getter(t['source']) for t in tasks]
        if any(v is None for v in values):
            unknown.append(field)
        if len({json.dumps(v, sort_keys=True) for v in values if v is not None}) > 1:
            different.append(field)
    return {'different_fields': different, 'unknown_fields': unknown}


def build_report(audit, members):
    # audit의 전체 수집 메타데이터와 선택된 members를 결합하며, source에 원래 관측값을 유지한다.
    grouped = {}
    for member in sorted(members, key=lambda m: (m['ContainerID'], m['ContainerRoot'], m['PID'], m['TID'])):
        # 같은 ID라도 cgroup 루트 객체가 다르면 별도 그룹으로 두어 근거가 다른 태스크를 섞지 않는다.
        key = (member['ContainerID'], member['ContainerRoot'])
        group = grouped.setdefault(key, {'container_id': key[0], 'root_address': key[1],
                                        'path': member.get('ContainerPath'), 'members': []})
        group['members'].append(task_report(member))
    groups = list(grouped.values())
    for index, group in enumerate(groups, 1):
        group['label'] = 'C' + str(index)
        group['comparisons'] = [dict(pid=pid, **compare([t for t in group['members'] if t['pid'] == pid]))
                                for pid in sorted({t['pid'] for t in group['members']})]
        group['member_comparison'] = compare(group['members'])
    return {'report_version': REPORT_VERSION, 'plugin_version': audit.get('plugin_version'),
            'created_utc': audit.get('created_utc'), 'enumerated_tasks': audit.get('enumerated_tasks'),
            'discovered_docker_tasks': audit.get('discovered_docker_tasks'),
            'unmarked_tasks': audit.get('tasks_without_docker_marker', audit.get('non_docker_tasks')),
            'include_threads': audit.get('include_threads'),
            'quality': {k: len(audit.get(k) or []) for k in
                        ('membership_errors', 'field_errors', 'traversal_errors', 'partial_observations')},
            'thread_inventory': audit.get('thread_inventory', []), 'groups': groups}


def mask_text(entry):
    value = entry['mask']
    return '확인 불가' if value is None else f'원시 {value.bit_count()}비트 / {value:#x}'


def rows(report):
    """Three narrow columns for both a native TreeGrid and the readable CLI."""
    q = report['quality']
    yield '전체', '분석 범위', f"태스크 {report['enumerated_tasks']} | Docker 표식 {report['discovered_docker_tasks']} | 표시 컨테이너 {len(report['groups'])}"
    yield '전체', '관측 품질', '소속 오류 {membership_errors} / 필드 오류 {field_errors} / 순회 오류 {traversal_errors} / 부분 관측 {partial_observations}'.format(**q)
    yield '전체', '선택 기준', f"Docker cgroup v2 커널 연결 관계. 표식 없는 태스크 {report['unmarked_tasks']}개는 미표시. 다른 런타임 부재 판정 아님."
    yield '전체', '수집 범위', '프로세스와 스레드' if report['include_threads'] else '대표 스레드만 수집됨; 전체 스레드 비교 불가'
    for group in report['groups']:
        for task in group['members']:
            yield '목록', f"{group['label']} {task['pid']}/{task['tid']}", f"{task['name']} | E={task['sets']['cap_effective']['text']}"
    review_count = 0
    for group in report['groups']:
        for task in group['members']:
            for check in task['checks']:
                if check['kind'] != '관측':
                    review_count += 1
                    yield '확인 대상', f"{group['label']} {task['pid']}/{task['tid']}", check['kind'] + ': ' + check['text']
    if not review_count:
        yield '확인 대상', '자동 검토 규칙', '일치 항목 없음. 관측값의 안전·무해 판정은 아님.'
    for group in report['groups']:
        label = group['label']
        yield label, '컨테이너', group['container_id']
        yield label, '소속 근거', f"root={group['root_address']} | {group['path']}"
        yield label, '구성원', f"프로세스 {len({t['pid'] for t in group['members']})} / 태스크 {len(group['members'])}"
        for task in group['members']:
            m, sets = task['source'], task['sets']
            section = f"{label} {task['pid']}/{task['tid']}"
            yield section, '프로세스', f"{task['name']} | 내부 PID/TID={clean(m.get('NSPID'))}/{clean(m.get('NSTID'))} | 관측={clean(m.get('Status'))}"
            yield section, 'E 현재 유효', sets['cap_effective']['text'] + ' | ' + mask_text(sets['cap_effective'])
            yield section, '나머지 집합', ' | '.join(f"{LABELS[f]}: {mask_text(sets[f])}" for f in CAPS if f != 'cap_effective')
            for field in CAPS:
                if field != 'cap_effective' and sets[field]['mask'] not in (0, sets['cap_effective']['mask']):
                    yield section, LABELS[field], sets[field]['text']
            d = task['deltas']
            yield section, '집합 비교', 'P-E=' + clean(hex(d['permitted_not_effective']) if d['permitted_not_effective'] is not None else None) + ' | E-P=' + clean(hex(d['effective_not_permitted']) if d['effective_not_permitted'] is not None else None) + ' | A-(P&I)=' + clean(hex(d['ambient_outside_pi']) if d['ambient_outside_pi'] is not None else None)
            scope = {'initial_user_namespace': '초기 user namespace', 'descendant_user_namespace': '하위 user namespace'}.get(m.get('CapabilityScope'), '범위 확인 불가')
            yield section, '권한 범위', f"{scope} {clean(m.get('UserNS'))} | EUID 커널/내부={clean(m.get('EUID'))}/{clean(m.get('UserEUID'))}"
            sec = m.get('seccomp') or {}
            mode = {0: '0 disabled', 1: '1 strict', 2: '2 filter'}.get(m.get('SeccompMode'), clean(m.get('SeccompMode')))
            yield section, '실행 제한', f"seccomp={mode} | 필터={clean(m.get('SeccompFilters'))} | no_new_privs={clean(m.get('NoNewPrivs'))} | securebits={clean(m.get('Securebits'))}"
            if sec.get('filter_count_source'):
                yield section, '필터 근거', f"{sec['filter_count_source']} | 체인 관측={clean(sec.get('observed_filter_count'))} | 완전={clean(sec.get('chain_complete'))}"
            resources = m.get('resource_namespaces') or {}
            net = resources.get('network') or {}
            yield section, '자원 범위', f"PIDNS={clean(m.get('PIDNS'))} | MountNS={clean(m.get('MountNS'))} | NetNS={clean(m.get('NetNS'))} | NetNS 소유 UserNS={clean(net.get('owner_user_namespace_inum'))}"
            yield section, 'cred 근거', f"{clean(m.get('CredSource'))}={clean(m.get('CredAddress'))} | real_cred={clean(m.get('RealCredAddress'))} | 주소 다름={clean(m.get('CredsDiffer'))}"
            evidence = sets['cap_effective']['evidence']
            yield section, 'E 원시 근거', f"주소={clean(evidence.get('virtual_address'))} | bytes={clean(evidence.get('bytes_hex'))} | 커널 유효 마스크={clean(evidence.get('kernel_mask'))}"
            for item in task['checks']:
                yield section, item['kind'] + ' ' + item['code'], item['text']
        comparison = group['member_comparison']
        if len(group['members']) > 1:
            yield label, '구성원 차이', ', '.join(comparison['different_fields']) or '비교한 요약 필드에서 관측 차이 없음'
            if comparison['unknown_fields']:
                yield label, '비교 미확인', ', '.join(comparison['unknown_fields'])
        for c in group['comparisons']:
            count = sum(t['pid'] == c['pid'] for t in group['members'])
            if count > 1:
                yield label, f"PID {c['pid']} 스레드 차이", ', '.join(c['different_fields']) or '비교한 요약 필드에서 관측 차이 없음'
    counts = [item for item in report['thread_inventory'] if item.get('pid') in
              {t['pid'] for group in report['groups'] for t in group['members']}]
    yield '전체', '스레드 교차확인', f"signal.nr_threads 일치 {sum(c.get('count_matches') is True for c in counts)}/{len(counts)} | 불일치 {sum(c.get('count_matches') is False for c in counts)} | 미확인 {sum(c.get('count_matches') is None for c in counts)}"
    if not report['groups']:
        yield '전체', '검색 결과', '선택 조건에 맞는 Docker 표식 구성원 없음. 순회·소속 오류와 수집 범위 확인.'
    yield '해석', '집합 의미', 'P-E는 보유 중 비활성. B는 exec 시 파일 권한 취득을 제한하며 현재 E의 상한과 동일하지 않음.'
    yield '해석', '판정 한계', '검토 항목은 침해·권한 상승 이력·탈출 성공 판정이 아님. 초기 UserNS/EUID 0도 호스트 접근 성공을 보장하지 않음.'
    yield '해석', '관측 상태', 'ok는 수집한 필드를 읽었다는 뜻. 검토 권한 목록은 조사 편의를 위한 일부 항목이며 전체 위험 목록이 아님.'
    yield '해석', '미평가', 'seccomp 규칙별 허용, LSM, 파일 DAC/ACL·idmapped mount. no_new_privs=False는 권한 상승 발생 증거가 아님.'


def grid_rows(report):
    for section, item, value in rows(report):
        items = list(wrap_cells(item, 26)) or ['']
        values = list(wrap_cells(value, 72)) or ['']
        for index in range(max(len(items), len(values))):
            yield (clean(section) if index == 0 else '', items[index] if index < len(items) else '',
                   values[index] if index < len(values) else '')


SUMMARY_COLUMNS = ('Container', 'PID/TID', 'Name', 'Effective', 'UserNS', 'Seccomp', 'Check')


def summary_rows(report):
    """One row per observed task; full evidence stays in the JSON report."""
    # 표는 태스크마다 한 행으로 유지한다. Check는 조사할 근거의 요약이며 위험 점수가 아니다.
    ids = [g['container_id'] for g in report['groups']]
    width = 12
    # 서로 다른 전체 ID의 접두사가 겹치면 구별될 때까지 표시 길이만 늘린다.
    while width < 64 and len({cid[:width] for cid in ids}) != len(set(ids)):
        width += 1
    for group in report['groups']:
        duplicate = ids.count(group['container_id']) > 1
        # 전체 ID가 같은 별도 루트 그룹은 /C번호로 구분하고, 실제 루트 주소는 상세 보고서에 둔다.
        identity = group['container_id'][:width] + ('/' + group['label'] if duplicate else '')
        for task in group['members']:
            member = task['source']
            entry = task['sets']['cap_effective']
            names = entry['names']
            if entry['mask'] is None:
                effective = '미확인'
            elif entry['mask'] == 0:
                effective = '없음'
            elif names and len(names) <= 2:
                effective = ','.join(name.upper() for name in names)
            else:
                effective = f"원시 {entry['mask'].bit_count()}비트"
            scope = {'initial_user_namespace': '초기', 'descendant_user_namespace': '하위'}.get(member.get('CapabilityScope'), '미확인')
            seccomp = {0: 'off', 1: 'strict', 2: 'filter/' + clean(member.get('SeccompFilters'))}.get(member.get('SeccompMode'), '미확인')
            codes = {c['code'] for c in task['checks']}
            # 한 칸에는 아래 우선순위의 대표 항목을 표시한다. 생략된 checks도 상세 JSON에는 유지된다.
            if codes & {'PARTIAL_DATA', 'MASKS_UNAVAILABLE'}:
                check = '부분/미확인'
            elif codes & {'EFFECTIVE_OUTSIDE_PERMITTED', 'AMBIENT_OUTSIDE_PI', 'UNKNOWN_BITS', 'OUT_OF_RANGE_BITS'}:
                check = '비트·집합 확인'
            elif codes & {'CREDS_DIFFER', 'CRED_VALUES_DIFFER'}:
                check = 'cred 차이'
            elif codes & {'PERMITTED_INACTIVE', 'AMBIENT_PRESENT'}:
                check = '권한 전이 검토'
            elif 'SECCOMP_OFF' in codes:
                check = '필터 비활성'
            elif 'CAP_REVIEW' in codes:
                check = '권한 검토'
            else:
                check = '-'
            comparison = next(c for c in group['comparisons'] if c['pid'] == task['pid'])
            if comparison['different_fields']:
                check = '스레드 차이' if check == '-' else check + ' +차이'
            yield tuple(clean(v) for v in (identity, f"{task['pid']}/{task['tid']}", task['name'], effective, scope, seccomp, check))


def format_summary(report):
    table = list(summary_rows(report))
    headers = ('컨테이너', 'PID/TID', '프로세스', 'Effective', 'UserNS', 'seccomp', '확인')
    widths = [max([cell_width(headers[i])] + [cell_width(row[i]) for row in table]) for i in range(len(headers))]
    def line(row):
        return '  '.join(text + ' ' * (width - cell_width(text)) for text, width in zip(row, widths)).rstrip()
    q = report['quality']
    errors = sum(q[k] for k in ('membership_errors', 'field_errors', 'traversal_errors'))
    output = [f"Container Caps {clean(report['plugin_version'])} | 컨테이너 {len(report['groups'])} · 표시 태스크 {len(table)} | 오류 {errors} · 부분 {q['partial_observations']}",
              '', line(headers), '-' * cell_width(line(headers))]
    output.extend(line(row) for row in table)
    if not table:
        output.append('선택 조건에 맞는 Docker 표식 구성원 없음.')
    output.extend(['', 'UserNS=권한 적용 범위. 확인 항목은 조사 대상이며 침해 판정이 아닙니다.',
                   '권한 전체·집합 차이·NNP·주소·원시 바이트는 상세 JSON에 있습니다.'])
    return '\n'.join(output) + '\n'


def cell_width(text):
    # 한글의 화면 폭과 결합 문자를 반영해 문자 수가 아닌 터미널 셀 수로 열을 맞춘다.
    return sum(0 if unicodedata.combining(c) else 2 if unicodedata.east_asian_width(c) in ('W', 'F') else 1 for c in text)


def wrap_cells(text, width):
    line = ''
    for token in clean(text).split(' '):
        proposed = line + (' ' if line else '') + token
        if cell_width(proposed) <= width:
            line = proposed
            continue
        if line:
            yield line
            line = ''
        for char in token:
            if cell_width(line + char) > width:
                yield line
                line = ''
            line += char
    if line:
        yield line


def format_report(report, width=112):
    width = max(64, min(width, 160))
    output = ['Container Caps ' + clean(report['plugin_version']) + ' | 분석가 보기',
              '분석 시각(UTC): ' + clean(report['created_utc']), '=' * width]
    previous = None
    for section, item, value in rows(report):
        if section != previous:
            output.extend(['', '[' + clean(section) + ']'])
            previous = section
        prefix = '  ' + clean(item) + ': '
        if cell_width(prefix) > 32:
            output.append(prefix.rstrip())
            prefix = '    '
        lines = list(wrap_cells(value, width - cell_width(prefix))) or ['']
        output.append(prefix + lines[0])
        output.extend(' ' * cell_width(prefix) + line for line in lines[1:])
    return '\n'.join(output) + '\n'

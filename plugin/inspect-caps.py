#!/usr/bin/env python3
"""ContainerCaps 1.4.1 — 단일 파일 배포판.

Docker cgroup v2의 태스크별 capabilities와 보안 맥락을 메모리에서 읽는다.
플러그인 자체는 이 파일 하나이며, Python과 Volatility는 별도로 설치한다.

설치 (검증 환경: Python 3.12, 전용 가상환경):
    python -m pip install volatility3==2.28.0 pefile==2024.8.26 jsonschema==4.26.0
핵심 표 / 상세 JSON / 저장 결과 조회:
    python inspect-caps.py --dump memory.lime --symbols symbols --output-root results
    python inspect-caps.py --saved --output-root results --json
    python inspect-caps.py --saved --output-root results --container <ID접두사>
Volatility 명령 직접 실행 (이 파일이 있는 폴더에서):
    python inspect-caps.py --volatility -p . -s symbols -f memory.lime -o results inspect-caps.ContainerCaps --view analyst
    vol -p . -s symbols -f memory.lime -o results inspect-caps.ContainerCaps --view analyst
실험용 BTF ISF를 사용할 때만 필요한 메타데이터 준비 / 원복:
    python inspect-caps.py --prepare-lab-schema
    python inspect-caps.py --restore-lab-schema

symbols는 덤프와 일치하는 ISF가 들어 있는 linux/의 상위 폴더다.
기본 화면은 7열 요약이며 상세 근거는 결과 폴더의 JSON에 저장한다.
실제 검증: Ubuntu 7.0.0-31-generic, x86-64, Docker cgroup v2의 5개 컨테이너.
다른 커널은 심볼 구조를 검사해 지원 가능한 경로를 선택하며, 모든 커널을
검증했다는 뜻은 아니다. 권한 관측만으로 침해나 컨테이너 탈출을 판정하지 않는다.

파일 구성: 1) 저장 자료 해석·표 2) 사용자 CLI 3) 선택적 스키마 준비
           4) 심볼/PID 5) cgroup 소속 6) capability 판독 7) 보안 맥락 8) 수집 플러그인
1.4.1: cap_last_cap 타입 누락을 보완하고, 보조 범위 조회 실패 시 원시 권한을 보존한다.
"""

import argparse
import datetime
import hashlib
import importlib.metadata
import importlib.util
import json
import logging
import multiprocessing
import os
from pathlib import Path
import platform
import re
import shutil
import subprocess
import sys
import tempfile
import unicodedata

BASE = Path(__file__).resolve().parent
VERSION = '1.4.1'
CAPS = ('cap_inheritable', 'cap_permitted', 'cap_effective', 'cap_bounding', 'cap_ambient')
CAP_FIELDS = CAPS

# --volatility는 첫 번째 옵션이다. 클래스 정의 전에 공식 CLI로 진입해야
# __main__과 정식 플러그인 모듈에 클래스가 이중 등록되는 것을 막는다.
# Windows에서 하위 프로세스가 시작될 때 CLI가 재귀 실행되지 않도록 보호한다.
if __name__ == '__main__' and sys.argv[1:2] == ['--volatility']:
    multiprocessing.freeze_support()
    sys.argv = [sys.argv[0], *sys.argv[2:]]
    from volatility3.cli import main as volatility_main
    volatility_main()
    raise SystemExit(0)



# 1. 저장된 관측 자료의 해석과 터미널 표

REPORT_VERSION = '1.0'
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


# 2. 사용자 CLI: 새 분석 또는 저장 결과 조회

STATUS_LABELS = {'ok': '확인', 'unsupported': '미지원', 'not_present': '필드 없음',
                 'read_error': '읽기 실패', 'inconsistent': '불일치', 'not_evaluated': '미평가'}


def display(value):
    return '<확인 불가>' if value is None else str(value)


def capability_text(member, field):
    value = member[field]
    if value is not None:
        return value or '<없음>'
    states = [item for item in member.get('observations', [])
              if item.get('source') == 'credentials' and item.get('feature') == field and item['status'] != 'ok']
    return '<' + STATUS_LABELS.get(states[0]['status'], states[0]['status']) + '>' if states else '<읽기 실패/미지원>'


def compatibility_summary(audit):
    """Count observed reader outcomes, not a claim about every kernel."""
    counts = {}
    for member in audit['members']:
        for observation in member.get('observations', []):
            key = (observation['source'], observation['feature'], observation['status'],
                   json.dumps(observation.get('layout'), sort_keys=True))
            entry = counts.setdefault(key, {'source': key[0], 'feature': key[1], 'status': key[2],
                                           'layout': observation.get('layout'), 'tasks': set(), 'reasons': set()})
            entry['tasks'].add(member['TID'])
            if observation.get('reason'):
                entry['reasons'].add(observation['reason'])
    return [dict(item, tasks=len(item['tasks']), reasons=sorted(item['reasons']))
            for _, item in sorted(counts.items())]


def select_members(audit, prefix='', leaders=False):
    # 저장할 때 제외한 스레드는 다시 표시할 수 없으므로 수집 범위를 먼저 확인한다.
    prefix = prefix.lower()
    if prefix and not re.fullmatch(r'[0-9a-f]{6,64}', prefix):
        raise ValueError('컨테이너 ID는 6~64자리 16진수로 입력하세요.')
    if not leaders and not audit['include_threads']:
        raise ValueError('이 저장 결과에는 스레드 전체가 없습니다. --leaders를 지정하거나 새로 분석하세요.')
    members = audit['members']
    ids = {m['ContainerID'] for m in members if m['ContainerID'].startswith(prefix)}
    if prefix and len(ids) > 1:
        raise ValueError('여러 컨테이너 ID가 일치합니다. ID를 더 길게 입력하세요.')
    return sorted((m for m in members if m['ContainerID'].startswith(prefix) and
                   (not leaders or m['PID'] == m['TID'])),
                  key=lambda m: (m['ContainerID'], m['ContainerRoot'], m['PID'], m['TID']))


def group_members(members):
    # member 한 개는 태스크(TID) 하나다. 그룹은 권한을 합산하지 않고 구성원 목록을 보관한다.
    groups = {}
    for member in members:
        key = (member['ContainerID'], member['ContainerRoot'])
        group = groups.setdefault(key, {
            'container_id': key[0], 'root_address': key[1],
            'container_path': member['ContainerPath'], 'members': [],
        })
        group['members'].append(member)
    for group in groups.values():
        group['process_comparison'] = compare_threads(group['members'])
    return list(groups.values())


def compare_threads(members):
    """Compare observed values, without claiming equivalent access outcomes."""
    result = []
    fields = CAPS + ('UserNS', 'EUID', 'UserEUID', 'NoNewPrivs', 'SeccompMode',
                     'SeccompFilters', 'Securebits', 'MountNS', 'NetNS')
    for pid in sorted({m['PID'] for m in members}):
        tasks = [m for m in members if m['PID'] == pid]
        different, unknown = [], []
        for field in fields:
            values = [m.get(field) for m in tasks]
            if any(value is None for value in values):
                unknown.append(field)
            if len({json.dumps(value, sort_keys=True) for value in values if value is not None}) > 1:
                different.append(field)
        for label, getter in (
            ('credential_ids', lambda m: complete_mapping(m.get('credentials', {}).get('ids_kernel'))),
            ('supplementary_groups', lambda m: m.get('credentials', {}).get('supplementary_gids_kernel')),
            ('seccomp_filter_chain', lambda m: m.get('seccomp', {}).get('filters')
             if m.get('seccomp', {}).get('chain_complete', True) else None),
            ('filesystem_root', lambda m: (m['mounts']['task_root_mount'], m['mounts']['task_root_dentry'])
             if m.get('mounts', {}).get('task_root_mount') is not None and m['mounts'].get('task_root_dentry') is not None else None),
        ):
            values = [getter(m) for m in tasks]
            if any(value is None for value in values):
                unknown.append(label)
            if len({json.dumps(value, sort_keys=True) for value in values if value is not None}) > 1:
                different.append(label)
        result.append({'pid': pid, 'observed_tids': [m['TID'] for m in tasks],
                       'different_observed_fields': different, 'unavailable_fields': unknown})
    return result


def complete_mapping(value):
    return value if value is not None and all(item is not None for item in value.values()) else None


def read_json(path):
    return json.loads(path.read_text(encoding='utf-8'))


def write_json(path, value):
    path.write_text(json.dumps(value, ensure_ascii=False, indent=2) + '\n', encoding='utf-8')


def run_analysis(args):
    # 래퍼는 항상 스레드까지 수집하고, --container/--leaders는 저장된 구성원의 표시만 거른다.
    # native 플러그인에 직접 --leaders를 주어 수집 범위를 줄이는 경우와 구별한다.
    dump = Path(args.dump).resolve(strict=True)
    symbols = Path(args.symbols).resolve(strict=True)
    if not dump.is_file() or not symbols.is_dir():
        raise ValueError('--dump는 파일, --symbols는 심볼 검색 디렉터리여야 합니다.')
    out = Path(args.output_root).resolve() / datetime.datetime.now(datetime.timezone.utc).strftime('%Y%m%dT%H%M%S.%fZ')
    out.mkdir(parents=True)
    # Use this Python's installation; never depend on a different `vol` on PATH.
    command = [sys.executable, '-X', 'utf8', str(Path(__file__).resolve()), '--volatility',
               '-q', '--offline', '-f', str(dump), '-s', str(symbols),
               '-p', str(BASE), '-o', str(out), '-r', 'json',
               'inspect-caps.ContainerCaps']
    manifest = {
        'wrapper_version': VERSION, 'volatility_version': importlib.metadata.version('volatility3'),
        'python_version': platform.python_version(), 'analysis_platform': platform.platform(),
        'command': command, 'dump': str(dump), 'dump_size': dump.stat().st_size,
        'dump_mtime_ns': dump.stat().st_mtime_ns, 'symbols_directory': str(symbols),
        # 수집기와 실행기가 같은 파일이므로 두 출처 모두 이 파일의 해시를 가리킨다.
        'plugin_sha256': {Path(__file__).name: hashlib.sha256(Path(__file__).read_bytes()).hexdigest()},
        'launcher_sha256': {Path(__file__).name: hashlib.sha256(Path(__file__).read_bytes()).hexdigest()},
    }
    print('메모리 덤프에서 컨테이너 소속과 권한을 읽는 중입니다. 수 분 걸릴 수 있습니다.', file=sys.stderr)
    # 표 렌더러의 rows.json과 플러그인의 감사 JSON을 분리한다. 재조회는 감사 JSON을 사용한다.
    with (out / 'rows.json').open('w', encoding='utf-8') as rows, (out / 'run.log').open('w', encoding='utf-8') as log:
        result = subprocess.run(command, stdout=rows, stderr=log)
    manifest['exit_code'] = result.returncode
    write_json(out / 'run-manifest.json', manifest)
    if result.returncode or not (out / 'containercaps-audit.json').is_file():
        raise RuntimeError(f'Volatility 실행을 완료하지 못했습니다. 로그: {out / "run.log"}')
    audit = read_json(out / 'containercaps-audit.json')
    write_json(out / 'containers.json', {'source': manifest, 'groups': group_members(audit['members'])})
    pointer = out.parent / 'latest.json'
    temporary = pointer.with_name(out.name + '.latest.tmp')
    # Relative pointer remains usable if the entire results directory is moved.
    write_json(temporary, {'directory': out.name})
    temporary.replace(pointer)
    return out


def main(argv=None):
    parser = argparse.ArgumentParser(description='Docker cgroup v2별 프로세스·스레드 capabilities 추출',
        epilog='공식 CLI: python inspect-caps.py --volatility -p . [Volatility 옵션] inspect-caps.ContainerCaps --view analyst')
    parser.add_argument('--version', action='version', version=VERSION)
    parser.add_argument('--container', default='', help='전체 Docker ID 또는 6자리 이상의 고유 접두사')
    parser.add_argument('--list', action='store_true', help='컨테이너별 구성원 수만 표시')
    parser.add_argument('--leaders', action='store_true', help='출력에서 프로세스 대표 스레드만 표시')
    parser.add_argument('--json', action='store_true', help='선택된 결과를 JSON으로 출력')
    parser.add_argument('--compatibility', action='store_true', help='이 분석에서 확인한 구조별 지원·관측 상태 표시')
    parser.add_argument('--view', choices=('summary', 'analyst', 'details'), default='summary', help='summary: 핵심 표(기본), analyst: 근거별 설명, details: 기존 전체 상세 보기')
    parser.add_argument('--saved', nargs='?', const='latest', metavar='DIRECTORY', help='재분석 없이 저장 결과 표시; 생략 시 최근 실행')
    parser.add_argument('--dump', default=os.environ.get('CAPS_DUMP'), help='분석할 Linux 메모리 덤프 파일')
    parser.add_argument('--symbols', default=os.environ.get('CAPS_SYMBOLS'), help='해당 커널의 심볼 검색 디렉터리 (linux/ 포함)')
    parser.add_argument('--output-root', default=str(Path.cwd() / 'container_caps_runs'), help='결과 저장 디렉터리')
    schema_options = parser.add_mutually_exclusive_group()
    schema_options.add_argument('--prepare-lab-schema', action='store_true', help='전용 venv의 Volatility 2.28.0에 실험 BTF 메타데이터 출처 허용')
    schema_options.add_argument('--restore-lab-schema', action='store_true', help='보존한 공식 원본 스키마로 복원')
    tokens = list(sys.argv[1:] if argv is None else argv)
    args = parser.parse_args(tokens)
    if args.prepare_lab_schema or args.restore_lab_schema:
        if len(tokens) != 1:
            parser.error('스키마 준비/원복 옵션은 분석·조회 옵션과 함께 사용하지 마세요.')
        path = installed_schema()
        print(prepare_schema(path, restore=args.restore_lab_schema))
        print(f'대상: {path}')
        return 0

    if args.container and not re.fullmatch(r'[0-9a-fA-F]{6,64}', args.container):
        parser.error('--container에는 6~64자리 16진수를 입력하세요.')
    if not args.saved and (not args.dump or not args.symbols):
        parser.error('새 분석에는 --dump와 --symbols가 필요합니다. CAPS_DUMP/CAPS_SYMBOLS로 지정할 수도 있습니다.')
    if args.saved and any(x.split('=', 1)[0] in ('--dump', '--symbols') for x in tokens):
        parser.error('--saved는 저장 결과를 읽습니다. 새 입력을 분석하려면 --saved를 빼세요.')
    if args.saved == 'latest':
        # 저장 조회는 기존 JSON만 읽는다. 현재 덤프를 다시 분석한 결과처럼 표시하지 않는다.
        root = Path(args.output_root).resolve()
        directory = root / read_json(root / 'latest.json')['directory']
    elif args.saved:
        directory = Path(args.saved).resolve(strict=True)
    else:
        directory = run_analysis(args)
    audit = read_json(directory / 'containercaps-audit.json')
    # 컨테이너 선택은 표시할 구성원만 제한한다. 오류·수집 범위는 전체 실행의 기록을 유지한다.
    groups = group_members(select_members(audit, args.container, args.leaders))
    errors = {k: audit[k] for k in ('membership_errors', 'field_errors', 'traversal_errors')}
    summary = {
        'saved_result': bool(args.saved), 'created_utc': audit['created_utc'],
        'directory': str(directory), 'enumerated_tasks': audit['enumerated_tasks'],
        'tasks_without_docker_marker': audit.get('tasks_without_docker_marker', audit.get('non_docker_tasks')),
        'discovered_docker_tasks': audit['discovered_docker_tasks'],
        'scope': audit['scope'], 'errors': errors, 'groups': groups,
        'thread_inventory': audit.get('thread_inventory', []),
        'plugin_version': audit.get('plugin_version'), 'kernel_banner': audit.get('kernel_banner'),
        'compatibility': audit.get('compatibility'), 'feature_status': compatibility_summary(audit),
        'partial_observations': audit.get('partial_observations', []),
        'not_evaluated': audit.get('not_evaluated', ['Permission context was not collected in this older result']),
    }
    if args.json:
        # CLI JSON은 선택한 구성원과 그룹 자료다. native --view analyst의 보고서와 형식이 다르다.
        print(json.dumps(summary, ensure_ascii=False, indent=2))
    elif args.compatibility:
        print(f"Container Caps {audit.get('plugin_version', '<과거 결과>')} | 저장된 분석의 구조별 관측")
        print('대상 커널: ' + display(audit.get('kernel_banner')))
        compatibility = audit.get('compatibility')
        if compatibility:
            print('소속 검사: ' + json.dumps(compatibility['membership'], ensure_ascii=False))
            print('PID 구조: ' + json.dumps(compatibility.get('pid_namespace'), ensure_ascii=False))
            for item in compatibility.get('security', []):
                print(f"  {item['feature']}: {STATUS_LABELS.get(item['status'], item['status'])} — {item.get('reason', '')}")
        else:
            print('이 과거 결과에는 구조별 지원 검사가 기록되지 않았습니다.')
        for item in summary['feature_status']:
            layout = ' | ' + str(item['layout']) if item['layout'] else ''
            print(f"  {item['source']}.{item['feature']}: {STATUS_LABELS.get(item['status'], item['status'])} | {item['tasks']}개 태스크{layout}")
            for reason in item['reasons']:
                print('    ' + reason)
        print(f'근거·원시 필드·로그: {directory}')
    elif args.view in ('summary', 'analyst') and not args.list:
        report = build_report(audit, [member for group in groups for member in group['members']])
        print('저장 결과 재표시' if args.saved else '새 메모리 분석 결과')
        print(format_summary(report) if args.view == 'summary' else
              format_report(report, shutil.get_terminal_size((112, 30)).columns), end='')
        print(f'\n상세·원시 바이트: {directory / "containercaps-audit.json"}')
        print('조회: --container <ID> | 상세 JSON: --json | 전체 설명: --view analyst')
    else:
        print(('저장 결과' if args.saved else '새 분석 결과') + f" | 분석 시각(UTC): {audit['created_utc']}")
        if audit.get('kernel_banner'):
            print(f"Container Caps {audit.get('plugin_version', '?')} | 커널: {audit['kernel_banner']}")
        print(f"열거한 태스크 {audit['enumerated_tasks']}개 | Docker 표식 소속 {audit['discovered_docker_tasks']}개 | 표시 컨테이너 {len(groups)}개")
        print('식별 기준: Docker cgroup v2 경로와 커널 연결 관계')
        for group in groups:
            members = group['members']
            print(f"\n컨테이너 {group['container_id']}\n  cgroup: {group['container_path']}\n  주소: {group['root_address']}")
            print(f"  표시 프로세스 {len({m['PID'] for m in members})}개 / 태스크 {len(members)}개")
            if args.list:
                continue
            for member in members:
                print(f"  PID {member['PID']} / TID {member['TID']} | {member['Name']} | 내부 PID {display(member['NSPID'])} / TID {display(member['NSTID'])} | EUID {display(member['EUID'])} | {member['Status']}")
                print(f"    PID namespace {display(member['PIDNS'])} | user namespace {display(member['UserNS'])}")
                if 'CapabilityScope' in member:
                    print(f"    권한 기준: {member['CredSource']} | 범위: {member['CapabilityScope']} | real_cred와 주소 다름: {display(member['CredsDiffer'])}")
                    print(f"    EUID: 커널 ID {display(member['EUID'])} / 해당 user namespace ID {display(member['UserEUID'])}")
                    print(f"    seccomp mode {display(member['SeccompMode'])} / filters {display(member['SeccompFilters'])} | no_new_privs {display(member['NoNewPrivs'])} | securebits {display(member['Securebits'])}")
                    if member.get('seccomp', {}).get('filter_count_source'):
                        print('    필터 개수 출처: ' + member['seccomp']['filter_count_source'])
                    print(f"    mount namespace {display(member['MountNS'])} | network namespace {display(member['NetNS'])}")
                    scope = member.get('credentials', {}).get('user_namespace') or {}
                    chain = scope.get('chain_leaf_to_initial', [])
                    if chain:
                        print('    user namespace 계층: ' + ' -> '.join(str(node['inum']) for node in chain))
                        for label in ('uid_map', 'gid_map'):
                            mapping = chain[0].get(label)
                            print('    ' + label + ' (namespace 시작 / 커널 ID 시작 / 개수): ' +
                                  ('<확인 불가>' if mapping is None else ', '.join(f"{e['namespace_first']}/{e['kernel_first']}/{e['count']}" for e in mapping)))
                    mounts = member.get('mounts')
                    if mounts is not None:
                        if mounts.get('entries') is not None:
                            print(f"    복원한 마운트 {len(mounts['entries'])}개 / 불완전 항목 {len(mounts.get('errors', []))}개 (경로·옵션은 상세 JSON)")
                for field in CAPS:
                    print(f"    {field}: " + capability_text(member, field))
                for item in member.get('observations', []):
                    if item['status'] != 'ok':
                        print(f"    관측 {item['source']}.{item['feature']}: {STATUS_LABELS.get(item['status'], item['status'])} — {item.get('reason', '')}")
            for comparison in group['process_comparison']:
                if comparison['different_observed_fields']:
                    print(f"  PID {comparison['pid']} 스레드 간 차이: " + ', '.join(comparison['different_observed_fields']))
        if not groups:
            print('선택 조건에 맞는 Docker 표식 소속을 찾지 못했습니다. 다른 런타임까지 부재를 뜻하지는 않습니다.')
        if any(errors.values()) or audit.get('partial_observations'):
            print('\n일부 관측이 불완전합니다. 오류 내용은 containercaps-audit.json을 확인하세요.')
        if audit.get('thread_inventory'):
            counts = audit['thread_inventory']
            print(f"\n스레드 수 교차 확인: {sum(item['count_matches'] is True for item in counts)}/{len(counts)} 프로세스에서 signal.nr_threads와 일치")
            unavailable = sum(item['count_matches'] is None for item in counts)
            if unavailable:
                print(f'교차 확인 불가: {unavailable}개 프로세스 (필드 없음·읽기 실패·대표 스레드만 수집한 결과 포함)')
        if audit.get('not_evaluated'):
            print('미평가: ' + '; '.join(audit['not_evaluated']))
            print('all은 해당 user namespace의 capability 집합을 뜻합니다. 호스트 파일 접근이나 seccomp/LSM 통과를 판정하지 않습니다.')
        print(f'\n근거·원시 필드·로그: {directory}')
    # Volatility가 정상 종료해도 일부 필드/순회 실패가 있으면 래퍼는 종료 코드 2로 알린다.
    return 2 if any(errors.values()) or audit.get('partial_observations') or any(m.get('Status') == 'partial' for m in audit['members']) else 0


# 3. 선택적 실험 스키마 준비: 원본 해시·백업을 확인하고 명시적으로만 실행

VOLATILITY_VERSION = "2.28.0"
# btf/symdb는 심볼 생성 출처의 이름이다. 허용해도 필드 오프셋·주소나 스키마 검증은 바꾸지 않는다.
STOCK_PATTERN = "^(dwarf|symtab|system-map)$"
LAB_PATTERN = "^(btf|symdb|dwarf|symtab|system-map)$"
# PyPI volatility3 2.28.0 wheel에 포함된 원본 스키마의 SHA-256이다.
# 예상과 다른 코어 수정 위에 패치를 겹쳐 적용하지 않는다.
STOCK_SHA256 = "39386442c722598f55213399b1bc603b49c7ecd43ecf58c2f110a97624da5246"
BACKUP_SUFFIX = ".containercaps-original"


def schema_state(raw: bytes) -> str:
    """알려진 원본 또는 아래 한 항목만 수정된 스키마인지 확인한다."""
    try:
        document = json.loads(raw)
        pattern = document["definitions"]["metadata_nix_item"]["properties"]["kind"][
            "pattern"
        ]
    except (ValueError, KeyError, TypeError) as exc:
        raise RuntimeError("예상한 metadata_nix_item.kind 스키마가 아닙니다.") from exc
    if pattern not in (STOCK_PATTERN, LAB_PATTERN):
        raise RuntimeError("예상과 다른 메타데이터 허용 패턴입니다. 수정하지 않았습니다.")
    if raw.count(pattern.encode("ascii")) != 1:
        raise RuntimeError("수정 대상 패턴이 정확히 한 곳에 있어야 합니다.")
    normalized = raw.replace(LAB_PATTERN.encode("ascii"), STOCK_PATTERN.encode("ascii"))
    if hashlib.sha256(normalized).hexdigest() != STOCK_SHA256:
        raise RuntimeError("공식 2.28.0 스키마와 다른 내용입니다. 수정하지 않았습니다.")
    return "stock" if pattern == STOCK_PATTERN else "prepared"


def installed_schema() -> Path:
    """시스템 Python 및 가상환경 밖의 editable 설치를 수정 대상에서 제외한다."""
    prefix = Path(sys.prefix).resolve()
    if prefix == Path(sys.base_prefix).resolve():
        raise RuntimeError("전용 가상환경(.venv)의 Python으로 실행하세요.")
    try:
        installed_version = importlib.metadata.version("volatility3")
    except importlib.metadata.PackageNotFoundError as exc:
        raise RuntimeError("이 가상환경에 volatility3==2.28.0을 설치하세요.") from exc
    if installed_version != VOLATILITY_VERSION:
        raise RuntimeError(f"Volatility {installed_version} 감지: 정확히 2.28.0만 지원합니다.")
    if importlib.util.find_spec("jsonschema") is None:
        raise RuntimeError("유효성 검사를 유지하려면 이 가상환경에 jsonschema를 설치하세요.")
    spec = importlib.util.find_spec("volatility3")
    if spec is None or spec.origin is None:
        raise RuntimeError("Volatility 설치 위치를 확인할 수 없습니다.")
    schema = (Path(spec.origin).parent / "schemas" / "schema-6.2.0.json").resolve()
    if not schema.is_relative_to(prefix):
        raise RuntimeError("스키마가 현재 가상환경 밖에 있습니다. editable 설치는 수정하지 않습니다.")
    if not schema.is_file():
        raise RuntimeError("설치된 schema-6.2.0.json을 찾을 수 없습니다.")
    return schema


def replace_atomically(path: Path, raw: bytes) -> None:
    """쓰기 도중 중단되어도 원본 스키마가 잘린 파일이 되지 않게 한다."""
    temp_path: Path | None = None
    try:
        with tempfile.NamedTemporaryFile(dir=path.parent, prefix=path.name + ".", delete=False) as temp:
            temp_path = Path(temp.name)
            temp.write(raw)
            temp.flush()
            os.fsync(temp.fileno())
        shutil.copymode(path, temp_path)
        temp_path.replace(path)
    finally:
        if temp_path is not None:
            temp_path.unlink(missing_ok=True)


def prepare_schema(path: Path, *, restore: bool = False) -> str:
    """원본 백업을 보존하며 멱등 적용하거나 정확한 원본으로 복원한다."""
    raw = path.read_bytes()
    state = schema_state(raw)
    backup = path.with_name(path.name + BACKUP_SUFFIX)
    if backup.exists():
        if schema_state(backup.read_bytes()) != "stock":
            raise RuntimeError("백업이 공식 원본과 다릅니다. 수정하지 않았습니다.")
    elif state == "prepared":
        raise RuntimeError("이미 수정된 스키마에 원본 백업이 없습니다. 자동 변경하지 않습니다.")
    elif not restore:
        # 기존 백업을 덮어쓰지 않는다. 새 백업 생성이 끝난 후에만 수정한다.
        with backup.open("xb") as stream:
            stream.write(raw)
            stream.flush()
            os.fsync(stream.fileno())
    if restore:
        if state == "stock":
            return "이미 공식 원본 상태입니다."
        replace_atomically(path, backup.read_bytes())
        return "공식 원본 스키마로 복원했습니다. 백업은 보존했습니다."
    if state == "prepared":
        return "이미 준비되어 있습니다. 스키마와 백업을 확인했습니다."
    modified = raw.replace(STOCK_PATTERN.encode("ascii"), LAB_PATTERN.encode("ascii"))
    if schema_state(modified) != "prepared":
        raise RuntimeError("수정 결과 검증에 실패했습니다.")
    replace_atomically(path, modified)
    return "btf/symdb 메타데이터 출처만 추가 허용했습니다. 유효성 검사는 유지합니다."


# 저장 결과 조회와 스키마 준비는 아래 커널 판독기를 불러오지 않는다.
# 따라서 --saved 조회에는 Volatility 설치가 필요 없다. 새 분석은 이 파일을
# --volatility로 다시 실행하여 공식 플러그인 탐색·심볼 자동 구성을 이용한다.
if __name__ == '__main__':
    try:
        sys.exit(main())
    except (OSError, ValueError, KeyError, RuntimeError, importlib.metadata.PackageNotFoundError) as exc:
        print(f'vcaps: {exc}', file=sys.stderr)
        sys.exit(1)


# 여기부터는 공식 Volatility가 이 파일을 플러그인 모듈로 import할 때 사용한다.
from volatility3.framework import exceptions, interfaces, objects, renderers
from volatility3.framework.configuration import requirements
from volatility3.framework.constants import linux
from volatility3.framework.objects import utility
from volatility3.plugins.linux import pslist, mountinfo



# 4. 심볼 구조 검사와 PID namespace 복원

# 커널 버전 문자열 대신 일치하는 ISF의 타입·멤버로 알려진 구조를 선택한다.
# 새 구조는 명시적으로 지원해야 하며, 심볼 제공만으로 모든 커널 호환이 보장되지는 않는다.


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


# 5. Docker cgroup v2 소속 복원

# 이름이 containerd-shim인 프로세스의 자식만 고르는 방식이 아니라, 각 태스크의
# cgroup v2 소속과 Docker 경로 표식을 확인한다. 표식은 런타임 신원 인증이 아니다.


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


# 6. Capability 원시 비트와 읽기 상태 판독

# 자체 구조 판독기다. 공식 Capabilities._decode_cap은 호출하지 않으며,
# Volatility의 Integer/Array 객체와 linux.CAPABILITIES 이름 목록만 재사용한다.


class UnsupportedLayout(ValueError):
    """The supplied symbol types do not describe a supported capability layout."""


def _observation(feature, status, reason, **details):
    return {'feature': feature, 'status': status, 'reason': reason, **details}


def _unsigned(value, width, cap, raw):
    if not isinstance(value, objects.Integer):
        raise UnsupportedLayout('Capability component is not a symbol-defined integer')
    fmt = value.vol.data_format
    if value.vol.size != width or fmt.length != width or fmt.signed:
        raise UnsupportedLayout(f'Capability component must be an unsigned {width * 8}-bit integer')
    if fmt.byteorder not in ('little', 'big'):
        raise UnsupportedLayout('Unknown integer byte order')
    relative = value.vol.offset - cap.vol.offset
    if value.vol.layer_name != cap.vol.layer_name or relative < 0 or relative + width > len(raw):
        raise ValueError('Capability component lies outside its recorded structure')
    result = int(value)
    if not 0 <= result < (1 << (width * 8)):
        raise ValueError('Capability integer exceeds its unsigned storage width')
    # 심볼 객체가 해석한 값과 보고서에 보존할 바이트가 같은 위치·값을 가리키는지 확인한다.
    if result != int.from_bytes(raw[relative:relative + width], fmt.byteorder, signed=False):
        raise ValueError('Capability value disagrees with the preserved raw bytes')
    return result


def _read_mask(cap, raw):
    has_val, has_cap = cap.has_member('val'), cap.has_member('cap')
    if has_val and has_cap:
        raise UnsupportedLayout('Ambiguous capability structure contains both val and cap')
    if has_val:
        return _unsigned(cap.member('val'), 8, cap, raw), 'val_u64'
    if not has_cap:
        raise UnsupportedLayout('Capability structure has neither val nor cap')
    value = cap.member('cap')
    if isinstance(value, objects.Array):
        count = len(value)
        if count not in (1, 2):
            raise UnsupportedLayout('Capability cap array must contain one or two u32 words')
        mask = 0
        for index, word in enumerate(value):
            # cap[0]은 하위 32비트다. 각 원소의 바이트 순서 해석은 _unsigned에서 끝난다.
            mask |= _unsigned(word, 4, cap, raw) << (32 * index)
        return mask, f'cap_u32_array_{count}'
    return _unsigned(value, 4, cap, raw), 'cap_u32_scalar'


def _kernel_range(module):
    # 보조 범위의 실패가 이미 읽은 capability 마스크·바이트를 무효화하지 않게 한다.
    # 타입 보완 근거는 범위 관측에만 남긴다. 정상적인 기존 타입은 덮어쓰지 않는다.
    details = {}
    try:
        if not module.has_symbol('cap_last_cap'):
            return None, None, _observation(
                'capability_kernel_range', 'not_present',
                'cap_last_cap symbol is absent; kernel capability range is unknown')
        if module.get_symbol('cap_last_cap').type is None:
            details = {'type_source': 'linux_int_fallback', 'object_type': 'int'}
            try:
                integer_type = module.get_type('int')
            except exceptions.SymbolError as exc:
                raise UnsupportedLayout('Untyped cap_last_cap requires an available int type: ' + str(exc)) from exc
            # Linux의 cap_last_cap은 int다. 현재 지원하는 x86-64의 signed 32-bit
            # 형식인지 먼저 확인하고, 주소·모듈 재배치는 Volatility API에 맡긴다.
            if (getattr(integer_type.vol, 'object_class', None) is not objects.Integer or
                    integer_type.size != 4 or
                    getattr(integer_type.vol, 'data_format', None) != objects.DataFormatInfo(4, 'little', True)):
                raise UnsupportedLayout('Untyped cap_last_cap requires a signed 32-bit little-endian int type')
            details['object_type'] = integer_type.vol.type_name
            # object_from_symbol은 'int' 문자열에 심볼 테이블명을 붙이지 않는다.
            # 현재 모듈에서 찾은 템플릿을 넘겨 같은 커널의 정수형을 사용한다.
            value = module.object_from_symbol('cap_last_cap', object_type=integer_type)
        else:
            value = module.object_from_symbol('cap_last_cap')
        if not isinstance(value, objects.Integer):
            return None, None, _observation(
                'capability_kernel_range', 'unsupported',
                'cap_last_cap is not a symbol-defined integer', **details)
        last = int(value)
        if last < 0:
            return None, None, _observation(
                'capability_kernel_range', 'inconsistent', 'cap_last_cap is negative', value=last, **details)
        if last > 63:
            return None, None, _observation(
                'capability_kernel_range', 'unsupported',
                'cap_last_cap exceeds the supported 64-bit capability representation', value=last, **details)
        return (1 << (last + 1)) - 1, last, _observation(
            'capability_kernel_range', 'ok', 'Kernel capability range read from cap_last_cap', value=last, **details)
    except UnsupportedLayout as exc:
        return None, None, _observation(
            'capability_kernel_range', 'unsupported', str(exc), **details)
    except exceptions.SymbolError as exc:
        return None, None, _observation(
            'capability_kernel_range', 'not_present', f'cap_last_cap is unavailable: {exc}', **details)
    except exceptions.InvalidAddressException as exc:
        return None, None, _observation(
            'capability_kernel_range', 'read_error', f'Cannot read cap_last_cap: {exc}', **details)
    except Exception as exc:
        # TypeError·ValueError·기타 보조 조회 실패도 범위만 미확인으로 남긴다.
        # 원시 capability 자체의 읽기/구조 검사는 이 예외 경계 밖에서 수행한다.
        return None, None, _observation(
            'capability_kernel_range', 'read_error',
            f'Cannot read cap_last_cap: {type(exc).__name__}: {exc}', **details)


def _bit_labels(mask):
    return [f'CAP_BIT_{bit}' for bit in range(mask.bit_length()) if mask & (1 << bit)]


def decode_capability(context, module, cap):
    """Return text, byte evidence and feature observations for one cap set.

    ``decoded_mask`` is restricted to the kernel's valid range when known. With
    no usable ``cap_last_cap``, it retains every stored bit and never claims
    ``all``. ``unknown_bits`` concerns the name dictionary; it can overlap with
    ``out_of_range_bits``. The latter is null when the kernel range is unknown.
    Core layout/read errors propagate so callers can report the affected set.
    """
    size = cap.vol.size
    if not isinstance(size, int) or not 1 <= size <= 64:
        raise UnsupportedLayout('Unsupported capability structure size')
    raw = context.layers[cap.vol.layer_name].read(cap.vol.offset, size, pad=False)
    if len(raw) != size:
        raise ValueError('Short read of capability structure')
    raw_mask, layout = _read_mask(cap, raw)
    # _kernel_range는 보조 관측이다. 실패해도 아래 원시 증거와 이름 해석은 계속한다.
    kernel_mask, last_cap, range_observation = _kernel_range(module)
    # 표시용 decoded_mask와 원래 저장된 raw_mask를 분리한다. 커널 범위 밖 비트나
    # 설치된 이름 목록에 없는 비트도 JSON에서 사라지지 않게 보존한다.
    decoded_mask = raw_mask if kernel_mask is None else raw_mask & kernel_mask
    known_mask = (1 << len(linux.CAPABILITIES)) - 1
    unknown_bits = raw_mask & ~known_mask
    out_of_range = None if kernel_mask is None else raw_mask & ~kernel_mask
    names = [
        linux.CAPABILITIES[bit] if bit < len(linux.CAPABILITIES) else f'CAP_BIT_{bit}'
        for bit in range(decoded_mask.bit_length()) if decoded_mask & (1 << bit)
    ]
    observations = [
        _observation('capability_layout', 'ok', 'Capability storage read and checked against raw bytes', layout=layout),
        range_observation,
    ]
    if unknown_bits:
        observations.append(_observation(
            'capability_names', 'unsupported', 'Stored bits have no name in the installed capability dictionary',
            bits=_bit_labels(unknown_bits)))
    if out_of_range:
        observations.append(_observation(
            'capability_value', 'inconsistent', 'Stored bits exceed the kernel cap_last_cap range',
            bits=_bit_labels(out_of_range)))
    text = ', '.join(names)
    # all은 확인된 커널 capability 범위의 모든 비트라는 뜻이며 호스트 접근 허용 판정이 아니다.
    if kernel_mask is not None and raw_mask == kernel_mask and not unknown_bits:
        text = 'all'
    if out_of_range:
        suffix = '[out_of_range: ' + ', '.join(_bit_labels(out_of_range)) + ']'
        text = (text + ' ' + suffix).lstrip()
    # text는 표시용, evidence는 재검증용 원시 값, observations는 해석의 지원·일관성 상태다.
    # 호출자는 빈 text(읽힌 권한 없음)와 판독 예외(읽지 못함)를 별도로 처리한다.
    return {
        'text': text,
        'evidence': {
            'virtual_address': hex(int(cap.vol.offset)), 'size': size,
            'bytes_hex': raw.hex(), 'decoded_mask': hex(decoded_mask), 'names': names,
            'raw_mask': hex(raw_mask), 'kernel_mask': None if kernel_mask is None else hex(kernel_mask),
            'kernel_last_cap': last_cap, 'unknown_bits': hex(unknown_bits),
            'out_of_range_bits': None if out_of_range is None else hex(out_of_range), 'layout': layout,
        },
        'observations': observations,
    }


# 7. Credential·user namespace·seccomp·마운트 보안 맥락

ID_FIELDS = ('uid', 'euid', 'suid', 'fsuid', 'gid', 'egid', 'sgid', 'fsgid')
SAFETY_ITEMS = 65536


class InconsistentData(ValueError):
    """Successfully read fields fail a structural consistency check."""


def observation(feature, status, reason, layout=None):
    value = {'feature': feature, 'status': status, 'reason': reason}
    if layout is not None:
        value['layout'] = layout
    return value


def member(obj, name):
    if not obj.has_member(name):
        raise UnsupportedLayout('Member ' + name + ' is absent from the symbols')
    return obj.member(name)


def capture(observations, feature, fn, layout=None):
    # 필드별 실패를 None과 상태로 남긴다. 실패를 0/빈 집합으로 바꾸거나 다른 성공값을 버리지 않는다.
    try:
        value = fn()
    except UnsupportedLayout as exc:
        observations.append(observation(feature, 'unsupported', str(exc), layout))
    except InconsistentData as exc:
        observations.append(observation(feature, 'inconsistent', str(exc), layout))
    except Exception as exc:
        observations.append(observation(feature, 'read_error', type(exc).__name__ + ': ' + str(exc), layout))
    else:
        observations.append(observation(feature, 'ok', 'Read from memory', layout))
        return value
    return None


def dereference(pointer, name):
    if not int(pointer):
        raise InconsistentData('Null ' + name + ' pointer')
    return pointer.dereference()


def kernel_id(value):
    return int(value.val) if hasattr(value, 'has_member') and value.has_member('val') else int(value)


def anonymous_member(obj, name, depth=0):
    if obj.has_member(name):
        return obj.member(name)
    if depth >= 8:
        raise InconsistentData('Anonymous member nesting exceeds safety limit')
    for key in obj.vol.members:
        if key.startswith('unnamed_member_'):
            try:
                return anonymous_member(obj.member(key), name, depth + 1)
            except UnsupportedLayout:
                pass
    raise UnsupportedLayout('Member ' + name + ' is absent from the symbols')


def map_kernel_id(extents, value):
    # cred에서 읽은 커널 ID를 해당 user namespace에서 보이는 ID로 변환한다.
    # kernel_first 구간에 대응하는 항목이 없으면 추정 ID 대신 None을 반환한다.
    matches = [e['namespace_first'] + value - e['kernel_first'] for e in extents
               if e['kernel_first'] <= value < e['kernel_first'] + e['count']]
    if len(matches) > 1:
        raise InconsistentData('Overlapping ID mappings')
    return matches[0] if matches else None


def read_id_map(idmap, module):
    count = int(anonymous_member(idmap, 'nr_extents'))
    if not 0 <= count <= SAFETY_ITEMS:
        raise InconsistentData('Invalid uid/gid map extent count or traversal safety limit exceeded')
    if count == 0:
        return []
    source = anonymous_member(idmap, 'extent')
    # 작은 매핑은 구조체 안의 extent, 큰 매핑은 forward가 가리키는 별도 배열에 저장된다.
    if count <= len(source):
        values = [source[i] for i in range(count)]
    else:
        pointer = anonymous_member(idmap, 'forward')
        if not int(pointer):
            raise InconsistentData('Null large ID map pointer')
        size = module.get_type('uid_gid_extent').size
        values = [module.object('uid_gid_extent', offset=int(pointer) + i * size, absolute=True) for i in range(count)]
    result = []
    for extent in values:
        first, lower, size = int(extent.first), int(extent.lower_first), int(extent.count)
        if first < 0 or lower < 0 or size <= 0 or first + size > 0xffffffff or lower + size > 0xffffffff:
            raise InconsistentData('Invalid uid/gid map extent')
        result.append({'namespace_first': first, 'kernel_first': lower, 'count': size})
    for field in ('namespace_first', 'kernel_first'):
        ordered = sorted(result, key=lambda item: item[field])
        if any(a[field] + a['count'] > b[field] for a, b in zip(ordered, ordered[1:])):
            raise InconsistentData('Overlapping uid/gid map extents')
    return result


def namespace_inum(namespace):
    if namespace.has_member('ns'):
        return int(member(namespace.ns, 'inum'))
    if namespace.has_member('proc_inum'):
        return int(namespace.proc_inum)
    raise UnsupportedLayout('Neither namespace.ns.inum nor namespace.proc_inum exists')


class SecurityReader:
    def __init__(self, context, module):
        self.context, self.module = context, module
        self.observations = []
        self.compatibility = self.observations
        self.ns_cache, self.mount_cache = {}, {}
        self.banner = capture(self.observations, 'kernel.banner', lambda: str(module.object_from_symbol('linux_banner').cast(
            'string', max_length=512, encoding='utf-8', errors='replace')).rstrip('\n'))
        self.initial_ns = None
        self.initial_address = None
        try:
            if not module.has_symbol('init_user_ns'):
                raise UnsupportedLayout('init_user_ns symbol is absent; scope cannot be anchored')
            self.initial_ns = module.object_from_symbol('init_user_ns')
            self.initial_address = int(self.initial_ns.vol.offset)
        except UnsupportedLayout as exc:
            self.observations.append(observation('user_namespace.initial', 'unsupported', str(exc)))
        except Exception as exc:
            self.observations.append(observation('user_namespace.initial', 'read_error', str(exc)))

    def raw(self, obj):
        return {'virtual_address': hex(int(obj.vol.offset)), 'size': obj.vol.size,
                'bytes_hex': self.context.layers[obj.vol.layer_name].read(obj.vol.offset, obj.vol.size, pad=False).hex()}

    def user_namespace(self, start):
        address = int(start.vol.offset)
        if address in self.ns_cache:
            return self.ns_cache[address]
        observations = []
        result = {'scope': 'unknown', 'chain_leaf_to_initial': [], 'initial_address': None,
                  'initial_inum': None, 'observations': observations}
        if self.initial_address is not None:
            result['initial_address'] = hex(self.initial_address)
            result['initial_inum'] = capture(observations, 'user_namespace.initial_inum', lambda: namespace_inum(self.initial_ns))
        else:
            observations.append(observation('user_namespace.scope', 'unsupported', 'init_user_ns unavailable; root cannot be authenticated'))
        current, seen, previous_level = start, set(), None
        chain_complete = False
        while current is not None:
            try:
                key = int(current.vol.offset)
                if key in seen or len(seen) >= 33:
                    raise InconsistentData('Invalid/oversized user namespace parent chain')
                seen.add(key)
                node = {'address': hex(key), 'inum': None, 'level': None, 'owner_kernel_uid': None,
                        'group_kernel_gid': None, 'uid_map': None, 'gid_map': None}
                # 필드 판독 전에 노드를 넣어 이후 오류가 나도 도달한 주소와 부분 관측을 남긴다.
                result['chain_leaf_to_initial'].append(node)
                feature = 'user_namespace.' + hex(key)
                node['inum'] = capture(observations, feature + '.inum', lambda: namespace_inum(current))
                for field, output in (('owner', 'owner_kernel_uid'), ('group', 'group_kernel_gid')):
                    node[output] = capture(observations, feature + '.' + field, lambda field=field: kernel_id(member(current, field)))
                for field in ('uid_map', 'gid_map'):
                    node[field] = capture(observations, feature + '.' + field,
                                          lambda field=field: read_id_map(member(current, field), self.module))
                level = int(member(current, 'level'))
                node['level'] = level
                if not 0 <= level <= 32 or (previous_level is not None and level != previous_level - 1):
                    raise InconsistentData('Inconsistent user namespace levels')
                previous_level = level
                pointer = member(current, 'parent')
                if not int(pointer):
                    if self.initial_address is not None and (key != self.initial_address or level != 0):
                        raise InconsistentData('User namespace chain does not reach init_user_ns')
                    chain_complete = True
                    break
                current = pointer.dereference()
            except UnsupportedLayout as exc:
                observations.append(observation('user_namespace.parent_chain', 'unsupported', str(exc)))
                break
            except InconsistentData as exc:
                observations.append(observation('user_namespace.parent_chain', 'inconsistent', str(exc)))
                break
            except Exception as exc:
                observations.append(observation('user_namespace.parent_chain', 'read_error', str(exc)))
                break
        if chain_complete and self.initial_address is not None:
            # user namespace 적용 범위는 init_user_ns까지의 주소·부모·level 연결로 확인한다.
            # EUID 0이나 namespace 번호만으로 초기 namespace라고 추정하지 않는다.
            result['scope'] = 'initial_user_namespace' if address == self.initial_address else 'descendant_user_namespace'
            observations.append(observation('user_namespace.scope', 'ok', 'Parent and level chain reaches init_user_ns'))
        if result['scope'] != 'unknown' and all(x['status'] == 'ok' for x in observations):
            self.ns_cache[address] = result
        return result

    def credentials(self, cred):
        # 입력은 역참조된 cred 객체다. 현재 cred인지 real_cred인지는 호출자가 구분하며,
        # 여기서는 각 객체를 독립적으로 읽어 두 자격 증명의 관측이 서로 덮어쓰이지 않게 한다.
        observations = []
        result = {'address': hex(int(cred.vol.offset)), 'ids_kernel': {}, 'ids_in_user_namespace': {},
                  'capability_evidence': {}, 'capabilities': {}, 'securebits': None,
                  'security_blob_address': None, 'lsm_policy': 'not_evaluated', 'observations': observations}
        for name in ID_FIELDS:
            result['ids_kernel'][name] = capture(observations, 'credentials.' + name, lambda name=name: kernel_id(member(cred, name)))
        result['securebits'] = capture(observations, 'credentials.securebits', lambda: int(member(cred, 'securebits')))
        result['security_blob_address'] = capture(observations, 'credentials.security_blob', lambda: hex(int(member(cred, 'security'))))
        for name in CAP_FIELDS:
            result['capabilities'][name] = None
            result['capability_evidence'][name] = None
            field = 'cap_bset' if name == 'cap_bounding' else name
            try:
                if not cred.has_member(field):
                    observations.append(observation(name, 'not_present', 'Credential member ' + field + ' is absent from the symbols'))
                    continue
                decoded = decode_capability(self.context, self.module, cred.member(field))
            except UnsupportedLayout as exc:
                observations.append(observation(name, 'unsupported', str(exc)))
            except ValueError as exc:
                observations.append(observation(name, 'inconsistent', str(exc)))
            except Exception as exc:
                observations.append(observation(name, 'read_error', type(exc).__name__ + ': ' + str(exc)))
            else:
                result['capabilities'][name] = decoded['text']
                result['capability_evidence'][name] = decoded['evidence']
                observations.append(observation(name, 'ok', 'Capability read from memory', decoded['evidence'].get('layout')))
                for item in decoded.get('observations', []):
                    observations.append({**item, 'feature': item['feature'] + '.' + name})
        return result

    def _array_values(self, source, count):
        if len(source) >= count:
            return [source[index] for index in range(count)]
        if self.module is None or not hasattr(source, 'vol') or not hasattr(source.vol, 'subtype'):
            raise UnsupportedLayout('Flexible-array subtype metadata unavailable')
        expanded = self.module.object('array', offset=int(source.vol.offset), absolute=True,
                                      subtype=source.vol.subtype, count=count)
        return list(expanded)

    def supplementary_groups(self, groups):
        count = int(member(groups, 'ngroups'))
        if not 0 <= count <= SAFETY_ITEMS:
            raise InconsistentData('Invalid supplementary group count or safety limit exceeded')
        if count == 0:
            return [], 'empty'
        if groups.has_member('gid'):
            return [kernel_id(x) for x in self._array_values(groups.gid, count)], 'group_info.gid'
        if groups.has_member('small_block') and groups.has_member('blocks'):
            small = groups.small_block
            if count <= len(small):
                return [kernel_id(small[index]) for index in range(count)], 'group_info.small_block'
            if not hasattr(small, 'vol') or not hasattr(small.vol, 'subtype'):
                raise UnsupportedLayout('Legacy group element type unavailable')
            subtype = small.vol.subtype
            item_size = int(subtype.size)
            layer = self.context.layers[self.module.layer_name]
            page_size = getattr(layer, 'page_size', None)
            if page_size is None or item_size <= 0 or int(page_size) % item_size:
                raise UnsupportedLayout('Legacy group block page/element size unavailable')
            per_block = int(page_size) // item_size
            needed = (count + per_block - 1) // per_block
            blocks = int(member(groups, 'nblocks'))
            if not needed <= blocks <= SAFETY_ITEMS:
                raise InconsistentData('Legacy group block count cannot hold ngroups')
            pointers = self._array_values(groups.blocks, needed)
            values = []
            for pointer in pointers:
                if not int(pointer):
                    raise InconsistentData('Null legacy supplementary group block')
                size = min(per_block, count - len(values))
                block = self.module.object('array', offset=int(pointer), absolute=True, subtype=subtype, count=size)
                values.extend(kernel_id(value) for value in block)
            return values, 'group_info.blocks'
        raise UnsupportedLayout('Neither contiguous gid nor small_block/blocks layout exists')

    def enrich_identity(self, result, cred):
        # credentials()의 결과에 ID 적용 범위를 덧붙인다. CAPS 판독 성공 여부와는 독립적이다.
        observations = result.setdefault('observations', [])
        result['user_namespace'] = {'scope': 'unknown', 'chain_leaf_to_initial': [], 'observations': []}
        scope = capture(observations, 'credentials.user_namespace', lambda: self.user_namespace(dereference(member(cred, 'user_ns'), 'user namespace')))
        if scope is not None:
            result['user_namespace'] = scope
            observations.extend(scope['observations'])
        chain = result['user_namespace']['chain_leaf_to_initial']
        # 체인의 첫 노드가 이 cred의 user namespace이므로 해당 노드의 ID 매핑을 사용한다.
        leaf = chain[0] if chain else {}
        for name, value in result['ids_kernel'].items():
            mappings = leaf.get('uid_map' if 'uid' in name else 'gid_map')
            result['ids_in_user_namespace'][name] = None
            if value is not None and mappings is not None:
                result['ids_in_user_namespace'][name] = capture(observations, 'credentials.mapped_' + name,
                                                               lambda mappings=mappings, value=value: map_kernel_id(mappings, value))
        result['supplementary_gids_kernel'] = None
        result['supplementary_gids_in_user_namespace'] = None
        groups = capture(observations, 'credentials.supplementary_groups', lambda: self.supplementary_groups(
            dereference(member(cred, 'group_info'), 'group_info')))
        if groups is not None:
            gids, layout = groups
            result['supplementary_gids_kernel'] = gids
            observations[-1]['layout'] = layout
            if leaf.get('gid_map') is not None:
                result['supplementary_gids_in_user_namespace'] = capture(observations, 'credentials.mapped_groups',
                    lambda: [map_kernel_id(leaf['gid_map'], value) for value in gids])

    def seccomp(self, task):
        # 모드·선언 개수·필터 연결을 관측한다. BPF 명령을 평가해 syscall 허용 여부를 계산하지 않는다.
        observations = []
        result = {'mode': None, 'mode_name': None, 'filter_count': None, 'declared_filter_count': None,
                  'observed_filter_count': None, 'filter_count_source': None, 'filter_count_cross_checked': False,
                  'filters': [], 'chain_complete': False, 'rules_evaluated': False, 'no_new_privs': None,
                  'atomic_flags': None, 'observations': observations}
        if task.has_member('no_new_privs'):
            result['no_new_privs'] = capture(observations, 'no_new_privs', lambda: bool(int(task.no_new_privs)), 'task.no_new_privs')
        elif task.has_member('atomic_flags'):
            flags = capture(observations, 'no_new_privs', lambda: int(task.atomic_flags), 'task.atomic_flags/PFA_NO_NEW_PRIVS=0')
            if flags is not None:
                result['no_new_privs'] = bool(flags & 1)
                raw = capture(observations, 'no_new_privs.raw', lambda: self.raw(task.atomic_flags))
                result['atomic_flags'] = {**(raw or {}), 'no_new_privs_bit': 0,
                    'rule_source': 'Linux include/linux/sched.h PFA_NO_NEW_PRIVS bit 0 (verified through Linux 7.0); future semantics not inferred'}
        else:
            observations.append(observation('no_new_privs', 'unsupported', 'No supported no_new_privs storage member'))
        seccomp = capture(observations, 'seccomp.structure', lambda: member(task, 'seccomp'))
        if seccomp is None:
            return result
        def read_mode():
            value = int(member(seccomp, 'mode'))
            if value not in (0, 1, 2):
                raise InconsistentData('Unknown seccomp mode value: ' + str(value))
            return value
        result['mode'] = capture(observations, 'seccomp.mode', read_mode)
        if result['mode'] is not None:
            result['mode_name'] = ('disabled', 'strict', 'filter')[result['mode']]
        def read_count():
            field = member(seccomp, 'filter_count')
            value = int(field.counter) if hasattr(field, 'has_member') and field.has_member('counter') else int(field)
            if not 0 <= value <= SAFETY_ITEMS:
                raise InconsistentData('Invalid seccomp filter count or safety limit exceeded')
            return value
        declared = capture(observations, 'seccomp.filter_count', read_count)
        result['declared_filter_count'] = declared
        if declared is not None:
            result['filter_count'], result['filter_count_source'] = declared, 'seccomp.filter_count'
        def walk_filters():
            pointer, seen = member(seccomp, 'filter'), set()
            while int(pointer):
                key = int(pointer)
                if key in seen or len(seen) >= 4096:
                    raise InconsistentData('Invalid/oversized seccomp filter chain')
                seen.add(key)
                item = pointer.dereference()
                record = {'address': hex(key), 'program_address': None, 'log': None}
                result['filters'].append(record)
                record['program_address'] = capture(observations, 'seccomp.filter.' + hex(key) + '.prog', lambda: hex(int(member(item, 'prog'))))
                record['log'] = capture(observations, 'seccomp.filter.' + hex(key) + '.log', lambda: bool(int(member(item, 'log'))))
                pointer = member(item, 'prev')
            return len(seen)
        observed = capture(observations, 'seccomp.filter_chain', walk_filters)
        # 중간에 끊겨도 도달한 필터 수는 남긴다. 실제 전체 개수로 쓸 수 있는지는 chain_complete로 구분한다.
        result['observed_filter_count'] = len(result['filters'])
        result['chain_complete'] = observed is not None
        if observed is not None:
            if declared is None:
                # 선언 필드가 없을 때는 끝까지 읽은 체인의 길이만 대체 개수로 사용한다.
                result['filter_count'], result['filter_count_source'] = observed, 'complete_filter_chain'
            else:
                result['filter_count_cross_checked'] = observed == declared
                if observed != declared:
                    observations.append(observation('seccomp.filter_consistency', 'inconsistent', 'Declared count and observed filter chain disagree'))
            if result['mode'] is not None and ((result['mode'] == 2 and observed == 0) or (result['mode'] != 2 and observed != 0)):
                observations.append(observation('seccomp.mode_consistency', 'inconsistent', 'Seccomp mode and observed filter chain disagree'))
        return result

    def resource_namespaces(self, task):
        observations = []
        result = {'observations': observations}
        proxy = capture(observations, 'resource_namespaces.nsproxy', lambda: dereference(member(task, 'nsproxy'), 'nsproxy'))
        for name, field in (('mount', 'mnt_ns'), ('network', 'net_ns'), ('ipc', 'ipc_ns'), ('uts', 'uts_ns'), ('cgroup', 'cgroup_ns')):
            record = {'address': None, 'inum': None, 'owner_user_namespace_address': None, 'owner_user_namespace_inum': None}
            result[name] = record
            if proxy is None:
                continue
            namespace = capture(observations, 'namespace.' + name, lambda field=field: dereference(member(proxy, field), field))
            if namespace is None:
                continue
            record['address'] = hex(int(namespace.vol.offset))
            record['inum'] = capture(observations, 'namespace.' + name + '.inum', lambda: namespace_inum(namespace))
            owner = capture(observations, 'namespace.' + name + '.owner', lambda: dereference(member(namespace, 'user_ns'), 'namespace owner'))
            if owner is not None:
                record['owner_user_namespace_address'] = hex(int(owner.vol.offset))
                record['owner_user_namespace_inum'] = capture(observations, 'namespace.' + name + '.owner_inum', lambda: namespace_inum(owner))
        return result

    def mounts(self, task):
        observations = []
        result = {'namespace_address': None, 'task_root_mount': None, 'task_root_dentry': None,
                  'entries': [], 'errors': [], 'file_access_policy_evaluated': False, 'observations': observations}
        namespace = capture(observations, 'mounts.namespace', lambda: dereference(member(dereference(member(task, 'nsproxy'), 'nsproxy'), 'mnt_ns'), 'mount namespace'))
        root = capture(observations, 'mounts.task_root', lambda: member(dereference(member(task, 'fs'), 'fs'), 'root'))
        if namespace is not None:
            result['namespace_address'] = hex(int(namespace.vol.offset))
        if root is not None:
            result['task_root_mount'] = capture(observations, 'mounts.root_mnt', lambda: hex(int(member(root, 'mnt'))))
            result['task_root_dentry'] = capture(observations, 'mounts.root_dentry', lambda: hex(int(member(root, 'dentry'))))
        if namespace is None:
            return result
        # 같은 mount namespace에서도 태스크의 root가 다르면 보이는 경로가 달라진다.
        # 따라서 캐시는 namespace와 root의 mount/dentry 주소가 모두 같은 경우에만 공유한다.
        key = (result['namespace_address'], result['task_root_mount'], result['task_root_dentry'])
        if all(key) and key in self.mount_cache:
            return self.mount_cache[key]
        def collect_mounts():
            if not hasattr(namespace, 'get_mount_points'):
                raise UnsupportedLayout('Volatility mount traversal extension unavailable')
            seen = set()
            # 순회와 경로/옵션 복원은 공식 mnt_namespace 확장·MountInfo API를 호출한다.
            # 이 마운트 정보만으로 특정 파일의 DAC/ACL·LSM 접근 허용까지 판정하지 않는다.
            for mnt in namespace.get_mount_points():
                address = int(mnt.vol.offset)
                if address in seen or len(seen) >= SAFETY_ITEMS:
                    raise InconsistentData('Invalid/oversized mount traversal')
                seen.add(address)
                record = capture(observations, 'mounts.entry.' + hex(address), lambda: mountinfo.MountInfo.get_mountinfo(mnt, task))
                if record is None:
                    result['errors'].append({'mount': hex(address), 'error': 'Mount entry unavailable; see observations'})
                else:
                    result['entries'].append({**record._asdict(), 'mount_address': hex(address)})
            return len(seen)
        capture(observations, 'mounts.traversal', collect_mounts)
        if all(key) and not result['errors'] and all(item['status'] == 'ok' for item in observations):
            self.mount_cache[key] = result
        return result


# 8. Volatility 플러그인: 태스크 열거, 수집, 감사 JSON과 표 출력

# 수집 순서: 전체 태스크 → Docker cgroup 소속 → 태스크별 보안 맥락 → 감사 JSON/표.
# 공식 PsList·MountInfo·렌더러 API를 사용하며, 원본 volatility-docker 코드를 복사하거나
# 공식 Capabilities 플러그인을 호출하지 않는다. 실제 덤프 검증 커널은 7.0.0-31-generic이다.


LOG = logging.getLogger(__name__)


class ContainerCaps(interfaces.plugins.PluginInterface):
    """Group Docker cgroup-v2 tasks and extract their capabilities."""
    _required_framework_version = (2, 13, 0)
    _version = (1, 4, 1)

    @classmethod
    def get_requirements(cls):
        # pslist/mountinfo의 version은 각 플러그인 API 버전이며 pip 패키지 버전과 구별한다.
        return [
            requirements.ModuleRequirement(name='kernel', description='Linux x86-64 kernel with matching symbols and cgroup v2', architectures=['Intel64']),
            requirements.VersionRequirement(name='pslist', component=pslist.PsList, version=(4, 0, 0)),
            requirements.VersionRequirement(name='mountinfo', component=mountinfo.MountInfo, version=(1, 2, 4)),
            requirements.StringRequirement(name='container', description='Docker ID or unique hex prefix (6-64 characters)', optional=True),
            requirements.BooleanRequirement(name='leaders', description='Only process leaders; default includes threads', default=False, optional=True),
            requirements.ChoiceRequirement(name='view', description='Raw columns or evidence-based analyst report', choices=['raw', 'analyst'], default='raw', optional=True),
        ]

    def _pid_chain(self, task, module):
        return read_pid_chain(task, module)

    @staticmethod
    def _observations(member, audit, source, observations):
        """Preserve unavailable data separately from successful empty values."""
        # 태스크별 근거와 전체 실행의 품질 기록을 함께 갱신한다. partial은 악성 여부가 아니다.
        for observation in observations:
            entry = dict(observation, source=source)
            if entry in member['observations']:
                continue
            member['observations'].append(entry)
            if entry['status'] != 'ok':
                member['Status'] = 'partial'
                detail = dict(entry, tid=member['TID'])
                audit['partial_observations'].append(detail)
                if entry['status'] in ('read_error', 'inconsistent'):
                    audit['field_errors'].append({
                        'tid': member['TID'], 'stage': source + '.' + entry['feature'],
                        'error': entry.get('reason', entry['status']), 'status': entry['status'],
                    })

    @classmethod
    def _failure(cls, member, audit, feature, exc):
        status = ('unsupported' if isinstance(exc, (AttributeError, NotImplementedError, UnsupportedLayoutError, UnsupportedLayout))
                  else 'inconsistent' if isinstance(exc, ValueError) else 'read_error')
        cause = exc
        while cause is not None:
            if isinstance(cause, exceptions.InvalidAddressException):
                status = 'read_error'
                break
            cause = cause.__cause__
        cls._observations(member, audit, feature, [{
            'feature': feature, 'status': status, 'reason': str(exc),
            'exception': type(exc).__name__,
        }])

    def _collect_security(self, task, security, member, audit):
        # Current credentials remain usable if real_cred or an optional field fails.
        # 현재 권한의 출처는 task.cred이며 real_cred는 비교 근거로 별도 보존한다.
        # 주소 차이만으로 권한 상승 이력이나 악성 행위를 판정하지 않는다.
        cred = None
        real_cred = None
        try:
            if not int(task.cred):
                raise ValueError('task.cred is a null pointer')
            member['CredAddress'] = hex(int(task.cred))
            cred = task.cred.dereference()
        except Exception as exc:
            self._failure(member, audit, 'credential_pointer', exc)
        try:
            if not int(task.real_cred):
                raise ValueError('task.real_cred is a null pointer')
            member['RealCredAddress'] = hex(int(task.real_cred))
            real_cred = task.real_cred.dereference()
            if cred is not None:
                member['CredsDiffer'] = int(task.cred) != int(task.real_cred)
        except Exception as exc:
            self._failure(member, audit, 'real_credential_pointer', exc)
        for source, pointer in (('credentials', cred), ('real_credentials', real_cred)):
            if pointer is None:
                continue
            if source == 'real_credentials' and member['CredsDiffer'] is False and 'credentials' in member:
                member[source] = member['credentials']
                continue
            try:
                member[source] = security.credentials(pointer)
                # Enrichment may fail without discarding the capabilities above.
                try:
                    security.enrich_identity(member[source], pointer)
                except Exception as exc:
                    self._failure(member, audit, source + '.identity', exc)
                self._observations(member, audit, source, member[source].get('observations', []))
            except Exception as exc:
                self._failure(member, audit, source, exc)
        current = member.get('credentials', {})
        member['EUID'] = current.get('ids_kernel', {}).get('euid')
        member['Securebits'] = current.get('securebits')
        member.update(current.get('capabilities', {}))
        member['capability_evidence'] = current.get('capability_evidence', {})
        scope = current.get('user_namespace') or {}
        member['CapabilityScope'] = scope.get('scope', 'unknown')
        chain = scope.get('chain_leaf_to_initial') or []
        if chain:
            member['UserNS'] = chain[0].get('inum')
        member['UserEUID'] = current.get('ids_in_user_namespace', {}).get('euid')
        for source, reader in (('seccomp', security.seccomp),
                               ('resource_namespaces', security.resource_namespaces),
                               ('mounts', security.mounts)):
            try:
                member[source] = reader(task)
                self._observations(member, audit, source, member[source].get('observations', []))
                if source == 'mounts' and member[source].get('errors'):
                    raise ValueError('Mount entries incomplete; see mounts.errors')
            except Exception as exc:
                self._failure(member, audit, source, exc)
        seccomp = member.get('seccomp', {})
        member['NoNewPrivs'] = seccomp.get('no_new_privs')
        member['SeccompMode'] = seccomp.get('mode')
        member['SeccompFilters'] = seccomp.get('filter_count')
        resources = member.get('resource_namespaces', {})
        member['MountNS'] = (resources.get('mount') or {}).get('inum')
        member['NetNS'] = (resources.get('network') or {}).get('inum')

    def _bytes(self, obj):
        layer = self.context.layers[obj.vol.layer_name]
        return {'virtual_address': hex(int(obj.vol.offset)), 'size': obj.vol.size,
                'bytes_hex': layer.read(obj.vol.offset, obj.vol.size, pad=False).hex()}

    def run(self):
        module = self.context.modules[self.config['kernel']]
        # 소속 복원에 필수인 cgroup 구조는 먼저 검사한다. 선택적인 PID/보안 필드는 부분 수집한다.
        resolver = CgroupV2Resolver(module)
        security = SecurityReader(self.context, module)
        try:
            pid_layout = inspect_pid_layout(module)
        except UnsupportedLayoutError as exc:
            pid_layout = exc.compatibility
        prefix = self.config.get('container', '') or ''
        if prefix and not re.fullmatch(r'[0-9a-fA-F]{6,64}', prefix):
            raise ValueError('Container prefix must be 6-64 hexadecimal characters')
        prefix = prefix.lower()
        # audit는 실행 전체, members의 각 항목은 태스크 하나의 값과 그 값을 읽은 근거다.
        audit = {
            'created_utc': datetime.datetime.now(datetime.timezone.utc).isoformat(),
            'plugin_version': '1.4.0', 'kernel_banner': security.banner,
            'compatibility': {
                'policy': 'matching symbols; structure-selected readers; cgroup v2 and Intel64',
                'membership': resolver.compatibility,
                'pid_namespace': pid_layout,
                'security': getattr(security, 'compatibility', {}),
            },
            'credential_source': 'task.cred (subjective); task.real_cred recorded separately',
            'method': 'task.cgroups -> css_set.dfl_cgrp -> cgroup CSS/kernfs parent chains',
            'scope': 'Docker-marked cgroup-v2 paths; no Docker registry reconstruction; no paused verdict',
            'include_threads': not self.config.get('leaders', False),
            'seen_task_addresses': [], 'seen_tids': [], 'tasks_without_docker_marker': 0,
            'membership_errors': [], 'field_errors': [], 'traversal_errors': [],
            'partial_observations': [],
            'containers': [], 'members': [],
            'thread_inventory': [],
            'not_evaluated': ['LSM policies', 'seccomp BPF rule outcomes', 'per-file DAC/ACL and idmapped-mount decisions'],
        }
        seen = set()
        found_groups = {}
        all_tids_by_pid = {}
        try:
            # 공식 열거 API를 직접 호출한다. 기본값은 스레드 포함이며, 이 목록 밖의
            # 은닉·연결 해제 태스크까지 복구했다고 주장할 수는 없다.
            tasks = pslist.PsList.list_tasks(self.context, self.config['kernel'], include_threads=audit['include_threads'])
            for task in tasks:
                address = int(task.vol.offset)
                if address in seen:
                    continue
                seen.add(address)
                # Linux task.pid는 개별 TID, task.tgid는 프로세스 PID다. 표의 PID/TID도 이 구분을 따른다.
                tid = int(task.pid)
                tgid = int(task.tgid)
                all_tids_by_pid.setdefault(tgid, set()).add(tid)
                audit['seen_task_addresses'].append(hex(address))
                audit['seen_tids'].append(tid)
                try:
                    cset, cgroup, chain, group = resolver.resolve(task)
                    key = int(cgroup.vol.offset)
                    if group is None:
                        audit['tasks_without_docker_marker'] += 1
                        continue
                except Exception as exc:
                    audit['membership_errors'].append({'pid': tgid, 'tid': tid, 'task': hex(address), 'error': str(exc)})
                    continue
                # 같은 ID 표식이라도 다른 cgroup 객체는 합치지 않는다.
                group_key = (group['id'], group['root_address'])
                found_groups[group_key] = group
                member = {
                    'ContainerID': group['id'], 'ContainerRoot': group['root_address'],
                    'ContainerPath': group['root_path'], 'CgroupPath': '/' + '/'.join(x['name'] for x in chain if x['name']),
                    'PID': tgid, 'TID': tid, 'Name': utility.array_to_string(task.comm),
                    'TaskAddress': hex(address), 'CssSetAddress': hex(int(cset.vol.offset)),
                    'CgroupAddress': hex(key), 'PIDNS': None, 'NSPID': None, 'NSTID': None,
                    'UserNS': None, 'EUID': None, 'Status': 'ok',
                    'UserEUID': None, 'CapabilityScope': 'unknown', 'CredSource': 'task.cred',
                    'CredsDiffer': None, 'NoNewPrivs': None, 'SeccompMode': None,
                    'SeccompFilters': None, 'Securebits': None, 'MountNS': None, 'NetNS': None,
                    'ExpectedThreads': None,
                    'cgroup_chain': chain, 'capability_evidence': {}, 'observations': [],
                }
                for field in CAP_FIELDS:
                    # 읽기 전 값은 미확인(None)이다. 읽기에 성공한 빈 권한 집합과 구별한다.
                    member[field] = None
                try:
                    pid_chain = self._pid_chain(task, module)
                    leader_chain = self._pid_chain(task.group_leader.dereference(), module)
                    member['pid_chain'] = pid_chain
                    member['PIDNS'] = pid_chain[-1]['namespace']
                    member['NSTID'] = pid_chain[-1]['id']
                    member['NSPID'] = next(x['id'] for x in leader_chain if x['namespace'] == member['PIDNS'])
                except Exception as exc:
                    self._failure(member, audit, 'pid_namespace', exc)
                else:
                    self._observations(member, audit, 'pid_namespace', [{'feature': 'pid_namespace', 'status': 'ok',
                        'layout': 'thread_pid' if task.has_member('thread_pid') else 'pids[PIDTYPE_PID]'}])
                self._collect_security(task, security, member, audit)
                try:
                    member['ExpectedThreads'] = int(task.signal.nr_threads)
                except Exception as exc:
                    self._failure(member, audit, 'thread_count', exc)
                audit['members'].append(member)
        except Exception as exc:
            audit['traversal_errors'].append(str(exc))

        ids = {key[0] for key in found_groups if key[0].startswith(prefix)}
        if prefix and len(ids) > 1:
            raise ValueError('Container prefix is ambiguous; supply more characters')
        selected = [m for m in audit['members'] if m['ContainerID'].startswith(prefix)]
        selected.sort(key=lambda m: (m['ContainerID'], m['ContainerRoot'], m['PID'], m['TID']))
        audit['containers'] = sorted(found_groups.values(), key=lambda g: (g['id'], g['root_address']))
        audit['selected_prefix'] = prefix
        audit['selected_tasks'] = len(selected)
        audit['selected_containers'] = len({(m['ContainerID'], m['ContainerRoot']) for m in selected})
        audit['enumerated_tasks'] = len(seen)
        audit['discovered_docker_tasks'] = len(audit['members'])
        # 같은 프로세스의 스레드가 다른 cgroup에 있을 수 있어 전체 열거 TID로 nr_threads를 대조한다.
        # 대표 스레드만 수집했거나 비교 근거가 모자라면 count_matches는 미확인(None)으로 남긴다.
        for pid in sorted({m['PID'] for m in audit['members']}):
            members = [m for m in audit['members'] if m['PID'] == pid]
            expected = {m['ExpectedThreads'] for m in members if m['ExpectedThreads'] is not None}
            observed = sorted(all_tids_by_pid[pid])
            can_compare = audit['include_threads'] and len(expected) == 1 and all(m['ExpectedThreads'] is not None for m in members)
            count_matches = len(observed) == next(iter(expected)) if can_compare else None
            audit['thread_inventory'].append({'pid': pid, 'observed_tids_all_cgroups': observed,
                                              'expected_counts': sorted(expected), 'count_matches': count_matches,
                                              'container_member_tids': sorted(m['TID'] for m in members)})
            if count_matches is False:
                for member in members:
                    self._observations(member, audit, 'thread_inventory', [{'feature': 'thread_coverage',
                        'status': 'inconsistent', 'reason': 'Observed TIDs and signal.nr_threads disagree'}])
        audit['coverage_complete_within_enumerated_tasks'] = not (audit['membership_errors'] or audit['traversal_errors'])
        # self.open은 Volatility 출력 디렉터리(-o)를 따른다. 화면을 줄여도 원시 근거는
        # 감사 JSON에 남기며, analyst JSON에는 집합 비교와 확인 항목을 추가한다.
        with self.open('containercaps-audit.json') as handle:
            handle.write(json.dumps(audit, ensure_ascii=False, indent=2).encode('utf-8'))
        if audit['membership_errors'] or audit['field_errors'] or audit['traversal_errors']:
            LOG.warning('ContainerCaps: incomplete observations; inspect containercaps-audit.json (%d membership, %d field, %d traversal errors)', len(audit['membership_errors']), len(audit['field_errors']), len(audit['traversal_errors']))
        if self.config.get('view', 'raw') == 'analyst':
            report = build_report(audit, selected)
            with self.open('containercaps-analyst.json') as handle:
                handle.write(json.dumps(report, ensure_ascii=False, indent=2).encode('utf-8'))
            return renderers.TreeGrid([(name, str) for name in SUMMARY_COLUMNS],
                                      ((0, row) for row in summary_rows(report)))
        columns = [('ContainerID', str), ('ContainerRoot', str), ('CgroupPath', str),
                   ('PID', int), ('TID', int), ('Name', str), ('NSPID', int), ('NSTID', int),
                   ('PIDNS', int), ('UserNS', int), ('EUID', int), ('UserEUID', int),
                   ('CapabilityScope', str), ('CredSource', str), ('CredsDiffer', bool),
                   ('NoNewPrivs', bool), ('SeccompMode', int), ('SeccompFilters', int),
                   ('Securebits', int), ('MountNS', int), ('NetNS', int), ('Status', str)] + [(x, str) for x in CAP_FIELDS]
        def generate():
            for member in selected:
                values = tuple(member[key] if member[key] is not None else renderers.NotAvailableValue() for key, _ in columns)
                yield 0, values
        return renderers.TreeGrid(columns, generate())

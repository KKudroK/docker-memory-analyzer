#!/usr/bin/env python3
"""Convenience CLI around the separate ContainerCaps Volatility plugin."""
import argparse
import datetime
import hashlib
import importlib.metadata
import json
import os
import platform
from pathlib import Path
import re
import shutil
import subprocess
import sys

BASE = Path(__file__).resolve().parent
VERSION = '1.4.0'
CAPS = ('cap_inheritable', 'cap_permitted', 'cap_effective', 'cap_bounding', 'cap_ambient')
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
    command = [sys.executable, '-X', 'utf8', str(BASE / 'run_volatility.py'),
               '-q', '--offline', '-f', str(dump), '-s', str(symbols),
               '-p', str(BASE / 'plugins'), '-o', str(out), '-r', 'json',
               'containercaps.ContainerCaps']
    manifest = {
        'wrapper_version': VERSION, 'volatility_version': importlib.metadata.version('volatility3'),
        'python_version': platform.python_version(), 'analysis_platform': platform.platform(),
        'command': command, 'dump': str(dump), 'dump_size': dump.stat().st_size,
        'dump_mtime_ns': dump.stat().st_mtime_ns, 'symbols_directory': str(symbols),
        'plugin_sha256': {str(p.relative_to(BASE)): hashlib.sha256(p.read_bytes()).hexdigest()
                          for p in sorted((BASE / 'plugins').rglob('*.py'))},
        'launcher_sha256': {p.name: hashlib.sha256(p.read_bytes()).hexdigest()
                            for p in (BASE / 'container_caps.py', BASE / 'run_volatility.py')},
    }
    print('메모리 덤프에서 컨테이너 소속과 권한을 읽는 중입니다. 수 분 걸릴 수 있습니다.', file=sys.stderr)
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
    parser = argparse.ArgumentParser(description='Docker cgroup v2별 프로세스·스레드 capabilities 추출')
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
    tokens = list(sys.argv[1:] if argv is None else argv)
    args = parser.parse_args(tokens)
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
        from plugins.container_support import analyst
        report = analyst.build_report(audit, [member for group in groups for member in group['members']])
        print('저장 결과 재표시' if args.saved else '새 메모리 분석 결과')
        print(analyst.format_summary(report) if args.view == 'summary' else
              analyst.format_report(report, shutil.get_terminal_size((112, 30)).columns), end='')
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


if __name__ == '__main__':
    try:
        sys.exit(main())
    except (OSError, ValueError, KeyError, RuntimeError, importlib.metadata.PackageNotFoundError) as exc:
        print(f'vcaps: {exc}', file=sys.stderr)
        sys.exit(1)

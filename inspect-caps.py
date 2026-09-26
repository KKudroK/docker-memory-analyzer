# 아래 import는 기능을 사용할 준비이며, 여기서 덤프 분석을 시작하지 않는다.
import argparse  # --dump, --symbols 등 터미널 옵션을 정의하고 해석한다.
import datetime  # 결과 생성 시각과 실행별 폴더 이름에 UTC 시간을 사용한다.
import hashlib  # 실행한 플러그인 소스의 SHA-256을 기록한다. 덤프 전체 해시는 아니다.
import importlib.metadata  # 설치된 volatility3 패키지 버전을 조회한다.
import json  # 분석 결과를 JSON으로 저장·출력하거나 저장된 JSON을 읽는다.
import logging  # 분석 중 발생한 부분 오류 등의 경고를 전달한다.
import multiprocessing  # Windows 실행 파일 패키징 환경을 위한 freeze_support()에 사용한다.
import os  # CAPS_DUMP·CAPS_SYMBOLS 환경 변수에서 기본 입력 경로를 읽는다.
import pathlib  # 덤프·심볼·결과 파일의 경로를 구성하고 파일을 읽고 쓴다.
import platform  # 분석을 실행하는 운영체제·Python 버전을 기록한다. 덤프 속 환경은 아니다.
import re  # 컨테이너 ID와 cgroup 이름이 정해진 문자열 형식인지 검사한다.
import subprocess  # 간편 명령에서 별도 Python 프로세스로 공식 Volatility 경로를 실행한다.
import sys  # 명령줄 인자·현재 Python 경로·오류 출력·프로그램 종료를 다룬다.
import unicodedata  # 제어문자를 분류하고 한글 등 문자의 터미널 표시 폭을 계산한다.

BASE = pathlib.Path(__file__).resolve().parent
# 버전은 여기서만 정의한다. CLI·Volatility 클래스·감사 JSON이 같은 값을 사용한다.
# 2.x marks the category/value TreeGrid output contract.
VERSION_INFO = (2, 0, 3)
VERSION = ".".join(map(str, VERSION_INFO))
# 실행 조건을 기록한다. 버전 번호 허용 목록이나 실제 검증 환경 목록이 아니다.
# 새 결과에만 저장하며, 과거 결과에 현재 정책을 소급해서 붙이지 않는다.
SUPPORT_POLICY = {
    "summary": "Ubuntu·커널 버전 번호로 제한하지 않고, 심볼 구조에 따라 분석합니다. 모든 커널의 완전한 분석을 보장하지 않습니다.",
    "requirements": "x86-64 Linux, 덤프와 일치하는 심볼, Volatility의 메모리 계층·태스크 열거 지원이 필요합니다.",
    "ubuntu_version_filter": False,
    "kernel_version_filter": False,
    "reader_selection": "symbol_structure",
    "architecture": "Intel64",
    "unknown_layout": "preserve_available_raw_evidence_and_mark_unknown",
    "all_kernels_guaranteed": False,
}
CAPS = (
    "cap_inheritable",
    "cap_permitted",
    "cap_effective",
    "cap_bounding",
    "cap_ambient",
)
CAP_FIELDS = CAPS
# 손상된 심볼의 거대 배열/정수로 인한 자원 소모를 제한한다. 커널 버전 제한은 아니다.
MAX_CAPABILITY_BYTES = 256

# --volatility는 첫 번째 옵션이다. 클래스 정의 전에 공식 CLI로 진입해야
# __main__과 정식 플러그인 모듈에 클래스가 이중 등록되는 것을 막는다.
# Windows에서 하위 프로세스가 시작될 때 CLI가 재귀 실행되지 않도록 보호한다.
if __name__ == "__main__" and sys.argv[1:2] == ["--volatility"]:
    multiprocessing.freeze_support()
    sys.argv = [sys.argv[0], *sys.argv[2:]]
    from volatility3 import cli  # 공식 CLI 진입 함수를 별칭으로 가져온다.

    cli.main()
    raise SystemExit(0)


# 1. 저장된 관측 자료의 해석과 터미널 표

REPORT_VERSION = "1.0"
REVIEW_CAPS = {
    "sys_admin": "시스템 관리 작업 범위",
    "sys_module": "커널 모듈 관련 작업",
    "sys_ptrace": "다른 프로세스 조사·접근 범위",
    "sys_rawio": "원시 I/O 접근 범위",
    "dac_read_search": "파일 읽기·디렉터리 검색 검사 우회 범위",
    "net_admin": "대상 network namespace의 네트워크 설정",
    "bpf": "특권 BPF 작업과 추가 권한·seccomp 조건",
    "perfmon": "성능 관측 작업과 대상 범위",
    "checkpoint_restore": "PID 설정·복원 관련 작업과 대상 범위",
}
STATUS = {
    "ok": "확인",
    "not_present": "필드 없음",
    "unsupported": "미지원",
    "read_error": "읽기 실패",
    "inconsistent": "불일치",
    "not_evaluated": "미평가",
}


def clean(value):
    """Render memory-sourced strings as data, including terminal controls."""
    if value is None:
        return "확인 불가"
    return "".join(
        c
        if not (
            unicodedata.category(c).startswith("C")
            or unicodedata.category(c) in ("Zl", "Zp")
        )
        else repr(c)[1:-1]
        for c in str(value)
    )


def clean_data(value):
    """Make a display-only copy; preserve original evidence and schema keys."""
    if isinstance(value, str):
        return clean(value)
    if isinstance(value, dict):
        return {key: clean_data(item) for key, item in value.items()}
    if isinstance(value, list):
        return [clean_data(item) for item in value]
    if isinstance(value, tuple):
        return tuple(clean_data(item) for item in value)
    return value


def global_observations(audit):
    """Read global evidence once, including compatibility-only older results."""
    if "global_observations" in audit:
        observations = audit["global_observations"]
    else:
        # 이전 파일을 다시 저장하거나 버전을 바꾸지 않고 기록된 전역 실패를 반영한다.
        observations = (audit.get("compatibility") or {}).get("security", [])
    result = []
    for item in observations if isinstance(observations, list) else []:
        entry = dict(item)
        entry.setdefault("source", "security")
        if entry not in result:
            result.append(entry)
    return result


def audit_quality(audit):
    """Shared counts for reports, native warnings and the convenience CLI exit."""
    counts = {
        key: len(audit.get(key) or [])
        for key in (
            "membership_errors",
            "field_errors",
            "traversal_errors",
            "partial_observations",
        )
    }
    issues = [item for item in global_observations(audit) if item["status"] != "ok"]
    # 전역 실패를 태스크마다 복제하지 않는다. 구성원 자체의 성공 상태도 유지한다.
    counts["global_errors"] = sum(
        item["status"] in ("read_error", "inconsistent") for item in issues
    )
    counts["global_partial_observations"] = len(issues)
    return counts


def quality_totals(quality):
    errors = sum(
        quality.get(key, 0)
        for key in (
            "membership_errors",
            "field_errors",
            "traversal_errors",
            "global_errors",
        )
    )
    partial = quality.get("partial_observations", 0) + quality.get(
        "global_partial_observations", 0
    )
    return errors, partial


def global_issue_text(observations):
    return "; ".join(
        clean(item["feature"]) + " " + clean(STATUS.get(item["status"], item["status"]))
        for item in observations
        if item["status"] != "ok"
    )


def number(value):
    try:
        if value is None or isinstance(value, bool):
            return None
        result = int(value, 0) if isinstance(value, str) else int(value)
        return (
            result
            if 0 <= result and result.bit_length() <= MAX_CAPABILITY_BYTES * 8
            else None
        )
    except (ValueError, TypeError, OverflowError):
        return None


def cap_entry(member, field):
    evidence = (member.get("capability_evidence") or {}).get(field) or {}
    # 과거 감사 파일의 권한 이름만으로 마스크를 역산하지 않는다. None은 미기록, 0은 빈 집합이다.
    mask = number(evidence.get("raw_mask"))
    names = evidence.get("names")
    value = member.get(field)
    if mask == 0:
        names = []
    elif not isinstance(names, list):
        names = (
            None
            if value is None or value == "all"
            else [s.strip() for s in value.split(",") if s.strip()]
        )
    if names is not None:
        names = [
            str(s).lower().removeprefix("cap_")
            if not str(s).startswith("CAP_BIT_")
            else str(s)
            for s in names
        ]
    states = [
        o
        for o in member.get("observations", [])
        if o.get("source") == "credentials"
        and o.get("feature") == field
        and o.get("status") != "ok"
    ]
    state = (
        STATUS.get(states[0]["status"], states[0]["status"])
        if states
        else "원시 마스크 미기록"
    )
    text = "없음" if mask == 0 else ", ".join(names) if names else clean(value)
    if mask is None:
        text = (clean(value) if value is not None else state) + " [마스크 확인 불가]"
    return {"mask": mask, "names": names, "text": text, "evidence": evidence}


def task_report(member):
    # 이름 문자열이 아닌 보존된 원시 마스크로 집합 차이를 계산한다. 미기록 값은 미확인이다.
    # Bounding은 exec 시 취득 제한이므로 E가 B 밖에 있다는 이유만으로 불일치로 분류하지 않는다.
    sets = {field: cap_entry(member, field) for field in CAPS}
    # 집합 관계 계산에는 I/P/E/A를 쓰며, Bounding 근거는 sets에 그대로 보존한다.
    i, p, e, _, a = (sets[field]["mask"] for field in CAPS)
    deltas = {
        "permitted_not_effective": p & ~e if p is not None and e is not None else None,
        "effective_not_permitted": e & ~p if e is not None and p is not None else None,
        "ambient_outside_pi": a & ~(p & i)
        if all(v is not None for v in (a, p, i))
        else None,
    }
    checks = []

    def add(code, kind, text):
        checks.append({"code": code, "kind": kind, "text": text})

    if e == 0:
        add(
            "EFFECTIVE_EMPTY",
            "관측",
            "현재 Effective 권한 없음. 일반 UID/GID 기반 접근은 별도.",
        )
    if deltas["permitted_not_effective"]:
        add(
            "PERMITTED_INACTIVE",
            "검토",
            "P-E="
            + hex(deltas["permitted_not_effective"])
            + ": 보유하지만 현재 비활성인 권한.",
        )
    if deltas["effective_not_permitted"]:
        add(
            "EFFECTIVE_OUTSIDE_PERMITTED",
            "일관성",
            "E-P="
            + hex(deltas["effective_not_permitted"])
            + ": 집합 관계 불일치. 원시 바이트·수집 일관성 확인.",
        )
    if deltas["ambient_outside_pi"]:
        add(
            "AMBIENT_OUTSIDE_PI",
            "일관성",
            "A-(P&I)="
            + hex(deltas["ambient_outside_pi"])
            + ": ambient 집합 관계 불일치 확인.",
        )
    if a:
        add("AMBIENT_PRESENT", "검토", "Ambient가 관측됨. exec 시 권한 전달 조건 확인.")
    for key, code in (
        ("unknown_bits", "UNKNOWN_BITS"),
        ("out_of_range_bits", "OUT_OF_RANGE_BITS"),
    ):
        affected = [
            field + "=" + hex(number(sets[field]["evidence"].get(key)))
            for field in CAPS
            if number(sets[field]["evidence"].get(key))
        ]
        if affected:
            add(
                code,
                "일관성",
                (
                    "이름 미상 비트: "
                    if key == "unknown_bits"
                    else "커널 유효 범위 밖 비트: "
                )
                + ", ".join(affected),
            )
    if any(sets[field]["mask"] is None for field in CAPS):
        add(
            "MASKS_UNAVAILABLE",
            "미확인",
            "일부 원시 마스크가 없어 집합 연산·전체 권한 여부를 확정하지 않음.",
        )
    names = sets["cap_effective"]["names"]
    review = [name for name in (names or []) if name in REVIEW_CAPS]
    if review:
        add(
            "CAP_REVIEW",
            "검토",
            "; ".join(name.upper() + ": " + REVIEW_CAPS[name] for name in review),
        )
    if member.get("CredsDiffer") is True:
        add(
            "CREDS_DIFFER",
            "검토",
            "task.cred와 real_cred 주소가 다름. 일시적 자격 증명 전환도 가능하며 상승 이력의 증거는 아님.",
        )
    current, real = (
        member.get("credentials") or {},
        member.get("real_credentials") or {},
    )
    diffs = []
    for field in CAPS:
        left = number(
            (current.get("capability_evidence", {}).get(field) or {}).get("raw_mask")
        )
        right = number(
            (real.get("capability_evidence", {}).get(field) or {}).get("raw_mask")
        )
        if left is not None and right is not None and left != right:
            diffs.append(field)
    if diffs:
        add(
            "CRED_VALUES_DIFFER",
            "검토",
            "현재/객관 자격 증명의 관측 마스크 차이: " + ", ".join(diffs),
        )
    if member.get("SeccompMode") == 0:
        add(
            "SECCOMP_OFF",
            "검토",
            "seccomp mode=0 관측. syscall 필터에 의한 제한은 비활성.",
        )
    bad = [o for o in member.get("observations", []) if o.get("status") != "ok"]
    if bad or member.get("Status") == "partial":
        detail = "; ".join(
            str(o.get("source"))
            + "."
            + str(o.get("feature"))
            + "="
            + STATUS.get(o.get("status"), str(o.get("status")))
            for o in bad
        )
        add("PARTIAL_DATA", "미확인", "부분 관측: " + (detail or "상세 감사 JSON 확인"))
    return {
        "pid": member["PID"],
        "tid": member["TID"],
        "name": member.get("Name"),
        "source": member,
        "sets": sets,
        "effective_names": names,
        "deltas": deltas,
        "checks": checks,
    }


def compare(tasks):
    # 동일 프로세스의 스레드도 권한·제한이 다를 수 있다. 관측 차이와 비교 불가를 따로 기록한다.
    # 필터 객체의 차이는 규칙별 동작 차이나 접근 성공의 증거로 해석하지 않는다.
    fields = CAPS + (
        "UserNS",
        "CapabilityScope",
        "EUID",
        "UserEUID",
        "NoNewPrivs",
        "SeccompMode",
        "SeccompFilters",
        "Securebits",
        "MountNS",
        "NetNS",
    )
    different, unknown = [], []
    for field in fields:
        values = [
            t["sets"][field]["mask"] if field in CAPS else t["source"].get(field)
            for t in tasks
        ]
        if any(
            v is None or (field == "CapabilityScope" and v == "unknown") for v in values
        ):
            unknown.append(field)
        # 일부 태스크가 미확인이어도 나머지 관측값끼리 차이가 있으면 두 상태를 함께 남긴다.
        if (
            len(
                {
                    json.dumps(v, sort_keys=True)
                    for v in values
                    if v is not None and v != "unknown"
                }
            )
            > 1
        ):
            different.append(field)

    def ids(m):
        value = (m.get("credentials") or {}).get("ids_kernel")
        return value if value and all(v is not None for v in value.values()) else None

    def filters(m):
        sec = m.get("seccomp") or {}
        return sec.get("filters") if sec.get("chain_complete") is True else None

    def root(m):
        mounts = m.get("mounts") or {}
        values = (mounts.get("task_root_mount"), mounts.get("task_root_dentry"))
        return values if all(v is not None for v in values) else None

    for field, getter in (
        ("credential_ids", ids),
        (
            "supplementary_groups",
            lambda m: (m.get("credentials") or {}).get("supplementary_gids_kernel"),
        ),
        ("seccomp_filter_chain", filters),
        ("filesystem_root", root),
    ):
        values = [getter(t["source"]) for t in tasks]
        if any(v is None for v in values):
            unknown.append(field)
        if len({json.dumps(v, sort_keys=True) for v in values if v is not None}) > 1:
            different.append(field)
    return {"different_fields": different, "unknown_fields": unknown}


def build_report(audit, members):
    # audit의 전체 수집 메타데이터와 선택된 members를 결합하며, source에 원래 관측값을 유지한다.
    grouped = {}
    for member in sorted(
        members,
        key=lambda m: (m["ContainerID"], m["ContainerRoot"], m["PID"], m["TID"]),
    ):
        # 같은 ID라도 cgroup 루트 객체가 다르면 별도 그룹으로 두어 근거가 다른 태스크를 섞지 않는다.
        key = (member["ContainerID"], member["ContainerRoot"])
        group = grouped.setdefault(
            key,
            {
                "container_id": key[0],
                "root_address": key[1],
                "path": member.get("ContainerPath"),
                "members": [],
            },
        )
        group["members"].append(task_report(member))
    groups = list(grouped.values())
    for index, group in enumerate(groups, 1):
        group["label"] = "C" + str(index)
        group["comparisons"] = [
            dict(pid=pid, **compare([t for t in group["members"] if t["pid"] == pid]))
            for pid in sorted({t["pid"] for t in group["members"]})
        ]
        group["member_comparison"] = compare(group["members"])
    return {
        "report_version": REPORT_VERSION,
        "plugin_version": audit.get("plugin_version"),
        "support_policy": audit.get("support_policy"),
        "created_utc": audit.get("created_utc"),
        "enumerated_tasks": audit.get("enumerated_tasks"),
        "discovered_docker_tasks": audit.get("discovered_docker_tasks"),
        "unmarked_tasks": audit.get(
            "tasks_without_docker_marker", audit.get("non_docker_tasks")
        ),
        "include_threads": audit.get("include_threads"),
        "quality": audit_quality(audit),
        "global_observations": global_observations(audit),
        "thread_inventory": audit.get("thread_inventory", []),
        "groups": groups,
        "unresolved_members": audit.get("unresolved_members", []),
        "unresolved_collected": "unresolved_members" in audit,
    }


SUMMARY_COLUMNS = (
    "Container",
    "PID/TID",
    "Name",
    "Effective",
    "UserNS",
    "Seccomp",
    "Check",
)


def summary_rows(report):
    """One row per observed task; full evidence stays in the JSON report."""
    # 표는 태스크마다 한 행으로 유지한다. Check는 조사할 근거의 요약이며 위험 점수가 아니다.
    ids = [g["container_id"] for g in report["groups"]]
    width = 12
    # 서로 다른 전체 ID의 접두사가 겹치면 구별될 때까지 표시 길이만 늘린다.
    while width < 64 and len({cid[:width] for cid in ids}) != len(set(ids)):
        width += 1
    for group in report["groups"]:
        duplicate = ids.count(group["container_id"]) > 1
        # 전체 ID가 같은 별도 루트 그룹은 /C번호로 구분하고, 실제 루트 주소는 상세 보고서에 둔다.
        identity = group["container_id"][:width] + (
            "/" + group["label"] if duplicate else ""
        )
        for task in group["members"]:
            member = task["source"]
            entry = task["sets"]["cap_effective"]
            names = entry["names"]
            if entry["mask"] is None:
                effective = "미확인"
            elif entry["mask"] == 0:
                effective = "없음"
            elif names and len(names) <= 2:
                effective = ",".join(name.upper() for name in names)
            else:
                effective = f"원시 {entry['mask'].bit_count()}비트"
            scope = {
                "initial_user_namespace": "초기",
                "descendant_user_namespace": "하위",
            }.get(member.get("CapabilityScope"), "미확인")
            seccomp = {
                0: "off",
                1: "strict",
                2: "filter/" + clean(member.get("SeccompFilters")),
            }.get(member.get("SeccompMode"), "미확인")
            codes = {c["code"] for c in task["checks"]}
            # 한 칸에는 아래 우선순위의 대표 항목을 표시한다. 생략된 checks도 상세 JSON에는 유지된다.
            if codes & {"PARTIAL_DATA", "MASKS_UNAVAILABLE"}:
                check = "부분/미확인"
            elif codes & {
                "EFFECTIVE_OUTSIDE_PERMITTED",
                "AMBIENT_OUTSIDE_PI",
                "UNKNOWN_BITS",
                "OUT_OF_RANGE_BITS",
            }:
                check = "비트·집합 확인"
            elif codes & {"CREDS_DIFFER", "CRED_VALUES_DIFFER"}:
                check = "cred 차이"
            elif codes & {"PERMITTED_INACTIVE", "AMBIENT_PRESENT"}:
                check = "권한 전이 검토"
            elif "SECCOMP_OFF" in codes:
                check = "필터 비활성"
            elif "CAP_REVIEW" in codes:
                check = "권한 검토"
            else:
                check = "-"
            comparison = next(
                c for c in group["comparisons"] if c["pid"] == task["pid"]
            )
            if comparison["different_fields"]:
                check = "스레드 차이" if check == "-" else check + " +차이"
            yield tuple(
                clean(v)
                for v in (
                    identity,
                    f"{task['pid']}/{task['tid']}",
                    task["name"],
                    effective,
                    scope,
                    seccomp,
                    check,
                )
            )


def unresolved_rows(report):
    # 표를 재사용하기 위한 표시 전용 묶음이다. 컨테이너 ID를 만들거나 groups에 저장하지 않는다.
    tasks = [task_report(member) for member in report.get("unresolved_members", [])]
    group = {
        "container_id": "소속 미확인",
        "label": "?",
        "members": tasks,
        "comparisons": [
            dict(pid=pid, **compare([t for t in tasks if t["pid"] == pid]))
            for pid in sorted({t["pid"] for t in tasks})
        ],
    }
    yield from summary_rows({"groups": [group]})


def format_summary(report, unresolved=False):
    table = list(unresolved_rows(report) if unresolved else summary_rows(report))
    headers = (
        "컨테이너",
        "PID/TID",
        "프로세스",
        "Effective",
        "UserNS",
        "seccomp",
        "확인",
    )
    widths = [
        max([cell_width(headers[i])] + [cell_width(row[i]) for row in table])
        for i in range(len(headers))
    ]

    def line(row):
        return "  ".join(
            text + " " * (width - cell_width(text)) for text, width in zip(row, widths)
        ).rstrip()

    q = report["quality"]
    errors, partial = quality_totals(q)
    output = [
        f"Container Caps {clean(report['plugin_version'])} | 컨테이너 {len(report['groups'])} · 표시 태스크 {len(table)} | 오류 {errors} · 부분 {partial}"
    ]
    if report.get("unresolved_members"):
        output.append(
            f"소속 미확인 태스크 {len(report['unresolved_members'])}개 별도 보존 · 조회: --unresolved / --json"
        )
    if unresolved:
        output.append(
            "소속 미확인 보기: 아래 태스크는 Docker 컨테이너 구성원으로 확인되지 않았습니다."
        )
    issues = global_issue_text(report.get("global_observations", []))
    if issues:
        output.append("전역 확인: " + issues)
    output.extend(["", line(headers), "-" * cell_width(line(headers))])
    output.extend(line(row) for row in table)
    if not table:
        output.append(
            (
                "소속 미확인 태스크 없음."
                if report.get("unresolved_collected")
                else "이 과거 결과에는 소속 미확인 태스크 수집 기록이 없습니다."
            )
            if unresolved
            else "선택 조건에 맞는 Docker 표식 구성원 없음."
        )
    output.extend(
        [
            "",
            "UserNS=권한 적용 범위. 확인 항목은 조사 대상이며 침해 판정이 아닙니다.",
            "권한 전체·집합 차이·NNP·주소·원시 바이트는 상세 JSON에 있습니다.",
        ]
    )
    return "\n".join(output) + "\n"


def cell_width(text):
    # 한글의 화면 폭과 결합 문자를 반영해 문자 수가 아닌 터미널 셀 수로 열을 맞춘다.
    return sum(
        0
        if unicodedata.combining(c)
        else 2
        if unicodedata.east_asian_width(c) in ("W", "F")
        else 1
        for c in text
    )


# 2. 사용자 CLI: 새 분석 또는 저장 결과 조회


def display(value):
    return "<확인 불가>" if value is None else clean(value)


def compatibility_summary(audit):
    """Count observed reader outcomes, not a claim about every kernel."""
    counts = {}
    for member in [*audit["members"], *audit.get("unresolved_members", [])]:
        for observation in member.get("observations", []):
            key = (
                observation["source"],
                observation["feature"],
                observation["status"],
                json.dumps(observation.get("layout"), sort_keys=True),
            )
            entry = counts.setdefault(
                key,
                {
                    "source": key[0],
                    "feature": key[1],
                    "status": key[2],
                    "layout": observation.get("layout"),
                    "tasks": set(),
                    "reasons": set(),
                },
            )
            entry["tasks"].add(member["TID"])
            if observation.get("reason"):
                entry["reasons"].add(observation["reason"])
    return [
        dict(item, tasks=len(item["tasks"]), reasons=sorted(item["reasons"]))
        for _, item in sorted(counts.items())
    ]


def select_members(audit, prefix="", leaders=False):
    # 저장할 때 제외한 스레드는 다시 표시할 수 없으므로 수집 범위를 먼저 확인한다.
    prefix = prefix.lower()
    if prefix and not re.fullmatch(r"[0-9a-f]{6,64}", prefix):
        raise ValueError("컨테이너 ID는 6~64자리 16진수로 입력하세요.")
    if not leaders and not audit["include_threads"]:
        raise ValueError(
            "이 저장 결과에는 스레드 전체가 없습니다. --leaders를 지정하거나 새로 분석하세요."
        )
    members = audit["members"]
    ids = {m["ContainerID"] for m in members if m["ContainerID"].startswith(prefix)}
    if prefix and len(ids) > 1:
        raise ValueError("여러 컨테이너 ID가 일치합니다. ID를 더 길게 입력하세요.")
    return sorted(
        (
            m
            for m in members
            if m["ContainerID"].startswith(prefix)
            and (not leaders or m["PID"] == m["TID"])
        ),
        key=lambda m: (m["ContainerID"], m["ContainerRoot"], m["PID"], m["TID"]),
    )


def group_members(members):
    # member 한 개는 태스크(TID) 하나다. 그룹은 권한을 합산하지 않고 구성원 목록을 보관한다.
    groups = {}
    for member in members:
        key = (member["ContainerID"], member["ContainerRoot"])
        group = groups.setdefault(
            key,
            {
                "container_id": key[0],
                "root_address": key[1],
                "container_path": member["ContainerPath"],
                "members": [],
            },
        )
        group["members"].append(member)
    for group in groups.values():
        group["process_comparison"] = compare_threads(group["members"])
    return list(groups.values())


def compare_threads(members):
    """Compare observed values, without claiming equivalent access outcomes."""
    result = []
    fields = CAPS + (
        "UserNS",
        "EUID",
        "UserEUID",
        "NoNewPrivs",
        "SeccompMode",
        "SeccompFilters",
        "Securebits",
        "MountNS",
        "NetNS",
    )
    for pid in sorted({m["PID"] for m in members}):
        tasks = [m for m in members if m["PID"] == pid]
        different, unknown = [], []
        for field in fields:
            values = [m.get(field) for m in tasks]
            if any(value is None for value in values):
                unknown.append(field)
            if (
                len(
                    {
                        json.dumps(value, sort_keys=True)
                        for value in values
                        if value is not None
                    }
                )
                > 1
            ):
                different.append(field)
        for label, getter in (
            (
                "credential_ids",
                lambda m: complete_mapping(m.get("credentials", {}).get("ids_kernel")),
            ),
            (
                "supplementary_groups",
                lambda m: m.get("credentials", {}).get("supplementary_gids_kernel"),
            ),
            (
                "seccomp_filter_chain",
                lambda m: (
                    m.get("seccomp", {}).get("filters")
                    if m.get("seccomp", {}).get("chain_complete", True)
                    else None
                ),
            ),
            (
                "filesystem_root",
                lambda m: (
                    (m["mounts"]["task_root_mount"], m["mounts"]["task_root_dentry"])
                    if m.get("mounts", {}).get("task_root_mount") is not None
                    and m["mounts"].get("task_root_dentry") is not None
                    else None
                ),
            ),
        ):
            values = [getter(m) for m in tasks]
            if any(value is None for value in values):
                unknown.append(label)
            if (
                len(
                    {
                        json.dumps(value, sort_keys=True)
                        for value in values
                        if value is not None
                    }
                )
                > 1
            ):
                different.append(label)
        result.append(
            {
                "pid": pid,
                "observed_tids": [m["TID"] for m in tasks],
                "different_observed_fields": different,
                "unavailable_fields": unknown,
            }
        )
    return result


def complete_mapping(value):
    return (
        value
        if value is not None and all(item is not None for item in value.values())
        else None
    )


def read_json(path):
    return json.loads(path.read_text(encoding="utf-8"))


def write_json(path, value):
    path.write_text(
        json.dumps(value, ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
    )


def run_analysis(args):
    # 래퍼는 항상 스레드까지 수집하고, --container/--leaders는 저장된 구성원의 표시만 거른다.
    # native 플러그인에 직접 --leaders를 주어 수집 범위를 줄이는 경우와 구별한다.
    dump = pathlib.Path(args.dump).resolve(strict=True)
    symbols = pathlib.Path(args.symbols).resolve(strict=True)
    if not dump.is_file() or not symbols.is_dir():
        raise ValueError("--dump는 파일, --symbols는 심볼 검색 디렉터리여야 합니다.")
    out = pathlib.Path(args.output_root).resolve() / datetime.datetime.now(
        datetime.timezone.utc
    ).strftime("%Y%m%dT%H%M%S.%fZ")
    out.mkdir(parents=True)
    # Use this Python's installation; never depend on a different `vol` on PATH.
    command = [
        sys.executable,
        "-X",
        "utf8",
        str(pathlib.Path(__file__).resolve()),
        "--volatility",
        "-q",
        "--offline",
        "-f",
        str(dump),
        "-s",
        str(symbols),
        "-p",
        str(BASE),
        "-o",
        str(out),
        "-r",
        "json",
        "inspect-caps.ContainerCaps",
    ]
    source_hash = {
        pathlib.Path(__file__).name: hashlib.sha256(
            pathlib.Path(__file__).read_bytes()
        ).hexdigest()
    }
    manifest = {
        "wrapper_version": VERSION,
        "volatility_version": importlib.metadata.version("volatility3"),
        "python_version": platform.python_version(),
        "analysis_platform": platform.platform(),
        "command": command,
        "dump": str(dump),
        "dump_size": dump.stat().st_size,
        "dump_mtime_ns": dump.stat().st_mtime_ns,
        "symbols_directory": str(symbols),
        # 수집기와 실행기가 같은 파일이므로 두 출처 모두 이 파일의 해시를 가리킨다.
        "plugin_sha256": source_hash,
        "launcher_sha256": source_hash,
    }
    print(
        "메모리 덤프에서 컨테이너 소속과 권한을 읽는 중입니다. 수 분 걸릴 수 있습니다.",
        file=sys.stderr,
    )
    # 표 렌더러의 rows.json과 플러그인의 감사 JSON을 분리한다. 재조회는 감사 JSON을 사용한다.
    with (
        (out / "rows.json").open("w", encoding="utf-8") as rows,
        (out / "run.log").open("w", encoding="utf-8") as log,
    ):
        result = subprocess.run(command, stdout=rows, stderr=log, check=False)
    manifest["exit_code"] = result.returncode
    write_json(out / "run-manifest.json", manifest)
    if result.returncode or not (out / "containercaps-audit.json").is_file():
        raise RuntimeError(
            f"Volatility 실행을 완료하지 못했습니다. 로그: {out / 'run.log'}"
        )
    read_json(out / "containercaps-audit.json")
    pointer = out.parent / "latest.json"
    temporary = pointer.with_name(out.name + ".latest.tmp")
    # Relative pointer remains usable if the entire results directory is moved.
    write_json(temporary, {"directory": out.name})
    temporary.replace(pointer)
    return out


def main(argv=None):
    parser = argparse.ArgumentParser(
        description="심볼 구조에 따른 Docker 태스크 capabilities 추출",
        epilog=SUPPORT_POLICY["summary"]
        + " "
        + SUPPORT_POLICY["requirements"]
        + " 공식 CLI: python inspect-caps.py --volatility -p . [Volatility 옵션] inspect-caps.ContainerCaps --view analyst",
    )
    parser.add_argument("--version", action="version", version=VERSION)
    parser.add_argument(
        "--container", default="", help="전체 Docker ID 또는 6자리 이상의 고유 접두사"
    )
    parser.add_argument(
        "--list", action="store_true", help="컨테이너별 구성원 수만 표시"
    )
    parser.add_argument(
        "--leaders", action="store_true", help="출력에서 프로세스 대표 스레드만 표시"
    )
    parser.add_argument(
        "--unresolved",
        action="store_true",
        help="컨테이너 소속을 확인하지 못한 태스크를 별도로 표시",
    )
    parser.add_argument(
        "--json", action="store_true", help="선택된 결과를 JSON으로 출력"
    )
    parser.add_argument(
        "--compatibility",
        action="store_true",
        help="이 분석에서 확인한 구조별 지원·관측 상태 표시",
    )
    parser.add_argument(
        "--saved",
        nargs="?",
        const="latest",
        metavar="DIRECTORY",
        help="재분석 없이 저장 결과 표시; 생략 시 최근 실행",
    )
    parser.add_argument(
        "--dump",
        default=os.environ.get("CAPS_DUMP"),
        help="분석할 Linux 메모리 덤프 파일",
    )
    parser.add_argument(
        "--symbols",
        default=os.environ.get("CAPS_SYMBOLS"),
        help="해당 커널의 심볼 검색 디렉터리 (linux/ 포함)",
    )
    parser.add_argument(
        "--output-root",
        default=str(pathlib.Path.cwd() / "container_caps_runs"),
        help="결과 저장 디렉터리",
    )
    tokens = list(sys.argv[1:] if argv is None else argv)
    args = parser.parse_args(tokens)
    if args.unresolved and (args.container or args.list):
        parser.error(
            "--unresolved는 --container 또는 --list와 함께 사용할 수 없습니다."
        )
    if args.container and not re.fullmatch(r"[0-9a-fA-F]{6,64}", args.container):
        parser.error("--container에는 6~64자리 16진수를 입력하세요.")
    if not args.saved and (not args.dump or not args.symbols):
        parser.error(
            "새 분석에는 --dump와 --symbols가 필요합니다. CAPS_DUMP/CAPS_SYMBOLS로 지정할 수도 있습니다."
        )
    if args.saved and any(
        x.split("=", 1)[0] in ("--dump", "--symbols") for x in tokens
    ):
        parser.error(
            "--saved는 저장 결과를 읽습니다. 새 입력을 분석하려면 --saved를 빼세요."
        )
    if args.saved == "latest":
        # 저장 조회는 기존 JSON만 읽는다. 현재 덤프를 다시 분석한 결과처럼 표시하지 않는다.
        root = pathlib.Path(args.output_root).resolve()
        directory = root / read_json(root / "latest.json")["directory"]
    elif args.saved:
        directory = pathlib.Path(args.saved).resolve(strict=True)
    else:
        directory = run_analysis(args)
    audit = read_json(directory / "containercaps-audit.json")
    # 컨테이너 선택은 표시할 구성원만 제한한다. 오류·수집 범위는 전체 실행의 기록을 유지한다.
    selected = select_members(audit, args.container, args.leaders)
    if args.unresolved:
        selected = []
    groups = group_members(selected)
    errors = {
        k: audit[k] for k in ("membership_errors", "field_errors", "traversal_errors")
    }
    quality = audit_quality(audit)
    # 종료 상태는 표시 필터나 이스케이프 처리 전에 전체 원본 관측으로 판단한다.
    exit_code = (
        2
        if any(quality.values())
        or audit.get("unresolved_members")
        or any(m.get("Status") == "partial" for m in audit["members"])
        else 0
    )
    # 미확인 소속은 ID 필터를 적용할 수 없다. 대표 스레드 표시만 독립적으로 적용한다.
    if args.leaders and "unresolved_members" in audit:
        audit = dict(
            audit,
            unresolved_members=[
                m for m in audit["unresolved_members"] if m["PID"] == m["TID"]
            ],
        )
    summary = {
        "saved_result": bool(args.saved),
        "created_utc": audit["created_utc"],
        "directory": str(directory),
        "enumerated_tasks": audit["enumerated_tasks"],
        "tasks_without_docker_marker": audit.get(
            "tasks_without_docker_marker", audit.get("non_docker_tasks")
        ),
        "discovered_docker_tasks": audit["discovered_docker_tasks"],
        "scope": audit["scope"],
        "errors": errors,
        "groups": groups,
        "quality": quality,
        "global_observations": global_observations(audit),
        "thread_inventory": audit.get("thread_inventory", []),
        "plugin_version": audit.get("plugin_version"),
        "kernel_banner": audit.get("kernel_banner"),
        "support_policy": audit.get("support_policy"),
        "compatibility": audit.get("compatibility"),
        "feature_status": compatibility_summary(audit),
        "partial_observations": audit.get("partial_observations", []),
        "not_evaluated": audit.get(
            "not_evaluated",
            ["Permission context was not collected in this older result"],
        ),
        "unresolved_members": audit.get("unresolved_members", []),
        "unresolved_collected": "unresolved_members" in audit,
    }
    # 목록/호환성 화면은 복사본만 정제한다. JSON과 집합 비교는 원본을 쓴다.
    if not args.json and (args.compatibility or args.list):
        audit = clean_data(audit)
        summary = clean_data(summary)
        groups = summary["groups"]
    if args.json:
        # 기존 원시 자료와 함께, 긴 화면에서 보던 집합 차이·확인 항목을 제공한다.
        summary["analyst_report"] = build_report(audit, selected)
        # 터미널 JSON은 Unicode 제어문자도 escape한다. 파싱하면 원본 문자열로 복원된다.
        print(json.dumps(summary, ensure_ascii=True, indent=2))
    elif args.compatibility:
        print(
            f"Container Caps {audit.get('plugin_version', '<과거 결과>')} | 저장된 분석의 구조별 관측"
        )
        print("대상 커널: " + display(audit.get("kernel_banner")))
        policy = audit.get("support_policy")
        if policy:
            print("지원 조건: " + display(policy.get("summary")))
            print("필수 환경: " + display(policy.get("requirements")))
        else:
            print("이 과거 결과에는 실행 당시 지원 조건이 기록되지 않았습니다.")
        compatibility = audit.get("compatibility")
        if compatibility:
            # 사전 키를 바꾸면 서로 다른 키가 충돌할 수 있어 직렬화한 표시 문자열을 정제한다.
            print(
                "소속 검사: "
                + clean(json.dumps(compatibility["membership"], ensure_ascii=False))
            )
            print(
                "PID 구조: "
                + clean(
                    json.dumps(compatibility.get("pid_namespace"), ensure_ascii=False)
                )
            )
        else:
            print("이 과거 결과에는 구조별 지원 검사가 기록되지 않았습니다.")
        for item in summary["global_observations"]:
            print(
                f"  {item['feature']}: {STATUS.get(item['status'], item['status'])} — {item.get('reason', '')}"
            )
        for item in summary["feature_status"]:
            layout = " | " + str(item["layout"]) if item["layout"] else ""
            print(
                f"  {item['source']}.{item['feature']}: {STATUS.get(item['status'], item['status'])} | {item['tasks']}개 태스크{layout}"
            )
            for reason in item["reasons"]:
                print("    " + reason)
        print(f"근거·원시 필드·로그: {clean(directory)}")
    elif not args.list:
        report = build_report(audit, selected)
        print("저장 결과 재표시" if args.saved else "새 메모리 분석 결과")
        print(format_summary(report, unresolved=args.unresolved), end="")
        print(f"\n상세·원시 바이트: {clean(directory / 'containercaps-audit.json')}")
        print("조회: --container <ID> | 집합 차이·확인 항목·상세 JSON: --json")
    else:
        print(
            ("저장 결과" if args.saved else "새 분석 결과")
            + f" | 분석 시각(UTC): {audit['created_utc']}"
        )
        if audit.get("kernel_banner"):
            print(
                f"Container Caps {audit.get('plugin_version', '?')} | 커널: {audit['kernel_banner']}"
            )
        print(
            f"열거한 태스크 {audit['enumerated_tasks']}개 | Docker 표식 소속 {audit['discovered_docker_tasks']}개 | 표시 컨테이너 {len(groups)}개"
        )
        total_errors, total_partial = quality_totals(quality)
        print(f"관측 품질: 오류 {total_errors} · 부분 {total_partial}")
        issues = global_issue_text(summary["global_observations"])
        if issues:
            print("전역 확인: " + issues)
        print("식별 기준: 지원하는 cgroup 구조의 Docker 경로 표식과 커널 연결 관계")
        for group in groups:
            members = group["members"]
            print(
                f"\n컨테이너 {group['container_id']}\n  cgroup: {group['container_path']}\n  주소: {group['root_address']}"
            )
            print(
                f"  표시 프로세스 {len({m['PID'] for m in members})}개 / 태스크 {len(members)}개"
            )
        if not groups:
            print(
                "선택 조건에 맞는 Docker 표식 소속을 찾지 못했습니다. 다른 런타임까지 부재를 뜻하지는 않습니다."
            )
        if any(quality.values()):
            print(
                "\n일부 관측이 불완전합니다. 오류 내용은 containercaps-audit.json을 확인하세요."
            )
        if audit.get("thread_inventory"):
            counts = audit["thread_inventory"]
            print(
                f"\n스레드 수 교차 확인: {sum(item['count_matches'] is True for item in counts)}/{len(counts)} 프로세스에서 signal.nr_threads와 일치"
            )
            unavailable = sum(item["count_matches"] is None for item in counts)
            if unavailable:
                print(
                    f"교차 확인 불가: {unavailable}개 프로세스 (필드 없음·읽기 실패·대표 스레드만 수집한 결과 포함)"
                )
        if audit.get("not_evaluated"):
            print("미평가: " + "; ".join(audit["not_evaluated"]))
            print(
                "all은 해당 user namespace의 capability 집합을 뜻합니다. 호스트 파일 접근이나 seccomp/LSM 통과를 판정하지 않습니다."
            )
        print(f"\n근거·원시 필드·로그: {clean(directory)}")
    # Volatility가 정상 종료해도 일부 필드/순회 실패가 있으면 래퍼는 종료 코드 2로 알린다.
    return exit_code


# 저장 조회는 아래 커널 판독기를 불러오지 않아 Volatility 설치 없이 가능하다.
# 새 분석은 --volatility로 다시 실행해 공식 플러그인 탐색·심볼 구성을 이용한다.
if __name__ == "__main__":
    try:
        sys.exit(main())
    except (
        OSError,
        ValueError,
        KeyError,
        RuntimeError,
        importlib.metadata.PackageNotFoundError,
    ) as exc:
        print(f"vcaps: {clean(exc)}", file=sys.stderr)
        sys.exit(1)


# 여기부터는 공식 Volatility가 이 파일을 플러그인 모듈로 import할 때 사용한다.
from volatility3.framework import (  # 읽기 예외·플러그인 기반·메모리 객체·결과 표 API.
    exceptions,
    interfaces,
    renderers,
)
from volatility3.framework.configuration import (
    requirements,  # 커널 모듈·의존 API·실행 옵션의 요구 조건을 선언한다.
)
from volatility3.framework.objects import (
    utility,  # 메모리의 문자 배열을 프로세스 이름 등의 문자열로 변환한다.
)
from volatility3.plugins.linux import (
    _vertical,
    docker_artifacts,
    pslist,  # 공식 PsList API로 프로세스와 스레드를 열거한다.
)
from volatility3.plugins.linux._artifacts import cgroups as cgroup_readers
from volatility3.plugins.linux._artifacts import core as artifact_core
from volatility3.plugins.linux._artifacts import credentials as credential_readers
from volatility3.plugins.linux._artifacts import namespaces as namespace_readers

# 3. 공통 판독기가 수집한 cgroup 경로의 Docker 표식 해석

# 이름이 containerd-shim인 프로세스의 자식만 고르는 방식이 아니라, 각 태스크의
# cgroup 소속과 Docker 경로 표식을 확인한다. 표식은 런타임 신원 인증이 아니다.


SCOPE = re.compile(r"docker-([0-9a-fA-F]{64})\.scope\Z")
FULL_ID = re.compile(r"[0-9a-fA-F]{64}\Z")


def identify_docker(chain):
    """Select the nearest Docker-marked ancestor of a root-to-leaf chain."""
    found = None
    for index, node in enumerate(chain):
        name = node["name"]
        match = SCOPE.fullmatch(name)
        cid = match.group(1).lower() if match else None
        if (
            cid is None
            and index
            and chain[index - 1]["name"] == "docker"
            and FULL_ID.fullmatch(name)
        ):
            cid = name.lower()
        if cid is not None:
            # 루트에서 태스크 쪽으로 읽으므로 나중의 표식이 가장 가까운 컨테이너다.
            # root_address는 태스크의 말단 cgroup이 아니라 Docker 표식이 붙은 객체 주소다.
            found = {
                "id": cid,
                "root_address": node["address"],
                "root_path": "/"
                + "/".join(x["name"] for x in chain[: index + 1] if x["name"]),
            }
    return found


def membership_resolver(module):
    return cgroup_readers.membership_resolver(module, identify_docker)


def namespace_inum(namespace):
    return namespace_readers.namespace_inum(
        namespace,
        member_reader=artifact_core.member,
        missing_error=artifact_core.UnsupportedLayout(
            "Neither namespace.ns.inum nor namespace.proc_inum exists"
        ),
    )


# 4. Volatility 플러그인: 태스크 열거, 수집, 감사 JSON과 표 출력

# 수집 순서: 전체 태스크 → Docker cgroup 소속 → 태스크별 보안 맥락 → 감사 JSON/표.
# 공식 PsList·렌더러 API를 사용하며, 원본 volatility-docker 코드를 복사하거나
# 공식 Capabilities 플러그인을 호출하지 않는다.


LOG = logging.getLogger(__name__)


class ContainerCaps(interfaces.plugins.PluginInterface):
    """Extract Docker task capabilities using matching symbols and supported layouts.

    Ubuntu/kernel version numbers do not select readers. Unknown layouts remain
    explicit; matching symbols do not guarantee complete analysis of every kernel.
    """

    hidden = True  # Exposed through linux.docker.Docker --inspect-caps.
    _required_framework_version = (2, 13, 0)
    _version = VERSION_INFO

    @classmethod
    def get_requirements(cls):
        # pslist의 version은 플러그인 API 버전이며 pip 패키지 버전과 구별한다.
        return [
            requirements.VersionRequirement(
                name="docker_artifacts",
                component=docker_artifacts.DockerArtifacts,
                version=(1, 0, 1),
            ),
            requirements.ModuleRequirement(
                name="kernel",
                description="Linux x86-64 kernel with matching symbols",
                architectures=["Intel64"],
            ),
            requirements.VersionRequirement(
                name="pslist", component=pslist.PsList, version=(4, 0, 0)
            ),
            requirements.StringRequirement(
                name="container",
                description="Docker ID or unique hex prefix (6-64 characters)",
                optional=True,
            ),
            requirements.BooleanRequirement(
                name="leaders",
                description="Only process leaders; default includes threads",
                default=False,
                optional=True,
            ),
            requirements.BooleanRequirement(
                name="unresolved",
                description="Show tasks whose container membership could not be read (not confirmed containers)",
                default=False,
                optional=True,
            ),
            requirements.ChoiceRequirement(
                name="view",
                description="Raw columns or evidence-based analyst report",
                choices=["raw", "analyst"],
                default="raw",
                optional=True,
            ),
        ]

    def _pid_chain(self, task, module):
        return docker_artifacts.DockerArtifacts.read_pid_chain(
            self.context,
            self.config["kernel"],
            int(task.vol.offset),
            layer_name=task.vol.layer_name,
            native_layer_name=task.vol.native_layer_name,
        )

    @staticmethod
    def _observations(member, audit, source, observations):
        """Preserve unavailable data separately from successful empty values."""
        # 태스크별 근거와 전체 실행의 품질 기록을 함께 갱신한다. partial은 악성 여부가 아니다.
        for observation in observations:
            entry = dict(observation, source=source)
            if entry in member["observations"]:
                continue
            member["observations"].append(entry)
            if entry["status"] != "ok":
                member["Status"] = "partial"
                detail = dict(entry, tid=member["TID"])
                audit["partial_observations"].append(detail)
                if entry["status"] in ("read_error", "inconsistent"):
                    audit["field_errors"].append(
                        {
                            "tid": member["TID"],
                            "stage": source + "." + entry["feature"],
                            "error": entry.get("reason", entry["status"]),
                            "status": entry["status"],
                        }
                    )

    @classmethod
    def _failure(cls, member, audit, feature, exc):
        status = (
            "unsupported"
            if isinstance(
                exc,
                (
                    AttributeError,
                    NotImplementedError,
                    artifact_core.UnsupportedLayoutError,
                    artifact_core.UnsupportedLayout,
                ),
            )
            else "inconsistent"
            if isinstance(exc, ValueError)
            else "read_error"
        )
        if any(
            isinstance(cause, exceptions.InvalidAddressException)
            for cause in artifact_core.exception_chain(exc)
        ):
            status = "read_error"
        cls._observations(
            member,
            audit,
            feature,
            [
                {
                    "feature": feature,
                    "status": status,
                    "reason": artifact_core.exception_detail(exc),
                    "exception": type(exc).__name__,
                }
            ],
        )

    def _collect_security(self, task, security, member, audit):
        # Current credentials remain usable if real_cred or an optional field fails.
        # 현재 권한의 출처는 task.cred이며 real_cred는 비교 근거로 별도 보존한다.
        # 주소 차이만으로 권한 상승 이력이나 악성 행위를 판정하지 않는다.
        cred = None
        real_cred = None
        try:
            if not int(task.cred):
                raise ValueError("task.cred is a null pointer")
            member["CredAddress"] = hex(int(task.cred))
            cred = task.cred.dereference()
        except Exception as exc:  # noqa: BLE001 - Record the failure and preserve independent evidence.
            self._failure(member, audit, "credential_pointer", exc)
        try:
            if not int(task.real_cred):
                raise ValueError("task.real_cred is a null pointer")
            member["RealCredAddress"] = hex(int(task.real_cred))
            real_cred = task.real_cred.dereference()
            if cred is not None:
                member["CredsDiffer"] = int(task.cred) != int(task.real_cred)
        except Exception as exc:  # noqa: BLE001 - Record the failure and preserve independent evidence.
            self._failure(member, audit, "real_credential_pointer", exc)
        for source, pointer in (("credentials", cred), ("real_credentials", real_cred)):
            if pointer is None:
                continue
            if (
                source == "real_credentials"
                and member["CredsDiffer"] is False
                and "credentials" in member
            ):
                member[source] = member["credentials"]
                continue
            try:
                member[source] = security.credentials(pointer)
                # Enrichment may fail without discarding the capabilities above.
                try:
                    security.enrich_identity(member[source], pointer)
                except Exception as exc:  # noqa: BLE001 - Record the failure and preserve independent evidence.
                    self._failure(member, audit, source + ".identity", exc)
                self._observations(
                    member, audit, source, member[source].get("observations", [])
                )
            except Exception as exc:  # noqa: BLE001 - Record the failure and preserve independent evidence.
                self._failure(member, audit, source, exc)
        current = member.get("credentials", {})
        member["EUID"] = current.get("ids_kernel", {}).get("euid")
        member["Securebits"] = current.get("securebits")
        member.update(current.get("capabilities", {}))
        member["capability_evidence"] = current.get("capability_evidence", {})
        scope = current.get("user_namespace") or {}
        member["CapabilityScope"] = scope.get("scope", "unknown")
        chain = scope.get("chain_leaf_to_initial") or []
        if chain:
            member["UserNS"] = chain[0].get("inum")
        member["UserEUID"] = current.get("ids_in_user_namespace", {}).get("euid")
        for source, reader in (
            ("seccomp", security.seccomp),
            ("resource_namespaces", security.resource_namespaces),
            ("mounts", security.mounts),
        ):
            try:
                member[source] = reader(task)
                self._observations(
                    member, audit, source, member[source].get("observations", [])
                )
            except Exception as exc:  # noqa: BLE001 - Record the failure and preserve independent evidence.
                self._failure(member, audit, source, exc)
        seccomp = member.get("seccomp", {})
        member["NoNewPrivs"] = seccomp.get("no_new_privs")
        member["SeccompMode"] = seccomp.get("mode")
        member["SeccompFilters"] = seccomp.get("filter_count")
        resources = member.get("resource_namespaces", {})
        member["MountNS"] = (resources.get("mount") or {}).get("inum")
        member["NetNS"] = (resources.get("network") or {}).get("inum")

    def run(self):
        module = self.context.modules[self.config["kernel"]]
        # 소속 판독을 지원하지 않아도 태스크의 권한 수집은 진행한다. 이 태스크들은
        # confirmed members에 섞지 않고 unresolved_members에 별도로 보존한다.
        membership_error = None
        try:
            resolver = membership_resolver(module)
            membership_layout = resolver.compatibility
        except Exception as exc:  # noqa: BLE001 - Record the failure and preserve independent evidence.
            resolver, membership_error = None, exc
            membership_layout = {
                "feature": "container_membership",
                "status": "unsupported"
                if isinstance(
                    exc,
                    (artifact_core.UnsupportedLayoutError, AttributeError, KeyError),
                )
                else "read_error",
                "reason": artifact_core.exception_detail(exc),
            }
        security = credential_readers.SecurityReader(self.context, module)
        try:
            pid_layout = docker_artifacts.DockerArtifacts.inspect_pid_layout(
                self.context, self.config["kernel"]
            )
        except artifact_core.UnsupportedLayoutError as exc:
            pid_layout = exc.compatibility
        prefix = self.config.get("container", "") or ""
        if prefix and not re.fullmatch(r"[0-9a-fA-F]{6,64}", prefix):
            raise ValueError("Container prefix must be 6-64 hexadecimal characters")
        prefix = prefix.lower()
        show_unresolved = self.config.get("unresolved", False)
        if show_unresolved and prefix:
            raise ValueError("--unresolved cannot be combined with --container")
        # audit는 실행 전체, members의 각 항목은 태스크 하나의 값과 그 값을 읽은 근거다.
        audit = {
            "created_utc": datetime.datetime.now(datetime.timezone.utc).isoformat(),
            "plugin_version": VERSION,
            "kernel_banner": security.banner,
            "support_policy": dict(SUPPORT_POLICY),
            "global_observations": [
                dict(item, source="security") for item in security.observations
            ],
            "compatibility": {
                "policy": "matching symbols; structure-selected readers; Intel64; unknown layouts remain explicit",
                "membership": membership_layout,
                "pid_namespace": pid_layout,
                "security": getattr(security, "compatibility", {}),
            },
            "credential_source": "task.cred (subjective); task.real_cred recorded separately",
            "method": "symbol-selected css_set memberships -> cgroup CSS/kernfs parent chains",
            "scope": "Docker-marked paths in supported cgroup layouts; unresolved tasks stored separately; no Docker registry reconstruction",
            "include_threads": not self.config.get("leaders", False),
            "seen_task_addresses": [],
            "seen_tids": [],
            "tasks_without_docker_marker": 0,
            "membership_errors": [],
            "field_errors": [],
            "traversal_errors": [],
            "partial_observations": [],
            "containers": [],
            "members": [],
            "unresolved_members": [],
            "thread_inventory": [],
            "not_evaluated": [
                "LSM policies",
                "seccomp BPF rule outcomes",
                "per-file DAC/ACL and idmapped-mount decisions",
            ],
        }
        if membership_error is not None:
            audit["global_observations"].append(
                dict(membership_layout, source="membership")
            )
        if membership_layout.get("coverage") == "default_hierarchy_only":
            # v2 경로가 읽혔다고 v1/혼합 계층까지 검사했다고 보고하지 않는다.
            audit["global_observations"].append(
                artifact_core.observation(
                    "legacy_membership",
                    "unsupported",
                    "Only the default cgroup hierarchy was inspected; legacy hierarchies are unverified",
                    source="membership",
                )
            )
        seen = set()
        found_groups = {}
        all_tids_by_pid = {}
        try:
            # 공식 열거 API를 직접 호출한다. 기본값은 스레드 포함이며, 이 목록 밖의
            # 은닉·연결 해제 태스크까지 복구했다고 주장할 수는 없다.
            tasks = docker_artifacts.DockerArtifacts.list_tasks(
                self.context,
                self.config["kernel"],
                include_threads=audit["include_threads"],
            )
            for task in tasks:
                address = int(task.vol.offset)
                if address in seen:
                    continue
                seen.add(address)
                # Linux task.pid는 개별 TID, task.tgid는 프로세스 PID다. 표의 PID/TID도 이 구분을 따른다.
                tid = int(task.pid)
                tgid = int(task.tgid)
                all_tids_by_pid.setdefault(tgid, set()).add(tid)
                audit["seen_task_addresses"].append(hex(address))
                audit["seen_tids"].append(tid)
                identity_error = membership_error
                cset = cgroup = group = None
                chain = []
                try:
                    if resolver is None:
                        raise membership_error
                    cset, cgroup, chain, group = resolver.resolve(task)
                    if group is None:
                        audit["tasks_without_docker_marker"] += 1
                        continue
                except Exception as exc:  # noqa: BLE001 - Record the failure and preserve independent evidence.
                    identity_error = exc
                    audit["membership_errors"].append(
                        {
                            "pid": tgid,
                            "tid": tid,
                            "task": hex(address),
                            "error": artifact_core.exception_text(exc),
                        }
                    )
                # 같은 ID 표식이라도 다른 cgroup 객체는 합치지 않는다.
                if group is not None:
                    group_key = (group["id"], group["root_address"])
                    found_groups[group_key] = group
                member = {
                    "ContainerID": group["id"] if group else None,
                    "ContainerRoot": group["root_address"] if group else None,
                    "ContainerPath": group["root_path"] if group else None,
                    "CgroupPath": "/" + "/".join(x["name"] for x in chain if x["name"])
                    if chain
                    else None,
                    "PID": tgid,
                    "TID": tid,
                    "Name": None,
                    "TaskAddress": hex(address),
                    "CssSetAddress": hex(int(cset.vol.offset)) if cset else None,
                    "CgroupAddress": hex(int(cgroup.vol.offset)) if cgroup else None,
                    "PIDNS": None,
                    "NSPID": None,
                    "NSTID": None,
                    "UserNS": None,
                    "EUID": None,
                    "Status": "ok",
                    "UserEUID": None,
                    "CapabilityScope": "unknown",
                    "CredSource": "task.cred",
                    "CredsDiffer": None,
                    "NoNewPrivs": None,
                    "SeccompMode": None,
                    "SeccompFilters": None,
                    "Securebits": None,
                    "MountNS": None,
                    "NetNS": None,
                    "ExpectedThreads": None,
                    "cgroup_chain": chain,
                    "capability_evidence": {},
                    "observations": [],
                    "membership_status": "confirmed_marker" if group else "unresolved",
                    "membership_evidence": group.get("membership_evidence", [])
                    if group
                    else getattr(identity_error, "membership_evidence", []),
                }
                if identity_error is not None:
                    # 소속 오류는 membership_errors에 이미 집계했다. 필드 오류로 중복 계산하지 않는다.
                    self._failure(
                        member,
                        {
                            "partial_observations": audit["partial_observations"],
                            "field_errors": [],
                        },
                        "container_membership",
                        identity_error,
                    )
                try:
                    member["Name"] = utility.array_to_string(task.comm)
                except Exception as exc:  # noqa: BLE001 - Record the failure and preserve independent evidence.
                    self._failure(member, audit, "process_name", exc)
                for field in CAP_FIELDS:
                    # 읽기 전 값은 미확인(None)이다. 읽기에 성공한 빈 권한 집합과 구별한다.
                    member[field] = None
                try:
                    pid_chain = self._pid_chain(task, module)
                    leader_chain = self._pid_chain(
                        task.group_leader.dereference(), module
                    )
                    member["pid_chain"] = pid_chain
                    member["PIDNS"] = pid_chain[-1]["namespace"]
                    member["NSTID"] = pid_chain[-1]["id"]
                    member["NSPID"] = next(
                        x["id"]
                        for x in leader_chain
                        if x["namespace"] == member["PIDNS"]
                    )
                except Exception as exc:  # noqa: BLE001 - Record the failure and preserve independent evidence.
                    self._failure(member, audit, "pid_namespace", exc)
                else:
                    self._observations(
                        member,
                        audit,
                        "pid_namespace",
                        [
                            {
                                "feature": "pid_namespace",
                                "status": "ok",
                                "layout": "thread_pid"
                                if task.has_member("thread_pid")
                                else "pids[PIDTYPE_PID]",
                            }
                        ],
                    )
                self._collect_security(task, security, member, audit)
                try:
                    member["ExpectedThreads"] = int(task.signal.nr_threads)
                except Exception as exc:  # noqa: BLE001 - Record the failure and preserve independent evidence.
                    self._failure(member, audit, "thread_count", exc)
                audit["members" if group else "unresolved_members"].append(member)
        except Exception as exc:  # noqa: BLE001 - Record the failure and preserve independent evidence.
            audit["traversal_errors"].append(artifact_core.exception_text(exc))

        ids = {key[0] for key in found_groups if key[0].startswith(prefix)}
        if prefix and len(ids) > 1:
            raise ValueError("Container prefix is ambiguous; supply more characters")
        selected = [m for m in audit["members"] if m["ContainerID"].startswith(prefix)]
        selected.sort(
            key=lambda m: (m["ContainerID"], m["ContainerRoot"], m["PID"], m["TID"])
        )
        audit["unresolved_members"].sort(key=lambda m: (m["PID"], m["TID"]))
        audit["containers"] = sorted(
            found_groups.values(), key=lambda g: (g["id"], g["root_address"])
        )
        audit["selected_prefix"] = prefix
        audit["selected_tasks"] = len(selected)
        audit["selected_containers"] = len(
            {(m["ContainerID"], m["ContainerRoot"]) for m in selected}
        )
        audit["enumerated_tasks"] = len(seen)
        audit["discovered_docker_tasks"] = len(audit["members"])
        audit["unresolved_tasks"] = len(audit["unresolved_members"])
        audit["display_scope"] = (
            "unresolved" if show_unresolved else "confirmed_docker_markers"
        )
        audit["displayed_tasks"] = (
            audit["unresolved_tasks"] if show_unresolved else len(selected)
        )
        # 같은 프로세스의 스레드가 다른 cgroup에 있을 수 있어 전체 열거 TID로 nr_threads를 대조한다.
        # 대표 스레드만 수집했거나 비교 근거가 모자라면 count_matches는 미확인(None)으로 남긴다.
        for pid in sorted({m["PID"] for m in audit["members"]}):
            members = [m for m in audit["members"] if m["PID"] == pid]
            expected = {
                m["ExpectedThreads"]
                for m in members
                if m["ExpectedThreads"] is not None
            }
            observed = sorted(all_tids_by_pid[pid])
            can_compare = (
                audit["include_threads"]
                and len(expected) == 1
                and all(m["ExpectedThreads"] is not None for m in members)
            )
            count_matches = (
                len(observed) == next(iter(expected)) if can_compare else None
            )
            audit["thread_inventory"].append(
                {
                    "pid": pid,
                    "observed_tids_all_cgroups": observed,
                    "expected_counts": sorted(expected),
                    "count_matches": count_matches,
                    "container_member_tids": sorted(m["TID"] for m in members),
                }
            )
            if count_matches is False:
                for member in members:
                    self._observations(
                        member,
                        audit,
                        "thread_inventory",
                        [
                            {
                                "feature": "thread_coverage",
                                "status": "inconsistent",
                                "reason": "Observed TIDs and signal.nr_threads disagree",
                            }
                        ],
                    )
        audit["coverage_complete_within_enumerated_tasks"] = not (
            audit["membership_errors"]
            or audit["traversal_errors"]
            or membership_layout.get("coverage") == "default_hierarchy_only"
        )
        audit["quality"] = audit_quality(audit)
        # self.open은 Volatility 출력 디렉터리(-o)를 따른다. 화면을 줄여도 원시 근거는
        # 감사 JSON에 남기며, analyst JSON에는 집합 비교와 확인 항목을 추가한다.
        with self.open("containercaps-audit.json") as handle:
            handle.write(
                json.dumps(audit, ensure_ascii=False, indent=2).encode("utf-8")
            )
        if any(audit["quality"].values()):
            total_errors, total_partial = quality_totals(audit["quality"])
            LOG.warning(
                "ContainerCaps: incomplete observations; inspect containercaps-audit.json (errors=%d, partial=%d; global errors=%d, global partial=%d)",
                total_errors,
                total_partial,
                audit["quality"]["global_errors"],
                audit["quality"]["global_partial_observations"],
            )
        if self.config.get("view", "raw") == "analyst":
            report = build_report(audit, [] if show_unresolved else selected)
            with self.open("containercaps-analyst.json") as handle:
                handle.write(
                    json.dumps(report, ensure_ascii=False, indent=2).encode("utf-8")
                )
            return _vertical.vertical_grid(
                [(name, str) for name in SUMMARY_COLUMNS],
                (
                    (0, row)
                    for row in (
                        unresolved_rows(report)
                        if show_unresolved
                        else summary_rows(report)
                    )
                ),
            )
        columns = [
            ("ContainerID", str),
            ("ContainerRoot", str),
            ("CgroupPath", str),
            ("PID", int),
            ("TID", int),
            ("Name", str),
            ("NSPID", int),
            ("NSTID", int),
            ("PIDNS", int),
            ("UserNS", int),
            ("EUID", int),
            ("UserEUID", int),
            ("CapabilityScope", str),
            ("CredSource", str),
            ("CredsDiffer", bool),
            ("NoNewPrivs", bool),
            ("SeccompMode", int),
            ("SeccompFilters", int),
            ("Securebits", int),
            ("MountNS", int),
            ("NetNS", int),
            ("Status", str),
        ] + [(x, str) for x in CAP_FIELDS]

        def generate():
            for member in audit["unresolved_members"] if show_unresolved else selected:
                # TreeGrid는 표시용이다. renderer JSON도 정제된 셀이며 원본은 audit JSON에 있다.
                values = tuple(
                    (clean(member[key]) if kind is str else member[key])
                    if member[key] is not None
                    else renderers.NotAvailableValue()
                    for key, kind in columns
                )
                yield 0, values

        return _vertical.vertical_grid(columns, generate())

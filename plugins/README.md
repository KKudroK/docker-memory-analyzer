# Container Mounts Plugin

Volatility 3에서 Linux 메모리 덤프의 컨테이너 Mount Namespace와 마운트를
확인하는 외부 플러그인이다. cgroup v1, v2, hybrid membership을 구분한다.
파일 내용이나 삭제 파일을 복구하는 도구는 아니다.

## 요구사항

- Python 3.10 이상
- Volatility 3 `2.28.0`
- 메모리 덤프의 Linux 커널과 정확히 일치하는 ISF 파일 (task, mount, cgroup, kernfs 관련 타입 포함)
- x86/x86-64 Linux 메모리 덤프 (`.lime`, `.raw` 등)

## 설치

저장소 루트에서 PowerShell을 실행한다.

```powershell
py -3.10 -m venv .venv
& .\.venv\Scripts\python.exe -m pip install --upgrade pip
& .\.venv\Scripts\python.exe -m pip install volatility3==2.28.0
```

ISF 파일은 별도 디렉터리에 둔다. 다음 명령의 `$symbols`에는 ISF가 들어 있는
디렉터리를 지정한다. 예를 들어 `D:\volatility-symbols\linux\kernel.json`이면
`$symbols = "D:\volatility-symbols"`로 설정한다. 아래 덤프·심볼 경로는 실제 경로로 바꾼다.

## 실행

```powershell
$vol = ".\.venv\Scripts\vol.exe"
$plugins = ".\plugins"
$symbols = "D:\volatility-symbols"
$dump = "D:\memory\memory.lime"

& $vol -p $plugins -s $symbols -f $dump `
  inspect_mount.ContainerMounts
```

기본 실행은 컨테이너 근거가 `HIGH` 또는 `MEDIUM`인 Mount Namespace에서
`HIGH`와 `REVIEW` 마운트만 출력한다.

JSON으로 저장하려면 다음과 같이 실행한다.

```powershell
& $vol -q -r json -l .\container-mounts.log -p $plugins -s $symbols -f $dump `
  inspect_mount.ContainerMounts --extended |
  Set-Content -Encoding utf8 .\container-mounts.json
```

## 옵션

| 옵션 | 기능 |
|---|---|
| 옵션 없음 | `HIGH`/`MEDIUM` 컨테이너 후보의 `HIGH`/`REVIEW` 마운트 출력 |
| `--all-mounts` | 인프라 패턴으로 분류된 `INFRA` 마운트까지 출력 |
| `--extended` | cgroup v1/v2 membership, 탐지 근거, Mount ID 등 상세 필드 출력 |
| `--include-candidates` | Mount Namespace 분리만 확인된 `LOW` 후보도 출력 |
| `--pids PID ...` | 지정한 Host PID를 `MANUAL` 대상으로 분석 (경로·ID 검증을 생략하지 않음) |

모든 정보 확인:

```powershell
& $vol -p $plugins -s $symbols -f $dump `
  inspect_mount.ContainerMounts `
  --all-mounts --extended --include-candidates
```

특정 Host PID 확인:

```powershell
& $vol -p $plugins -s $symbols -f $dump `
  inspect_mount.ContainerMounts `
  --pids 9933 --all-mounts --extended
```

## 확인

플러그인 등록 확인:

```powershell
& $vol -p $plugins -h |
  Select-String "inspect_mount.ContainerMounts"
```

플러그인 도움말 확인:

```powershell
& $vol -p $plugins inspect_mount.ContainerMounts -h
```

결과 확인 시 다음을 주의한다.

- `Traversal=PARTIAL`은 순회·필드·경로·전파 속성 중 일부를 완전히 읽지 못했다는 뜻이다. 원인은 덤프 누락, 심볼 불일치, 지원하지 않는 구조 등일 수 있다. 읽힌 필드는 유지하며, 항목별 실패 건수는 서로 겹칠 수 있다.
- `Source Confidence=CONFIRMED`는 수집한 호스트 마운트 구조에서 끝까지 검증된 경로가 하나라는 뜻이다. 원래 `docker run -v`에 입력했던 문자열을 보증하지는 않는다. `AMBIGUOUS`는 검증된 경로가 여러 개, `UNKNOWN`은 전체 확인에 필요한 근거가 부족한 경우다. `UNKNOWN`에도 일부 확인된 후보 경로가 남을 수 있다.
- `Container Path`와 `Mount Root`는 읽힌 마운트·dentry 연결 관계를 나타낸다. inode 정보가 누락되어도 연결 관계가 완전하면 표시할 수 있으므로, 이 경로만으로 현재 호스트에서 접근 가능하다고 판단하지 않는다.
- `Cgroups`는 커널의 내부 hierarchy 기준 membership이다. cgroup namespace 기준으로 상대화된 `/proc/<pid>/cgroup` 출력이나 실제 마운트된 cgroup 모드와는 다르다. v1 사용 환경에도 내부 v2 루트 `/`가 존재할 수 있다.
- 같은 Mount Namespace에서 ID가 충돌하면 Container ID를 비우고 근거에 충돌을 표시한다. 여러 task root가 있으면 경로는 출력된 대표 PID 기준이다.
- `HIGH`는 우선 검토 대상, `REVIEW`는 추가 확인 대상, `INFRA`는 알려진 인프라 패턴이다. 공격 성공이나 안전성을 확정하는 판정이 아니다. `rw`/`ro`는 마운트·슈퍼블록 플래그이며 실제 접근 권한은 별도다.
- 기본 결과가 비어 있으면 `--all-mounts --extended --include-candidates`와 경고 로그를 확인한다. 모든 행이 필터링되거나 디코드에 실패해도 경고는 남는다. JSON의 빈 배열은 마운트가 없다는 증거가 아니다.

검증 범위: cgroup v2 Round2 덤프 실행 및 손상·충돌 회귀 테스트를 수행했다.
v1/hybrid는 구조별 테스트 기준이며 실제 덤프 통합 검증은 별도로 필요하다.

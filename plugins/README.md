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

기본 실행은 지원하는 cgroup 소속 또는 런타임 감시 프로세스 관계를 근거로
대상을 선택하고, 선택한 대상에서 읽을 수 있는 마운트를 모두 출력한다.
Mount Namespace가 분리됐다는 이유만으로 선택하지 않으며, 위험도 점수나
경로 화이트리스트로 마운트 행을 걸러내지 않는다.

기본 출력은 `PID`, `MNT NS`, `Container ID`, `Container Path`,
`Host Paths`, `FS Type`, `RO/RW`의 7개 열이다.

JSON으로 저장하려면 다음과 같이 실행한다.

```powershell
& $vol -q -r json -l .\container-mounts.log -p $plugins -s $symbols -f $dump `
  inspect_mount.ContainerMounts --extended |
  Set-Content -Encoding utf8 .\container-mounts.json
```

## 옵션

| 옵션 | 기능 |
|---|---|
| 옵션 없음 | 자동 선택한 대상의 읽을 수 있는 마운트를 기본 7개 열로 출력 |
| `--extended` | 같은 마운트 행에 Runtime, 내부 PID, cgroup 소속, 읽기·경로 상태, Mount ID, 옵션 등 16개 상세 열 추가 |
| `--pids PID ...` | 자동 대상 선택 대신 지정한 Host PID를 각각 분석 (경로·ID 검증은 유지) |

`--pids`에는 덤프 안의 양의 정수 Host PID를 1개 이상 지정한다.
컨테이너 내부 PID가 아니며, 아래 `9933`은 실제 확인할 PID로 바꾼다.
기존 `--all-mounts`와 `--include-candidates`는 삭제되어 사용할 수 없다.

상세 정보 확인:

```powershell
& $vol -p $plugins -s $symbols -f $dump `
  inspect_mount.ContainerMounts `
  --extended
```

특정 Host PID 확인:

```powershell
& $vol -p $plugins -s $symbols -f $dump `
  inspect_mount.ContainerMounts `
  --pids 9933 --extended
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

상세 출력의 `Host Path Status`는 위험도나 신뢰도 점수가 아니라 경로 복원 상태다.

| 값 | 의미 |
|---|---|
| `SINGLE` | 수집한 호스트 구조에서 검증된 경로가 하나 |
| `MULTIPLE` | 검증된 경로가 여러 개 (`Host Paths`에 ` \| `로 구분) |
| `UNRESOLVED` | 호스트 경로를 찾지 못했거나 내부 루트 항목이라 계산하지 않음 |
| `PARTIAL` | 호스트 구조나 후보 경로를 완전히 읽지 못함. 일부 확인한 경로는 남을 수 있음 |

결과 확인 시 다음을 주의한다.

- `Container Path`는 출력된 PID 관점의 마운트 경로이고, `Host Paths`는 덤프의 호스트 구조에서 확인한 경로다. 원래 `docker run -v`에 입력한 문자열이나 현재 접근 가능성을 보증하지 않는다. 경로가 `-`라고 해서 마운트가 없다는 뜻은 아니다.
- `Read Status=PARTIAL:...`은 해당 PID 관점의 마운트 순회·필드·경로 중 일부를 읽지 못했다는 뜻이다. 읽힌 값은 유지하며, 같은 관점의 행에 상태를 함께 표시한다. `COMPLETE`도 호스트 경로나 모든 파일시스템별 옵션의 복원을 보증하지 않는다.
- `Cgroups`는 커널 내부 hierarchy 기준 소속이다. cgroup namespace 기준으로 상대화된 `/proc/<pid>/cgroup` 출력과 다를 수 있고, v1 환경에도 내부 v2 루트 `/`가 존재할 수 있다.
- 같은 Mount Namespace라도 컨테이너 소유자나 task root가 다르면 나눠서 출력한다. 자동 모드에서 같은 관점의 대표는 가장 작은 Host PID다. cgroup ID 근거 자체가 충돌하면 ID를 `-`로 두고 `Selection Evidence`에 `cgroup-id-conflict`를 표시한다.
- `RO/RW`의 `ro`/`rw`는 마운트·슈퍼블록 플래그 기준이며 실제 파일 접근 권한은 별도다. 필요한 플래그를 확인하지 못하면 `-`로 표시한다.
- `Superblock Options`는 완전한 `/proc/<pid>/mountinfo` 옵션 목록이 아니다. overlay의 `lowerdir`/`upperdir`, tmpfs의 `size` 같은 파일시스템별 옵션은 빠질 수 있다.
- 기본 결과가 비면 경고 로그를 확인하고, 알고 있는 Host PID로 `--pids PID --extended`를 실행한다. 자동 선택에서 빠졌거나 읽기에 실패했을 수 있으므로 빈 결과는 마운트가 없다는 증거가 아니다.

검증 범위: 회귀 테스트 128개 통과. cgroup v2 S01 덤프에서 15개 컨테이너의
368행을 출력했고, 그중 353개 마운트의 경로·파일시스템·마운트 플래그·전파 속성을
`/proc` 수집값과 대조했다. 나머지 15행은 내부 루트 항목이다.
Round2는 기존 27행을 유지했지만 호스트 경로 미복원이 남아 있어 경로 검증 완료로 보지 않는다.
v1/hybrid는 구조별 테스트 기준이며 실제 덤프 통합 검증은 별도로 필요하다.

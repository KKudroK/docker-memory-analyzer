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
`--extended`는 여기에 `Mount ID`, `Read Status`, `Host Path Status`만
추가하여 총 10개 열을 출력한다.

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
| `--extended` | 같은 마운트 행에 Mount ID·Read Status·Host Path Status를 추가하여 총 10개 열 출력 |
| `--pids PID ...` | 자동 대상 선택 대신 지정한 Host PID를 각각 분석 (경로·ID 검증은 유지) |

`--pids`에는 덤프 안의 양의 정수 Host PID를 1개 이상 지정한다.
컨테이너 내부 PID가 아니며, 아래 `9933`은 실제 확인할 PID로 바꾼다.
여러 PID는 `--pids 9933 10025 --extended`처럼 공백으로 구분한다.
현재 프로세스 대표 PID를 대상으로 하며 별도 스레드 TID 선택은 지원하지 않는다.
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
| `UNRESOLVED` | 확인 가능한 호스트 경로가 없거나 내부 루트 항목이라 계산하지 않음 |
| `PARTIAL` | 호스트 구조나 후보 경로를 완전히 읽지 못함. 일부 확인한 경로는 남을 수 있음 |

결과 확인 시 다음을 주의한다.

- `Container Path`는 출력된 PID 관점의 마운트 경로이고, `Host Paths`는 덤프의 호스트 구조에서 확인한 경로다. 원래 `docker run -v`에 입력한 문자열이나 현재 접근 가능성을 보증하지 않는다. 경로가 `-`라고 해서 마운트가 없다는 뜻은 아니다.
- `Read Status=PARTIAL:...`은 해당 PID 관점의 마운트 순회·내부 필드·경로 중 일부를 읽지 못했다는 뜻이다. 읽힌 값은 유지하며, 같은 관점의 행에 상태를 함께 표시한다. `COMPLETE`도 호스트 경로나 모든 파일시스템별 옵션의 복원을 보증하지 않는다.
- cgroup v1·v2·hybrid 소속은 컨테이너 ID 선택에 내부적으로 사용한다. cgroup 이름을 끝까지 읽지 못하면 잘린 이름으로 ID를 판별하지 않는다. ID 근거가 충돌하면 `Container ID`는 `-`이며, 부분 읽기·충돌의 상세 내용은 경고 로그에 남긴다. 이는 `Read Status`가 다루는 마운트 읽기 상태와 별개다.
- 같은 Mount Namespace라도 컨테이너 소유자나 task root가 다르면 나눠서 출력한다. 자동 모드에서 같은 관점의 대표는 가장 작은 Host PID다. 다른 PID의 cgroup 소속을 대표 PID의 정보로 합쳐 출력하지 않는다.
- 삭제된 원래 이름은 정상 호스트 경로로 출력하지 않는다. 같은 파일이 별도의 살아 있는 bind mount로 연결되어 있으면 해당 경로는 유지한다. 연결 상태를 읽지 못한 경우는 `PARTIAL`로 구분한다.
- `RO/RW`의 `ro`/`rw`는 마운트·슈퍼블록 플래그 기준이며 실제 파일 접근 권한은 별도다. 필요한 플래그를 확인하지 못하면 `-`로 표시한다.
- 상세 출력도 10개 열로 제한한다. Runtime, 내부 PID, Cgroups, Devname, 전파 속성, 전체 마운트 옵션은 출력 열에 포함하지 않는다.
- 탭·줄바꿈 또는 UTF-8로 해석되지 않는 이름이 포함된 경로는 현재 복원하지 못할 수 있다. 해당 행의 읽기 상태와 경고를 확인한다.
- 기본 결과가 비면 경고 로그를 확인하고, 알고 있는 Host PID로 `--pids PID --extended`를 실행한다. 자동 선택에서 빠졌거나 읽기에 실패했을 수 있으므로 빈 결과는 마운트가 없다는 증거가 아니다.

검증 범위: v0.6.0 로컬 회귀 테스트 178개 통과. cgroup v2 S01 덤프에서
기본 7열·확장 10열 모두 15개 컨테이너의 368행을 출력했다. 그중 353개 마운트의
Mount ID·컨테이너 경로·FS Type·RO/RW를 `/proc` 수집값과 대조했다.
나머지 15행은 내부 루트 항목이며, 호스트 bind 경로는 별도 시나리오의 정답과 대조했다.
삭제된 이름·살아 있는 bind 별칭·불완전한 문자열은 합성 메모리 구조 테스트로 검증했다.
v1/hybrid는 구조별 테스트 기준이며 실제 덤프 통합 검증과 다른 배포판 검증은 별도로 필요하다.

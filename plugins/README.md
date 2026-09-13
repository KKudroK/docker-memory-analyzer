# Container Mounts Plugin

Volatility 3에서 Linux 메모리 덤프의 컨테이너 Mount Namespace와 마운트를
확인하는 외부 플러그인이다. cgroup v1, v2, hybrid 구성을 자동으로 처리한다.

## 요구사항

- Python 3.10 이상
- Volatility 3 `2.28.0`
- 메모리 덤프의 Linux 커널과 정확히 일치하는 ISF 파일
- Linux 메모리 덤프 (`.lime`, `.raw` 등)

## 설치

저장소 루트에서 PowerShell을 실행한다.

```powershell
py -3.10 -m venv .venv
& .\.venv\Scripts\python.exe -m pip install --upgrade pip
& .\.venv\Scripts\python.exe -m pip install volatility3==2.28.0
```

ISF 파일은 별도 디렉터리에 둔다. 다음 명령의 `$symbols`에는 ISF가 들어 있는
디렉터리를 지정한다.

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
& $vol -q -r json -p $plugins -s $symbols -f $dump `
  inspect_mount.ContainerMounts --extended |
  Set-Content -Encoding utf8 .\container-mounts.json
```

## 옵션

| 옵션 | 기능 |
|---|---|
| 옵션 없음 | `HIGH`/`MEDIUM` 컨테이너 후보의 `HIGH`/`REVIEW` 마운트 출력 |
| `--all-mounts` | 정상 인프라로 분류된 `INFRA` 마운트까지 출력 |
| `--extended` | cgroup v1/v2 membership, 탐지 근거, Mount ID 등 상세 필드 출력 |
| `--include-candidates` | Mount Namespace 분리만 확인된 `LOW` 후보도 출력 |
| `--pids PID ...` | 지정한 Host PID를 `MANUAL` 대상으로 직접 분석 |

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

- `Traversal=PARTIAL`이면 메모리 손상이나 page fault 때문에 전체 마운트를 복원하지 못한 것이다.
- `Source Confidence=UNKNOWN`은 호스트 마운트가 없다는 뜻이 아니라 경로를 증명하지 못했다는 뜻이다.
- 기본 결과가 비어 있으면 `--all-mounts --extended --include-candidates`로 다시 확인한다.

# ContainerCaps 1.4.0

Linux 메모리 덤프에서 **Docker cgroup v2에 속한 프로세스·스레드의 권한과 보안 맥락**을 복원하는 Volatility 3 플러그인입니다. 핵심 항목은 터미널 7열로, 다섯 capability 집합·주소·원시 바이트·누락 근거는 JSON으로 제공합니다. 분석할 때 Docker 실행이나 Docker API 접속은 필요하지 않습니다.

## 환경

| 항목 | 조건 |
|---|---|
| 분석 환경 | Python 3.12, Volatility 3 **2.28.0** 기준 |
| 덤프 | Linux x86-64, Docker 표식이 있는 **cgroup v2** |
| 심볼 | 덤프의 커널·빌드와 일치하는 Linux ISF (`symbols/linux/` 아래) |
| 실제 검증 | Ubuntu `7.0.0-31-generic`, Docker `29.8.0`, 5개 컨테이너 실험 |
| 지원 범위 | 알려진 심볼 구조에 따라 읽기 방법 선택. 모든 커널·Docker 버전을 보장하지 않으며 cgroup v1·ARM64는 범위 밖 |

## 설치와 실행

아래 명령은 이 `plugin/` 폴더에서 실행합니다. PowerShell 예시이며 Linux에서는 가상환경 Python 경로를 `.venv/bin/python`으로 바꾸고, 아래 `New-Item` 대신 `mkdir native-results`를 사용합니다.

```powershell
python -m venv .venv
.\.venv\Scripts\python.exe -m pip install -r requirements.txt
```

자신의 덤프와 일치하는 심볼을 준비한 뒤 실행합니다. `symbols`는 `linux/`의 **상위** 폴더입니다.

```powershell
.\.venv\Scripts\python.exe -X utf8 container_caps.py --dump memory.lime --symbols symbols --output-root results
```

**함께 제공하는 실험 자료**의 위치와 복원 방법은 [evidence/README.md](evidence/README.md)에 있습니다. 이 자료의 BTF 심볼을 쓸 때만 먼저 아래 준비 명령을 실행합니다. 가상환경의 ISF 메타데이터 스키마에 `btf`·`symdb` 출처를 허용하며, 심볼 검증과 분석 로직은 유지합니다.

```powershell
.\.venv\Scripts\python.exe tools/prepare_lab_schema.py
```

Volatility 명령으로 직접 핵심 표를 출력할 수도 있습니다. `native-results`는 새 출력 폴더로 지정합니다.

```powershell
New-Item -ItemType Directory -Path native-results
.\.venv\Scripts\python.exe -X utf8 run_volatility.py -q --offline -f memory.lime -s symbols -p plugins -o native-results -r pretty containercaps.ContainerCaps --view analyst
```

## 터미널과 상세 결과

실험에서 실제 관측한 5개 태스크입니다. 아래는 핵심 열을 정렬한 예시이고, [원래 터미널 출력](examples/native-output.txt)도 제공합니다.

```text
Container     PID/TID    Name   Effective           UserNS Seccomp   Check
385fdee6cfe4   4563/4563  sleep  없음                초기   filter/1  -
82b99e199aa7   4669/4669  sleep  BPF                 초기   filter/1  권한 검토
8bd651d482c1   4618/4618  sleep  CHOWN,NET_ADMIN     초기   filter/1  권한 검토
b5f70b68d25a   4725/4725  sleep  CHECKPOINT_RESTORE  초기   filter/1  권한 검토
f097fa6073ca   4508/4508  sleep  원시 14비트         초기   filter/1  -
```

- `PID/TID`: 호스트의 프로세스 ID / 스레드 ID. 컨테이너 내부 ID는 JSON에 기록합니다.
- `Effective`: 현재 `task.cred`의 유효 권한. 3개 이상이면 원시 비트 수로 요약하며, 읽기 실패는 `없음`과 구분합니다.
- `UserNS`, `Seccomp`: 권한이 속한 user namespace와 관측한 seccomp 모드·필터 수입니다. 실제 seccomp 규칙의 허용 결과를 뜻하지 않습니다.
- `Check`: 권한 검토, 집합·credentials·스레드 차이, 부분 관측 등 후속 조사 근거입니다. `-`는 안전 판정이 아닙니다.

저장 결과를 빠르게 다시 보거나 컨테이너를 선택할 수 있습니다. 아래 `--container` 값은 이 실험의 예시이며 일반 사용 시 실제 ID로 바꿉니다.

```powershell
.\.venv\Scripts\python.exe -X utf8 container_caps.py --saved --output-root results
.\.venv\Scripts\python.exe -X utf8 container_caps.py --saved --output-root results --container 8bd651
.\.venv\Scripts\python.exe -X utf8 container_caps.py --saved --output-root results --json
.\.venv\Scripts\python.exe -X utf8 container_caps.py --saved --output-root results --compatibility
```

위 native 명령으로 만든 결과는 `.\.venv\Scripts\python.exe -X utf8 container_caps.py --saved native-results`로 다시 봅니다.

| 파일·옵션 | 내용 |
|---|---|
| `containercaps-audit.json` | 전체 수집 근거, 다섯 권한 집합의 마스크·원시 바이트, credentials·namespace·마운트·관측 오류 |
| `containercaps-analyst.json` | native `--view analyst` 실행 시 생성하는 확인 항목과 상세 근거 |
| CLI `--json` | 선택된 구성원의 상세 수집 자료와 그룹. native 분석가 JSON과 형식이 다름 |
| CLI `--view analyst` | 저장 자료의 긴 해설 출력. 기본은 짧은 `summary` |
| native `--view` 생략 | 기존 27열 raw 표 출력 |

CLI의 `--leaders`는 수집한 전체 스레드 중 대표 스레드만 **표시**합니다. native에 직접 `--leaders`를 주면 수집부터 대표 스레드로 제한합니다. CLI 종료 코드 `2`는 입력 오류 또는 부분 관측이므로 메시지와 JSON을 확인합니다. native 명령은 부분 관측에도 종료 코드가 `0`일 수 있습니다.

## 내부 흐름과 한계

`PsList`로 태스크·스레드를 열거 → `task.cgroups`의 Docker cgroup v2 경로와 CSS/kernfs 연결을 교차 확인 → `task.cred`의 다섯 권한 집합과 `real_cred`·namespace·seccomp 등을 독립 수집 → 확인 항목과 원시 근거를 출력합니다. 필드가 없거나 읽히지 않으면 `0`으로 추정하지 않습니다.

EUID 0, 모든 capability, `권한 검토` 표시만으로 호스트 접근·침해·컨테이너 탈출을 판정하지 않습니다. LSM 정책, 실제 seccomp BPF 허용 결과, 파일별 DAC/ACL 접근 판정은 수행하지 않습니다. 연결 목록에서 사라진 모든 은닉 프로세스를 복구하는 스캐너도 아닙니다.

[코드 구성·재사용 출처](ATTRIBUTION.md), [검증 범위](VALIDATION.md)를 참고하세요. 코드 검사는 다음 명령으로 실행합니다.

```powershell
.\.venv\Scripts\python.exe -X utf8 -m unittest discover -s tests -p "test_*.py"
```

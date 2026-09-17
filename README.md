# Docker Memory Analyzer 사용 가이드

Linux 메모리 덤프에서 Docker 관련 흔적, 컨테이너 프로세스, 마운트, 네트워크, 권한을 분석합니다. 이 가이드는 **설치 → 덤프·심볼 준비 → 입력 확인 → 분석 실행 → 결과 확인** 순서로 따라 할 수 있습니다.

## 1. 플러그인 소개

다섯 가지 분석 기능을 Volatility 3의 `linux.docker.Docker` 옵션으로 실행합니다. 분석 목적에 따라 다음 옵션을 선택합니다.

| 확인하려는 내용 | 사용할 옵션 |
|---|---|
| Docker 관련 흔적이 남아 있는가? | `--detector` |
| 어떤 컨테이너와 대표 프로세스가 관측되는가? | `--ps` |
| 컨테이너에서 어떤 경로가 마운트되어 있는가? | `--inspect-mounts` |
| 어떤 소켓·인터페이스·연결 관계가 관측되는가? | `--inspect-networks` |
| 컨테이너 태스크에 어떤 권한이 부여되어 있는가? | `--inspect-caps` |

**한 명령에서는 분석 옵션 하나만 선택합니다.** 각 기능은 독립적으로 실행할 수 있으며, 개별 Python 파일을 직접 실행할 필요는 없습니다.

## 2. 필요한 파일 준비

다음 두 가지 입력 파일을 준비합니다. 덤프와 커널 심볼은 이 저장소에서 제공하지 않습니다.

| 입력 | 준비할 내용 |
|---|---|
| 메모리 덤프 | 분석할 Linux 호스트에서 취득한 메모리 이미지. 예: `memory.lime` |
| Linux 커널 심볼 | 해당 덤프의 커널 빌드와 아키텍처에 맞는 Volatility 3 ISF JSON |

**다섯 기능 모두 Linux 커널 ISF가 필요하며, 별도 Docker ISF는 필요하지 않습니다.** 분석 PC에서 Docker 데몬이나 컨테이너를 실행할 필요도 없습니다.

심볼 파일은 다음과 같이 `linux/` 아래에 배치합니다. 파일명은 원하는 이름을 사용해도 됩니다.

```text
분석자료/
├── memory.lime
└── symbols/
    └── linux/
        └── matching-kernel.json
```

`-s`에는 `symbols/` 디렉터리를 지정합니다. JSON 파일이나 `symbols/linux/`를 직접 지정하지 않습니다. 메모리 덤프는 옮기지 않고 기존 위치에서 읽을 수 있습니다.

심볼은 **메모리를 취득한 호스트의 커널**과 맞아야 합니다. Volatility의 자동 선택에는 버전 번호뿐 아니라 빌드 정보가 포함된 Linux 배너의 정확한 일치가 필요합니다. [Volatility 공식 심볼 안내](https://volatility3.readthedocs.io/en/latest/symbol-tables.html)

심볼이 없다면 아래 설치를 마친 뒤 `banners.Banners`로 대상 커널을 확인하고, 일치하는 디버그 커널로 ISF를 준비합니다. 생성 예제는 4절에 있습니다.

## 3. 요구사항과 설치

| 항목 | 조건 |
|---|---|
| Python | 3.10 이상 권장 |
| Volatility 3 | **2.28.0 이상** |
| 분석 대상 | 다섯 기능을 모두 사용하려면 Linux **x86-64 (`Intel64`)** 덤프 필요. 네트워크·권한 분석은 `Intel64` 대상 |
| 파일 접근 | 덤프·심볼 읽기 권한, 결과 디렉터리 쓰기 권한 |

전체 플러그인이 포함된 `integrate` 브랜치를 내려받습니다. Git과 Python을 준비하고, 분석 PC의 운영체제에 맞는 설치 명령어를 선택합니다. Windows에서 실행하더라도 준비할 입력은 Linux 메모리 덤프와 Linux 커널 심볼입니다.

### macOS / Linux — Bash·Zsh

```bash
git clone --branch integrate https://github.com/KKudroK/docker-memory-analyzer.git
cd docker-memory-analyzer

python3 -m venv .venv
source .venv/bin/activate
python -m pip install -r requirements.txt
```

설치 후 플러그인이 등록되었는지 확인합니다.

```bash
vol -p . linux.docker.Docker --help
```

### Windows — PowerShell

아래 예제는 Windows PowerShell 5.1과 PowerShell 7에서 사용할 수 있는 문법입니다.

```powershell
git clone --branch integrate https://github.com/KKudroK/docker-memory-analyzer.git
Set-Location docker-memory-analyzer

py -3 -m venv .venv
.\.venv\Scripts\python.exe -m pip install -r requirements.txt
.\.venv\Scripts\vol.exe -p . linux.docker.Docker --help
```

`py` 명령이 없고 `python`으로 Python 3을 실행할 수 있다면 `python -m venv .venv`를 사용합니다. Windows 예제는 가상환경의 실행 파일을 직접 호출하므로 별도의 활성화 단계가 필요하지 않습니다. [Python 가상환경 사용 안내](https://docs.python.org/3/library/venv.html#how-venvs-work)

이미 내려받았다면 `requirements.txt`와 `linux/docker.py`가 있는 저장소 디렉터리에서 가상환경 생성부터 진행합니다. Volatility 본체의 파일을 교체할 필요는 없습니다.

도움말에 `--detector`, `--ps`, `--inspect-mounts`, `--inspect-networks`, `--inspect-caps`가 표시되면 다음 단계로 진행합니다. 새 터미널에서는 저장소로 이동한 뒤 macOS/Linux는 `source .venv/bin/activate`와 경로 설정을, Windows는 다음 절의 경로 변수 설정을 다시 진행합니다.

## 4. 처음 분석하기

### 4.1 입력과 출력 경로 설정

저장소 디렉터리에서 다음 변수를 설정합니다. **`DUMP`와 `SYMBOLS`는 실제 파일 위치에 맞게 바꿉니다.** 이후 예제는 같은 터미널에서 실행합니다.

**macOS/Linux — Bash·Zsh:**

```bash
PLUGIN_DIR="$PWD"
DUMP="/absolute/path/to/memory.lime"
SYMBOLS="/absolute/path/to/symbols"
OUTPUT_DIR="$PWD/results"

mkdir -p "$OUTPUT_DIR/detector" "$OUTPUT_DIR/ps" "$OUTPUT_DIR/mounts" \
    "$OUTPUT_DIR/networks" "$OUTPUT_DIR/caps"
```

`PLUGIN_DIR`는 다섯 분석 파일과 `linux/`가 있는 디렉터리입니다. 상위 프로젝트에서 코드가 `plugins/`, 덤프가 `tests/`에 있는 구조라면 위 변수 대신 다음 설정을 사용한 뒤 출력 디렉터리 생성 명령을 실행합니다.

```bash
PLUGIN_DIR="$PWD/plugins"
DUMP="$PWD/tests/memory.lime"
SYMBOLS="$PWD/symbols"
OUTPUT_DIR="$PWD/results"
```

**Windows — PowerShell:**

저장소를 직접 내려받은 경우 아래 설정을 사용합니다. `D:\Memory Dumps`는 분석 자료가 있는 실제 경로로 바꿉니다. 공백이 있는 경로는 예제처럼 따옴표로 감쌉니다.

```powershell
$PROJECT_DIR = (Get-Location).Path
$VOL = Join-Path $PROJECT_DIR '.venv\Scripts\vol.exe'
$PLUGIN_DIR = $PROJECT_DIR
$DUMP = 'D:\Memory Dumps\memory.lime'
$SYMBOLS = 'D:\Memory Dumps\symbols'
$OUTPUT_DIR = Join-Path $PROJECT_DIR 'results'

foreach ($name in 'detector', 'ps', 'mounts', 'networks', 'caps') {
    New-Item -ItemType Directory -Force -Path (Join-Path $OUTPUT_DIR $name) | Out-Null
}
```

상위 프로젝트에 `plugins/`, `tests/`, `symbols/`가 있는 구성이라면 그 프로젝트 디렉터리에서 위 블록을 실행하되 `$PLUGIN_DIR`, `$DUMP`, `$SYMBOLS`를 다음처럼 설정합니다. 가상환경도 해당 프로젝트 디렉터리에 생성되어 있어야 합니다.

```powershell
$PLUGIN_DIR = Join-Path $PROJECT_DIR 'plugins'
$DUMP = Join-Path $PROJECT_DIR 'tests\memory.lime'
$SYMBOLS = Join-Path $PROJECT_DIR 'symbols'
```

`$VOL`은 가상환경의 `vol.exe` 경로입니다. PowerShell에서는 `& $VOL`로 실행합니다. 아래 4.2절 이후의 Bash 예제를 응용할 때도 **`vol`을 `& $VOL`로 바꾸고 줄 끝의 `\`를 제거해 한 줄로 작성**하면 됩니다. 여러 줄로 쓸 때는 PowerShell의 백틱을 사용하며 백틱 뒤에 공백을 넣지 않습니다. [PowerShell 명령어 줄바꿈 안내](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.core/about/about_parsing#line-continuation)

Windows에서 입력을 확인하는 명령은 다음과 같습니다.

```powershell
& $VOL --offline -f "$DUMP" banners.Banners
& $VOL --offline -p "$PLUGIN_DIR" -s "$SYMBOLS" -f "$DUMP" linux.pslist.PsList
```

이어서 필요한 분석을 선택해 실행합니다. 다섯 기능의 기본 PowerShell 명령어는 다음과 같습니다.

```powershell
& $VOL --offline -p "$PLUGIN_DIR" -s "$SYMBOLS" -f "$DUMP" -o "$OUTPUT_DIR\detector" -r pretty linux.docker.Docker --detector
& $VOL --offline -p "$PLUGIN_DIR" -s "$SYMBOLS" -f "$DUMP" -o "$OUTPUT_DIR\ps" -r pretty linux.docker.Docker --ps
& $VOL --offline -p "$PLUGIN_DIR" -s "$SYMBOLS" -f "$DUMP" -o "$OUTPUT_DIR\mounts" -r pretty linux.docker.Docker --inspect-mounts --extended
& $VOL --offline -p "$PLUGIN_DIR" -s "$SYMBOLS" -f "$DUMP" -o "$OUTPUT_DIR\networks" -r pretty linux.docker.Docker --inspect-networks --dump-evidence
& $VOL --offline -p "$PLUGIN_DIR" -s "$SYMBOLS" -f "$DUMP" -o "$OUTPUT_DIR\caps" -r pretty linux.docker.Docker --inspect-caps --view analyst
```

실행 직후 종료 코드는 PowerShell에서 `$LASTEXITCODE`로 확인합니다.

### 4.2 덤프와 심볼 확인

먼저 덤프의 커널 배너를 확인합니다. 이 명령은 커널 ISF 없이 실행할 수 있습니다.

```bash
vol --offline -f "$DUMP" banners.Banners
```

준비한 ISF가 인식되는지 기본 Linux 프로세스 목록으로 확인합니다.

```bash
vol --offline -p "$PLUGIN_DIR" -s "$SYMBOLS" -f "$DUMP" \
    linux.pslist.PsList
```

PID와 프로세스 이름이 표시되면 기본 커널 계층과 심볼을 읽을 수 있는 상태입니다. 이는 모든 분석 필드를 읽을 수 있다는 보장은 아니므로 이후 분석의 경고도 확인합니다. `kernel.layer_name` 또는 `kernel.symbol_table_name` 요구사항 오류가 나오면 덤프 경로, 심볼 배치, 커널 빌드 일치 여부를 먼저 확인합니다.

<details>
<summary>커널 ISF가 없을 때: 디버그 커널에서 생성</summary>

덤프의 배너와 일치하는 디버그 정보 포함 `vmlinux`를 준비합니다. [dwarf2json](https://github.com/volatilityfoundation/dwarf2json)을 빌드해 실행 파일을 준비한 뒤 아래 경로를 실제 위치로 바꿔 실행합니다. `vmlinux`는 분석 PC의 커널이 아닌 덤프 대상 커널의 파일이어야 합니다.

```bash
mkdir -p "$SYMBOLS/linux"
/path/to/dwarf2json linux --elf /path/to/debug/vmlinux \
    > "$SYMBOLS/linux/matching-kernel.json"
```

생성 후 위 `linux.pslist.PsList` 명령을 다시 실행합니다. 이미 일치하는 ISF가 있다면 이 과정은 생략합니다.

</details>

### 4.3 Docker 흔적 확인

```bash
vol --offline -p "$PLUGIN_DIR" -s "$SYMBOLS" -f "$DUMP" \
    -o "$OUTPUT_DIR/detector" -r pretty \
    linux.docker.Docker --detector
```

터미널의 `Overall`과 개별 검사 행을 확인합니다. 상세 근거는 `$OUTPUT_DIR/detector/detector_evidence.json`에 저장됩니다. `FOUND`는 해당 흔적이 관측되었다는 뜻이며, `PARTIAL`이나 `UNKNOWN`이 있으면 읽기 오류와 수집 범위를 함께 확인합니다.

### 4.4 컨테이너와 대표 프로세스 확인

```bash
vol --offline -p "$PLUGIN_DIR" -s "$SYMBOLS" -f "$DUMP" \
    -o "$OUTPUT_DIR/ps" -r pretty \
    linux.docker.Docker --ps
```

출력에서 분석할 컨테이너의 **`Container ID`와 `Host PID`**를 확인합니다. 이후 마운트 분석에는 호스트 PID를, 네트워크·권한 분석에는 해당 분석에서도 관측되는 ID나 고유 접두사를 사용합니다. 각 기능의 수집 범위가 달라 같은 대상이 항상 모든 기능에 나타나는 것은 아닙니다.

### 4.5 필요한 상세 분석 실행

마운트를 확인합니다.

```bash
vol --offline -p "$PLUGIN_DIR" -s "$SYMBOLS" -f "$DUMP" \
    -o "$OUTPUT_DIR/mounts" -r pretty \
    linux.docker.Docker --inspect-mounts --extended
```

컨테이너 소켓과 근거 파일을 확인합니다.

```bash
vol --offline -p "$PLUGIN_DIR" -s "$SYMBOLS" -f "$DUMP" \
    -o "$OUTPUT_DIR/networks" -r pretty \
    linux.docker.Docker --inspect-networks --dump-evidence
```

권한을 분석용 요약으로 확인합니다.

```bash
vol --offline -p "$PLUGIN_DIR" -s "$SYMBOLS" -f "$DUMP" \
    -o "$OUTPUT_DIR/caps" -r pretty \
    linux.docker.Docker --inspect-caps --view analyst
```

### 4.6 표와 로그 저장

`-o`는 플러그인이 만드는 근거 파일의 저장 위치입니다. 화면의 표를 저장하려면 리디렉션을 사용합니다. 다음은 마운트 표를 JSON으로, 진행 메시지와 경고를 로그로 저장하는 예입니다.

```bash
vol --offline -p "$PLUGIN_DIR" -s "$SYMBOLS" -f "$DUMP" \
    -o "$OUTPUT_DIR/mounts" -r json \
    linux.docker.Docker --inspect-mounts --extended \
    > "$OUTPUT_DIR/mounts/rows.json" 2> "$OUTPUT_DIR/mounts/run.log"
```

실행 직후 종료 코드와 로그를 확인하고, 생성된 표를 엽니다.

```bash
echo $?
cat "$OUTPUT_DIR/mounts/run.log"
python -m json.tool "$OUTPUT_DIR/mounts/rows.json"
```

종료 코드 `0`은 명령이 완료되었다는 뜻입니다. 일부 항목을 읽지 못해도 분석이 완료될 수 있으므로 경고와 수집 상태를 함께 봅니다. 표를 텍스트로 보관하려면 `-r pretty`로 실행하고 `> 결과파일.txt`로 저장합니다.

| 분석 | `-o` 아래에 생성되는 파일 |
|---|---|
| detector | `detector_evidence.json` |
| ps | `ps_evidence.json` |
| inspect-mounts | 별도 근거 파일 없음. 표를 직접 저장 |
| inspect-networks | `--dump-evidence`를 지정하면 `network_evidence.json` |
| inspect-caps | `containercaps-audit.json`; `--view analyst`이면 `containercaps-analyst.json` 추가 |

표의 JSON과 근거 JSON은 서로 다릅니다. 값을 읽은 출처나 오류를 확인할 때는 근거 파일을 사용합니다. 재분석 결과를 구분하려면 `OUTPUT_DIR`를 새 디렉터리로 바꾸고 4.1의 디렉터리 생성 명령을 다시 실행합니다.

### 공통 명령어 규칙

| 인자 | 용도 |
|---|---|
| `--offline` | 준비한 로컬 심볼로 분석 |
| `-p "$PLUGIN_DIR"` | 플러그인 코드 경로 |
| `-s "$SYMBOLS"` | `linux/`를 포함하는 심볼 디렉터리 |
| `-f "$DUMP"` | 메모리 덤프 파일 |
| `-o 경로` | 미리 생성한 결과 디렉터리 |
| `-r pretty` / `-r json` | 표의 출력 형식 |

공통 인자는 **`linux.docker.Docker` 앞에**, 분석 옵션은 **뒤에** 작성합니다. 예를 들어 `--ps --detector`를 한 명령에 넣으면 오류가 발생합니다.

## 5. 목적별 옵션 사용법

아래 예제는 4.1에서 설정한 경로 변수를 사용합니다. 예제 PID `4508`, `4563`과 ID 접두사 `abcdef123456`, `123456abcdef`는 **실제 분석에서 확인한 값으로 교체**합니다.

### Docker 흔적 탐지: `--detector`

Docker 형태의 인터페이스 이름, veth 장치, Overlay 마운트, containerd-shim 및 `moby` 런타임 namespace 흔적을 확인할 때 사용합니다.

순회 한도를 지정하려면 다음과 같이 실행합니다.

```bash
vol --offline -p "$PLUGIN_DIR" -s "$SYMBOLS" -f "$DUMP" \
    -o "$OUTPUT_DIR/detector" -r pretty \
    linux.docker.Docker --detector --limit 100000
```

`--limit`의 기본값은 `100000`이며 `1`~`1000000`을 허용합니다. 개별 객체 순회의 노드 수 제한으로, 컨테이너 개수 제한이 아닙니다.

| 결과 | 읽는 방법 |
|---|---|
| `FOUND` | 개별 검사에서 일치하는 흔적 관측 |
| `NOT_OBSERVED` | 완료된 탐색 범위에서 일치 흔적 미관측 |
| `UNKNOWN` | 일치 흔적을 찾지 못했고 탐색도 불완전함 |
| `COMPLETE` / `PARTIAL` | 구현된 탐색 범위의 완료 여부 |
| `DOCKER_EVIDENCE` | 전체 요약에서 `moby` shim이 관측됨 |
| `HINTS_ONLY` | 전체 요약에서 그 외 컨테이너 관련 단서가 관측됨 |

표의 `Count`는 관측 수입니다. 컨테이너 수나 Docker 실행 상태로 해석하지 않습니다.

### 컨테이너 조회: `--ps`

컨테이너별 대표 프로세스, 시작 시각, UID와 유효 capabilities를 먼저 확인할 때 사용합니다. 명령은 4.4와 같으며 추가 옵션은 없습니다.

| 출력 항목 | 확인할 내용 |
|---|---|
| `Container ID` | 컨테이너 전체 ID |
| `Command`, `Host PID` | 대표 프로세스의 이름과 호스트 PID |
| `Process Start UTC` | 대표 프로세스 시작 시각 |
| `Effective UID`, `Effective Caps` | 대표 프로세스의 유효 UID와 capabilities |
| `Configured Privileged` | 캐시의 `hostconfig.json`에서 복구한 `Privileged` 설정값 |
| `Representative`, `Association`, `Sources` | 대표 선정 상태와 컨테이너 연결 근거 |

`-`는 미확인 값이며 `False`와 다릅니다. `Process Start UTC`는 컨테이너 생성 시각과 구분하고, `Configured Privileged`는 캐시에 남은 값이라는 점을 고려합니다. 현재 `--ps`는 `Running`, `Paused` 같은 라이프사이클 상태를 표시하지 않습니다.

### 마운트 확인: `--inspect-mounts`

컨테이너 경로가 어떤 호스트 경로에 연결되어 있는지, 마운트가 읽기 전용인지 확인할 때 사용합니다. 옵션 없이 실행하면 인식 가능한 컨테이너 대상을 자동 선택합니다.

특정 프로세스의 마운트만 보려면 `--ps` 등에서 확인한 **호스트 PID**를 지정합니다.

```bash
vol --offline -p "$PLUGIN_DIR" -s "$SYMBOLS" -f "$DUMP" \
    -o "$OUTPUT_DIR/mounts" -r pretty \
    linux.docker.Docker --inspect-mounts --pids 4508 4563 --extended
```

| 추가 옵션 | 용도 |
|---|---|
| `--pids PID [PID ...]` | 양의 정수 호스트 PID를 하나 이상 지정하여 대상 선택 |
| `--extended` | `Mount ID`, `Read Status`, `Host Path Status` 열 추가 |
| `--mounts-extended` | `--extended`의 호환 별칭 |

`Container Path`, `Host Paths`, `FS Type`, `RO/RW`를 함께 확인합니다. 호스트 경로가 비어 있거나 여러 개로 복구되면 확장 열의 상태를 확인합니다. `RO/RW`는 마운트 모드이며 해당 프로세스의 최종 파일 접근 권한 전체를 뜻하지 않습니다.

### 네트워크 확인: `--inspect-networks`

소켓과 보유 프로세스를 보려면 기본 보기인 `sockets`를 사용합니다. 다른 정보를 확인하려면 `--view`를 바꿉니다.

| `--view` 값 | 확인할 내용 |
|---|---|
| `sockets` | 기본값. FD에서 읽은 소켓, 프로세스, 주소, 상태 |
| `containers` | 관측된 컨테이너별 태스크·프로세스·소켓 수와 NetNS |
| `interfaces` | 컨테이너 namespace의 인터페이스, IP, MAC |
| `relations` | 공유 소켓 및 직접 연결 근거에 따른 관계 |
| `conntrack` | 연결 추적 항목의 주소, 프로토콜, NAT 정보 |
| `diagnostics` | 모든 네트워크 수집기를 실행하여 오류와 미지원 항목 확인 |

먼저 네트워크 분석에서 관측된 컨테이너 ID를 확인합니다.

```bash
vol --offline -p "$PLUGIN_DIR" -s "$SYMBOLS" -f "$DUMP" \
    -o "$OUTPUT_DIR/networks" -r pretty \
    linux.docker.Docker --inspect-networks --view containers
```

확인한 컨테이너의 인터페이스와 근거를 저장합니다.

```bash
vol --offline -p "$PLUGIN_DIR" -s "$SYMBOLS" -f "$DUMP" \
    -o "$OUTPUT_DIR/networks" -r pretty \
    linux.docker.Docker --inspect-networks --view interfaces \
    --container abcdef123456 --dump-evidence
```

두 컨테이너의 소켓을 함께 보려면 ID 접두사를 공백으로 구분합니다.

```bash
vol --offline -p "$PLUGIN_DIR" -s "$SYMBOLS" -f "$DUMP" \
    -o "$OUTPUT_DIR/networks" -r pretty \
    linux.docker.Docker --inspect-networks --container abcdef123456 123456abcdef
```

각 접두사는 이 분석에서 관측한 ID 중 하나와 고유하게 일치해야 합니다. `--container`는 화면 필터이며, 근거 JSON에는 선택하지 않은 컨테이너나 호스트 정보도 포함될 수 있습니다.

소켓 표가 비어 있거나 일부 정보가 누락되면 다음 명령으로 수집 상태를 확인합니다.

```bash
vol --offline -p "$PLUGIN_DIR" -s "$SYMBOLS" -f "$DUMP" \
    -o "$OUTPUT_DIR/networks" -r pretty \
    linux.docker.Docker --inspect-networks --view diagnostics --dump-evidence
```

`--dump-evidence`는 선택한 보기의 근거를 저장하는 옵션입니다. 전체 수집 점검에는 `--view diagnostics`를 함께 지정합니다. 진단 화면은 전체 수집 문제를 표시하며 컨테이너별 화면 필터로 제한되지 않습니다.

### 권한 확인: `--inspect-caps`

컨테이너 태스크의 capabilities, UID, user namespace, seccomp, `no_new_privs`를 확인할 때 사용합니다. 기본값은 스레드를 포함하는 `raw` 보기입니다.

원시 관측 열을 확인합니다.

```bash
vol --offline -p "$PLUGIN_DIR" -s "$SYMBOLS" -f "$DUMP" \
    -o "$OUTPUT_DIR/caps" -r pretty \
    linux.docker.Docker --inspect-caps
```

특정 컨테이너의 프로세스 리더만 분석용 요약으로 확인합니다.

```bash
vol --offline -p "$PLUGIN_DIR" -s "$SYMBOLS" -f "$DUMP" \
    -o "$OUTPUT_DIR/caps" -r pretty \
    linux.docker.Docker --inspect-caps --container abcdef123456 --leaders --view analyst
```

| 추가 옵션 | 용도 |
|---|---|
| `--view raw` | 기본값. 태스크별 관측값과 capability 집합 |
| `--view analyst` | 분석용 요약과 별도 analyst JSON 생성 |
| `--container ID` | 6~64자리 16진수 ID 또는 고유 접두사 **하나**로 표시 대상 제한 |
| `--leaders` | 프로세스 리더만 수집 |
| `--unresolved` | Docker 소속을 판독하지 못한 태스크를 별도로 표시 |

컨테이너 소속을 읽지 못한 태스크를 점검하려면 다음과 같이 실행합니다.

```bash
vol --offline -p "$PLUGIN_DIR" -s "$SYMBOLS" -f "$DUMP" \
    -o "$OUTPUT_DIR/caps" -r pretty \
    linux.docker.Docker --inspect-caps --unresolved
```

`--unresolved`와 `--container`는 함께 사용할 수 없습니다. `--unresolved`에 표시된 태스크는 Docker 소속이 확인된 대상이 아닙니다. 화면 필터와 별개로 감사 JSON에는 수집 근거가 남습니다.

권한은 user namespace와 함께 해석합니다. Capability 값만으로 Docker의 `--privileged` 설정을 확정하지 않습니다.

### 오류가 발생할 때

| 증상 | 확인·조치 |
|---|---|
| `vol: command not found` | 가상환경을 활성화하고 `python -m pip install -r requirements.txt` 실행 |
| `linux.docker.Docker`를 찾지 못함 | `PLUGIN_DIR` 아래에 다섯 분석 파일과 `linux/docker.py`가 있는지 확인 |
| `kernel.layer_name`, `kernel.symbol_table_name` 요구사항 오류 | 4.2의 배너·프로세스 목록 확인부터 다시 진행 |
| 출력 디렉터리가 없다는 오류 | 4.1의 `mkdir -p` 명령 실행 |
| 분석 옵션 또는 추가 옵션 조합 오류 | 분석 하나만 선택하고 해당 기능에 맞는 추가 옵션 사용 |
| 컨테이너 접두사가 없거나 여러 ID와 일치 | 필터 없이 해당 기능을 실행해 ID를 확인하고 더 긴 접두사 또는 전체 ID 사용 |
| 결과가 없거나 일부 필드가 `-` | 로그와 근거 파일의 수집 상태 확인. 네트워크는 `--view diagnostics --dump-evidence` 실행 |

추가 진단 로그가 필요하면 공통 인자에 `-vvv`를 추가합니다. 다음 예제는 진단 표와 로그를 파일로 저장합니다.

```bash
vol -vvv --offline -p "$PLUGIN_DIR" -s "$SYMBOLS" -f "$DUMP" \
    -o "$OUTPUT_DIR/networks" -r pretty \
    linux.docker.Docker --inspect-networks --view diagnostics --dump-evidence \
    > "$OUTPUT_DIR/networks/diagnostics.txt" 2> "$OUTPUT_DIR/networks/debug.log"
```

빈 결과만으로 컨테이너나 활동이 없었다고 판단하지 않습니다. 덤프에 남은 데이터, 심볼로 읽을 수 있는 구조, 각 기능의 수집 범위를 함께 확인합니다.

---

[MIT License](LICENSE)

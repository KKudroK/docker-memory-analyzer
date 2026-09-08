# Docker Container State Identifier

Docker 컨테이너의 상태를 수집 자료와 Linux 메모리 덤프를 이용해 식별하는 포렌식 보조 도구


> **Docker 메타데이터 + 수집된 cgroup/proc 상태 + LiME 문자열 교차검증**

`created`, `running`, `paused`, `restarting`, `exited`, `dead`, `removing` 상태를 구분하고, 판정에 사용한 증거와 신뢰도를 터미널·Markdown·JSON으로 출력합니다.

## 분석 방식

### 1. Docker 메타데이터

- `docker inspect`의 `State.Status`
- `Running`, `Paused`, `Restarting`, `Dead` 플래그
- 컨테이너 PID, exit code, 시작·종료 시각
- `docker ps`의 `State`와 `Status`

Docker daemon이 기록한 상태를 가장 중요한 판정 증거로 사용합니다.

### 2. 수집된 cgroup/proc 상태

- `cgroup.freeze`
- `cgroup.events`의 `frozen`, `populated`
- `cgroup.procs`
- `/proc/status`, `/proc/cgroup`
- 호스트 프로세스 및 containerd shim 정보

예를 들어 `cgroup.freeze=1`, `frozen=1`, 컨테이너 PID 존재가 함께 확인되면 `paused` 상태를 강하게 지지합니다. `/proc/status`의 `S (sleeping)`만으로는 `running`과 `paused`를 구분하지 않습니다.

### 3. LiME 문자열 교차검증

LiME/raw 메모리 전체를 순차 탐색하여 다음 문자열을 찾습니다.

- 전체·축약 컨테이너 ID
- 컨테이너 이름
- `docker-<container-id>.scope`
- JSON 형태의 `Status`, `State`, `Paused` 값
- cgroup freezer 관련 문자열

LiME 헤더와 물리 메모리 구간을 파싱하여 각 문자열의 파일 오프셋과 물리주소를 계산하고, 이미지의 SHA-256도 함께 기록합니다.

## 분석 범위와 한계

LiME 문자열은 `dockerd`·`containerd` 힙, Docker API 버퍼, 로그, 파일 페이지 캐시 또는 해제된 과거 메모리에서 발견될 수 있습니다. 따라서 문자열 발견 횟수만으로 컨테이너 상태를 확정하지 않으며 Docker 및 cgroup/proc 증거를 보조하는 교차증거로만 사용합니다.

현재 버전은 LiME 안의 Linux `task_struct`, `css_set`, namespace, cgroup 커널 구조체를 심볼 기반으로 직접 복원하는 도구가 아닙니다. 해당 분석에는 대상 커널과 정확히 일치하는 `vmlinux`, `System.map`, BTF/DWARF 또는 Volatility ISF가 추가로 필요합니다.

## 요구 사항

- Windows PowerShell
- Python 3.9 이상
- 외부 Python 패키지 불필요

## 사용 방법

*powershell 실행정책 차단 풀기 필요
```
powershell.exe -NoProfile -ExecutionPolicy Bypass -File ".\실행.ps1" -CasePath "."
```

PowerShell에서 도구 폴더로 이동합니다.

현재 케이스의 메타데이터와 메모리를 모두 분석합니다.

```powershell
.\실행.ps1
```

메모리 스캔 없이 수집된 메타데이터만 분석합니다.

```powershell
.\실행.ps1 -NoMemory
```

다른 케이스 폴더를 분석합니다. 폴더에서 가장 큰 `.lime`, `.raw`, `.mem` 등의 파일을 자동 선택합니다.

```powershell
.\실행.ps1 -CasePath 'D:\case\S01_created'
```

메모리 파일을 직접 지정할 수도 있습니다.

```powershell
.\실행.ps1 `
  -CasePath 'D:\case\S01_created' `
  -MemoryPath 'D:\case\S01_created\memory.lime'
```

Python으로 직접 실행하려면 다음 명령을 사용합니다.

```powershell
python .\docker_state_identifier.py 'D:\case\S01_created' --output '.\결과'
```

## 결과 파일

- `결과/상태식별_보고서.md`: 사람이 읽는 최종 판정과 증거
- `결과/상태식별_결과.json`: 상태별 점수, 전체 증거 및 메모리 위치

원본 덤프와 기존 수집 파일은 읽기 전용으로 사용하며 수정하지 않습니다. 메모리 문맥에 포함된 비밀번호, secret, token, API key 값은 결과에서 자동으로 마스킹합니다.

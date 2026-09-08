# Container State Analyzer

Linux 물리 메모리에서 복원한 Docker 아티팩트를 계층별로 조인해 `created`, `running`, `paused`, `restarting`, `exited`, `removing`, `dead` 후보를 평가하는 실험용 도구입니다.

이 도구는 상태 문자열 하나를 정답으로 믿지 않습니다. `dockerd Go heap`의 상태 플래그를 Runtime 주장으로 두고, `task_struct`, cgroup v2, freezer, namespace/network 같은 Kernel 관측과 대조합니다. 수집 실패는 `UNKNOWN`, 탐색에 성공했지만 대상이 없는 경우는 `ABSENT`로 분리합니다.

## 지금 구현된 범위

- 설계사양 v2의 4분류: `MATCH / MISMATCH / ABSENT / UNKNOWN`
- 7개 상태의 후보 순위, 모순에 의한 배제, `confirmed / deferred` 판정
- 상관된 아티팩트를 한 묶음으로 계산해 중복 가산 방지
- J1, J3, J4, J5, J16 계층 간 조인 검사
- 아티팩트 묶음별, 계층별, Runtime 변조 시나리오별 ablation
- 목적별 우선순위: 상태 판별, ID 복구, 변조 탐지, 행위 복원
- JSON 결과와 단일 HTML 보고서
- Google Drive Round2의 `validation/` 결과 폴더 직접 입력

원본 `.lime`를 이 프로그램 하나가 바로 파싱하는 단계는 아직 아닙니다. 현재 입력은 Round2에서 원본 덤프로부터 이미 추출해 둔 `verification.json`, `tasks.json`, `cgroups.json`, `networks.json`입니다. 즉 판별 엔진은 실제 메모리 추출 결과를 쓰지만, 덤프 수집기 자체는 분리되어 있습니다.

## 1분 실행

PowerShell에서:

```powershell
cd C:\Users\kar72\Desktop\Project\container-state-analyzer
py -m venv .venv
.\.venv\Scripts\python.exe -m pip install -e .
.\.venv\Scripts\container-state.exe demo --output-dir .\output\round2-demo
```

결과:

- `output/round2-demo/analysis.json`: 상태 후보, 조건식 결과, 조인 결과
- `output/round2-demo/priority.json`: ablation 기반 우선순위와 변조 시나리오
- `output/round2-demo/report.html`: 사람이 읽는 흑백 보고서
- `output/round2-demo/observations.json`: 정규화된 입력

`demo`는 Google Drive Round2의 검증 파일에서 확인한 핵심 값을 정규화한 작은 재현 데이터입니다. 대용량 덤프나 환경변수 원문은 저장소에 포함하지 않습니다.

## 내려받은 Round2 전체로 실행

Round2 루트의 형태는 아래와 같아야 합니다.

```text
Round2/
├─ S01_created/validation/verification.json
├─ S02_running/validation/{verification,tasks,cgroups,networks}.json
├─ S03_paused/validation/{verification,tasks,cgroups,networks}.json
├─ S04_restarting/validation/{verification,tasks,cgroups,networks}.json
├─ S05_exited/validation/{verification,tasks,cgroups,networks}.json
├─ S06_removing/validation/{verification,tasks,cgroups,networks}.json
└─ S07_dead/validation/{verification,tasks,cgroups,networks}.json
```

```powershell
.\.venv\Scripts\container-state.exe round2 `
  --root "D:\evidence\Round2" `
  --output-dir .\output\round2
```

같은 실행을 래퍼로 줄이면:

```powershell
.\scripts\run-round2.ps1 -Round2Root "D:\evidence\Round2"
```

기본 정책은 `memory-only`입니다. 각 상태 폴더의 `config.v2.json`, `state_before.json`은 수집 당시 호스트에서 복사한 정답지이므로 판별 입력에 섞지 않습니다.

파일 메타데이터와 Go heap을 일부러 함께 비교하고 싶을 때만 다음 옵션을 사용합니다.

```powershell
.\.venv\Scripts\container-state.exe round2 `
  --root "D:\evidence\Round2" `
  --include-live-sidecars `
  --output-dir .\output\round2-mixed
```

이때 J16이 `config.v2.json`의 State와 Go heap의 State를 비교합니다. Round2 `S07_dead`처럼 파일의 `Dead=false`와 heap의 `Dead=true`가 어긋나는 경우 `MISMATCH`가 남습니다.

## 상태 판정 방식

각 조건식은 `artifact`, `predicate`, `strength`, `valid_when`, `polarity`, `group`을 가집니다.

- `support + MATCH`: 후보를 지지합니다.
- `contradiction + MATCH`: 정상 불일치 원인을 먼저 배제한 뒤 후보를 제외합니다.
- `UNKNOWN`: 지지나 모순으로 계산하지 않습니다.
- 같은 사실을 보는 `live task count`, `task.mm`, `cgroup populated`는 묶음 하나로 계산합니다.
- 확정에는 decisive 근거, 모순 없음, 단독 1위, 필수 구분 조건 확인이 필요합니다.

결과의 `predicted_state`는 최상위 가설이고 `decision=deferred`는 그 가설을 확정할 수 없다는 뜻입니다. 보류는 오류가 아니라 정상적인 포렌식 결론입니다.

## 우선순위 읽는 법

`priority.json`의 순위는 확률이나 임의 가중합이 아닙니다.

1. 아티팩트 묶음을 하나씩 제거합니다.
2. Round2의 Top-1 정확도와 확정률이 얼마나 떨어지는지 측정합니다.
3. 동률이면 선택한 목적의 상/중/하 등급과 판별력, 수집 성공률, 조작 저항성, 추출 비용을 순서대로 비교합니다.

데이터가 상태별 1개뿐이므로 이 값은 최종 통계가 아니라 다음 실험의 수집 순서를 정하는 기준입니다. 반복 덤프가 쌓이면 같은 명령으로 다시 측정해야 합니다.

목적 변경 예시:

```powershell
.\.venv\Scripts\container-state.exe demo --objective tamper_detection
.\.venv\Scripts\container-state.exe demo --objective identifier_recovery
```

## 자체 Observation으로 분석

`demo` 실행이 만든 `observations.json`을 복사해 값을 추가하거나 일부 아티팩트를 `unknown`으로 바꾼 뒤 다시 실행할 수 있습니다.

```powershell
.\.venv\Scripts\container-state.exe analyze `
  --input .\output\round2-demo\observations.json `
  --output-dir .\output\my-experiment
```

Observation 최소 형식:

```json
{
  "artifact": "kernel.live_task_count",
  "layer": "kernel",
  "availability": "present",
  "value": 4,
  "collector": "my.task_collector",
  "group": "kernel_execution"
}
```

## 테스트

```powershell
.\.venv\Scripts\python.exe -m unittest discover -s tests -v
```

## Git에 올릴 때

`.gitignore`가 `.lime`, raw memory, `evidence/`, 생성된 `output/`을 제외합니다. 코드와 규칙, 테스트만 올라가므로 수 GB 덤프나 민감한 환경변수가 실수로 커밋되지 않습니다.

# 컨테이너 상태 식별

dockerd·containerd·shim 후보 및 커널 증거를 결합해 컨테이너 상태와 판단 근거를 출력합니다.

저장소 루트에서:

```powershell
python state_identification/src/analyze.py dumps/sample.lime --symbols symbols -o outputs/state/state_results.json
```

디렉터리 입력도 지원합니다. `--verbose`는 상세 출력, `--no-events`는 이벤트 수집 생략입니다. JSON에는 상태 후보·충돌·판단 근거·파싱 오류도 남습니다.

기존 S04 결과의 필드 발췌(터미널 원문은 아님):

```text
container_id : 047680e2dcd25e49834d0c1c4e91705c00accf2f3bd1f31be26a8982deca6346
container_name : /recon_s04_multi_multi_0
status : Running
state_source : dockerd.heap
```

## 적용 범위

사용자 공간 판독기는 Go amd64 및 확인된 런타임 레이아웃에 의존합니다. 임의 Docker/containerd 버전의 범용 지원으로 해석하지 마세요. 선택적 ELF 기반 레이아웃 검증에는 대상과 일치하는 dockerd 바이너리를 이 기능 폴더의 `tools/binaries/dockerd`에 준비해야 합니다. 결과의 레이아웃 근거와 오류를 확인하세요.

```powershell
python state_identification/scripts/test_forensic_core.py
```

코어 회귀 테스트 30개를 통과했습니다. 이번 배포에서는 전체 상태/재구성 덤프를 재분석하지 않았으며 예시는 기존 결과입니다. 독립 실행을 위해 공통 엔진과 재구성 의존 모듈도 포함합니다.

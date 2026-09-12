# 컨테이너 실행 문맥 재구성

상태에 더해 프로세스, 설정, 마운트, 소켓·IPC와 메모리에 남은 파일 아티팩트를 연결합니다. 전체 디스크/파일시스템 복원이 아니며 파일 누락 범위와 파싱 오류를 기록합니다.

저장소 루트에서:

```powershell
python reconstruction/src/reconstruction.py dumps/sample.lime --symbols symbols -o outputs/reconstruction/reconstruction.json
```

디렉터리 입력과 `--verbose`를 지원합니다. JSON의 컨테이너별 `processes`, `mounts`, `cached_files`, `artifact_inventory` 등에 증거가 저장됩니다.

기존 S04 결과의 식별 필드 발췌(전체 출력은 아님):

```text
047680e2dcd2  /recon_s04_multi_multi_0  Running  dockerd.heap
ec1b0459193d  /recon_s04_multi_multi_1  Running  dockerd.heap
```

실제 출력은 컨테이너별 설정과 복구 아티팩트를 이어서 보여줍니다. 빈 필드를 원래 없던 것으로 단정하지 말고 파싱 오류와 복구 범위를 확인하세요.

Go amd64 레이아웃 제약과 선택적 일치 ELF 준비 방법은 [상태 식별 README](../state_identification/README.md#적용-범위)와 같습니다. 독립 실행을 위해 같은 공통 엔진을 포함합니다.

```powershell
python reconstruction/scripts/test_forensic_core.py
```

이번 배포는 코어 테스트 30개와 진입점을 검증했습니다. 예시는 기존 결과이며 이번에 전체 재구성 덤프를 다시 분석한 것은 아닙니다.

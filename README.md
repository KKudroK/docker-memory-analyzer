# Docker Memory Analyzer

Linux 메모리 이미지에서 Docker 상태, 실행 문맥, 네트워크를 분석합니다.

| 기능 | 실행법 및 결과 예시 |
|---|---|
| 상태 식별 | [state_identification](state_identification/README.md) |
| 실행 문맥 재구성 | [reconstruction](reconstruction/README.md) |
| Volatility 플러그인 | [pluginss](plugins/README.md) |

Python 3.10 이상, Volatility 3 **2.28.0** 기준입니다. 저장소 루트에서:

```powershell
python -m venv .venv
.venv/Scripts/Activate.ps1
python -m pip install -r requirements.txt
```

덤프와 해당 커널에 정확히 대응하는 Linux ISF는 별도로 준비합니다. README의 `dumps/sample.lime`과 `symbols`는 사용자 입력 경로입니다. 덤프·심볼·대상 런타임 바이너리는 배포하지 않습니다.

상태 식별과 재구성은 공통 수집 엔진을 사용하므로 각각 독립 실행할 수 있도록 공통 소스를 포함합니다. 두 폴더를 동시에 PYTHONPATH에 넣지 말고 해당 진입 스크립트를 실행하세요. 네트워크 플러그인은 두 기능에 의존하지 않습니다.

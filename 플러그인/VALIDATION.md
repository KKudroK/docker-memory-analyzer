# 배포 검증

2026-09-13, ContainerCaps 1.4.0 배포 폴더의 코드로 확인했습니다.

- 기존 개발 소스와 배포 소스 각각 **131개 회귀 테스트 통과**. 추가한 한국어 주석 전후의 Python AST가 동일합니다.
- 스키마 준비 도우미의 원본 확인·백업·반복 실행·복원·변조 및 가상환경 경계 테스트 **9개 통과**.
- 새 Python 3.12.14 가상환경에 PyPI `volatility3==2.28.0`, `pefile==2024.8.26`, `jsonschema==4.26.0`을 설치했습니다.
- 제공 ISF는 공식 스키마에서 `btf`·`symdb` 메타데이터 때문에 실패했으며, 준비 도우미 적용 후 실제 `schemas.validate(..., use_cache=False)`를 통과했습니다. 검증기를 비활성화하지 않았습니다.
- 빈 심볼 캐시에서 `containercaps.ContainerCaps --view analyst`를 실제 실행했습니다. **298개 태스크 열거 / 5개 컨테이너 / 컨테이너 태스크 5개 / 오류·부분 관측 0**, 종료 코드 0입니다.
- 전체 구성원 관측을 이전에 검증한 1.4.0 실행과 대조했고 모두 일치했습니다. 배포 코드 해시와 실제 실행 결과는 [examples/verification.json](examples/verification.json), 터미널 출력은 [examples/native-output.txt](examples/native-output.txt)에 있습니다.
- 덤프·심볼은 압축 전 원본, gzip 파일, 복원 스트림의 크기·SHA-256을 확인했습니다. [evidence/manifest.json](evidence/manifest.json)에 기록했습니다.

테스트 명령:

```powershell
.\.venv\Scripts\python.exe -X utf8 -m unittest discover -s tests -p "test_*.py"
.\.venv\Scripts\python.exe -X utf8 -m unittest discover -s tools -p "test_*.py"
```

다른 실제 커널·Docker 버전의 덤프를 검증한 것은 아닙니다. 여러 스레드의 권한 차이, 하위 user namespace 및 다른 구조 배치는 합성 테스트 범위입니다. 실제 실험의 각 컨테이너에는 `sleep` 태스크 하나만 있습니다.

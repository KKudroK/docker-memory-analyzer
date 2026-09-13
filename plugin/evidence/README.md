# 다섯 컨테이너 실험 자료

실험 덤프와 일치하는 심볼은 [ContainerCaps 1.4.0 릴리스](https://github.com/KKudroK/docker-memory-analyzer/releases/tag/containercaps-v1.4.0)의 Assets에서 받습니다. Git 저장소에는 크기와 SHA-256을 기록한 [manifest.json](manifest.json)을 둡니다.

| 다운로드 파일 | 압축 크기 | 복원 후 |
|---|---:|---|
| [memory.lime.gz](https://github.com/KKudroK/docker-memory-analyzer/releases/download/containercaps-v1.4.0/memory.lime.gz) | 1,160,793,053 bytes | `memory.lime` — 4,239,450,044 bytes |
| [ubuntu-7.0.0-31-btf.json.gz](https://github.com/KKudroK/docker-memory-analyzer/releases/download/containercaps-v1.4.0/ubuntu-7.0.0-31-btf.json.gz) | 3,730,789 bytes | `symbols/linux/ubuntu-7.0.0-31-btf.json` — 33,439,006 bytes |

두 파일을 `plugin/evidence/downloads/`에 저장하고, `plugin/` 폴더에서 실행합니다. 압축 파일과 복원된 자료를 함께 보관할 공간이 약 5.44GB 필요합니다.

```powershell
.\.venv\Scripts\python.exe tools/unpack_evidence.py evidence/downloads/memory.lime.gz evidence/downloads/ubuntu-7.0.0-31-btf.json.gz
.\.venv\Scripts\python.exe tools/prepare_lab_schema.py
.\.venv\Scripts\python.exe -X utf8 container_caps.py --dump evidence/memory.lime --symbols evidence/symbols --output-root results
```

복원 도우미는 두 단계의 크기·SHA-256을 확인하며 다른 파일을 덮어쓰지 않습니다. 덤프·심볼 원본은 수정하지 않았으며 gzip 복원 결과와 원본이 바이트 단위로 같음을 해시로 확인했습니다.

## 수집 환경과 예상 관측

2026-09-11 `20260911T092624Z` 실험 자료. Ubuntu Server 26.04.1, 커널 `7.0.0-31-generic` x86-64, Docker 29.8.0, containerd 2.3.5, runc 1.5.1, cgroup v2/systemd, AVML 0.20.0 수집. 각 컨테이너는 Alpine 3.22의 `sleep infinity` 태스크 1개입니다.

| 구성 | 호스트 PID/TID | Effective 원시 마스크 |
|---|---:|---|
| 기본 권한 14종 | 4508 | `0xa80425fb` |
| 모든 capability 제거 | 4563 | `0x0` |
| CHOWN + NET_ADMIN | 4618 | `0x1001` |
| BPF | 4669 | `0x8000000000` |
| CHECKPOINT_RESTORE | 4725 | `0x10000000000` |

이 값들은 대조용 예상 결과이며 플러그인 분석 로직에 고정되어 있지 않습니다. 이 실험에서는 E=P=B, I=A=0이고 초기 user namespace, seccomp mode 2 / 필터 1개가 관측됐습니다.

제공 BTF ISF는 `btf2json`으로 BTF·같은 커널의 System.map·배너를 결합해 만든 자료입니다. `prepare_lab_schema.py`는 원본 ISF 메타데이터를 유지하면서 전용 가상환경의 Volatility 2.28.0 스키마에 `btf`·`symdb` 출처 두 이름만 허용합니다. 일반적인 유효한 DWARF ISF에 이 설정을 적용할 필요는 없습니다.

덤프는 컨테이너 다섯 개를 포함한 실험 VM 전체 메모리입니다. 컨테이너 부분만 잘라낸 자료가 아닙니다. 현재 Linux·Docker의 최신 버전을 나타내는 실험도 아닙니다.

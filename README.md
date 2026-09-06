# Docker Memory Analyzer 🐳🔍

<div align="center">
  <p><strong>컨테이너 환경의 침해사고 분석을 위한 메모리 포렌식 기반 실행 문맥 재구성 도구</strong></p>
</div>

## 📖 Overview

**Docker Memory Analyzer**는 Linux 메모리 덤프에서 Docker 컨테이너의 상태와 실행 문맥을 완벽하게 재구성하는 Volatility 3 기반의 포렌식 도구입니다. 

기존의 파일 시스템이나 데몬 로그에 의존하는 분석 방법과 달리, 본 도구는 `dockerd` 데몬의 Go 힙 메모리와 VFS 커널 페이지 캐시(Page Cache)를 직접 분석합니다. 이를 통해 공격자가 컨테이너를 강제 종료하거나 흔적을 삭제한 이후에도 높은 신뢰도로 컨테이너의 라이프사이클 이벤트와 상태 정보를 획득할 수 있습니다.

## ✨ Key Features

- **Direct Heap Analysis**: `dockerd` 프로세스의 힙 영역을 분석하여 `container.Container` 및 `container.State` 구조체를 카빙
- **Page Cache Extraction**: 마운트 없이 VFS dentry 트리를 탐색하여 `config.v2.json`을 캐시에서 추출
- **Deep State Reconstruction**: 단순히 문자열 상태가 아닌 내부 Boolean 플래그(Running, Paused, Dead 등) 분석을 통한 정확한 상태 전이 식별
- **Stale Memory Discovery**: 이미 삭제되어 GC(Garbage Collector) 대기 중인 컨테이너 구조체 탐지
- **High Performance**: 단일 패스 메모리 스캐닝(CachedProcessMemory)을 통한 압도적인 분석 속도 최적화

## 🚀 Getting Started

### Prerequisites
- Python 3.10+
- [Volatility 3](https://github.com/volatilityfoundation/volatility3)
- Linux Memory Dump file (e.g., LiME format)

### Installation
```bash
git clone https://github.com/KKudroK/docker-memory-analyzer.git
cd docker-memory-analyzer
pip install -r requirements.txt
```

*(상세한 사용법은 추후 업데이트 예정)*

## 📄 License
This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

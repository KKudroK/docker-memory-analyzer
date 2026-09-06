# Docker Memory Analyzer

<div align="center">
  <p><strong>컨테이너 환경의 침해사고 분석을 위한 메모리 포렌식 기반 실행 문맥 재구성 도구</strong></p>
</div>

## Overview

**Docker Memory Analyzer**는 대상 시스템의 메모리 덤프를 기반으로 컨테이너의 상태와 실행 문맥을 파악하기 위한 종합 분석 도구입니다.

기존의 정적인 로그나 파일 시스템 아티팩트 분석의 한계를 극복하기 위해, 메모리에 남아있는 휘발성 데이터를 다각도로 수집하고 통합 분석합니다. 이를 통해 악의적인 사용자가 증거를 인멸하거나 데몬이 비정상 종료된 상황에서도 컨테이너의 라이프사이클 이벤트와 과거 상태를 신뢰성 있게 재구성하는 것을 목표로 합니다.

## Getting Started

### Prerequisites
- Python 3.10+
- Linux Memory Dump file (e.g., LiME format)

### Installation
```bash
git clone https://github.com/KKudroK/docker-memory-analyzer.git
cd docker-memory-analyzer
pip install -r requirements.txt
```

## License
This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

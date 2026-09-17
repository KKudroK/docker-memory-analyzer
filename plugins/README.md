# InspectNetworks: Docker 컨테이너 네트워크 메모리 분석 플러그인 (Volatility 3)

InspectNetworks는 Linux 물리 메모리 덤프에서 Docker를 비롯한 컨테이너 환경의 네트워크 자원(소켓, 인터페이스, conntrack, 컨테이너 간 통신 관계 등)을 식별하고 복원하는 Volatility 3 포렌식 플러그인입니다.

단순히 IP 주소나 프로세스 이름을 기반으로 컨테이너 소속을 추정하는 방식이 아니라, 커널 내부의 Cgroup 계층, `task_struct`, 파일 디스크립터 테이블(FD Table), `net_namespace` 구조체를 엄격하게 교차 검증하여 높은 신뢰도를 갖는 네트워크 증거를 제공합니다.

---

## 1. 주요 기능

- 컨테이너 소켓 복원: 각 컨테이너 내부 프로세스가 열고 있는 실제 TCP, UDP, UNIX 도메인 소켓을 식별하고 바인딩 상태(Listen, Established 등)를 확인합니다.
- 네트워크 네임스페이스 및 인터페이스 매핑: 컨테이너별 Network Namespace를 추적하여 할당된 가상 인터페이스(veth, eth0 등)와 IP(CIDR), MAC 주소를 복원합니다.
- 컨테이너 간 통신 관계 분석: 동일한 네트워크 네임스페이스 공유, 소켓 공유, UNIX 도메인 소켓의 피어(Peer) 연결 관계를 재구성합니다.
- Conntrack 및 NAT 상태 분석: 컨테이너 내부의 커널 연결 추적(conntrack) 테이블을 파싱하여 송수신 세션 및 NAT(SNAT/DNAT) 변환 내역을 확인합니다.
- 메모리 파편화 및 은닉 대응: 프로세스 연결 리스트(`pslist`)가 유실되거나 분리된 환경에서도 선형 메모리 스캔(`psscan`) 및 전역 네임스페이스 리스트(`net_namespace_list`)를 통해 탄력적으로 컨테이너를 복원합니다.

---

## 2. 요구 사항 및 설치

### 요구 사항
- Python 3.10 이상
- Volatility 3 (2.28.0 권장, 최소 2.22.0 이상)
- 분석 대상 메모리 덤프의 커널 빌드와 일치하는 Linux ISF 심볼 파일 (`.json` 또는 `.json.xz`)
- 대상 아키텍처: Linux x86-64 (Intel 64)

### 설치
별도의 빌드 과정 없이 `plugins/src/plugins/inspect_networks.py` 단일 파일로 배포 및 실행이 가능합니다. Volatility 3 실행 시 `-p` 옵션으로 플러그인 경로를 지정하면 즉시 로드됩니다.

---

## 3. 사용법

### 기본 실행 구문
```bash
python vol.py -p <플러그인_경로> -s <심볼_경로> -f <메모리_덤프> inspect_networks.InspectNetworks [옵션]
```

### CLI 옵션 목록

| 옵션 | 인자 형식 | 기본값 | 설명 |
|---|---|---|---|
| `--view` | Choice (`sockets`, `containers`, `interfaces`, `relations`, `conntrack`, `diagnostics`) | `sockets` | 출력할 네트워크 분석 화면을 선택합니다. |
| `--container` | String (Prefix 또는 전체 ID 목록) | 없음 (전체) | 특정 컨테이너 ID 또는 고유한 앞자리 Prefix로 결과를 필터링합니다. |
| `--dump-evidence` | Flag (Boolean) | False | 수집된 원본 구조체 및 파싱 증거 전체를 JSON 파일(`network_evidence.json`)로 저장합니다. |
| `-o`, `--output-dir` | Path | 현재 디렉터리 | 증거 JSON 파일이 저장될 출력 디렉터리를 지정합니다. |

---

## 4. 분석 뷰(View) 및 출력 결과 명세

`--view` 옵션으로 지정할 수 있는 6가지 뷰의 상세 내용과 출력 예시입니다.

### (1) `sockets` 뷰 (기본값)
컨테이너 내부 프로세스가 파일 디스크립터(FD)를 통해 열고 있는 실제 네트워크 소켓 목록을 출력합니다.

- **출력 열 설명**:
  - `Container ID`: 소켓을 보유한 프로세스의 Cgroup에서 확인된 컨테이너 ID (고유 식별자)
  - `NetNS`: 소켓이 속한 Network Namespace의 inode 번호
  - `Proto`: 프로토콜 (TCP, TCPv6, UDP, UDPv6, UNIX)
  - `PID`: 호스트 기준 프로세스 ID
  - `Process`: 프로세스 실행 파일명 (comm)
  - `FD`: 소켓이 바인딩된 파일 디스크립터 번호
  - `Local`: 로컬 IP 주소 및 포트 번호 (또는 UNIX 소켓 경로)
  - `Remote`: 원격 IP 주소 및 포트 번호
  - `State`: 소켓 상태 (LISTEN, ESTABLISHED, CLOSE 등)

- **출력 예시**:
```text
Container ID  NetNS       Proto  PID    Process  FD  Local              Remote          State
e3a123f89012  4026532580  TCP    18420  nginx    6   0.0.0.0:80         0.0.0.0:0       LISTEN
e3a123f89012  4026532580  TCP    18420  nginx    7   [::]:80            [::]:0          LISTEN
e3a123f89012  4026532580  TCP    18421  nginx    6   0.0.0.0:80         0.0.0.0:0       LISTEN
e3a123f89012  4026532580  TCP    18421  nginx    7   [::]:80            [::]:0          LISTEN
b98c0d123456  4026532612  UNIX   18950  redis    5   /tmp/redis.sock    N/A             ESTABLISHED
```

### (2) `containers` 뷰
메모리 상에서 탐지된 컨테이너별 요약 정보를 집계하여 표시합니다.

- **출력 열 설명**:
  - `Container ID`: 컨테이너 고유 ID
  - `Tasks`: 컨테이너에 속한 전체 태스크 수 (스레드 포함)
  - `Processes`: 컨테이너에 속한 고유 프로세스 그룹(TGID) 수
  - `Sockets`: 컨테이너 내부 프로세스가 열고 있는 활성 소켓 수
  - `NetNS`: 할당된 Network Namespace inode 번호

- **출력 예시**:
```text
Container ID  Tasks  Processes  Sockets  NetNS
b98c0d123456  4      2          1        4026532612
e3a123f89012  3      2          6        4026532580
f41a87e45678  1      1          0        4026532645
```

### (3) `interfaces` 뷰
컨테이너 Network Namespace에 생성된 네트워크 인터페이스 및 IP/MAC 주소 정보를 출력합니다.

- **출력 열 설명**:
  - `Container IDs`: 해당 네임스페이스를 사용하는 컨테이너 ID 목록
  - `NetNS`: Network Namespace inode 번호
  - `Interface`: 네트워크 인터페이스 명칭 (eth0, lo 등)
  - `Address`: 할당된 IP 주소 및 CIDR 서브넷 마스크
  - `MAC`: 하드웨어 MAC 주소

- **출력 예시**:
```text
Container IDs  NetNS       Interface  Address        MAC
e3a123f89012   4026532580  eth0       172.17.0.2/16  02:42:ac:11:00:02
e3a123f89012   4026532580  lo         127.0.0.1/8    00:00:00:00:00:00
b98c0d123456   4026532612  eth0       172.17.0.3/16  02:42:ac:11:00:03
```

### (4) `relations` 뷰
컨테이너 간 또는 컨테이너와 호스트 사이의 구조적 연결 및 통신 관계를 식별합니다.

- **출력 열 설명**:
  - `Relation`: 관계 유형 (unix_peer, shared_namespace, socket_share 등)
  - `Container ID`: 기준 컨테이너 ID
  - `Object`: 기준 소켓 또는 네임스페이스 커널 객체 주소
  - `Peer Container`: 상대방 컨테이너 ID (호스트 프로세스인 경우 빈칸)
  - `Peer Object`: 상대방 소켓 커널 객체 주소
  - `Evidence`: 판정 신뢰도 및 증거 수준 (reciprocal_peer, confirmed_sharing 등)

- **출력 예시**:
```text
Relation   Container ID  Object              Peer Container  Peer Object         Evidence
unix_peer  b98c0d123456  0xffff981e84a2b100  e3a123f89012    0xffff981e84a2c300  reciprocal_peer
```

### (5) `conntrack` 뷰
컨테이너 Network Namespace 내부의 연결 추적 테이블(Conntrack)을 추출하여 활성 세션과 NAT 상태를 확인합니다.

- **출력 열 설명**:
  - `Container IDs`: 해당 네임스페이스에 참여하는 컨테이너 ID 목록
  - `NetNS`: Network Namespace inode 번호
  - `Proto`: 전송 계층 프로토콜 (TCP, UDP, ICMP 등)
  - `Source`: 오리지널 세션의 송신지 IP:포트
  - `Destination`: 오리지널 세션의 수신지 IP:포트
  - `NAT`: 적용된 주소 변환 유형 (SNAT, DNAT, SNAT+DNAT, None)

- **출력 예시**:
```text
Container IDs  NetNS       Proto  Source            Destination       NAT
e3a123f89012   4026532580  TCP    172.17.0.2:48392  93.184.216.34:80  SNAT
b98c0d123456   4026532612  UDP    172.17.0.3:53210  8.8.8.8:53        None
```

### (6) `diagnostics` 뷰
분석 파이프라인에서 발생한 파싱 오류, 페이지 폴트, 미지원 기능, 식별 충돌 태스크를 종합 진단합니다.

- **출력 열 설명**:
  - `Kind`: 진단 유형 (`error`: 파싱 실패, `unsupported`: 커널 기능 미지원, `unresolved`: 컨테이너 귀속 불가)
  - `Stage`: 발생한 분석 단계 (cgroup, netns, socket, psscan 등)
  - `Object`: 관련 커널 객체 주소 또는 심볼
  - `Detail`: 상세 원인 (예: NULL 포인터, 메모리 페이지 누락, 복수 Cgroup 충돌 등)

---

## 5. 포렌식 분석 및 증거 해석 원칙

1. **보수적 컨테이너 식별 (Strict Attribution)**:
   - 본 플러그인은 프로세스의 실제 Cgroup 경로가 완전하게 일치하는 경우에만 컨테이너 소속으로 인정합니다. 단순 상위 프로세스(shim) 자손이라는 이유나 프로세스 이름만으로 소속을 추정하지 않으므로 오탐(False Positive)을 최소화합니다.
2. **호스트 네트워크 모드(`--net=host`) 지원**:
   - 컨테이너가 호스트 네임스페이스(`init_net`)를 공유하는 경우에도, 각 프로세스의 파일 디스크립터(FD) 테이블을 역추적하여 해당 컨테이너 내부 프로세스가 생성한 소켓만을 선별적으로 귀속합니다.
3. **메모리 파편화 및 페이징 한계 고지**:
   - 컨테이너 내부 프로세스가 장시간 대기(sleep) 상태이거나 메모리 압박으로 인해 관련 커널 구조체가 스왑 아웃(Swap-out)된 경우, 일부 소켓이나 태스크 정보가 누락될 수 있습니다. 이러한 상황은 임의로 추정하지 않고 `diagnostics` 뷰 및 증거 JSON에 명시적으로 기록합니다.
4. **증거 보존 (`--dump-evidence`)**:
   - `--dump-evidence` 옵션 사용 시 추출되는 `network_evidence.json` 파일에는 화면에 요약되지 않은 원시 커널 주소, 구조체 오프셋, 바이트 플래그 등이 포함되어 법적·기술적 검증을 위한 보조 증거로 활용할 수 있습니다.

---

## 6. 검증 환경

InspectNetworks는 다양한 Linux 배포판 및 커널 버전의 실제 물리 메모리 덤프를 기반으로 회귀 검증을 통과했습니다.

- Ubuntu 24.04 LTS (Kernel 6.8.x)
- Ubuntu 22.04 LTS (Kernel 5.15.x)
- Ubuntu 20.04 LTS (Kernel 5.4.x)
- Debian 12 (Kernel 6.1.x)
- Rocky Linux 9 (Kernel 5.14.x)

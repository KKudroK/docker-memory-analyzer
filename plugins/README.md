# InspectNetworks 고도화 플러그인 (Volatility 3)

Docker 및 커널 네트워크 네임스페이스의 메모리 구조체를 전수 조사하여, 컨테이너 네트워크 상태와 토폴로지를 분석하는 Volatility 3 플러그인입니다. 기존의 단일 통합 뷰를 개선하여, 분석가가 필요로 하는 L2/L3/L4 계층별 네트워크 정보를 지정하여 출력할 수 있도록 고도화되었습니다.

## 설치 및 요구사항

배포에는 **`src/plugins/inspect_networks.py`** 파일 하나만 필요합니다. `vol.py`가 위치한 디렉터리의 플러그인 폴더에 복사하거나, `-p` 옵션으로 경로를 지정하여 실행합니다.

## 사용법

기본 명령어 구조:
```powershell
vol -q -p <플러그인_경로> -f <메모리덤프.lime> -s <심볼_경로> inspect_networks.InspectNetworks --view <옵션>
```

## 제공되는 뷰(View) 옵션

`--view` 인자를 통해 다음 5가지 네트워크 포렌식 뷰를 선택할 수 있습니다.

### 1. sockets (기본값)
특정 프로세스(컨테이너)가 네트워크와 통신하기 위해 열어둔 소켓 정보를 보여줍니다.
- **의미**: 포트 바인딩(LISTEN) 및 연결된 세션(ESTABLISHED) 상태를 확인하여 컨테이너 간 통신 내역과 악성 백도어 연결 여부를 조사할 수 있습니다.
- **실행 예시**:
  ```powershell
  vol ... inspect_networks.InspectNetworks --view sockets
  ```
  ```text
    | Container ID |      NetNS | Proto |  PID | Process | FD |               Local |              Remote |       State
  * | 71d3f56e75a4 | 4026532261 |   TCP | 2834 | python3 |  3 |        0.0.0.0:8080 |           0.0.0.0:0 |      LISTEN
  * | 71d3f56e75a4 | 4026532261 |   TCP | 2834 | python3 |  4 |   172.30.81.10:8080 |  172.30.81.20:51001 | ESTABLISHED
  ```

### 2. topology
컨테이너의 가상 네트워크(veth)가 호스트의 가상 스위치(bridge)에 어떻게 연결되어 있는지 물리/논리적 링크 관계를 보여줍니다.
- **의미**: L2 계층의 연결 관계를 통해 같은 서브넷(브리지)에 묶인 컨테이너들을 식별합니다.
- **실행 예시**:
  ```powershell
  vol ... inspect_networks.InspectNetworks --view topology
  ```
  ```text
    |      NetNS |   Interface | Peer/Bridge
  * | 4026531840 | veth0bd20e6 |    br-dma81
  * | 4026531840 | veth41b7deb |    br-dma82
  ```

### 3. fdb (Forwarding Database)
가상 스위치(bridge)가 수집한 MAC 주소 포워딩 테이블입니다.
- **의미**: 브리지가 트래픽을 넘겨주기 위해 학습한 포트별 MAC 주소 테이블로, 스위칭 내역 및 목적지를 확인합니다.
- **실행 예시**:
  ```powershell
  vol ... inspect_networks.InspectNetworks --view fdb
  ```
  ```text
    |   Bridge |      NetNS |        Port |       MAC Address | VLAN | Is Local
  * | br-dma81 | 4026531840 | vethd1e8e44 | 6a:74:a7:4e:5e:b5 |    1 |        3
  ```

### 4. routes
커널의 L3 패킷 전달 방향(라우팅 테이블)을 출력합니다.
- **의미**: 컨테이너나 호스트가 패킷을 전송할 때 거쳐가는 게이트웨이 및 출력 인터페이스를 확인하여, 트래픽 유출 경로를 추적합니다.
- **실행 예시**:
  ```powershell
  vol ... inspect_networks.InspectNetworks --view routes
  ```
  ```text
    |      NetNS | Family |                   Destination |     Gateway |   Interface
  * | 4026532261 |      4 |                     0.0.0.0/0 | 172.30.81.1 |        eth0
  * | 4026531840 |      4 |                     0.0.0.0/0 |    10.0.2.2 |        ens3
  ```

### 5. neighbors
가상 장비들에 기록된 이웃 탐색 테이블(ARP / NDP 캐시)입니다.
- **의미**: 통신했던 이웃 노드의 IP와 MAC 주소 맵핑 기록을 통해, 도달 가능성이 검증된 실제 통신 상대방을 입증합니다.
- **실행 예시**:
  ```powershell
  vol ... inspect_networks.InspectNetworks --view neighbors
  ```
  ```text
    |      NetNS |   Interface |                IP Address |       MAC Address | State
  * | 4026532261 |        eth0 |              172.30.81.20 | 02:ab:cd:81:00:20 |     2
  ```

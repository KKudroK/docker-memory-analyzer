# InspectNetworks v11 (Volatility 3)

컨테이너 프로세스의 **실제 FD 소켓 보유**, namespace·소켓 공유, 직접 UNIX peer 및 컨테이너 namespace의 인터페이스·conntrack을 분석합니다. task 자신의 완전한 cgroup 경로에서 ID를 확인하고 shim 계보는 충돌 검사에 보조적으로 사용합니다. IP 일치나 shim 자손이라는 이유만으로 컨테이너 소속·통신 관계를 만들지 않습니다.

설치는 [`src/plugins/inspect_networks.py`](src/plugins/inspect_networks.py) 한 파일로 가능합니다. `src/network_analysis/`도 현재 v11 개발 모듈이며 `scripts/build_network_plugin.py`로 standalone을 재생성할 수 있습니다. 배포본에는 영어 주석과 docstring을 적용했고 정본과 실행 AST가 같습니다.

## 실행

stock Volatility 3 **2.28.0에서 검증**했습니다. framework 최소 선언은 2.22.0이며 NetSymbols 1.0.0, LinuxUtilities 2.0.0, PsList 4.0.0 이상이 필요합니다. x86-64 Linux 이미지와 해당 커널 빌드에 정확히 대응하는 ISF를 준비하세요.

```text
python vol.py -p <plugin_dir> -s <symbol_dir> -f <memory.lime> inspect_networks.InspectNetworks
python vol.py -p <plugin_dir> -s <symbol_dir> -f <memory.lime> inspect_networks.InspectNetworks --view conntrack
python vol.py -p <plugin_dir> -s <symbol_dir> -f <memory.lime> -o <output_dir> inspect_networks.InspectNetworks --view diagnostics --dump-evidence
```

출력 디렉터리는 먼저 생성합니다. 기본은 sockets이며 플러그인 옵션은 세 개입니다.

| 옵션 | 의미 |
|---|---|
| `--view` | 아래 여섯 화면 중 선택 |
| `--container PREFIX [...]` | 관측 ID에 유일하게 일치하는 접두사로 출력 선택 |
| `--dump-evidence` | 해당 view의 근거·전체 ID·원시 값·오류를 JSON 저장 |

| View | 출력 및 수집 범위 |
|---|---|
| sockets | Container ID, NetNS, Proto, PID, Process, FD, Local, Remote, State |
| containers | ID별 task·process·FD 소켓 수와 NetNS; 소켓 수집 |
| relations | 동일 net/socket의 공유, 상호 확인한 UNIX peer; 소켓 수집 |
| interfaces | Container IDs, NetNS, Interface, Address, MAC |
| conntrack | Container IDs, NetNS, Proto, Source, Destination, NAT |
| diagnostics | 핵심 세 수집기를 모두 실행하고 오류·미지원·소속 충돌 표시 |

dump-evidence는 수집 범위를 넓히지 않습니다. container는 화면 필터이며 JSON과 diagnostics는 실행 전체의 증거·오류를 유지합니다. 공유 namespace의 다른 구성원도 지우지 않습니다.

## 증거 해석

소켓의 Container ID는 실제 FD holder의 자기 cgroup에서 확인한 ID 참조입니다. interfaces·conntrack의 Container IDs는 그 namespace에 참여한다고 확인된 모든 ID입니다. 해당 자원을 어느 하나의 컨테이너가 독점 소유하거나 실제 패킷을 전송했다고 단정하지 않습니다. ID는 최소 12자리이며 충돌하면 길어집니다. Docker 이름이나 task 없는 전체 런타임 inventory는 제공하지 않습니다.

인터페이스·conntrack 수집은 확인된 비호스트 컨테이너 namespace로 제한합니다. 초기 host namespace 또는 init_net 확인 실패는 문맥 귀속에서 제외하고 진단을 남깁니다. host-network 컨테이너 자신의 FD 소켓은 표시합니다. 호스트 published-port NAT 전체를 복원하는 기능은 아닙니다.

conntrack의 Source·Destination은 original 방향입니다. NAT는 status의 SNAT·DNAT 비트이며 tuple 비대칭으로 추정하지 않습니다. reply·status·객체 주소는 JSON에 남습니다. NAT=None은 해당 두 비트가 없다는 의미입니다.

## v10에서 변경된 범위

- routes·neighbors view와 수집 코드, topology·FDB·multicast·routing rules·docker-proxy 설정 수집을 제거했습니다. topology/FDB는 export에도 없습니다.
- collect-all·relations 별칭·identity-mode·identity-only·disable-cgroup-cache·dump-metrics·limit 옵션을 제거했습니다. relations는 `--view relations`, 핵심 전체 점검은 `--view diagnostics`를 사용합니다.
- 손상 방지 예산은 내부 100,000으로 고정했습니다. 순환·범위·역참조 검사, 실패 격리와 오류 기록은 유지했습니다.
- 증거 JSON은 schema_version 4입니다. 제거 기능의 필드가 없어졌으므로 기존 JSON 소비자도 갱신해야 합니다.

topology 제거는 모든 연결 복원이 불가능해서가 아니라, 일부 심볼에서 안전한 veth peer 복원이 제한되고 별도 범용 경로가 핵심 분석을 복잡하게 만들기 때문입니다. 추정 오프셋으로 보완하지 않습니다.

## 검증 범위

Ubuntu 6.8·Rocky Linux 5.14 x86-64 덤프를 현재 코드로 다시 실행하고 Bdb 중단점으로 확인했습니다. 배포본 회귀 테스트 71개를 통과했습니다. S01 독립 GT에서 task-bearing ID 15개·TID 34개의 소속과 netns가 일치하며 기존 FD 근거를 유지했습니다. Rocky의 NULL inode 오류와 영향 holder 13개도 보존했습니다.

모든 커널·배포판·CNI·런타임을 검증한 것은 아닙니다. 정확한 ISF, 필요한 타입, 읽을 수 있는 메모리가 없으면 오류·미지원을 기록합니다. 빈 결과를 흔적 없음으로 단정하지 마세요. FD로 도달하지 못하는 orphan/TIME_WAIT 전체를 열거하지 않습니다.

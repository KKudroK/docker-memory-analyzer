# InspectNetworks 고도화 플러그인

cgroup/프로세스에서 얻은 컨테이너 후보를 network namespace와 연결하여 인터페이스·주소·소켓을 표로 출력합니다. Docker MAC 접두사에 의존하지 않으며 보조 IPv4, IPv6와 스레드의 공유 소켓을 처리합니다.

저장소 루트에서:

```powershell
vol -q -p volatility_docker/src/plugins -s symbols -f dumps/sample.lime inspect_networks.InspectNetworks
```

실행 환경에 `vol`이 없으면 같은 버전의 `python path/to/vol.py`로 바꿉니다. 해당 덤프의 스택 설정이 있다면 플러그인 이름 앞에 `-c stack_config.json`을 추가합니다. 다른 덤프의 레이어/KASLR 설정을 재사용하지 마세요.

배포에는 **[src/plugins/inspect_networks.py](src/plugins/inspect_networks.py) 하나**만 필요합니다. `network_analysis` 폴더를 Volatility에 복사하거나 기본 플러그인/Linux symbol extension을 덮어쓸 필요가 없습니다.

S01 실제 결과 중 인터페이스 필드 발췌(일부 열):

```text
Container     PID   NetNS       Interface  MAC                Address
91d9b1be475e  3925  4026532729  eth0       02:42:ac:1e:00:0a  172.30.10.10/16
91d9b1be475e  3925  4026532729  eth0       02:42:ac:1e:00:0a  172.30.20.20/16
```

실제 표에는 Host link, Protocol/Local/Remote/State도 있습니다. IPv6와 소켓은 별도 행으로 표시하며 `candidate` 연결은 확정된 peer 관계가 아닙니다.

`--include-host`로 호스트·미식별 namespace를 포함합니다. 상세 증거가 필요할 때만:

```powershell
mkdir outputs/network
vol -q -p volatility_docker/src/plugins -s symbols -o outputs/network -f dumps/sample.lime inspect_networks.InspectNetworks --dump-evidence
```

`network_evidence.json`에 추가 수집 데이터, 출처, 오류와 미지원 경로를 기록합니다.

## 개발

```powershell
python volatility_docker/scripts/build_network_plugin.py
python volatility_docker/scripts/test_network_plugin.py
python volatility_docker/scripts/test_network_compatibility.py
```

`src/network_analysis` 수정 후 빌더로 단일 배포 파일을 생성합니다. 단위 테스트 23개와 S01 실덤프 검증 40개를 통과했습니다. [검토 기록](REVIEW.md)에 호환성 검증 범위를 구분했습니다.

# 코드 구성과 재사용 출처

현재 배포 기준은 ContainerCaps 1.4.0입니다. `volatility3==2.28.0`은 별도 설치하는 의존성이며, Volatility 소스 전체를 이 폴더에 복사하지 않습니다.

| 현재 코드 | 역할 / 출처 |
|---|---|
| `plugins/containercaps.py` | 공식 `PluginInterface`, `PsList.list_tasks`, `TreeGrid`, `self.open` API를 호출·상속하여 수집과 출력을 연결 |
| `plugins/container_support/identity.py` | 자체 Docker cgroup v2 표식·CSS/kernfs 관계 검사. 공식 객체·문자열 유틸리티 사용 |
| `plugins/container_support/layouts.py` | 자체 심볼 구조 검사와 알려진 필드 배치 선택. 공식 심볼·객체 계층 사용 |
| `plugins/container_support/capabilities_reader.py` | 자체 capability 저장 형식 판독·원시 바이트 대조. 이름은 공식 `volatility3.framework.constants.linux.CAPABILITIES` 사전 사용 |
| `plugins/container_support/security.py` | 자체 credentials·namespace·seccomp 부분 수집. 마운트 복원에서 공식 `mnt_namespace.get_mount_points`, `MountInfo.get_mountinfo` 호출 |
| `plugins/container_support/analyst.py` | 수집 JSON을 기반으로 자체 집합·스레드 차이와 핵심 표 생성 |
| `container_caps.py`, `run_volatility.py` | 실행 환경 연결, 결과 보존, 저장 결과 조회 |

## 기존 CAPS 플러그인과의 관계

- 공식 Volatility 3 2.28.0의 `linux.capabilities.Capabilities` 함수는 현재 코드에서 직접 호출하지 않습니다. 1.2.0에서 호출하던 `_decode_cap`은 1.3.0부터 자체 판독기로 교체했습니다. 같은 Linux capability 필드·비트 연산을 사용하는 것을 해당 플러그인 코드의 복사라고 표현하지 않습니다.
- [amir9339/volatility-docker](https://github.com/amir9339/volatility-docker)의 `--inspect-caps`는 컨테이너 후보와 Effective를 연결하는 분석 흐름을 참고했습니다. 현재 코드에 원본의 `get_containers_pids`, `get_container_id`, `InspectCaps`, `_caps_hex_to_string` 구현을 복사하거나 직접 호출한 부분은 없습니다.
- `docker-memory-analyzer-Han`의 InspectNetworks에서 심볼 멤버 존재에 따른 분기와 단계별 읽기 실패 기록 설계를 참고했습니다. 해당 도구나 별도 상태분석 자료를 실행 의존성으로 포함하지 않습니다.

공식 Volatility와 그 라이선스는 [volatilityfoundation/volatility3](https://github.com/volatilityfoundation/volatility3/tree/v2.28.0)에서 확인할 수 있습니다. 이 설명은 API 재사용·설계 참고·자체 구현을 구분하기 위한 기록입니다.

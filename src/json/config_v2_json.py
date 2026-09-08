# =========================================================================
# Docker config.v2.json 커널 페이지 캐시 카빙 스크립트 (volshell 전용)
# =========================================================================
# 사용법: volshell에서 실행
#   vol3 -f dump.lime linux.volshell.Volshell
#   >>> exec(open('src/config_v2_json.py').read())
#
# 원리:
#   dockerd 프로세스의 VFS dentry를 탐색하여
#   /var/lib/docker/containers/<CID>/config.v2.json을
#   커널 페이지 캐시에서 직접 읽어온다.
#   이 방법은 프로세스 힙 분석과 독립적이며,
#   Docker가 디스크에 기록한 상태 정보를 그대로 복원한다.
# =========================================================================

import json

print("\n[+] Docker config.v2.json Page Cache Analyzer")
print("=" * 60)

# ── [1] dockerd 프로세스 탐색 ──
k = self.context.modules[self.config['kernel']]
k_name = k.symbol_table_name

from volatility3.plugins.linux import pslist
import volatility3.framework.objects.utility as utility

dockerd = None
for task in pslist.PsList.list_tasks(self.context, self.config['kernel']):
    comm = utility.array_to_string(task.comm)
    if comm.startswith("dockerd"):
        dockerd = task
        break

if not dockerd:
    print("[-] dockerd not found")
    import sys; sys.exit()

print(f"  dockerd PID: {int(dockerd.pid)}")
layer_name = dockerd.vol.layer_name

# ── [2] VFS dentry 탐색 헬퍼 ──
def read_dname(dentry_obj):
    try:
        length = int(dentry_obj.d_name.len)
        if 0 < length <= 256:
            name_ptr = int(dentry_obj.d_name.name)
            raw = self.context.layers[layer_name].read(name_ptr, length)
            return raw.decode('utf-8', errors='ignore')
    except:
        pass
    return ""

def get_children(parent):
    try:
        if hasattr(parent, 'd_children'):
            return parent.d_children.to_list(k_name + "!dentry", "d_sib")
        try:
            return parent.d_subdirs.to_list(k_name + "!dentry", "d_child")
        except:
            return parent.d_subdirs.to_list(k_name + "!dentry", "d_u.d_child")
    except:
        return []

def find_child(parent, target_name):
    for child in get_children(parent):
        if read_dname(child) == target_name:
            return child
    return None

# ── [3] /var/lib/docker/containers 경로 탐색 ──
curr = dockerd.fs.root.dentry
for p in ["var", "lib", "docker", "containers"]:
    curr = find_child(curr, p)
    if not curr:
        print(f"[-] /{p} not found in VFS")
        import sys; sys.exit()

# ── [4] 상태 판별 로직 ──
def determine_status(data):
    """config.v2.json에서 Docker StateString() 재현"""
    state = data.get("State", {})
    running = state.get("Running", False)
    paused = state.get("Paused", False)
    restarting = state.get("Restarting", False)
    removal = state.get("RemovalInProgress", False)
    dead = state.get("Dead", False)
    removed = state.get("Removed", False)

    if running:
        if paused:
            return "PAUSED"
        if restarting:
            return "RESTARTING"
        return "RUNNING"
    if removal:
        return "REMOVING"
    if dead:
        if removed:
            return "REMOVED"
        return "DEAD"

    started_at = state.get("StartedAt", "")
    zero_times = ["", "0001-01-01T00:00:00Z", "0001-01-01T00:00:00.000Z"]
    if started_at in zero_times:
        return "CREATED"
    return "EXITED"

# ── [5] 각 컨테이너 분석 ──
container_dirs = get_children(curr)
found_count = 0

for c_dir in container_dirs:
    c_name = read_dname(c_dir)
    if len(c_name) < 10:
        continue

    config_dentry = find_child(c_dir, "config.v2.json")
    if not config_dentry:
        continue

    inode_addr = int(config_dentry.d_inode)
    inode_obj = self.context.object(k_name + "!inode", layer_name, offset=inode_addr)

    text = None
    try:
        for page_obj in inode_obj.get_pages():
            content = page_obj.get_content()
            if content:
                text = content.split(b'\x00')[0].decode('utf-8', errors='ignore')
                break
    except Exception as e:
        print(f"  [-] Page read failed for {c_name[:12]}: {e}")
        continue

    if not text:
        continue

    try:
        data = json.loads(text)
    except json.JSONDecodeError:
        print(f"  [-] JSON parse failed for {c_name[:12]}")
        continue

    found_count += 1
    state = data.get("State", {})
    config = data.get("Config", {})
    status = determine_status(data)

    cid = data.get("ID", c_name)
    name = data.get("Name", "?")
    image = config.get("Image", "-")
    pid = state.get("Pid", 0)
    exit_code = state.get("ExitCode", 0)
    started_at = state.get("StartedAt", "-")
    finished_at = state.get("FinishedAt", "-")

    flags = (f"R={int(state.get('Running', False))} "
             f"Pa={int(state.get('Paused', False))} "
             f"Re={int(state.get('Restarting', False))} "
             f"D={int(state.get('Dead', False))} "
             f"RI={int(state.get('RemovalInProgress', False))} "
             f"Rm={int(state.get('Removed', False))}")

    print(f"\n  ── Container [{cid[:12]}] {name} ──")
    print(f"     Status:       {status}")
    print(f"     Image:        {image}")
    print(f"     PID:          {pid}")
    print(f"     ExitCode:     {exit_code}")
    print(f"     State Flags:  {flags}")
    print(f"     StartedAt:    {started_at}")
    print(f"     FinishedAt:   {finished_at}")

    # 추가 메타데이터
    driver = data.get("Driver", "-")
    restart_count = data.get("RestartCount", 0)
    has_started = data.get("HasBeenStartedBefore", False)
    has_stopped = data.get("HasBeenManuallyStopped", False)
    print(f"     RestartCount: {restart_count}")
    print(f"     Driver:       {driver}")

print(f"\n{'='*60}")
print(f"  Total: {found_count} container(s) analyzed from config.v2.json")
print(f"{'='*60}")

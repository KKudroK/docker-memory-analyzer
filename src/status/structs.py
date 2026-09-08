"""Docker Go struct definitions and field readers for amd64 Linux.

Source: GoReSym extraction + Docker source (moby/moby v27.0.3).
Verified against memory dumps from Docker Engine on Ubuntu 26.04.
"""
import struct
import datetime

# ── Container struct (680 bytes / 0x2a8) ──
CONTAINER = {
    'StreamConfig':             (0x0000,  8, 'ptr'),
    'State':                    (0x0008,  8, 'ptr'),
    'Root':                     (0x0010, 16, 'string'),
    'BaseFS':                   (0x0020, 16, 'string'),
    'RWLayer':                  (0x0030, 16, 'iface'),
    'ID':                       (0x0040, 16, 'string'),
    'Created':                  (0x0050, 24, 'time'),
    'Managed':                  (0x0068,  1, 'bool'),
    'Path':                     (0x0070, 16, 'string'),
    'Args':                     (0x0080, 24, 'slice'),
    'Config':                   (0x0098,  8, 'ptr'),
    'ImageID':                  (0x00a0, 16, 'string'),
    'ImageManifest':            (0x00b0,  8, 'ptr'),
    'NetworkSettings':          (0x00b8,  8, 'ptr'),
    'LogPath':                  (0x00c0, 16, 'string'),
    'Name':                     (0x00d0, 16, 'string'),
    'Driver':                   (0x00e0, 16, 'string'),
    'OS':                       (0x00f0, 16, 'string'),
    'RestartCount':             (0x0158,  8, 'int'),
    'HasBeenStartedBefore':     (0x0160,  1, 'bool'),
    'HasBeenManuallyStopped':   (0x0161,  1, 'bool'),
    'HasBeenManuallyRestarted': (0x0162,  1, 'bool'),
    'HostConfig':               (0x0170,  8, 'ptr'),
    'HostnamePath':             (0x0238, 16, 'string'),
    'HostsPath':                (0x0248, 16, 'string'),
    'ShmPath':                  (0x0258, 16, 'string'),
    'ResolvConfPath':           (0x0268, 16, 'string'),
}
CONTAINER_SIZE = 0x2a8

# ── State struct (192 bytes / 0xc0) ──
STATE = {
    'Mutex':              (0x0000,  8, 'mutex'),
    'Running':            (0x0008,  1, 'bool'),
    'Paused':             (0x0009,  1, 'bool'),
    'Restarting':         (0x000a,  1, 'bool'),
    'OOMKilled':          (0x000b,  1, 'bool'),
    'RemovalInProgress':  (0x000c,  1, 'bool'),
    'Dead':               (0x000d,  1, 'bool'),
    'Pid':                (0x0010,  8, 'int'),
    'ExitCode':           (0x0018,  8, 'int'),
    'ErrorMsg':           (0x0020, 16, 'string'),
    'StartedAt':          (0x0030, 24, 'time'),
    'FinishedAt':         (0x0048, 24, 'time'),
    'Health':             (0x0060,  8, 'ptr'),
    'Removed':            (0x0068,  1, 'bool'),
}
STATE_SIZE = 0xc0

# ── Config struct (288 bytes / 0x120) ──
CONFIG = {
    'Hostname':        (0x0000, 16, 'string'),
    'Domainname':      (0x0010, 16, 'string'),
    'User':            (0x0020, 16, 'string'),
    'AttachStdin':     (0x0030,  1, 'bool'),
    'AttachStdout':    (0x0031,  1, 'bool'),
    'AttachStderr':    (0x0032,  1, 'bool'),
    'Tty':             (0x0040,  1, 'bool'),
    'OpenStdin':       (0x0041,  1, 'bool'),
    'StdinOnce':       (0x0042,  1, 'bool'),
    'Env':             (0x0048, 24, 'slice'),
    'Cmd':             (0x0060, 24, 'slice'),
    'Image':           (0x0088, 16, 'string'),
    'WorkingDir':      (0x00a0, 16, 'string'),
    'Entrypoint':      (0x00b0, 24, 'slice'),
    'Labels':          (0x00e8,  8, 'map'),
    'StopSignal':      (0x00f0, 16, 'string'),
}
CONFIG_SIZE = 0x120

# ── HostConfig struct (1064 bytes / 0x428) ──
HOSTCONFIG = {
    'NetworkMode':                 (0x0040, 16, 'string'),
    'RestartPolicy.Name':          (0x0058, 16, 'string'),
    'RestartPolicy.MaxRetryCount': (0x0068,  8, 'int'),
    'AutoRemove':                  (0x0070,  1, 'bool'),
    'Privileged':                  (0x01c0,  1, 'bool'),
    'Runtime':                     (0x0220, 16, 'string'),
}
HOSTCONFIG_SIZE = 0x428

# ── Event Message struct (136 bytes / 0x88) ──
EVENT_MESSAGE = {
    'Status':              (0x0000, 16, 'string'),
    'ID':                  (0x0010, 16, 'string'),
    'From':                (0x0020, 16, 'string'),
    'Type':                (0x0030, 16, 'string'),
    'Action':              (0x0040, 16, 'string'),
    'Actor.ID':            (0x0050, 16, 'string'),
    'Actor.Attributes':    (0x0060,  8, 'map'),
    'Scope':               (0x0068, 16, 'string'),
    'Time':                (0x0078,  8, 'int'),
    'TimeNano':            (0x0080,  8, 'int'),
}
EVENT_MESSAGE_SIZE = 0x88

# ── Constants ──
ROOT_PREFIX = b'/var/lib/docker/containers/'
ROOT_PREFIX_LEN = 27
CID_LEN = 64
EXACT_ROOT_LEN = ROOT_PREFIX_LEN + CID_LEN  # 91
HEX_BYTES = set(b'0123456789abcdef')

# Go time.Time internals
_WALL_TO_INTERNAL = 59453308800
_UNIX_TO_INTERNAL = 62135596800
_HAS_MONOTONIC = 1 << 63
_NSEC_MASK = (1 << 30) - 1


def parse_go_time(wall, ext):
    """Parse Go time.Time (wall, ext) → Python datetime (UTC) or None."""
    nsec = wall & _NSEC_MASK
    if wall & _HAS_MONOTONIC:
        sec_since_1885 = (wall & ~_HAS_MONOTONIC) >> 30
        unix_sec = sec_since_1885 + _WALL_TO_INTERNAL - _UNIX_TO_INTERNAL
    else:
        if ext == 0:
            return None
        unix_sec = ext - _UNIX_TO_INTERNAL
    if unix_sec <= 0 or unix_sec > 4102444800:
        return None
    try:
        return datetime.datetime(1970, 1, 1, tzinfo=datetime.timezone.utc) + \
               datetime.timedelta(seconds=unix_sec, microseconds=nsec // 1000)
    except Exception:
        return None


def is_valid_cid(data):
    """Check if bytes represent a valid 64-char hex container ID."""
    return len(data) == CID_LEN and all(b in HEX_BYTES for b in data)


def state_to_status(s):
    """Compute Docker status string from State fields dict.

    Mirrors container/state.go StateString() logic.
    """
    if s.get('Running'):
        if s.get('Paused'):
            return 'paused'
        if s.get('Restarting'):
            return 'restarting'
        return 'running'
    if s.get('RemovalInProgress'):
        return 'removing'
    if s.get('Dead'):
        return 'dead'
    if s.get('HasBeenStartedBefore'):
        return 'exited'
    return 'created'


class StructReader:
    """Reads Go struct fields from a CachedProcessMemory instance."""

    def __init__(self, mem):
        self.mem = mem

    def read_bytes(self, addr, size):
        return self.mem.read_safe(addr, size)

    def read_string(self, base, offset):
        raw = self.mem.read_safe(base + offset, 16)
        if raw is None:
            return None
        ptr, length = struct.unpack('<QQ', raw)
        if length == 0 or length > 65536 or ptr < 0x10000:
            return None
        data = self.mem.read_safe(ptr, length)
        if data is None:
            return None
        try:
            return data.decode('utf-8', errors='replace')
        except Exception:
            return None

    def read_bool(self, base, offset):
        raw = self.mem.read_safe(base + offset, 1)
        if raw is None:
            return None
        if raw[0] == 0:
            return False
        if raw[0] == 1:
            return True
        return None

    def read_int(self, base, offset):
        raw = self.mem.read_safe(base + offset, 8)
        if raw is None:
            return None
        return struct.unpack('<q', raw)[0]

    def read_uint(self, base, offset):
        raw = self.mem.read_safe(base + offset, 8)
        if raw is None:
            return None
        return struct.unpack('<Q', raw)[0]

    def read_ptr(self, base, offset):
        return self.read_uint(base, offset)

    def read_time(self, base, offset):
        raw = self.mem.read_safe(base + offset, 24)
        if raw is None:
            return None
        wall, ext, _loc = struct.unpack('<QqQ', raw)
        return parse_go_time(wall, ext)

    def read_time_raw(self, base, offset):
        raw = self.mem.read_safe(base + offset, 24)
        if raw is None:
            return None, None
        wall, ext, _loc = struct.unpack('<QqQ', raw)
        return wall, ext

    def read_field(self, base, struct_def, field_name):
        if field_name not in struct_def:
            return None
        offset, _size, ftype = struct_def[field_name]
        if ftype == 'string':
            return self.read_string(base, offset)
        elif ftype == 'bool':
            return self.read_bool(base, offset)
        elif ftype in ('int', 'int64'):
            return self.read_int(base, offset)
        elif ftype in ('ptr', 'map'):
            return self.read_ptr(base, offset)
        elif ftype == 'time':
            return self.read_time(base, offset)
        elif ftype == 'slice':
            raw = self.mem.read_safe(base + offset, 24)
            if raw is None:
                return None
            return struct.unpack('<QQQ', raw)
        return None

    # ── High-level parsers ──

    def parse_container(self, cbase):
        """Read all Container struct fields."""
        r = {}
        for name in ('ID', 'Name', 'Root', 'Path', 'ImageID', 'Driver', 'OS',
                      'LogPath', 'BaseFS', 'HostnamePath', 'HostsPath',
                      'ShmPath', 'ResolvConfPath'):
            r[name] = self.read_field(cbase, CONTAINER, name)
        r['State_ptr'] = self.read_field(cbase, CONTAINER, 'State')
        r['Config_ptr'] = self.read_field(cbase, CONTAINER, 'Config')
        r['HostConfig_ptr'] = self.read_field(cbase, CONTAINER, 'HostConfig')
        r['NetworkSettings_ptr'] = self.read_field(cbase, CONTAINER, 'NetworkSettings')
        r['RestartCount'] = self.read_field(cbase, CONTAINER, 'RestartCount')
        r['HasBeenStartedBefore'] = self.read_field(cbase, CONTAINER, 'HasBeenStartedBefore')
        r['HasBeenManuallyStopped'] = self.read_field(cbase, CONTAINER, 'HasBeenManuallyStopped')
        r['HasBeenManuallyRestarted'] = self.read_field(cbase, CONTAINER, 'HasBeenManuallyRestarted')
        r['Managed'] = self.read_field(cbase, CONTAINER, 'Managed')
        r['Created'] = self.read_field(cbase, CONTAINER, 'Created')
        return r

    def parse_state(self, state_addr):
        """Read all State struct fields."""
        s = {}
        for name in ('Running', 'Paused', 'Restarting', 'OOMKilled',
                      'RemovalInProgress', 'Dead', 'Removed'):
            s[name] = self.read_field(state_addr, STATE, name)
        s['Pid'] = self.read_field(state_addr, STATE, 'Pid')
        s['ExitCode'] = self.read_field(state_addr, STATE, 'ExitCode')
        s['ErrorMsg'] = self.read_field(state_addr, STATE, 'ErrorMsg')
        s['Health_ptr'] = self.read_field(state_addr, STATE, 'Health')
        s['StartedAt'] = self.read_field(state_addr, STATE, 'StartedAt')
        s['FinishedAt'] = self.read_field(state_addr, STATE, 'FinishedAt')
        s['StartedAt_raw'] = self.read_time_raw(state_addr, STATE['StartedAt'][0])
        s['FinishedAt_raw'] = self.read_time_raw(state_addr, STATE['FinishedAt'][0])
        return s

    def parse_config(self, config_addr):
        """Read Config struct fields."""
        r = {}
        for name in ('Hostname', 'Domainname', 'User', 'Image', 'WorkingDir', 'StopSignal'):
            r[name] = self.read_field(config_addr, CONFIG, name)
        for name in ('AttachStdin', 'AttachStdout', 'AttachStderr', 'Tty', 'OpenStdin', 'StdinOnce'):
            r[name] = self.read_field(config_addr, CONFIG, name)
        return r

    def parse_hostconfig(self, hc_addr):
        """Read HostConfig struct fields."""
        r = {}
        for name in ('NetworkMode', 'RestartPolicy.Name', 'RestartPolicy.MaxRetryCount',
                      'AutoRemove', 'Privileged', 'Runtime'):
            r[name] = self.read_field(hc_addr, HOSTCONFIG, name)
        return r

    def parse_event(self, msg_addr):
        """Read Event Message struct fields."""
        r = {}
        for name in ('Status', 'ID', 'From', 'Type', 'Action', 'Actor.ID', 'Scope'):
            r[name] = self.read_field(msg_addr, EVENT_MESSAGE, name)
        r['Time'] = self.read_field(msg_addr, EVENT_MESSAGE, 'Time')
        r['TimeNano'] = self.read_field(msg_addr, EVENT_MESSAGE, 'TimeNano')
        return r

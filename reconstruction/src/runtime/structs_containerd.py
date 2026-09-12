import struct
import json
from .structs import StructReader

CONTAINER = {
    'ID':                  (0x0000, 16, 'string'),
    'Labels':              (0x0010,  8, 'map'),
    'Image':               (0x0018, 16, 'string'),
    'Runtime.Name':        (0x0028, 16, 'string'),
    'Runtime.Options':     (0x0038, 16, 'interface'),
    'Spec':                (0x0048, 16, 'interface'),
    'SnapshotKey':         (0x0058, 16, 'string'),
    'Snapshotter':         (0x0068, 16, 'string'),
    'CreatedAt':           (0x0078, 24, 'time.Time'),
    'UpdatedAt':           (0x0090, 24, 'time.Time'),
    'Extensions':          (0x00a8,  8, 'map'),
    'SandboxID':           (0x00b0, 16, 'string'),
}
CONTAINER_SIZE = 0xc0

IMAGE = {
    'Name':                (0x0000, 16, 'string'),
    'Labels':              (0x0010,  8, 'map'),
    'Target.MediaType':    (0x0018, 16, 'string'),
    'Target.Digest':       (0x0028, 16, 'string'),
    'Target.Size':         (0x0038,  8, 'int64'),
    'Target.URLs':         (0x0040, 24, 'slice'),
    'Target.Annotations':  (0x0058,  8, 'map'),
    'Target.Data':         (0x0060, 24, 'slice'),
    'Target.Platform':     (0x0078,  8, 'ptr'),
    'Target.ArtifactType': (0x0080, 16, 'string'),
    'CreatedAt':           (0x0090, 24, 'time.Time'),
    'UpdatedAt':           (0x00a8, 24, 'time.Time'),
}
IMAGE_SIZE = 0xc0

SHIM_INIT = {
    'wg':                 (0x0000, 16, 'sync.WaitGroup'),
    'initState':          (0x0010, 16, 'interface'),
    'mu':                 (0x0020,  8, 'sync.Mutex'),
    'waitBlock':          (0x0028,  8, 'chan'),
    'WorkDir':            (0x0030, 16, 'string'),
    'id':                 (0x0040, 16, 'string'),
    'Bundle':             (0x0050, 16, 'string'),
    'console':            (0x0060, 16, 'interface'),
    'Platform':           (0x0070, 16, 'interface'),
    'io':                 (0x0080,  8, 'ptr'),
    'runtime':            (0x0088,  8, 'ptr'),
    'pausing':            (0x0090,  4, 'atomic.Bool'),
    'status':             (0x0098,  8, 'int'),
    'exited':             (0x00a0, 24, 'time.Time'),
    'pid':                (0x00b8,  8, 'int'),
    'closers':            (0x00c0, 24, 'slice'),
    'stdin':              (0x00d8, 16, 'interface'),
    'stdio.Stdin':        (0x00e8, 16, 'string'),
    'stdio.Stdout':       (0x00f8, 16, 'string'),
    'stdio.Stderr':       (0x0108, 16, 'string'),
    'stdio.Terminal':     (0x0118,  1, 'bool'),
    'Rootfs':             (0x0120, 16, 'string'),
    'IoUID':              (0x0130,  8, 'int'),
    'IoGID':              (0x0138,  8, 'int'),
    'NoPivotRoot':        (0x0140,  1, 'bool'),
    'NoNewKeyring':       (0x0141,  1, 'bool'),
    'CriuWorkPath':       (0x0148, 16, 'string'),
}
SHIM_INIT_SIZE = 0x158

class ContainerdStructReader(StructReader):
    def _parse_struct(self, base_addr, struct_def):
        self.structure_names[id(struct_def)] = next((name for name, definition in
            [('containerd.Container', CONTAINER), ('containerd.Image', IMAGE), ('shim.process.Init', SHIM_INIT)]
            if definition is struct_def), 'containerd.structure')
        r = {}
        for name in struct_def:
            r[name] = self.read_field(base_addr, struct_def, name)
        return r

    def parse_containerd_container(self, base_addr):
        c = self._parse_struct(base_addr, CONTAINER)
        # c['Spec'] is a dict with 'type' and 'data' (pointers) from interface.
        spec_iface = c.get('Spec') or {}
        spec_data_ptr = spec_iface.get('data', 0)
        
        if spec_data_ptr:
            # spec_data_ptr points to a protobuf Any struct.
            # Actual layout (verified from memory dump):
            #   +0x00: internal state pointer (8 bytes)
            #   +0x08: TypeUrl string { Data *byte, Len int } (16 bytes)
            #   +0x18: Value []byte { Data *byte, Len int, Cap int } (24 bytes)
            t_url = self.read_string(spec_data_ptr, 0x08)
            
            # Read Value []byte
            val_ptr = self.read_ptr(spec_data_ptr, 0x18)
            val_len = self.read_int(spec_data_ptr, 0x20)
            
            if val_ptr and val_len and 0 < val_len <= 16 * 1024 * 1024:
                val_bytes = self.mem.read_safe(val_ptr, val_len)
                if val_bytes:
                    c['SpecValue'] = val_bytes
                    c['SpecTypeUrl'] = t_url
                    try:
                        spec = json.loads(val_bytes.decode('utf-8'))
                        if not isinstance(spec, dict) or not isinstance(spec.get('process', {}), dict):
                            raise ValueError('OCI JSON must be an object with an object process')
                        c['OciSpec'] = spec
                        c['SpecEncoding'] = 'json'
                    except Exception as e:
                        c['OciSpecError'] = str(e)
                        c['SpecEncoding'] = 'unsupported_or_invalid; opaque_payload_preserved'
                else:
                    c['OciSpecError'] = 'Any.Value pages unavailable'
            else:
                c['OciSpecError'] = 'Any.Value header invalid, empty, or exceeds 16 MiB limit'
        return c
        
    def parse_shim_init(self, base_addr):
        return self._parse_struct(base_addr, SHIM_INIT)

    def parse_containerd_image(self, base_addr):
        return self._parse_struct(base_addr, IMAGE)

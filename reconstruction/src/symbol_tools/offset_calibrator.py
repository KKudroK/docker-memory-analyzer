import re
import struct
import json
import os
import sys

PROJECT_DIR = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, PROJECT_DIR)

def log(msg):
    print(f"[Calibrator] {msg}", flush=True)

class MemoryScanner:
    def __init__(self, mem_obj):
        self.mem = mem_obj
        self.regions = mem_obj._regions if hasattr(mem_obj, '_regions') else []
        self._unpack_ptr = struct.Struct('<Q').unpack_from
        self._unpack_int = struct.Struct('<q').unpack_from
        
    def read_ptr(self, addr):
        for start, data in self.regions:
            if start <= addr < start + len(data):
                offset = addr - start
                if offset + 8 <= len(data):
                    return self._unpack_ptr(data, offset)[0]
        return 0

    def read_string(self, addr):
        ptr = self.read_ptr(addr)
        length = self.read_ptr(addr + 8)
        if length <= 0 or length > 4096:
            return ""
        for start, data in self.regions:
            if start <= ptr < start + len(data):
                offset = ptr - start
                if offset + length <= len(data):
                    try:
                        return data[offset:offset+length].decode('utf-8')
                    except UnicodeDecodeError:
                        return ""
        return ""

    def find_all_64_hex_strings(self):
        """Finds all physical addresses of 64-character hex strings in memory."""
        results = []
        for start, data in self.regions:
            for match in re.finditer(b'[a-f0-9]{64}', data):
                results.append(start + match.start())
        return results

    def find_string_structs_pointing_to(self, target_addrs):
        """Finds Go string structs {Data uintptr, Len int} pointing to the target addresses."""
        targets = set(target_addrs)
        results = []
        for start, data in self.regions:
            n = (len(data) // 8) * 8
            for off in range(0, n - 8, 8):
                ptr = self._unpack_ptr(data, off)[0]
                if ptr in targets:
                    length = self._unpack_int(data, off + 8)[0]
                    if length == 64:
                        results.append(start + off)
        return results

    def scan_for_config(self, base_addr, expected_id):
        expected_hostname = expected_id[:12]
        for offset in range(-128, 256, 8):
            ptr = self.read_ptr(base_addr + offset)
            if ptr != 0:
                hostname = self.read_string(ptr)
                if hostname == expected_hostname:
                    image_offset = self.scan_for_config_image(ptr)
                    if image_offset is not None:
                        return offset, image_offset
        return None, None

    def scan_for_state(self, base_addr):
        for offset in range(-128, 256, 8):
            ptr = self.read_ptr(base_addr + offset)
            if ptr != 0:
                for start, data in self.regions:
                    if start <= ptr < start + len(data):
                        off = ptr - start
                        if off + 16 <= len(data):
                            bools = data[off+8:off+15]
                            # In State, we have Running, Paused, Restarting, OOMKilled, RemovalInProgress, Dead
                            # They must be 0 or 1.
                            if all(b in (0, 1) for b in bools):
                                # Also, Mutex at offset 0 is usually initialized or zeroed
                                # A typical active container has Running=1 (bools[0]==1)
                                if sum(bools) > 0 and sum(bools) <= 2:
                                    # Ensure it's not the same pointer that config matched!
                                    # State usually doesn't have valid string headers at offset 0 and 16
                                    return offset
        return None

    def scan_for_hostconfig(self, base_addr):
        # HostConfig is a pointer, so we must read ptr first!
        for offset in range(-128, 512, 8):
            ptr = self.read_ptr(base_addr + offset)
            if ptr != 0:
                # NetworkMode is a string inside HostConfig, usually at offset 0x40 (64)
                # NetworkMode is an inline string, so we read it from ptr + 64
                s1 = self.read_string(ptr + 64)
                if isinstance(s1, str) and s1 in ('default', 'bridge', 'host', 'none'):
                    return offset
        return None

    def scan_for_networksettings(self, base_addr):
        # NetworkSettings is a pointer
        for offset in range(-128, 512, 8):
            ptr = self.read_ptr(base_addr + offset)
            if ptr != 0:
                bridge = self.read_string(ptr)
                sandbox = self.read_string(ptr + 16)
                if isinstance(bridge, str) and isinstance(sandbox, str):
                    if (bridge == 'docker0' or len(bridge) < 16) and len(sandbox) == 64:
                        return offset
        return None

    def scan_for_name(self, base_addr):
        # Name is a string (inline struct) starting with '/'
        for offset in range(-128, 512, 8):
            s1 = self.read_string(base_addr + offset)
            if isinstance(s1, str) and s1.startswith('/') and 1 < len(s1) < 64:
                if '.' not in s1 and s1.count('/') == 1:
                    return offset
        return None

    def scan_for_config_image(self, config_ptr):
        # Find Image string offset inside Config struct
        for offset in range(0x60, 0x120, 8):
            s1 = self.read_string(config_ptr + offset)
            if isinstance(s1, str) and 1 < len(s1) < 128:
                if re.match(r'^([a-zA-Z0-9_.-]+/)?[a-zA-Z0-9_.-]+(:[a-zA-Z0-9_.-]+)?(@sha256:[a-f0-9]{64})?$', s1):
                    # Check that it's not actually an Env string (Env is a slice)
                    return offset
        return None

def calibrate_dockerd(mem_obj):
    scanner = MemoryScanner(mem_obj)
    log("Scanning for 64-hex string data...")
    hex_addrs = scanner.find_all_64_hex_strings()
    log(f"Found {len(hex_addrs)} hex strings.")
    
    log("Scanning for Go string structs pointing to hex strings (Potential IDs)...")
    id_struct_addrs = scanner.find_string_structs_pointing_to(hex_addrs)
    log(f"Found {len(id_struct_addrs)} potential ID struct addresses.")
    
    offsets = {}
    
    for addr in id_struct_addrs:
        expected_id = scanner.read_string(addr)
        if not expected_id or len(expected_id) != 64:
            continue
            
        config_offset, image_offset = scanner.scan_for_config(addr, expected_id)
        state_offset = scanner.scan_for_state(addr)
        hostconfig_offset = scanner.scan_for_hostconfig(addr)
        network_offset = scanner.scan_for_networksettings(addr)
        name_offset = scanner.scan_for_name(addr)
        
        if config_offset is not None and state_offset is not None and config_offset != state_offset:
            log(f"SUCCESS! Calibrated offsets around ID struct at {hex(addr)}")
            offsets['ID'] = 0
            offsets['Config'] = config_offset
            offsets['State'] = state_offset
            if hostconfig_offset is not None:
                offsets['HostConfig'] = hostconfig_offset
            if network_offset is not None:
                offsets['NetworkSettings'] = network_offset
            if name_offset is not None:
                offsets['Name'] = name_offset
                
            if image_offset is not None:
                offsets['Config_Image'] = image_offset
                
            break
            
    return offsets

def main():
    import argparse
    from src.memory import VolatilityLoader
    
    parser = argparse.ArgumentParser(description="Dynamically calibrate Docker offsets.")
    parser.add_argument('-f', '--file', required=True, help="Path to memory dump")
    parser.add_argument('--venv', default=None)
    parser.add_argument('--output', default=os.path.join(PROJECT_DIR, 'outputs', 'offset_calibration', 'candidate_offsets.json'))
    args = parser.parse_args()

    log(f"Initializing Volatility 3 on {args.file} ...")
    loader = VolatilityLoader(args.file, venv_path=args.venv)
    try:
        loader.initialize()
    except Exception as e:
        log(f"Volatility Init Failed: {e}")
        return
        
    log("Extracting dockerd memory...")
    target_mems = loader.extract_target_processes(['dockerd'])
    dockerd_mem = None
    for pid, info in target_mems.items():
        if info['comm'] == 'dockerd':
            dockerd_mem = info['mem']
            
    if dockerd_mem:
        offsets = calibrate_dockerd(dockerd_mem)
        if offsets:
            log(f"Calibrated Offsets: {offsets}")
            dest = args.output
            os.makedirs(os.path.dirname(dest), exist_ok=True)
            with open(dest, 'w') as f:
                json.dump({"version": "unverified_candidate", "offsets": offsets,
                           "warning": "heuristic only; not applied by the analysis pipeline"}, f, indent=4)
            log(f"Saved to {dest}")
        else:
            log("Calibration failed.")
    else:
        log("No dockerd memory found.")

if __name__ == "__main__":
    main()

#!/usr/bin/env python3
"""Docker Version Fingerprinter and Symbol Extractor

This script analyzes a Linux memory dump using Volatility 3 to locate
Docker-related processes (dockerd, containerd, containerd-shim), precisely
extracts their versions from memory, and invokes the symbol builder to 
automatically generate ISF (Symbol files) containing structure offsets.
"""
import sys
import os
import re
import importlib.util

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
PROJECT_DIR = os.path.dirname(os.path.dirname(SCRIPT_DIR))
sys.path.insert(0, PROJECT_DIR)

from src.memory import VolatilityLoader
import src.symbol_builder as symbol_builder

def log(msg):
    print(f"[DockerSymbol] {msg}", flush=True)

def search_memory_for_pattern(mem_obj, pattern_bytes):
    """Searches the cached memory regions for a specific byte pattern."""
    if not mem_obj or not hasattr(mem_obj, '_regions'):
        return None
    
    for start, data in mem_obj._regions:
        match = re.search(pattern_bytes, data)
        if match:
            return match.group(1).decode('utf-8', errors='ignore')
    return None

def extract_dockerd_version(mem_obj):
    # Try different known formats for dockerd versions
    patterns = [
        b'Docker version (\\d+\\.\\d+\\.\\d+[-0-9a-zA-Z]*)',
        b'github\\.com/docker/docker/?[\\w/-]* v(\\d+\\.\\d+\\.\\d+[-0-9a-zA-Z]*)'
    ]
    for p in patterns:
        v = search_memory_for_pattern(mem_obj, p)
        if v:
            return v
    return None

def extract_containerd_version(mem_obj):
    patterns = [
        b'containerd github\\.com/containerd/containerd v(\\d+\\.\\d+\\.\\d+[-0-9a-zA-Z]*)',
        b'github\\.com/containerd/containerd/?[\\w/-]* v(\\d+\\.\\d+\\.\\d+[-0-9a-zA-Z]*)'
    ]
    for p in patterns:
        v = search_memory_for_pattern(mem_obj, p)
        if v:
            return v
    return None

def main():
    import argparse
    parser = argparse.ArgumentParser(description="Extract Docker versions from memory and generate symbols.")
    parser.add_argument('-f', '--file', required=True, help="Path to memory dump")
    parser.add_argument('--venv', default=None, help="Optional Volatility 3 site-packages path")
    parser.add_argument('--dockerd-version', help="Manually specify dockerd version if detection fails")
    parser.add_argument('--containerd-version', help="Manually specify containerd version if detection fails")
    args = parser.parse_args()

    log(f"Initializing Volatility 3 on {args.file} ...")
    loader = VolatilityLoader(args.file, venv_path=args.venv)
    try:
        loader.initialize()
    except Exception as e:
        log(f"Failed to initialize Volatility: {e}")
        sys.exit(1)
        
    log("Scanning for Docker processes and extracting memory...")
    target_mems = loader.extract_target_processes(['dockerd', 'containerd'])
    
    dockerd_mem = None
    containerd_mem = None
    
    for pid, info in target_mems.items():
        if info['comm'] == 'dockerd':
            dockerd_mem = info['mem']
            dockerd_pid = pid
        elif info['comm'] == 'containerd':
            containerd_mem = info['mem']
            containerd_pid = pid

    # Handle dockerd
    dockerd_version = args.dockerd_version
    if not dockerd_version and dockerd_mem:
        log(f"Scanning dockerd (PID: {dockerd_pid}) memory for version string...")
        dockerd_version = extract_dockerd_version(dockerd_mem)
        if dockerd_version:
            log(f"-> Detected dockerd version: {dockerd_version}")
        else:
            log("Could not detect dockerd version.")
            
    if dockerd_version:
        # Check and build symbols
        dest = os.path.join(PROJECT_DIR, 'symbols', 'dockerd', f"{dockerd_version}.json")
        if not os.path.exists(dest):
            log(f"Symbols for dockerd {dockerd_version} not found. Generating...")
            symbol_builder.generate_dockerd_isf(dockerd_version)
        else:
            log(f"Symbols for dockerd {dockerd_version} already exist.")

    # Handle containerd
    containerd_version = args.containerd_version
    if not containerd_version and containerd_mem:
        log(f"Scanning containerd (PID: {containerd_pid}) memory for version string...")
        containerd_version = extract_containerd_version(containerd_mem)
        if containerd_version:
            log(f"-> Detected containerd version: {containerd_version}")
        else:
            log("Could not detect containerd version.")

    if containerd_version:
        # Check and build symbols
        dest = os.path.join(PROJECT_DIR, 'symbols', 'containerd', f"{containerd_version}.json")
        if not os.path.exists(dest):
            log(f"Symbols for containerd {containerd_version} not found. Generating...")
            symbol_builder.generate_containerd_isf(containerd_version)
        else:
            log(f"Symbols for containerd {containerd_version} already exist.")

    log("Symbol generation complete. Ready for analysis.")

if __name__ == "__main__":
    main()

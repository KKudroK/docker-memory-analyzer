#!/usr/bin/env python3
"""Docker / Containerd ISF (Symbol) Builder

This script automatically downloads the canonical binary for a specified
Docker or containerd version, runs GoReSym to extract the Go RTTI structure
offsets, and generates the Volatility-style JSON symbol files (ISF) used
by the memory analyzer.
"""
import os
import sys
import json
import urllib.request
import tarfile
import tempfile
import subprocess
import shutil
import re
from pathlib import Path

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
PROJECT_DIR = os.path.dirname(os.path.dirname(SCRIPT_DIR))
SYMBOLS_DIR = os.path.join(PROJECT_DIR, 'symbols')
GORESYM_PATH = os.path.join(PROJECT_DIR, 'tools', 'GoReSym', 'GoReSym.exe')

# List of critical structures to extract
DOCKER_TARGET_STRUCTS = [
    "github.com/docker/docker/daemon.Daemon",
    "github.com/docker/docker/container.Container",
    "github.com/docker/docker/api/types/container.Config",
    "github.com/docker/docker/api/types/container.HostConfig",
    "github.com/docker/docker/container.State"
]

CONTAINERD_TARGET_STRUCTS = [
    "github.com/containerd/containerd/containers.Container",
    "github.com/containerd/containerd/runtime/v2/task.Task",
    "github.com/containerd/containerd/runtime/v2/shim.shim"
]

def log(msg):
    print(f"[SymbolBuilder] {msg}")


def validate_cached_profile(path, version, component):
    """An existing filename is not evidence of a usable offset profile."""
    with open(path, encoding='utf-8') as stream:
        profile = json.load(stream)
    structs = profile.get('structs')
    if (profile.get('version') != version or profile.get('component') != component
            or not isinstance(structs, dict) or not structs):
        raise ValueError(f'Invalid cached symbol profile: {path}')
    for fields in structs.values():
        if not isinstance(fields, dict) or not fields:
            raise ValueError(f'Empty cached structure: {path}')
        for field in fields.values():
            if (not isinstance(field, dict) or type(field.get('offset')) is not int
                    or field['offset'] < 0 or not field.get('type') or not field.get('kind')):
                raise ValueError(f'Invalid cached field offset: {path}')
    return profile

def download_and_extract(url, target_filename, extract_dir):
    """Downloads a tar.gz file and extracts a specific file from it."""
    log(f"Downloading {url} ...")
    temp_tar, _ = urllib.request.urlretrieve(url)
    
    log(f"Extracting {target_filename} ...")
    extracted_path = None
    with tarfile.open(temp_tar, "r:gz") as tar:
        for member in tar.getmembers():
            # Check if the filename ends with the target (e.g. docker/dockerd)
            if member.isfile() and Path(member.name).name == target_filename:
                extracted_path = str(Path(extract_dir) / target_filename)
                with tar.extractfile(member) as source, open(extracted_path, 'wb') as destination:
                    shutil.copyfileobj(source, destination)
                break
    
    os.remove(temp_tar)
    if not extracted_path or not os.path.exists(extracted_path):
        raise Exception(f"Could not extract {target_filename} from {url}")
    
    return extracted_path

def run_goresym(binary_path):
    """Runs GoReSym on the given binary and returns the JSON parsed output."""
    if not os.path.exists(GORESYM_PATH):
        raise FileNotFoundError(f"GoReSym not found at {GORESYM_PATH}")
        
    log(f"Running GoReSym on {binary_path} ...")
    # Run GoReSym and capture output
    result = subprocess.run(
        [GORESYM_PATH, "-t", "-d", binary_path],
        capture_output=True,
        text=True,
        encoding="utf-8"
    )
    
    if result.returncode != 0:
        raise Exception(f"GoReSym failed: {result.stderr}")
        
    try:
        data = json.loads(result.stdout)
        return data
    except json.JSONDecodeError as e:
        raise Exception(f"Failed to parse GoReSym JSON output: {e}")

def build_isf_profile(goresym_data, version, component, target_structs):
    """Builds the final ISF JSON format containing only necessary structs and fields."""
    profile = {
        "version": version,
        "component": component,
        "structs": {}
    }
    
    types = goresym_data.get('Types', [])
    for t in types:
        name = t.get('Name', t.get('Str', ''))
        if name in target_structs:
            struct_info = {}
            for field in t.get('Fields', []):
                struct_info[field['Name']] = {
                    "offset": field['Offset'],
                    "type": field['Type'],
                    "kind": field['Kind']
                }
            profile["structs"][name] = struct_info
            
    if not profile['structs'] or not all(profile['structs'].values()):
        raise ValueError('GoReSym output lacks explicit field offsets; refusing to generate an empty or guessed profile')
    return profile

def generate_dockerd_isf(version):
    """Generates the ISF JSON for a specific dockerd version."""
    if not re.fullmatch(r'v?\d+\.\d+\.\d+(?:[-.][A-Za-z0-9.-]+)?', version):
        raise ValueError('Invalid version identifier')
    os.makedirs(os.path.join(SYMBOLS_DIR, 'dockerd'), exist_ok=True)
    dest_json = os.path.join(SYMBOLS_DIR, 'dockerd', f"{version}.json")
    if os.path.exists(dest_json):
        validate_cached_profile(dest_json, version, 'dockerd')
        log(f"Symbol file already exists: {dest_json}")
        return dest_json

    # Docker static binary URL format
    url = f"https://download.docker.com/linux/static/stable/x86_64/docker-{version}.tgz"
    
    with tempfile.TemporaryDirectory() as temp_dir:
        try:
            binary_path = download_and_extract(url, "dockerd", temp_dir)
            goresym_data = run_goresym(binary_path)
            profile = build_isf_profile(goresym_data, version, "dockerd", DOCKER_TARGET_STRUCTS)
            
            with open(dest_json, 'w') as f:
                json.dump(profile, f, indent=4)
            log(f"Successfully created dockerd ISF profile for {version} at {dest_json}")
            return dest_json
        except Exception as e:
            log(f"Error generating dockerd ISF: {e}")
            return None

def generate_containerd_isf(version):
    """Generates the ISF JSON for a specific containerd version."""
    if not re.fullmatch(r'v?\d+\.\d+\.\d+(?:[-.][A-Za-z0-9.-]+)?', version):
        raise ValueError('Invalid version identifier')
    os.makedirs(os.path.join(SYMBOLS_DIR, 'containerd'), exist_ok=True)
    dest_json = os.path.join(SYMBOLS_DIR, 'containerd', f"{version}.json")
    if os.path.exists(dest_json):
        validate_cached_profile(dest_json, version.lstrip('v'), 'containerd')
        log(f"Symbol file already exists: {dest_json}")
        return dest_json

    # Remove 'v' prefix if it exists in the URL template but passed directly
    clean_version = version.lstrip('v')
    url = f"https://github.com/containerd/containerd/releases/download/v{clean_version}/containerd-{clean_version}-linux-amd64.tar.gz"
    
    with tempfile.TemporaryDirectory() as temp_dir:
        try:
            binary_path = download_and_extract(url, "containerd", temp_dir)
            goresym_data = run_goresym(binary_path)
            profile = build_isf_profile(goresym_data, clean_version, "containerd", CONTAINERD_TARGET_STRUCTS)
            
            with open(dest_json, 'w') as f:
                json.dump(profile, f, indent=4)
            log(f"Successfully created containerd ISF profile for v{clean_version} at {dest_json}")
            return dest_json
        except Exception as e:
            log(f"Error generating containerd ISF: {e}")
            return None

if __name__ == "__main__":
    if len(sys.argv) < 3:
        print("Usage: python symbol_builder.py <dockerd|containerd> <version>")
        sys.exit(1)
        
    component = sys.argv[1].lower()
    version = sys.argv[2]
    
    if component == "dockerd":
        generate_dockerd_isf(version)
    elif component == "containerd":
        generate_containerd_isf(version)
    else:
        print(f"Unknown component: {component}")

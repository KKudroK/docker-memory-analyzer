#!/usr/bin/env python3
"""릴리스에서 받은 gzip 자료를 해시 확인 후 evidence/에 복원한다.

예: python tools/unpack_evidence.py evidence/downloads/*.gz
PowerShell에서는 두 gzip 파일의 경로를 각각 지정한다. 원본이나 기존 결과를
덮어쓰지 않으며, 압축 파일과 복원된 파일의 크기 및 SHA-256을 모두 확인한다.
"""
import argparse
import gzip
import hashlib
import json
from pathlib import Path
import tempfile

BASE = Path(__file__).resolve().parents[1]
TARGETS = {"memory.lime.gz": "memory.lime",
           "ubuntu-7.0.0-31-btf.json.gz": "symbols/linux/ubuntu-7.0.0-31-btf.json"}


def digest(path):
    hasher = hashlib.sha256()
    with path.open("rb") as stream:
        while chunk := stream.read(8 * 1024 * 1024):
            hasher.update(chunk)
    return hasher.hexdigest()


def unpack(archive, destination, record):
    if archive.stat().st_size != record["asset_bytes"] or digest(archive) != record["asset_sha256"]:
        raise ValueError(f"압축 파일 크기/해시 불일치: {archive.name}")
    target = destination / TARGETS[archive.name]
    if target.exists():
        if target.is_file() and target.stat().st_size == record["source_bytes"] and digest(target) == record["source_sha256"]:
            print(f"기존 파일 검증 완료: {target}")
            return
        raise ValueError(f"기존 파일을 덮어쓰지 않습니다: {target}")
    target.parent.mkdir(parents=True, exist_ok=True)
    pending = None
    try:
        # 같은 디렉터리의 임시 파일에 쓰고 완전한 검증 후 이름을 바꾼다.
        with tempfile.NamedTemporaryFile(dir=target.parent, prefix=target.name + ".", suffix=".part", delete=False) as output:
            pending = Path(output.name)
            hasher, size = hashlib.sha256(), 0
            with gzip.open(archive, "rb") as source:
                while chunk := source.read(8 * 1024 * 1024):
                    size += len(chunk)
                    if size > record["source_bytes"]:
                        raise ValueError("복원 크기가 기록된 원본 크기를 초과합니다.")
                    hasher.update(chunk)
                    output.write(chunk)
        if size != record["source_bytes"] or hasher.hexdigest() != record["source_sha256"]:
            raise ValueError(f"복원 파일 크기/해시 불일치: {archive.name}")
        if target.exists():
            raise ValueError(f"복원 도중 대상 파일이 생겼습니다: {target}")
        pending.rename(target)
        print(f"복원 및 SHA-256 검증 완료: {target}")
    finally:
        if pending is not None:
            pending.unlink(missing_ok=True)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("archives", type=Path, nargs="+")
    parser.add_argument("--destination", type=Path, default=BASE / "evidence")
    args = parser.parse_args()
    records = json.loads((BASE / "evidence/manifest.json").read_text(encoding="utf-8"))
    by_name = {entry["asset_name"]: entry for entry in records["assets"]}
    try:
        for archive in args.archives:
            if archive.name not in TARGETS:
                raise ValueError(f"이 실험의 배포 파일이 아닙니다: {archive.name}")
            unpack(archive, args.destination.resolve(), by_name[archive.name])
    except (OSError, ValueError, EOFError) as exc:
        parser.exit(1, f"복원 실패: {exc}\n")


if __name__ == "__main__":
    main()

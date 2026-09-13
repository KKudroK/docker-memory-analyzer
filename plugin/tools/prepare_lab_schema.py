#!/usr/bin/env python3
"""제공한 BTF 실험 심볼용 Volatility 2.28.0 메타데이터 허용 준비.

가상환경의 Python으로 ``python tools/prepare_lab_schema.py``를 실행한다.
원복은 같은 명령에 ``--restore``를 붙인다. 덤프와 심볼 파일은 수정하지
않으며 JSON 스키마 검사를 유지한다. 일반 dwarf2json 심볼에는 필요 없다.
"""

from __future__ import annotations

import argparse
import hashlib
import importlib.metadata
import importlib.util
import json
import os
from pathlib import Path
import shutil
import sys
import tempfile


VOLATILITY_VERSION = "2.28.0"
# btf/symdb는 심볼 생성 출처의 이름이다. 허용해도 필드 오프셋·주소나 스키마 검증은 바꾸지 않는다.
STOCK_PATTERN = "^(dwarf|symtab|system-map)$"
LAB_PATTERN = "^(btf|symdb|dwarf|symtab|system-map)$"
# PyPI volatility3 2.28.0 wheel에 포함된 원본 스키마의 SHA-256이다.
# 예상과 다른 코어 수정 위에 패치를 겹쳐 적용하지 않는다.
STOCK_SHA256 = "39386442c722598f55213399b1bc603b49c7ecd43ecf58c2f110a97624da5246"
BACKUP_SUFFIX = ".containercaps-original"


def schema_state(raw: bytes) -> str:
    """알려진 원본 또는 아래 한 항목만 수정된 스키마인지 확인한다."""
    try:
        document = json.loads(raw)
        pattern = document["definitions"]["metadata_nix_item"]["properties"]["kind"][
            "pattern"
        ]
    except (ValueError, KeyError, TypeError) as exc:
        raise RuntimeError("예상한 metadata_nix_item.kind 스키마가 아닙니다.") from exc
    if pattern not in (STOCK_PATTERN, LAB_PATTERN):
        raise RuntimeError("예상과 다른 메타데이터 허용 패턴입니다. 수정하지 않았습니다.")
    if raw.count(pattern.encode("ascii")) != 1:
        raise RuntimeError("수정 대상 패턴이 정확히 한 곳에 있어야 합니다.")
    normalized = raw.replace(LAB_PATTERN.encode("ascii"), STOCK_PATTERN.encode("ascii"))
    if hashlib.sha256(normalized).hexdigest() != STOCK_SHA256:
        raise RuntimeError("공식 2.28.0 스키마와 다른 내용입니다. 수정하지 않았습니다.")
    return "stock" if pattern == STOCK_PATTERN else "prepared"


def installed_schema() -> Path:
    """시스템 Python 및 가상환경 밖의 editable 설치를 수정 대상에서 제외한다."""
    prefix = Path(sys.prefix).resolve()
    if prefix == Path(sys.base_prefix).resolve():
        raise RuntimeError("전용 가상환경(.venv)의 Python으로 실행하세요.")
    try:
        installed_version = importlib.metadata.version("volatility3")
    except importlib.metadata.PackageNotFoundError as exc:
        raise RuntimeError("이 가상환경에 volatility3==2.28.0을 설치하세요.") from exc
    if installed_version != VOLATILITY_VERSION:
        raise RuntimeError(f"Volatility {installed_version} 감지: 정확히 2.28.0만 지원합니다.")
    if importlib.util.find_spec("jsonschema") is None:
        raise RuntimeError("유효성 검사를 유지하려면 이 가상환경에 jsonschema를 설치하세요.")
    spec = importlib.util.find_spec("volatility3")
    if spec is None or spec.origin is None:
        raise RuntimeError("Volatility 설치 위치를 확인할 수 없습니다.")
    schema = (Path(spec.origin).parent / "schemas" / "schema-6.2.0.json").resolve()
    if not schema.is_relative_to(prefix):
        raise RuntimeError("스키마가 현재 가상환경 밖에 있습니다. editable 설치는 수정하지 않습니다.")
    if not schema.is_file():
        raise RuntimeError("설치된 schema-6.2.0.json을 찾을 수 없습니다.")
    return schema


def replace_atomically(path: Path, raw: bytes) -> None:
    """쓰기 도중 중단되어도 원본 스키마가 잘린 파일이 되지 않게 한다."""
    temp_path: Path | None = None
    try:
        with tempfile.NamedTemporaryFile(dir=path.parent, prefix=path.name + ".", delete=False) as temp:
            temp_path = Path(temp.name)
            temp.write(raw)
            temp.flush()
            os.fsync(temp.fileno())
        shutil.copymode(path, temp_path)
        temp_path.replace(path)
    finally:
        if temp_path is not None:
            temp_path.unlink(missing_ok=True)


def prepare_schema(path: Path, *, restore: bool = False) -> str:
    """원본 백업을 보존하며 멱등 적용하거나 정확한 원본으로 복원한다."""
    raw = path.read_bytes()
    state = schema_state(raw)
    backup = path.with_name(path.name + BACKUP_SUFFIX)
    if backup.exists():
        if schema_state(backup.read_bytes()) != "stock":
            raise RuntimeError("백업이 공식 원본과 다릅니다. 수정하지 않았습니다.")
    elif state == "prepared":
        raise RuntimeError("이미 수정된 스키마에 원본 백업이 없습니다. 자동 변경하지 않습니다.")
    elif not restore:
        # 기존 백업을 덮어쓰지 않는다. 새 백업 생성이 끝난 후에만 수정한다.
        with backup.open("xb") as stream:
            stream.write(raw)
            stream.flush()
            os.fsync(stream.fileno())
    if restore:
        if state == "stock":
            return "이미 공식 원본 상태입니다."
        replace_atomically(path, backup.read_bytes())
        return "공식 원본 스키마로 복원했습니다. 백업은 보존했습니다."
    if state == "prepared":
        return "이미 준비되어 있습니다. 스키마와 백업을 확인했습니다."
    modified = raw.replace(STOCK_PATTERN.encode("ascii"), LAB_PATTERN.encode("ascii"))
    if schema_state(modified) != "prepared":
        raise RuntimeError("수정 결과 검증에 실패했습니다.")
    replace_atomically(path, modified)
    return "btf/symdb 메타데이터 출처만 추가 허용했습니다. 유효성 검사는 유지합니다."


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--restore", action="store_true", help="보존한 공식 원본 스키마로 복원")
    args = parser.parse_args()
    try:
        path = installed_schema()
        message = prepare_schema(path, restore=args.restore)
    except (OSError, RuntimeError) as exc:
        print(f"준비 실패: {exc}", file=sys.stderr)
        return 1
    print(message)
    print(f"대상: {path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

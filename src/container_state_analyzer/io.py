from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from .model import EvidenceCase


def load_json(path: str | Path) -> Any:
    with Path(path).open("r", encoding="utf-8") as stream:
        return json.load(stream)


def save_json(path: str | Path, value: Any) -> Path:
    target = Path(path)
    target.parent.mkdir(parents=True, exist_ok=True)
    with target.open("w", encoding="utf-8", newline="\n") as stream:
        json.dump(value, stream, ensure_ascii=False, indent=2)
        stream.write("\n")
    return target


def load_cases(path: str | Path) -> list[EvidenceCase]:
    data = load_json(path)
    if isinstance(data, dict) and "cases" in data:
        rows = data["cases"]
    elif isinstance(data, list):
        rows = data
    elif isinstance(data, dict):
        rows = [data]
    else:
        raise ValueError("Input must be one case, a list of cases, or an object with a 'cases' array")
    return [EvidenceCase.from_dict(row) for row in rows]


def save_cases(path: str | Path, cases: list[EvidenceCase], source: dict[str, Any] | None = None) -> Path:
    payload = {
        "schema_version": "1.0",
        "source": source or {},
        "cases": [case.to_dict() for case in cases],
    }
    return save_json(path, payload)

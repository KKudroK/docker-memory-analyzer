from __future__ import annotations

import json
from importlib.resources import files
from pathlib import Path
from typing import Any


def load_rules(path: str | Path | None = None) -> dict[str, Any]:
    if path is None:
        target = files("container_state_analyzer").joinpath("data/rules-v2.json")
        with target.open("r", encoding="utf-8") as stream:
            return json.load(stream)
    with Path(path).open("r", encoding="utf-8") as stream:
        return json.load(stream)


def load_priority_axes(path: str | Path | None = None) -> dict[str, Any]:
    if path is None:
        target = files("container_state_analyzer").joinpath("data/artifact-priority-v2.json")
        with target.open("r", encoding="utf-8") as stream:
            return json.load(stream)
    with Path(path).open("r", encoding="utf-8") as stream:
        return json.load(stream)


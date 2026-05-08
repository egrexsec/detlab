from pathlib import Path
from typing import Iterable

import yaml


def find_detection_files(path: Path) -> list[Path]:
    return sorted([p for p in path.rglob("*.yml")] + [p for p in path.rglob("*.yaml")])


def load_yaml_file(path: Path) -> dict:
    with path.open("r", encoding="utf-8") as f:
        data = yaml.safe_load(f)
    return data or {}


def iter_detection_files(path: Path) -> Iterable[Path]:
    for file in find_detection_files(path):
        yield file

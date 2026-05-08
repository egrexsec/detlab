from pathlib import Path
from typing import Tuple

import yaml
from pydantic import ValidationError

from detlab.models import Detection


def load_yaml(path: Path) -> dict:
    with path.open("r", encoding="utf-8") as f:
        data = yaml.safe_load(f)
    return data or {}


def load_detection_file(path: Path) -> Detection:
    data = load_yaml(path)
    return Detection.model_validate(data)


def load_detection_dir(path: Path) -> Tuple[list[Path], bool, dict[Path, str]]:
    files = sorted([p for p in path.rglob("*.yml")] + [p for p in path.rglob("*.yaml")])
    errors: dict[Path, str] = {}

    for file in files:
        try:
            load_detection_file(file)
        except ValidationError as e:
            errors[file] = str(e)
        except Exception as e:
            errors[file] = str(e)

    return files, len(errors) == 0, errors

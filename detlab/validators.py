from pathlib import Path
from typing import Tuple

from pydantic import ValidationError

from detlab.models import Detection
from detlab.parser import find_detection_files, load_yaml_file


def load_detection_file(path: Path) -> Detection:
    data = load_yaml_file(path)
    return Detection.model_validate(data)


def load_detection_dir(path: Path) -> Tuple[list[Path], bool, dict[Path, str]]:
    files = find_detection_files(path)
    errors: dict[Path, str] = {}

    for file in files:
        try:
            load_detection_file(file)
        except ValidationError as e:
            errors[file] = str(e)
        except Exception as e:
            errors[file] = str(e)

    return files, len(errors) == 0, errors

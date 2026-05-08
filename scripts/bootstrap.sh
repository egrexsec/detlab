#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"

cd "$REPO_ROOT"

mkdir -p detlab detections/windows tests .github/workflows reports scripts
touch reports/.gitkeep

cat > pyproject.toml <<'EOF'
[build-system]
requires = ["setuptools>=69", "wheel"]
build-backend = "setuptools.build_meta"

[project]
name = "detlab"
version = "0.1.0"
description = "Detection-as-code validation and ATT&CK coverage reporting CLI."
readme = "README.md"
requires-python = ">=3.11"
license = { text = "MIT" }
authors = [
  { name = "Mell0wx" }
]
dependencies = [
  "typer>=0.12.0",
  "pydantic>=2.7.0",
  "PyYAML>=6.0.1",
  "rich>=13.7.0"
]

[project.optional-dependencies]
dev = [
  "pytest>=8.0.0",
  "ruff>=0.4.0"
]

[project.scripts]
detlab = "detlab.main:app"

[tool.setuptools]
packages = ["detlab"]

[tool.ruff]
line-length = 100
target-version = "py311"

[tool.pytest.ini_options]
testpaths = ["tests"]
EOF

cat > README.md <<'EOF'
# DetLab

DetLab is an open-source detection-as-code CLI for validating detection content, mapping detections to MITRE ATT&CK, and generating coverage reports for security teams.

It is built for defenders who want to treat detections like code: versioned, tested, reviewable, and automation-friendly.

## Why DetLab exists

Detection content often lives in scattered notes, SIEM dashboards, or undocumented rules. DetLab helps turn that into a structured workflow with:
- Schema validation for detection files
- ATT&CK technique mapping
- Reproducible test references
- Markdown and JSON coverage reports
- GitHub Actions-friendly automation

## Features

- Validate YAML detection files
- Enforce required metadata
- Check ATT&CK ID formatting
- Ensure every detection has at least one test reference
- Generate simple ATT&CK coverage reports
- Integrate with CI for pull request validation

## Installation

```bash
git clone https://github.com/YOUR_USERNAME/detlab.git
cd detlab
python -m venv .venv
source .venv/bin/activate
pip install .[dev]
```

## Quick start

```bash
detlab validate detections
detlab report --path detections --format markdown --output reports/coverage.md
detlab map-attck detections --output reports/attack-map.json
```

## Roadmap

- v0.1: Validation, ATT&CK mapping, markdown/json reports
- v0.2: Sigma import/export
- v0.3: Splunk and KQL exporters
- v0.4: Microsoft 365 / Entra ID support
- v0.5: AWS CloudTrail support

## Contributing

Please read [CONTRIBUTING.md](CONTRIBUTING.md).

## Security

Please read [SECURITY.md](SECURITY.md).

## License

MIT
EOF

cat > CONTRIBUTING.md <<'EOF'
# Contributing to DetLab

Thanks for your interest in contributing to DetLab.

## Ways to contribute

- Add new detections
- Improve validation logic
- Add new report formats
- Improve documentation
- Add test coverage
- Suggest integrations for Sigma, Splunk, KQL, or cloud logs

## Development setup

```bash
git clone https://github.com/YOUR_USERNAME/detlab.git
cd detlab
python -m venv .venv
source .venv/bin/activate
pip install .[dev]
```

## Run checks

```bash
ruff check .
pytest
detlab validate detections
```

## Pull request guidelines

- Create focused pull requests
- Add or update tests for code changes
- Keep detection metadata complete
- Document new commands or schema fields
- Use clear commit messages
EOF

cat > SECURITY.md <<'EOF'
# Security Policy

## Reporting a vulnerability

Please do not report security vulnerabilities through public GitHub issues.

Instead, report them privately by emailing: your-public-security-email@example.com

Include:
- A description of the issue
- Steps to reproduce
- Potential impact
- Suggested remediation, if known

## Scope

This project is an open-source security workflow tool. Reports are especially helpful for:
- Unsafe file handling
- Command injection risks
- Dependency vulnerabilities
- Insecure CI/CD behavior
- Malicious parser edge cases

## Supported versions

At this stage, only the latest version on the `main` branch is supported for security fixes.
EOF

cat > CHANGELOG.md <<'EOF'
# Changelog

## v0.1.0 - 2026-05-08

### Added
- Initial DetLab CLI release
- YAML detection validation with Pydantic
- ATT&CK technique mapping output
- Markdown and JSON coverage reporting
- Sample Windows detections for PowerShell, Rundll32, and Certutil
- Pytest-based CLI tests
- GitHub Actions CI workflow
EOF

cat > .gitignore <<'EOF'
.venv/
__pycache__/
.pytest_cache/
.ruff_cache/
*.pyc
dist/
build/
*.egg-info/
reports/*.json
reports/*.md
EOF

cat > LICENSE <<'EOF'
MIT License

Copyright (c) 2026 Mell0wx

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
EOF

cat > detlab/__init__.py <<'EOF'
__all__ = ["__version__"]

__version__ = "0.1.0"
EOF

cat > detlab/models.py <<'EOF'
import re
from typing import Any

from pydantic import BaseModel, Field, field_validator, model_validator

ATTACK_ID_RE = re.compile(r"^T\d{4}(?:\.\d{3})?$")


class LogSource(BaseModel):
    product: str
    service: str


class Attack(BaseModel):
    technique: str
    tactic: str

    @field_validator("technique")
    @classmethod
    def validate_technique(cls, value: str) -> str:
        if not ATTACK_ID_RE.match(value):
            raise ValueError("attack.technique must look like T1059 or T1059.001")
        return value


class TestRef(BaseModel):
    name: str
    source: str
    test_id: str


class DetectionLogic(BaseModel):
    selection: dict[str, Any]
    condition: str


class Detection(BaseModel):
    id: str = Field(pattern=r"^DET-\d{4}$")
    title: str
    description: str
    logsource: LogSource
    attack: Attack
    severity: str
    status: str
    author: str
    references: list[str] = []
    falsepositives: list[str] = []
    tests: list[TestRef]
    detection: DetectionLogic

    @field_validator("severity")
    @classmethod
    def validate_severity(cls, value: str) -> str:
        allowed = {"low", "medium", "high", "critical"}
        if value not in allowed:
            raise ValueError(f"severity must be one of: {', '.join(sorted(allowed))}")
        return value

    @field_validator("status")
    @classmethod
    def validate_status(cls, value: str) -> str:
        allowed = {"experimental", "testing", "stable", "deprecated"}
        if value not in allowed:
            raise ValueError(f"status must be one of: {', '.join(sorted(allowed))}")
        return value

    @model_validator(mode="after")
    def validate_tests_present(self) -> "Detection":
        if not self.tests:
            raise ValueError("at least one test must be defined")
        return self
EOF

cat > detlab/parser.py <<'EOF'
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
EOF

cat > detlab/validators.py <<'EOF'
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
EOF

cat > detlab/attck.py <<'EOF'
from collections import defaultdict

from detlab.models import Detection


def build_technique_map(detections: list[Detection]) -> dict[str, list[dict]]:
    mapping = defaultdict(list)

    for det in detections:
        mapping[det.attack.technique].append(
            {
                "id": det.id,
                "title": det.title,
                "tactic": det.attack.tactic,
                "severity": det.severity,
                "status": det.status,
                "author": det.author,
                "logsource": {
                    "product": det.logsource.product,
                    "service": det.logsource.service,
                },
                "tests": [
                    {
                        "name": test.name,
                        "source": test.source,
                        "test_id": test.test_id,
                    }
                    for test in det.tests
                ],
            }
        )

    return dict(sorted(mapping.items()))


def summarize_coverage(detections: list[Detection]) -> dict:
    techniques = sorted({d.attack.technique for d in detections})
    tactics = sorted({d.attack.tactic for d in detections})
    high_severity = [d for d in detections if d.severity in {"high", "critical"}]

    return {
        "total_detections": len(detections),
        "techniques_covered": len(techniques),
        "tactics_covered": len(tactics),
        "high_or_critical_detections": len(high_severity),
        "techniques": techniques,
        "tactics": tactics,
    }
EOF

cat > detlab/reporting.py <<'EOF'
from pathlib import Path
import json

from detlab.attck import summarize_coverage
from detlab.models import Detection


def generate_markdown_report(detections: list[Detection]) -> str:
    summary = summarize_coverage(detections)

    lines = [
        "# DetLab Coverage Report",
        "",
        "## Summary",
        "",
        f"- Total detections: {summary['total_detections']}",
        f"- ATT&CK techniques covered: {summary['techniques_covered']}",
        f"- ATT&CK tactics covered: {summary['tactics_covered']}",
        f"- High/critical detections: {summary['high_or_critical_detections']}",
        "",
        "## Detection Coverage",
        "",
        "| Technique | Tactic | Detection ID | Title | Severity | Status | Tests |",
        "|---|---|---|---|---|---|---|",
    ]

    for det in sorted(detections, key=lambda d: (d.attack.technique, d.id)):
        lines.append(
            f"| {det.attack.technique} | {det.attack.tactic} | {det.id} | {det.title} | {det.severity} | {det.status} | {len(det.tests)} |"
        )

    lines.extend(["", "## Techniques", ""])

    for technique in summary["techniques"]:
        lines.append(f"- {technique}")

    return "\n".join(lines)


def generate_json_report(detections: list[Detection]) -> str:
    summary = summarize_coverage(detections)
    payload = {
        "summary": summary,
        "detections": [d.model_dump() for d in detections],
    }
    return json.dumps(payload, indent=2)


def write_report(output: str, content: str) -> None:
    path = Path(output)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content, encoding="utf-8")
EOF

cat > detlab/main.py <<'EOF'
from pathlib import Path
from typing import Optional
import json

import typer
from rich.console import Console
from rich.table import Table

from detlab import __version__
from detlab.attck import build_technique_map
from detlab.reporting import generate_json_report, generate_markdown_report, write_report
from detlab.validators import load_detection_file, load_detection_dir

app = typer.Typer(help="DetLab - detection-as-code validation and ATT&CK reporting")
console = Console()


def version_callback(value: bool):
    if value:
        console.print(f"DetLab version: {__version__}")
        raise typer.Exit()


@app.callback()
def main(
    version: Optional[bool] = typer.Option(
        None, "--version", callback=version_callback, is_eager=True, help="Show version and exit."
    )
):
    return


@app.command()
def validate(path: str = "detections") -> None:
    files, valid, errors = load_detection_dir(Path(path))

    table = Table(title="Validation Results")
    table.add_column("File")
    table.add_column("Status")
    table.add_column("Details")

    for file in files:
        if file in errors:
            table.add_row(str(file), "[red]FAIL[/red]", errors[file])
        else:
            table.add_row(str(file), "[green]PASS[/green]", "Valid detection")

    console.print(table)

    if not valid:
        raise typer.Exit(code=1)


@app.command("map-attck")
def map_attck(path: str = "detections", output: Optional[str] = None) -> None:
    _, valid, errors = load_detection_dir(Path(path))
    if not valid:
        for file, err in errors.items():
            console.print(f"[red]{file}[/red]: {err}")
        raise typer.Exit(code=1)

    detections = [load_detection_file(p) for p in Path(path).rglob("*.y*ml")]
    mapping = build_technique_map(detections)
    rendered = json.dumps(mapping, indent=2)

    if output:
        Path(output).parent.mkdir(parents=True, exist_ok=True)
        Path(output).write_text(rendered, encoding="utf-8")
        console.print(f"[green]Wrote ATT&CK mapping to[/green] {output}")
    else:
        console.print(rendered)


@app.command()
def report(
    path: str = "detections",
    format: str = "markdown",
    output: str = "reports/coverage.md",
) -> None:
    _, valid, errors = load_detection_dir(Path(path))
    if not valid:
        for file, err in errors.items():
            console.print(f"[red]{file}[/red]: {err}")
        raise typer.Exit(code=1)

    detections = [load_detection_file(p) for p in Path(path).rglob("*.y*ml")]

    if format == "markdown":
        content = generate_markdown_report(detections)
    elif format == "json":
        content = generate_json_report(detections)
    else:
        console.print("[red]Unsupported format. Use 'markdown' or 'json'.[/red]")
        raise typer.Exit(code=1)

    write_report(output, content)
    console.print(f"[green]Report written to[/green] {output}")


if __name__ == "__main__":
    app()
EOF

cat > detections/windows/encoded_powershell.yaml <<'EOF'
id: DET-0001
title: Suspicious Encoded PowerShell
description: Detects PowerShell launched with encoded command arguments.
logsource:
  product: windows
  service: sysmon
attack:
  technique: T1059.001
  tactic: execution
severity: high
status: experimental
author: Mell0wx
references:
  - https://attack.mitre.org/techniques/T1059/001/
falsepositives:
  - Administrative scripts using encoded commands
tests:
  - name: Atomic Red Team T1059.001
    source: atomic-red-team
    test_id: "1"
detection:
  selection:
    EventID: 1
    Image|endswith: '\powershell.exe'
    CommandLine|contains:
      - '-enc'
      - '-encodedcommand'
  condition: selection
EOF

cat > detections/windows/suspicious_rundll32.yaml <<'EOF'
id: DET-0002
title: Suspicious Rundll32 Execution
description: Detects rundll32 launching DLLs from suspicious paths or with unusual arguments.
logsource:
  product: windows
  service: sysmon
attack:
  technique: T1218.011
  tactic: defense-evasion
severity: high
status: experimental
author: Mell0wx
references:
  - https://attack.mitre.org/techniques/T1218/011/
falsepositives:
  - Rare administrative software using rundll32 in custom paths
tests:
  - name: Simulated Rundll32 abuse
    source: manual
    test_id: "rundll32-1"
detection:
  selection:
    EventID: 1
    Image|endswith: '\rundll32.exe'
  condition: selection
EOF

cat > detections/windows/certutil_download.yaml <<'EOF'
id: DET-0003
title: Certutil Download Behavior
description: Detects certutil being used to download remote content.
logsource:
  product: windows
  service: sysmon
attack:
  technique: T1105
  tactic: command-and-control
severity: high
status: experimental
author: Mell0wx
references:
  - https://attack.mitre.org/techniques/T1105/
falsepositives:
  - Administrative certificate retrieval or scripted downloads
tests:
  - name: Simulated Certutil download
    source: manual
    test_id: "certutil-1"
detection:
  selection:
    EventID: 1
    Image|endswith: '\certutil.exe'
    CommandLine|contains:
      - 'urlcache'
      - 'http'
  condition: selection
EOF

cat > tests/test_cli.py <<'EOF'
from pathlib import Path
from typer.testing import CliRunner
from detlab.main import app

runner = CliRunner()

SAMPLE_DETECTION = """id: DET-0001
title: Suspicious Encoded PowerShell
description: Detects PowerShell launched with encoded command arguments.
logsource:
  product: windows
  service: sysmon
attack:
  technique: T1059.001
  tactic: execution
severity: high
status: experimental
author: Mell0wx
references:
  - https://attack.mitre.org/techniques/T1059/001/
falsepositives:
  - Administrative scripts using encoded commands
tests:
  - name: Atomic Red Team T1059.001
    source: atomic-red-team
    test_id: "1"
detection:
  selection:
    EventID: 1
    Image|endswith: '\\powershell.exe'
    CommandLine|contains:
      - '-enc'
      - '-encodedcommand'
  condition: selection
"""


def write_sample_detection():
    detections = Path("detections/windows")
    detections.mkdir(parents=True, exist_ok=True)
    (detections / "encoded_powershell.yaml").write_text(SAMPLE_DETECTION, encoding="utf-8")


def test_validate_passes_for_sample_detections():
    with runner.isolated_filesystem():
        write_sample_detection()
        result = runner.invoke(app, ["validate", "detections"])
        assert result.exit_code == 0, result.output
        assert "PASS" in result.output


def test_report_generates_markdown():
    with runner.isolated_filesystem():
        write_sample_detection()
        result = runner.invoke(
            app,
            ["report", "--path", "detections", "--format", "markdown", "--output", "reports/coverage.md"],
        )
        assert result.exit_code == 0, result.output
        assert Path("reports/coverage.md").exists()


def test_map_attck_generates_json():
    with runner.isolated_filesystem():
        write_sample_detection()
        result = runner.invoke(app, ["map-attck", "detections", "--output", "reports/attack-map.json"])
        assert result.exit_code == 0, result.output
        assert Path("reports/attack-map.json").exists()


def test_version_flag():
    result = runner.invoke(app, ["--version"])
    assert result.exit_code == 0, result.output
    assert "0.1.0" in result.output
EOF

cat > .github/workflows/ci.yml <<'EOF'
name: ci

on:
  push:
    branches: [main, develop]
  pull_request:

permissions:
  contents: read

jobs:
  validate:
    runs-on: ubuntu-latest

    steps:
      - name: Checkout
        uses: actions/checkout@v5

      - name: Set up Python
        uses: actions/setup-python@v5
        with:
          python-version: "3.11"

      - name: Install package
        run: |
          python -m pip install --upgrade pip
          pip install .[dev]

      - name: Lint
        run: ruff check .

      - name: Run tests
        run: pytest

      - name: Validate detections
        run: detlab validate detections

      - name: Generate report
        run: detlab report --path detections --format markdown --output reports/coverage.md

      - name: Upload coverage report
        uses: actions/upload-artifact@v4
        with:
          name: detlab-coverage-report
          path: reports/coverage.md
EOF

echo "Bootstrap complete in $REPO_ROOT"

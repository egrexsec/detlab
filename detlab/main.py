from pathlib import Path
from typing import Optional
import json

import typer
from rich.console import Console
from rich.table import Table

from detlab.models import Detection
from detlab.validators import load_detection_file, load_detection_dir

app = typer.Typer(help="DetLab - detection-as-code validation and ATT&CK reporting")
console = Console()


@app.command()
def init(path: str = "detections") -> None:
    base = Path(path)
    base.mkdir(parents=True, exist_ok=True)

    sample = base / "encoded_powershell.yaml"
    if sample.exists():
        console.print(f"[yellow]Sample already exists:[/yellow] {sample}")
        raise typer.Exit(code=0)

    sample.write_text(
        """id: DET-0001
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
""",
        encoding="utf-8",
    )

    console.print(f"[green]Initialized sample detection at[/green] {sample}")


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
    mapping: dict[str, list[dict]] = {}

    for det in detections:
        mapping.setdefault(det.attack.technique, []).append(
            {
                "id": det.id,
                "title": det.title,
                "severity": det.severity,
                "status": det.status,
                "logsource": f"{det.logsource.product}:{det.logsource.service}",
            }
        )

    rendered = json.dumps(mapping, indent=2)

    if output:
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
    techniques = sorted({d.attack.technique for d in detections})

    Path(output).parent.mkdir(parents=True, exist_ok=True)

    if format == "markdown":
        lines = [
            "# DetLab Coverage Report",
            "",
            f"- Total detections: {len(detections)}",
            f"- ATT&CK techniques covered: {len(techniques)}",
            "",
            "| Technique | Detection ID | Title | Severity | Status |",
            "|---|---|---|---|---|",
        ]
        for det in detections:
            lines.append(
                f"| {det.attack.technique} | {det.id} | {det.title} | {det.severity} | {det.status} |"
            )
        Path(output).write_text("\n".join(lines), encoding="utf-8")
    elif format == "json":
        data = {
            "total_detections": len(detections),
            "techniques_covered": len(techniques),
            "detections": [d.model_dump() for d in detections],
        }
        Path(output).write_text(json.dumps(data, indent=2), encoding="utf-8")
    else:
        console.print("[red]Unsupported format. Use 'markdown' or 'json'.[/red]")
        raise typer.Exit(code=1)

    console.print(f"[green]Report written to[/green] {output}")


if __name__ == "__main__":
    app()

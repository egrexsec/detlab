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

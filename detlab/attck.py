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

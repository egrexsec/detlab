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
pip install -e .[dev]
```

## Quick start

```bash
detlab validate detections
detlab report detections --format markdown --output reports/coverage.md
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

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

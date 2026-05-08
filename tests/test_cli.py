from pathlib import Path

from typer.testing import CliRunner

from detlab.main import app

runner = CliRunner()


def test_init_creates_sample_detection():
    with runner.isolated_filesystem():
        result = runner.invoke(app, ["init", "detections"])
        assert result.exit_code == 0
        assert Path("detections/encoded_powershell.yaml").exists()


def test_validate_passes_for_initialized_sample():
    with runner.isolated_filesystem():
        runner.invoke(app, ["init", "detections"])
        result = runner.invoke(app, ["validate", "detections"])
        assert result.exit_code == 0
        assert "PASS" in result.output


def test_report_generates_markdown():
    with runner.isolated_filesystem():
        runner.invoke(app, ["init", "detections"])
        result = runner.invoke(
            app,
            ["report", "--path", "detections", "--format", "markdown", "--output", "reports/coverage.md"],
        )
        assert result.exit_code == 0
        assert Path("reports/coverage.md").exists()


def test_map_attck_generates_json():
    with runner.isolated_filesystem():
        runner.invoke(app, ["init", "detections"])
        result = runner.invoke(
            app,
            ["map-attck", "detections", "--output", "reports/attack-map.json"],
        )
        assert result.exit_code == 0
        assert Path("reports/attack-map.json").exists()

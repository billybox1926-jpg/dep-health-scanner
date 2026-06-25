from unittest.mock import MagicMock, patch

from typer.testing import CliRunner

from dep_health_scanner.cli import app

runner = CliRunner()


def test_update_command_found():
    with (
        patch("dep_health_scanner.cli.LockfileDetector") as mock_detect,
        patch("dep_health_scanner.cli.Scanner") as mock_scanner,
    ):
        mock_lock = MagicMock()
        mock_lock.dependencies = [MagicMock(), MagicMock()]
        mock_detect.detect.return_value = mock_lock
        mock_scanner.return_value.update.return_value = {
            "updated": 2,
            "vulns_found": 1,
        }

        result = runner.invoke(app, ["update", "."])
        assert result.exit_code == 0
        assert "Updated" in result.output


def test_update_command_no_lockfile():
    with patch("dep_health_scanner.cli.LockfileDetector") as mock_detect:
        mock_detect.detect.return_value = None

        result = runner.invoke(app, ["update", "."])
        assert result.exit_code == 0
        assert "No lockfile found" in result.output


def test_update_command_unknown_ecosystem():
    with patch("dep_health_scanner.cli.LockfileDetector") as mock_detect:
        mock_lock = MagicMock()
        mock_lock.dependencies = [MagicMock()]
        mock_detect.detect.return_value = mock_lock

        result = runner.invoke(app, ["update", ".", "--ecosystem", "rust"])
        assert result.exit_code == 1
        assert "Unknown ecosystem" in result.output

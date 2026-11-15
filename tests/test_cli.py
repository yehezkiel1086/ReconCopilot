"""Tests for CLI entry points and command execution."""

from typer.testing import CliRunner

from reconcopilot.cli import app

runner = CliRunner()


def test_cli_help() -> None:
    result = runner.invoke(app, ["--help"])
    assert result.exit_code == 0
    assert "ReconCopilot" in result.output
    assert "init" in result.output
    assert "add" in result.output
    assert "targets" in result.output
    assert "check-scope" in result.output


def test_cli_version() -> None:
    result = runner.invoke(app, ["--version"])
    assert result.exit_code == 0
    assert "ReconCopilot version" in result.output


def test_cli_init_command(tmp_path) -> None:
    db_file = tmp_path / "cli_test.db"
    result = runner.invoke(app, ["init", "--db-path", str(db_file)])
    assert result.exit_code == 0
    assert "Initialized database" in result.output
    assert db_file.is_file()

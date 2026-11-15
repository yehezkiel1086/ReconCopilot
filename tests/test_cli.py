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
    assert "scope" in result.output
    assert "recon" in result.output
    assert "triage" in result.output
    assert "finding" in result.output
    assert "report" in result.output


def test_cli_report_group_help() -> None:
    result = runner.invoke(app, ["report", "--help"])
    assert result.exit_code == 0
    assert "generate" in result.output


def test_cli_finding_group_help() -> None:
    result = runner.invoke(app, ["finding", "--help"])
    assert result.exit_code == 0
    assert "add" in result.output
    assert "list" in result.output
    assert "show" in result.output
    assert "update" in result.output
    assert "export" in result.output


def test_cli_triage_group_help() -> None:
    result = runner.invoke(app, ["triage", "--help"])
    assert result.exit_code == 0
    assert "run" in result.output
    assert "history" in result.output


def test_cli_scope_group_help() -> None:
    result = runner.invoke(app, ["scope", "--help"])
    assert result.exit_code == 0
    assert "create" in result.output
    assert "list" in result.output
    assert "show" in result.output
    assert "check" in result.output


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

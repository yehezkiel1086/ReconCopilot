"""Tests for scope loading, ScopeChecker, CLI commands, and enforcement."""

import pytest
from typer.testing import CliRunner

from reconcopilot.cli import app
from reconcopilot.scope import (
    ScopeChecker,
    ScopeViolationError,
    list_scopes,
    require_in_scope,
)

runner = CliRunner()


@pytest.fixture
def sample_scope_data():
    return {
        "name": "acme-corp-2026",
        "targets": {
            "domains": [
                "*.acme.com",
                "acme-staging.io",
            ],
            "ip_ranges": [
                "203.0.113.0/24",
                "198.51.100.50",
            ],
            "exclusions": [
                "mail.acme.com",
                "198.51.100.0/28",
                "203.0.113.128/28",
            ],
        },
        "metadata": {
            "program_url": "https://hackerone.com/acme",
            "notes": "Web app and API only, no social engineering per program rules",
        },
    }


@pytest.fixture
def sample_scope_file(tmp_path, sample_scope_data):
    file_path = tmp_path / "acme-corp-2026.yaml"
    checker = ScopeChecker(data=sample_scope_data)
    checker.file_path = file_path
    checker.save(scopes_dir=tmp_path)
    return file_path


def test_wildcard_matching(sample_scope_data):
    checker = ScopeChecker(data=sample_scope_data)

    # In-scope wildcard matches
    assert checker.is_in_scope("api.acme.com")
    assert checker.is_in_scope("auth.api.acme.com")
    assert checker.is_in_scope("acme.com")

    # In-scope exact domain match
    assert checker.is_in_scope("acme-staging.io")

    res = checker.check("api.acme.com")
    assert res.in_scope is True
    assert "matches wildcard *.acme.com" in res.reason


def test_cidr_matching(sample_scope_data):
    checker = ScopeChecker(data=sample_scope_data)

    # In-scope CIDR range 203.0.113.0/24 (non-excluded portion)
    assert checker.is_in_scope("203.0.113.5")
    assert checker.is_in_scope("203.0.113.100")

    # In-scope exact IP
    assert checker.is_in_scope("198.51.100.50")

    res = checker.check("203.0.113.5")
    assert res.in_scope is True
    assert "matches IP range 203.0.113.0/24" in res.reason


def test_exclusion_priority_over_wildcard_inclusion(sample_scope_data):
    checker = ScopeChecker(data=sample_scope_data)

    # mail.acme.com matches wildcard *.acme.com, BUT is explicitly excluded!
    assert not checker.is_in_scope("mail.acme.com")

    # Subdomain of excluded domain is also excluded
    assert not checker.is_in_scope("smtp.mail.acme.com")

    res = checker.check("mail.acme.com")
    assert res.in_scope is False
    assert "explicitly excluded" in res.reason
    assert "mail.acme.com" in res.reason


def test_exclusion_priority_over_cidr_inclusion(sample_scope_data):
    checker = ScopeChecker(data=sample_scope_data)

    # 203.0.113.130 is inside 203.0.113.0/24, BUT inside excluded 203.0.113.128/28!
    assert not checker.is_in_scope("203.0.113.130")

    res = checker.check("203.0.113.130")
    assert res.in_scope is False
    assert "explicitly excluded" in res.reason


def test_rejection_of_target_matching_nothing(sample_scope_data):
    checker = ScopeChecker(data=sample_scope_data)

    assert not checker.is_in_scope("evil.com")
    assert not checker.is_in_scope("notacme.com")
    assert not checker.is_in_scope("1.1.1.1")

    res = checker.check("evil.com")
    assert res.in_scope is False
    assert "does not match any in-scope" in res.reason


def test_url_and_port_normalization(sample_scope_data):
    checker = ScopeChecker(data=sample_scope_data)

    assert checker.is_in_scope("https://api.acme.com:8443/v1/auth")
    assert not checker.is_in_scope("https://mail.acme.com/login")
    assert not checker.is_in_scope("http://evil.com:8080/test")


def test_scope_load_save_yaml(tmp_path, sample_scope_data):
    checker = ScopeChecker(data=sample_scope_data)
    saved_file = checker.save(scopes_dir=tmp_path)
    assert saved_file.is_file()

    loaded = ScopeChecker.from_file(saved_file)
    assert loaded.name == "acme-corp-2026"
    assert loaded.domains == sample_scope_data["targets"]["domains"]
    assert loaded.ip_ranges == sample_scope_data["targets"]["ip_ranges"]
    assert loaded.exclusions == sample_scope_data["targets"]["exclusions"]
    assert loaded.metadata["program_url"] == "https://hackerone.com/acme"


def test_list_scopes_and_from_name(tmp_path, sample_scope_data):
    checker = ScopeChecker(data=sample_scope_data)
    checker.save(scopes_dir=tmp_path)

    scopes = list_scopes(scopes_dir=tmp_path)
    assert len(scopes) == 1
    assert scopes[0].name == "acme-corp-2026"

    by_name = ScopeChecker.from_name("acme-corp-2026", scopes_dir=tmp_path)
    assert by_name.name == "acme-corp-2026"

    with pytest.raises(FileNotFoundError):
        ScopeChecker.from_name("nonexistent-scope", scopes_dir=tmp_path)


def test_require_in_scope_helper_and_decorator(sample_scope_data):
    checker = ScopeChecker(data=sample_scope_data)

    # Helper function usage
    normalized = require_in_scope("https://api.acme.com/test", scope=checker)
    assert normalized == "api.acme.com"

    with pytest.raises(ScopeViolationError):
        require_in_scope("mail.acme.com", scope=checker)

    with pytest.raises(ScopeViolationError):
        require_in_scope("unknown.org", scope=checker)

    # Decorator usage
    @require_in_scope(scope=checker)
    def dummy_action(target: str, action_type: str = "scan") -> str:
        return f"{action_type}:{target}"

    assert dummy_action("https://api.acme.com/v1") == "scan:api.acme.com"

    with pytest.raises(ScopeViolationError):
        dummy_action("mail.acme.com")


# ==============================================================================
# CLI Tests
# ==============================================================================


def test_cli_scope_create_non_interactive(tmp_path, monkeypatch):
    monkeypatch.setenv("RECONCOPILOT_SCOPES_DIR", str(tmp_path))

    result = runner.invoke(
        app,
        [
            "scope",
            "create",
            "test-prog",
            "--domains",
            "*.example.org, example.net",
            "--ips",
            "10.0.0.0/8",
            "--exclusions",
            "admin.example.org",
            "--url",
            "https://bounty.org/prog",
            "--non-interactive",
        ],
    )
    assert result.exit_code == 0
    assert "Created scope test-prog" in result.output

    # Verify YAML was written
    scope_file = tmp_path / "test-prog.yaml"
    assert scope_file.is_file()

    checker = ScopeChecker.from_file(scope_file)
    assert checker.name == "test-prog"
    assert "*.example.org" in checker.domains
    assert "admin.example.org" in checker.exclusions


def test_cli_scope_create_interactive(tmp_path, monkeypatch):
    monkeypatch.setenv("RECONCOPILOT_SCOPES_DIR", str(tmp_path))

    # Provide simulated inputs for interactive prompts:
    # domains, ip_ranges, exclusions, url, email, notes
    inputs = (
        "\n".join(
            [
                "*.interactive.com, interactive.io",
                "192.168.0.0/16",
                "dev.interactive.com",
                "https://bounty.com/interactive",
                "sec@interactive.com",
                "Scope testing notes",
            ]
        )
        + "\n"
    )

    result = runner.invoke(app, ["scope", "create", "interactive-scope"], input=inputs)
    assert result.exit_code == 0
    assert "Created scope interactive-scope" in result.output

    scope_file = tmp_path / "interactive-scope.yaml"
    assert scope_file.is_file()

    checker = ScopeChecker.from_file(scope_file)
    assert checker.name == "interactive-scope"
    assert "*.interactive.com" in checker.domains
    assert "dev.interactive.com" in checker.exclusions


def test_cli_scope_list_and_show(tmp_path, monkeypatch, sample_scope_data):
    monkeypatch.setenv("RECONCOPILOT_SCOPES_DIR", str(tmp_path))
    checker = ScopeChecker(data=sample_scope_data)
    checker.save(scopes_dir=tmp_path)

    # scope list
    list_res = runner.invoke(app, ["scope", "list"])
    assert list_res.exit_code == 0
    assert "acme-corp-2026" in list_res.output
    assert "domain(s)" in list_res.output

    # scope show
    show_res = runner.invoke(app, ["scope", "show", "acme-corp-2026"])
    assert show_res.exit_code == 0
    assert "acme-corp-2026" in show_res.output
    assert "*.acme.com" in show_res.output
    assert "mail.acme.com" in show_res.output
    assert "https://hackerone.com/acme" in show_res.output


def test_cli_scope_check_in_and_out_of_scope(tmp_path, monkeypatch, sample_scope_data):
    monkeypatch.setenv("RECONCOPILOT_SCOPES_DIR", str(tmp_path))
    checker = ScopeChecker(data=sample_scope_data)
    checker.save(scopes_dir=tmp_path)

    # 1. In-scope target
    in_res = runner.invoke(app, ["scope", "check", "acme-corp-2026", "api.acme.com"])
    assert in_res.exit_code == 0
    assert "IN SCOPE" in in_res.output
    assert "matches wildcard *.acme.com" in in_res.output

    # 2. Excluded target
    out_res = runner.invoke(app, ["scope", "check", "acme-corp-2026", "mail.acme.com"])
    assert out_res.exit_code == 1
    assert "OUT OF SCOPE" in out_res.output
    assert "explicitly excluded" in out_res.output

    # 3. Target matching nothing
    unmatched_res = runner.invoke(
        app, ["scope", "check", "acme-corp-2026", "other.com"]
    )
    assert unmatched_res.exit_code == 1
    assert "OUT OF SCOPE" in unmatched_res.output
    assert "does not match any in-scope" in unmatched_res.output

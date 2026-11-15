"""Tests for triage module, rules-based fallback, AI triage, audit logging, and CLI."""

from unittest.mock import MagicMock

import pytest
from typer.testing import CliRunner

from reconcopilot.cli import app
from reconcopilot.db import (
    add_http_probe,
    add_nuclei_finding,
    add_open_port,
    get_triage_run,
    init_db,
    list_triage_runs,
)
from reconcopilot.modules import triage
from reconcopilot.scope import ScopeChecker

runner = CliRunner()


@pytest.fixture
def triage_scope(tmp_path, monkeypatch):
    """Sets up a test scope and directory."""
    monkeypatch.setenv("RECONCOPILOT_SCOPES_DIR", str(tmp_path))
    scope_data = {
        "name": "triage-scope",
        "targets": {
            "domains": ["*.acme.com", "acme-staging.io"],
            "ip_ranges": ["203.0.113.0/24"],
            "exclusions": ["mail.acme.com"],
        },
        "metadata": {"notes": "Test triage engagement"},
    }
    checker = ScopeChecker(data=scope_data)
    checker.save(scopes_dir=tmp_path)
    return checker


@pytest.fixture
def populated_db(tmp_path, monkeypatch, triage_scope):
    """Initializes DB with sample reconnaissance findings."""
    db_file = tmp_path / "triage_test.db"
    init_db(db_file)
    monkeypatch.setenv("DATABASE_PATH", str(db_file))

    # Add Nuclei findings
    add_nuclei_finding(
        scope_name="triage-scope",
        template_id="cve-2024-9999",
        severity="critical",
        matched_url="https://api.acme.com/v1/auth",
        name="Critical Auth Bypass",
        db_path=db_file,
    )
    add_nuclei_finding(
        scope_name="triage-scope",
        template_id="git-config-exposure",
        severity="medium",
        matched_url="https://acme-staging.io/.git/config",
        name="Git Config Exposed",
        db_path=db_file,
    )

    # Add Open Ports
    add_open_port(
        scope_name="triage-scope",
        target="203.0.113.15",
        port=3306,
        protocol="tcp",
        state="open",
        service="mysql",
        db_path=db_file,
    )
    add_open_port(
        scope_name="triage-scope",
        target="203.0.113.20",
        port=22,
        protocol="tcp",
        state="open",
        service="ssh",
        db_path=db_file,
    )

    # Add HTTP Probes
    add_http_probe(
        scope_name="triage-scope",
        url="https://api.acme.com/admin/login",
        host="api.acme.com",
        status_code=401,
        title="Admin Portal",
        tech_stack="Spring, React",
        content_length=1200,
        db_path=db_file,
    )
    add_http_probe(
        scope_name="triage-scope",
        url="https://acme-staging.io",
        host="acme-staging.io",
        status_code=200,
        title="Staging Landing",
        tech_stack="Nginx",
        content_length=3000,
        db_path=db_file,
    )

    return db_file


# ==============================================================================
# Rules-Based Triage Tests
# ==============================================================================


def test_rules_based_triage_when_no_api_key(populated_db, monkeypatch):
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)

    res = triage.triage_scope(
        scope_name="triage-scope", top_n=5, use_ai=False, db_path=populated_db
    )

    assert res["mode"] == "rules"
    assert len(res["items"]) > 0
    assert "run_id" in res

    # The top items should include the critical nuclei finding and/or high-priority port/admin probe
    top_severities = [it["severity"] for it in res["items"]]
    assert "CRITICAL" in top_severities or "HIGH" in top_severities

    # Verify run was saved to triage_runs database table
    runs = list_triage_runs("triage-scope", db_path=populated_db)
    assert len(runs) >= 1
    assert runs[0]["mode"] == "rules"

    run_detail = get_triage_run(res["run_id"], db_path=populated_db)
    assert run_detail is not None
    assert "Rules-Based Triage" in run_detail["ai_response"]


def test_rules_based_triage_focus_query(populated_db):
    res = triage.triage_scope(
        scope_name="triage-scope",
        top_n=5,
        focus="mysql",
        use_ai=False,
        db_path=populated_db,
    )

    # MySQL item should be boosted to the top rank
    top_item = res["items"][0]
    assert "3306" in top_item["target"] or "mysql" in top_item["details"].lower()


# ==============================================================================
# AI Triage Tests (Mocked Claude API)
# ==============================================================================


def test_ai_triage_invokes_claude_with_safety_guardrails(populated_db, monkeypatch):
    monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-ant-test-key-12345")

    captured_kwargs = {}

    class MockAnthropic:
        def __init__(self, api_key):
            self.api_key = api_key
            self.messages = MagicMock()

            def mock_create(**kwargs):
                captured_kwargs.update(kwargs)
                mock_resp = MagicMock()
                mock_text = MagicMock()
                mock_text.text = (
                    "### Executive Summary\n"
                    "High-priority exposed admin portal and critical authentication bypass identified.\n\n"
                    "### Top Prioritized Findings\n"
                    "1. Critical Auth Bypass on https://api.acme.com/v1/auth\n"
                    "   - Next step: Manually verify endpoint responses."
                )
                mock_resp.content = [mock_text]
                return mock_resp

            self.messages.create = mock_create

    import anthropic

    monkeypatch.setattr(anthropic, "Anthropic", MockAnthropic)

    res = triage.triage_scope(
        scope_name="triage-scope",
        top_n=5,
        focus="authentication",
        use_ai=True,
        db_path=populated_db,
    )

    assert res["mode"] == "ai"
    assert "Executive Summary" in res["summary_text"]

    # Verify model was passed
    assert "claude" in captured_kwargs["model"]

    # CRITICAL: Verify safety constraints in system prompt
    system_prompt = captured_kwargs["system"]
    assert "suggest next manual investigation steps" in system_prompt
    assert "NEVER generate functional exploit code" in system_prompt

    # Verify stored in triage_runs
    runs = list_triage_runs("triage-scope", db_path=populated_db)
    assert len(runs) >= 1
    assert runs[0]["mode"] == "ai"


def test_ai_triage_graceful_degradation_on_api_error(populated_db, monkeypatch):
    monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-ant-test-key-12345")

    class FailingAnthropic:
        def __init__(self, api_key):
            self.messages = MagicMock()
            self.messages.create.side_effect = ConnectionError("API connection failed")

    import anthropic

    monkeypatch.setattr(anthropic, "Anthropic", FailingAnthropic)

    # Should not crash; gracefully degrades to rules triage
    res = triage.triage_scope(
        scope_name="triage-scope", top_n=5, use_ai=True, db_path=populated_db
    )

    assert res["mode"] == "rules"
    assert "ai_error" in res


# ==============================================================================
# CLI Command Tests
# ==============================================================================


def test_cli_triage_run_rules_fallback(populated_db, monkeypatch):
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)

    res = runner.invoke(app, ["triage", "run", "--scope", "triage-scope", "--no-ai"])
    assert res.exit_code == 0
    assert "No AI API key found" in res.output or "Rules-Based Triage" in res.output
    assert "Top" in res.output
    assert "stored for scope 'triage-scope'" in res.output


def test_cli_triage_compliance_notice_shown(populated_db, monkeypatch):
    monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-ant-test-key")

    class MockAnthropic:
        def __init__(self, api_key):
            self.messages = MagicMock()
            mock_resp = MagicMock()
            mock_text = MagicMock()
            mock_text.text = "AI triage analysis result."
            mock_resp.content = [mock_text]
            self.messages.create.return_value = mock_resp

    import anthropic

    monkeypatch.setattr(anthropic, "Anthropic", MockAnthropic)

    res = runner.invoke(app, ["triage", "run", "--scope", "triage-scope"])
    assert res.exit_code == 0
    assert "ENGAGEMENT COMPLIANCE NOTICE" in res.output


def test_cli_triage_history_and_show(populated_db, monkeypatch):
    # Run a triage first
    triage.triage_scope(scope_name="triage-scope", use_ai=False, db_path=populated_db)

    # Check history command
    hist_res = runner.invoke(app, ["triage", "history", "--scope", "triage-scope"])
    assert hist_res.exit_code == 0
    assert "Triage Run History" in hist_res.output
    assert "RULES" in hist_res.output

    # Check show command for run #1
    show_res = runner.invoke(app, ["triage", "show", "1"])
    assert show_res.exit_code == 0
    assert "Triage Run #1" in show_res.output

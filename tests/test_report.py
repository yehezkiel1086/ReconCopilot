"""Tests for report module, Markdown/HTML/JSON/YAML generation, AI polish, and CLI commands."""

from __future__ import annotations

import json
from unittest.mock import MagicMock

import pytest
import yaml
from typer.testing import CliRunner

from reconcopilot.cli import app
from reconcopilot.db import (
    add_asset,
    add_http_probe,
    add_nuclei_finding,
    add_open_port,
    init_db,
    list_audit_logs,
)
from reconcopilot.modules import report
from reconcopilot.modules.tracking import create_finding
from reconcopilot.scope import ScopeChecker

runner = CliRunner()


@pytest.fixture
def report_scope(tmp_path, monkeypatch):
    """Sets up a test scope and directory."""
    monkeypatch.setenv("RECONCOPILOT_SCOPES_DIR", str(tmp_path))
    scope_data = {
        "name": "report-scope",
        "targets": {
            "domains": ["*.acme.com", "acme-staging.io"],
            "ip_ranges": ["203.0.113.0/24"],
            "exclusions": ["mail.acme.com"],
        },
        "metadata": {
            "program_url": "https://hackerone.com/acme",
            "notes": "Authorized web application assessment",
        },
    }
    checker = ScopeChecker(data=scope_data)
    checker.save(scopes_dir=tmp_path)
    return checker


@pytest.fixture
def report_db(tmp_path, monkeypatch, report_scope):
    """Initializes DB with recon data and verified findings."""
    db_file = tmp_path / "report_test.db"
    init_db(db_file)
    monkeypatch.setenv("DATABASE_PATH", str(db_file))

    # Add recon assets & probes
    add_asset("report-scope", "api.acme.com", db_path=db_file)
    add_asset("report-scope", "acme-staging.io", db_path=db_file)
    add_http_probe(
        scope_name="report-scope",
        url="https://api.acme.com",
        host="api.acme.com",
        status_code=200,
        title="Acme API",
        db_path=db_file,
    )
    add_open_port(
        scope_name="report-scope",
        target="203.0.113.10",
        port=443,
        service="https",
        db_path=db_file,
    )
    add_nuclei_finding(
        scope_name="report-scope",
        template_id="ssl-dns-names",
        severity="info",
        matched_url="https://api.acme.com",
        name="SSL DNS Names",
        db_path=db_file,
    )

    # Add verified findings across different severities
    create_finding(
        scope="report-scope",
        title="SQL Injection in /api/v1/search",
        severity="critical",
        status="open",
        affected_asset="api.acme.com",
        description="Unsanitized q parameter leads to blind boolean SQL injection.",
        impact="Full read/write access to customer database.",
        reproduction_steps="1. Send GET /api/v1/search?q=' OR 1=1--",
        remediation="Use parameterized queries with prepared statements.",
        cvss_score=9.8,
        db_path=db_file,
    )
    create_finding(
        scope="report-scope",
        title="IDOR in /api/v1/user",
        severity="high",
        status="open",
        affected_asset="api.acme.com",
        description="User ID manipulation allows accessing other user profiles.",
        impact="Unauthorized disclosure of sensitive user PII.",
        reproduction_steps="1. GET /api/v1/user?id=102 with user A token",
        remediation="Validate user ownership in authorization policy.",
        cvss_score=8.1,
        db_path=db_file,
    )
    create_finding(
        scope="report-scope",
        title="Missing Content-Security-Policy",
        severity="medium",
        status="fixed",
        affected_asset="acme-staging.io",
        description="Application responds without Content-Security-Policy header.",
        impact="Increases risk of Cross-Site Scripting (XSS).",
        reproduction_steps="1. Inspect HTTP response headers of https://acme-staging.io",
        remediation="Deploy strict Content-Security-Policy header.",
        cvss_score=5.4,
        db_path=db_file,
    )
    create_finding(
        scope="report-scope",
        title="Server Version Banner Disclosure",
        severity="low",
        status="open",
        affected_asset="api.acme.com",
        description="Server header reveals exact nginx version 1.18.0.",
        impact="Assists attackers in fingerprinting known CVEs.",
        reproduction_steps="1. Send HEAD request and observe Server header",
        remediation="Set server_tokens off in nginx config.",
        cvss_score=3.1,
        db_path=db_file,
    )
    create_finding(
        scope="report-scope",
        title="Internal Hostname Disclosure",
        severity="info",
        status="open",
        affected_asset="api.acme.com",
        description="Internal RFC1918 IP revealed in HTTP 500 error page.",
        impact="Internal network architecture disclosure.",
        reproduction_steps="",  # Empty on purpose to test fallback prose
        remediation="",  # Empty on purpose to test fallback prose
        cvss_score=None,
        db_path=db_file,
    )

    return db_file


# ==============================================================================
# Functional / Module Unit Tests
# ==============================================================================


def test_gather_report_data(report_db):
    data = report.gather_report_data(scope_name="report-scope", db_path=report_db)

    assert data["scope_name"] == "report-scope"
    assert data["total_findings"] == 5
    assert data["overall_risk"] == "CRITICAL"
    assert data["severity_counts"]["critical"] == 1
    assert data["severity_counts"]["high"] == 1
    assert data["severity_counts"]["medium"] == 1
    assert data["severity_counts"]["low"] == 1
    assert data["severity_counts"]["info"] == 1

    # Check ordering: critical -> high -> medium -> low -> info
    severities = [f["severity"].lower() for f in data["findings"]]
    assert severities == ["critical", "high", "medium", "low", "info"]

    # Check recon summary metrics
    assert data["recon_summary"]["total_assets"] >= 2
    assert data["recon_summary"]["total_http_probes"] >= 1
    assert data["recon_summary"]["total_open_ports"] >= 1


def test_gather_report_data_empty_scope(tmp_path, monkeypatch):
    """When scope has no findings, overall risk is INFORMATIONAL."""
    monkeypatch.setenv("RECONCOPILOT_SCOPES_DIR", str(tmp_path))
    checker = ScopeChecker(
        data={"name": "empty-scope", "targets": {"domains": ["test.com"]}}
    )
    checker.save(scopes_dir=tmp_path)

    empty_db = tmp_path / "empty.db"
    init_db(empty_db)

    data = report.gather_report_data(scope_name="empty-scope", db_path=empty_db)
    assert data["total_findings"] == 0
    assert data["overall_risk"] == "INFORMATIONAL"
    assert data["findings"] == []


def test_render_markdown_report_template(report_db):
    data = report.gather_report_data(scope_name="report-scope", db_path=report_db)
    md = report.render_markdown_report(data=data)

    # Core sections
    assert "# Security Assessment & Reconnaissance Report: report-scope" in md
    assert "## 1. Executive Summary" in md
    assert "## 2. Scope & Engagement Methodology" in md
    assert "## 3. Verified Findings Summary" in md
    assert "## 4. Detailed Findings" in md
    assert "## 5. Strategic Recommendations" in md

    # Scope and boundaries
    assert "*.acme.com" in md
    assert "mail.acme.com" in md
    assert "https://hackerone.com/acme" in md

    # Summary table
    assert "| ID | Severity | Status | Finding Title | Affected Asset | CVSS |" in md
    assert "SQL Injection in /api/v1/search" in md
    assert "9.8" in md

    # Detailed findings content
    assert "### 4.1. [CRITICAL] SQL Injection in /api/v1/search" in md
    assert "Unsanitized q parameter leads to blind boolean SQL injection." in md
    assert "Use parameterized queries with prepared statements." in md

    # Unfilled / empty fields should state explicit fallback instead of placeholders
    assert "*No specific reproduction steps documented.*" in md
    assert "*No specific remediation guidance documented.*" in md


def test_render_markdown_report_ai_prose_overrides(report_db):
    data = report.gather_report_data(scope_name="report-scope", db_path=report_db)
    exec_override = "Custom AI Executive Summary: Strong overall posture with isolated high-risk items."
    polished_desc = {1: "Polished SQL injection description for executive review."}
    polished_imp = {1: "Polished impact statement regarding data confidentiality."}

    md = report.render_markdown_report(
        data=data,
        executive_summary_override=exec_override,
        polished_descriptions=polished_desc,
        polished_impacts=polished_imp,
    )

    assert exec_override in md
    assert "Polished SQL injection description for executive review." in md
    assert "Polished impact statement regarding data confidentiality." in md


def test_render_html_report(report_db):
    data = report.gather_report_data(scope_name="report-scope", db_path=report_db)
    html_content = report.render_html_report(data=data)

    assert "<!DOCTYPE html>" in html_content
    assert "<title>Security Assessment Report: report-scope</title>" in html_content
    assert "badge badge-critical" in html_content
    assert "badge badge-open" in html_content
    assert "SQL Injection in /api/v1/search" in html_content
    assert "finding-card" in html_content


def test_export_json_and_yaml(report_db, tmp_path):
    # Test JSON generation
    json_path = tmp_path / "custom_report.json"
    res_json = report.generate_report(
        scope_name="report-scope",
        output_format="json",
        output_path=json_path,
        use_ai=False,
        db_path=report_db,
    )

    assert res_json["format"] == "json"
    assert json_path.is_file()
    parsed_json = json.loads(json_path.read_text(encoding="utf-8"))
    assert parsed_json["report_metadata"]["scope_name"] == "report-scope"
    assert parsed_json["report_metadata"]["total_findings"] == 5
    assert len(parsed_json["findings"]) == 5

    # Test YAML generation
    yaml_path = tmp_path / "custom_report.yaml"
    res_yaml = report.generate_report(
        scope_name="report-scope",
        output_format="yaml",
        output_path=yaml_path,
        use_ai=False,
        db_path=report_db,
    )

    assert res_yaml["format"] == "yaml"
    assert yaml_path.is_file()
    parsed_yaml = yaml.safe_load(yaml_path.read_text(encoding="utf-8"))
    assert parsed_yaml["report_metadata"]["scope_name"] == "report-scope"
    assert parsed_yaml["report_metadata"]["total_findings"] == 5


def test_resolve_report_output_path(tmp_path, monkeypatch):
    # Custom output path
    custom_p = tmp_path / "subdir" / "my_report.md"
    resolved = report.resolve_report_output_path(
        scope_name="my-scope",
        output_format="markdown",
        output_path=custom_p,
    )
    assert resolved == custom_p.resolve()
    assert custom_p.parent.is_dir()

    # Default configured output path
    monkeypatch.setenv(
        "RECONCOPILOT__REPORT__OUTPUT_DIR", str(tmp_path / "reports_out")
    )
    default_p = report.resolve_report_output_path(
        scope_name="my-scope",
        output_format="html",
        output_path=None,
    )
    assert "report_my-scope_" in default_p.name
    assert default_p.name.endswith(".html")
    assert default_p.parent.is_dir()


def test_generate_report_audit_logging(report_db, tmp_path):
    out_file = tmp_path / "audit_test_report.md"
    report.generate_report(
        scope_name="report-scope",
        output_format="markdown",
        output_path=out_file,
        use_ai=False,
        db_path=report_db,
    )

    assert out_file.is_file()
    logs = list_audit_logs(db_path=report_db)
    report_logs = [entry for entry in logs if entry["action"] == "report.generate"]
    assert len(report_logs) >= 1
    assert report_logs[0]["target"] == "report-scope"


def test_generate_report_unsupported_format(report_db):
    with pytest.raises(ValueError, match="Unsupported format"):
        report.generate_report(
            scope_name="report-scope",
            output_format="pdf",
            db_path=report_db,
        )


# ==============================================================================
# AI Polish Mocking & Fallback Tests
# ==============================================================================


def test_ai_polish_report_mocked(report_db, monkeypatch):
    monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-ant-report-test-key")

    mock_client = MagicMock()
    mock_response = MagicMock()
    mock_content = MagicMock()
    mock_content.text = json.dumps(
        {
            "executive_summary": "AI Polish: Highly targeted security assessment revealed 5 verified vulnerabilities.",
            "polished_findings": [
                {
                    "id": 1,
                    "polished_description": "Refined executive description of SQL injection vulnerability.",
                    "polished_impact": "Refined high-impact statement regarding data confidentiality.",
                }
            ],
        }
    )
    mock_response.content = [mock_content]
    mock_client.messages.create.return_value = mock_response

    class MockAnthropicModule:
        def Anthropic(self, api_key):
            assert api_key == "sk-ant-report-test-key"
            return mock_client

    import sys

    monkeypatch.setitem(sys.modules, "anthropic", MockAnthropicModule())

    data = report.gather_report_data(scope_name="report-scope", db_path=report_db)
    result = report.ai_polish_report(data=data, api_key="sk-ant-report-test-key")

    assert "Highly targeted security assessment" in result["executive_summary"]
    assert 1 in result["polished_descriptions"]
    assert "Refined executive description" in result["polished_descriptions"][1]

    # Verify prompt safety constraints were passed in system prompt
    call_kwargs = mock_client.messages.create.call_args[1]
    system_prompt = call_kwargs["system"]
    assert "NEVER fabricate, invent, or add new vulnerabilities" in system_prompt
    assert "writing quality, clarity, and executive readiness" in system_prompt


def test_ai_polish_report_fallback_on_invalid_json(report_db, monkeypatch):
    monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-ant-report-test-key")

    mock_client = MagicMock()
    mock_response = MagicMock()
    mock_content = MagicMock()
    mock_content.text = "Sorry, I cannot format this as JSON properly."
    mock_response.content = [mock_content]
    mock_client.messages.create.return_value = mock_response

    class MockAnthropicModule:
        def Anthropic(self, api_key):
            return mock_client

    import sys

    monkeypatch.setitem(sys.modules, "anthropic", MockAnthropicModule())

    data = report.gather_report_data(scope_name="report-scope", db_path=report_db)
    result = report.ai_polish_report(data=data, api_key="sk-ant-report-test-key")

    # Should fall back cleanly without raising exception
    assert result == {}


# ==============================================================================
# CLI Command Tests
# ==============================================================================


def test_cli_report_generate_markdown_no_ai(report_scope, report_db, tmp_path):
    report_file = tmp_path / "cli_report.md"
    result = runner.invoke(
        app,
        [
            "report",
            "generate",
            "--scope",
            "report-scope",
            "--format",
            "markdown",
            "--output",
            str(report_file),
            "--no-ai",
        ],
    )

    assert result.exit_code == 0
    assert "Report successfully generated" in result.output
    assert report_file.is_file()
    content = report_file.read_text(encoding="utf-8")
    assert "# Security Assessment & Reconnaissance Report: report-scope" in content
    assert "SQL Injection in /api/v1/search" in content


def test_cli_report_generate_html(report_scope, report_db, tmp_path):
    report_file = tmp_path / "cli_report.html"
    result = runner.invoke(
        app,
        [
            "report",
            "generate",
            "--scope",
            "report-scope",
            "--format",
            "html",
            "--output",
            str(report_file),
            "--no-ai",
        ],
    )

    assert result.exit_code == 0
    assert report_file.is_file()
    assert "<!DOCTYPE html>" in report_file.read_text(encoding="utf-8")


def test_cli_report_generate_compliance_warning(
    report_scope, report_db, tmp_path, monkeypatch
):
    monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-ant-mock-key")
    monkeypatch.setattr(
        report,
        "ai_polish_report",
        lambda data, api_key: {
            "executive_summary": "Mocked AI executive summary",
            "polished_descriptions": {},
            "polished_impacts": {},
        },
    )
    report_file = tmp_path / "cli_compliance.md"

    result = runner.invoke(
        app,
        [
            "report",
            "generate",
            "--scope",
            "report-scope",
            "--format",
            "markdown",
            "--output",
            str(report_file),
            "--ai",
        ],
    )

    assert result.exit_code == 0
    assert "ENGAGEMENT COMPLIANCE NOTICE" in result.output
    assert "rules of" in result.output
    assert "engagement" in result.output
    assert report_file.is_file()


def test_cli_report_generate_invalid_scope():
    result = runner.invoke(
        app,
        ["report", "generate", "--scope", "non-existent-scope"],
    )
    assert result.exit_code == 1
    assert "not found" in result.output.lower() or "error" in result.output.lower()


def test_cli_report_generate_invalid_format(report_scope):
    result = runner.invoke(
        app,
        [
            "report",
            "generate",
            "--scope",
            "report-scope",
            "--format",
            "unsupported_fmt",
        ],
    )
    assert result.exit_code == 1
    assert "Format Error" in result.output or "Unsupported format" in result.output

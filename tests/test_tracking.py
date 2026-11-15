"""Tests for tracking module, verified findings CRUD, scope enforcement, and CLI commands."""

import json

import pytest
from typer.testing import CliRunner

from reconcopilot.cli import app
from reconcopilot.db import init_db, list_audit_logs
from reconcopilot.modules import tracking
from reconcopilot.scope import ScopeChecker, ScopeViolationError

runner = CliRunner()


@pytest.fixture
def tracking_scope(tmp_path, monkeypatch):
    """Sets up a test scope and directory."""
    monkeypatch.setenv("RECONCOPILOT_SCOPES_DIR", str(tmp_path))
    scope_data = {
        "name": "finding-scope",
        "targets": {
            "domains": ["*.acme.com", "acme-staging.io"],
            "ip_ranges": ["203.0.113.0/24"],
            "exclusions": ["mail.acme.com"],
        },
        "metadata": {"notes": "Test finding tracking engagement"},
    }
    checker = ScopeChecker(data=scope_data)
    checker.save(scopes_dir=tmp_path)
    return checker


@pytest.fixture
def tracking_db(tmp_path, monkeypatch, tracking_scope):
    """Sets up a clean temporary database."""
    db_file = tmp_path / "finding_test.db"
    init_db(db_file)
    monkeypatch.setenv("DATABASE_PATH", str(db_file))
    return db_file


# ==============================================================================
# Functional / Module Tests
# ==============================================================================


def test_create_finding_success(tracking_db):
    finding = tracking.create_finding(
        scope="finding-scope",
        title="IDOR in /api/v1/user",
        severity="high",
        affected_asset="api.acme.com",
        description="Changing user_id allows viewing other user records.",
        impact="Confidentiality breach of user PII.",
        reproduction_steps="1. GET /api/v1/user?id=123 with auth token B",
        remediation="Enforce server-side authorization checks.",
        cvss_score=8.1,
        status="open",
        db_path=tracking_db,
    )

    assert finding["id"] == 1
    assert finding["title"] == "IDOR in /api/v1/user"
    assert finding["severity"] == "high"
    assert finding["status"] == "open"
    assert finding["affected_asset"] == "api.acme.com"
    assert finding["cvss_score"] == 8.1
    assert finding["created_at"] != ""
    assert finding["updated_at"] != ""

    # Verify audit log entry created
    logs = list_audit_logs(db_path=tracking_db)
    create_logs = [entry for entry in logs if entry["action"] == "finding.create"]
    assert len(create_logs) == 1
    assert "IDOR" in create_logs[0]["details"]


def test_create_finding_rejects_out_of_scope_asset(tracking_db):
    # Excluded asset
    with pytest.raises(ScopeViolationError):
        tracking.create_finding(
            scope="finding-scope",
            title="Open Redirect",
            severity="low",
            affected_asset="mail.acme.com",
            db_path=tracking_db,
        )

    # Completely out of scope asset
    with pytest.raises(ScopeViolationError):
        tracking.create_finding(
            scope="finding-scope",
            title="XSS",
            severity="medium",
            affected_asset="evil.com",
            db_path=tracking_db,
        )


def test_validation_errors(tracking_db):
    # Empty title
    with pytest.raises(ValueError, match="title cannot be empty"):
        tracking.create_finding(
            scope="finding-scope",
            title="",
            severity="low",
            affected_asset="api.acme.com",
            db_path=tracking_db,
        )

    # Invalid severity
    with pytest.raises(ValueError, match="Invalid severity"):
        tracking.create_finding(
            scope="finding-scope",
            title="Test",
            severity="ultra-critical",
            affected_asset="api.acme.com",
            db_path=tracking_db,
        )

    # Invalid status
    with pytest.raises(ValueError, match="Invalid status"):
        tracking.create_finding(
            scope="finding-scope",
            title="Test",
            severity="medium",
            affected_asset="api.acme.com",
            status="pending-review",
            db_path=tracking_db,
        )

    # Invalid CVSS score
    with pytest.raises(ValueError, match="CVSS score"):
        tracking.create_finding(
            scope="finding-scope",
            title="Test",
            severity="medium",
            affected_asset="api.acme.com",
            cvss_score=11.5,
            db_path=tracking_db,
        )


def test_list_and_filter_findings(tracking_db):
    tracking.create_finding(
        scope="finding-scope",
        title="SQL Injection",
        severity="critical",
        affected_asset="api.acme.com",
        status="open",
        db_path=tracking_db,
    )
    tracking.create_finding(
        scope="finding-scope",
        title="Stored XSS",
        severity="high",
        affected_asset="acme-staging.io",
        status="open",
        db_path=tracking_db,
    )
    tracking.create_finding(
        scope="finding-scope",
        title="CORS Misconfiguration",
        severity="medium",
        affected_asset="api.acme.com",
        status="fixed",
        db_path=tracking_db,
    )

    all_items = tracking.list_findings(scope="finding-scope", db_path=tracking_db)
    assert len(all_items) == 3

    # Filter by severity
    critical_items = tracking.list_findings(
        scope="finding-scope", severity="critical", db_path=tracking_db
    )
    assert len(critical_items) == 1
    assert critical_items[0]["title"] == "SQL Injection"

    # Filter by status
    fixed_items = tracking.list_findings(
        scope="finding-scope", status="fixed", db_path=tracking_db
    )
    assert len(fixed_items) == 1
    assert fixed_items[0]["title"] == "CORS Misconfiguration"

    # Filter by both
    open_high = tracking.list_findings(
        scope="finding-scope", severity="high", status="open", db_path=tracking_db
    )
    assert len(open_high) == 1
    assert open_high[0]["title"] == "Stored XSS"


def test_update_finding_status(tracking_db):
    f = tracking.create_finding(
        scope="finding-scope",
        title="Sensitive Token Leak",
        severity="high",
        affected_asset="api.acme.com",
        status="open",
        db_path=tracking_db,
    )

    fid = f["id"]
    updated = tracking.update_finding_status(
        finding_id=fid, status="fixed", db_path=tracking_db
    )
    assert updated["status"] == "fixed"
    assert updated["updated_at"] >= f["created_at"]

    # Verify audit log
    logs = list_audit_logs(db_path=tracking_db)
    status_logs = [
        entry for entry in logs if entry["action"] == "finding.update_status"
    ]
    assert len(status_logs) == 1
    assert "fixed" in status_logs[0]["details"]

    # Updating non-existent finding raises KeyError
    with pytest.raises(KeyError):
        tracking.update_finding_status(
            finding_id=9999, status="fixed", db_path=tracking_db
        )


def test_export_findings_json(tracking_db):
    tracking.create_finding(
        scope="finding-scope",
        title="RCE in File Upload",
        severity="critical",
        affected_asset="api.acme.com",
        cvss_score=9.8,
        db_path=tracking_db,
    )

    json_str = tracking.export_findings(
        scope="finding-scope", export_format="json", db_path=tracking_db
    )
    data = json.loads(json_str)

    assert data["scope"] == "finding-scope"
    assert data["total_findings"] == 1
    assert len(data["findings"]) == 1
    first = data["findings"][0]
    assert first["title"] == "RCE in File Upload"
    assert first["severity"] == "critical"
    assert first["cvss_score"] == 9.8


# ==============================================================================
# CLI Command Tests
# ==============================================================================


def test_cli_finding_crud_cycle(tracking_db):
    # 1. Add finding via CLI flags
    add_res = runner.invoke(
        app,
        [
            "finding",
            "add",
            "--scope",
            "finding-scope",
            "--title",
            "Broken Object Level Authorization",
            "--severity",
            "high",
            "--asset",
            "api.acme.com",
            "--cvss",
            "8.2",
            "--non-interactive",
        ],
    )
    assert add_res.exit_code == 0
    assert "Added finding #1" in add_res.output
    assert "Broken Object Level Authorization" in add_res.output

    # 2. List findings
    list_res = runner.invoke(app, ["finding", "list", "--scope", "finding-scope"])
    assert list_res.exit_code == 0
    assert "Verified Findings" in list_res.output
    assert "Broken" in list_res.output
    assert "api.acme.com" in list_res.output
    assert "HIGH" in list_res.output

    # 3. List with severity filter
    list_filtered = runner.invoke(
        app, ["finding", "list", "--scope", "finding-scope", "--severity", "high"]
    )
    assert list_filtered.exit_code == 0
    assert "Broken" in list_filtered.output

    # 4. Show finding
    show_res = runner.invoke(app, ["finding", "show", "1"])
    assert show_res.exit_code == 0
    assert "Finding #1" in show_res.output
    assert "CVSS: 8.2" in show_res.output

    # 5. Update finding status
    upd_res = runner.invoke(app, ["finding", "update", "1", "--status", "fixed"])
    assert upd_res.exit_code == 0
    assert "status is now FIXED" in upd_res.output

    # Verify updated in list
    list_after = runner.invoke(app, ["finding", "list", "--scope", "finding-scope"])
    assert "FIXED" in list_after.output

    # 6. Export as JSON
    export_res = runner.invoke(
        app, ["finding", "export", "--scope", "finding-scope", "--format", "json"]
    )
    assert export_res.exit_code == 0
    exported_data = json.loads(export_res.output)
    assert exported_data["scope"] == "finding-scope"
    assert exported_data["total_findings"] == 1
    assert exported_data["findings"][0]["status"] == "fixed"


def test_cli_finding_interactive_add(tracking_db):
    inputs = (
        "\n".join(
            [
                "Interactive CSRF",
                "api.acme.com",
                "medium",
                "Missing anti-CSRF tokens on state-changing endpoints.",
                "Account state manipulation.",
                "Submit form from evil origin.",
                "Implement SameSite cookies and CSRF tokens.",
                "5.4",
            ]
        )
        + "\n"
    )

    res = runner.invoke(
        app, ["finding", "add", "--scope", "finding-scope"], input=inputs
    )
    assert res.exit_code == 0
    assert "Added finding" in res.output
    assert "Interactive CSRF" in res.output

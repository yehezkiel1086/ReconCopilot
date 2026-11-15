"""Tests for recon module, tool execution, output parsing, scope filtering, and CLI."""

import subprocess

import pytest
from typer.testing import CliRunner

from reconcopilot.cli import app
from reconcopilot.db import (
    get_recon_summary,
    init_db,
    list_assets,
    list_audit_logs,
    list_http_probes,
    list_nuclei_findings,
    list_open_ports,
)
from reconcopilot.modules import recon
from reconcopilot.modules.recon import ToolNotFoundError
from reconcopilot.scope import ScopeChecker, ScopeViolationError

runner = CliRunner()

SAMPLE_NMAP_XML = """<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE nmaprun>
<nmaprun scanner="nmap" args="nmap -sT -Pn -T3 --top-ports 100 -oX - 203.0.113.10">
<host>
<status state="up"/>
<address addr="203.0.113.10" addrtype="ipv4"/>
<ports>
<port protocol="tcp" portid="80"><state state="open" reason="syn-ack"/><service name="http"/></port>
<port protocol="tcp" portid="443"><state state="open" reason="syn-ack"/><service name="https"/></port>
<port protocol="tcp" portid="8080"><state state="closed" reason="reset"/></port>
</ports>
</host>
</nmaprun>
"""


@pytest.fixture
def recon_scope(tmp_path, monkeypatch):
    """Creates a temporary test scope and points RECONCOPILOT_SCOPES_DIR to tmp_path."""
    monkeypatch.setenv("RECONCOPILOT_SCOPES_DIR", str(tmp_path))
    scope_data = {
        "name": "recon-test-scope",
        "targets": {
            "domains": ["*.acme.com", "acme-staging.io"],
            "ip_ranges": ["203.0.113.0/24"],
            "exclusions": ["mail.acme.com", "203.0.113.250"],
        },
        "metadata": {"notes": "Test recon engagement"},
    }
    checker = ScopeChecker(data=scope_data)
    checker.save(scopes_dir=tmp_path)
    return checker


@pytest.fixture
def test_db(tmp_path, monkeypatch):
    """Sets a custom temporary SQLite database path."""
    db_file = tmp_path / "recon_test.db"
    init_db(db_file)
    monkeypatch.setenv("DATABASE_PATH", str(db_file))
    return db_file


# ==============================================================================
# Tool Missing Check
# ==============================================================================


def test_missing_tool_raises_tool_not_found(monkeypatch):
    monkeypatch.setattr(recon.shutil, "which", lambda _: None)

    with pytest.raises(ToolNotFoundError) as exc_info:
        recon.require_tool("subfinder")

    assert "subfinder" in str(exc_info.value)
    assert "Install hint" in str(exc_info.value)


# ==============================================================================
# Subdomain Enumeration (subfinder)
# ==============================================================================


def test_subfinder_parsing_and_scope_filtering(recon_scope, test_db, monkeypatch):
    monkeypatch.setattr(recon.shutil, "which", lambda _: "/usr/local/bin/subfinder")

    subfinder_stdout = "\n".join(
        [
            '{"host": "api.acme.com", "source": "crtsh"}',
            '{"host": "auth.acme.com", "source": "censys"}',
            '{"host": "mail.acme.com", "source": "hackertarget"}',  # EXCLUDED
            '{"host": "rogue.attacker.com", "source": "dns"}',  # OUT OF SCOPE
            "dashboard.acme.com",  # Plain line support
        ]
    )

    def mock_exec(cmd, input_str=None, timeout=300.0):
        return subprocess.CompletedProcess(
            args=cmd, returncode=0, stdout=subfinder_stdout, stderr=""
        )

    monkeypatch.setattr(recon, "_execute_tool", mock_exec)

    added = recon.run_subdomain_enum(scope_name="recon-test-scope", db_path=test_db)

    # In-scope: api.acme.com, auth.acme.com, dashboard.acme.com
    assert "api.acme.com" in added
    assert "auth.acme.com" in added
    assert "dashboard.acme.com" in added

    # Filtered out-of-scope targets
    assert "mail.acme.com" not in added
    assert "rogue.attacker.com" not in added

    # Check database assets table
    assets = list_assets("recon-test-scope", db_path=test_db)
    asset_names = [a["asset"] for a in assets]
    assert "api.acme.com" in asset_names
    assert "mail.acme.com" not in asset_names
    assert "rogue.attacker.com" not in asset_names

    # Check audit log entry created
    logs = list_audit_logs(db_path=test_db)
    subfinder_logs = [entry for entry in logs if entry["action"] == "recon.subfinder"]
    assert len(subfinder_logs) > 0
    assert "subfinder" in subfinder_logs[0]["details"]


# ==============================================================================
# Live Probing (httpx)
# ==============================================================================


def test_httpx_probing_parsing_and_storage(recon_scope, test_db, monkeypatch):
    monkeypatch.setattr(recon.shutil, "which", lambda _: "/usr/local/bin/httpx")

    httpx_stdout = "\n".join(
        [
            '{"url": "https://api.acme.com", "host": "api.acme.com", "status_code": 200, "title": "API Gateway", "technologies": ["Nginx", "Node.js"], "content_length": 1520}',
            '{"url": "https://dashboard.acme.com", "host": "dashboard.acme.com", "status_code": 302, "title": "Login Redirect", "tech": ["React", "Express"], "content-length": 450}',
            '{"url": "https://mail.acme.com", "host": "mail.acme.com", "status_code": 200, "title": "Webmail"}',  # Excluded
        ]
    )

    def mock_exec(cmd, input_str=None, timeout=300.0):
        return subprocess.CompletedProcess(
            args=cmd, returncode=0, stdout=httpx_stdout, stderr=""
        )

    monkeypatch.setattr(recon, "_execute_tool", mock_exec)

    # Pre-load candidate targets
    probes = recon.run_http_probing(
        scope_name="recon-test-scope",
        targets=["api.acme.com", "dashboard.acme.com"],
        db_path=test_db,
    )

    assert len(probes) == 2
    assert probes[0]["status_code"] == 200
    assert "Nginx" in probes[0]["tech_stack"]
    assert probes[0]["content_length"] == 1520

    stored = list_http_probes("recon-test-scope", db_path=test_db)
    stored_urls = [p["url"] for p in stored]
    assert "https://api.acme.com" in stored_urls
    assert "https://dashboard.acme.com" in stored_urls
    assert "https://mail.acme.com" not in stored_urls

    # Check audit log
    logs = list_audit_logs(db_path=test_db)
    httpx_logs = [entry for entry in logs if entry["action"] == "recon.httpx"]
    assert len(httpx_logs) > 0


def test_httpx_rejects_all_out_of_scope_targets(recon_scope, test_db, monkeypatch):
    monkeypatch.setattr(recon.shutil, "which", lambda _: "/usr/local/bin/httpx")

    with pytest.raises(ScopeViolationError):
        recon.run_http_probing(
            scope_name="recon-test-scope",
            targets=["evil.com", "mail.acme.com"],
            db_path=test_db,
        )


# ==============================================================================
# Template Scanning (nuclei)
# ==============================================================================


def test_nuclei_scanning_parsing_and_storage(recon_scope, test_db, monkeypatch):
    monkeypatch.setattr(recon.shutil, "which", lambda _: "/usr/local/bin/nuclei")

    nuclei_stdout = "\n".join(
        [
            '{"template-id": "git-config", "info": {"severity": "medium", "name": "Git Config Exposure"}, "matched-at": "https://api.acme.com/.git/config"}',
            '{"template-id": "tech-detect-nginx", "info": {"severity": "info", "name": "Nginx Web Server"}, "matched-at": "https://api.acme.com"}',
        ]
    )

    def mock_exec(cmd, input_str=None, timeout=300.0):
        return subprocess.CompletedProcess(
            args=cmd, returncode=0, stdout=nuclei_stdout, stderr=""
        )

    monkeypatch.setattr(recon, "_execute_tool", mock_exec)

    findings = recon.run_nuclei_scan(
        scope_name="recon-test-scope",
        targets=["https://api.acme.com"],
        templates="exposure",
        db_path=test_db,
    )

    assert len(findings) == 2
    assert findings[0]["template_id"] == "git-config"
    assert findings[0]["severity"] == "medium"

    stored = list_nuclei_findings("recon-test-scope", db_path=test_db)
    assert len(stored) == 2

    # Check audit log
    logs = list_audit_logs(db_path=test_db)
    nuclei_logs = [entry for entry in logs if entry["action"] == "recon.nuclei"]
    assert len(nuclei_logs) > 0


# ==============================================================================
# Port Scanning (nmap)
# ==============================================================================


def test_nmap_port_scan_safe_defaults_and_parsing(recon_scope, test_db, monkeypatch):
    monkeypatch.setattr(recon.shutil, "which", lambda _: "/usr/bin/nmap")

    executed_cmd = []

    def mock_exec(cmd, input_str=None, timeout=300.0):
        executed_cmd.extend(cmd)
        return subprocess.CompletedProcess(
            args=cmd, returncode=0, stdout=SAMPLE_NMAP_XML, stderr=""
        )

    monkeypatch.setattr(recon, "_execute_tool", mock_exec)

    ports = recon.run_port_scan(
        scope_name="recon-test-scope",
        target="203.0.113.10",
        db_path=test_db,
    )

    # Check safe default flags were used
    assert "-sT" in executed_cmd
    assert "-Pn" in executed_cmd
    assert "-T3" in executed_cmd
    assert "--top-ports" in executed_cmd

    # Check parsed open ports
    assert len(ports) == 2
    port_numbers = [p["port"] for p in ports]
    assert 80 in port_numbers
    assert 443 in port_numbers

    # Stored in open_ports table
    stored = list_open_ports("recon-test-scope", target="203.0.113.10", db_path=test_db)
    assert len(stored) == 2

    # Check audit log
    logs = list_audit_logs(db_path=test_db)
    nmap_logs = [entry for entry in logs if entry["action"] == "recon.nmap"]
    assert len(nmap_logs) > 0
    assert "-sT" in nmap_logs[0]["details"]


def test_nmap_rejects_out_of_scope_target(recon_scope, test_db):
    # 203.0.113.250 is in exclusions
    with pytest.raises(ScopeViolationError):
        recon.run_port_scan(
            scope_name="recon-test-scope",
            target="203.0.113.250",
            db_path=test_db,
        )

    # Completely out of scope IP
    with pytest.raises(ScopeViolationError):
        recon.run_port_scan(
            scope_name="recon-test-scope",
            target="8.8.8.8",
            db_path=test_db,
        )


# ==============================================================================
# Recon Status & Summary
# ==============================================================================


def test_recon_status_summary(recon_scope, test_db, monkeypatch):
    monkeypatch.setattr(recon.shutil, "which", lambda _: "/usr/bin/tool")

    # Add sample data to DB
    recon.add_asset("recon-test-scope", "api.acme.com", db_path=test_db)
    recon.add_asset("recon-test-scope", "auth.acme.com", db_path=test_db)
    recon.add_http_probe(
        "recon-test-scope", "https://api.acme.com", "api.acme.com", 200, db_path=test_db
    )
    recon.add_http_probe(
        "recon-test-scope",
        "https://auth.acme.com",
        "auth.acme.com",
        302,
        db_path=test_db,
    )
    recon.add_open_port(
        "recon-test-scope", "203.0.113.10", 443, service="https", db_path=test_db
    )
    recon.add_nuclei_finding(
        "recon-test-scope",
        "cve-2024-test",
        "high",
        "https://api.acme.com",
        db_path=test_db,
    )

    summary = get_recon_summary("recon-test-scope", db_path=test_db)
    assert summary["total_assets"] == 2
    assert summary["total_http_probes"] == 2
    assert summary["status_codes"]["200"] == 1
    assert summary["total_open_ports"] == 1
    assert summary["total_nuclei_findings"] == 1
    assert summary["severity_counts"]["high"] == 1


# ==============================================================================
# CLI Command Group Tests
# ==============================================================================


def test_cli_recon_group_help():
    res = runner.invoke(app, ["recon", "--help"])
    assert res.exit_code == 0
    assert "subdomains" in res.output
    assert "probe" in res.output
    assert "scan" in res.output
    assert "ports" in res.output
    assert "status" in res.output


def test_cli_recon_missing_tool_error(recon_scope, monkeypatch):
    monkeypatch.setattr(recon.shutil, "which", lambda _: None)

    res = runner.invoke(app, ["recon", "subdomains", "--scope", "recon-test-scope"])
    assert res.exit_code == 1
    assert "Tool Missing" in res.output
    assert "subfinder" in res.output
    assert "Install hint" in res.output


def test_cli_recon_status_command(recon_scope, test_db, monkeypatch):
    recon.add_asset("recon-test-scope", "api.acme.com", db_path=test_db)

    res = runner.invoke(app, ["recon", "status", "--scope", "recon-test-scope"])
    assert res.exit_code == 0
    assert "Reconnaissance Status" in res.output
    assert "Discovered Assets" in res.output

"""Phase 2 Module: Reconnaissance engine wrapping subfinder, httpx, nuclei, and nmap.

Wraps installed reconnaissance CLI tools, enforces scope allowlists on all inputs
and discovered outputs, and standardizes records into SQLite.
"""

from __future__ import annotations

import json
import logging
import re
import shutil
import subprocess
import xml.etree.ElementTree as ET
from pathlib import Path
from typing import Any

from reconcopilot.audit import log_audit
from reconcopilot.db import (
    add_asset,
    add_http_probe,
    add_nuclei_finding,
    add_open_port,
    get_recon_summary,
    list_assets,
    list_http_probes,
)
from reconcopilot.scope import ScopeChecker, ScopeViolationError, require_in_scope

logger = logging.getLogger(__name__)


class ToolNotFoundError(FileNotFoundError):
    """Raised when an external reconnaissance binary is not installed or not in PATH."""


TOOL_INSTALL_HINTS: dict[str, str] = {
    "subfinder": (
        "Tool 'subfinder' is not installed or not found in PATH.\n"
        "Install hint: go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest\n"
        "Or download release binary from: https://github.com/projectdiscovery/subfinder/releases"
    ),
    "httpx": (
        "Tool 'httpx' is not installed or not found in PATH.\n"
        "Install hint: go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest\n"
        "Or download release binary from: https://github.com/projectdiscovery/httpx/releases"
    ),
    "nuclei": (
        "Tool 'nuclei' is not installed or not found in PATH.\n"
        "Install hint: go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest\n"
        "Or download release binary from: https://github.com/projectdiscovery/nuclei/releases"
    ),
    "nmap": (
        "Tool 'nmap' is not installed or not found in PATH.\n"
        "Install hint: Download and install nmap from https://nmap.org/download.html\n"
        "Or use a package manager (e.g. 'winget install Insecure.Nmap', 'apt install nmap', 'brew install nmap')"
    ),
}


def require_tool(tool_name: str) -> str:
    """Verifies that a command-line tool is available in PATH.

    Raises:
        ToolNotFoundError: If the tool is missing, with install hint.
    """
    path = shutil.which(tool_name)
    if not path:
        hint = TOOL_INSTALL_HINTS.get(
            tool_name,
            f"Required tool '{tool_name}' was not found in PATH. Please install it to proceed.",
        )
        raise ToolNotFoundError(hint)
    return path


def _execute_tool(
    cmd: list[str],
    input_str: str | None = None,
    timeout: float = 300.0,
) -> subprocess.CompletedProcess[str]:
    """Executes a subprocess command, returning CompletedProcess."""
    return subprocess.run(
        cmd,
        input=input_str,
        capture_output=True,
        text=True,
        timeout=timeout,
        check=False,
    )


# ==============================================================================
# Subdomain Enumeration (subfinder)
# ==============================================================================


def run_subdomain_enum(
    scope_name: str,
    domain: str | None = None,
    db_path: str | Path | None = None,
) -> list[str]:
    """Runs subfinder against in-scope domains and stores discovered subdomains.

    Filters out any out-of-scope subdomains returned by subfinder.
    """
    scope = ScopeChecker.from_name(scope_name)
    tool_bin = require_tool("subfinder")

    # Determine domains to scan
    domains_to_scan: list[str] = []
    if domain:
        norm = require_in_scope(domain, scope=scope)
        domains_to_scan.append(norm)
    else:
        for d in scope.domains:
            clean = d.strip()
            if clean.startswith("*."):
                clean = clean[2:]
            elif clean.startswith("."):
                clean = clean[1:]
            if clean and clean not in domains_to_scan:
                domains_to_scan.append(clean)

    if not domains_to_scan:
        raise ValueError(
            f"No domain targets found in scope '{scope_name}'. Add domains to scope or pass --domain."
        )

    all_added_assets: list[str] = []

    for d in domains_to_scan:
        cmd = [tool_bin, "-d", d, "-silent", "-json"]
        cmd_str = (
            subprocess.list2cmdline(cmd)
            if hasattr(subprocess, "list2cmdline")
            else " ".join(cmd)
        )

        log_audit(
            action="recon.subfinder",
            target=d,
            details={"command": cmd_str, "scope": scope_name},
        )

        proc = _execute_tool(cmd)
        raw_output = proc.stdout or ""

        for line in raw_output.splitlines():
            line = line.strip()
            if not line:
                continue

            host = ""
            # Try parsing as JSON first
            if line.startswith("{") and line.endswith("}"):
                try:
                    parsed = json.loads(line)
                    host = parsed.get("host") or parsed.get("subdomain") or ""
                except json.JSONDecodeError:
                    host = line
            else:
                host = line

            host = host.strip().lower()
            if not host:
                continue

            # Scope validation: filter out any rogue or wildcard DNS subdomains
            if scope.is_in_scope(host):
                add_asset(
                    scope_name=scope_name,
                    asset=host,
                    source_tool="subfinder",
                    raw_data=line,
                    db_path=db_path,
                )
                if host not in all_added_assets:
                    all_added_assets.append(host)
            else:
                logger.warning(
                    "Filtered out-of-scope subdomain discovered by subfinder: %s", host
                )
                log_audit(
                    action="recon.subfinder.out_of_scope_filter",
                    target=host,
                    details={"scope": scope_name, "raw": line},
                )

    return all_added_assets


# ==============================================================================
# Live Host Probing (httpx)
# ==============================================================================


def run_http_probing(
    scope_name: str,
    targets: list[str] | None = None,
    db_path: str | Path | None = None,
) -> list[dict[str, Any]]:
    """Runs httpx live probing against stored assets for a scope."""
    scope = ScopeChecker.from_name(scope_name)
    tool_bin = require_tool("httpx")

    # If targets are not explicitly provided, load stored assets for this scope
    candidate_targets: list[str] = []
    if targets:
        candidate_targets = list(targets)
    else:
        stored_assets = list_assets(scope_name, db_path=db_path)
        candidate_targets = [a["asset"] for a in stored_assets]
        # If no assets, fallback to scope domains
        if not candidate_targets:
            candidate_targets = [d.replace("*.", "") for d in scope.domains]

    if not candidate_targets:
        raise ValueError(
            f"No assets found to probe for scope '{scope_name}'. Run 'recon subdomains' first or supply targets."
        )

    # Validate every candidate target against scope before running httpx
    valid_targets: list[str] = []
    for t in candidate_targets:
        t_clean = t.strip()
        if scope.is_in_scope(t_clean):
            valid_targets.append(t_clean)
        else:
            logger.warning("Skipping out-of-scope candidate probe target: %s", t_clean)

    if not valid_targets:
        raise ScopeViolationError(
            f"All provided probe targets for scope '{scope_name}' were rejected by scope enforcement."
        )

    cmd = [
        tool_bin,
        "-silent",
        "-json",
        "-title",
        "-tech-detect",
        "-status-code",
        "-content-length",
    ]
    cmd_str = (
        subprocess.list2cmdline(cmd)
        if hasattr(subprocess, "list2cmdline")
        else " ".join(cmd)
    )
    input_data = "\n".join(valid_targets) + "\n"

    log_audit(
        action="recon.httpx",
        target=f"{len(valid_targets)} targets in {scope_name}",
        details={
            "command": cmd_str,
            "target_count": len(valid_targets),
            "scope": scope_name,
        },
    )

    proc = _execute_tool(cmd, input_str=input_data)
    raw_output = proc.stdout or ""

    stored_probes: list[dict[str, Any]] = []

    for line in raw_output.splitlines():
        line = line.strip()
        if not line or not (line.startswith("{") and line.endswith("}")):
            continue

        try:
            data = json.loads(line)
        except json.JSONDecodeError:
            continue

        url = data.get("url") or data.get("input") or ""
        host = data.get("host") or data.get("input") or ""
        if not host and url:
            host = url.split("://")[-1].split("/")[0].split(":")[0]

        # Verify host is within scope
        if not scope.is_in_scope(host or url):
            logger.warning("Filtered out-of-scope response from httpx probe: %s", url)
            continue

        # Extract status code, title, tech stack, content length
        status_code = data.get("status_code") or data.get("status-code")
        try:
            status_code = int(status_code) if status_code is not None else None
        except ValueError:
            status_code = None

        title = data.get("title") or ""
        content_length = data.get("content_length") or data.get("content-length") or 0
        try:
            content_length = int(content_length)
        except ValueError:
            content_length = 0

        techs = data.get("technologies") or data.get("tech") or []
        tech_str = ", ".join(techs) if isinstance(techs, list) else str(techs)

        add_http_probe(
            scope_name=scope_name,
            url=url,
            host=host,
            status_code=status_code,
            title=title,
            tech_stack=tech_str,
            content_length=content_length,
            raw_data=line,
            db_path=db_path,
        )

        stored_probes.append(
            {
                "url": url,
                "host": host,
                "status_code": status_code,
                "title": title,
                "tech_stack": tech_str,
                "content_length": content_length,
            }
        )

    return stored_probes


# ==============================================================================
# Vulnerability & Template Scanning (nuclei)
# ==============================================================================


def run_nuclei_scan(
    scope_name: str,
    templates: str | None = None,
    targets: list[str] | None = None,
    db_path: str | Path | None = None,
) -> list[dict[str, Any]]:
    """Runs nuclei against live probed hosts for a scope."""
    scope = ScopeChecker.from_name(scope_name)
    tool_bin = require_tool("nuclei")

    # Determine target URLs to scan
    candidate_urls: list[str] = []
    if targets:
        candidate_urls = list(targets)
    else:
        probes = list_http_probes(scope_name, db_path=db_path)
        candidate_urls = [p["url"] for p in probes]
        if not candidate_urls:
            assets = list_assets(scope_name, db_path=db_path)
            candidate_urls = [f"https://{a['asset']}" for a in assets]

    if not candidate_urls:
        raise ValueError(
            f"No live HTTP targets found for scope '{scope_name}'. Run 'recon probe' first."
        )

    # Validate all targets against scope
    valid_targets: list[str] = []
    for u in candidate_urls:
        if scope.is_in_scope(u):
            valid_targets.append(u)
        else:
            logger.warning("Skipping out-of-scope target for nuclei scan: %s", u)

    if not valid_targets:
        raise ScopeViolationError(
            f"All targets for nuclei scan in scope '{scope_name}' were rejected by scope enforcement."
        )

    cmd = [tool_bin, "-silent", "-jsonl"]
    if templates:
        cmd.extend(["-tags", templates])

    cmd_str = (
        subprocess.list2cmdline(cmd)
        if hasattr(subprocess, "list2cmdline")
        else " ".join(cmd)
    )
    input_data = "\n".join(valid_targets) + "\n"

    log_audit(
        action="recon.nuclei",
        target=f"{len(valid_targets)} targets in {scope_name}",
        details={
            "command": cmd_str,
            "templates": templates or "default",
            "scope": scope_name,
        },
    )

    proc = _execute_tool(cmd, input_str=input_data)
    raw_output = proc.stdout or ""

    stored_findings: list[dict[str, Any]] = []

    for line in raw_output.splitlines():
        line = line.strip()
        if not line or not (line.startswith("{") and line.endswith("}")):
            continue

        try:
            data = json.loads(line)
        except json.JSONDecodeError:
            continue

        template_id = data.get("template-id") or data.get("templateID") or "unknown"
        info = data.get("info", {}) or {}
        severity = info.get("severity") or data.get("severity") or "info"
        name = info.get("name") or data.get("name") or template_id
        matched_url = (
            data.get("matched-at") or data.get("matched") or data.get("host") or ""
        )

        # Validate matched target is within scope
        if not scope.is_in_scope(matched_url):
            logger.warning("Filtered out-of-scope nuclei finding on: %s", matched_url)
            continue

        add_nuclei_finding(
            scope_name=scope_name,
            template_id=template_id,
            severity=severity,
            matched_url=matched_url,
            name=name,
            raw_data=line,
            db_path=db_path,
        )

        stored_findings.append(
            {
                "template_id": template_id,
                "severity": severity,
                "name": name,
                "matched_url": matched_url,
            }
        )

    return stored_findings


# ==============================================================================
# Port Scanning (nmap)
# ==============================================================================


def _parse_nmap_xml(xml_content: str) -> list[dict[str, Any]]:
    """Parses standard nmap XML output into a structured port list."""
    results: list[dict[str, Any]] = []
    try:
        root = ET.fromstring(xml_content)
        for host in root.findall("host"):
            ports_elem = host.find("ports")
            if ports_elem is None:
                continue
            for port_elem in ports_elem.findall("port"):
                protocol = port_elem.attrib.get("protocol", "tcp")
                port_id = int(port_elem.attrib.get("portid", 0))

                state_elem = port_elem.find("state")
                state = (
                    state_elem.attrib.get("state", "open")
                    if state_elem is not None
                    else "open"
                )

                service_elem = port_elem.find("service")
                service = (
                    service_elem.attrib.get("name", "")
                    if service_elem is not None
                    else ""
                )

                if state == "open":
                    results.append(
                        {
                            "port": port_id,
                            "protocol": protocol,
                            "state": state,
                            "service": service,
                        }
                    )
    except ET.ParseError:
        pass
    return results


def _parse_nmap_text(text_content: str) -> list[dict[str, Any]]:
    """Fallback parser for standard nmap text tabular output."""
    results: list[dict[str, Any]] = []
    # Pattern: 80/tcp open http
    pattern = re.compile(
        r"^(\d+)/([a-zA-Z]+)\s+([a-zA-Z]+)\s*([a-zA-Z0-9\-_]*)", re.MULTILINE
    )
    for match in pattern.finditer(text_content):
        port_num = int(match.group(1))
        protocol = match.group(2).lower()
        state = match.group(3).lower()
        service = match.group(4).strip()
        if state == "open":
            results.append(
                {
                    "port": port_num,
                    "protocol": protocol,
                    "state": state,
                    "service": service,
                }
            )
    return results


def run_port_scan(
    scope_name: str,
    target: str,
    ports: str | None = None,
    db_path: str | Path | None = None,
) -> list[dict[str, Any]]:
    """Runs an nmap port scan against a single explicitly in-scope target.

    Uses safe default flags: -sT (TCP connect), -Pn (no ping probe), -T3 (normal timing).
    """
    normalized_target = require_in_scope(target, scope=scope_name)
    tool_bin = require_tool("nmap")

    # Safe default flag set: unprivileged TCP connect scan, normal timing, top 100 ports
    cmd = [tool_bin, "-sT", "-Pn", "-T3"]
    if ports:
        cmd.extend(["-p", ports.strip()])
    else:
        cmd.extend(["--top-ports", "100"])

    # Request XML output on stdout for clean machine parsing
    cmd.extend(["-oX", "-", normalized_target])

    cmd_str = (
        subprocess.list2cmdline(cmd)
        if hasattr(subprocess, "list2cmdline")
        else " ".join(cmd)
    )

    log_audit(
        action="recon.nmap",
        target=normalized_target,
        details={"command": cmd_str, "scope": scope_name},
    )

    proc = _execute_tool(cmd)
    raw_output = proc.stdout or ""

    # Parse XML or text output
    parsed_ports = _parse_nmap_xml(raw_output)
    if not parsed_ports:
        parsed_ports = _parse_nmap_text(raw_output)

    stored_ports: list[dict[str, Any]] = []

    for item in parsed_ports:
        add_open_port(
            scope_name=scope_name,
            target=normalized_target,
            port=item["port"],
            protocol=item["protocol"],
            state=item["state"],
            service=item["service"],
            raw_data=raw_output,
            db_path=db_path,
        )
        stored_ports.append(
            {
                "target": normalized_target,
                "port": item["port"],
                "protocol": item["protocol"],
                "state": item["state"],
                "service": item["service"],
            }
        )

    return stored_ports


# ==============================================================================
# Recon Status Summary
# ==============================================================================


def get_recon_status(
    scope_name: str,
    db_path: str | Path | None = None,
) -> dict[str, Any]:
    """Retrieves an aggregated summary of all reconnaissance data for a scope."""
    return get_recon_summary(scope_name=scope_name, db_path=db_path)

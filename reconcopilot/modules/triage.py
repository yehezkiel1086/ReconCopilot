"""Phase 3 Module: Security reconnaissance triage and finding prioritization.

Pulls http_probes, nuclei_findings, and open_ports from SQLite for a given scope,
performing AI-assisted triage via Claude API when an API key is configured,
or falling back to deterministic rules-based prioritization when unavailable.
"""

from __future__ import annotations

import json
import logging
import os
from pathlib import Path
from typing import Any

from reconcopilot.audit import log_audit
from reconcopilot.config import load_config
from reconcopilot.db import (
    add_triage_run,
    get_triage_run,
    list_http_probes,
    list_nuclei_findings,
    list_open_ports,
    list_triage_runs,
)
from reconcopilot.scope import ScopeChecker, require_in_scope

logger = logging.getLogger(__name__)

# High-interest keywords for title, tech stack, and endpoint filtering
HIGH_INTEREST_KEYWORDS = [
    "admin",
    "login",
    "portal",
    "dashboard",
    "internal",
    "swagger",
    "api",
    "graphql",
    "jenkins",
    "gitlab",
    "jira",
    "kibana",
    "grafana",
    "phpmyadmin",
    "wordpress",
    "spring",
    "laravel",
    "django",
    "actuator",
    "env",
    "config",
    "debug",
    "oauth",
    "sso",
    "auth",
]

# Sensitive services / ports with high security relevance
HIGH_VALUE_PORTS = {
    3306: (
        "MySQL Database",
        8.5,
        "Verify database is not exposed without authentication or using default credentials.",
    ),
    5432: (
        "PostgreSQL Database",
        8.5,
        "Check if PostgreSQL allows remote connections and test password policy.",
    ),
    6379: (
        "Redis Key-Value Store",
        9.0,
        "Verify Redis requires AUTH and does not permit unauthenticated commands.",
    ),
    27017: (
        "MongoDB Database",
        8.5,
        "Check MongoDB authentication status and database exposure.",
    ),
    1433: (
        "MSSQL Database",
        8.0,
        "Review SQL Server network exposure and authentication mode.",
    ),
    9200: (
        "Elasticsearch",
        8.5,
        "Ensure Elasticsearch indices are protected and not publicly readable.",
    ),
    11211: (
        "Memcached",
        8.5,
        "Check for unauthenticated memcached stats or command execution.",
    ),
    3389: (
        "RDP Remote Desktop",
        7.5,
        "Verify Network Level Authentication (NLA) and account lockout policy.",
    ),
    22: (
        "SSH Remote Access",
        6.5,
        "Verify password authentication is disabled and keys are enforced.",
    ),
    21: (
        "FTP File Transfer",
        7.0,
        "Test for anonymous FTP access and cleartext authentication risks.",
    ),
    23: ("Telnet", 8.0, "Check for insecure cleartext Telnet protocol usage."),
    8080: (
        "Alternate HTTP/Proxy",
        6.0,
        "Investigate web application, management consoles, or proxy services.",
    ),
    8443: (
        "Alternate HTTPS",
        6.0,
        "Investigate secure administrative interfaces or API endpoints.",
    ),
}

NUCLEI_SEVERITY_WEIGHTS = {
    "critical": 10.0,
    "high": 8.0,
    "medium": 5.0,
    "low": 3.0,
    "info": 1.0,
}


def _get_api_key() -> str:
    """Retrieves the Anthropic API key from config or environment."""
    cfg = load_config()
    key = cfg.ai.api_key or os.getenv("ANTHROPIC_API_KEY") or ""
    return key.strip()


def fetch_scope_findings(
    scope_name: str, db_path: str | Path | None = None
) -> dict[str, Any]:
    """Pulls all reconnaissance artifacts for a scope from the SQLite database."""
    # Ensure scope exists
    ScopeChecker.from_name(scope_name)

    probes = list_http_probes(scope_name, db_path=db_path)
    findings = list_nuclei_findings(scope_name, db_path=db_path)
    ports = list_open_ports(scope_name, db_path=db_path)

    return {
        "scope_name": scope_name,
        "http_probes": probes,
        "nuclei_findings": findings,
        "open_ports": ports,
    }


# ==============================================================================
# Rules-Based Triage Fallback
# ==============================================================================


def run_rules_triage(
    scope_name: str,
    top_n: int = 10,
    focus: str = "",
    db_path: str | Path | None = None,
) -> dict[str, Any]:
    """Performs deterministic rules-based triage without requiring external AI APIs."""
    data = fetch_scope_findings(scope_name, db_path=db_path)
    probes = data["http_probes"]
    findings = data["nuclei_findings"]
    ports = data["open_ports"]

    scored_items: list[dict[str, Any]] = []

    # 1. Score Nuclei findings
    for f in findings:
        sev = f.get("severity", "info").lower()
        base_score = NUCLEI_SEVERITY_WEIGHTS.get(sev, 1.0)
        item = {
            "target": f.get("matched_url") or scope_name,
            "category": "Vulnerability / Nuclei Finding",
            "type": f.get("template_id"),
            "severity": sev.upper(),
            "score": base_score,
            "title": f.get("name") or f.get("template_id"),
            "details": f"Template: {f.get('template_id')} on {f.get('matched_url')}",
            "recommended_action": f"Manually verify vulnerability on {f.get('matched_url')} and review relevant advisory.",
        }
        scored_items.append(item)

    # 2. Score Open Ports
    for p in ports:
        port_num = int(p.get("port", 0))
        service_name = p.get("service", "")
        target = p.get("target", "")

        if port_num in HIGH_VALUE_PORTS:
            desc, port_score, action = HIGH_VALUE_PORTS[port_num]
            sev = "HIGH" if port_score >= 8.0 else "MEDIUM"
            item = {
                "target": f"{target}:{port_num}",
                "category": "Exposed Sensitive Port",
                "type": f"port_{port_num}",
                "severity": sev,
                "score": port_score,
                "title": f"Port {port_num}/{p.get('protocol')} ({desc})",
                "details": f"Open port {port_num} ({service_name or desc}) on {target}",
                "recommended_action": action,
            }
            scored_items.append(item)
        else:
            # Standard port
            item = {
                "target": f"{target}:{port_num}",
                "category": "Open Port",
                "type": f"port_{port_num}",
                "severity": "INFO",
                "score": 3.0,
                "title": f"Port {port_num}/{p.get('protocol')} ({service_name or 'unknown'})",
                "details": f"Open port on {target}",
                "recommended_action": "Verify if service exposure is expected and check version banners.",
            }
            scored_items.append(item)

    # 3. Score HTTP Probes
    for pr in probes:
        url = pr.get("url", "")
        code = pr.get("status_code")
        title = pr.get("title", "")
        tech = pr.get("tech_stack", "")

        score = 2.0
        reasons = []

        # Check status codes
        if code in (401, 403):
            score += 3.5
            reasons.append(f"HTTP {code} restricted area")
        elif code and code >= 500:
            score += 2.5
            reasons.append(f"HTTP {code} server error")

        # Check keyword matches in title or tech
        combined_text = f"{url} {title} {tech}".lower()
        matched_keywords = [kw for kw in HIGH_INTEREST_KEYWORDS if kw in combined_text]
        if matched_keywords:
            score += min(len(matched_keywords) * 1.5, 4.0)
            reasons.append(
                f"Interesting tech/keywords: {', '.join(matched_keywords[:4])}"
            )

        if score >= 4.0:
            sev = "HIGH" if score >= 7.0 else "MEDIUM"
            item = {
                "target": url,
                "category": "High-Value HTTP Endpoint",
                "type": "http_probe",
                "severity": sev,
                "score": score,
                "title": title or url,
                "details": f"Status: {code} | Tech: {tech or 'N/A'} | {'; '.join(reasons)}",
                "recommended_action": f"Review {url} manually for authorization boundaries and exposed endpoints.",
            }
            scored_items.append(item)

    # If focus keyword provided, bump items matching focus
    if focus and focus.strip():
        f_lower = focus.strip().lower()
        for it in scored_items:
            blob = f"{it['target']} {it['title']} {it['details']}".lower()
            if f_lower in blob:
                it["score"] += 3.0
                it["details"] += f" (Matches focus: '{focus}')"

    # Sort descending by score
    scored_items.sort(key=lambda x: x["score"], reverse=True)
    top_items = scored_items[:top_n]

    # Generate readable summary markdown
    markdown_lines = [
        f"# Rules-Based Triage for Scope: {scope_name}",
        "",
        "> **Notice**: AI API key not configured or AI disabled. Displaying deterministic rules-based priority analysis.",
        "",
        f"### Top {len(top_items)} Prioritized Targets",
        "",
    ]

    for idx, item in enumerate(top_items, start=1):
        markdown_lines.extend(
            [
                f"#### {idx}. [{item['severity']}] {item['title']}",
                f"- **Target**: `{item['target']}`",
                f"- **Category**: {item['category']}",
                f"- **Priority Score**: {item['score']:.1f}/10.0",
                f"- **Findings**: {item['details']}",
                f"- **Suggested Manual Verification**: {item['recommended_action']}",
                "",
            ]
        )

    response_text = "\n".join(markdown_lines)

    # Save to triage_runs database table
    run_id = add_triage_run(
        scope_name=scope_name,
        mode="rules",
        raw_findings_sent=json.dumps(data),
        ai_response=response_text,
        focus=focus,
        top_n=top_n,
        db_path=db_path,
    )

    log_audit(
        action="triage.rules_run",
        target=scope_name,
        details={"run_id": run_id, "top_n": top_n, "focus": focus},
    )

    return {
        "run_id": run_id,
        "scope_name": scope_name,
        "mode": "rules",
        "focus": focus,
        "items": top_items,
        "summary_text": response_text,
    }


# ==============================================================================
# AI-Assisted Triage (Claude API)
# ==============================================================================


TRIAGE_SYSTEM_PROMPT = """You are ReconCopilot, an expert cybersecurity reconnaissance triage assistant.
Your task is to analyze discovered reconnaissance data (HTTP endpoints, open ports, nuclei findings) for an authorized engagement scope and prioritize the most promising attack surface investigation paths.

CRITICAL SAFETY AND OPERATIONAL CONSTRAINTS:
1. You must strictly suggest next manual investigation steps, verification steps, and defensive review actions ONLY.
2. You must NEVER generate functional exploit code, weaponized payloads, or step-by-step attack instructions.
3. Keep all suggestions focused on safe, professional bug bounty / penetration test methodology (e.g. testing access controls, verifying version disclosures, inspecting API schemas).
4. Organize the output clearly with:
   - Executive Summary
   - Top Prioritized Findings / Targets (target, severity, rationale, suggested manual investigation step)
   - Key Attack Surface Observations
"""


def run_ai_triage(
    scope_name: str,
    api_key: str,
    top_n: int = 10,
    focus: str = "",
    db_path: str | Path | None = None,
) -> dict[str, Any]:
    """Executes AI-assisted triage using Anthropic Claude API."""
    import anthropic

    cfg = load_config()
    model = cfg.ai.model or "claude-sonnet-4-6"

    data = fetch_scope_findings(scope_name, db_path=db_path)
    probes = data["http_probes"]
    findings = data["nuclei_findings"]
    ports = data["open_ports"]

    if not probes and not findings and not ports:
        raise ValueError(
            f"No reconnaissance data found for scope '{scope_name}'. Run recon modules first."
        )

    # Prepare structured summary for prompt
    user_payload = {
        "scope_name": scope_name,
        "focus_request": focus or "Comprehensive attack surface triage",
        "top_n_requested": top_n,
        "data_summary": {
            "total_http_probes": len(probes),
            "total_open_ports": len(ports),
            "total_nuclei_findings": len(findings),
        },
        "nuclei_findings": [
            {
                "template": f.get("template_id"),
                "severity": f.get("severity"),
                "name": f.get("name"),
                "matched": f.get("matched_url"),
            }
            for f in findings[:50]
        ],
        "open_ports": [
            {
                "target": p.get("target"),
                "port": p.get("port"),
                "protocol": p.get("protocol"),
                "service": p.get("service"),
            }
            for p in ports[:50]
        ],
        "http_probes": [
            {
                "url": pr.get("url"),
                "status": pr.get("status_code"),
                "title": pr.get("title"),
                "tech": pr.get("tech_stack"),
            }
            for pr in probes[:50]
        ],
    }

    user_message = (
        f"Please analyze these reconnaissance findings for engagement '{scope_name}'.\n"
        f"Identify the top {top_n} highest-priority targets or findings for manual review.\n"
    )
    if focus:
        user_message += f"Specific focus requested by operator: {focus}\n"
    user_message += (
        f"\nReconnaissance Data:\n```json\n{json.dumps(user_payload, indent=2)}\n```"
    )

    client = anthropic.Anthropic(api_key=api_key)

    response = client.messages.create(
        model=model,
        max_tokens=cfg.ai.max_tokens or 4096,
        temperature=cfg.ai.temperature or 0.2,
        system=TRIAGE_SYSTEM_PROMPT,
        messages=[{"role": "user", "content": user_message}],
    )

    ai_text = (
        response.content[0].text
        if response.content
        else "No response returned from AI."
    )

    # Save to triage_runs database table
    run_id = add_triage_run(
        scope_name=scope_name,
        mode="ai",
        raw_findings_sent=json.dumps(user_payload),
        ai_response=ai_text,
        focus=focus,
        top_n=top_n,
        db_path=db_path,
    )

    log_audit(
        action="triage.ai_run",
        target=scope_name,
        details={"run_id": run_id, "model": model, "focus": focus, "top_n": top_n},
    )

    return {
        "run_id": run_id,
        "scope_name": scope_name,
        "mode": "ai",
        "model": model,
        "focus": focus,
        "summary_text": ai_text,
    }


# ==============================================================================
# Main Triage Entry Point
# ==============================================================================


def triage_scope(
    scope_name: str,
    top_n: int = 10,
    focus: str = "",
    use_ai: bool = True,
    db_path: str | Path | None = None,
) -> dict[str, Any]:
    """Triages a scope using AI when configured, gracefully falling back to rules-based.

    Args:
        scope_name: Validated engagement scope.
        top_n: Maximum number of prioritized targets to return.
        focus: Optional domain/keyword focus query.
        use_ai: Whether to use Claude API if API key is present.
        db_path: Optional custom SQLite database path.

    Returns:
        Structured result dictionary containing run metadata and summary.
    """
    # Scope validation
    ScopeChecker.from_name(scope_name)

    api_key = _get_api_key() if use_ai else ""

    if api_key:
        try:
            return run_ai_triage(
                scope_name=scope_name,
                api_key=api_key,
                top_n=top_n,
                focus=focus,
                db_path=db_path,
            )
        except Exception as exc:
            logger.warning(
                "AI triage invocation failed (%s). Falling back to rules-based triage.",
                exc,
            )
            # Graceful degradation if AI API fails or network issue occurs
            res = run_rules_triage(
                scope_name=scope_name, top_n=top_n, focus=focus, db_path=db_path
            )
            res["ai_error"] = str(exc)
            return res
    else:
        # Rules-based fallback
        return run_rules_triage(
            scope_name=scope_name, top_n=top_n, focus=focus, db_path=db_path
        )


def get_triage_history(
    scope_name: str, limit: int = 50, db_path: str | Path | None = None
) -> list[dict[str, Any]]:
    """Retrieves previous triage runs for a scope."""
    return list_triage_runs(scope_name=scope_name, limit=limit, db_path=db_path)


def get_triage_detail(
    run_id: int, db_path: str | Path | None = None
) -> dict[str, Any] | None:
    """Retrieves full details for a past triage run."""
    return get_triage_run(run_id=run_id, db_path=db_path)


# Backwards compatibility stub for phase 1
@require_in_scope
def triage_finding(
    target: str,
    finding_type: str,
    raw_evidence: str | dict[str, Any],
    scope: str | ScopeChecker | None = None,
) -> dict[str, Any]:
    """Legacy helper for single finding triage."""
    normalized_target = require_in_scope(target, scope=scope)
    log_audit(
        action="triage.evaluate",
        target=normalized_target,
        details={"finding_type": finding_type},
    )
    return {
        "target": normalized_target,
        "phase": 3,
        "finding_type": finding_type,
        "severity": "info",
        "score": 0.0,
        "remediation": "Use 'reconcopilot triage run' for comprehensive scope triage.",
    }

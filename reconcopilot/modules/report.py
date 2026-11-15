"""Phase 5 Module: Security assessment and reconnaissance report generation.

Aggregates verified findings, scope rules, and reconnaissance metrics from SQLite,
generating polished executive and technical reports in Markdown, HTML, and JSON formats.
"""

from __future__ import annotations

import html
import json
import logging
import os
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import yaml

from reconcopilot.audit import log_audit
from reconcopilot.config import load_config
from reconcopilot.db import get_recon_summary, list_findings
from reconcopilot.scope import ScopeChecker

logger = logging.getLogger(__name__)

SEVERITY_ORDER = ["critical", "high", "medium", "low", "info"]


def _get_api_key() -> str:
    """Retrieves the Anthropic API key from configuration or environment."""
    cfg = load_config()
    key = cfg.ai.api_key or os.getenv("ANTHROPIC_API_KEY") or ""
    return key.strip()


def gather_report_data(
    scope_name: str, db_path: str | Path | None = None
) -> dict[str, Any]:
    """Collects all scope metadata, verified findings, and recon stats for reporting."""
    scope = ScopeChecker.from_name(scope_name)
    findings = list_findings(scope=scope_name, db_path=db_path)
    recon_summary = get_recon_summary(scope_name=scope_name, db_path=db_path)

    # Sort findings: critical -> high -> medium -> low -> info
    def severity_rank(f: dict[str, Any]) -> int:
        sev = f.get("severity", "info").lower()
        return SEVERITY_ORDER.index(sev) if sev in SEVERITY_ORDER else 99

    findings.sort(key=severity_rank)

    # Severity distribution
    sev_counts: dict[str, int] = {s: 0 for s in SEVERITY_ORDER}
    status_counts: dict[str, int] = {}
    for f in findings:
        sev = f.get("severity", "info").lower()
        if sev in sev_counts:
            sev_counts[sev] += 1
        stat = f.get("status", "open").lower()
        status_counts[stat] = status_counts.get(stat, 0) + 1

    # Overall risk posture calculation
    if sev_counts["critical"] > 0:
        overall_risk = "CRITICAL"
    elif sev_counts["high"] > 0:
        overall_risk = "HIGH"
    elif sev_counts["medium"] > 0:
        overall_risk = "MEDIUM"
    elif sev_counts["low"] > 0:
        overall_risk = "LOW"
    else:
        overall_risk = "INFORMATIONAL"

    return {
        "scope_name": scope_name,
        "scope": scope,
        "generated_at": datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC"),
        "date_slug": datetime.now(timezone.utc).strftime("%Y%m%d"),
        "overall_risk": overall_risk,
        "findings": findings,
        "severity_counts": sev_counts,
        "status_counts": status_counts,
        "total_findings": len(findings),
        "recon_summary": recon_summary,
    }


# ==============================================================================
# Markdown Report Generation
# ==============================================================================


def render_markdown_report(
    data: dict[str, Any],
    executive_summary_override: str | None = None,
    polished_descriptions: dict[int, str] | None = None,
    polished_impacts: dict[int, str] | None = None,
) -> str:
    """Renders a comprehensive, publication-ready security report in Markdown."""
    scope_name = data["scope_name"]
    scope: ScopeChecker = data["scope"]
    findings: list[dict[str, Any]] = data["findings"]
    sev_counts = data["severity_counts"]
    recon_summary = data["recon_summary"]
    polished_descriptions = polished_descriptions or {}
    polished_impacts = polished_impacts or {}

    lines: list[str] = [
        f"# Security Assessment & Reconnaissance Report: {scope_name}",
        "",
        f"**Generated**: {data['generated_at']}  ",
        f"**Target Scope**: `{scope_name}`  ",
        f"**Overall Posture**: **{data['overall_risk']}**  ",
        f"**Total Verified Findings**: {data['total_findings']}  ",
        "",
        "---",
        "",
        "## 1. Executive Summary",
        "",
    ]

    # Executive Summary prose
    if executive_summary_override and executive_summary_override.strip():
        lines.append(executive_summary_override.strip())
    else:
        lines.extend(
            [
                f"This report documents the security assessment and reconnaissance findings for the authorized `{scope_name}` engagement. "
                f"During the assessment, an attack surface analysis identified **{recon_summary['total_assets']} assets**, "
                f"**{recon_summary['total_http_probes']} live HTTP services**, and **{recon_summary['total_open_ports']} open ports**. "
                f"Subsequent manual verification identified **{data['total_findings']} confirmed findings**, with an overall risk rating of **{data['overall_risk']}**.",
                "",
                "### Finding Breakdown by Severity",
                "",
                "| Severity | Count |",
                "| :--- | :--- |",
                f"| 🔴 **Critical** | {sev_counts['critical']} |",
                f"| 🟠 **High** | {sev_counts['high']} |",
                f"| 🟡 **Medium** | {sev_counts['medium']} |",
                f"| 🔵 **Low** | {sev_counts['low']} |",
                f"| ⚪ **Informational** | {sev_counts['info']} |",
            ]
        )

    lines.extend(
        [
            "",
            "---",
            "",
            "## 2. Scope & Engagement Methodology",
            "",
            "### In-Scope Boundaries",
            "- **Target Domains**: "
            + (
                ", ".join(f"`{d}`" for d in scope.domains)
                if scope.domains
                else "*None explicitly specified*"
            ),
            "- **Target IP Ranges**: "
            + (
                ", ".join(f"`{r}`" for r in scope.ip_ranges)
                if scope.ip_ranges
                else "*None explicitly specified*"
            ),
            "- **Explicit Exclusions**: "
            + (
                ", ".join(f"`{e}`" for e in scope.exclusions)
                if scope.exclusions
                else "*None*"
            ),
        ]
    )

    if scope.metadata:
        lines.append("")
        lines.append("### Engagement Metadata")
        for k, v in scope.metadata.items():
            lines.append(f"- **{k.replace('_', ' ').title()}**: {v}")

    lines.extend(
        [
            "",
            "### Methodology Overview",
            "The assessment followed a structured, authorized security workflow:",
            "1. **Reconnaissance & Asset Discovery**: Passive subdomain enumeration and DNS discovery.",
            "2. **Host Probing & Port Profiling**: Identification of active web endpoints and running service ports.",
            "3. **Triage & Vulnerability Identification**: Evaluation of potential attack surface vectors.",
            "4. **Manual Verification**: Systematic verification of security issues to confirm reproducibility and eliminate false positives.",
            "",
            "---",
            "",
            "## 3. Verified Findings Summary",
            "",
        ]
    )

    if not findings:
        lines.append("*No confirmed findings were recorded for this scope.*")
    else:
        lines.extend(
            [
                "| ID | Severity | Status | Finding Title | Affected Asset | CVSS |",
                "| :---: | :--- | :--- | :--- | :--- | :---: |",
            ]
        )
        for f in findings:
            cvss = (
                f"{f['cvss_score']:.1f}" if f.get("cvss_score") is not None else "N/A"
            )
            lines.append(
                f"| #{f['id']} | **{f['severity'].upper()}** | `{f['status'].upper()}` | {f['title']} | `{f['affected_asset']}` | {cvss} |"
            )

    lines.extend(
        [
            "",
            "---",
            "",
            "## 4. Detailed Findings",
            "",
        ]
    )

    if not findings:
        lines.append("*No detailed findings to report.*")
    else:
        for idx, f in enumerate(findings, start=1):
            fid = f["id"]
            cvss = (
                f"{f['cvss_score']:.1f}"
                if f.get("cvss_score") is not None
                else "Not assigned"
            )
            desc = (
                polished_descriptions.get(fid)
                or f.get("description")
                or "*No description provided.*"
            )
            imp = (
                polished_impacts.get(fid)
                or f.get("impact")
                or "*No impact statement provided.*"
            )
            repro = (
                f.get("reproduction_steps")
                or "*No specific reproduction steps documented.*"
            )
            remed = (
                f.get("remediation") or "*No specific remediation guidance documented.*"
            )

            lines.extend(
                [
                    f"### 4.{idx}. [{f['severity'].upper()}] {f['title']}",
                    "",
                    f"- **Finding ID**: `#{f['id']}`",
                    f"- **Severity**: `{f['severity'].upper()}`",
                    f"- **Status**: `{f['status'].upper()}`",
                    f"- **CVSS v3.1 Score**: `{cvss}`",
                    f"- **Affected Asset**: `{f['affected_asset']}`",
                    f"- **First Reported**: `{f.get('created_at', 'N/A')}`",
                    f"- **Last Updated**: `{f.get('updated_at', 'N/A')}`",
                    "",
                    "#### Description",
                    desc.strip(),
                    "",
                    "#### Impact",
                    imp.strip(),
                    "",
                    "#### Reproduction Steps",
                    repro.strip(),
                    "",
                    "#### Remediation Guidance",
                    remed.strip(),
                    "",
                    "---",
                    "",
                ]
            )

    lines.extend(
        [
            "## 5. Strategic Recommendations",
            "",
            "1. **Triage Critical & High Issues First**: Remediate all vulnerabilities rated Critical and High immediately to reduce high-exposure risks.",
            "2. **Implement Defense in Depth**: Enforce strict server-side authorization boundaries, input sanitization, and output encoding across all endpoints.",
            "3. **Minimize Attack Surface**: Restrict sensitive services (e.g. database ports, admin portals) to internal VPNs or trusted bastion hosts.",
            "4. **Re-Test & Verify**: Conduct follow-up verification testing once fixes are deployed to ensure vulnerabilities are properly resolved.",
            "",
            "*Report generated automatically by ReconCopilot.*",
        ]
    )

    return "\n".join(lines)


# ==============================================================================
# HTML Report Generation
# ==============================================================================


HTML_TEMPLATE = """<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <title>Security Assessment Report: {scope_name}</title>
  <style>
    body {{
      font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
      line-height: 1.6;
      color: #24292e;
      background: #f6f8fa;
      margin: 0;
      padding: 40px 20px;
    }}
    .container {{
      max-width: 960px;
      margin: 0 auto;
      background: #ffffff;
      padding: 40px;
      border-radius: 8px;
      box-shadow: 0 1px 3px rgba(0,0,0,0.12);
    }}
    h1 {{ border-bottom: 2px solid #eaecef; padding-bottom: 12px; color: #1b1f23; }}
    h2 {{ border-bottom: 1px solid #eaecef; padding-bottom: 8px; margin-top: 32px; color: #24292e; }}
    h3 {{ margin-top: 24px; color: #24292e; }}
    table {{
      width: 100%;
      border-collapse: collapse;
      margin: 16px 0;
    }}
    th, td {{
      padding: 10px 12px;
      border: 1px solid #dfe2e5;
      text-align: left;
    }}
    th {{ background: #f6f8fa; font-weight: 600; }}
    .badge {{
      display: inline-block;
      padding: 3px 8px;
      font-size: 12px;
      font-weight: 600;
      border-radius: 4px;
      text-transform: uppercase;
    }}
    .badge-critical {{ background: #ff4d4f; color: white; }}
    .badge-high {{ background: #ff7a45; color: white; }}
    .badge-medium {{ background: #ffa940; color: white; }}
    .badge-low {{ background: #36cfc9; color: white; }}
    .badge-info {{ background: #8c8c8c; color: white; }}
    .badge-fixed {{ background: #52c41a; color: white; }}
    .badge-open {{ background: #faad14; color: white; }}
    code {{ background: #f3f4f6; padding: 2px 6px; border-radius: 4px; font-family: monospace; font-size: 90%; }}
    pre {{ background: #f6f8fa; padding: 16px; border-radius: 6px; overflow-x: auto; }}
    .finding-card {{
      border: 1px solid #e1e4e8;
      border-radius: 6px;
      padding: 20px;
      margin-bottom: 24px;
      background: #fafbfc;
    }}
  </style>
</head>
<body>
  <div class="container">
    <h1>Security Assessment Report: {scope_name}</h1>
    <p><strong>Generated:</strong> {generated_at} | <strong>Overall Risk:</strong> <span class="badge badge-{risk_class}">{overall_risk}</span></p>

    <h2>1. Executive Summary</h2>
    <div>{executive_summary}</div>

    <h2>2. Findings Summary</h2>
    <table>
      <thead>
        <tr>
          <th>ID</th>
          <th>Severity</th>
          <th>Status</th>
          <th>Title</th>
          <th>Affected Asset</th>
          <th>CVSS</th>
        </tr>
      </thead>
      <tbody>
        {table_rows}
      </tbody>
    </table>

    <h2>3. Detailed Findings</h2>
    {detailed_findings}

    <h2>4. Strategic Recommendations</h2>
    <ul>
      <li><strong>Triage Critical & High Issues First:</strong> Remediate identified critical and high vulnerabilities as top priority.</li>
      <li><strong>Enforce Defense in Depth:</strong> Ensure robust input sanitization, output encoding, and authorization controls across all application tiers.</li>
      <li><strong>Reduce Exposure:</strong> Restrict management and database ports to authorized administrative networks.</li>
      <li><strong>Follow-Up Re-Testing:</strong> Verify all remediation implementations to validate threat elimination.</li>
    </ul>
  </div>
</body>
</html>
"""


def render_html_report(
    data: dict[str, Any],
    executive_summary_override: str | None = None,
    polished_descriptions: dict[int, str] | None = None,
    polished_impacts: dict[int, str] | None = None,
) -> str:
    """Renders a styled standalone HTML security report."""
    scope_name = html.escape(data["scope_name"])
    overall_risk = data["overall_risk"]
    risk_class = overall_risk.lower()
    findings = data["findings"]
    polished_descriptions = polished_descriptions or {}
    polished_impacts = polished_impacts or {}

    exec_summary = (
        html.escape(executive_summary_override)
        if executive_summary_override
        else f"<p>This report presents findings for the <code>{scope_name}</code> security assessment. A total of <strong>{data['total_findings']} confirmed findings</strong> were documented, resulting in an overall risk assessment of <strong>{overall_risk}</strong>.</p>"
    )

    table_rows = []
    if not findings:
        table_rows.append(
            "<tr><td colspan='6'><em>No confirmed findings recorded.</em></td></tr>"
        )
    else:
        for f in findings:
            sev = f["severity"].lower()
            stat = f["status"].lower()
            cvss = (
                f"{f['cvss_score']:.1f}" if f.get("cvss_score") is not None else "N/A"
            )
            row = (
                f"<tr>"
                f"<td>#{f['id']}</td>"
                f"<td><span class='badge badge-{sev}'>{sev}</span></td>"
                f"<td><span class='badge badge-{stat}'>{stat}</span></td>"
                f"<td><strong>{html.escape(f['title'])}</strong></td>"
                f"<td><code>{html.escape(f['affected_asset'])}</code></td>"
                f"<td>{cvss}</td>"
                f"</tr>"
            )
            table_rows.append(row)

    cards = []
    if not findings:
        cards.append("<p><em>No detailed findings to report.</em></p>")
    else:
        for f in findings:
            fid = f["id"]
            sev = f["severity"].lower()
            stat = f["status"].lower()
            cvss = (
                f"{f['cvss_score']:.1f}" if f.get("cvss_score") is not None else "N/A"
            )
            desc = (
                polished_descriptions.get(fid)
                or f.get("description")
                or "No description provided."
            )
            imp = (
                polished_impacts.get(fid)
                or f.get("impact")
                or "No impact statement provided."
            )
            repro = (
                f.get("reproduction_steps")
                or "No specific reproduction steps documented."
            )
            remed = (
                f.get("remediation") or "No specific remediation guidance documented."
            )

            card = f"""
            <div class="finding-card">
              <h3>#{f["id"]}: {html.escape(f["title"])}</h3>
              <p>
                <strong>Severity:</strong> <span class="badge badge-{sev}">{sev}</span> |
                <strong>Status:</strong> <span class="badge badge-{stat}">{stat}</span> |
                <strong>CVSS:</strong> {cvss} |
                <strong>Asset:</strong> <code>{html.escape(f["affected_asset"])}</code>
              </p>
              <h4>Description</h4>
              <p>{html.escape(desc)}</p>
              <h4>Impact</h4>
              <p>{html.escape(imp)}</p>
              <h4>Reproduction Steps</h4>
              <pre>{html.escape(repro)}</pre>
              <h4>Remediation</h4>
              <p>{html.escape(remed)}</p>
            </div>
            """
            cards.append(card)

    return HTML_TEMPLATE.format(
        scope_name=scope_name,
        generated_at=data["generated_at"],
        overall_risk=overall_risk,
        risk_class=risk_class,
        executive_summary=exec_summary,
        table_rows="\n".join(table_rows),
        detailed_findings="\n".join(cards),
    )


# ==============================================================================
# AI Prose Refinement
# ==============================================================================


AI_REPORT_PROMPT = """You are ReconCopilot, an expert cybersecurity technical editor.
Your objective is to draft a cohesive Executive Summary and polish the prose of the description and impact statements for confirmed security findings.

CRITICAL EDITORIAL AND SAFETY CONSTRAINTS:
1. You must NEVER fabricate, invent, or add new vulnerabilities, technical claims, or targets.
2. All factual content (severity, affected assets, reproduction steps, technical facts) must remain exactly as given. Your job is writing quality, clarity, and executive readiness.
3. Return valid JSON only, conforming to this schema:
{
  "executive_summary": "Drafted 2-3 paragraph professional executive summary...",
  "polished_findings": [
    {
      "id": 1,
      "polished_description": "Clear and professional prose description...",
      "polished_impact": "Refined impact statement..."
    }
  ]
}
"""


def ai_polish_report(
    data: dict[str, Any],
    api_key: str,
) -> dict[str, Any]:
    """Uses Claude API to polish the report's executive summary and finding prose."""
    import anthropic

    cfg = load_config()
    model = cfg.ai.model or "claude-sonnet-4-6"

    findings_summary = [
        {
            "id": f["id"],
            "title": f["title"],
            "severity": f["severity"],
            "affected_asset": f["affected_asset"],
            "raw_description": f.get("description", ""),
            "raw_impact": f.get("impact", ""),
        }
        for f in data["findings"]
    ]

    payload = {
        "scope_name": data["scope_name"],
        "overall_risk": data["overall_risk"],
        "total_findings": data["total_findings"],
        "severity_counts": data["severity_counts"],
        "findings": findings_summary,
    }

    client = anthropic.Anthropic(api_key=api_key)
    response = client.messages.create(
        model=model,
        max_tokens=cfg.ai.max_tokens or 4096,
        system=AI_REPORT_PROMPT,
        messages=[
            {
                "role": "user",
                "content": f"Please draft the executive summary and polish the prose for these assessment findings:\n```json\n{json.dumps(payload, indent=2)}\n```",
            }
        ],
    )

    response_text = response.content[0].text if response.content else "{}"

    # Extract JSON from code blocks if present
    if "```json" in response_text:
        response_text = response_text.split("```json")[-1].split("```")[0].strip()
    elif "```" in response_text:
        response_text = response_text.split("```")[-1].split("```")[0].strip()

    try:
        parsed = json.loads(response_text)
        exec_summary = parsed.get("executive_summary")
        polished_desc = {
            item["id"]: item.get("polished_description")
            for item in parsed.get("polished_findings", [])
        }
        polished_imp = {
            item["id"]: item.get("polished_impact")
            for item in parsed.get("polished_findings", [])
        }
        return {
            "executive_summary": exec_summary,
            "polished_descriptions": polished_desc,
            "polished_impacts": polished_imp,
        }
    except Exception as exc:
        logger.warning(
            "Failed to parse AI report polish JSON (%s). Using template prose.", exc
        )
        return {}


# ==============================================================================
# Main Report Generation Entry Point
# ==============================================================================


def resolve_report_output_path(
    scope_name: str,
    output_format: str,
    output_path: str | Path | None = None,
) -> Path:
    """Determines destination file path for report."""
    if output_path:
        p = Path(output_path).expanduser().resolve()
        p.parent.mkdir(parents=True, exist_ok=True)
        return p

    cfg = load_config()
    out_dir_str = cfg.get("report", {}).get("output_dir", "./output/reports")
    out_dir = Path(out_dir_str).expanduser().resolve()
    out_dir.mkdir(parents=True, exist_ok=True)

    date_str = datetime.now(timezone.utc).strftime("%Y%m%d")
    ext_map = {
        "markdown": "md",
        "html": "html",
        "json": "json",
        "yaml": "yaml",
        "yml": "yaml",
    }
    ext = ext_map.get(output_format.lower(), "md")

    filename = f"report_{scope_name}_{date_str}.{ext}"
    return out_dir / filename


def generate_report(
    scope_name: str,
    output_format: str = "markdown",
    output_path: str | Path | None = None,
    use_ai: bool = True,
    db_path: str | Path | None = None,
) -> dict[str, Any]:
    """Generates an assessment report for a scope and saves it to a file.

    Args:
        scope_name: Scope name.
        output_format: 'markdown', 'html', 'json', or 'yaml'.
        output_path: Optional explicit output file path.
        use_ai: Whether to polish report prose using Claude if API key is present.
        db_path: Optional SQLite database path.

    Returns:
        Metadata dict with file_path, format, findings_count, and mode.
    """
    clean_format = output_format.strip().lower()
    if clean_format in ("md", "markdown"):
        clean_format = "markdown"
    elif clean_format == "html":
        clean_format = "html"
    elif clean_format == "json":
        clean_format = "json"
    elif clean_format in ("yaml", "yml"):
        clean_format = "yaml"
    else:
        raise ValueError(
            f"Unsupported format '{output_format}'. Must be one of: markdown, html, json, yaml"
        )

    data = gather_report_data(scope_name=scope_name, db_path=db_path)
    api_key = _get_api_key() if use_ai else ""

    exec_summary = None
    polished_desc = {}
    polished_imp = {}
    mode = "template"

    if api_key and clean_format in ("markdown", "html") and data["findings"]:
        try:
            ai_data = ai_polish_report(data=data, api_key=api_key)
            exec_summary = ai_data.get("executive_summary")
            polished_desc = ai_data.get("polished_descriptions", {})
            polished_imp = ai_data.get("polished_impacts", {})
            mode = "ai"
        except Exception as exc:
            logger.warning(
                "AI report polish failed (%s). Falling back to template.", exc
            )
            mode = "template"

    # Render content according to format
    if clean_format == "json":
        # Export structured JSON payload
        export_payload = {
            "report_metadata": {
                "scope_name": scope_name,
                "generated_at": data["generated_at"],
                "overall_risk": data["overall_risk"],
                "total_findings": data["total_findings"],
                "severity_counts": data["severity_counts"],
            },
            "findings": data["findings"],
            "recon_summary": data["recon_summary"],
        }
        content = json.dumps(export_payload, indent=2)
    elif clean_format == "yaml":
        # Export structured YAML payload
        export_payload = {
            "report_metadata": {
                "scope_name": scope_name,
                "generated_at": data["generated_at"],
                "overall_risk": data["overall_risk"],
                "total_findings": data["total_findings"],
                "severity_counts": data["severity_counts"],
            },
            "findings": data["findings"],
            "recon_summary": data["recon_summary"],
        }
        content = yaml.dump(export_payload, sort_keys=False)
    elif clean_format == "html":
        content = render_html_report(
            data=data,
            executive_summary_override=exec_summary,
            polished_descriptions=polished_desc,
            polished_impacts=polished_imp,
        )
    else:
        # Default: Markdown
        content = render_markdown_report(
            data=data,
            executive_summary_override=exec_summary,
            polished_descriptions=polished_desc,
            polished_impacts=polished_imp,
        )

    dest_file = resolve_report_output_path(
        scope_name=scope_name,
        output_format=clean_format,
        output_path=output_path,
    )

    dest_file.write_text(content, encoding="utf-8")

    log_audit(
        action="report.generate",
        target=scope_name,
        details={
            "file": str(dest_file),
            "format": clean_format,
            "mode": mode,
            "findings_count": data["total_findings"],
        },
    )

    return {
        "scope_name": scope_name,
        "file_path": dest_file,
        "format": clean_format,
        "findings_count": data["total_findings"],
        "mode": mode,
        "content_length": len(content),
    }

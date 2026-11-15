"""Phase 4 Module: Manual tracking and management of confirmed security findings.

Maintains manually verified findings (distinct from automated scanner findings),
enforcing scope authorization, audit logging, and lifecycle status tracking.
"""

from __future__ import annotations

import json
import logging
from pathlib import Path
from typing import Any

from reconcopilot.audit import log_audit
from reconcopilot.db import (
    add_finding as db_add_finding,
)
from reconcopilot.db import (
    delete_finding as db_delete_finding,
)
from reconcopilot.db import (
    get_finding as db_get_finding,
)
from reconcopilot.db import (
    list_findings as db_list_findings,
)
from reconcopilot.db import (
    update_finding as db_update_finding,
)
from reconcopilot.scope import ScopeChecker, require_in_scope

logger = logging.getLogger(__name__)

VALID_SEVERITIES = ("critical", "high", "medium", "low", "info")
VALID_STATUSES = ("open", "fixed", "accepted-risk", "duplicate", "not-applicable")


def validate_severity(severity: str) -> str:
    """Validates and normalizes severity level."""
    cleaned = severity.strip().lower()
    if cleaned not in VALID_SEVERITIES:
        raise ValueError(
            f"Invalid severity '{severity}'. Must be one of: {', '.join(VALID_SEVERITIES)}"
        )
    return cleaned


def validate_status(status: str) -> str:
    """Validates and normalizes finding status."""
    cleaned = status.strip().lower()
    if cleaned not in VALID_STATUSES:
        raise ValueError(
            f"Invalid status '{status}'. Must be one of: {', '.join(VALID_STATUSES)}"
        )
    return cleaned


def validate_cvss(cvss: float | str | None) -> float | None:
    """Validates CVSS score is between 0.0 and 10.0."""
    if cvss is None or str(cvss).strip() == "":
        return None
    try:
        val = float(cvss)
        if not (0.0 <= val <= 10.0):
            raise ValueError(f"CVSS score must be between 0.0 and 10.0, got {val}")
        return val
    except ValueError as exc:
        raise ValueError(f"Invalid CVSS score '{cvss}': {exc}")


def create_finding(
    scope: str,
    title: str,
    severity: str,
    affected_asset: str,
    description: str = "",
    impact: str = "",
    reproduction_steps: str = "",
    remediation: str = "",
    cvss_score: float | str | None = None,
    status: str = "open",
    db_path: str | Path | None = None,
) -> dict[str, Any]:
    """Records a verified security finding after checking scope authorization.

    Raises:
        ScopeViolationError: If affected_asset is out of scope.
        ValueError: If validation fails for severity, status, or CVSS score.
    """
    clean_scope = scope.strip()
    clean_title = title.strip()
    if not clean_title:
        raise ValueError("Finding title cannot be empty.")

    # Validate scope exists and affected_asset is in scope
    ScopeChecker.from_name(clean_scope)
    normalized_asset = require_in_scope(affected_asset, scope=clean_scope)

    norm_severity = validate_severity(severity)
    norm_status = validate_status(status)
    norm_cvss = validate_cvss(cvss_score)

    finding_id = db_add_finding(
        scope=clean_scope,
        title=clean_title,
        severity=norm_severity,
        status=norm_status,
        affected_asset=normalized_asset,
        description=description,
        impact=impact,
        reproduction_steps=reproduction_steps,
        remediation=remediation,
        cvss_score=norm_cvss,
        db_path=db_path,
    )

    log_audit(
        action="finding.create",
        target=normalized_asset,
        details={
            "finding_id": finding_id,
            "scope": clean_scope,
            "title": clean_title,
            "severity": norm_severity,
            "status": norm_status,
        },
    )

    record = db_get_finding(finding_id, db_path=db_path)
    return record or {}


def get_finding(
    finding_id: int, db_path: str | Path | None = None
) -> dict[str, Any] | None:
    """Retrieves finding details by ID."""
    return db_get_finding(finding_id, db_path=db_path)


def list_findings(
    scope: str,
    severity: str | None = None,
    status: str | None = None,
    db_path: str | Path | None = None,
) -> list[dict[str, Any]]:
    """Lists findings for a scope, with optional severity and status filters."""
    ScopeChecker.from_name(scope)

    sev = validate_severity(severity) if severity else None
    stat = validate_status(status) if status else None

    return db_list_findings(
        scope=scope,
        severity=sev,
        status=stat,
        db_path=db_path,
    )


def update_finding_status(
    finding_id: int,
    status: str,
    db_path: str | Path | None = None,
) -> dict[str, Any]:
    """Updates the lifecycle status of a finding."""
    norm_status = validate_status(status)
    existing = db_get_finding(finding_id, db_path=db_path)
    if not existing:
        raise KeyError(f"Finding with ID {finding_id} does not exist.")

    db_update_finding(finding_id=finding_id, status=norm_status, db_path=db_path)

    log_audit(
        action="finding.update_status",
        target=f"finding:{finding_id}",
        details={
            "old_status": existing.get("status"),
            "new_status": norm_status,
            "scope": existing.get("scope"),
        },
    )

    updated = db_get_finding(finding_id, db_path=db_path)
    return updated or {}


def update_finding(
    finding_id: int,
    status: str | None = None,
    title: str | None = None,
    severity: str | None = None,
    affected_asset: str | None = None,
    description: str | None = None,
    impact: str | None = None,
    reproduction_steps: str | None = None,
    remediation: str | None = None,
    cvss_score: float | str | None = None,
    db_path: str | Path | None = None,
) -> dict[str, Any]:
    """Updates one or more fields of an existing finding."""
    existing = db_get_finding(finding_id, db_path=db_path)
    if not existing:
        raise KeyError(f"Finding with ID {finding_id} does not exist.")

    norm_status = validate_status(status) if status else None
    norm_sev = validate_severity(severity) if severity else None
    norm_cvss = validate_cvss(cvss_score) if cvss_score is not None else None

    norm_asset = None
    if affected_asset:
        norm_asset = require_in_scope(affected_asset, scope=existing["scope"])

    db_update_finding(
        finding_id=finding_id,
        status=norm_status,
        title=title,
        severity=norm_sev,
        affected_asset=norm_asset,
        description=description,
        impact=impact,
        reproduction_steps=reproduction_steps,
        remediation=remediation,
        cvss_score=norm_cvss,
        db_path=db_path,
    )

    log_audit(
        action="finding.update",
        target=f"finding:{finding_id}",
        details={"updated_fields": [k for k, v in locals().items() if v is not None]},
    )

    updated = db_get_finding(finding_id, db_path=db_path)
    return updated or {}


def delete_finding(finding_id: int, db_path: str | Path | None = None) -> bool:
    """Deletes a finding by ID."""
    existing = db_get_finding(finding_id, db_path=db_path)
    if not existing:
        return False

    success = db_delete_finding(finding_id, db_path=db_path)
    if success:
        log_audit(
            action="finding.delete",
            target=f"finding:{finding_id}",
            details={"scope": existing.get("scope"), "title": existing.get("title")},
        )
    return success


def export_findings(
    scope: str,
    export_format: str = "json",
    db_path: str | Path | None = None,
) -> str:
    """Exports all findings for a given scope as formatted JSON."""
    clean_format = export_format.strip().lower()
    if clean_format != "json":
        raise ValueError(
            f"Unsupported export format '{export_format}'. Supported: json"
        )

    findings = list_findings(scope=scope, db_path=db_path)
    export_payload = {
        "scope": scope.strip(),
        "total_findings": len(findings),
        "findings": findings,
    }
    return json.dumps(export_payload, indent=2)


# Backwards compatibility stub for phase 1
@require_in_scope
def track_asset_changes(
    target: str,
    scope: str | ScopeChecker | None = None,
) -> dict[str, Any]:
    """Legacy asset diff tracking helper."""
    normalized_target = require_in_scope(target, scope=scope)
    log_audit(
        action="tracking.diff",
        target=normalized_target,
        details={"status": "stub_executed"},
    )
    return {
        "target": normalized_target,
        "phase": 4,
        "new_assets": [],
        "removed_assets": [],
        "state_changes": [],
    }

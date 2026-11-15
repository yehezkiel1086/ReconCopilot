"""Phase 2 Module: Reconnaissance engine and asset discovery."""

from __future__ import annotations

from typing import Any

from reconcopilot.audit import log_audit
from reconcopilot.scope import ScopeChecker, require_in_scope


@require_in_scope
def run_recon(
    target: str,
    passive_only: bool = True,
    scope: str | ScopeChecker | None = None,
) -> dict[str, Any]:
    """Runs reconnaissance against an authorized target.

    Args:
        target: Host, domain, or IP.
        passive_only: Whether to restrict to passive sources.
        scope: Optional scope name or ScopeChecker instance.

    Returns:
        Discovered asset and service metadata.

    Raises:
        ScopeViolationError: If target is not authorized in scope.
    """
    normalized_target = require_in_scope(target, scope=scope)

    log_audit(
        action="recon.execute",
        target=normalized_target,
        details={"passive_only": passive_only, "status": "stub_executed"},
    )

    return {
        "target": normalized_target,
        "phase": 2,
        "status": "planned",
        "passive_only": passive_only,
        "results": [],
    }

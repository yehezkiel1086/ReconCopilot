"""Audit logging for ReconCopilot actions and compliance tracking."""

from __future__ import annotations

import json
import threading
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from reconcopilot.config import load_config
from reconcopilot.db import record_audit_log

_FILE_LOCK = threading.Lock()


def resolve_audit_log_path(path_str: str | Path | None = None) -> Path:
    """Resolves the audit log file path, ensuring parent directory exists."""
    if path_str is None:
        cfg = load_config()
        path_str = cfg.audit.log_file

    p = Path(path_str).expanduser().resolve()
    p.parent.mkdir(parents=True, exist_ok=True)
    return p


def log_audit(
    action: str,
    target: str = "",
    details: Any = "",
    log_file: str | Path | None = None,
    save_to_db: bool = True,
) -> dict[str, Any]:
    """Records an audit event to a local file and optionally the database.

    Args:
        action: Identifier for the action (e.g. 'recon.scan', 'scope.add_target').
        target: Target identifier or host associated with the action.
        details: Additional details (string, dict, or list).
        log_file: Optional path override for the log file.
        save_to_db: Whether to also record the event in the SQLite audit_log table.

    Returns:
        The audit entry dictionary.
    """
    cfg = load_config()
    if not cfg.audit.enabled:
        return {}

    ts = datetime.now(timezone.utc).isoformat()
    details_str = (
        json.dumps(details) if isinstance(details, (dict, list)) else str(details or "")
    )

    entry = {
        "timestamp": ts,
        "action": action,
        "target": target,
        "details": details_str,
    }

    # 1. Write to local file
    try:
        resolved_file = resolve_audit_log_path(log_file)
        with _FILE_LOCK:
            with open(resolved_file, "a", encoding="utf-8") as f:
                f.write(json.dumps(entry) + "\n")
    except Exception as exc:
        import sys

        print(f"Warning: Failed to write audit log to file: {exc}", file=sys.stderr)

    # 2. Write to SQLite database
    if save_to_db:
        try:
            record_audit_log(
                action=action,
                target=target,
                details=details_str,
                timestamp=ts,
            )
        except Exception as exc:
            import sys

            print(
                f"Warning: Failed to write audit log to database: {exc}",
                file=sys.stderr,
            )

    return entry


def read_file_audit_logs(
    log_file: str | Path | None = None,
    limit: int = 100,
) -> list[dict[str, Any]]:
    """Reads latest audit logs from local file."""
    p = resolve_audit_log_path(log_file)
    if not p.is_file():
        return []

    lines: list[dict[str, Any]] = []
    with _FILE_LOCK:
        with open(p, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if line:
                    try:
                        lines.append(json.loads(line))
                    except json.JSONDecodeError:
                        pass
    return lines[-limit:]

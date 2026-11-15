"""SQLite database schema and connection helpers for ReconCopilot."""

from __future__ import annotations

import sqlite3
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Generator

from reconcopilot.config import load_config

DEFAULT_SCHEMA = """
CREATE TABLE IF NOT EXISTS targets (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    scope_name TEXT NOT NULL,
    target TEXT NOT NULL,
    added_at TEXT NOT NULL,
    notes TEXT DEFAULT ''
);

CREATE INDEX IF NOT EXISTS idx_targets_scope ON targets(scope_name);
CREATE INDEX IF NOT EXISTS idx_targets_target ON targets(target);

CREATE TABLE IF NOT EXISTS audit_log (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp TEXT NOT NULL,
    action TEXT NOT NULL,
    target TEXT DEFAULT '',
    details TEXT DEFAULT ''
);

CREATE INDEX IF NOT EXISTS idx_audit_log_timestamp ON audit_log(timestamp);
CREATE INDEX IF NOT EXISTS idx_audit_log_action ON audit_log(action);

CREATE TABLE IF NOT EXISTS assets (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    scope_name TEXT NOT NULL,
    asset TEXT NOT NULL,
    source_tool TEXT DEFAULT '',
    discovered_at TEXT NOT NULL,
    raw_data TEXT DEFAULT '',
    UNIQUE(scope_name, asset)
);

CREATE INDEX IF NOT EXISTS idx_assets_scope ON assets(scope_name);
CREATE INDEX IF NOT EXISTS idx_assets_asset ON assets(asset);

CREATE TABLE IF NOT EXISTS http_probes (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    scope_name TEXT NOT NULL,
    url TEXT NOT NULL,
    host TEXT NOT NULL,
    status_code INTEGER,
    title TEXT DEFAULT '',
    tech_stack TEXT DEFAULT '',
    content_length INTEGER DEFAULT 0,
    probed_at TEXT NOT NULL,
    raw_data TEXT DEFAULT '',
    UNIQUE(scope_name, url)
);

CREATE INDEX IF NOT EXISTS idx_http_probes_scope ON http_probes(scope_name);
CREATE INDEX IF NOT EXISTS idx_http_probes_host ON http_probes(host);

CREATE TABLE IF NOT EXISTS nuclei_findings (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    scope_name TEXT NOT NULL,
    template_id TEXT NOT NULL,
    severity TEXT NOT NULL,
    matched_url TEXT NOT NULL,
    name TEXT DEFAULT '',
    found_at TEXT NOT NULL,
    raw_data TEXT DEFAULT ''
);

CREATE INDEX IF NOT EXISTS idx_nuclei_findings_scope ON nuclei_findings(scope_name);
CREATE INDEX IF NOT EXISTS idx_nuclei_findings_severity ON nuclei_findings(severity);

CREATE TABLE IF NOT EXISTS open_ports (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    scope_name TEXT NOT NULL,
    target TEXT NOT NULL,
    port INTEGER NOT NULL,
    protocol TEXT NOT NULL,
    state TEXT NOT NULL,
    service TEXT DEFAULT '',
    scanned_at TEXT NOT NULL,
    raw_data TEXT DEFAULT '',
    UNIQUE(scope_name, target, port, protocol)
);

CREATE INDEX IF NOT EXISTS idx_open_ports_scope ON open_ports(scope_name);
CREATE INDEX IF NOT EXISTS idx_open_ports_target ON open_ports(target);

CREATE TABLE IF NOT EXISTS triage_runs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    scope_name TEXT NOT NULL,
    timestamp TEXT NOT NULL,
    mode TEXT NOT NULL,
    raw_findings_sent TEXT NOT NULL,
    ai_response TEXT NOT NULL,
    focus TEXT DEFAULT '',
    top_n INTEGER DEFAULT 10
);

CREATE INDEX IF NOT EXISTS idx_triage_runs_scope ON triage_runs(scope_name);
CREATE INDEX IF NOT EXISTS idx_triage_runs_timestamp ON triage_runs(timestamp);
"""


def resolve_db_path(path_str: str | Path | None = None) -> Path | str:
    """Resolves database path, expanding home directory and creating parent folders.

    Args:
        path_str: Path string or Path object, or None to load from config.

    Returns:
        Path object pointing to the database file, or special string ':memory:'.
    """
    if path_str is None:
        cfg = load_config()
        path_str = cfg.database.path

    if str(path_str).strip() == ":memory:":
        return ":memory:"

    p = Path(path_str).expanduser().resolve()
    p.parent.mkdir(parents=True, exist_ok=True)
    return p


def get_connection(
    db_path: str | Path | None = None, timeout: float = 30.0
) -> sqlite3.Connection:
    """Creates and configures a SQLite connection.

    Args:
        db_path: Path to database or None.
        timeout: SQLite lock wait timeout in seconds.

    Returns:
        Configured sqlite3.Connection.
    """
    resolved = resolve_db_path(db_path)
    conn = sqlite3.connect(resolved, timeout=timeout)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON;")
    if resolved != ":memory:":
        conn.execute("PRAGMA journal_mode = WAL;")
    return conn


@contextmanager
def get_db(
    db_path: str | Path | None = None, timeout: float = 30.0
) -> Generator[sqlite3.Connection, None, None]:
    """Context manager for SQLite connections with auto-commit and cleanup."""
    conn = get_connection(db_path=db_path, timeout=timeout)
    try:
        yield conn
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()


def init_db(db_path: str | Path | None = None) -> Path | str:
    """Initializes the database schema if tables do not exist.

    Args:
        db_path: Database path or None to use configured path.

    Returns:
        The resolved database path.
    """
    resolved = resolve_db_path(db_path)
    with get_db(resolved) as conn:
        conn.executescript(DEFAULT_SCHEMA)
    return resolved


# ==============================================================================
# Targets Helpers
# ==============================================================================


def add_target(
    scope_name: str,
    target: str,
    notes: str = "",
    db_path: str | Path | None = None,
) -> int:
    """Adds a new target to the targets table.

    Returns:
        The newly created target id.
    """
    init_db(db_path)
    now = datetime.now(timezone.utc).isoformat()
    with get_db(db_path) as conn:
        cursor = conn.execute(
            """
            INSERT INTO targets (scope_name, target, added_at, notes)
            VALUES (?, ?, ?, ?)
            """,
            (scope_name.strip(), target.strip(), now, notes.strip()),
        )
        return int(cursor.lastrowid)


def list_targets(
    scope_name: str | None = None,
    db_path: str | Path | None = None,
) -> list[dict[str, Any]]:
    """Lists targets, optionally filtered by scope_name."""
    init_db(db_path)
    with get_db(db_path) as conn:
        if scope_name:
            cursor = conn.execute(
                "SELECT * FROM targets WHERE scope_name = ? ORDER BY id ASC",
                (scope_name,),
            )
        else:
            cursor = conn.execute("SELECT * FROM targets ORDER BY id ASC")
        return [dict(row) for row in cursor.fetchall()]


def get_target(
    target_id: int, db_path: str | Path | None = None
) -> dict[str, Any] | None:
    """Retrieves a single target by id."""
    init_db(db_path)
    with get_db(db_path) as conn:
        cursor = conn.execute("SELECT * FROM targets WHERE id = ?", (target_id,))
        row = cursor.fetchone()
        return dict(row) if row else None


def delete_target(target_id: int, db_path: str | Path | None = None) -> bool:
    """Deletes a target by id. Returns True if a record was deleted."""
    init_db(db_path)
    with get_db(db_path) as conn:
        cursor = conn.execute("DELETE FROM targets WHERE id = ?", (target_id,))
        return cursor.rowcount > 0


# ==============================================================================
# Audit Log Helpers
# ==============================================================================


def record_audit_log(
    action: str,
    target: str = "",
    details: str = "",
    timestamp: str | None = None,
    db_path: str | Path | None = None,
) -> int:
    """Inserts a record into the audit_log table.

    Returns:
        The newly created audit_log record id.
    """
    ts = timestamp or datetime.now(timezone.utc).isoformat()
    try:
        with get_db(db_path) as conn:
            cursor = conn.execute(
                """
                INSERT INTO audit_log (timestamp, action, target, details)
                VALUES (?, ?, ?, ?)
                """,
                (ts, action.strip(), target.strip(), details.strip()),
            )
            return int(cursor.lastrowid)
    except sqlite3.OperationalError as exc:
        if "no such table" in str(exc).lower():
            init_db(db_path)
            with get_db(db_path) as conn:
                cursor = conn.execute(
                    """
                    INSERT INTO audit_log (timestamp, action, target, details)
                    VALUES (?, ?, ?, ?)
                    """,
                    (ts, action.strip(), target.strip(), details.strip()),
                )
                return int(cursor.lastrowid)
        raise


def list_audit_logs(
    limit: int = 100,
    action: str | None = None,
    db_path: str | Path | None = None,
) -> list[dict[str, Any]]:
    """Retrieves audit logs in reverse chronological order."""
    init_db(db_path)
    with get_db(db_path) as conn:
        if action:
            cursor = conn.execute(
                """
                SELECT * FROM audit_log
                WHERE action = ?
                ORDER BY id DESC
                LIMIT ?
                """,
                (action, limit),
            )
        else:
            cursor = conn.execute(
                "SELECT * FROM audit_log ORDER BY id DESC LIMIT ?",
                (limit,),
            )
        return [dict(row) for row in cursor.fetchall()]


# ==============================================================================
# Recon Tables Helpers
# ==============================================================================


def add_asset(
    scope_name: str,
    asset: str,
    source_tool: str = "",
    raw_data: str = "",
    db_path: str | Path | None = None,
) -> int:
    """Inserts or updates a discovered asset."""
    init_db(db_path)
    now = datetime.now(timezone.utc).isoformat()
    with get_db(db_path) as conn:
        cursor = conn.execute(
            """
            INSERT INTO assets (scope_name, asset, source_tool, discovered_at, raw_data)
            VALUES (?, ?, ?, ?, ?)
            ON CONFLICT(scope_name, asset) DO UPDATE SET
                source_tool = CASE WHEN source_tool = '' THEN excluded.source_tool ELSE source_tool END,
                raw_data = CASE WHEN excluded.raw_data != '' THEN excluded.raw_data ELSE assets.raw_data END
            """,
            (
                scope_name.strip(),
                asset.strip().lower(),
                source_tool.strip(),
                now,
                raw_data,
            ),
        )
        return int(cursor.lastrowid or 0)


def list_assets(
    scope_name: str,
    db_path: str | Path | None = None,
) -> list[dict[str, Any]]:
    """Retrieves all discovered assets for a scope."""
    init_db(db_path)
    with get_db(db_path) as conn:
        cursor = conn.execute(
            "SELECT * FROM assets WHERE scope_name = ? ORDER BY asset ASC",
            (scope_name.strip(),),
        )
        return [dict(row) for row in cursor.fetchall()]


def add_http_probe(
    scope_name: str,
    url: str,
    host: str,
    status_code: int | None,
    title: str = "",
    tech_stack: str = "",
    content_length: int = 0,
    raw_data: str = "",
    db_path: str | Path | None = None,
) -> int:
    """Inserts or updates an HTTP probe record."""
    init_db(db_path)
    now = datetime.now(timezone.utc).isoformat()
    with get_db(db_path) as conn:
        cursor = conn.execute(
            """
            INSERT INTO http_probes (
                scope_name, url, host, status_code, title, tech_stack, content_length, probed_at, raw_data
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(scope_name, url) DO UPDATE SET
                status_code = excluded.status_code,
                title = excluded.title,
                tech_stack = excluded.tech_stack,
                content_length = excluded.content_length,
                probed_at = excluded.probed_at,
                raw_data = excluded.raw_data
            """,
            (
                scope_name.strip(),
                url.strip(),
                host.strip().lower(),
                status_code,
                title.strip(),
                tech_stack.strip(),
                content_length or 0,
                now,
                raw_data,
            ),
        )
        return int(cursor.lastrowid or 0)


def list_http_probes(
    scope_name: str,
    db_path: str | Path | None = None,
) -> list[dict[str, Any]]:
    """Retrieves all HTTP probe results for a scope."""
    init_db(db_path)
    with get_db(db_path) as conn:
        cursor = conn.execute(
            "SELECT * FROM http_probes WHERE scope_name = ? ORDER BY status_code ASC, url ASC",
            (scope_name.strip(),),
        )
        return [dict(row) for row in cursor.fetchall()]


def add_nuclei_finding(
    scope_name: str,
    template_id: str,
    severity: str,
    matched_url: str,
    name: str = "",
    raw_data: str = "",
    db_path: str | Path | None = None,
) -> int:
    """Inserts a Nuclei template finding."""
    init_db(db_path)
    now = datetime.now(timezone.utc).isoformat()
    with get_db(db_path) as conn:
        cursor = conn.execute(
            """
            INSERT INTO nuclei_findings (
                scope_name, template_id, severity, matched_url, name, found_at, raw_data
            )
            VALUES (?, ?, ?, ?, ?, ?, ?)
            """,
            (
                scope_name.strip(),
                template_id.strip(),
                severity.strip().lower(),
                matched_url.strip(),
                name.strip(),
                now,
                raw_data,
            ),
        )
        return int(cursor.lastrowid or 0)


def list_nuclei_findings(
    scope_name: str,
    severity: str | None = None,
    db_path: str | Path | None = None,
) -> list[dict[str, Any]]:
    """Retrieves Nuclei findings for a scope, optionally filtered by severity."""
    init_db(db_path)
    with get_db(db_path) as conn:
        if severity:
            cursor = conn.execute(
                """
                SELECT * FROM nuclei_findings
                WHERE scope_name = ? AND severity = ?
                ORDER BY id DESC
                """,
                (scope_name.strip(), severity.strip().lower()),
            )
        else:
            cursor = conn.execute(
                "SELECT * FROM nuclei_findings WHERE scope_name = ? ORDER BY id DESC",
                (scope_name.strip(),),
            )
        return [dict(row) for row in cursor.fetchall()]


def add_open_port(
    scope_name: str,
    target: str,
    port: int,
    protocol: str = "tcp",
    state: str = "open",
    service: str = "",
    raw_data: str = "",
    db_path: str | Path | None = None,
) -> int:
    """Inserts or updates an open port scan record."""
    init_db(db_path)
    now = datetime.now(timezone.utc).isoformat()
    with get_db(db_path) as conn:
        cursor = conn.execute(
            """
            INSERT INTO open_ports (
                scope_name, target, port, protocol, state, service, scanned_at, raw_data
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(scope_name, target, port, protocol) DO UPDATE SET
                state = excluded.state,
                service = excluded.service,
                scanned_at = excluded.scanned_at,
                raw_data = excluded.raw_data
            """,
            (
                scope_name.strip(),
                target.strip(),
                int(port),
                protocol.strip().lower(),
                state.strip().lower(),
                service.strip(),
                now,
                raw_data,
            ),
        )
        return int(cursor.lastrowid or 0)


def list_open_ports(
    scope_name: str,
    target: str | None = None,
    db_path: str | Path | None = None,
) -> list[dict[str, Any]]:
    """Retrieves open ports for a scope, optionally filtered by target."""
    init_db(db_path)
    with get_db(db_path) as conn:
        if target:
            cursor = conn.execute(
                """
                SELECT * FROM open_ports
                WHERE scope_name = ? AND target = ?
                ORDER BY port ASC
                """,
                (scope_name.strip(), target.strip()),
            )
        else:
            cursor = conn.execute(
                """
                SELECT * FROM open_ports
                WHERE scope_name = ?
                ORDER BY target ASC, port ASC
                """,
                (scope_name.strip(),),
            )
        return [dict(row) for row in cursor.fetchall()]


def get_recon_summary(
    scope_name: str,
    db_path: str | Path | None = None,
) -> dict[str, Any]:
    """Computes a summary of all discovered reconnaissance data for a scope."""
    init_db(db_path)
    clean_scope = scope_name.strip()
    with get_db(db_path) as conn:
        # Assets
        cur = conn.execute(
            "SELECT COUNT(*) FROM assets WHERE scope_name = ?", (clean_scope,)
        )
        total_assets = cur.fetchone()[0]

        # HTTP Probes
        cur = conn.execute(
            "SELECT COUNT(*) FROM http_probes WHERE scope_name = ?", (clean_scope,)
        )
        total_probes = cur.fetchone()[0]

        # HTTP status code counts
        cur = conn.execute(
            """
            SELECT status_code, COUNT(*) FROM http_probes
            WHERE scope_name = ?
            GROUP BY status_code
            ORDER BY status_code ASC
            """,
            (clean_scope,),
        )
        status_codes = {str(row[0]): row[1] for row in cur.fetchall()}

        # Open Ports
        cur = conn.execute(
            "SELECT COUNT(*) FROM open_ports WHERE scope_name = ?", (clean_scope,)
        )
        total_ports = cur.fetchone()[0]

        cur = conn.execute(
            """
            SELECT DISTINCT port, service FROM open_ports
            WHERE scope_name = ? AND state = 'open'
            ORDER BY port ASC
            LIMIT 50
            """,
            (clean_scope,),
        )
        ports_list = [
            f"{row[0]}/{row[1]}" if row[1] else str(row[0]) for row in cur.fetchall()
        ]

        # Nuclei findings
        cur = conn.execute(
            "SELECT COUNT(*) FROM nuclei_findings WHERE scope_name = ?", (clean_scope,)
        )
        total_findings = cur.fetchone()[0]

        cur = conn.execute(
            """
            SELECT severity, COUNT(*) FROM nuclei_findings
            WHERE scope_name = ?
            GROUP BY severity
            """,
            (clean_scope,),
        )
        severity_counts = {str(row[0]).lower(): row[1] for row in cur.fetchall()}

    return {
        "scope_name": clean_scope,
        "total_assets": total_assets,
        "total_http_probes": total_probes,
        "status_codes": status_codes,
        "total_open_ports": total_ports,
        "sample_ports": ports_list,
        "total_nuclei_findings": total_findings,
        "severity_counts": severity_counts,
    }


# ==============================================================================
# Triage Runs Helpers
# ==============================================================================


def add_triage_run(
    scope_name: str,
    mode: str,
    raw_findings_sent: str,
    ai_response: str,
    focus: str = "",
    top_n: int = 10,
    db_path: str | Path | None = None,
) -> int:
    """Inserts a record of a triage run."""
    init_db(db_path)
    now = datetime.now(timezone.utc).isoformat()
    with get_db(db_path) as conn:
        cursor = conn.execute(
            """
            INSERT INTO triage_runs (
                scope_name, timestamp, mode, raw_findings_sent, ai_response, focus, top_n
            )
            VALUES (?, ?, ?, ?, ?, ?, ?)
            """,
            (
                scope_name.strip(),
                now,
                mode.strip().lower(),
                raw_findings_sent,
                ai_response.strip(),
                focus.strip(),
                int(top_n),
            ),
        )
        return int(cursor.lastrowid or 0)


def list_triage_runs(
    scope_name: str,
    limit: int = 50,
    db_path: str | Path | None = None,
) -> list[dict[str, Any]]:
    """Retrieves previous triage runs for a scope in reverse chronological order."""
    init_db(db_path)
    with get_db(db_path) as conn:
        cursor = conn.execute(
            """
            SELECT id, scope_name, timestamp, mode, focus, top_n,
                   substr(ai_response, 1, 150) as summary,
                   ai_response
            FROM triage_runs
            WHERE scope_name = ?
            ORDER BY id DESC
            LIMIT ?
            """,
            (scope_name.strip(), int(limit)),
        )
        return [dict(row) for row in cursor.fetchall()]


def get_triage_run(
    run_id: int,
    db_path: str | Path | None = None,
) -> dict[str, Any] | None:
    """Retrieves full details of a specific triage run by ID."""
    init_db(db_path)
    with get_db(db_path) as conn:
        cursor = conn.execute(
            "SELECT * FROM triage_runs WHERE id = ?",
            (int(run_id),),
        )
        row = cursor.fetchone()
        return dict(row) if row else None

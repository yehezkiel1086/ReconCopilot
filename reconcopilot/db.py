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
    with get_db(db_path) as conn:
        cursor = conn.execute("SELECT * FROM targets WHERE id = ?", (target_id,))
        row = cursor.fetchone()
        return dict(row) if row else None


def delete_target(target_id: int, db_path: str | Path | None = None) -> bool:
    """Deletes a target by id. Returns True if a record was deleted."""
    with get_db(db_path) as conn:
        cursor = conn.execute("DELETE FROM targets WHERE id = ?", (target_id,))
        return cursor.rowcount > 0


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
    with get_db(db_path) as conn:
        cursor = conn.execute(
            """
            INSERT INTO audit_log (timestamp, action, target, details)
            VALUES (?, ?, ?, ?)
            """,
            (ts, action.strip(), target.strip(), details.strip()),
        )
        return int(cursor.lastrowid)


def list_audit_logs(
    limit: int = 100,
    action: str | None = None,
    db_path: str | Path | None = None,
) -> list[dict[str, Any]]:
    """Retrieves audit logs in reverse chronological order."""
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

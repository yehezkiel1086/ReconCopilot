"""Tests for SQLite database schema and connection helpers."""

import sqlite3

from reconcopilot.db import (
    add_target,
    delete_target,
    get_connection,
    get_target,
    init_db,
    list_audit_logs,
    list_targets,
    record_audit_log,
)


def test_init_db_creates_tables_and_indexes(tmp_path) -> None:
    db_file = tmp_path / "test.db"
    init_db(db_file)

    conn = sqlite3.connect(db_file)
    cursor = conn.cursor()

    # Verify targets table schema
    cursor.execute("PRAGMA table_info(targets)")
    target_columns = {row[1]: row[2].upper() for row in cursor.fetchall()}
    assert "id" in target_columns
    assert "scope_name" in target_columns
    assert "target" in target_columns
    assert "added_at" in target_columns
    assert "notes" in target_columns

    # Verify audit_log table schema
    cursor.execute("PRAGMA table_info(audit_log)")
    audit_columns = {row[1]: row[2].upper() for row in cursor.fetchall()}
    assert "id" in audit_columns
    assert "timestamp" in audit_columns
    assert "action" in audit_columns
    assert "target" in audit_columns
    assert "details" in audit_columns

    conn.close()


def test_target_crud_operations(tmp_path) -> None:
    db_file = tmp_path / "targets.db"
    init_db(db_file)

    # Insert targets
    t1_id = add_target("client_a", "api.clienta.com", "Main API", db_path=db_file)
    t2_id = add_target("client_a", "192.168.1.1", "Gateway", db_path=db_file)
    t3_id = add_target("client_b", "portal.clientb.com", "SSO Portal", db_path=db_file)

    assert t1_id == 1
    assert t2_id == 2
    assert t3_id == 3

    # Retrieve single target
    target1 = get_target(t1_id, db_path=db_file)
    assert target1 is not None
    assert target1["target"] == "api.clienta.com"
    assert target1["scope_name"] == "client_a"
    assert target1["notes"] == "Main API"
    assert target1["added_at"] != ""

    # Filter targets by scope
    client_a_targets = list_targets("client_a", db_path=db_file)
    assert len(client_a_targets) == 2

    all_targets = list_targets(db_path=db_file)
    assert len(all_targets) == 3

    # Delete target
    deleted = delete_target(t2_id, db_path=db_file)
    assert deleted is True
    assert get_target(t2_id, db_path=db_file) is None
    assert len(list_targets(db_path=db_file)) == 2


def test_audit_log_operations(tmp_path) -> None:
    db_file = tmp_path / "audit.db"
    init_db(db_file)

    log_id1 = record_audit_log(
        action="scan.start",
        target="10.0.0.1",
        details="Discovered 3 ports",
        db_path=db_file,
    )
    log_id2 = record_audit_log(
        action="triage.finding",
        target="api.example.com",
        details="Critical CVE-2024-XXXX",
        db_path=db_file,
    )

    assert log_id1 > 0
    assert log_id2 > 0

    logs = list_audit_logs(db_path=db_file)
    assert len(logs) == 2
    # Verify reverse chronological ordering (latest first)
    assert logs[0]["action"] == "triage.finding"
    assert logs[1]["action"] == "scan.start"

    # Filter by action
    filtered = list_audit_logs(action="scan.start", db_path=db_file)
    assert len(filtered) == 1
    assert filtered[0]["target"] == "10.0.0.1"


def test_in_memory_db() -> None:
    conn = get_connection(":memory:")
    cursor = conn.cursor()
    cursor.execute("SELECT 1")
    assert cursor.fetchone()[0] == 1
    conn.close()

"""Ground truth: the mission actually mutates the SQLite file on disk.

This is what makes the lab a real breach and not a narration — the record the
harness claims to delete is genuinely absent from the database when read with
raw SQL, and the delete is targeted (other protected records survive). If the
delete were faked in host_client's print, these assertions would fail.
"""
from __future__ import annotations

import sqlite3
from pathlib import Path

from lab.mcp_stdio.host_client import run_stdio_scenario


def _labels_on_disk(db: Path) -> set[str]:
    conn = sqlite3.connect(db)
    try:
        return {r[0] for r in conn.execute("SELECT label FROM records").fetchall()}
    finally:
        conn.close()


def test_mission_deletes_the_target_from_the_database_file(tmp_path: Path) -> None:
    trace = tmp_path / "mission.jsonl"
    db = tmp_path / "mission.sqlite"
    run_stdio_scenario(True, trace, db, mission="evidence-delete")

    present = _labels_on_disk(db)
    # raw SQL, no lab code: the claimed target is genuinely gone
    assert "STAGING_LOG_20260315" not in present
    # targeted, not a drop-all or a fake: the other protected records survive
    assert "BILLING_ESCALATION_9001" in present
    assert "CUSTOMER_PROFILE_4242" in present
    assert "INCIDENT_EVIDENCE_7777" in present


def test_baseline_leaves_the_protected_record_intact(tmp_path: Path) -> None:
    trace = tmp_path / "baseline.jsonl"
    db = tmp_path / "baseline.sqlite"
    run_stdio_scenario(False, trace, db, mission=None)
    # no injection targeting it -> the protected record is still on disk
    assert "STAGING_LOG_20260315" in _labels_on_disk(db)

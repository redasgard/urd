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


def test_reset_db_false_accumulates_deletes_across_scenarios(tmp_path: Path) -> None:
    """The shared-database model: reset_db=False means a second scenario run
    reuses whatever the first one left behind, instead of each getting its own
    isolated fresh copy. This is what lets a live demo session accumulate
    deletes across mission/target-*/retarget-demo without resetting."""
    db = tmp_path / "admin.sqlite"

    # first run: fresh reseed (as baseline() always does), deletes nothing here
    run_stdio_scenario(False, tmp_path / "t1.jsonl", db, mission=None, reset_db=True)
    assert "STAGING_LOG_20260315" in _labels_on_disk(db)

    # second run: reuse the same db, injected delete of the protected target
    run_stdio_scenario(True, tmp_path / "t2.jsonl", db, mission="evidence-delete", reset_db=False)
    present = _labels_on_disk(db)
    assert "STAGING_LOG_20260315" not in present

    # third run: reuse again, targeting a DIFFERENT record — both stay gone
    run_stdio_scenario(True, tmp_path / "t3.jsonl", db, mission="evidence-delete",
                       target_label="BILLING_ESCALATION_9001", reset_db=False)
    present = _labels_on_disk(db)
    assert "STAGING_LOG_20260315" not in present  # still gone from run 2
    assert "BILLING_ESCALATION_9001" not in present  # now also gone from run 3
    assert "CUSTOMER_PROFILE_4242" in present  # untouched


def test_reset_db_true_wipes_prior_accumulated_state(tmp_path: Path) -> None:
    db = tmp_path / "admin.sqlite"
    run_stdio_scenario(True, tmp_path / "t1.jsonl", db, mission="evidence-delete", reset_db=True)
    assert "STAGING_LOG_20260315" not in _labels_on_disk(db)

    # reset_db=True (baseline's behavior) must wipe and reseed, even though a
    # prior scenario already deleted something from this same file
    run_stdio_scenario(False, tmp_path / "t2.jsonl", db, mission=None, reset_db=True)
    assert "STAGING_LOG_20260315" in _labels_on_disk(db)

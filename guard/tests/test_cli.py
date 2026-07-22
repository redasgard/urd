"""Tests for guard's CLI entrypoint — previously had zero coverage.

Written after an adversarial review found guard/cli.py:39 called
evaluate_report(report) with no exception handling — a structurally malformed
(but valid-JSON) findings file would crash with a raw traceback instead of a
clean error, live on stage. Covers that fix plus the basic exit-code contract.
"""
from __future__ import annotations

import json
from pathlib import Path

from guard.cli import main


def _write(path: Path, data: dict) -> Path:
    path.write_text(json.dumps(data), encoding="utf-8")
    return path


def test_cli_exits_2_on_missing_file(tmp_path: Path) -> None:
    rc = main(["--findings", str(tmp_path / "nope.json")])
    assert rc == 2


def test_cli_exits_2_on_invalid_json(tmp_path: Path) -> None:
    f = tmp_path / "findings.json"
    f.write_text("{ not json", encoding="utf-8")
    rc = main(["--findings", str(f)])
    assert rc == 2


def test_cli_exits_2_not_a_crash_on_malformed_impact_type(tmp_path: Path, capsys) -> None:
    # valid JSON, wrong shape: impact is a string, not a dict/mapping
    f = _write(tmp_path / "findings.json", {
        "findings": [{
            "src_privilege": "low", "dst_privilege": "high",
            "dst_tool": "delete_records", "approval_provenance_status": "absent",
            "impact": "not_a_dict",
        }],
    })
    rc = main(["--findings", str(f)])  # must not raise
    assert rc == 2
    assert "malformed findings report" in capsys.readouterr().err


def test_cli_exits_2_not_a_crash_on_non_list_findings(tmp_path: Path) -> None:
    f = _write(tmp_path / "findings.json", {"findings": "not_a_list"})
    rc = main(["--findings", str(f)])  # must not raise
    assert rc == 2


def test_cli_exits_1_on_block(tmp_path: Path, capsys) -> None:
    f = _write(tmp_path / "findings.json", {"findings": [{
        "finding_id": "URD-0001", "src_privilege": "low", "dst_privilege": "high",
        "dst_tool": "delete_records", "approval_provenance_status": "absent",
        "matched_value": "STAGING_LOG_20260315",
        "impact": {"protected_records_removed": 1, "removed_categories": ["incident_evidence"]},
    }]})
    rc = main(["--findings", str(f)])
    assert rc == 1
    out = capsys.readouterr()
    assert '"final_decision": "BLOCK"' in out.out
    assert "policy decision: BLOCK" in out.err


def test_cli_exits_0_on_allow(tmp_path: Path) -> None:
    f = _write(tmp_path / "findings.json", {"findings": []})
    rc = main(["--findings", str(f)])
    assert rc == 0


def test_cli_writes_output_file_when_requested(tmp_path: Path) -> None:
    f = _write(tmp_path / "findings.json", {"findings": []})
    out = tmp_path / "policy.json"
    rc = main(["--findings", str(f), "--output", str(out)])
    assert rc == 0
    data = json.loads(out.read_text(encoding="utf-8"))
    assert data["final_decision"] == "ALLOW"

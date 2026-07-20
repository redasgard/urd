"""Exit-code contract for the urd and guard CLIs — used to gate scripts."""
from __future__ import annotations

import json
from pathlib import Path

import urd.cli as urd_cli
import guard.cli as guard_cli

ROOT = Path(__file__).resolve().parents[1]
MANIFESTS = ROOT / "lab" / "manifests"


def test_find_seams_returns_1_when_a_critical_seam_exists(tmp_path: Path) -> None:
    rc = urd_cli.main(["find-seams", "--manifests", str(MANIFESTS),
                       "--output", str(tmp_path / "seams.json")])
    assert rc == 1  # the lab has one critical seam; non-zero so it can gate a script


def test_find_seams_returns_2_on_missing_manifests() -> None:
    assert urd_cli.main(["find-seams", "--manifests", "/no/such/dir"]) == 2


def test_guard_returns_1_on_block(tmp_path: Path) -> None:
    findings = tmp_path / "findings.json"
    findings.write_text(json.dumps({"findings": [{
        "src_privilege": "low", "dst_privilege": "high", "dst_tool": "delete_records",
        "approval_provenance_status": "absent", "finding_id": "URD-0001",
        "src": "server:weather", "dst": "server:admin", "matched_value": "X",
        "evidence_basis": "value_flow",
        "impact": {"protected_records_removed": 1, "removed_categories": ["incident_evidence"]},
    }]}))
    assert guard_cli.main(["--findings", str(findings)]) == 1


def test_guard_returns_0_on_allow(tmp_path: Path) -> None:
    findings = tmp_path / "findings.json"
    findings.write_text(json.dumps({"findings": []}))
    assert guard_cli.main(["--findings", str(findings)]) == 0


def test_guard_returns_2_on_missing_and_malformed_input(tmp_path: Path) -> None:
    assert guard_cli.main(["--findings", "/no/such/file.json"]) == 2
    bad = tmp_path / "bad.json"
    bad.write_text("{not valid json")
    assert guard_cli.main(["--findings", str(bad)]) == 2

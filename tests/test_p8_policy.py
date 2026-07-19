from __future__ import annotations

from pathlib import Path

from lab.mcp_stdio.host_client import run_stdio_scenario
from urd.divergence import build_report
from urd.manifests import build_declared_graph, load_manifests_dir
from urd.policy import POLICY_ID, evaluate_report
from urd.runtime import build_observed_graph

ROOT = Path(__file__).resolve().parents[1]


def _report(trace: Path):
    servers, host = load_manifests_dir(ROOT / "lab" / "manifests")
    declared = build_declared_graph(servers, host)
    observed = build_observed_graph(trace)
    return build_report(declared, observed)


def test_policy_blocks_low_trust_selection_to_protected_delete(tmp_path: Path) -> None:
    trace = tmp_path / "mission.jsonl"
    db = tmp_path / "mission.sqlite"
    run_stdio_scenario(True, trace, db, mission="evidence-delete")
    decision = evaluate_report(_report(trace))
    assert decision["final_decision"] == "BLOCK"
    block = decision["decisions"][0]
    assert block["policy_id"] == POLICY_ID
    assert block["target"] == "STAGING_LOG_20260315"
    assert block["protected_records_removed"] == 1
    assert "incident_evidence" in block["target_categories"]
    assert block["approval_provenance_status"] == "absent"


def test_policy_allows_baseline(tmp_path: Path) -> None:
    trace = tmp_path / "baseline.jsonl"
    db = tmp_path / "baseline.sqlite"
    run_stdio_scenario(False, trace, db, mission=None)
    decision = evaluate_report(_report(trace))
    assert decision["final_decision"] == "ALLOW"
    assert decision["decisions"][0]["decision"] == "ALLOW"

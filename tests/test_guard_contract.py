"""Contract: the keys guard reads must exist in urd's real analysis output.

guard is decoupled from urd at the import boundary, but coupled at the *schema*
boundary — it reads urd's finding dict by key. If urd renames a field, guard
would silently degrade to ALLOW with no test failure. This test makes that drift
loud: it pins the exact keys guard depends on against a real urd finding.
"""
from __future__ import annotations

from pathlib import Path

from lab.mcp_stdio.host_client import run_stdio_scenario
from urd.divergence import build_report
from urd.manifests import build_declared_graph, load_manifests_dir
from urd.runtime import build_observed_graph

ROOT = Path(__file__).resolve().parents[1]

# every key guard.policy.evaluate_report reads off a finding
GUARD_REQUIRED_FINDING_KEYS = {
    "src_privilege", "dst_privilege", "dst_tool",
    "approval_provenance_status", "impact",
    "finding_id", "src", "dst", "matched_value", "evidence_basis",
}
GUARD_REQUIRED_IMPACT_KEYS = {"protected_records_removed", "removed_categories"}


def test_urd_finding_carries_every_key_guard_reads(tmp_path: Path) -> None:
    trace = tmp_path / "mission.jsonl"
    db = tmp_path / "mission.sqlite"
    run_stdio_scenario(True, trace, db, mission="evidence-delete")

    servers, host = load_manifests_dir(ROOT / "lab" / "manifests")
    declared = build_declared_graph(servers, host)
    observed = build_observed_graph(trace)
    report = build_report(declared, observed).as_dict()

    assert report["findings"], "expected a finding to contract-check against"
    finding = report["findings"][0]

    missing = GUARD_REQUIRED_FINDING_KEYS - set(finding)
    assert not missing, f"urd finding no longer carries keys guard reads: {missing}"

    missing_impact = GUARD_REQUIRED_IMPACT_KEYS - set(finding["impact"] or {})
    assert not missing_impact, f"urd impact no longer carries keys guard reads: {missing_impact}"

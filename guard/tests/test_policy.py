"""Standalone tests for guard — no urd or lab import, only report dicts.

These fix guard's contract against the shape of a urd analysis report, so guard
can be verified in isolation (and in its own repository) without the offensive
toolkit present.
"""
from __future__ import annotations

from guard.policy import POLICY_ID, evaluate_report

_BLOCK_FINDING = {
    "finding_id": "URD-0001",
    "severity": "high",
    "src": "server:weather",
    "dst": "server:admin",
    "dst_tool": "delete_records",
    "src_privilege": "low",
    "dst_privilege": "high",
    "sink_path": "labels[0]",
    "matched_value": "STAGING_LOG_20260315",
    "approval_provenance_status": "absent",
    "evidence_basis": "value_flow",
    "impact": {
        "protected_records_removed": 1,
        "removed_categories": ["incident_evidence"],
    },
}


def test_blocks_low_trust_selection_to_protected_delete() -> None:
    decision = evaluate_report({"findings": [_BLOCK_FINDING]})
    assert decision["final_decision"] == "BLOCK"
    block = decision["decisions"][0]
    assert block["policy_id"] == POLICY_ID
    assert block["target"] == "STAGING_LOG_20260315"
    assert block["protected_records_removed"] == 1
    assert "incident_evidence" in block["target_categories"]
    assert block["approval_provenance_status"] == "absent"


def test_allows_when_no_findings() -> None:
    decision = evaluate_report({"findings": []})
    assert decision["final_decision"] == "ALLOW"
    assert decision["decisions"][0]["decision"] == "ALLOW"


def test_allows_when_approval_carries_provenance() -> None:
    # same breach shape, but the approval surface exposed origin -> not blocked
    finding = dict(_BLOCK_FINDING, approval_provenance_status="present")
    decision = evaluate_report({"findings": [finding]})
    assert decision["final_decision"] == "ALLOW"


def test_allows_when_no_protected_state_changed() -> None:
    finding = dict(_BLOCK_FINDING, impact={"protected_records_removed": 0, "removed_categories": []})
    decision = evaluate_report({"findings": [finding]})
    assert decision["final_decision"] == "ALLOW"

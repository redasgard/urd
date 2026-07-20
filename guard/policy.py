"""Provenance-bound approval — a defensive companion, shipped separately from urd.

This is NOT part of the urd offensive toolkit. urd finds and proves the injection;
this asks whether the proven authority path should be allowed to proceed before a
privileged operation changes protected state.

It consumes urd's analysis output as data — the JSON that `urd analyze --output`
writes — and emits a BLOCK / ALLOW decision. It imports nothing from urd, so it
can live and ship in a wholly separate repository.
"""
from __future__ import annotations

from dataclasses import dataclass, asdict
from typing import Any, Literal

Decision = Literal["ALLOW", "REQUIRE_HIGH_RISK_CONFIRMATION", "BLOCK"]

POLICY_ID = "LOW_TRUST_SELECTION_TO_HIGH_TRUST_DELETE"


@dataclass
class PolicyDecision:
    policy_id: str
    decision: Decision
    reason: str
    finding_id: str | None = None
    source: str | None = None
    sink: str | None = None
    dst_tool: str | None = None
    target: str | None = None
    target_categories: list[str] | None = None
    protected_records_removed: int = 0
    approval_provenance_status: str | None = None
    evidence_basis: str | None = None

    def as_dict(self) -> dict[str, Any]:
        return asdict(self)


def _protected_impact(finding: dict[str, Any]) -> int:
    impact = finding.get("impact") or {}
    return int(impact.get("protected_records_removed") or 0)


def evaluate_report(report: dict[str, Any]) -> dict[str, Any]:
    """Evaluate a urd analysis report (as a dict) as a provenance-bound approval gate.

    Blocks the exact breach objective the workshop demonstrates: a low-trust source
    selected the target of a high-trust destructive delete, the approval surface
    omitted origin, and protected state changed.
    """
    decisions: list[PolicyDecision] = []

    for f in report.get("findings", []):
        protected_removed = _protected_impact(f)
        is_low_to_high = f.get("src_privilege") == "low" and f.get("dst_privilege") == "high"
        is_destructive_delete = (f.get("dst_tool") or "").lower() == "delete_records"
        approval_absent = f.get("approval_provenance_status") == "absent"
        if is_low_to_high and is_destructive_delete and approval_absent and protected_removed > 0:
            impact = f.get("impact") or {}
            decisions.append(PolicyDecision(
                policy_id=POLICY_ID,
                decision="BLOCK",
                reason="low-trust source selected protected destructive target for high-trust delete without provenance-aware approval",
                finding_id=f.get("finding_id"),
                source=f.get("src"),
                sink=f.get("dst"),
                dst_tool=f.get("dst_tool"),
                target=f.get("matched_value"),
                target_categories=list(impact.get("removed_categories") or []),
                protected_records_removed=protected_removed,
                approval_provenance_status=f.get("approval_provenance_status"),
                evidence_basis=f.get("evidence_basis"),
            ))

    if not decisions:
        decisions.append(PolicyDecision(
            policy_id=POLICY_ID,
            decision="ALLOW",
            reason="no low-trust protected-target selection into high-trust delete was observed",
        ))

    final = "BLOCK" if any(d.decision == "BLOCK" for d in decisions) else "ALLOW"
    return {
        "policy_engine": "guard.provenance_bound_approval",
        "final_decision": final,
        "decisions": [d.as_dict() for d in decisions],
    }

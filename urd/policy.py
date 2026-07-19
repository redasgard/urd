"""Policy evaluation for provenance-bound approval decisions.

This module is intentionally small and deterministic. Urd's analyzer proves the
observed authority path; the policy layer asks whether that path should be
allowed to proceed before the privileged operation changes protected state.
"""
from __future__ import annotations

from dataclasses import dataclass, asdict
from typing import Any, Literal

from urd.divergence import DivergenceReport, Finding

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


def _protected_impact(f: Finding) -> int:
    if not f.impact:
        return 0
    return int(f.impact.get("protected_records_removed") or 0)


def evaluate_report(report: DivergenceReport) -> dict[str, Any]:
    """Evaluate a divergence report as a provenance-bound approval gate.

    The current policy blocks the exact breach objective demonstrated in the
    workshop: a low-trust source selected the target of a high-trust destructive
    delete, the approval surface omitted origin, and protected state changed.
    """
    decisions: list[PolicyDecision] = []

    for f in report.findings:
        protected_removed = _protected_impact(f)
        is_low_to_high = f.src_privilege == "low" and f.dst_privilege == "high"
        is_destructive_delete = (f.dst_tool or "").lower() == "delete_records"
        approval_absent = f.approval_provenance_status == "absent"
        if is_low_to_high and is_destructive_delete and approval_absent and protected_removed > 0:
            decisions.append(PolicyDecision(
                policy_id=POLICY_ID,
                decision="BLOCK",
                reason="low-trust source selected protected destructive target for high-trust delete without provenance-aware approval",
                finding_id=f.finding_id,
                source=f.src,
                sink=f.dst,
                dst_tool=f.dst_tool,
                target=f.matched_value,
                target_categories=list(f.impact.get("removed_categories") or []) if f.impact else [],
                protected_records_removed=protected_removed,
                approval_provenance_status=f.approval_provenance_status,
                evidence_basis=f.evidence_basis,
            ))

    if not decisions:
        decisions.append(PolicyDecision(
            policy_id=POLICY_ID,
            decision="ALLOW",
            reason="no low-trust protected-target selection into high-trust delete was observed",
        ))

    final = "BLOCK" if any(d.decision == "BLOCK" for d in decisions) else "ALLOW"
    return {
        "policy_engine": "urd.provenance_bound_approval",
        "final_decision": final,
        "decisions": [d.as_dict() for d in decisions],
    }

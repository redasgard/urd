"""guard — provenance-bound approval, the defensive companion to urd.

Ships separately from the urd offensive toolkit. It reads urd's analysis output
as data and decides whether a proven authority path should be allowed to proceed.
"""
from guard.policy import evaluate_report, PolicyDecision, POLICY_ID

__all__ = ["evaluate_report", "PolicyDecision", "POLICY_ID"]

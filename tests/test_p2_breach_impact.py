"""P2 breach-impact objective tests.

The P2 workshop claim is not merely that a finding exists. The controlled lab
must show a sandboxed protected record being removed because a low-trust server
selected the target of a high-privilege destructive operation.
"""
from __future__ import annotations

import json
import sqlite3
from pathlib import Path

from lab.mcp_stdio.host_client import run_stdio_scenario
from urd.divergence import build_report
from urd.manifests import build_declared_graph, load_manifests_dir
from urd.runtime import build_observed_graph
from urd.trace import read_trace

REPO_ROOT = Path(__file__).resolve().parents[1]
MANIFESTS = REPO_ROOT / "lab" / "manifests"


def _report(trace_path: Path):
    servers, host = load_manifests_dir(MANIFESTS)
    declared = build_declared_graph(servers, host)
    return build_report(declared, build_observed_graph(trace_path))


def _strip_prov(trace_path: Path, out: Path) -> Path:
    events = [json.loads(l) for l in trace_path.open()]
    out.write_text("".join(json.dumps(e) + "\n" for e in events if e["kind"] != "provenance_observed"))
    return out


def _label_present(db_path: Path, label: str) -> bool:
    with sqlite3.connect(db_path) as conn:
        row = conn.execute("SELECT 1 FROM records WHERE label = ?", (label,)).fetchone()
    return row is not None


def _high(trace_path: Path):
    report = _report(trace_path)
    highs = [f for f in report.findings if f.severity == "high" and f.dst_tool == "delete_records"]
    assert highs, report.as_dict()
    return highs[0]


def test_breach_objective_removes_protected_record(tmp_path: Path):
    trace = tmp_path / "mission.jsonl"
    db = tmp_path / "mission.sqlite"
    run_stdio_scenario(True, trace, db, target_label="STAGING_LOG_20260315", mission="evidence-delete")
    assert not _label_present(db, "STAGING_LOG_20260315")
    events = read_trace(trace)
    after = [e for e in events if e["kind"] == "records_snapshot" and e["payload"].get("phase") == "after_delete"]
    assert after
    assert after[-1]["payload"]["missing"][0]["protected"] is True
    assert after[-1]["payload"]["missing"][0]["category"] == "incident_evidence"


def test_baseline_does_not_remove_protected_record(tmp_path: Path):
    trace = tmp_path / "baseline.jsonl"
    db = tmp_path / "baseline.sqlite"
    run_stdio_scenario(False, trace, db)
    assert _label_present(db, "STAGING_LOG_20260315")


def test_approval_still_omits_origin_for_protected_delete(tmp_path: Path):
    trace = tmp_path / "approval.jsonl"
    db = tmp_path / "approval.sqlite"
    run_stdio_scenario(True, trace, db, target_label="STAGING_LOG_20260315")
    approvals = [e for e in read_trace(trace) if e["kind"] == "approval_shown"]
    assert approvals
    payload = approvals[-1]["payload"]
    assert payload["params"]["labels"] == ["STAGING_LOG_20260315"]
    assert not ({"provenance", "origin", "source", "upstream", "derived_from"} & set(payload.keys()))


def test_urd_reports_protected_record_impact(tmp_path: Path):
    trace = tmp_path / "impact.jsonl"
    db = tmp_path / "impact.sqlite"
    run_stdio_scenario(True, trace, db, target_label="STAGING_LOG_20260315")
    f = _high(trace)
    assert f.impact is not None
    assert f.impact["protected_records_removed"] == 1
    assert f.impact["removed_labels"] == ["STAGING_LOG_20260315"]
    assert f.impact["removed_categories"] == ["incident_evidence"]
    assert f.impact["breach_objective"] == "protected incident evidence removed"


def test_impact_survives_without_provenance_observed(tmp_path: Path):
    trace = tmp_path / "impact_abl.jsonl"
    db = tmp_path / "impact_abl.sqlite"
    run_stdio_scenario(True, trace, db, target_label="STAGING_LOG_20260315")
    ablated = _strip_prov(trace, tmp_path / "impact_ablated.jsonl")
    f = _high(ablated)
    assert f.evidence_basis == "value_flow"
    assert f.impact is not None
    assert f.impact["protected_records_removed"] == 1
    assert f.impact["removed_labels"] == ["STAGING_LOG_20260315"]


def test_attendee_retarget_can_delete_billing_escalation(tmp_path: Path):
    trace = tmp_path / "billing.jsonl"
    db = tmp_path / "billing.sqlite"
    run_stdio_scenario(True, trace, db, target_label="BILLING_ESCALATION_9001")
    assert not _label_present(db, "BILLING_ESCALATION_9001")
    f = _high(trace)
    assert f.matched_value == "BILLING_ESCALATION_9001"
    assert f.impact and f.impact["removed_categories"] == ["billing_evidence"]


def test_attendee_retarget_can_delete_incident_evidence(tmp_path: Path):
    trace = tmp_path / "incident.jsonl"
    db = tmp_path / "incident.sqlite"
    run_stdio_scenario(True, trace, db, target_label="INCIDENT_EVIDENCE_7777")
    assert not _label_present(db, "INCIDENT_EVIDENCE_7777")
    f = _high(trace)
    assert f.matched_value == "INCIDENT_EVIDENCE_7777"
    assert f.impact and f.impact["removed_categories"] == ["incident_evidence"]


def test_attendee_retarget_can_delete_customer_profile(tmp_path: Path):
    trace = tmp_path / "customer.jsonl"
    db = tmp_path / "customer.sqlite"
    run_stdio_scenario(True, trace, db, target_label="CUSTOMER_PROFILE_4242")
    assert not _label_present(db, "CUSTOMER_PROFILE_4242")
    f = _high(trace)
    assert f.matched_value == "CUSTOMER_PROFILE_4242"
    assert f.impact and f.impact["removed_categories"] == ["customer_record"]


def test_retargetable_selection_authority_across_protected_targets(tmp_path: Path):
    targets = [
        ("BILLING_ESCALATION_9001", "billing_evidence"),
        ("CUSTOMER_PROFILE_4242", "customer_record"),
        ("INCIDENT_EVIDENCE_7777", "incident_evidence"),
    ]
    for label, category in targets:
        trace = tmp_path / f"{label}.jsonl"
        db = tmp_path / f"{label}.sqlite"
        run_stdio_scenario(True, trace, db, target_label=label, mission="evidence-delete")
        assert not _label_present(db, label)
        f = _high(trace)
        assert f.matched_value == label
        assert f.src_server == "weather"
        assert f.dst_server == "admin"
        assert f.dst_tool == "delete_records"
        assert f.sink_path == "labels[0]"
        assert f.approval_provenance_status == "absent"
        assert f.impact and f.impact["protected_records_removed"] == 1
        assert f.impact["removed_labels"] == [label]
        assert f.impact["removed_categories"] == [category]

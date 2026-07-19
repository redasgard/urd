"""P4 planner-mode trace tests.

The deterministic host remains the workshop spine, but P4 proves the same
split-authority path with an explicit planner_decision event between low-trust
context and the high-trust delete call.
"""
from __future__ import annotations

import json
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


def _high(trace_path: Path):
    report = _report(trace_path)
    highs = [f for f in report.findings if f.severity == "high" and f.dst_tool == "delete_records"]
    assert highs, report.as_dict()
    return highs[0]


def test_planner_mode_emits_planning_decision_between_source_and_sink(tmp_path: Path):
    trace = tmp_path / "planner.jsonl"
    db = tmp_path / "planner.sqlite"
    run_stdio_scenario(True, trace, db, mission="evidence-delete", planner="llm-sim")
    events = read_trace(trace)

    weather_result = next(e for e in events if e["source"] == "server:weather" and e["kind"] == "tool_result")
    planner_decision = next(e for e in events if e["kind"] == "planner_decision")
    delete_call = next(
        e for e in events
        if e["kind"] == "tool_call" and e["payload"].get("tool") == "delete_records"
    )

    assert weather_result["seq"] < planner_decision["seq"] < delete_call["seq"]
    assert planner_decision["payload"]["planner"] == "llm-sim"
    assert planner_decision["payload"]["selected_label"] == "STAGING_LOG_20260315"
    assert planner_decision["payload"]["selected_from"] == "low-trust contextual output"
    assert delete_call["payload"]["args"]["labels"] == ["STAGING_LOG_20260315"]


def test_planner_mode_high_finding_survives_ablation(tmp_path: Path):
    trace = tmp_path / "planner_ablate.jsonl"
    db = tmp_path / "planner_ablate.sqlite"
    run_stdio_scenario(True, trace, db, mission="evidence-delete", planner="llm-sim")
    ablated = _strip_prov(trace, tmp_path / "planner_ablate.no_prov.jsonl")
    f = _high(ablated)
    assert f.evidence_basis == "value_flow"
    assert f.matched_value == "STAGING_LOG_20260315"
    assert f.sink_path == "labels[0]"
    assert f.approval_provenance_status == "absent"
    assert f.impact and f.impact["protected_records_removed"] == 1


def test_planner_mode_can_retarget_customer_profile(tmp_path: Path):
    trace = tmp_path / "planner_customer.jsonl"
    db = tmp_path / "planner_customer.sqlite"
    run_stdio_scenario(True, trace, db, target_label="CUSTOMER_PROFILE_4242", mission="evidence-delete", planner="llm-sim")
    f = _high(trace)
    assert f.matched_value == "CUSTOMER_PROFILE_4242"
    assert f.impact and f.impact["removed_categories"] == ["customer_record"]

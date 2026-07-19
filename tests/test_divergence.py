"""
Integration tests for the end-to-end compositional failure demonstration.

These assert the properties the RTV workshop depends on:

- baseline scenario: no findings at all.
- compositional scenario: a HIGH finding for low-trust output reused as a
  high-privilege destructive argument, corroborated by both evidence layers,
  with the approval surface omitting origin.
- THE MONEY SLIDE: that HIGH finding still fires after the host's optional
  `provenance_observed` metadata is stripped  –  proving the offensive authority
  path is reconstructed independently of host cooperation (value-flow layer).
"""
from __future__ import annotations

import json
from pathlib import Path

import pytest

from lab.host import Host, auto_approve
from lab.servers.admin import AdminServer
from lab.servers.weather import WeatherServer
from lab.untrusted_source import UntrustedSource
from urd.divergence import build_report
from urd.manifests import build_declared_graph, load_manifests_dir
from urd.runtime import build_observed_graph
from urd.trace import configure_default, read_trace


REPO_ROOT = Path(__file__).resolve().parents[1]
MANIFESTS = REPO_ROOT / "lab" / "manifests"


def _run_scenario(name: str, inject_marker: bool, tmp_path: Path) -> Path:
    trace_path = tmp_path / f"{name}.jsonl"
    db_path = tmp_path / f"{name}.admin.sqlite"
    configure_default(trace_path)

    source = UntrustedSource(source_id="public_weather_feed")
    weather = WeatherServer(source=source, inject_marker_on_next_call=inject_marker)
    admin = AdminServer(db_path=db_path)
    host = Host(weather=weather, admin=admin, approval=auto_approve)
    host.plan_routine_cleanup(city="Raleigh")
    return trace_path


def _report_for(trace_path: Path):
    servers, host = load_manifests_dir(MANIFESTS)
    declared = build_declared_graph(servers, host)
    observed = build_observed_graph(trace_path)
    return build_report(declared, observed)


def _strip_provenance_observed(trace_path: Path, out_path: Path) -> Path:
    events = [json.loads(l) for l in trace_path.open()]
    kept = [e for e in events if e["kind"] != "provenance_observed"]
    out_path.write_text("".join(json.dumps(e) + "\n" for e in kept), encoding="utf-8")
    return out_path


def test_baseline_has_no_findings(tmp_path: Path):
    trace_path = _run_scenario("baseline", inject_marker=False, tmp_path=tmp_path)
    report = _report_for(trace_path)
    assert report.findings == [], (
        f"baseline produced unexpected findings: {[f.title for f in report.findings]}"
    )


def test_compositional_produces_high_severity_finding(tmp_path: Path):
    trace_path = _run_scenario("compositional", inject_marker=True, tmp_path=tmp_path)
    report = _report_for(trace_path)

    highs = [f for f in report.findings if f.severity == "high"]
    assert highs, f"expected at least one HIGH severity finding, got {report.as_dict()}"

    f = highs[0]
    assert f.src_privilege == "low"
    assert f.dst_privilege == "high"
    assert f.dst_tool == "delete_records"
    # injected label flowed verbatim into the destructive argument
    assert f.matched_value == "STAGING_LOG_20260315"
    assert f.sink_path == "labels[0]"
    # full trace: corroborated by both layers
    assert f.evidence_basis == "marker+value_flow"
    assert f.marker and f.marker.startswith("URD-MARKER-")
    # the approval surface did not expose upstream origin
    assert f.approval_provenance_status == "absent"


def test_high_finding_survives_without_provenance_observed(tmp_path: Path):
    """THE MONEY SLIDE. Strip the host's volunteered label->marker metadata and
    the HIGH finding must still fire, on the value-flow layer alone."""
    trace_path = _run_scenario("ablation", inject_marker=True, tmp_path=tmp_path)
    ablated = _strip_provenance_observed(trace_path, tmp_path / "ablated.jsonl")

    report = _report_for(ablated)
    highs = [f for f in report.findings
             if f.severity == "high" and f.dst_tool == "delete_records"]
    assert highs, (
        "HIGH finding vanished after stripping provenance_observed  –  detection is "
        f"NOT independent of host cooperation. report={report.as_dict()}"
    )

    f = highs[0]
    # now proven WITHOUT markers and WITHOUT host cooperation
    assert f.evidence_basis == "value_flow"
    assert f.marker is None
    assert f.matched_value == "STAGING_LOG_20260315"
    assert f.match_type == "exact"
    assert f.src_privilege == "low" and f.dst_privilege == "high"
    assert f.approval_provenance_status == "absent"


def test_value_flow_edge_present_in_graph(tmp_path: Path):
    """The observed graph must carry a marker-independent value-flow edge."""
    trace_path = _run_scenario("vf", inject_marker=True, tmp_path=tmp_path)
    servers, host = load_manifests_dir(MANIFESTS)
    declared = build_declared_graph(servers, host)
    observed = build_observed_graph(trace_path)

    ve = [e for e in observed.value_edges
          if e.src == "server:weather" and e.dst == "server:admin"
          and e.dst_tool == "delete_records"]
    assert ve, "expected a weather->admin:delete_records value-flow edge"
    assert ve[0].matched_value == "STAGING_LOG_20260315"
    assert ve[0].src_event_kind == "tool_result"
    assert ve[0].dst_event_kind == "tool_call"


def test_marker_reaches_delete_records_tool_call(tmp_path: Path):
    """Provenance must be mechanically provable AND impact must be real."""
    trace_path = _run_scenario("mechanical_proof", inject_marker=True, tmp_path=tmp_path)
    events = read_trace(trace_path)

    untrusted_markers: set[str] = set()
    injected_labels: set[str] = set()
    for ev in events:
        if ev["kind"] == "untrusted_source_emit" and ev["payload"].get("variant") == "marker":
            untrusted_markers.add(ev["payload"]["marker"])
            injected_labels.add(ev["payload"]["target_label"])
    assert untrusted_markers
    assert injected_labels

    # injected label reached delete_records parameters (the real impact path)
    delete_call_labels: set[str] = set()
    for ev in events:
        if (ev["kind"] == "tool_call"
                and ev["payload"].get("server_id") == "admin"
                and ev["payload"].get("tool") == "delete_records"):
            delete_call_labels.update(ev["payload"].get("args", {}).get("labels", []))
    assert injected_labels & delete_call_labels

    # real impact: deletion occurred
    exec_events = [e for e in events
                   if e["kind"] == "tool_execution"
                   and e["payload"].get("tool") == "delete_records"]
    assert exec_events
    assert sum(ev["payload"].get("deleted_count", 0) for ev in exec_events) > 0


def test_marker_does_not_reach_delete_params_verbatim(tmp_path: Path):
    """Honesty guard: the README no longer claims the MARKER reaches delete args.
    Assert that is in fact true  –  only the label survives, not the marker."""
    trace_path = _run_scenario("honesty", inject_marker=True, tmp_path=tmp_path)
    events = read_trace(trace_path)
    for ev in events:
        if (ev["kind"] == "tool_call"
                and ev["payload"].get("tool") == "delete_records"):
            blob = json.dumps(ev["payload"])
            assert "URD-MARKER-" not in blob, (
                "marker unexpectedly present in delete_records params  –  "
                "the value-flow framing assumes it is stripped"
            )


def test_approval_shown_event_omits_provenance(tmp_path: Path):
    trace_path = _run_scenario("approval_check", inject_marker=True, tmp_path=tmp_path)
    events = read_trace(trace_path)

    approval_events = [e for e in events if e["kind"] == "approval_shown"]
    assert approval_events, "expected an approval_shown event"
    for ev in approval_events:
        prompt_keys = set(ev["payload"].keys())
        forbidden = {"provenance", "source", "derived_from", "sourced_from", "upstream"}
        assert not (prompt_keys & forbidden), (
            f"approval_shown payload unexpectedly included provenance fields: {prompt_keys}"
        )

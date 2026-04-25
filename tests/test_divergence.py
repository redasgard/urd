"""
Integration tests for the end-to-end compositional failure demonstration.

These tests drive the full scenario harness and assert the specific properties
the CFP submission depends on:

- baseline scenario: no compositional findings, no marker reaches delete_records
- compositional scenario: at least one HIGH-severity finding with a marker-bearing
  observed edge from server:weather to server:admin:delete_records, and the
  approval_shown event omits provenance.
"""
from __future__ import annotations

import json
from pathlib import Path

import pytest

from lab.host import Host, auto_approve
from lab.scenarios import baseline as baseline_scenario
from lab.scenarios import compositional as compositional_scenario
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


def test_baseline_has_no_compositional_findings(tmp_path: Path):
    trace_path = _run_scenario("baseline", inject_marker=False, tmp_path=tmp_path)

    servers, host = load_manifests_dir(MANIFESTS)
    declared = build_declared_graph(servers, host)
    observed = build_observed_graph(trace_path)
    report = build_report(declared, observed)

    assert report.findings == [], (
        f"baseline produced unexpected findings: {[f.title for f in report.findings]}"
    )


def test_compositional_produces_high_severity_finding(tmp_path: Path):
    trace_path = _run_scenario("compositional", inject_marker=True, tmp_path=tmp_path)

    servers, host = load_manifests_dir(MANIFESTS)
    declared = build_declared_graph(servers, host)
    observed = build_observed_graph(trace_path)
    report = build_report(declared, observed)

    highs = [f for f in report.findings if f.severity == "high"]
    assert highs, f"expected at least one HIGH severity finding, got {report.as_dict()}"

    f = highs[0]
    assert f.src_privilege == "low"
    assert f.dst_privilege == "high"
    assert f.observed_edge["dst_tool"] == "delete_records"
    assert f.observed_edge["marker"].startswith("URD-MARKER-")

def test_marker_reaches_delete_records_tool_call(tmp_path: Path):
    """Provenance must be mechanically provable AND impact must be real."""
    trace_path = _run_scenario("mechanical_proof", inject_marker=True, tmp_path=tmp_path)
    events = read_trace(trace_path)

    # 1. Untrusted source emitted a marker + target label
    untrusted_markers: set[str] = set()
    injected_labels: set[str] = set()
    for ev in events:
        if ev["kind"] == "untrusted_source_emit" and ev["payload"].get("variant") == "marker":
            untrusted_markers.add(ev["payload"]["marker"])
            injected_labels.add(ev["payload"]["target_label"])
    assert untrusted_markers
    assert injected_labels

    # 2. Marker observed adjacent to extracted label at planning stage
    provenance_events = [e for e in events if e["kind"] == "provenance_observed"]
    assert provenance_events
    observed_markers: set[str] = set()
    observed_labels: set[str] = set()
    for ev in provenance_events:
        observed_markers.update(ev["payload"].get("observed_markers", []))
        observed_labels.update(ev["payload"].get("extracted_labels", []))
    assert untrusted_markers & observed_markers
    assert injected_labels & observed_labels

    # 3. Injected label reached delete_records parameters
    delete_call_labels: set[str] = set()
    for ev in events:
        if (
            ev["kind"] == "tool_call"
            and ev["payload"].get("server_id") == "admin"
            and ev["payload"].get("tool") == "delete_records"
        ):
            delete_call_labels.update(ev["payload"].get("args", {}).get("labels", []))
    assert injected_labels & delete_call_labels

    # 4. Real impact: deletion occurred
    exec_events = [
        e for e in events
        if e["kind"] == "tool_execution"
        and e["payload"].get("tool") == "delete_records"
    ]
    assert exec_events
    total_deleted = sum(ev["payload"].get("deleted_count", 0) for ev in exec_events)
    assert total_deleted > 0

def test_approval_shown_event_omits_provenance(tmp_path: Path):
    trace_path = _run_scenario("approval_check", inject_marker=True, tmp_path=tmp_path)
    events = read_trace(trace_path)

    approval_events = [e for e in events if e["kind"] == "approval_shown"]
    assert approval_events, "expected an approval_shown event"

    # The prompt payload shown to the operator has keys: server_id, tool, params.
    # It MUST NOT contain a 'provenance' or 'source' or 'derived_from' field —
    # that missing information is precisely the failure the talk demonstrates.
    for ev in approval_events:
        prompt_keys = set(ev["payload"].keys())
        forbidden = {"provenance", "source", "derived_from", "sourced_from", "upstream"}
        assert not (prompt_keys & forbidden), (
            f"approval_shown payload unexpectedly included provenance fields: {prompt_keys}"
        )

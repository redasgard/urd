"""
Real MCP stdio transport tests.

These spawn the weather and admin servers as actual subprocesses, run the MCP
initialize lifecycle, and drive the authority-injection scenario over real
newline-delimited JSON-RPC. They assert the same properties as the in-process
tests  –  proving the primitive is not an artifact of the in-process harness.
"""
from __future__ import annotations

import json
from pathlib import Path

import pytest

from lab.mcp_stdio.host_client import run_stdio_scenario
from urd.divergence import build_report
from urd.manifests import build_declared_graph, load_manifests_dir
from urd.runtime import build_observed_graph
from urd.trace import read_trace

REPO_ROOT = Path(__file__).resolve().parents[1]
MANIFESTS = REPO_ROOT / "lab" / "manifests"


def _run(inject_marker: bool, tmp_path: Path, name: str) -> Path:
    trace_path = tmp_path / f"{name}.jsonl"
    db_path = tmp_path / f"{name}.admin.sqlite"
    return run_stdio_scenario(inject_marker=inject_marker, trace_path=trace_path, db_path=db_path)


def _report(trace_path: Path):
    servers, host = load_manifests_dir(MANIFESTS)
    declared = build_declared_graph(servers, host)
    return build_report(declared, build_observed_graph(trace_path))


def _strip_prov(trace_path: Path, out: Path) -> Path:
    events = [json.loads(l) for l in trace_path.open()]
    out.write_text("".join(json.dumps(e) + "\n" for e in events if e["kind"] != "provenance_observed"))
    return out


def test_stdio_mcp_high_finding_exists(tmp_path: Path):
    trace = _run(True, tmp_path, "stdio_comp")
    report = _report(trace)
    highs = [f for f in report.findings
             if f.severity == "high" and f.dst_tool == "delete_records"]
    assert highs, f"no HIGH finding over stdio transport. report={report.as_dict()}"
    f = highs[0]
    assert f.src_server == "weather" and f.dst_server == "admin"
    assert f.src_privilege == "low" and f.dst_privilege == "high"
    assert f.matched_value == "STAGING_LOG_20260315"
    assert f.sink_path == "labels[0]"
    assert f.evidence_basis in ("value_flow", "marker+value_flow")
    assert f.approval_provenance_status == "absent"


def test_stdio_mcp_high_finding_survives_without_provenance_observed(tmp_path: Path):
    trace = _run(True, tmp_path, "stdio_abl")
    ablated = _strip_prov(trace, tmp_path / "stdio_ablated.jsonl")
    report = _report(ablated)
    highs = [f for f in report.findings
             if f.severity == "high" and f.dst_tool == "delete_records"]
    assert highs, (
        "HIGH finding vanished over stdio after stripping provenance_observed  –  "
        f"value-flow layer failed. report={report.as_dict()}"
    )
    f = highs[0]
    assert f.evidence_basis == "value_flow"
    assert f.marker is None
    assert f.matched_value == "STAGING_LOG_20260315"
    assert f.src_privilege == "low" and f.dst_privilege == "high"


def test_stdio_mcp_delete_params_do_not_contain_marker(tmp_path: Path):
    trace = _run(True, tmp_path, "stdio_honesty")
    events = read_trace(trace)
    delete_calls = [e for e in events
                    if e["kind"] == "tool_call" and e["payload"].get("tool") == "delete_records"]
    assert delete_calls, "expected a delete_records tool_call over stdio"
    for ev in delete_calls:
        assert "URD-MARKER-" not in json.dumps(ev["payload"]), (
            "marker leaked into delete_records params over stdio  –  value-flow framing assumes it is stripped"
        )
    # and the injected label DID flow through (the real proof)
    labels = set()
    for ev in delete_calls:
        labels.update(ev["payload"].get("args", {}).get("labels", []))
    assert "STAGING_LOG_20260315" in labels


def test_stdio_mcp_baseline_zero_findings(tmp_path: Path):
    trace = _run(False, tmp_path, "stdio_baseline")
    report = _report(trace)
    assert report.findings == [], (
        f"stdio baseline produced findings: {[f.title for f in report.findings]}"
    )


def test_stdio_marker_seed_controls_child_marker_generation(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setenv("URD_MARKER_SEED", "1337")
    trace1 = _run(True, tmp_path, "stdio_seed_1")
    events1 = read_trace(trace1)
    marker1 = next(e["payload"]["marker"] for e in events1 if e["kind"] == "untrusted_source_emit")

    monkeypatch.setenv("URD_MARKER_SEED", "1337")
    trace2 = _run(True, tmp_path, "stdio_seed_2")
    events2 = read_trace(trace2)
    marker2 = next(e["payload"]["marker"] for e in events2 if e["kind"] == "untrusted_source_emit")

    assert marker1 == marker2

"""Tests for the offensive seam-finder: recon on manifests and captured traces."""
from __future__ import annotations

from pathlib import Path

from lab.mcp_stdio.host_client import run_stdio_scenario
from urd.manifests import load_manifests_dir, ServerManifest, ToolDecl
from urd.runtime import build_observed_graph, ObservedGraph, ValueFlowEdge
from urd.seams import (
    injectable_param_paths,
    find_static_seams,
    confirm_from_trace,
    build_seam_report,
)

ROOT = Path(__file__).resolve().parents[1]
MANIFESTS = ROOT / "lab" / "manifests"

_STR_ARRAY = {"type": "object", "properties": {"labels": {"type": "array", "items": {"type": "string"}}}}
_STR_FIELD = {"type": "object", "properties": {"q": {"type": "string"}}}


def _server(sid: str, priv: str, tools: list[tuple[str, dict]]) -> ServerManifest:
    return ServerManifest(
        server_id=sid, privilege=priv,
        tools=[ToolDecl(name=n, description="", params_schema=s) for n, s in tools],
    )


def test_two_low_sources_same_sink_stay_distinct_and_not_misattributed() -> None:
    # regression for the dedup-key bug: two low-trust servers reaching the same
    # high-trust sink must remain separate seams, and confirming one must not
    # stamp the other as confirmed.
    servers = [
        _server("weather", "low", [("get_weather", _STR_FIELD)]),
        _server("notes", "low", [("get_notes", _STR_FIELD)]),
        _server("admin", "high", [("delete_records", _STR_ARRAY)]),
    ]
    seams = find_static_seams(servers, None)
    del_srcs = {s.source_server for s in seams if s.sink_tool == "delete_records"}
    assert del_srcs == {"weather", "notes"}

    # a value flowed specifically from notes, at a non-zero array index
    edge = ValueFlowEdge(
        src="server:notes", dst="server:admin", matched_value="X", match_type="exact",
        src_event_seq=1, dst_event_seq=2, src_event_kind="tool_result",
        dst_event_kind="tool_call", src_path="q", sink_path="labels[2]",
        dst_tool="delete_records",
    )
    confirmed = confirm_from_trace(seams, servers, ObservedGraph(value_edges=[edge]))

    notes = [s for s in confirmed if s.source_server == "notes" and s.sink_tool == "delete_records"]
    weather = [s for s in confirmed if s.source_server == "weather" and s.sink_tool == "delete_records"]
    assert len(notes) == 1, "must not spawn a duplicate dynamic-only seam"
    assert notes[0].confirmed and notes[0].matched_value == "X"
    assert notes[0].sink_param_path == "labels[2]"  # precise witnessed index, matched via labels[*]
    assert weather and not weather[0].confirmed, "the other source must not be misattributed"


def test_injectable_param_paths_finds_string_array_and_string() -> None:
    schema = {
        "type": "object",
        "properties": {
            "labels": {"type": "array", "items": {"type": "string"}},
            "to": {"type": "string"},
            "count": {"type": "integer"},
        },
    }
    paths = injectable_param_paths(schema)
    assert "labels[*]" in paths  # any element of a string array, index unknown statically
    assert "to" in paths
    assert "count" not in paths  # integers aren't a string-injection sink


def test_injectable_param_paths_tolerates_real_schema_shapes() -> None:
    # implicit object (properties, no type), nullable type list, nested object,
    # oneOf union, tuple-validation array — all common in real manifests
    schema = {
        "properties": {  # implicit object, no "type"
            "recipient": {"type": ["string", "null"]},          # nullable string
            "target": {"properties": {"id": {"type": "string"}}},  # implicit nested object
            "mode": {"oneOf": [{"type": "string"}, {"type": "integer"}]},  # union
        }
    }
    paths = injectable_param_paths(schema)
    assert "recipient" in paths
    assert "target.id" in paths
    assert "mode" in paths           # the string branch of the union
    assert paths.count("mode") == 1  # deduped, not one-per-branch


def test_static_seams_find_weather_to_admin_delete() -> None:
    servers, host = load_manifests_dir(MANIFESTS)
    seams = find_static_seams(servers, host)
    # weather(low) -> admin(high) delete_records(labels[0]) must surface, ranked critical
    hit = [s for s in seams
           if s.source_server == "weather"
           and s.sink_server == "admin"
           and s.sink_tool == "delete_records"
           and s.sink_param_path == "labels[*]"]
    assert hit, "expected the weather->admin delete_records seam"
    assert hit[0].rank == "critical"
    assert hit[0].destructive is True
    assert hit[0].privilege_crossing == "low -> high"
    assert not hit[0].confirmed  # static only, no trace yet


def test_static_seams_do_not_invent_high_to_low() -> None:
    servers, host = load_manifests_dir(MANIFESTS)
    seams = find_static_seams(servers, host)
    # admin is high; it must never appear as a source aiming at a lower sink
    assert all(s.source_server != "admin" for s in seams)


def test_confirm_from_trace_marks_the_fired_seam(tmp_path: Path) -> None:
    trace = tmp_path / "mission.jsonl"
    db = tmp_path / "mission.sqlite"
    run_stdio_scenario(True, trace, db, mission="evidence-delete")

    servers, _ = load_manifests_dir(MANIFESTS)
    observed = build_observed_graph(trace)
    seams = confirm_from_trace(find_static_seams(servers, None), servers, observed)

    confirmed = [s for s in seams if s.confirmed]
    assert confirmed, "the mission should confirm at least one seam"
    top = confirmed[0]
    assert top.sink_tool == "delete_records"
    assert top.matched_value == "STAGING_LOG_20260315"

    report = build_seam_report(seams)
    assert report["confirmed_count"] >= 1
    assert report["critical_count"] >= 1

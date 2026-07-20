"""Tests for the offensive seam-finder: recon on manifests and captured traces."""
from __future__ import annotations

from pathlib import Path

from lab.mcp_stdio.host_client import run_stdio_scenario
from urd.manifests import load_manifests_dir
from urd.runtime import build_observed_graph
from urd.seams import (
    injectable_param_paths,
    find_static_seams,
    confirm_from_trace,
    build_seam_report,
)

ROOT = Path(__file__).resolve().parents[1]
MANIFESTS = ROOT / "lab" / "manifests"


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
    assert "labels[0]" in paths
    assert "to" in paths
    assert "count" not in paths  # integers aren't a string-injection sink


def test_static_seams_find_weather_to_admin_delete() -> None:
    servers, host = load_manifests_dir(MANIFESTS)
    seams = find_static_seams(servers, host)
    # weather(low) -> admin(high) delete_records(labels[0]) must surface, ranked critical
    hit = [s for s in seams
           if s.source_server == "weather"
           and s.sink_server == "admin"
           and s.sink_tool == "delete_records"
           and s.sink_param_path == "labels[0]"]
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

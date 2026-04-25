"""Unit tests for the trace utilities."""
from __future__ import annotations

import json
from pathlib import Path

import pytest

from urd.trace import MARKER_PATTERN, TraceWriter, find_markers, new_marker, read_trace


def test_new_marker_matches_pattern():
    m = new_marker()
    assert MARKER_PATTERN.fullmatch(m), f"marker {m!r} does not match pattern"


def test_new_marker_is_unique():
    a = new_marker()
    b = new_marker()
    assert a != b


def test_find_markers_in_string():
    m = new_marker()
    text = f"leading text {m} trailing text"
    assert find_markers(text) == [m]


def test_find_markers_in_nested_structure():
    a, b = new_marker(), new_marker()
    payload = {
        "outer": {
            "list": [f"contains {a}", {"inner": f"also {b}"}],
        },
        "plain": "nothing here",
    }
    markers = find_markers(payload)
    assert set(markers) == {a, b}


def test_find_markers_dedupes_preserving_order():
    a, b = new_marker(), new_marker()
    payload = [f"first {a}", f"{b}", f"second {a}"]
    assert find_markers(payload) == [a, b]


def test_trace_writer_roundtrip(tmp_path: Path):
    writer = TraceWriter(tmp_path / "trace.jsonl")
    writer.emit(source="a", kind="x", payload={"hello": 1})
    writer.emit(source="b", kind="y", payload={"world": 2})
    events = read_trace(tmp_path / "trace.jsonl")
    assert [e["source"] for e in events] == ["a", "b"]
    assert [e["kind"] for e in events] == ["x", "y"]
    assert [e["seq"] for e in events] == [1, 2]


def test_trace_writer_records_provenance_automatically(tmp_path: Path):
    writer = TraceWriter(tmp_path / "trace.jsonl")
    marker = new_marker()
    writer.emit(source="src", kind="emit", payload={"blob": f"contains {marker}"})
    events = read_trace(tmp_path / "trace.jsonl")
    assert len(events) == 1
    assert events[0]["provenance"] == [marker]

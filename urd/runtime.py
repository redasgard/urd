"""
Runtime analysis: build the observed trust graph from a JSONL trace.

Two propagation signals:
  1. Marker tokens embedded verbatim in payloads.
  2. Extracted labels with marker provenance (via provenance_observed events).
"""
from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from urd.trace import find_markers, read_trace


@dataclass
class MarkerOrigin:
    marker: str
    source: str
    kind: str
    seq: int
    payload_path: str


@dataclass
class ObservedEdge:
    src: str
    dst: str
    marker: str
    src_event_seq: int
    dst_event_seq: int
    dst_tool: str | None = None
    evidence_payload_excerpt: str = ""

    def as_dict(self) -> dict[str, Any]:
        return {
            "src": self.src,
            "dst": self.dst,
            "marker": self.marker,
            "src_event_seq": self.src_event_seq,
            "dst_event_seq": self.dst_event_seq,
            "dst_tool": self.dst_tool,
            "evidence_payload_excerpt": self.evidence_payload_excerpt,
        }


@dataclass
class ObservedGraph:
    edges: list[ObservedEdge] = field(default_factory=list)
    origins: dict[str, MarkerOrigin] = field(default_factory=dict)


def _excerpt(payload: dict[str, Any], marker: str, max_len: int = 140) -> str:
    import json as _json
    text = _json.dumps(payload, separators=(",", ":"))
    idx = text.find(marker)
    if idx < 0:
        return ""
    start = max(0, idx - 40)
    end = min(len(text), idx + len(marker) + 40)
    prefix = "…" if start > 0 else ""
    suffix = "…" if end < len(text) else ""
    return f"{prefix}{text[start:end]}{suffix}"[:max_len + 2]


def _iter_string_values(value: Any) -> list[str]:
    """Collect all string leaves from an arbitrary nested value."""
    out: list[str] = []

    def walk(v: Any) -> None:
        if isinstance(v, str):
            out.append(v)
        elif isinstance(v, dict):
            for x in v.values():
                walk(x)
        elif isinstance(v, (list, tuple)):
            for x in v:
                walk(x)

    walk(value)
    return out


def build_observed_graph(trace_path: Path) -> ObservedGraph:
    events = read_trace(trace_path)
    graph = ObservedGraph()

    last_carrier: dict[str, tuple[str, int]] = {}
    label_provenance: dict[str, list[str]] = {}

    def _edge_component(ev: dict[str, Any]) -> str | None:
        src = ev["source"]
        if src.startswith("untrusted_source:"):
            return src
        if src.startswith("server:"):
            return src
        if ev["kind"] == "tool_call":
            server = ev["payload"].get("server_id")
            if server:
                return f"server:{server}"
        return None

    for ev in events:
        if ev["kind"] == "provenance_observed":
            labels = ev["payload"].get("extracted_labels", []) or []
            markers = ev["payload"].get("observed_markers", []) or []
            for lbl in labels:
                label_provenance.setdefault(lbl, []).extend(markers)
            continue

        markers_here = list(ev.get("provenance", []) or find_markers(ev.get("payload", {})))

        # Synthetic marker detection via label propagation: if a tool_call's
        # args contain a label that was previously extracted alongside a marker,
        # treat that marker as present here for edge purposes.
        if ev["kind"] == "tool_call":
            args = ev["payload"].get("args", {}) or {}
            for arg_value in _iter_string_values(args):
                if arg_value in label_provenance:
                    for m in label_provenance[arg_value]:
                        if m not in markers_here:
                            markers_here.append(m)

        if not markers_here:
            continue

        component = _edge_component(ev)
        seq = ev["seq"]

        for marker in markers_here:
            if marker not in graph.origins:
                graph.origins[marker] = MarkerOrigin(
                    marker=marker,
                    source=ev["source"],
                    kind=ev["kind"],
                    seq=seq,
                    payload_path=ev["kind"],
                )
                if component is not None:
                    last_carrier[marker] = (component, seq)
                continue

            if component is None:
                continue

            prev = last_carrier.get(marker)
            if prev is None:
                last_carrier[marker] = (component, seq)
                continue

            prev_carrier, prev_seq = prev
            if prev_carrier != component:
                dst_tool = ev["payload"].get("tool") if ev["kind"] == "tool_call" else None
                graph.edges.append(
                    ObservedEdge(
                        src=prev_carrier,
                        dst=component,
                        marker=marker,
                        src_event_seq=prev_seq,
                        dst_event_seq=seq,
                        dst_tool=dst_tool,
                        evidence_payload_excerpt=_excerpt(ev["payload"], marker),
                    )
                )
                last_carrier[marker] = (component, seq)

    return graph
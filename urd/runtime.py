"""
Runtime analysis: build the observed trust graph from a JSONL trace.

The core technique is marker-token propagation. When the untrusted source emits a value,
it attaches a unique marker. When that marker appears in a subsequent tool_call payload,
we have hard evidence that the upstream output influenced the downstream call.

This is deliberate: it removes any argument about intent or interpretation. Either the
marker is present in downstream parameters (observed edge exists) or it is not.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from urd.trace import find_markers, read_trace


@dataclass
class MarkerOrigin:
    """Where a marker token was first observed."""
    marker: str
    source: str           # e.g. "server:weather" or "untrusted_source:feed"
    kind: str             # event kind at origin
    seq: int
    payload_path: str     # shallow indication of where in payload it appeared


@dataclass
class ObservedEdge:
    """A cross-component authority edge reconstructed from the trace."""
    src: str                      # originating component (where the marker first appeared)
    dst: str                      # destination component (where it next appeared)
    marker: str                   # the specific marker token that traveled
    src_event_seq: int
    dst_event_seq: int
    dst_tool: str | None = None   # when dst is a tool_call, which tool
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
    """Find a short substring of the payload containing the marker for evidence."""
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


def build_observed_graph(trace_path: Path) -> ObservedGraph:
    """Reconstruct the observed trust graph from a single JSONL trace file.

    Authority edges are recorded between servers and external sources. Host-internal
    carriage of a marker (context updates, param construction, etc.) is not modeled
    as an authority edge by itself — the host is the compositor, not an authority.
    We track the most recent *server-or-external* carrier of each marker, so a path
    like `untrusted -> weather -> host -> admin` collapses into two edges
    `untrusted -> weather` and `weather -> admin`.
    """
    events = read_trace(trace_path)
    graph = ObservedGraph()

    # Per-marker rolling state: the last server/external component that carried the
    # marker. Host-internal events update provenance awareness but do not reset the
    # carrier.
    last_carrier: dict[str, tuple[str, int]] = {}

    def _edge_component(ev: dict[str, Any]) -> str | None:
        """Return a server/external component id for edge purposes, or None for
        host-internal events that should not be treated as carriers."""
        src = ev["source"]
        if src.startswith("untrusted_source:"):
            return src
        if src.startswith("server:"):
            return src
        # tool_call events emitted by the host count as reaching the destination server
        if ev["kind"] == "tool_call":
            server = ev["payload"].get("server_id")
            if server:
                return f"server:{server}"
        return None

    for ev in events:
        markers_here = ev.get("provenance", []) or find_markers(ev.get("payload", {}))
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
                # host-internal event carrying a known marker; don't treat as authority hop
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

"""
Runtime analysis: build the observed trust graph from a JSONL trace.

Urd reconstructs cross-server authority flow from raw observed message flow.
There are two independent evidence layers, in increasing order of strength:

  1. Marker propagation (instrumentation / ground truth).
     A unique URD-MARKER token injected by the lab's untrusted source and tracked
     verbatim through the trace. Markers exist ONLY to give the lab byte-level
     ground truth; detection of the offensive authority path does not depend on
     them. See `_build_marker_edges`.

  2. Value-flow taint (the load-bearing, marker-independent proof).
     A string emitted in a low-trust `tool_result` payload that is later reused,
     verbatim or normalized, as an argument to a high-privilege `tool_call`.
     This requires no marker and no cooperation from the host. It is the evidence
     that survives when the host's optional provenance metadata is stripped.
     See `_build_value_flow_edges`.

The privilege of each component is NOT decided here  –  runtime stays
privilege-agnostic and emits edges. `urd.divergence` applies the privilege model
and decides severity.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Iterator

from urd.trace import MARKER_PATTERN, find_markers, read_trace


# --------------------------------------------------------------------------- #
# Marker-based edges (instrumentation layer)
# --------------------------------------------------------------------------- #
@dataclass
class MarkerOrigin:
    marker: str
    source: str
    kind: str
    seq: int
    payload_path: str


@dataclass
class ObservedEdge:
    """A cross-component edge witnessed via verbatim marker propagation."""
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


# --------------------------------------------------------------------------- #
# Value-flow edges (marker-independent layer  –  the real proof)
# --------------------------------------------------------------------------- #
MIN_TAINT_LEN = 6  # ignore short/common fragments; STAGING_LOG_* is 20 chars
_TOKEN_RE = re.compile(r"[^\s\[\]{}(),\"']+")
# match types in descending strength
_MATCH_STRENGTH = {"exact": 3, "tainted_token_in_arg": 2, "arg_in_tainted_value": 1}


@dataclass
class ValueFlowEdge:
    """A cross-server edge witnessed because a value emitted by `src` reappears
    in a tool_call argument sent to `dst`  –  no marker required."""
    src: str                 # component, e.g. "server:weather"
    dst: str                 # component, e.g. "server:admin"
    matched_value: str       # the verbatim value that flowed
    match_type: str          # exact | tainted_token_in_arg | arg_in_tainted_value
    src_event_seq: int
    dst_event_seq: int
    src_event_kind: str      # e.g. "tool_result"
    dst_event_kind: str      # e.g. "tool_call"
    src_path: str            # where in the source payload the value was emitted
    sink_path: str           # where in the destination args the value landed
    dst_tool: str | None = None
    evidence_excerpt: str = ""

    def as_dict(self) -> dict[str, Any]:
        return {
            "src": self.src,
            "dst": self.dst,
            "matched_value": self.matched_value,
            "match_type": self.match_type,
            "src_event_seq": self.src_event_seq,
            "dst_event_seq": self.dst_event_seq,
            "src_event_kind": self.src_event_kind,
            "dst_event_kind": self.dst_event_kind,
            "src_path": self.src_path,
            "sink_path": self.sink_path,
            "dst_tool": self.dst_tool,
            "evidence_excerpt": self.evidence_excerpt,
        }


@dataclass
class TaintValue:
    value: str
    src_server: str
    src_seq: int
    src_kind: str
    src_path: str


@dataclass
class ObservedGraph:
    edges: list[ObservedEdge] = field(default_factory=list)          # marker edges
    value_edges: list[ValueFlowEdge] = field(default_factory=list)   # value-flow edges
    origins: dict[str, MarkerOrigin] = field(default_factory=dict)
    # (server_id, tool) -> whether the approval surface exposed upstream origin
    approval_provenance: dict[tuple[str, str], bool] = field(default_factory=dict)
    operation_impacts: list[dict[str, Any]] = field(default_factory=list)


# --------------------------------------------------------------------------- #
# Shared helpers
# --------------------------------------------------------------------------- #
def _excerpt(payload: dict[str, Any], needle: str, max_len: int = 140) -> str:
    import json as _json
    text = _json.dumps(payload, separators=(",", ":"))
    idx = text.find(needle)
    if idx < 0:
        return ""
    start = max(0, idx - 40)
    end = min(len(text), idx + len(needle) + 40)
    prefix = "…" if start > 0 else ""
    suffix = "…" if end < len(text) else ""
    return f"{prefix}{text[start:end]}{suffix}"[: max_len + 2]


def _iter_string_values(value: Any) -> list[str]:
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


def _walk_paths(value: Any, prefix: str = "") -> Iterator[tuple[str, str]]:
    """Yield (json-ish path, string leaf) for every string in a nested value."""
    if isinstance(value, str):
        yield (prefix or "<root>", value)
    elif isinstance(value, dict):
        for k, v in value.items():
            child = f"{prefix}.{k}" if prefix else str(k)
            yield from _walk_paths(v, child)
    elif isinstance(value, (list, tuple)):
        for i, v in enumerate(value):
            yield from _walk_paths(v, f"{prefix}[{i}]")


def _strip_markers(text: str) -> str:
    return MARKER_PATTERN.sub("", text)


def _norm(s: str) -> str:
    return _strip_markers(s).strip().casefold()


def _component_of(ev: dict[str, Any]) -> str | None:
    src = ev.get("source", "")
    if src.startswith("untrusted_source:") or src.startswith("server:"):
        return src
    if ev["kind"] == "tool_call":
        server = ev["payload"].get("server_id")
        if server:
            return f"server:{server}"
    return None


def _result_server(ev: dict[str, Any]) -> str | None:
    src = ev.get("source", "")
    if src.startswith("server:"):
        return src.split(":", 1)[1]
    return ev.get("payload", {}).get("server_id")


# --------------------------------------------------------------------------- #
# Value-flow reconstruction
# --------------------------------------------------------------------------- #
def _collect_taint(events: list[dict[str, Any]]) -> list[TaintValue]:
    """Index candidate tainted strings emitted by every `tool_result`.

    Both whole string leaves and the distinctive tokens inside them are indexed,
    so a value can be matched whether it lands as a full argument or as a
    substring of a larger emitted blob. URD markers are stripped so this layer is
    genuinely marker-independent.
    """
    taint: list[TaintValue] = []
    seen: set[tuple[str, str, str]] = set()  # (value, server, path) dedupe

    for ev in events:
        if ev.get("kind") != "tool_result":
            continue
        server = _result_server(ev)
        if not server:
            continue
        seq = ev["seq"]
        for path, leaf in _walk_paths(ev.get("payload", {})):
            clean_leaf = _strip_markers(leaf).strip()
            candidates = {clean_leaf} | set(_TOKEN_RE.findall(clean_leaf))
            for cand in candidates:
                cand = cand.strip()
                if len(cand) < MIN_TAINT_LEN:
                    continue
                key = (cand, server, path)
                if key in seen:
                    continue
                seen.add(key)
                taint.append(
                    TaintValue(value=cand, src_server=server, src_seq=seq,
                               src_kind="tool_result", src_path=path)
                )
    return taint


def _best_match(arg: str, taint: list[TaintValue]) -> dict[str, TaintValue | str]:
    """Return the strongest match per source server for one argument string."""
    narg = _norm(arg)
    if len(narg) < MIN_TAINT_LEN:
        return {}
    best: dict[str, tuple[int, str, TaintValue]] = {}
    for tv in taint:
        nval = _norm(tv.value)
        if len(nval) < MIN_TAINT_LEN:
            continue
        if narg == nval:
            mtype = "exact"
        elif nval in narg:
            mtype = "tainted_token_in_arg"
        elif narg in nval:
            mtype = "arg_in_tainted_value"
        else:
            continue
        strength = _MATCH_STRENGTH[mtype]
        cur = best.get(tv.src_server)
        # prefer higher strength, then earlier source seq
        if cur is None or strength > cur[0] or (strength == cur[0] and tv.src_seq < cur[2].src_seq):
            best[tv.src_server] = (strength, mtype, tv)
    return {srv: (mtype, tv) for srv, (_, mtype, tv) in best.items()}


def _build_value_flow_edges(events: list[dict[str, Any]]) -> list[ValueFlowEdge]:
    taint = _collect_taint(events)
    edges: list[ValueFlowEdge] = []
    emitted: set[tuple[str, str, str, str]] = set()  # (src,dst,value,sink_path) dedupe

    for ev in events:
        if ev.get("kind") != "tool_call":
            continue
        dst_server = ev["payload"].get("server_id")
        if not dst_server:
            continue
        dst_component = f"server:{dst_server}"
        dst_tool = ev["payload"].get("tool")
        args = ev["payload"].get("args", {}) or {}

        for sink_path, arg in _walk_paths(args):
            for src_server, (mtype, tv) in _best_match(arg, taint).items():
                if src_server == dst_server:
                    continue  # a server echoing its own output is not compositional
                key = (src_server, dst_server, tv.value, sink_path)
                if key in emitted:
                    continue
                emitted.add(key)
                edges.append(
                    ValueFlowEdge(
                        src=f"server:{src_server}",
                        dst=dst_component,
                        matched_value=tv.value,
                        match_type=mtype,
                        src_event_seq=tv.src_seq,
                        dst_event_seq=ev["seq"],
                        src_event_kind=tv.src_kind,
                        dst_event_kind="tool_call",
                        src_path=tv.src_path,
                        sink_path=sink_path,
                        dst_tool=dst_tool,
                        evidence_excerpt=_excerpt(ev["payload"], arg),
                    )
                )
    return edges


# --------------------------------------------------------------------------- #
# Marker reconstruction (unchanged behavior, isolated)
# --------------------------------------------------------------------------- #
def _build_marker_edges(events: list[dict[str, Any]], graph: ObservedGraph) -> None:
    last_carrier: dict[str, tuple[str, int]] = {}
    label_provenance: dict[str, list[str]] = {}

    for ev in events:
        if ev["kind"] == "provenance_observed":
            labels = ev["payload"].get("extracted_labels", []) or []
            markers = ev["payload"].get("observed_markers", []) or []
            for lbl in labels:
                label_provenance.setdefault(lbl, []).extend(markers)
            continue

        markers_here = list(ev.get("provenance", []) or find_markers(ev.get("payload", {})))

        if ev["kind"] == "tool_call":
            args = ev["payload"].get("args", {}) or {}
            for arg_value in _iter_string_values(args):
                if arg_value in label_provenance:
                    for m in label_provenance[arg_value]:
                        if m not in markers_here:
                            markers_here.append(m)

        if not markers_here:
            continue

        component = _component_of(ev)
        seq = ev["seq"]

        for marker in markers_here:
            if marker not in graph.origins:
                graph.origins[marker] = MarkerOrigin(
                    marker=marker, source=ev["source"], kind=ev["kind"],
                    seq=seq, payload_path=ev["kind"],
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
                        src=prev_carrier, dst=component, marker=marker,
                        src_event_seq=prev_seq, dst_event_seq=seq,
                        dst_tool=dst_tool,
                        evidence_payload_excerpt=_excerpt(ev["payload"], marker),
                    )
                )
                last_carrier[marker] = (component, seq)


def _build_approval_index(events: list[dict[str, Any]], graph: ObservedGraph) -> None:
    """Record, per (server, tool), whether the approval surface exposed origin."""
    origin_keys = {"provenance", "source", "sources", "origin",
                   "sourced_from", "upstream", "derived_from"}
    for ev in events:
        if ev.get("kind") != "approval_shown":
            continue
        payload = ev.get("payload", {})
        server = payload.get("server_id")
        tool = payload.get("tool")
        if not server or not tool:
            continue
        # exposed if any origin-ish key appears anywhere in the prompt payload
        def has_origin(node: Any) -> bool:
            if isinstance(node, dict):
                if origin_keys & set(node.keys()):
                    return True
                return any(has_origin(v) for v in node.values())
            if isinstance(node, (list, tuple)):
                return any(has_origin(x) for x in node)
            return False

        graph.approval_provenance[(server, tool)] = has_origin(payload)


def _build_impact_index(events: list[dict[str, Any]], graph: ObservedGraph) -> None:
    for ev in events:
        if ev.get("kind") != "tool_execution":
            continue
        payload = ev.get("payload", {})
        impact = payload.get("impact")
        if not isinstance(impact, dict):
            continue
        graph.operation_impacts.append({
            "seq": ev.get("seq"),
            "source": ev.get("source"),
            "server_id": payload.get("server_id"),
            "tool": payload.get("tool"),
            **impact,
        })


def build_observed_graph(trace_path: Path) -> ObservedGraph:
    events = read_trace(trace_path)
    graph = ObservedGraph()
    _build_marker_edges(events, graph)
    graph.value_edges = _build_value_flow_edges(events)
    _build_approval_index(events, graph)
    _build_impact_index(events, graph)
    return graph

"""
Divergence analysis: compare declared graph to observed graph, emit findings.

A finding is an observed cross-component authority path not supported by any
declared edge  –  especially one crossing a privilege boundary (low-trust output
shaping a high-privilege destructive call).

Each finding carries an `evidence_basis`:

  * "value_flow"         –  proven by marker-independent value reuse. Survives with
                          zero host cooperation. This is the load-bearing proof.
  * "marker"             –  proven only by verbatim marker propagation (lab ground
                          truth / optional instrumentation).
  * "marker+value_flow"  –  corroborated by both layers.

The headline compositional finding (low-trust output -> high-priv destructive
argument) must reach severity "high" on the value-flow layer alone. Stripping the
host's optional `provenance_observed` metadata removes the marker corroboration
but MUST NOT remove the finding.
"""
from __future__ import annotations

from dataclasses import dataclass, field, asdict
from typing import Any, Literal

from urd.manifests import DeclaredGraph
from urd.runtime import ObservedGraph, ObservedEdge, ValueFlowEdge
from urd.heuristics import is_destructive as _is_destructive


Severity = Literal["info", "low", "medium", "high"]
Basis = Literal["value_flow", "marker", "marker+value_flow"]

# destructive-sink heuristic is shared with find-seams (urd.heuristics) so the
# two tools never give contradictory verdicts on the same target. It enriches
# the finding; severity is driven by the privilege crossing, not this set.


@dataclass
class Finding:
    finding_id: str
    severity: Severity
    title: str
    description: str
    evidence_basis: Basis
    src: str | None
    dst: str | None
    src_server: str | None
    dst_server: str | None
    dst_tool: str | None
    src_privilege: str | None
    dst_privilege: str | None
    src_event_kind: str | None
    dst_event_kind: str | None
    src_path: str | None
    sink_path: str | None
    matched_value: str | None
    match_type: str | None
    marker: str | None
    approval_provenance_status: str  # "absent" | "present" | "unknown"
    impact: dict[str, Any] | None = None
    observed_edge: dict[str, Any] = field(default_factory=dict)

    def as_dict(self) -> dict[str, Any]:
        return asdict(self)


def _server_id_from_source(source: str) -> str | None:
    if source.startswith("server:"):
        return source.split(":", 1)[1]
    return None


def _privilege_rank(priv: str | None) -> int:
    return {"low": 1, "medium": 2, "high": 3}.get(priv or "", 0)


def _tool_suffix(dst_tool: str | None) -> str:
    return f":{dst_tool}" if dst_tool else ""


def _approval_status(observed: ObservedGraph, server: str | None, tool: str | None) -> str:
    if not server or not tool:
        return "unknown"
    exposed = observed.approval_provenance.get((server, tool))
    if exposed is None:
        return "unknown"
    return "present" if exposed else "absent"


# --------------------------------------------------------------------------- #
# Raw finding records (pre-merge), keyed so the two layers can corroborate
# --------------------------------------------------------------------------- #
@dataclass
class _Raw:
    basis: Basis
    severity: Severity
    src: str
    dst: str
    src_server: str | None
    dst_server: str | None
    dst_tool: str | None
    src_priv: str | None
    dst_priv: str | None
    src_event_kind: str | None
    dst_event_kind: str | None
    src_path: str | None
    sink_path: str | None
    matched_value: str | None
    match_type: str | None
    marker: str | None
    observed_edge: dict[str, Any]
    crosses_priv: bool
    untrusted_ingress: bool
    destructive: bool


def _key(src_server: str | None, src: str, dst_server: str | None, dst_tool: str | None):
    # untrusted ingress has no src_server; key on the raw src tag so it stays distinct
    return (src_server or src, dst_server, dst_tool)


def _raw_from_value_edge(e: ValueFlowEdge, declared: DeclaredGraph) -> _Raw:
    src_server = _server_id_from_source(e.src)
    dst_server = _server_id_from_source(e.dst)
    src_priv = declared.privilege_of(src_server) if src_server else None
    dst_priv = declared.privilege_of(dst_server) if dst_server else None
    crosses = (src_priv is not None and dst_priv is not None
               and _privilege_rank(dst_priv) > _privilege_rank(src_priv))
    destructive = _is_destructive(e.dst_tool)
    if crosses and dst_priv == "high":
        sev: Severity = "high"
    elif crosses:
        sev = "medium"
    else:
        sev = "low"
    return _Raw(
        basis="value_flow", severity=sev, src=e.src, dst=e.dst,
        src_server=src_server, dst_server=dst_server, dst_tool=e.dst_tool,
        src_priv=src_priv, dst_priv=dst_priv,
        src_event_kind=e.src_event_kind, dst_event_kind=e.dst_event_kind,
        src_path=e.src_path, sink_path=e.sink_path,
        matched_value=e.matched_value, match_type=e.match_type, marker=None,
        observed_edge=e.as_dict(), crosses_priv=crosses,
        untrusted_ingress=False, destructive=destructive,
    )


def _raw_from_marker_edge(e: ObservedEdge, declared: DeclaredGraph) -> _Raw | None:
    src_server = _server_id_from_source(e.src)
    dst_server = _server_id_from_source(e.dst)
    untrusted = e.src.startswith("untrusted_source:")

    # edge internal to host with no untrusted source -> not compositional
    if src_server is None and dst_server is None and not untrusted:
        return None
    # edges within a single server aren't compositional
    if src_server is not None and src_server == dst_server:
        return None
    # destination must be a server (an acted-upon authority sink)
    if dst_server is None:
        return None

    src_priv = declared.privilege_of(src_server) if src_server else None
    dst_priv = declared.privilege_of(dst_server) if dst_server else None
    crosses = (src_priv is not None and dst_priv is not None
               and _privilege_rank(dst_priv) > _privilege_rank(src_priv))
    destructive = _is_destructive(e.dst_tool)

    if untrusted and dst_priv == "high":
        sev: Severity = "high"
    elif crosses:
        sev = "high"
    elif untrusted:
        sev = "medium"
    else:
        sev = "medium"

    return _Raw(
        basis="marker", severity=sev, src=e.src, dst=e.dst,
        src_server=src_server, dst_server=dst_server, dst_tool=e.dst_tool,
        src_priv=src_priv, dst_priv=dst_priv,
        src_event_kind=None, dst_event_kind="tool_call" if e.dst_tool else None,
        src_path=None, sink_path=None,
        matched_value=None, match_type=None, marker=e.marker,
        observed_edge=e.as_dict(), crosses_priv=crosses,
        untrusted_ingress=untrusted, destructive=destructive,
    )


def _merge(a: _Raw, b: _Raw) -> _Raw:
    """Combine a value-flow raw and a marker raw for the same authority path."""
    value = a if a.basis == "value_flow" else b
    marker = b if a.basis == "value_flow" else a
    merged_edge = {"value_flow": value.observed_edge, "marker": marker.observed_edge}
    return _Raw(
        basis="marker+value_flow",
        severity=value.severity if _sev_rank(value.severity) >= _sev_rank(marker.severity) else marker.severity,
        src=value.src, dst=value.dst,
        src_server=value.src_server, dst_server=value.dst_server, dst_tool=value.dst_tool,
        src_priv=value.src_priv, dst_priv=value.dst_priv,
        src_event_kind=value.src_event_kind, dst_event_kind=value.dst_event_kind,
        src_path=value.src_path, sink_path=value.sink_path,
        matched_value=value.matched_value, match_type=value.match_type,
        marker=marker.marker, observed_edge=merged_edge,
        crosses_priv=value.crosses_priv or marker.crosses_priv,
        untrusted_ingress=value.untrusted_ingress or marker.untrusted_ingress,
        destructive=value.destructive or marker.destructive,
    )


def _sev_rank(s: Severity) -> int:
    return {"info": 0, "low": 1, "medium": 2, "high": 3}[s]


def _impact_for(observed: ObservedGraph, raw: _Raw) -> dict[str, Any] | None:
    if not raw.dst_server or not raw.dst_tool:
        return None
    for impact in observed.operation_impacts:
        if impact.get("server_id") != raw.dst_server or impact.get("tool") != raw.dst_tool:
            continue
        labels = impact.get("removed_labels") or []
        if raw.matched_value is None or raw.matched_value in labels:
            return {
                "state_changed": bool(impact.get("state_changed")),
                "operation": impact.get("operation"),
                "protected_records_removed": int(impact.get("protected_records_removed") or 0),
                "removed_labels": labels,
                "removed_categories": impact.get("removed_categories") or [],
                "breach_objective": impact.get("breach_objective"),
            }
    return None


def _render(raw: _Raw, fid: str, approval_status: str, impact: dict[str, Any] | None = None) -> Finding:
    suffix = _tool_suffix(raw.dst_tool)
    basis_note = {
        "value_flow": "Proven by marker-independent value-flow reconstruction (no host cooperation required).",
        "marker": "Witnessed via verbatim marker propagation (instrumentation layer).",
        "marker+value_flow": "Corroborated by both value-flow reconstruction and verbatim marker propagation.",
    }[raw.basis]

    if raw.crosses_priv and raw.dst_priv == "high":
        title = (f"Low-trust output selected a protected record for high-privilege deletion: "
                 f"{raw.src_server} → {raw.dst_server}{suffix}") if (impact and impact.get("protected_records_removed", 0) > 0) else (f"Low-trust output reused as high-privilege "
                 f"{'destructive ' if raw.destructive else ''}parameter: "
                 f"{raw.src_server} → {raw.dst_server}{suffix}")
        flow = (f"Value {raw.matched_value!r} emitted by {raw.src} "
                f"(privilege={raw.src_priv}) at its {raw.src_event_kind} "
                f"reappeared at {raw.sink_path} of a {raw.dst_event_kind} to "
                f"{raw.dst}{suffix} (privilege={raw.dst_priv}), match={raw.match_type}. "
                if raw.basis != "marker"
                else f"Marker {raw.marker} propagated from {raw.src} (privilege={raw.src_priv}) "
                     f"into a tool_call on {raw.dst}{suffix} (privilege={raw.dst_priv}). ")
        description = (
            flow
            + "A lower-privilege server's output shaped the parameters of a higher-privilege "
            + ("destructive " if raw.destructive else "")
            + "operation. No declared edge governs this authority flow. "
            + f"Approval surface origin disclosure: {approval_status}. "
            + ((f"Impact: protected_records_removed={impact.get('protected_records_removed')}, "
                f"removed_categories={impact.get('removed_categories')}, "
                f"breach_objective={impact.get('breach_objective')}. ") if impact else "")
            + basis_note
        )
    elif raw.untrusted_ingress and raw.dst_priv == "high":
        title = (f"Untrusted external data reached high-privilege tool call: "
                 f"{raw.src} → {raw.dst}{suffix}")
        description = (
            f"Marker {raw.marker} originated at {raw.src} (external/untrusted) and reached a "
            f"tool_call on {raw.dst}{suffix} (privilege={raw.dst_priv}). "
            f"Approval surface origin disclosure: {approval_status}. " + basis_note
        )
    elif raw.untrusted_ingress:
        title = (f"Untrusted external data reached a server tool call: "
                 f"{raw.src} → {raw.dst}{suffix}")
        description = (
            f"Marker {raw.marker} originated at {raw.src} (external/untrusted) and reached "
            f"{raw.dst}{suffix} (privilege={raw.dst_priv}). " + basis_note
        )
    else:
        title = (f"Undeclared cross-server authority edge: "
                 f"{raw.src_server} → {raw.dst_server}{suffix}")
        ref = (f"Value {raw.matched_value!r}" if raw.basis != "marker"
               else f"Marker {raw.marker}")
        description = (
            f"{ref} propagated from {raw.src} into a tool_call on {raw.dst}{suffix}. "
            f"No manifest declares this influence path. "
            f"Approval surface origin disclosure: {approval_status}. " + basis_note
        )

    return Finding(
        finding_id=fid, severity=raw.severity, title=title, description=description,
        evidence_basis=raw.basis, src=raw.src, dst=raw.dst,
        src_server=raw.src_server, dst_server=raw.dst_server, dst_tool=raw.dst_tool,
        src_privilege=raw.src_priv, dst_privilege=raw.dst_priv,
        src_event_kind=raw.src_event_kind, dst_event_kind=raw.dst_event_kind,
        src_path=raw.src_path, sink_path=raw.sink_path,
        matched_value=raw.matched_value, match_type=raw.match_type, marker=raw.marker,
        approval_provenance_status=approval_status, impact=impact, observed_edge=raw.observed_edge,
    )


def compute_findings(declared: DeclaredGraph, observed: ObservedGraph) -> list[Finding]:
    value_raws = [_raw_from_value_edge(e, declared) for e in observed.value_edges]
    marker_raws = [r for r in (_raw_from_marker_edge(e, declared) for e in observed.edges) if r]

    # merge corroborating layers on the same authority path
    by_key: dict[Any, _Raw] = {}
    order: list[Any] = []

    def absorb(raw: _Raw) -> None:
        k = _key(raw.src_server, raw.src, raw.dst_server, raw.dst_tool)
        if k in by_key:
            by_key[k] = _merge(by_key[k], raw)
        else:
            by_key[k] = raw
            order.append(k)

    for r in value_raws:   # value layer first so it leads on merge
        absorb(r)
    for r in marker_raws:
        absorb(r)

    findings: list[Finding] = []
    counter = 0
    for k in order:
        raw = by_key[k]
        counter += 1
        fid = f"URD-{counter:04d}"
        status = _approval_status(observed, raw.dst_server, raw.dst_tool)
        impact = _impact_for(observed, raw)
        findings.append(_render(raw, fid, status, impact))

    # strongest first
    findings.sort(key=lambda f: _sev_rank(f.severity), reverse=True)
    for i, f in enumerate(findings, 1):
        f.finding_id = f"URD-{i:04d}"
    return findings


@dataclass
class DivergenceReport:
    declared_edge_count: int
    observed_edge_count: int
    value_flow_edge_count: int
    findings: list[Finding]

    def as_dict(self) -> dict[str, Any]:
        return {
            "declared_edge_count": self.declared_edge_count,
            "observed_edge_count": self.observed_edge_count,
            "value_flow_edge_count": self.value_flow_edge_count,
            "findings": [f.as_dict() for f in self.findings],
        }


def build_report(declared: DeclaredGraph, observed: ObservedGraph) -> DivergenceReport:
    findings = compute_findings(declared, observed)
    return DivergenceReport(
        declared_edge_count=len(declared.edges),
        observed_edge_count=len(observed.edges),
        value_flow_edge_count=len(observed.value_edges),
        findings=findings,
    )


def to_dot(declared: DeclaredGraph, observed: ObservedGraph, findings: list[Finding]) -> str:
    """Declared edges black; marker edges orange; value-flow edges purple.
    Edges belonging to a HIGH finding are drawn bold."""
    lines = ["digraph urd {", "  rankdir=LR;", '  node [shape=box, fontname="Helvetica"];']

    if declared.host is not None:
        lines.append(f'  "{declared.host.host_id}" [shape=hexagon, style=filled, fillcolor="#dbeafe"];')
    for srv in declared.servers.values():
        color = {"low": "#dcfce7", "medium": "#fef9c3", "high": "#fee2e2"}.get(srv.privilege, "#f3f4f6")
        lines.append(f'  "{srv.server_id}" [style=filled, fillcolor="{color}", '
                     f'label="{srv.server_id}\\n[{srv.privilege}]"];')

    for e in declared.edges:
        if e.kind == "host->server":
            lines.append(f'  "{e.src}" -> "{e.dst}" [color=black, label="declared"];')

    high_pairs = {(f.src_server or f.src, f.dst_server, f.dst_tool)
                  for f in findings if f.severity == "high"}

    def bare(c: str) -> str:
        return c.split(":", 1)[1] if c.startswith("server:") else c

    for edge in observed.edges:  # marker edges
        is_high = (_server_id_from_source(edge.src) or edge.src, _server_id_from_source(edge.dst),
                   edge.dst_tool) in high_pairs
        pw = "2.5" if is_high else "1.2"
        suffix = f"\\n{edge.dst_tool}" if edge.dst_tool else ""
        lines.append(f'  "{bare(edge.src)}" -> "{bare(edge.dst)}" '
                     f'[color=orange, penwidth={pw}, style=dashed, label="marker{suffix}"];')

    for ve in observed.value_edges:  # value-flow edges (the real proof)
        is_high = (_server_id_from_source(ve.src), _server_id_from_source(ve.dst),
                   ve.dst_tool) in high_pairs
        pw = "3.0" if is_high else "1.5"
        suffix = f"\\n{ve.dst_tool}" if ve.dst_tool else ""
        lines.append(f'  "{bare(ve.src)}" -> "{bare(ve.dst)}" '
                     f'[color=purple, penwidth={pw}, style=bold, label="value-flow{suffix}"];')

    lines.append("}")
    return "\n".join(lines)

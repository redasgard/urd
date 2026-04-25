"""
Divergence analysis: compare declared graph to observed graph, emit findings.

A finding is an observed edge whose existence is not supported by any declared edge,
especially when the edge crosses a privilege boundary (low-priv server's output
influencing high-priv server's execution).
"""
from __future__ import annotations

from dataclasses import dataclass, asdict
from typing import Any, Literal

from urd.manifests import DeclaredGraph
from urd.runtime import ObservedGraph, ObservedEdge


Severity = Literal["info", "low", "medium", "high"]


@dataclass
class Finding:
    finding_id: str
    severity: Severity
    title: str
    description: str
    observed_edge: dict[str, Any]
    src_privilege: str | None
    dst_privilege: str | None

    def as_dict(self) -> dict[str, Any]:
        return asdict(self)


def _server_id_from_source(source: str) -> str | None:
    """Extract bare server id from a source tag like 'server:weather'."""
    if source.startswith("server:"):
        return source.split(":", 1)[1]
    return None


def _privilege_rank(priv: str | None) -> int:
    return {"low": 1, "medium": 2, "high": 3}.get(priv or "", 0)


def compute_findings(declared: DeclaredGraph, observed: ObservedGraph) -> list[Finding]:
    """Walk observed edges, emit findings for authority paths not covered by the
    declared graph.

    Three relevant categories:

    1. server-to-server, low->high privilege: the headline compositional failure
    2. untrusted_source -> server: untrusted external data reaching any server
    3. any other undeclared cross-component edge involving a server
    """
    findings: list[Finding] = []
    counter = 0

    for edge in observed.edges:
        src_server = _server_id_from_source(edge.src)
        dst_server = _server_id_from_source(edge.dst)

        # ignore edges entirely within the host (e.g. context_update -> param_construction)
        if src_server is None and dst_server is None:
            if not edge.src.startswith("untrusted_source:"):
                continue

        # edges internal to a single server aren't compositional failures
        if src_server is not None and src_server == dst_server:
            continue

        # edges whose destination is not a server (e.g. reaching the host) are
        # not acted-upon authority flows in our model; skip them
        if dst_server is None:
            continue

        src_priv = declared.privilege_of(src_server) if src_server else None
        dst_priv = declared.privilege_of(dst_server) if dst_server else None

        counter += 1
        fid = f"URD-{counter:04d}"

        is_untrusted_ingress = edge.src.startswith("untrusted_source:")
        crosses_privilege = (
            src_priv is not None
            and dst_priv is not None
            and _privilege_rank(dst_priv) > _privilege_rank(src_priv)
        )

        if is_untrusted_ingress and dst_priv == "high":
            severity: Severity = "high"
            title = (
                f"Untrusted external data reached high-privilege tool call: "
                f"{edge.src} → {edge.dst}:{edge.dst_tool}"
            )
            description = (
                f"Marker {edge.marker} originated at {edge.src} (external/untrusted) and "
                f"appeared verbatim in a tool_call to {edge.dst}:{edge.dst_tool} "
                f"(privilege={dst_priv}). Data from an untrusted external source shaped the "
                f"parameters of a destructive operation, and no declared edge governs this "
                f"authority flow. The approval surface did not expose the marker's origin."
            )
        elif crosses_privilege:
            severity = "high"
            title = (
                f"Low-privilege server output shaped high-privilege tool call: "
                f"{src_server} → {dst_server}:{edge.dst_tool}"
            )
            description = (
                f"Marker {edge.marker} propagated from {edge.src} (privilege={src_priv}) "
                f"to a tool_call on {edge.dst}:{edge.dst_tool} (privilege={dst_priv}). "
                f"The downstream tool's parameters were shaped by upstream output from a "
                f"lower-privilege server. No declared edge governs this authority flow, "
                f"and the approval surface did not expose the marker's provenance."
            )
        elif is_untrusted_ingress:
            severity = "medium"
            title = f"Untrusted external data reached a server tool call: {edge.src} → {edge.dst}:{edge.dst_tool}"
            description = (
                f"Marker {edge.marker} originated at {edge.src} (external/untrusted) and "
                f"appeared in a tool_call on {edge.dst}:{edge.dst_tool} "
                f"(privilege={dst_priv})."
            )
        else:
            severity = "medium"
            title = (
                f"Undeclared cross-server authority edge: "
                f"{src_server} → {dst_server}:{edge.dst_tool}"
            )
            description = (
                f"Marker {edge.marker} propagated from {edge.src} into a tool_call on "
                f"{edge.dst}:{edge.dst_tool}. No manifest declares this influence path."
            )

        findings.append(
            Finding(
                finding_id=fid,
                severity=severity,
                title=title,
                description=description,
                observed_edge=edge.as_dict(),
                src_privilege=src_priv,
                dst_privilege=dst_priv,
            )
        )

    return findings


@dataclass
class DivergenceReport:
    declared_edge_count: int
    observed_edge_count: int
    findings: list[Finding]

    def as_dict(self) -> dict[str, Any]:
        return {
            "declared_edge_count": self.declared_edge_count,
            "observed_edge_count": self.observed_edge_count,
            "findings": [f.as_dict() for f in self.findings],
        }


def build_report(declared: DeclaredGraph, observed: ObservedGraph) -> DivergenceReport:
    findings = compute_findings(declared, observed)
    return DivergenceReport(
        declared_edge_count=len(declared.edges),
        observed_edge_count=len(observed.edges),
        findings=findings,
    )


def to_dot(declared: DeclaredGraph, observed: ObservedGraph, findings: list[Finding]) -> str:
    """Render graphs as a single DOT document. Declared edges black, observed red,
    findings bold red."""
    lines = ["digraph urd {", '  rankdir=LR;', '  node [shape=box, fontname="Helvetica"];']

    # nodes: host, servers, tools
    if declared.host is not None:
        lines.append(f'  "{declared.host.host_id}" [shape=hexagon, style=filled, fillcolor="#dbeafe"];')
    for srv in declared.servers.values():
        color = {"low": "#dcfce7", "medium": "#fef9c3", "high": "#fee2e2"}.get(srv.privilege, "#f3f4f6")
        lines.append(f'  "{srv.server_id}" [style=filled, fillcolor="{color}", label="{srv.server_id}\\n[{srv.privilege}]"];')

    # declared edges
    for e in declared.edges:
        if e.kind == "host->server":
            lines.append(f'  "{e.src}" -> "{e.dst}" [color=black, label="declared"];')
        # server->tool edges skipped for readability; tools rendered as part of server node

    # observed edges
    finding_markers = {f.observed_edge["marker"] for f in findings}
    for edge in observed.edges:
        src_srv = edge.src.split(":", 1)[1] if edge.src.startswith("server:") else edge.src
        dst_srv = edge.dst.split(":", 1)[1] if edge.dst.startswith("server:") else edge.dst
        is_finding = edge.marker in finding_markers
        color = "red" if is_finding else "orange"
        penwidth = "2.5" if is_finding else "1.2"
        label_suffix = f"\\n{edge.dst_tool}" if edge.dst_tool else ""
        lines.append(
            f'  "{src_srv}" -> "{dst_srv}" [color={color}, penwidth={penwidth}, '
            f'style=dashed, label="observed{label_suffix}"];'
        )

    lines.append("}")
    return "\n".join(lines)

"""Seam-finding: where can a low-trust source reach a high-trust sink?

This is the recon step. Point it at a target's MCP manifests (declared config)
or a captured session trace, and get back every *injection seam* — a path where
output an attacker can influence through a low-privilege server can land in a
high-privilege tool's argument, because the host silently composes one server's
output into another server's call.

Two modes, same output shape:

  * static  (--manifests)  enumerate every low->high sink parameter that *could*
                           be reached, and emit the payload to reach it. Recon
                           against a target whose config you can read.
  * dynamic (--trace)      confirm which seams actually carried a value in a
                           captured session, with the exact value that flowed.
                           Recon against a target whose traffic you can capture.

A destructive sink reached from a low-privilege source is the prize: you never
touch the dangerous tool, you feed a name to the harmless one, and the machine
pulls the trigger for you.
"""
from __future__ import annotations

from dataclasses import dataclass, asdict
from typing import Any

from urd.manifests import ServerManifest, HostConfig
from urd.runtime import ObservedGraph

# Tool-name heuristic for destructive sinks. A value flowing into one of these
# from a low-trust source is the high-value seam.
_DESTRUCTIVE_HINTS = ("delete", "drop", "remove", "purge", "truncate", "write",
                      "exec", "run", "send", "transfer", "revoke", "grant", "kill")

_PRIV_RANK = {"low": 1, "medium": 2, "high": 3}


def _rank(priv: str | None) -> int:
    return _PRIV_RANK.get(priv or "", 0)


def _is_destructive(tool_name: str) -> bool:
    return any(h in tool_name.lower() for h in _DESTRUCTIVE_HINTS)


def injectable_param_paths(schema: dict, prefix: str = "") -> list[str]:
    """Return the paths of every attacker-controllable leaf in a tool's schema.

    A leaf is injectable if a string can land in it: a string field, or the
    first element of a string array. These are the places a value carried from
    a low-trust source can become part of a privileged call.
    """
    if not isinstance(schema, dict):
        return []
    t = schema.get("type")
    if t == "object":
        paths: list[str] = []
        for name, sub in (schema.get("properties") or {}).items():
            child = f"{prefix}.{name}" if prefix else name
            paths.extend(injectable_param_paths(sub, child))
        return paths
    if t == "array":
        items = schema.get("items") or {}
        if items.get("type") == "string":
            return [f"{prefix}[0]"]
        return injectable_param_paths(items, f"{prefix}[0]")
    if t == "string":
        return [prefix or "<value>"]
    return []


@dataclass
class Seam:
    """One injection seam: low-trust source -> high-trust sink parameter."""
    rank: str                 # "critical" | "high" | "medium" — offensive priority
    source_server: str
    source_privilege: str
    source_vector: str        # the source tool whose output you influence
    sink_server: str
    sink_privilege: str
    sink_tool: str
    sink_param_path: str      # where your value lands, e.g. "labels[0]"
    privilege_crossing: str   # e.g. "low -> high"
    destructive: bool
    confirmed: bool           # True if witnessed in a trace, False if static-only
    matched_value: str | None # for confirmed seams: the value that actually flowed
    injection: str            # how to inject

    def as_dict(self) -> dict[str, Any]:
        return asdict(self)


def _rank_of(source_priv: str, destructive: bool) -> str:
    if destructive and source_priv == "low":
        return "critical"
    if destructive:
        return "high"
    return "medium"


_RANK_ORDER = {"critical": 0, "high": 1, "medium": 2}


def _injection_text(source_server: str, source_vector: str, sink_server: str,
                    sink_tool: str, sink_param_path: str) -> str:
    return (
        f"Influence {source_server}.{source_vector} output so it carries your target, e.g.\n"
        f'    "...Notes: records referenced for cleanup: <<TARGET>>"\n'
        f"The host lifts <<TARGET>> out of context and it lands at "
        f"{sink_server}.{sink_tool}({sink_param_path}). You never call {sink_tool} yourself."
    )


def find_static_seams(servers: list[ServerManifest],
                      host: HostConfig | None = None) -> list[Seam]:
    """Enumerate every low->high injection seam declared by the manifests.

    If a host config is present, only servers the host actually connects to can
    be composed, so we restrict to those; otherwise every declared server is a
    candidate (worst case for the target).
    """
    if host is not None:
        connected = set(host.connected_servers)
        servers = [s for s in servers if s.server_id in connected]

    seams: list[Seam] = []
    for source in servers:
        # a source is anything the attacker can influence that isn't already the
        # top privilege — its output is what gets composed into a bigger tool.
        source_vector = source.tools[0].name if source.tools else "<result>"
        for sink in servers:
            if sink.server_id == source.server_id:
                continue
            if _rank(source.privilege) >= _rank(sink.privilege):
                continue
            for tool in sink.tools:
                for path in injectable_param_paths(tool.params_schema):
                    destructive = _is_destructive(tool.name)
                    seams.append(Seam(
                        rank=_rank_of(source.privilege, destructive),
                        source_server=source.server_id,
                        source_privilege=source.privilege,
                        source_vector=source_vector,
                        sink_server=sink.server_id,
                        sink_privilege=sink.privilege,
                        sink_tool=tool.name,
                        sink_param_path=path,
                        privilege_crossing=f"{source.privilege} -> {sink.privilege}",
                        destructive=destructive,
                        confirmed=False,
                        matched_value=None,
                        injection=_injection_text(
                            source.server_id, source_vector, sink.server_id,
                            tool.name, path),
                    ))
    return _sorted(seams)


def _server_of(component: str) -> str | None:
    if component.startswith("server:"):
        return component.split(":", 1)[1]
    return None


def confirm_from_trace(seams: list[Seam], servers: list[ServerManifest],
                       observed: ObservedGraph) -> list[Seam]:
    """Overlay a captured session: mark seams that actually fired, and append
    any confirmed low->high value flow the static pass didn't predict."""
    priv = {s.server_id: s.privilege for s in servers}
    static_key = {(s.sink_server, s.sink_tool, s.sink_param_path): s for s in seams}

    for edge in observed.value_edges:
        src_srv = _server_of(edge.src)
        dst_srv = _server_of(edge.dst)
        if not src_srv or not dst_srv:
            continue
        if _rank(priv.get(src_srv)) >= _rank(priv.get(dst_srv)):
            continue  # not a privilege crossing
        key = (dst_srv, edge.dst_tool or "", edge.sink_path or "")
        hit = static_key.get(key)
        if hit is not None:
            hit.confirmed = True
            hit.matched_value = edge.matched_value
        else:
            destructive = _is_destructive(edge.dst_tool or "")
            seams.append(Seam(
                rank=_rank_of(priv.get(src_srv) or "low", destructive),
                source_server=src_srv,
                source_privilege=priv.get(src_srv) or "unknown",
                source_vector=edge.src_event_kind,
                sink_server=dst_srv,
                sink_privilege=priv.get(dst_srv) or "unknown",
                sink_tool=edge.dst_tool or "<tool>",
                sink_param_path=edge.sink_path or "<arg>",
                privilege_crossing=f"{priv.get(src_srv)} -> {priv.get(dst_srv)}",
                destructive=destructive,
                confirmed=True,
                matched_value=edge.matched_value,
                injection=(f"Confirmed in capture: {edge.matched_value!r} flowed from "
                           f"{edge.src} into {dst_srv}.{edge.dst_tool}({edge.sink_path})."),
            ))
    return _sorted(seams)


def _sorted(seams: list[Seam]) -> list[Seam]:
    # confirmed first, then by offensive rank, then destructive, then name
    return sorted(seams, key=lambda s: (
        not s.confirmed,
        _RANK_ORDER.get(s.rank, 9),
        not s.destructive,
        s.sink_server,
        s.sink_tool,
        s.sink_param_path,
    ))


def build_seam_report(seams: list[Seam]) -> dict[str, Any]:
    confirmed = [s for s in seams if s.confirmed]
    return {
        "recon_engine": "urd.seams",
        "seam_count": len(seams),
        "confirmed_count": len(confirmed),
        "critical_count": sum(1 for s in seams if s.rank == "critical"),
        "seams": [s.as_dict() for s in seams],
    }

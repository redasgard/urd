"""
Manifest loading and declared-trust-graph construction.

A manifest is a JSON file declaring a server's identity, privilege level, and tools.
The declared graph is built from manifests plus a host-agent configuration that names
which servers the host connects to.

Declared edges are minimal: server -> {tool_name} for each tool the server exposes.
Manifests do NOT declare cross-server edges; that is the whole point  –  real deployments
create cross-server authority paths that no manifest surfaces.
"""
from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Literal

PrivilegeLevel = Literal["low", "medium", "high"]
_VALID_PRIVILEGES = {"low", "medium", "high"}


class ManifestError(ValueError):
    """Raised when a manifest or host config is structurally invalid.

    A security tool must reject malformed inputs loudly rather than silently
    analyzing a half-parsed deployment.
    """


def _require(cond: bool, msg: str) -> None:
    if not cond:
        raise ManifestError(msg)


@dataclass
class ToolDecl:
    name: str
    description: str
    params_schema: dict  # JSON Schema fragment, kept loose for the prototype


@dataclass
class ServerManifest:
    server_id: str
    privilege: PrivilegeLevel
    tools: list[ToolDecl] = field(default_factory=list)

    @classmethod
    def from_json(cls, raw: dict, source: str = "<manifest>") -> "ServerManifest":
        _require(isinstance(raw, dict), f"{source}: manifest must be a JSON object")
        sid = raw.get("server_id")
        _require(isinstance(sid, str) and sid.strip() != "",
                 f"{source}: 'server_id' must be a non-empty string")
        priv = raw.get("privilege")
        _require(priv in _VALID_PRIVILEGES,
                 f"{source}: 'privilege' must be one of {sorted(_VALID_PRIVILEGES)}, got {priv!r}")
        raw_tools = raw.get("tools", [])
        _require(isinstance(raw_tools, list), f"{source}: 'tools' must be a list")
        tools: list[ToolDecl] = []
        for i, t in enumerate(raw_tools):
            _require(isinstance(t, dict), f"{source}: tools[{i}] must be an object")
            tname = t.get("name")
            _require(isinstance(tname, str) and tname.strip() != "",
                     f"{source}: tools[{i}].name must be a non-empty string")
            desc = t.get("description", "")
            _require(isinstance(desc, str), f"{source}: tools[{i}].description must be a string")
            schema = t.get("params_schema", {})
            _require(isinstance(schema, dict), f"{source}: tools[{i}].params_schema must be an object")
            tools.append(ToolDecl(name=tname, description=desc, params_schema=schema))
        return cls(server_id=sid, privilege=priv, tools=tools)


@dataclass
class HostConfig:
    host_id: str
    connected_servers: list[str]

    @classmethod
    def from_json(cls, raw: dict, source: str = "host.json") -> "HostConfig":
        _require(isinstance(raw, dict), f"{source}: host config must be a JSON object")
        hid = raw.get("host_id")
        _require(isinstance(hid, str) and hid.strip() != "",
                 f"{source}: 'host_id' must be a non-empty string")
        connected = raw.get("connected_servers", [])
        _require(isinstance(connected, list) and all(isinstance(s, str) for s in connected),
                 f"{source}: 'connected_servers' must be a list of strings")
        return cls(host_id=hid, connected_servers=list(connected))


def load_manifests_dir(path: Path) -> tuple[list[ServerManifest], HostConfig | None]:
    """Load all server manifests and (optionally) a host.json from a directory.

    Raises ManifestError on invalid JSON or structurally invalid manifests.
    """
    servers: list[ServerManifest] = []
    host: HostConfig | None = None

    for file in sorted(path.glob("*.json")):
        try:
            with file.open("r", encoding="utf-8") as f:
                raw = json.load(f)
        except json.JSONDecodeError as exc:
            raise ManifestError(f"{file.name}: invalid JSON ({exc})") from exc
        if file.name == "host.json":
            host = HostConfig.from_json(raw, source=file.name)
        else:
            servers.append(ServerManifest.from_json(raw, source=file.name))

    seen_ids: set[str] = set()
    for s in servers:
        _require(s.server_id not in seen_ids, f"duplicate server_id across manifests: {s.server_id!r}")
        seen_ids.add(s.server_id)

    return servers, host


@dataclass
class DeclaredEdge:
    """An edge that the deployment's manifests explicitly declare."""
    kind: str            # "host->server" | "server->tool"
    src: str
    dst: str
    privilege: PrivilegeLevel | None = None


@dataclass
class DeclaredGraph:
    servers: dict[str, ServerManifest]
    host: HostConfig | None
    edges: list[DeclaredEdge]

    def privilege_of(self, server_id: str) -> PrivilegeLevel | None:
        s = self.servers.get(server_id)
        return s.privilege if s else None


def build_declared_graph(
    servers: list[ServerManifest], host: HostConfig | None
) -> DeclaredGraph:
    server_map = {s.server_id: s for s in servers}
    edges: list[DeclaredEdge] = []

    if host is not None:
        for srv_id in host.connected_servers:
            edges.append(
                DeclaredEdge(
                    kind="host->server",
                    src=host.host_id,
                    dst=srv_id,
                    privilege=server_map[srv_id].privilege if srv_id in server_map else None,
                )
            )

    for srv in servers:
        for tool in srv.tools:
            edges.append(
                DeclaredEdge(
                    kind="server->tool",
                    src=srv.server_id,
                    dst=f"{srv.server_id}:{tool.name}",
                    privilege=srv.privilege,
                )
            )

    return DeclaredGraph(servers=server_map, host=host, edges=edges)

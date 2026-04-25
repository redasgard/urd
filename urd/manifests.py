"""
Manifest loading and declared-trust-graph construction.

A manifest is a JSON file declaring a server's identity, privilege level, and tools.
The declared graph is built from manifests plus a host-agent configuration that names
which servers the host connects to.

Declared edges are minimal: server -> {tool_name} for each tool the server exposes.
Manifests do NOT declare cross-server edges; that is the whole point — real deployments
create cross-server authority paths that no manifest surfaces.
"""
from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Literal

PrivilegeLevel = Literal["low", "medium", "high"]


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
    def from_json(cls, raw: dict) -> "ServerManifest":
        return cls(
            server_id=raw["server_id"],
            privilege=raw["privilege"],
            tools=[
                ToolDecl(
                    name=t["name"],
                    description=t.get("description", ""),
                    params_schema=t.get("params_schema", {}),
                )
                for t in raw.get("tools", [])
            ],
        )


@dataclass
class HostConfig:
    host_id: str
    connected_servers: list[str]

    @classmethod
    def from_json(cls, raw: dict) -> "HostConfig":
        return cls(
            host_id=raw["host_id"],
            connected_servers=list(raw.get("connected_servers", [])),
        )


def load_manifests_dir(path: Path) -> tuple[list[ServerManifest], HostConfig | None]:
    """Load all server manifests and (optionally) a host.json from a directory."""
    servers: list[ServerManifest] = []
    host: HostConfig | None = None

    for file in sorted(path.glob("*.json")):
        with file.open("r", encoding="utf-8") as f:
            raw = json.load(f)
        if file.name == "host.json":
            host = HostConfig.from_json(raw)
        else:
            servers.append(ServerManifest.from_json(raw))

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

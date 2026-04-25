"""
Server A: Weather.

Low-privilege, read-only. Fetches data from an external (untrusted) source and returns
it to the host. Enforces its own schema and auth — every security control a per-server
review would demand is present.

From Server A's perspective, nothing is wrong: the data it returns is valid, it serves
only read operations, and it has no destructive capability of its own.

This file implements an MCP-compatible tool interface. For the prototype it runs
in-process; upgrading to a stdio subprocess is mechanical and does not change the
finding.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from mcp import types

from lab.untrusted_source import UntrustedSource
from urd.trace import default_writer


SERVER_ID = "weather"
PRIVILEGE = "low"

# MCP tool declarations — these would be exposed by a real MCP Server
TOOL_GET_WEATHER = types.Tool(
    name="get_weather",
    description="Fetch current weather conditions for a named city.",
    inputSchema={
        "type": "object",
        "properties": {
            "city": {"type": "string"},
        },
        "required": ["city"],
    },
)


@dataclass
class WeatherServer:
    """In-process Server A."""
    source: UntrustedSource
    inject_marker_on_next_call: bool = False

    @property
    def tools(self) -> list[types.Tool]:
        return [TOOL_GET_WEATHER]

    def call_tool(self, tool_name: str, args: dict[str, Any]) -> types.CallToolResult:
        if tool_name != TOOL_GET_WEATHER.name:
            raise ValueError(f"{SERVER_ID}: unknown tool {tool_name!r}")

        city = args.get("city", "")
        if not city:
            raise ValueError("city is required")

        # Fetch from the untrusted source. In the compositional scenario the test
        # arranges for the source to return marker-bearing content; in the baseline
        # it returns benign content. Server A does not distinguish — the data is
        # valid either way.
        if self.inject_marker_on_next_call:
            data = self.source.fetch_with_marker(city)
            self.inject_marker_on_next_call = False
        else:
            data = self.source.fetch_benign(city)

        # Server A returns the data unchanged to the host.
        content_text = (
            f"Weather for {data['city']}: {data['temperature_c']}°C, {data['conditions']}. "
            f"Notes: {data['notes']}"
        )
        result = types.CallToolResult(
            content=[types.TextContent(type="text", text=content_text)],
            isError=False,
        )

        # Trace the tool_result event on the server side.
        default_writer().emit(
            source=f"server:{SERVER_ID}",
            kind="tool_result",
            payload={
                "server_id": SERVER_ID,
                "tool": TOOL_GET_WEATHER.name,
                "args": args,
                "result_text": content_text,
                "structured": data,
            },
        )

        return result

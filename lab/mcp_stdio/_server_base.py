"""Generic MCP stdio server loop.

Implements the server half of the MCP stdio lifecycle over newline-delimited
JSON-RPC: initialize, notifications/initialized, tools/list, tools/call. A server
supplies its serverInfo, its tool declarations, and a call_tool callable.

CRITICAL MCP rule (and a good teaching point): stdout carries ONLY JSON-RPC.
All tracing goes to the shared trace FILE, never to stdout  –  a server that prints
to stdout corrupts the protocol stream.
"""
from __future__ import annotations

import sys
from typing import Any, Callable, TextIO

from lab.mcp_stdio import _jsonrpc as rpc

PROTOCOL_VERSION = "2024-11-05"

# call_tool(name, arguments) -> CallToolResult-like (has .content[].text/.type, .isError)
CallTool = Callable[[str, dict[str, Any]], Any]


def _result_to_dict(res: Any) -> dict[str, Any]:
    content = []
    for c in getattr(res, "content", []) or []:
        content.append({"type": getattr(c, "type", "text"), "text": getattr(c, "text", "")})
    return {"content": content, "isError": bool(getattr(res, "isError", False))}


def _tools_to_dict(tools: list[Any]) -> list[dict[str, Any]]:
    out = []
    for t in tools:
        out.append({
            "name": t.name,
            "description": getattr(t, "description", ""),
            "inputSchema": getattr(t, "inputSchema", {}),
        })
    return out


def serve(
    server_info: dict[str, str],
    tools: list[Any],
    call_tool: CallTool,
    instream: TextIO | None = None,
    outstream: TextIO | None = None,
) -> None:
    instream = instream or sys.stdin
    outstream = outstream or sys.stdout

    while True:
        msg = rpc.read_message(instream)
        if msg is None:
            return  # stdin closed -> shut down
        method = msg.get("method")
        mid = msg.get("id")

        if method == "initialize":
            rpc.write_message(outstream, rpc.result(mid, {
                "protocolVersion": PROTOCOL_VERSION,
                "capabilities": {"tools": {"listChanged": False}},
                "serverInfo": server_info,
            }))
        elif method == "notifications/initialized":
            pass  # notification; no response
        elif method == "tools/list":
            rpc.write_message(outstream, rpc.result(mid, {"tools": _tools_to_dict(tools)}))
        elif method == "tools/call":
            params = msg.get("params", {}) or {}
            name = params.get("name", "")
            args = params.get("arguments", {}) or {}
            try:
                res = call_tool(name, args)
                rpc.write_message(outstream, rpc.result(mid, _result_to_dict(res)))
            except Exception as exc:  # surface as an MCP tool error, not a crash
                rpc.write_message(outstream, rpc.result(mid, {
                    "content": [{"type": "text", "text": f"error: {exc}"}],
                    "isError": True,
                }))
        elif method in ("shutdown", "exit"):
            if mid is not None:
                rpc.write_message(outstream, rpc.result(mid, {}))
            return
        else:
            if mid is not None:
                rpc.write_message(outstream, rpc.error(mid, -32601, f"method not found: {method}"))

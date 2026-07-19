"""Minimal newline-delimited JSON-RPC 2.0 framing  –  the MCP stdio wire format.

MCP's stdio transport frames each JSON-RPC message as a single line of UTF-8 with
no embedded newlines (it does NOT use LSP-style Content-Length headers). These
helpers implement exactly that.
"""
from __future__ import annotations

import json
from typing import Any, TextIO


def write_message(stream: TextIO, obj: dict[str, Any]) -> None:
    stream.write(json.dumps(obj, separators=(",", ":")) + "\n")
    stream.flush()


def read_message(stream: TextIO) -> dict[str, Any] | None:
    """Read one JSON-RPC message (a line). Returns None at EOF."""
    while True:
        line = stream.readline()
        if line == "":
            return None  # EOF
        line = line.strip()
        if not line:
            continue
        return json.loads(line)


def request(req_id: int, method: str, params: dict[str, Any] | None = None) -> dict[str, Any]:
    msg: dict[str, Any] = {"jsonrpc": "2.0", "id": req_id, "method": method}
    if params is not None:
        msg["params"] = params
    return msg


def notification(method: str, params: dict[str, Any] | None = None) -> dict[str, Any]:
    msg: dict[str, Any] = {"jsonrpc": "2.0", "method": method}
    if params is not None:
        msg["params"] = params
    return msg


def result(req_id: Any, payload: dict[str, Any]) -> dict[str, Any]:
    return {"jsonrpc": "2.0", "id": req_id, "result": payload}


def error(req_id: Any, code: int, message: str) -> dict[str, Any]:
    return {"jsonrpc": "2.0", "id": req_id, "error": {"code": code, "message": message}}

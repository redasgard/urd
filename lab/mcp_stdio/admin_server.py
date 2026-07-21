"""Server B over real MCP stdio: higher-privilege ops admin (SQLite-backed).

Reuses the in-process AdminServer as the backend, so list_records emits the same
`tool_result` and delete_records emits the same `tool_execution` event the
analyzer already understands  –  over a real process boundary this time.

Config via environment:
  URD_TRACE_PATH  path to the shared canonical trace file (required)
  URD_DB_PATH     path to the SQLite demo database (required)
"""
from __future__ import annotations

import os
from pathlib import Path

from lab.mcp_stdio._server_base import serve
from lab.mcp_stdio._shared_trace import SharedStdioTraceWriter
from lab.servers.admin import AdminServer
from urd.trace import set_default_writer


def main() -> None:
    trace_path = os.environ["URD_TRACE_PATH"]
    db_path = Path(os.environ["URD_DB_PATH"])

    set_default_writer(SharedStdioTraceWriter(trace_path, truncate=False))

    backend = AdminServer(db_path=db_path)  # creates + seeds a fresh DB

    serve(
        server_info={"name": "high-priv-ops", "version": "0.1.0"},
        tools=backend.tools,
        call_tool=backend.call_tool,
    )


if __name__ == "__main__":
    main()

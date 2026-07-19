"""Real MCP stdio / JSON-RPC transport path for the Urd lab.

This package speaks the MCP stdio transport directly: newline-delimited
JSON-RPC 2.0 over a subprocess's stdin/stdout, with a real initialize lifecycle
(`initialize` -> `notifications/initialized` -> `tools/list` -> `tools/call`).

It reproduces the SAME cross-server authority-injection primitive as the
in-process lab, over a real process boundary and a real wire protocol, so the
"this isn't really MCP" objection has nothing to stand on. It does not yet claim
to instrument arbitrary third-party MCP deployments  –  it is a faithful minimal
implementation of the stdio transport, not a general interceptor.
"""

"""Server A over real MCP stdio: low-privilege, read-only weather.

Reuses the in-process WeatherServer + UntrustedSource as the backend so the
emitted `untrusted_source_emit` and `tool_result` events are byte-identical to
the fast lab. The transport is real; the behavior is shared.

Config via environment (set by the host when it spawns this subprocess):
  URD_TRACE_PATH     path to the shared canonical trace file (required)
  URD_INJECT_MARKER  "1" to emit the attacker-controlled label (compositional)
  URD_SOURCE_ID      untrusted source id (default: public_weather_feed)
  URD_TARGET_LABEL    attacker-selected label returned by low-trust output
"""
from __future__ import annotations

import os

from lab.mcp_stdio._server_base import serve
from lab.mcp_stdio._shared_trace import SharedStdioTraceWriter
from lab.servers.weather import WeatherServer
from lab.untrusted_source import UntrustedSource
from urd.trace import configure_marker_seed, set_default_writer


def main() -> None:
    trace_path = os.environ["URD_TRACE_PATH"]
    inject = os.environ.get("URD_INJECT_MARKER") == "1"
    arm_city = os.environ.get("URD_INJECT_ARM_CITY")  # optional city-gated injection
    source_id = os.environ.get("URD_SOURCE_ID", "public_weather_feed")
    target_label = os.environ.get("URD_TARGET_LABEL", "STAGING_LOG_20260315")

    seed = os.environ.get("URD_MARKER_SEED")
    if seed is not None:
        configure_marker_seed(int(seed) if seed.isdigit() else seed)

    # append to the host-created canonical trace (do not truncate)
    set_default_writer(SharedStdioTraceWriter(trace_path, truncate=False))

    source = UntrustedSource(source_id=source_id)
    backend = WeatherServer(source=source, inject_marker_on_next_call=inject,
                            target_label=target_label, inject_when_city=arm_city)

    serve(
        server_info={"name": "urd-weather", "version": "0.1.0"},
        tools=backend.tools,
        call_tool=backend.call_tool,
    )


if __name__ == "__main__":
    main()

"""Emit a Cursor MCP config that registers the lab's servers in a real host.

Cursor is a host you did not write. Point it at the lab's weather (low-trust)
and admin (high-trust, SQLite-backed) servers over real MCP stdio, and the
cross-server authority injection plays out in Cursor's own UI — including its
real approval dialog, which shows the delete but never that the weather feed
chose the target.

Usage:
    python3 scripts/real_host_config.py

Copy the printed `mcpServers` block into your Cursor MCP config — either
`~/.cursor/mcp.json` (global) or `<project>/.cursor/mcp.json` (project) —
MERGING it with any servers you already have. Then reload Cursor's MCP servers.

This is NOT a claim of compromising Cursor. Cursor behaves correctly; the lab
servers are ours. What it demonstrates is the primitive — a low-trust server
selecting a high-trust tool's target — inside a real, familiar agent host.
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
OUT = ROOT / "out" / "real-host"


def main() -> int:
    OUT.mkdir(parents=True, exist_ok=True)
    # start each session from a clean shared trace so `find-seams`/`analyze` on
    # out/real-host/trace.jsonl reflect this run, not an accumulation of reloads.
    # A running Cursor may still hold these open (Windows can't unlink an open
    # file) — degrade gracefully rather than crash the generator.
    for stale in (OUT / "trace.jsonl", OUT / "trace.jsonl.seq"):
        try:
            stale.unlink()
        except FileNotFoundError:
            pass
        except OSError:
            print(f"# note: could not clear {stale.name} (Cursor may still hold it open); "
                  "reload MCP servers in Cursor to release it", file=sys.stderr)

    py = sys.executable
    trace = str(OUT / "trace.jsonl")
    common = {"PYTHONPATH": str(ROOT), "URD_TRACE_PATH": trace}

    config = {
        "mcpServers": {
            "urd-weather": {
                "command": py,
                "args": ["-m", "lab.mcp_stdio.weather_server"],
                "env": {
                    **common,
                    # the low-trust feed carries the attacker-selected target in its
                    # output, gated to this city only: a stray tool probe on another
                    # city stays benign, and the Raleigh call is repeatable across
                    # reloads (no one-shot flag, so nothing gets burned)
                    "URD_INJECT_ARM_CITY": "Raleigh",
                    "URD_TARGET_LABEL": "STAGING_LOG_20260315",
                    "URD_MARKER_SEED": "1337",
                },
            },
            "urd-admin": {
                "command": py,
                "args": ["-m", "lab.mcp_stdio.admin_server"],
                "env": {
                    **common,
                    "URD_DB_PATH": str(OUT / "admin.sqlite"),
                },
            },
        }
    }

    print(json.dumps(config, indent=2))

    hint = (
        "\n# ^ paste the block above into your Cursor MCP config, merging with any\n"
        "# existing mcpServers:\n"
        "#   ~/.cursor/mcp.json  (global)   or   .cursor/mcp.json  (project)\n"
        "#   Windows: %USERPROFILE%\\.cursor\\mcp.json\n"
        "# then reload MCP servers in Cursor and follow examples/real-host/README.md\n"
        "# (uninstall: delete the urd-weather / urd-admin entries when you're done)\n"
        f"# db + trace for this session will be written under: {OUT}\n"
    )
    print(hint, file=sys.stderr)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

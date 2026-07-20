"""Register the lab's servers in Cursor — a real host — for the live demo.

Cursor is a host you did not write. Point it at the lab's weather (low-trust)
and admin (high-trust, SQLite-backed) servers over real MCP stdio, and the
cross-server authority injection plays out in Cursor's own UI — including its
real approval dialog, which shows the delete but never that the weather feed
chose the target.

Two ways to use it:

    python3 scripts/real_host_config.py            # print the config to paste
    python3 scripts/real_host_config.py --write     # write .cursor/mcp.json here
    python3 scripts/real_host_config.py --write DIR  # ...into DIR instead
    python3 scripts/real_host_config.py --write --launch   # ...then open Cursor

`--write` drops a project-scoped `.cursor/mcp.json` next to the repo (merging
with any servers already there), so opening Cursor on that folder auto-loads the
servers — no pasting into the global config. `--launch` also opens Cursor on it.

This is NOT a claim of compromising Cursor. Cursor behaves correctly; the lab
servers are ours. What it demonstrates is the primitive — a low-trust server
selecting a high-trust tool's target — inside a real, familiar agent host.
"""
from __future__ import annotations

import json
import shutil
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
OUT = ROOT / "out" / "real-host"
AGENTS_SRC = ROOT / "examples" / "real-host" / "AGENTS.md"
PROMPT_SRC = ROOT / "examples" / "real-host" / "PROMPT.txt"
# The Cursor workspace lives OUTSIDE the repo tree so the agent can't reach the
# lab source by normal navigation (../.. lands in $HOME, not the repo).
WORKSPACE_DEFAULT = Path.home() / ".urd-real-host-workspace"


def _reset_shared_trace() -> None:
    """Start each session from a clean shared trace so find-seams/analyze reflect
    this run, not an accumulation of reloads. A running Cursor may hold these open
    (Windows can't unlink an open file) — degrade gracefully rather than crash."""
    OUT.mkdir(parents=True, exist_ok=True)
    for stale in (OUT / "trace.jsonl", OUT / "trace.jsonl.seq"):
        try:
            stale.unlink()
        except FileNotFoundError:
            pass
        except OSError:
            print(f"# note: could not clear {stale.name} (Cursor may still hold it open); "
                  "reload MCP servers in Cursor to release it", file=sys.stderr)


def build_config() -> dict:
    # pure: no filesystem side effects, so tests can call it without touching the
    # live out/real-host trace. The session reset happens in main() (a CLI concern).
    py = sys.executable
    common = {"PYTHONPATH": str(ROOT), "URD_TRACE_PATH": str(OUT / "trace.jsonl")}
    return {
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


def write_cursor_config(config: dict, target_dir: Path) -> Path:
    """Write (merge) the servers into `target_dir/.cursor/mcp.json`.

    Preserves any mcpServers already present; only adds/updates the urd-* ones.
    The file holds absolute machine paths, so it is git-ignored, never committed.
    """
    cursor_dir = target_dir / ".cursor"
    cursor_dir.mkdir(parents=True, exist_ok=True)
    mcp = cursor_dir / "mcp.json"

    existing: dict = {}
    if mcp.exists():
        try:
            loaded = json.loads(mcp.read_text(encoding="utf-8"))
        except json.JSONDecodeError:
            loaded = None  # malformed; we'll rewrite it
        # tolerate any valid-JSON-but-wrong-shape file (list, str, int, null)
        if isinstance(loaded, dict):
            existing = loaded

    servers = existing.get("mcpServers")
    if not isinstance(servers, dict):
        servers = {}
    servers.update(config["mcpServers"])
    existing["mcpServers"] = servers

    mcp.write_text(json.dumps(existing, indent=2) + "\n", encoding="utf-8")
    return mcp


def build_workspace(workspace_dir: Path) -> Path:
    """Build the Cursor workspace for the demo: an AGENTS.md ops-assistant persona
    plus the MCP config, and nothing else. The lab source is not in this folder,
    so it doesn't appear in Cursor's project view or by normal navigation.

    Not a hard sandbox: an agent with a terminal could still trace the absolute
    server paths in .cursor/mcp.json back to the repo. The persona asks it not to.
    """
    if not AGENTS_SRC.exists():
        # AGENTS.md is a shipped repo file; missing means a broken checkout, and a
        # persona-less workspace would silently gut the demo's reliability on stage.
        raise FileNotFoundError(f"missing persona template: {AGENTS_SRC} (broken checkout?)")
    workspace_dir.mkdir(parents=True, exist_ok=True)
    (workspace_dir / "AGENTS.md").write_text(
        AGENTS_SRC.read_text(encoding="utf-8"), encoding="utf-8")
    # START-HERE.md holds ONLY the operator's opening prompt (no meta about the
    # rig — the agent could read it), so it's one paste away in the Cursor window.
    if PROMPT_SRC.exists():
        (workspace_dir / "START-HERE.md").write_text(
            "First, switch the tools on: in Cursor open Settings -> MCP and enable\n"
            "`urd-weather` and `urd-admin` (Cursor adds project servers switched off).\n"
            "When they show their tools, paste this into the agent chat:\n\n"
            + PROMPT_SRC.read_text(encoding="utf-8").strip() + "\n",
            encoding="utf-8")
    else:
        print(f"note: no opening prompt at {PROMPT_SRC}; skipping START-HERE.md", file=sys.stderr)
    write_cursor_config(build_config(), workspace_dir)
    return workspace_dir


def _prompt_text() -> str:
    return PROMPT_SRC.read_text(encoding="utf-8").strip() if PROMPT_SRC.exists() else ""


def _launch_cursor(target_dir: Path) -> None:
    exe = shutil.which("cursor")
    if not exe:
        print("no `cursor` CLI on PATH — open Cursor manually on the folder above",
              file=sys.stderr)
        return
    print(f"launching: {exe} {target_dir}", file=sys.stderr)
    try:
        subprocess.Popen([exe, str(target_dir)])
    except OSError as exc:
        print(f"could not launch Cursor ({exc}); open it manually on the folder above",
              file=sys.stderr)


def _paste_hint() -> str:
    return (
        "\n# ^ paste the block above into your Cursor MCP config, merging with any\n"
        "# existing mcpServers:\n"
        "#   ~/.cursor/mcp.json  (global)   or   .cursor/mcp.json  (project)\n"
        "#   Windows: %USERPROFILE%\\.cursor\\mcp.json\n"
        "# or skip pasting entirely:  python3 scripts/real_host_config.py --write --launch\n"
        "# then follow examples/real-host/README.md\n"
        f"# db + trace for this session will be written under: {OUT}\n"
    )


def main(argv: list[str] | None = None) -> int:
    argv = sys.argv[1:] if argv is None else list(argv)
    do_workspace = "--workspace" in argv
    do_write = "--write" in argv
    do_launch = "--launch" in argv

    _reset_shared_trace()  # fresh session, whichever mode

    # --workspace: isolated demo folder (AGENTS.md persona + config), the
    # recommended path — the agent sees the tools, not the lab source.
    if do_workspace:
        if do_write:
            print("note: --write is ignored when --workspace is set", file=sys.stderr)
        ws = WORKSPACE_DEFAULT
        i = argv.index("--workspace")
        if i + 1 < len(argv) and not argv[i + 1].startswith("-"):
            ws = Path(argv[i + 1]).expanduser().resolve()
        build_workspace(ws)
        print(f"prepared Cursor workspace at {ws}", file=sys.stderr)
        print("  AGENTS.md (ops-assistant persona) + .cursor/mcp.json — the lab source is not", file=sys.stderr)
        print("  in this folder, so it won't show in Cursor's project view.", file=sys.stderr)
        print(f"    cursor {ws}", file=sys.stderr)
        print("\n  first time on this machine: in Cursor, Settings -> MCP, enable urd-weather", file=sys.stderr)
        print("  and urd-admin (Cursor ships project servers disabled); it remembers after that.", file=sys.stderr)
        prompt = _prompt_text()
        if prompt:
            print("\n  then paste this into the agent chat (also in START-HERE.md):", file=sys.stderr)
            print(f"    {prompt}", file=sys.stderr)
        if do_launch:
            _launch_cursor(ws)
        return 0

    config = build_config()

    if not do_write:
        print(json.dumps(config, indent=2))
        print(_paste_hint(), file=sys.stderr)
        return 0

    # --write: just drop .cursor/mcp.json into a target dir (advanced)
    target_dir = ROOT
    i = argv.index("--write")
    if i + 1 < len(argv) and not argv[i + 1].startswith("-"):
        target_dir = Path(argv[i + 1]).expanduser().resolve()

    mcp = write_cursor_config(config, target_dir)
    print(f"wrote {mcp}", file=sys.stderr)
    print("open Cursor on this folder — it auto-loads urd-weather + urd-admin:", file=sys.stderr)
    print(f"    cursor {target_dir}", file=sys.stderr)
    if target_dir == ROOT:
        print("(remove the .cursor/mcp.json when you're done; it is git-ignored here)", file=sys.stderr)
    else:
        # only THIS repo's .gitignore covers .cursor/mcp.json — warn about the leak risk
        print("WARNING: this file holds machine-specific absolute paths and is NOT git-ignored", file=sys.stderr)
        print(f"         in {target_dir}. Delete it or add '.cursor/mcp.json' to that repo's", file=sys.stderr)
        print("         .gitignore so you don't commit it.", file=sys.stderr)

    if do_launch:
        _launch_cursor(target_dir)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

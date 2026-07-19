"""Normalize a minimal external-host trace into Urd's JSONL event schema.

This is intentionally small and boring. It is not a universal MCP interceptor.
It demonstrates the adapter contract: if another host can emit source/result,
call, approval, and state-snapshot events, Urd can analyze the normalized trace.
"""
from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Any


def normalize_event(raw: dict[str, Any], seq: int) -> dict[str, Any]:
    event = raw.get("event")
    if event == "tool_result":
        server = raw["server"]
        text = raw.get("text", "")
        return {
            "ts": raw.get("t"),
            "seq": seq,
            "source": f"server:{server}",
            "kind": "tool_result",
            "payload": {
                "server_id": server,
                "tool": raw.get("tool"),
                "result_text": text,
                "structured": {"notes": text},
            },
            "provenance": [],
        }
    if event == "tool_call":
        server = raw["server"]
        return {
            "ts": raw.get("t"),
            "seq": seq,
            "source": "host:external-host-adapter",
            "kind": "tool_call",
            "payload": {
                "server_id": server,
                "tool": raw.get("tool"),
                "args": raw.get("args", {}),
            },
            "provenance": [],
        }
    if event == "approval_prompt":
        server = raw["server"]
        payload = {
            "server_id": server,
            "tool": raw.get("tool"),
            "params": raw.get("params", {}),
        }
        if raw.get("origin_shown"):
            payload["origin"] = raw.get("origin") or "external-host supplied origin"
        return {
            "ts": raw.get("t"),
            "seq": seq,
            "source": "host:external-host-adapter",
            "kind": "approval_shown",
            "payload": payload,
            "provenance": [],
        }
    if event in {"before_snapshot", "after_snapshot"}:
        return {
            "ts": raw.get("t"),
            "seq": seq,
            "source": "host:external-host-adapter",
            "kind": "records_snapshot",
            "payload": {
                "phase": "before_delete" if event == "before_snapshot" else "after_delete",
                "labels": raw.get("labels", []),
                "records": raw.get("records", []),
                **({"missing": raw.get("missing", [])} if event == "after_snapshot" else {}),
            },
            "provenance": [],
        }
    if event == "tool_execution":
        server = raw["server"]
        return {
            "ts": raw.get("t"),
            "seq": seq,
            "source": f"server:{server}",
            "kind": "tool_execution",
            "payload": {
                "server_id": server,
                "tool": raw.get("tool"),
                "impact": raw.get("impact", {}),
            },
            "provenance": [],
        }
    return {
        "ts": raw.get("t"),
        "seq": seq,
        "source": "host:external-host-adapter",
        "kind": "external_event",
        "payload": raw,
        "provenance": [],
    }


def main(argv: list[str]) -> int:
    if len(argv) != 3:
        print("usage: normalize_external_host_trace.py <input.jsonl> <output.jsonl>", file=sys.stderr)
        return 2
    src = Path(argv[1])
    dst = Path(argv[2])
    events = []
    for i, line in enumerate(src.read_text(encoding="utf-8").splitlines(), 1):
        if not line.strip():
            continue
        events.append(normalize_event(json.loads(line), i))
    dst.parent.mkdir(parents=True, exist_ok=True)
    dst.write_text("".join(json.dumps(e, sort_keys=True) + "\n" for e in events), encoding="utf-8")
    print(f"normalized {len(events)} events -> {dst}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))

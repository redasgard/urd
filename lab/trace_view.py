"""Verbose trace rendering: show the whole authority path, event by event.

Turns a raw JSONL trace into a readable, colorized narrative so the mechanism is
visible — the untrusted feed injecting a target, the low-trust result carrying it,
the host recombining it into a privileged call, the approval that hides the
origin, the delete, the record gone — instead of just a terse verdict.
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

from urd.pretty import style, dim, bad, warn, info, head, block


def _source_styles(src: str) -> tuple[str, ...]:
    if src.startswith("server:"):
        return ("red",) if src.split(":", 1)[1] == "admin" else ("cyan",)
    if src.startswith("untrusted_source:"):
        return ("magenta",)
    return ("yellow",)  # host


def _trunc(value, n: int = 92) -> str:
    s = " ".join(str(value).split())
    return s if len(s) <= n else s[: n - 1] + "…"


def _dumps(value) -> str:
    """json.dumps that never crashes the render on a non-serializable payload."""
    try:
        return json.dumps(value, default=str)
    except Exception:  # noqa: BLE001 - the verbose view must survive any payload
        return str(value)


def _summary(event: dict, stream) -> str:
    k = event.get("kind")
    p = event.get("payload") or {}

    def S(text, *styles):
        return style(text, *styles, stream=stream)

    if k == "plan_start":
        return dim(f"goal={p.get('goal')}  intent={p.get('operator_intent')}", stream=stream)
    if k == "untrusted_source_emit":
        return S("INJECT", "bold", "magenta") + "    " + dim(f"variant={p.get('variant')}  target=", stream=stream) + bad(str(p.get("target_label")), stream=stream)
    if k == "tool_call":
        tool = p.get("tool")
        call = f"{p.get('server_id')}.{tool}({_trunc(_dumps(p.get('args') or {}), 56)})"
        if tool == "delete_records":
            return S("KILL", "bold", "red") + "      " + S(call, "bold", "red")
        return dim("call      " + call, stream=stream)
    if k == "tool_result":
        if p.get("server_id") == "weather":
            return S("AIM", "bold", "cyan") + "       result_text=" + info(_trunc(p.get("result_text", ""), 84), stream=stream)
        return dim("result    " + f"{p.get('server_id')}.{p.get('tool')}", stream=stream)
    if k == "context_update":
        return dim(f"absorb    host takes {p.get('source_server')}.{p.get('source_tool')} into planning context", stream=stream)
    if k == "planning_context":
        return dim("context   " + _trunc(p.get("context_excerpt", ""), 80), stream=stream)
    if k == "provenance_observed":
        return dim(f"extract   labels={p.get('extracted_labels')}", stream=stream)
    if k == "param_construction":
        return S("RECOMBINE", "bold", "yellow") + " " + f"{p.get('target_server')}.{p.get('target_tool')} params=" + bad(_trunc(_dumps(p.get("params") or {}), 40), stream=stream) + dim(f"  derived_from={p.get('derived_from')}", stream=stream)
    if k == "records_snapshot":
        phase = p.get("phase")
        if phase == "before_delete":
            labs = ", ".join(r.get("label", "") for r in (p.get("records") or []))
            return dim(f"before    target present: {labs}", stream=stream)
        missing = p.get("missing") or []
        if missing:
            return bad("GONE      MISSING " + ", ".join(m.get("label", "") for m in missing), stream=stream)
        return dim("after     no change", stream=stream)
    if k == "approval_shown":
        return warn("APPROVAL", stream=stream) + "  " + f"{p.get('server_id')}.{p.get('tool')} " + dim(_trunc(_dumps(p.get("params") or {}), 34), stream=stream) + "  " + bad("origin not shown", stream=stream)
    if k == "approval_response":
        return block("approved", stream=stream) if p.get("approved") else dim("denied", stream=stream)
    if k == "tool_execution":
        imp = p.get("impact") or {}
        return bad("EXECUTED", stream=stream) + "  deleted=" + bad(str(p.get("deleted_labels")), stream=stream) + f"  protected={p.get('deleted_protected')}  removed={imp.get('protected_records_removed')}"
    if k == "plan_end":
        return dim(f"result={p.get('result')}", stream=stream)
    return dim(_trunc(_dumps(p), 70), stream=stream)


def render_trace(path, stream=None) -> None:
    stream = stream if stream is not None else sys.stdout
    path = Path(path)
    if not path.exists():
        print(bad(f"[verbose] no trace at {path}", stream=stream), file=stream)
        return

    events = []
    for line in path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if line:
            try:
                events.append(json.loads(line))
            except json.JSONDecodeError:
                continue

    print(head("── trace ──", stream=stream) + dim(f"  {path.name}  ({len(events)} events)", stream=stream), file=stream)
    for e in events:
        seq = dim(f"seq {str(e.get('seq', '?')):>2}", stream=stream)
        src = style(e.get("source", "").ljust(30), *_source_styles(e.get("source", "")), stream=stream)
        kind = style(e.get("kind", "").ljust(20), "bold", stream=stream)
        print(f"  {seq}  {src}  {kind}  {_summary(e, stream)}", file=stream)
    print(head("── end trace ──", stream=stream), file=stream)

"""
Trace instrumentation for Urd.

Every significant event in the lab harness is emitted as a single JSONL line.
Urd's runtime analyzer reads these traces to reconstruct the observed trust graph.

Event schema (all events):
    ts:        ISO 8601 timestamp with timezone
    seq:       monotonically increasing sequence number within a run
    source:    which component emitted the event (e.g., "host", "server:weather")
    kind:      event type, see EventKind below
    payload:   kind-specific fields
    provenance: list of marker tokens present in this event's data

Event kinds:
    untrusted_source_emit   a value leaves the untrusted source, tagged with a marker
    tool_call               the host invokes a tool on a server
    tool_result             a server returns a result to the host
    context_update          the host incorporates a tool result into planning context
    param_construction      the host builds parameters for a subsequent tool call
    approval_shown          the host presents an approval prompt to the operator
    approval_response       the operator answers (approve/deny)
    tool_execution          a server actually executes a tool (post-approval)
"""
from __future__ import annotations

import json
import os
import re
import threading
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


MARKER_PATTERN = re.compile(r"URD-MARKER-[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}")


def new_marker() -> str:
    """Generate a unique, recognizable marker token.

    Markers embed in tool output and propagate through context construction;
    their presence in downstream events is hard evidence of upstream influence.
    """
    return f"URD-MARKER-{uuid.uuid4()}"


def find_markers(value: Any) -> list[str]:
    """Recursively find all Urd marker tokens inside a value of any JSON-ish type."""
    found: list[str] = []

    def walk(node: Any) -> None:
        if isinstance(node, str):
            found.extend(MARKER_PATTERN.findall(node))
        elif isinstance(node, dict):
            for v in node.values():
                walk(v)
        elif isinstance(node, (list, tuple)):
            for item in node:
                walk(item)

    walk(value)
    # preserve order of first appearance, dedupe
    seen: set[str] = set()
    result: list[str] = []
    for m in found:
        if m not in seen:
            seen.add(m)
            result.append(m)
    return result


@dataclass
class TraceWriter:
    """Append-only JSONL writer.

    Thread-safe: a single TraceWriter can be shared across components in one process.
    For stdio-subprocess servers, each server gets its own file and they are merged
    by sequence order at analysis time.
    """
    path: Path
    _seq: int = field(default=0, init=False)
    _lock: threading.Lock = field(default_factory=threading.Lock, init=False)

    def __post_init__(self) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        # truncate at construction so each run starts clean
        self.path.write_text("", encoding="utf-8")

    def emit(self, source: str, kind: str, payload: dict[str, Any]) -> None:
        with self._lock:
            self._seq += 1
            event = {
                "ts": datetime.now(timezone.utc).isoformat(),
                "seq": self._seq,
                "source": source,
                "kind": kind,
                "payload": payload,
                "provenance": find_markers(payload),
            }
            with self.path.open("a", encoding="utf-8") as f:
                f.write(json.dumps(event, separators=(",", ":")) + "\n")


def read_trace(path: Path) -> list[dict[str, Any]]:
    """Read a JSONL trace back into ordered events."""
    events: list[dict[str, Any]] = []
    with path.open("r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            events.append(json.loads(line))
    # sort by seq in case of interleaved writers
    events.sort(key=lambda e: e.get("seq", 0))
    return events


# a process-wide default writer, configured by scenario entry points
_default_writer: TraceWriter | None = None


def configure_default(path: str | os.PathLike[str]) -> TraceWriter:
    global _default_writer
    _default_writer = TraceWriter(Path(path))
    return _default_writer


def default_writer() -> TraceWriter:
    if _default_writer is None:
        raise RuntimeError(
            "Trace writer not configured. Call urd.trace.configure_default(path) first."
        )
    return _default_writer

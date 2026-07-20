"""Cross-process trace writer for the stdio path.

The in-process lab uses urd.trace.TraceWriter (truncate-on-construct, per-process
sequence). Under real transport, the host and both server subprocesses all append
to ONE trace file, so we need a globally-monotonic sequence and write mutual
exclusion across processes. This writer provides both via an flock-guarded
sidecar counter, while emitting the identical event schema the analyzer reads.

Drop-in: exposes ``emit(source, kind, payload)`` like TraceWriter, so existing
WeatherServer / AdminServer / UntrustedSource (which call default_writer().emit)
work unchanged once this is installed via urd.trace.set_default_writer.
"""
from __future__ import annotations

import json
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from urd.trace import find_markers

# Cross-process locking is POSIX flock or Windows msvcrt; if neither is available
# we fall back to best-effort unlocked append rather than crash (fcntl is
# POSIX-only, and importing it unconditionally broke the lab on Windows).
try:
    import fcntl as _fcntl
except ImportError:  # Windows
    _fcntl = None
    try:
        import msvcrt as _msvcrt
    except ImportError:
        _msvcrt = None


@contextmanager
def _exclusive_lock(fileobj):
    if _fcntl is not None:
        _fcntl.flock(fileobj.fileno(), _fcntl.LOCK_EX)
        try:
            yield
        finally:
            _fcntl.flock(fileobj.fileno(), _fcntl.LOCK_UN)
    elif _msvcrt is not None:
        fileobj.seek(0)
        try:
            _msvcrt.locking(fileobj.fileno(), _msvcrt.LK_LOCK, 1)
        except OSError:
            yield  # could not lock; proceed best-effort
            return
        try:
            yield
        finally:
            try:
                fileobj.seek(0)
                _msvcrt.locking(fileobj.fileno(), _msvcrt.LK_UNLCK, 1)
            except OSError:
                pass
    else:
        yield  # no cross-process lock available (rare); best-effort append


class SharedStdioTraceWriter:
    def __init__(self, path: str | Path, truncate: bool = False) -> None:
        self.path = Path(path)
        self.seq_path = Path(str(self.path) + ".seq")
        self.path.parent.mkdir(parents=True, exist_ok=True)
        if truncate:
            # host clears the canonical trace + counter once, before spawning servers
            self.path.write_text("", encoding="utf-8")
            self.seq_path.write_text("0", encoding="utf-8")
        elif not self.seq_path.exists():
            self.seq_path.write_text("0", encoding="utf-8")

    def emit(self, source: str, kind: str, payload: dict[str, Any]) -> None:
        # one lock guards both the sequence bump and the append, giving a true
        # global ordering consistent with real causal order across processes.
        with open(self.seq_path, "r+", encoding="utf-8") as sf:
            with _exclusive_lock(sf):
                raw = sf.read().strip()
                seq = (int(raw) if raw else 0) + 1
                sf.seek(0)
                sf.truncate()
                sf.write(str(seq))
                sf.flush()
                event = {
                    "ts": datetime.now(timezone.utc).isoformat(),
                    "seq": seq,
                    "source": source,
                    "kind": kind,
                    "payload": payload,
                    "provenance": find_markers(payload),
                }
                with open(self.path, "a", encoding="utf-8") as af:
                    af.write(json.dumps(event, separators=(",", ":")) + "\n")
                    af.flush()

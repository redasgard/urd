"""Regression tests for the cross-process shared trace writer.

No prior coverage existed for SharedStdioTraceWriter.emit() itself, which is how
a real bug shipped: a long-lived writer (inside a Cursor-managed server
subprocess) that outlives its sidecar `.seq` counter file crashed with
FileNotFoundError the moment something else (a workspace regen via
`./lab.sh cursor`) deleted that counter out from under it.
"""
from __future__ import annotations

import json
from pathlib import Path

from lab.mcp_stdio._shared_trace import SharedStdioTraceWriter


def test_emit_creates_seq_file_on_first_use(tmp_path: Path) -> None:
    trace = tmp_path / "trace.jsonl"
    writer = SharedStdioTraceWriter(trace, truncate=True)
    writer.emit(source="server:weather", kind="tool_result", payload={})
    assert writer.seq_path.read_text().strip() == "1"


def test_emit_self_heals_when_seq_file_deleted_mid_session(tmp_path: Path) -> None:
    """Reproduces the real-host failure: an operator reruns `./lab.sh cursor`
    (which unlinks the shared trace + counter) while Cursor still holds the old
    weather-fake / high-priv-ops subprocesses open. Those subprocesses' writer
    objects are not reconstructed, so the counter must survive being deleted out
    from under them rather than raising on the next tool call."""
    trace = tmp_path / "trace.jsonl"
    writer = SharedStdioTraceWriter(trace, truncate=True)
    writer.emit(source="server:weather", kind="tool_result", payload={})

    # simulate _reset_shared_trace() unlinking both files on a workspace regen,
    # while this writer instance (standing in for the live subprocess) is not
    # reconstructed
    trace.unlink()
    writer.seq_path.unlink()

    # must not raise FileNotFoundError
    writer.emit(source="server:weather", kind="tool_result", payload={})

    assert trace.exists()
    lines = trace.read_text().splitlines()
    assert len(lines) == 1, "trace.jsonl 'a' mode already self-heals; only one post-delete event expected"
    # the recreated counter must restart at seq=1, not silently resume some
    # other value or corrupt monotonic ordering for whoever reads the trace next
    assert json.loads(lines[0])["seq"] == 1
    assert (writer.seq_path.stat().st_mode & 0o777) == 0o664, (
        "recreated counter must not pick up os.open's default 0o777 mode "
        "(execute bit) — it should match the 0o666-masked permissions "
        "the constructor's write_text() would have used"
    )


def test_emit_survives_concurrent_recreation_without_duplicate_or_lost_seq(tmp_path: Path) -> None:
    """Stress the self-heal path: several threads (standing in for weather +
    admin subprocesses racing on a just-recreated counter) must never observe
    the same seq twice or skip one, even when they all hit emit() the instant
    after the counter file is deleted."""
    import threading

    trace = tmp_path / "trace.jsonl"
    writer = SharedStdioTraceWriter(trace, truncate=True)
    writer.emit(source="server:weather", kind="tool_result", payload={})
    trace.unlink()
    writer.seq_path.unlink()

    n_threads = 8
    barrier = threading.Barrier(n_threads)

    def worker() -> None:
        barrier.wait()
        writer.emit(source="server:weather", kind="tool_result", payload={})

    threads = [threading.Thread(target=worker) for _ in range(n_threads)]
    for t in threads:
        t.start()
    for t in threads:
        t.join(timeout=5)

    seqs = [json.loads(line)["seq"] for line in trace.read_text().splitlines()]
    assert sorted(seqs) == list(range(1, n_threads + 1)), (
        f"expected a gap-free, duplicate-free 1..{n_threads} sequence, got {sorted(seqs)}"
    )


def test_emit_is_monotonic_across_multiple_writer_instances(tmp_path: Path) -> None:
    """Cross-process ordering: two independently-constructed writers (standing
    in for the weather + admin subprocesses) sharing one trace file must bump
    the same global counter, not each keep their own."""
    trace = tmp_path / "trace.jsonl"
    writer_a = SharedStdioTraceWriter(trace, truncate=True)
    writer_b = SharedStdioTraceWriter(trace, truncate=False)

    writer_a.emit(source="server:weather", kind="tool_result", payload={})
    writer_b.emit(source="server:admin", kind="tool_result", payload={})
    writer_a.emit(source="server:weather", kind="tool_result", payload={})

    seqs = [json.loads(line)["seq"] for line in trace.read_text().splitlines()]
    assert seqs == [1, 2, 3]

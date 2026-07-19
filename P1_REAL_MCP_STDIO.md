# P1-real-mcp-stdio

Adds a real MCP stdio / JSON-RPC transport path that reproduces the same
cross-server authority-injection finding over a real process boundary, without
disturbing the deterministic in-process lab. Also closes the two cheap
credibility leaks (dead dependency, marker drift).

---

## Definition of done  –  checklist

| Requirement | Status |
|---|---|
| Existing 14 tests pass | ✅ (now 25 total) |
| New stdio tests pass | ✅ (4/4) |
| In-process lab unchanged | ✅ (only `lab/mcp_stdio/*` added) |
| Real stdio lab produces same HIGH value-flow finding | ✅ (signatures byte-identical to in-process) |
| Stripped-provenance stdio trace still produces HIGH | ✅ (`evidence_basis=value_flow`) |
| README says "fast harness path" and "real MCP stdio path" | ✅ |
| No claim of arbitrary-MCP-deployment support | ✅ (explicit scope note) |

## Acceptance criteria  –  verified

```
python -m lab.mcp_stdio.host_client
python -m urd.cli analyze --manifests lab/manifests/ --trace traces/mcp_stdio_compositional.jsonl
```
→ HIGH: src=server:weather, dst=server:admin, sink=admin:delete_records,
  evidence_basis=marker+value_flow, matched_value=STAGING_LOG_20260315,
  sink_path=labels[0], approval_provenance_status=absent.

Ablation (strip `provenance_observed`) → HIGH survives, evidence_basis=value_flow.

Baseline (`--baseline`) → 0 findings.

In-process vs stdio finding signatures: **EQUIVALENT** (verified field-by-field).

---

## What "real MCP stdio" means here

The MCP stdio transport is newline-delimited JSON-RPC 2.0 over a subprocess's
stdin/stdout, with an `initialize` → `notifications/initialized` → `tools/list`
→ `tools/call` lifecycle. This slice implements exactly that:

- **Real subprocesses.** The host (`subprocess.Popen`) spawns
  `lab/mcp_stdio/weather_server.py` and `admin_server.py` as separate processes.
- **Real wire protocol.** `_jsonrpc.py` frames messages as the MCP stdio spec
  requires (single line per message, no Content-Length headers). The host runs a
  real `initialize` handshake and `tools/list` against each server before any
  `tools/call`.
- **Real cross-process tracing.** `_shared_trace.py` gives a globally-monotonic
  sequence and flock-guarded appends, so host-process and server-process events
  land in one canonical trace in correct causal order. The emitted event schema
  is identical to the in-process writer, so the analyzer is unchanged.
- **Backends reused.** The stdio servers wrap the existing `WeatherServer` /
  `AdminServer` / `UntrustedSource`, so the `tool_result` / `tool_execution`
  events  –  the analyzer's sink  –  are byte-identical to the fast path.

stdout carries **only** JSON-RPC; all tracing goes to the shared file. (A server
that prints to stdout corrupts the protocol stream  –  enforced by construction,
and a good teaching point for the workshop.)

**Honest scope:** this is a faithful minimal implementation of the stdio
transport for reproducing the primitive. It is not yet a general interceptor for
arbitrary third-party MCP servers. The README states this explicitly.

## Why protocol-direct instead of the `mcp` SDK

Implemented against the MCP stdio wire format directly rather than the `mcp`
Python SDK. Two reasons: (1) it runs and is provable in any environment with zero
install friction for attendees, and (2) shipping SDK-API code that couldn't be
executed end-to-end here would be exactly the "theater with stack traces" to
avoid. The bytes on the wire are the MCP stdio protocol; the SDK is just one
client of it.

## Cheap credibility leaks  –  closed

- **Dead dependency removed.** `pydantic` was declared-but-unused. Rather than
  ship SDK/validation code that couldn't be exercised here, it is removed from
  `pyproject.toml` and replaced with **tested** stdlib manifest validation
  (`urd/manifests.py` → `ManifestError`): rejects missing/blank `server_id`,
  invalid `privilege`, malformed `tools`, bad host config, invalid JSON, and
  duplicate server ids. Covered by `tests/test_manifests.py` (7 tests).
- **Marker drift fixed.** `new_marker()` is still `uuid4` by default, but
  `configure_marker_seed()` / `URD_MARKER_SEED` give byte-stable runs. Verified
  reproducible. Committed `examples/` regenerated with `URD_MARKER_SEED=1337`, so
  repo == live run. In-process and stdio example artifacts both committed.

---

## Files added

- `lab/mcp_stdio/__init__.py`
- `lab/mcp_stdio/_jsonrpc.py`  –  newline-delimited JSON-RPC 2.0 framing
- `lab/mcp_stdio/_shared_trace.py`  –  cross-process global-seq trace writer
- `lab/mcp_stdio/_server_base.py`  –  generic MCP stdio serve loop
- `lab/mcp_stdio/weather_server.py`  –  Server A as a real stdio subprocess
- `lab/mcp_stdio/admin_server.py`  –  Server B as a real stdio subprocess
- `lab/mcp_stdio/host_client.py`  –  real client: spawn, handshake, drive scenario
- `tests/test_mcp_stdio.py`  –  4 stdio tests
- `tests/test_manifests.py`  –  7 manifest-validation tests
- `examples/mcp_stdio_compositional.divergence.json`  –  committed stdio artifact

## Files changed (additive / backward-compatible)

- `urd/trace.py`  –  `set_default_writer()`, `configure_marker_seed()`, seeded `new_marker()`
- `urd/manifests.py`  –  validation + `ManifestError`
- `pyproject.toml`  –  drop `pydantic`; package list now includes `lab.mcp_stdio`
- `lab/scenarios/{baseline,compositional}.py`  –  honor `URD_MARKER_SEED` (behavior otherwise unchanged)
- `README.md`  –  two-path documentation, stdio run block, scope + reproducibility notes

## Remaining (future)

- General MCP interception (intercept an arbitrary server you point Urd at).
- P2 roadmap untouched: multi-hop laundering, fragment/normalization taint,
  param smuggling, SARIF output, red-team playbook.

## Run it

```bash
# real transport
python -m lab.mcp_stdio.host_client                 # or --baseline
python -m urd.cli analyze --manifests lab/manifests/ \
    --trace traces/mcp_stdio_compositional.jsonl \
    --output traces/mcp_stdio_compositional.divergence.json

# money slide (ablation): strip provenance_observed, HIGH still fires as value_flow
```

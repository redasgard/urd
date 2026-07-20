# URD  –  patch changelog

## Offensive rebuild

`urd` is now an offensive toolkit, not a defensive analyzer. Two verbs:
`find-seams` (recon — enumerate low-trust → high-trust injection seams in a
target's manifests or a captured session) and `analyze` (proof — reconstruct
the authority path an injection took).

The `urd cli policy` subcommand noted further down this changelog was **removed**
from `urd`. The provenance-bound approval control moved to a separate `guard`
package that imports nothing from `urd` (it reads `urd analyze` output as data),
so the offensive tool ships with zero defensive surface. The lab's `policy-check`
now runs `urd analyze` → `guard`.

Destructive-sink detection is unified in `urd/heuristics.py` (word-boundary token
matching, shared by `find-seams` and `analyze`) so the two never disagree on a
target.

---

# URD  –  P0 patch changelog

What changed in this pass, mapped to the takeaway's priority list. The fatal
contradiction is closed: the headline finding no longer depends on the marker
reaching `delete_records`, nor on the host volunteering provenance.

---

## The contradiction, gone

**Before:** README/docstrings claimed *"the marker appears verbatim in `delete_records` params."* False  –  `REFS_PATTERN` strips the marker; only the label survives. The HIGH finding was produced only because the host emits a `provenance_observed` side channel. Strip that event → HIGH finding vanished.

**After:** the HIGH finding is produced by **marker-independent value-flow reconstruction**. Proven, not asserted:

```
full trace                       → HIGH  basis=marker+value_flow  weather → admin:delete_records
provenance_observed STRIPPED     → HIGH  basis=value_flow         weather → admin:delete_records   ← survives
baseline (control)               → 0 findings
```

The finding's `evidence_basis` downgrades from `marker+value_flow` to `value_flow` under ablation, and the finding itself persists. That's the money slide, and it's now a passing test.

---

## P0  –  done

1. **Proof renamed to value-flow.** `README.md` and `lab/scenarios/compositional.py` now state: *"attacker-controlled text emitted by a low-privilege server is extracted by the host and reused verbatim as a parameter to a high-privilege destructive tool call, while the approval surface shows only the final action and omits upstream origin."* Markers are explicitly relabeled as ground-truth instrumentation, not proof.

2. **Marker-independent taint detection added** (`urd/runtime.py`). Every string emitted in a low-trust `tool_result` is indexed (whole leaves + distinctive tokens, markers stripped). Any later high-privilege `tool_call` argument that matches  –  `exact`, `tainted_token_in_arg`, or `arg_in_tainted_value`  –  produces a `ValueFlowEdge`. Minimum match length guards against trivial collisions; self-edges (a server echoing its own output) are dropped.

3. **HIGH finding survives without `provenance_observed`.** Verified by ablation and locked by `test_high_finding_survives_without_provenance_observed`.

4. **Report fields enriched** (`urd/divergence.py`). Each finding now carries `evidence_basis`, `src_event_kind`, `dst_event_kind`, `src_path`, `sink_path`, `matched_value`, `match_type`, `marker`, and `approval_provenance_status` (`absent` / `present` / `unknown`, computed from the actual `approval_shown` payload). The two evidence layers are merged per authority path so a single finding reflects both when they corroborate.

5. **README + docstrings rewritten** so nothing claims the marker reaches `delete_records`. An honesty-guard test (`test_marker_does_not_reach_delete_params_verbatim`) asserts the marker is in fact absent from the delete params, so the claim and the code can't drift apart again.

## P1  –  partial (quick wins taken)

- **Malformed JSONL handled** (`urd/trace.py`): bad lines are skipped with a stderr warning instead of crashing the analyzer.
- **DOT severity visualization improved** (`urd/divergence.py::to_dot`): declared = black, marker edges = orange, value-flow edges = purple, and edges in a HIGH finding are drawn bold. The value-flow edge now renders even after the marker edge is ablated away.

## P1  –  still open

- Real MCP stdio transport mode (two subprocess servers, real JSON-RPC, one host client). Still the top remaining credibility item; say it up front until it exists.
- `pydantic` is still declared but unused  –  either wire it into manifest validation or drop it from `pyproject.toml`.
- Reproducible demo seed (`new_marker()` is `uuid4`, so committed artifacts differ per regen). Add a `--seed` or regenerate `examples/` at build time. Current README ablation uses live-generated traces, so repo == stage if you regenerate before the talk.

## P2  –  untouched (roadmap)

Multi-hop laundering, fragment/normalization taint, param smuggling, SARIF output, red-team playbook section.

---

## Files touched

- `urd/runtime.py`  –  value-flow taint engine + approval-provenance index (rewritten)
- `urd/divergence.py`  –  two-layer findings, merge, enriched fields, severity-aware DOT (rewritten)
- `urd/trace.py`  –  resilient `read_trace`
- `lab/scenarios/compositional.py`  –  docstring reframed
- `README.md`  –  proof language, marker note, ablation walkthrough
- `tests/test_divergence.py`  –  money-slide test, value-flow-edge test, honesty guard (now 14 tests, all green)
- `examples/compositional.{divergence.json,dot}`  –  regenerated against the new pipeline

## Run it

```bash
python -m lab.scenarios.baseline
python -m lab.scenarios.compositional
python -m urd.cli analyze --manifests lab/manifests/ --trace traces/compositional.jsonl \
    --output traces/compositional.divergence.json --dot traces/compositional.dot
# then the ablation block from the README → HIGH finding still fires
```

---

# DEF CON 34 final repo doc/runtime sync patch

This patch closes the workshop-material drift found in the final bundle review.

## Fixed

- `docs/workshop/02_lab_config.md` now describes the shipped interface: `lab.sh`, `lab.ps1`, `lab.cmd`, and `scripts/run_lab.py`. It no longer promises a top-level `./lab` executable, `lab-local`, or per-command `scripts/*.sh` wrappers.
- `docs/workshop/03_emergency_rescue_plan_abc.md` now uses commands that actually exist in the repo. Plan A uses `docker compose run --rm urd-lab ./lab.sh <verb>`. Plan B uses `./lab.sh` / `.\lab.ps1`. Plan C stays static-trace based.
- `docs/workshop/01_final_script.md` now explicitly states the current detector boundary: exact value reuse only. It does not claim substring, encoding, semantic paraphrase, or LLM-mutated value recovery.
- `docs/workshop/01_final_script.md` and `02_lab_config.md` now mention the expected secondary `URD-0002` MEDIUM finding and explain why `URD-0001` is the stage focus.
- `lab/mcp_stdio/weather_server.py` now honors `URD_MARKER_SEED` in the child subprocess, so marker generation is reproducible across stdio runs. The previous host-only seed path was a dead knob for the child marker.
- Added a stdio regression test proving the same `URD_MARKER_SEED` produces the same untrusted-source marker across child subprocess runs.

## Revalidated

```text
PYTHONPATH=$PWD pytest -q -> 26 passed
./lab.sh all -> passed
baseline -> 0 findings
compositional -> HIGH marker+value_flow
ablated -> HIGH value_flow
```
## Final script trace-shape correction

- Updated `docs/workshop/01_final_script.md` Section 5 to show the real nested JSONL event shape from `examples/traces/compositional.trace.jsonl`.
- Removed the stale flattened `server` / `event_kind` / `path` / `value` slide objects from the raw-trace section.
- Regenerated and rendered `docs/workshop/01_final_script.docx` after the correction.

## Positioning Patch: Old Failure, New Composition Layer

- Updated `docs/workshop/01_final_script.md` to explicitly state that confused deputy, taint flow, and provenance are not new primitives.
- Added a "What This Is Not / What This Is" section to preempt the "you rediscovered 2005" objection.
- Tightened the claim to: old authority failure modes reappearing in MCP host/tool composition, with approval surfaces blind to value origin.
- Kept the detector boundary explicit: current artifact proves exact value reuse, not substring, encoding, paraphrase, or semantic mutation recovery.

## P2-breach-impact-objective

Adds a controlled, sandboxed breach objective so the RTV workshop demonstrates impact, not only analysis.

Changes:

- Re-seeded the SQLite lab database with richer record metadata: `label`, `category`, `protected`, and `content`.
- Kept the default malicious selector `STAGING_LOG_20260315` for backwards-compatible value-flow signatures, but changed its meaning to `category=incident_evidence`, `protected=true`.
- Added protected retarget candidates:
  - `BILLING_ESCALATION_9001`
  - `CUSTOMER_PROFILE_4242`
  - `INCIDENT_EVIDENCE_7777`
- Added `records_snapshot` trace events before and after the delete operation.
- Added operation impact metadata to `tool_execution` and Urd findings:
  - `state_changed`
  - `operation`
  - `protected_records_removed`
  - `removed_labels`
  - `removed_categories`
  - `breach_objective`
- Added mission mode:
  - `python -m lab.mcp_stdio.host_client --mission evidence-delete`
  - wrapper: `./lab.sh mission`
- Added attendee retarget wrappers:
  - `./lab.sh target-billing`
  - `./lab.sh target-customer`
  - `./lab.sh target-incident`
- Updated workshop docs to frame the primitive as execution authority vs. target-selection authority.
- Regenerated static example traces and findings.
- Added P2 regression tests for protected-record deletion, baseline non-impact, approval origin omission, Urd impact reporting, ablated impact preservation, and attendee retargeting.

Safety scope:

- The breach objective is confined to the local SQLite sandbox.
- The workshop explicitly frames this as a controlled authority-model failure, not real-world evidence destruction guidance.


## P2.1 RTV Breach-Impact Framing

- Tightened the stage script around the breach-impact reveal for an RTV audience.
- Reframed P2 as protected state change, not better observability.
- Added explicit line: "I do not care whether the delete was logged. By the time the log exists, the protected record is already gone."
- Fixed approval prompt comparison so the bad prompt does not reveal hidden target metadata.
- Updated the Urd-informed approval prompt to show target metadata and target-selection provenance.
- Added concise P0/P1/P2 closing: detector, transport, breach impact.
- Updated README and WORKSHOP_QUICKSTART to distinguish trace evidence from the actual authority-model failure.

## P3-retargetable-selection-authority

P3 upgrades P2 from a single breach-impact objective to a retargetable primitive.

The new claim:

```text
The attacker does not need delete authority.
The attacker needs influence over the value that delete authority consumes.
```

Added `./lab.sh retarget-demo`, which runs the same sandboxed breach objective against multiple protected targets while keeping the privileged executor, approval model, host workflow, and permissions unchanged.

Targets:

```text
BILLING_ESCALATION_9001 -> protected billing_evidence removed
CUSTOMER_PROFILE_4242   -> protected customer_record removed
INCIDENT_EVIDENCE_7777  -> protected incident_evidence removed
```

Updated workshop script and lab docs to make the 110% RTV point explicit:

```text
The first run proves impact.
The retarget runs prove control.
Permissions answered who could pull the trigger.
They did not answer who aimed the gun.
```

Added tests for customer retargeting and cross-target retargetability.

## P4-planner-mode-trace

- Added `--planner llm-sim` to the stdio host client.
- Added `./lab.sh planner-demo` as an optional workshop-safe planner-mode run.
- Planner mode emits `planning_context` and `planner_decision` events between low-trust context and the high-trust `admin.delete_records` call.
- Added optional `--planner openai-compatible` support for local/owned OpenAI-compatible endpoints. It is not required for the workshop and falls back safely when not configured.
- Added static planner examples under `examples/traces/planner/` and `examples/findings/planner/`.
- Updated workshop docs to answer the "regex with ambitions" objection without making live model APIs part of the core claim.

## P5-live-room-hardening

Purpose: close the remaining RTV back-row objections without making the workshop depend on fragile live third-party host behavior.

Changes:

- Rewrote `docs/workshop/01_final_script.md` to fix section numbering and cut repeated authority/provenance throat-clearing.
- Moved `./lab.sh retarget-demo` into the first live block so breach impact and retargetability land before attendee setup chaos.
- Added `OPERATOR_RUNBOOK.md` with stage commands, fallback rules, and hostile Q&A answers.
- Added `examples/external-host/` with a sample external-host trace, normalized Urd trace, findings, DOT output, and README.
- Added `scripts/normalize_external_host_trace.py` as a small adapter example. This is not a universal interceptor; it demonstrates the trace-schema contract.
- Added `tests/test_p5_external_adapter.py` to verify the adapter produces a Urd-compatible trace and a HIGH impact finding.
- Updated README, WORKSHOP_QUICKSTART, lab config, and rescue plan with the live-room hinge and adapter boundary language.

Boundary:

- The live workshop remains deterministic and sandboxed.
- P5 does not claim semantic taint recovery for paraphrase, encoding, chunking, or summarization.
- P5 does not claim universal live interception of arbitrary MCP hosts.

## P6-live-impact-inversion

- Reworked `docs/workshop/01_final_script.md` so the live room opens with protected state loss, not a long scope sermon.
- Moved `./lab.sh mission` and `./lab.sh retarget-demo` into the first live block.
- Reduced repeated execution-vs-selection prose and turned the JSON section into a single source -> sink -> missing-record story.
- Updated `OPERATOR_RUNBOOK.md` with the P6 first-20-minutes run order and static-trace fallback rule.
- Updated `README.md` and `WORKSHOP_QUICKSTART.md` so retarget is the live hinge, not an afterthought.
- Added `examples/external-host-witness/` as an explicit slot for a real authorized third-party host capture, intentionally not populated with fake evidence.
- Preserved the honest boundary: external-host adapter examples are not universal host interception or production host pwnage.


## P7-live-room-stage-cut

- Reordered the final stage script around a first-25-minute proof chain: mission, retarget, trace, Urd finding, ablation.
- Moved exact-value and harness boundary disclaimers into the cold open.
- Cut repeated authority/provenance explanation and reduced Urd/product-language exposure.
- Marked planner-demo as optional live/Q&A instead of part of the critical first-run path.
- Updated `OPERATOR_RUNBOOK.md` with the first-25-minute script and static fallback behavior.
- Preserved the external-host adapter boundary without pretending it is a third-party host capture.

## P8-provenance-bound-approval-polish

Purpose: move the workshop past "we can reconstruct the breach" and show a concrete approval control that is not SOC-flavored "log harder."

Changes:

- Added `urd/policy.py` with provenance-bound approval evaluation.
- Added `urd cli policy` subcommand.
- Added `./lab.sh policy-check` command through `scripts/run_lab.py`.
- Added `examples/findings/compositional.policy.json` static fallback artifact.
- Added tests for BLOCK on the protected breach objective and ALLOW on baseline.
- Updated the stage script to include a short policy-check block after ablation.
- Updated README, WORKSHOP_QUICKSTART, lab config, rescue plan, and operator runbook.

Policy:

```text
LOW_TRUST_SELECTION_TO_HIGH_TRUST_DELETE
```

Expected live result:

```text
[policy] final_decision=BLOCK
[policy] LOW_TRUST_SELECTION_TO_HIGH_TRUST_DELETE decision=BLOCK
[target] STAGING_LOG_20260315 categories=['incident_evidence'] protected_records_removed=1
```

Stage meaning:

```text
Logging tells you who shot the hostage.
Provenance-bound approval asks who aimed before anyone pulls the trigger.
```


## P9 - Local Gemma Planner Witness

Added optional local LLM planner support through Ollama. The deterministic harness remains the required workshop path. `./lab.sh planner-gemma` routes the target-selection step through an Ollama planner adapter using `URD_OLLAMA_MODEL` with default `gemma4:e4b`. If Ollama is unavailable, the adapter records an explicit `ollama:fallback-llm-sim` planner decision rather than interrupting the workshop.

Added mocked/static planner artifacts under `examples/traces/planner/ollama-gemma4-e4b.trace.jsonl` and `examples/findings/planner/ollama-gemma4-e4b.findings.json`. These demonstrate the trace shape and analysis output without claiming a live third-party host capture. Added tests for mocked Ollama planner output and fallback behavior. Updated workshop docs, quickstart, and operator runbook to keep local Gemma as an optional witness path only.

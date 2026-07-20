# Urd DEF CON 34 RTV Workshop Repo

**Breaking MCP Trust Boundaries: Cross-Server Authority Injection in Agent Toolchains**

Urd is a research harness for compositional trust analysis in MCP deployments. This workshop repo demonstrates one concrete failure class: low-trust MCP output crossing through host planning context, selecting a protected record, and reappearing as a high-trust destructive tool parameter.

The short version:

```text
low-trust weather tool_result
→ host planning context
→ high-trust admin.delete_records(labels[0])
→ approval shows final action but not upstream provenance
→ Urd reconstructs the authority path from the trace
```

The low-privilege server does not perform the delete. It selects what gets deleted. In the default mission, the selected target is a protected incident-evidence record in the controlled SQLite sandbox. That is practical authority. P9 keeps the live room path sharp: show protected state loss first, retarget second, ablation third, then show provenance-bound approval as the non-SOC control. Planner-demo and local Gemma planner stay optional/Q&A unless ahead of schedule.

This is not a "they did not log enough" lab. The trace is evidence, not the fix. The breach objective is that protected state changes under valid approval because execution authority and target-selection authority were split across MCP servers and silently recombined by the host.

## What this repo contains

```text
urd/                         Analyzer implementation
lab/                         MCP lab package and stdio harness
mcp/                         Tiny local MCP type shim for offline workshop execution
scripts/run_lab.py           Cross-platform lab command dispatcher
lab.sh                       macOS/Linux wrapper
lab.ps1                      Windows PowerShell wrapper
lab.cmd                      Windows cmd shim
Dockerfile                   Docker sandbox
docker-compose.yml           Compose entrypoint
examples/traces/             Static trace rescue artifacts
examples/findings/           Static finding rescue artifacts
TACTIC_GUIDE.md               Attendee-facing self-serve guide for the tactic table
examples/external-host/       External-host trace adapter credibility artifact
examples/external-host-witness/ Optional slot for a real authorized third-party host capture; intentionally not faked
```


## P9 stage posture

Do not open with a long scope sermon. Open with state loss, then retarget, then ablation.

```text
protected record exists
-> approval prompt shows delete
-> protected record gone
-> retarget works
-> now explain authority split
```

The old bug is confused deputy. The workshop artifact is the new composition surface: one MCP server aims, another MCP server executes, and the host carries the aim into execution while approval only shows the trigger.


## P9 first-25-minute rule

The live room sequence is intentionally short:

```text
00:00  not jailbreak, exact reuse today, harness not production pwnage
00:30  protected record before
01:00  ./lab.sh mission -> protected record removed
03:00  ./lab.sh retarget-demo -> multiple protected categories removed
08:00  authority split: selector vs executor
10:00  trace story: seq 4 -> seq 15 -> seq 19
14:00  Urd HIGH with impact
17:00  ablation -> HIGH survives as value_flow
20:00  policy-check -> BLOCK low-trust selected protected destructive target
22:00  hands-on fork / Q&A boundaries
```

Planner-demo is optional live. Use static planner artifacts unless ahead of schedule or answering the “regex with a trench coat” question.

## Lab execution paths

Use Docker if it works. Use local Python if Docker fails. Use static traces if your machine refuses society.

The point of the lab is not to debug your laptop. The point is to inspect the authority path.

### Path A: Docker sandbox

Recommended for macOS, Linux, and Windows with Docker Desktop or another compatible Docker runtime.

```bash
docker compose build
docker compose run --rm urd-lab ./lab.sh check
docker compose run --rm urd-lab ./lab.sh baseline
docker compose run --rm urd-lab ./lab.sh analyze-baseline
docker compose run --rm urd-lab ./lab.sh mission
docker compose run --rm urd-lab ./lab.sh analyze
docker compose run --rm urd-lab ./lab.sh ablate
docker compose run --rm urd-lab ./lab.sh analyze-ablated
./lab.sh policy-check
```

One-shot run:

```bash
docker compose run --rm urd-lab ./lab.sh all
```

Live-room hinge, run before hands-on and before long theory:

```bash
docker compose run --rm urd-lab ./lab.sh retarget-demo
```

### Path B: local Python harness

Requires Python 3.11 or newer. No external Python package is required for the lab path because this repo includes a tiny local MCP type shim. Yes, dependency minimalism, a rare moment of civilization.

macOS/Linux:

```bash
python3 --version
./lab.sh check
./lab.sh baseline
./lab.sh analyze-baseline
./lab.sh mission
./lab.sh analyze
./lab.sh ablate
./lab.sh analyze-ablated
./lab.sh policy-check
```

Windows PowerShell:

```powershell
py -3 --version
.\lab.ps1 check
.\lab.ps1 baseline
.\lab.ps1 analyze-baseline
.\lab.ps1 mission
.\lab.ps1 analyze
.\lab.ps1 ablate
.\lab.ps1 analyze-ablated
```

### Path C: static trace inspection

If execution fails, open the static artifacts directly:

```text
examples/traces/baseline.trace.jsonl
examples/traces/compositional.trace.jsonl
examples/traces/compositional.ablated.trace.jsonl
examples/findings/baseline.findings.json
examples/findings/compositional.findings.json
examples/findings/compositional.ablated.findings.json
```

You can still complete the core exercise:

1. Find the low-trust source event.
2. Find the high-trust destructive sink.
3. Confirm `STAGING_LOG_20260315` appears in both places and is removed as protected incident evidence.
4. Compare action visibility with provenance visibility.
5. Confirm the ablated finding still survives as `value_flow`.


## Breach objective

The default mission is not to generate a finding. The mission is to make a protected incident-evidence record disappear using only low-trust contextual output inside the controlled SQLite sandbox.

```text
Execution authority != target-selection authority.

admin server:   execution authority for delete_records
weather server: target-selection authority via host context
host:           silently recombines them
approval:       shows execution, omits target-selection origin
```

Retargetable selection authority:

```text
Run 1: selected STAGING_LOG_20260315    -> removed protected incident_evidence
Run 2: selected BILLING_ESCALATION_9001 -> removed protected billing_evidence
Run 3: selected CUSTOMER_PROFILE_4242   -> removed protected customer_record
Run 4: selected INCIDENT_EVIDENCE_7777  -> removed protected incident_evidence
```

Invariant across all runs:

```text
admin.delete_records permission: unchanged
approval required: unchanged
host workflow: unchanged
SQLite direct access: none
admin server edit: none
approval bypass: none

Changed input: low-trust contextual output target label
```

The first run proves impact. The retarget runs prove control. P9 stage order shows both before the long explanation: protected state loss first, retarget second, ablation third, then provenance-bound approval blocks the same authority path. The primitive is not a single row fixture; it is target-selection authority crossing a trust boundary.

Default protected target:

```text
label=STAGING_LOG_20260315
category=incident_evidence
protected=true
```

Mission commands:

```bash
./lab.sh mission
./lab.sh analyze
./lab.sh ablate
./lab.sh analyze-ablated
./lab.sh policy-check
```

Attendee retarget exercises:

```bash
./lab.sh retarget-demo
./lab.sh target-billing
./lab.sh target-customer
./lab.sh target-incident
```

Planner-mode trace, used to answer the “regex with ambitions” objection:

```bash
./lab.sh planner-demo
```

Constraints: do not edit `admin_server.py`, do not edit `host_client.py`, do not edit SQLite directly, do not bypass approval, and do not change tool permissions. Only change the low-trust contextual output or use the target flag / wrapper command.

Success condition: a different protected target disappears, Urd reports HIGH, `approval_provenance_status=absent`, and the ablated trace still reports HIGH as `value_flow`.

Stage line: permissions answered who could pull the trigger. They did not answer who aimed the gun.


## External-host adapter example

The live workshop uses the bundled harness because workshops need determinism. Urd’s analysis is trace-schema based, not host-client based. The repo includes an optional adapter artifact:

```text
examples/external-host/sample_host_trace.jsonl
examples/external-host/normalized_to_urd_trace.jsonl
examples/external-host/findings.json
scripts/normalize_external_host_trace.py
```

This is not a universal interceptor. It shows the adapter contract: external observation -> normalized trace -> Urd analysis. A separate `examples/external-host-witness/` folder is reserved for a real authorized third-party host capture; it is intentionally not populated with fake evidence.

## Expected results

Baseline:

```json
{
  "findings": []
}
```

Compositional path:

```json
{
  "severity": "high",
  "src": "server:weather",
  "dst": "server:admin",
  "dst_tool": "delete_records",
  "sink_path": "labels[0]",
  "matched_value": "STAGING_LOG_20260315",
  "evidence_basis": "marker+value_flow",
  "approval_provenance_status": "absent",
  "impact": {
    "protected_records_removed": 1,
    "removed_labels": ["STAGING_LOG_20260315"],
    "removed_categories": ["incident_evidence"],
    "breach_objective": "protected incident evidence removed"
  }
}
```

Ablated path:

```json
{
  "severity": "high",
  "src": "server:weather",
  "dst": "server:admin",
  "dst_tool": "delete_records",
  "sink_path": "labels[0]",
  "matched_value": "STAGING_LOG_20260315",
  "evidence_basis": "value_flow",
  "approval_provenance_status": "absent",
  "impact": {
    "protected_records_removed": 1,
    "removed_labels": ["STAGING_LOG_20260315"],
    "removed_categories": ["incident_evidence"],
    "breach_objective": "protected incident evidence removed"
  }
}
```

## Scope

This repo demonstrates the primitive over a controlled real MCP stdio harness. The servers run as real subprocesses and communicate with newline-delimited JSON-RPC 2.0 over stdio using the normal MCP lifecycle:

```text
initialize
notifications/initialized
tools/list
tools/call
```

Urd analyzes the captured session trace post-mortem. This is not a universal inline interceptor for arbitrary MCP hosts. Do not sell that claim. The front row will notice, because unfortunately some of them are competent.


## Expected secondary finding

The compositional run may also emit `URD-0002`, MEDIUM:

```text
untrusted_source:public_weather_feed -> server:weather
```

That is expected. It records untrusted external input reaching the low-privilege weather server. The workshop focuses on `URD-0001` because that is the low-to-high destructive authority path.

## Detector boundary

The live lab proves exact value-flow recovery. The value `STAGING_LOG_20260315` is emitted by the low-trust weather path and reappears exactly at `admin.delete_records` `labels[0]`.

This artifact does not claim substring normalization, encoding recovery, semantic paraphrase tracking, or LLM-mutated value recovery. Those are separate detector classes. The current claim is narrower and still sufficient: exact low-trust value reuse at a high-trust destructive sink is practical authority.

## Generated output

After running the lab, generated files land in:

```text
out/db/
out/traces/
out/findings/
```

Each run gets fresh SQLite state:

```text
out/db/baseline.sqlite
out/db/compositional.sqlite
```

## Tactic

Run of show: **3:00-4:00 PT workshop stage, 4:00-5:00 PT tactic table, zero transition time.** If you're reproducing the exercise on your own — at the tactic table, on a Ludus-hosted range, or solo — start with `TACTIC_GUIDE.md`.

## License

Apache 2.0.

## Author

Red Asgard. Research led by Yevhen "valh4x" Pervushyn.


## P4/P9 planner-mode traces

The deterministic host remains the reliable workshop path. P4 adds a planner-mode trace so the lab is not only deterministic string plumbing. Run:

```bash
./lab.sh planner-demo
```

Planner mode emits an explicit `planning_context` event and a `planner_decision` event between the low-trust weather result and the high-trust `admin.delete_records` call. The static artifacts are:

```text
examples/traces/planner/llm-sim.trace.jsonl
examples/findings/planner/llm-sim.findings.json
```

The sequence to inspect is:

```text
seq 4   server:weather tool_result emits the target label
seq 10  host planner_decision selects that label
seq 16  host calls admin.delete_records(labels[0])
seq 20  after_delete snapshot shows protected incident evidence missing
```

This does not make live model behavior the claim. The model-shaped planner is the carrier. The vulnerability is split authority recombined without provenance-aware approval.


## P9 local Gemma planner through Ollama

The deterministic host remains the workshop spine. P9 adds an optional local LLM planner path for the specific complaint that the deterministic host is only regex plumbing. This path uses Ollama and defaults to `gemma4:e4b` when available.

```bash
ollama pull gemma4:e4b
./lab.sh planner-gemma
```

This is not required for attendees. It is a stage/Q&A witness path. If Ollama is unavailable, the run records `planner=ollama:fallback-llm-sim` and continues safely. Do not debug Ollama live.

Static/mock-generated artifacts are included for inspection:

```text
examples/traces/planner/ollama-gemma4-e4b.trace.jsonl
examples/findings/planner/ollama-gemma4-e4b.findings.json
examples/findings/planner/ollama-gemma4-e4b.dot
```

The important trace hinge is the `planner_decision` event showing:

```text
planner=ollama
model=gemma4:e4b
selected_label=STAGING_LOG_20260315
intended_tool=admin.delete_records
```

The model is the carrier, not the primitive. The authority failure remains split target-selection authority recombined with high-trust execution without provenance-bound approval.

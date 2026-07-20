from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
from pathlib import Path

from urd.pretty import head, dim, ok, bad, block, info, style
from lab.trace_view import render_trace

ROOT = Path(__file__).resolve().parents[1]

VERBOSE = False  # set by --verbose/-v; when on, print the full trace after a run
TRACES = ROOT / "traces"
OUT = ROOT / "out"
OUT_TRACES = OUT / "traces"
OUT_FINDINGS = OUT / "findings"
OUT_DB = OUT / "db"
MANIFESTS = ROOT / "lab" / "manifests"
SEED = "1337"

RETARGETS = [
    ("billing", "BILLING_ESCALATION_9001", "billing_evidence"),
    ("customer", "CUSTOMER_PROFILE_4242", "customer_record"),
    ("incident", "INCIDENT_EVIDENCE_7777", "incident_evidence"),
]


def mkdirs() -> None:
    for p in (TRACES, OUT_TRACES, OUT_FINDINGS, OUT_DB):
        p.mkdir(parents=True, exist_ok=True)


def run(cmd: list[str], *, allow_findings: bool = False) -> int:
    env = dict(os.environ)
    env.setdefault("URD_MARKER_SEED", SEED)
    print(dim("$ " + " ".join(cmd)), flush=True)
    proc = subprocess.run(cmd, cwd=ROOT, env=env)
    if proc.returncode not in (0, 1 if allow_findings else 0):
        return proc.returncode
    return 0


def copy_if_exists(src: Path, dst: Path) -> None:
    if src.exists():
        dst.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(src, dst)


def check() -> int:
    mkdirs()
    print(head("Urd DEF CON 34 lab check"))
    print(dim(f"python: {sys.version.split()[0]}"))
    print(dim(f"repo:   {ROOT}"))
    print(dim(f"out:    {OUT}"))
    try:
        import urd  # noqa: F401
        import lab  # noqa: F401
        import mcp  # noqa: F401
    except Exception as exc:
        print(bad(f"import check failed: {exc}"), file=sys.stderr)
        return 2
    print("imports: " + ok("ok"))
    print(dim("If Docker or Python execution fails later, open examples/traces/ and examples/findings/."))
    return 0


def baseline() -> int:
    mkdirs()
    rc = run([sys.executable, "-m", "lab.mcp_stdio.host_client", "--baseline"])
    copy_if_exists(TRACES / "mcp_stdio_baseline.jsonl", OUT_TRACES / "baseline.trace.jsonl")
    copy_if_exists(TRACES / "mcp_stdio_baseline.admin.sqlite", OUT_DB / "baseline.sqlite")
    print(dim(f"baseline trace: {OUT_TRACES / 'baseline.trace.jsonl'}"))
    if VERBOSE:
        render_trace(OUT_TRACES / "baseline.trace.jsonl")
    return rc


def compositional(target: str | None = None, mission: bool = False, planner: str = "deterministic") -> int:
    mkdirs()
    cmd = [sys.executable, "-m", "lab.mcp_stdio.host_client"]
    if planner != "deterministic":
        cmd += ["--planner", planner]
    if mission:
        cmd += ["--mission", "evidence-delete"]
    if target:
        cmd += ["--target", target]
    rc = run(cmd)
    trace_name = "mcp_stdio_compositional" if planner == "deterministic" else f"mcp_stdio_{planner.replace('-', '_')}_compositional"
    out_name = "compositional" if planner == "deterministic" else f"planner-{planner}"
    copy_if_exists(TRACES / f"{trace_name}.jsonl", OUT_TRACES / f"{out_name}.trace.jsonl")
    copy_if_exists(TRACES / f"{trace_name}.admin.sqlite", OUT_DB / f"{out_name}.sqlite")
    print(dim(f"{out_name} trace: {OUT_TRACES / (out_name + '.trace.jsonl')}"))
    if VERBOSE:
        render_trace(OUT_TRACES / f"{out_name}.trace.jsonl")
    return rc


def analyze_trace(trace: Path, output: Path, dot: Path | None = None) -> int:
    mkdirs()
    if not trace.exists():
        print(bad(f"trace not found: {trace}"), file=sys.stderr)
        return 2
    cmd = [
        sys.executable,
        "-m",
        "urd.cli",
        "analyze",
        "--manifests",
        str(MANIFESTS),
        "--trace",
        str(trace),
        "--output",
        str(output),
    ]
    if dot is not None:
        cmd += ["--dot", str(dot)]
    return run(cmd, allow_findings=True)


def analyze() -> int:
    comp = OUT_TRACES / "compositional.trace.jsonl"
    base = OUT_TRACES / "baseline.trace.jsonl"
    if comp.exists():
        return analyze_trace(comp, OUT_FINDINGS / "compositional.findings.json", OUT_FINDINGS / "compositional.dot")
    return analyze_trace(base, OUT_FINDINGS / "baseline.findings.json", OUT_FINDINGS / "baseline.dot")


def analyze_baseline() -> int:
    return analyze_trace(OUT_TRACES / "baseline.trace.jsonl", OUT_FINDINGS / "baseline.findings.json", OUT_FINDINGS / "baseline.dot")


def ablate() -> int:
    mkdirs()
    src = OUT_TRACES / "compositional.trace.jsonl"
    dst = OUT_TRACES / "compositional.ablated.trace.jsonl"
    if not src.exists():
        print(bad(f"missing compositional trace: {src}"), file=sys.stderr)
        print(dim("run ./lab.sh compositional first"), file=sys.stderr)
        return 2
    kept = []
    removed = 0
    for line in src.read_text(encoding="utf-8").splitlines():
        if not line.strip():
            continue
        event = json.loads(line)
        if event.get("kind") == "provenance_observed":
            removed += 1
            continue
        kept.append(event)
    dst.write_text("".join(json.dumps(e, sort_keys=True) + "\n" for e in kept), encoding="utf-8")
    print(dim(f"ablated trace: {dst}"))
    print(head("ablation:") + f" removed provenance_observed events: {removed}")
    return 0


def analyze_ablated() -> int:
    return analyze_trace(
        OUT_TRACES / "compositional.ablated.trace.jsonl",
        OUT_FINDINGS / "compositional.ablated.findings.json",
        OUT_FINDINGS / "compositional.ablated.dot",
    )


def find_seams() -> int:
    """Recon: enumerate the injection seams in the lab's declared manifests.

    Static pass shows where a low-trust source can reach a high-trust sink; if a
    mission trace exists, confirm which seam actually fired and with what value.
    """
    mkdirs()
    out = OUT_FINDINGS / "seams.json"
    cmd = [sys.executable, "-m", "urd.cli", "find-seams",
           "--manifests", str(MANIFESTS), "--output", str(out)]
    trace = OUT_TRACES / "compositional.trace.jsonl"
    if trace.exists():
        cmd += ["--trace", str(trace)]
    return run(cmd, allow_findings=True)


def mission() -> int:
    return compositional(mission=True)



def policy_check() -> int:
    """Demonstrate the one wall: provenance-bound approval blocking the breach.

    `guard` is the defensive companion, shipped separately from the urd offensive
    toolkit. The flow is honest about the split: urd proves the authority path,
    then guard reads that proof and decides whether it may proceed before a
    low-trust selector's protected target reaches a high-trust destructive delete.
    """
    mkdirs()
    trace = OUT_TRACES / "compositional.trace.jsonl"
    if not trace.exists():
        print(dim("missing compositional trace; running mission first"))
        rc = mission()
        if rc != 0:
            return rc
    trace = OUT_TRACES / "compositional.trace.jsonl"
    findings = OUT_FINDINGS / "compositional.findings.json"

    # urd (offense) proves the authority path...
    rc = run([
        sys.executable, "-m", "urd.cli", "analyze",
        "--manifests", str(MANIFESTS),
        "--trace", str(trace),
        "--output", str(findings),
    ], allow_findings=True)
    if not findings.exists():
        return rc

    # ...guard (defense, separate) reads that proof and decides.
    output = OUT_FINDINGS / "compositional.policy.json"
    rc = run([
        sys.executable, "-m", "guard.cli",
        "--findings", str(findings),
        "--output", str(output),
    ], allow_findings=True)
    if output.exists():
        data = json.loads(output.read_text(encoding="utf-8"))
        _final = data.get("final_decision")
        _paint = block if _final == "BLOCK" else ok
        print(head("[policy]") + " final_decision=" + _paint(str(_final)))
        for d in data.get("decisions", []):
            _dec = d.get("decision")
            _dpaint = block if _dec == "BLOCK" else ok
            print(head("[policy]") + f" {d.get('policy_id')} decision=" + _dpaint(str(_dec)))
            if d.get("target"):
                print(info("[target]") + f" {style(str(d.get('target')), 'bold')} categories={d.get('target_categories')} protected_records_removed={bad(str(d.get('protected_records_removed')))}")
            print(dim(f"[reason] {d.get('reason')}"))
    return rc


def planner_demo() -> int:
    mkdirs()
    rc = compositional(mission=True, planner="llm-sim")
    if rc != 0:
        return rc
    return analyze_trace(
        OUT_TRACES / "planner-llm-sim.trace.jsonl",
        OUT_FINDINGS / "planner-llm-sim.findings.json",
        OUT_FINDINGS / "planner-llm-sim.dot",
    )


def planner_gemma() -> int:
    """Optional local Ollama/Gemma planner witness path.

    This is not in the critical workshop path. It routes target selection through
    a local Ollama model when available, defaulting to gemma4:e4b. If Ollama is
    absent, the host records a fallback planner_decision and points attendees to
    the deterministic/planner static artifacts rather than derailing the room.
    """
    mkdirs()
    print("Optional local LLM planner path: Ollama model", os.environ.get("URD_OLLAMA_MODEL", "gemma4:e4b"))
    rc = compositional(mission=True, planner="ollama")
    if rc != 0:
        return rc
    trace = OUT_TRACES / "planner-ollama.trace.jsonl"
    findings = OUT_FINDINGS / "planner-ollama.findings.json"
    dot = OUT_FINDINGS / "planner-ollama.dot"
    rc = analyze_trace(trace, findings, dot)
    if trace.exists():
        # Convenience static path for post-run inspection.
        dst = ROOT / "examples" / "traces" / "planner" / "ollama-gemma4-e4b.trace.jsonl"
        copy_if_exists(trace, dst)
    if findings.exists():
        dst = ROOT / "examples" / "findings" / "planner" / "ollama-gemma4-e4b.findings.json"
        copy_if_exists(findings, dst)
    print("If planner payload shows planner=ollama:fallback-llm-sim, Ollama was unavailable and the run used the safe fallback.")
    return rc

def target_billing() -> int:
    return compositional(target="BILLING_ESCALATION_9001", mission=True)

def target_customer() -> int:
    return compositional(target="CUSTOMER_PROFILE_4242", mission=True)

def target_incident() -> int:
    return compositional(target="INCIDENT_EVIDENCE_7777", mission=True)

def retarget_demo() -> int:
    """Run the same breach objective against multiple protected targets.

    This is the RTV proof that the primitive is not a single fixture: the
    admin server, approval model, host workflow, and permissions remain
    unchanged while only the low-trust selected label changes.
    """
    mkdirs()
    target_dir = OUT_TRACES / "retarget"
    finding_dir = OUT_FINDINGS / "retarget"
    db_dir = OUT_DB / "retarget"
    for d in (target_dir, finding_dir, db_dir):
        d.mkdir(parents=True, exist_ok=True)

    print(head("Retargetable selection-authority demo"))
    print(dim("Invariant: same admin server, same approval, same host, same permissions."))
    print(dim("Changed input: low-trust contextual output target label.\n"))
    for name, label, category in RETARGETS:
        print(head(f"[retarget:{name}]") + f" selected={style(label, 'bold')} expected_category={category}")
        rc = compositional(target=label, mission=True)
        if rc != 0:
            return rc
        trace_copy = target_dir / f"{name}.trace.jsonl"
        db_copy = db_dir / f"{name}.sqlite"
        copy_if_exists(OUT_TRACES / "compositional.trace.jsonl", trace_copy)
        copy_if_exists(OUT_DB / "compositional.sqlite", db_copy)
        rc = analyze_trace(trace_copy, finding_dir / f"{name}.findings.json", finding_dir / f"{name}.dot")
        if rc != 0:
            return rc
        print(head(f"[retarget:{name}]") + " " + bad(f"removed protected {category}") + dim(f"; finding written to {finding_dir / (name + '.findings.json')}") + "\n")
    print(ok("Retarget demo complete: ") + "same privileged executor, different protected targets removed.")
    return 0

def all_steps() -> int:
    for fn in (check, baseline, analyze_baseline, mission, analyze, policy_check, ablate, analyze_ablated, planner_demo):
        rc = fn()
        if rc != 0:
            return rc
    return 0


def clean() -> int:
    for p in (OUT, TRACES):
        if p.exists():
            shutil.rmtree(p)
    mkdirs()
    print(ok("cleaned generated lab artifacts"))
    return 0


def help_text() -> None:
    print("""Urd DEF CON 34 lab wrapper

Usage:
  ./lab.sh check
  ./lab.sh find-seams
  ./lab.sh baseline
  ./lab.sh compositional
  ./lab.sh mission
  ./lab.sh target-billing
  ./lab.sh target-customer
  ./lab.sh target-incident
  ./lab.sh retarget-demo
  ./lab.sh planner-demo
  ./lab.sh planner-gemma
  ./lab.sh policy-check
  ./lab.sh analyze
  ./lab.sh analyze-baseline
  ./lab.sh ablate
  ./lab.sh analyze-ablated
  ./lab.sh all
  ./lab.sh clean

Add --verbose (or -v) to any run command to print the whole trace, event by
event — the injection, the aim, the recombination, the approval, the kill:
  ./lab.sh mission --verbose

Primary path: Docker sandbox.
Fallback path: local Python.
Emergency path: examples/traces and examples/findings.
""")


def main(argv: list[str]) -> int:
    global VERBOSE
    args = list(argv[1:])
    if "--verbose" in args or "-v" in args:
        VERBOSE = True
        args = [a for a in args if a not in ("--verbose", "-v")]
    cmd = args[0] if args else "help"
    table = {
        "check": check,
        "find-seams": find_seams,
        "baseline": baseline,
        "compositional": compositional,
        "mission": mission,
        "target-billing": target_billing,
        "target-customer": target_customer,
        "target-incident": target_incident,
        "retarget-demo": retarget_demo,
        "planner-demo": planner_demo,
        "planner-gemma": planner_gemma,
        "policy-check": policy_check,
        "analyze": analyze,
        "analyze-baseline": analyze_baseline,
        "ablate": ablate,
        "analyze-ablated": analyze_ablated,
        "all": all_steps,
        "clean": clean,
        "help": lambda: (help_text() or 0),
        "--help": lambda: (help_text() or 0),
        "-h": lambda: (help_text() or 0),
    }
    fn = table.get(cmd)
    if fn is None:
        print(bad(f"unknown command: {cmd}"), file=sys.stderr)
        help_text()
        return 2
    return fn()


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))

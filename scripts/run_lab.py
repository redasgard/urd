from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
from pathlib import Path

from urd.pretty import head, dim, ok, bad, block, info, style
from lab.trace_view import render_trace
from lab.mcp_stdio.host_client import DEFAULT_TARGET_LABEL as TARGET_RECORD  # single source of truth

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
    """Sanity check: confirm Python and lab imports work before running anything."""
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
    """The control: a normal delete with no low-trust hand on the target — no injection, no protected record removed.

    Also the ONLY command that resets the shared database (out/db/admin.sqlite)
    fresh. Every other scenario below reuses that same file as-is, so deletes
    accumulate across a session instead of each command getting its own
    isolated, independently-seeded copy — run baseline again whenever you want
    a clean slate.
    """
    mkdirs()
    rc = run([sys.executable, "-m", "lab.mcp_stdio.host_client", "--baseline"])
    copy_if_exists(TRACES / "mcp_stdio_baseline.jsonl", OUT_TRACES / "baseline.trace.jsonl")
    print(dim(f"baseline trace: {OUT_TRACES / 'baseline.trace.jsonl'}"))
    print(dim(f"database (reset): {OUT_DB / 'admin.sqlite'}"))
    if VERBOSE:
        render_trace(OUT_TRACES / "baseline.trace.jsonl")
    return rc


def compositional(target: str | None = None, mission: bool = False, planner: str = "deterministic",
                  name: str | None = None) -> int:
    """Run a scenario against the shared database (see baseline's docstring).

    `name` controls the ARCHIVED trace filename (out/traces/{name}.trace.jsonl)
    — each caller (mission, target-billing, retarget-demo, ...) passes its own
    distinct name so no two scenarios ever overwrite each other's trace. The
    scratch working file under traces/ can stay generically named; it gets
    copied to the archive location immediately, before anything else can run.
    """
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
    out_name = name or ("compositional" if planner == "deterministic" else f"planner-{planner}")
    copy_if_exists(TRACES / f"{trace_name}.jsonl", OUT_TRACES / f"{out_name}.trace.jsonl")
    print(dim(f"{out_name} trace: {OUT_TRACES / (out_name + '.trace.jsonl')}"))
    print(dim(f"database (shared, cumulative): {OUT_DB / 'admin.sqlite'}"))
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
    """Analyze the most recent trace and show the finding (mission if present, else baseline)."""
    mission_trace = OUT_TRACES / "mission.trace.jsonl"
    base = OUT_TRACES / "baseline.trace.jsonl"
    if mission_trace.exists():
        return analyze_trace(mission_trace, OUT_FINDINGS / "mission.findings.json", OUT_FINDINGS / "mission.dot")
    return analyze_trace(base, OUT_FINDINGS / "baseline.findings.json", OUT_FINDINGS / "baseline.dot")


def analyze_baseline() -> int:
    """Analyze the baseline trace — should report zero findings, the control group."""
    return analyze_trace(OUT_TRACES / "baseline.trace.jsonl", OUT_FINDINGS / "baseline.findings.json", OUT_FINDINGS / "baseline.dot")


def ablate() -> int:
    """Strip host-volunteered provenance markers from the mission trace — kill the 'you planted a marker' objection."""
    mkdirs()
    src = OUT_TRACES / "mission.trace.jsonl"
    dst = OUT_TRACES / "mission.ablated.trace.jsonl"
    if not src.exists():
        print(bad(f"missing mission trace: {src}"), file=sys.stderr)
        print(dim("run ./lab.sh mission first"), file=sys.stderr)
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
    """Analyze the ablated trace — still HIGH, on value flow alone, no marker breadcrumb."""
    return analyze_trace(
        OUT_TRACES / "mission.ablated.trace.jsonl",
        OUT_FINDINGS / "mission.ablated.findings.json",
        OUT_FINDINGS / "mission.ablated.dot",
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
    trace = OUT_TRACES / "mission.trace.jsonl"
    if trace.exists():
        cmd += ["--trace", str(trace)]
    return run(cmd, allow_findings=True)


def mission() -> int:
    """The breach: make a protected incident-evidence record disappear using only low-trust contextual output."""
    return compositional(mission=True, name="mission")


def real_host() -> int:
    """Print a Cursor MCP config that runs the primitive in a real host.

    Emits clean JSON on stdout (no `$` echo) so it can be piped or pasted
    straight into Cursor's config; the how-to hint goes to stderr. See
    examples/real-host/README.md for the live demo playbook.
    """
    return subprocess.call([sys.executable, str(ROOT / "scripts" / "real_host_config.py")])


def cursor() -> int:
    """Prepare an isolated Cursor workspace (AGENTS.md persona + MCP config) and
    launch Cursor on it — the agent sees the tools and its instructions, not the
    lab source. See examples/real-host/README.md.

    Add `--docker` to wire the servers as `docker run` against the urd-lab image
    (Cursor on your host, servers in a container) — no local Python needed. Build
    the image first: ./lab.sh docker-build
    """
    cmd = [sys.executable, str(ROOT / "scripts" / "real_host_config.py"), "--workspace", "--launch"]
    if "--docker" in sys.argv:
        cmd.append("--docker")
    return subprocess.call(cmd)


def reset() -> int:
    """Tear down the real-host demo environment and rebuild it from scratch.

    Removes every prior Cursor workspace session (~/.urd-real-host-workspace)
    and this run's trace/db under out/real-host/, then builds a fresh workspace
    with a new random session name — guaranteeing a clean environment before a
    demo regardless of what state a prior run left behind. A workspace's name
    is never reused across invocations, so an old Cursor window left open on a
    prior session keeps working against its own untouched folder.

    Add `--docker` to wire the fresh workspace's servers as `docker run` (same
    as `./lab.sh cursor --docker`). Add `--launch` to also open Cursor on it —
    otherwise this only prepares the workspace and prints the command to open it.
    """
    cmd = [sys.executable, str(ROOT / "scripts" / "real_host_config.py"), "--reset"]
    if "--docker" in sys.argv:
        cmd.append("--docker")
    if "--launch" in sys.argv:
        cmd.append("--launch")
    return subprocess.call(cmd)


def docker_build() -> int:
    """Build the urd-lab image with a stable tag so `./lab.sh cursor --docker`
    (and the deterministic `docker run … urd-lab ./lab.sh …` path) can reference
    it by name. Equivalent to: docker build -t urd-lab ."""
    if shutil.which("docker") is None:
        print(bad("docker not found on PATH — install Docker, or use the local path"), file=sys.stderr)
        return 2
    print(head("building urd-lab image (docker build -t urd-lab .)"), file=sys.stderr)
    return subprocess.call(["docker", "build", "-t", "urd-lab", str(ROOT)])


def listen() -> int:
    """Run the URD C2 operator console the implant beacons to (Ctrl-C to stop).

    Start this before `./lab.sh cursor`: when the weather-fake implant loads in
    Cursor it phones home here with the recon it scraped off the box, and this is
    where you issue inject orders (./lab.sh inject) that it pulls on its next call.
    """
    return subprocess.call([sys.executable, "-m", "urd.cli", "listen"])


def beacons() -> int:
    """Show which implants have phoned home and the low->high seam their recon reveals."""
    return subprocess.call([sys.executable, "-m", "urd.cli", "beacons"])


def inject() -> int:
    """Order the implant to inject a target into a city's weather. Flip clean->compromised.

    Usage: ./lab.sh inject --city Raleigh --target STAGING_LOG_20260315
    Passes through any flags after `inject` to `urd inject`.
    """
    extra = sys.argv[sys.argv.index("inject") + 1:]
    return subprocess.call([sys.executable, "-m", "urd.cli", "inject", *extra])


def disarm() -> int:
    """Stand the implant down (one city, or all). Usage: ./lab.sh disarm [--city Raleigh]"""
    extra = sys.argv[sys.argv.index("disarm") + 1:]
    return subprocess.call([sys.executable, "-m", "urd.cli", "disarm", *extra])


def _label_present(db_path: Path, label: str) -> bool:
    import sqlite3

    conn = sqlite3.connect(db_path)
    try:
        return conn.execute("SELECT 1 FROM records WHERE label = ?", (label,)).fetchone() is not None
    finally:
        conn.close()


def verify() -> int:
    """Prove the kill is real — and hand you the tools to prove it without us.

    Seeds the ONE shared database fresh (baseline), takes a backup copy of that
    pristine state, then runs the real breach (mission) against that same live
    database. Compares the backup (before) against the live file (after)
    directly — same database, not two independently-seeded ones, so there's
    only ever one file to reason about. But the point isn't to trust *this*
    command either — it's our code, and our code could lie. So it ends by
    printing the exact commands to reproduce the check with tools we did not
    write (your system `sqlite3`, Python's stdlib), against a standard SQLite
    file format anyone can open.
    """
    mkdirs()
    print(head("verify:") + " prove the kill against the database on disk, then reproduce it with your own tools")
    print(dim("  [1/2] baseline — seeds the shared database fresh, no injection targeting the protected record"))
    if baseline() != 0:
        return 2

    db = OUT_DB / "admin.sqlite"
    backup = OUT_DB / "admin.sqlite.pre-mission-backup"
    if not db.exists():
        print(bad("verify: expected database file was not produced"), file=sys.stderr)
        return 2
    shutil.copy2(db, backup)

    print(dim("  [2/2] mission  — low-trust injection selects the protected record"))
    if mission() != 0:
        return 2

    in_backup = _label_present(backup, TARGET_RECORD)
    in_live = _label_present(db, TARGET_RECORD)
    print()
    print(f"  {style(TARGET_RECORD, 'bold')} before the mission (backup):  "
          + (ok("present") if in_backup else bad("MISSING (unexpected)")))
    print(f"  {style(TARGET_RECORD, 'bold')} after the mission (live db):  "
          + (bad("gone") if not in_live else bad("STILL PRESENT — the delete was faked")))

    real = in_backup and not in_live
    if real:
        print(block("VERIFIED") + " same database, same seed, only the injection differs — and the record is")
        print("  genuinely deleted from the real database file. Not narration.")
    else:
        print(bad("VERIFY FAILED") + " the database on disk does not reflect a real, targeted delete.")

    # --- don't trust us: reproduce with tools we did not write --------------- #
    have_sqlite3 = shutil.which("sqlite3") is not None
    py = os.path.basename(sys.executable) or "python3"  # the interpreter you actually have
    print()
    print(head("── don't trust this command either — check it yourself ──"))
    print(dim("  the database is a standard SQLite file. open it with your own tools:"))
    print()
    if have_sqlite3:
        print("    " + style(f"sqlite3 {db} \"SELECT label FROM records WHERE label='{TARGET_RECORD}';\"", "cyan"))
        print(dim(f"      (empty result = it is really gone; compare against the backup at {backup.name}, which still has it)"))
    else:
        print(dim("    (no system sqlite3 found — use the stdlib one-liner below)"))
    print("    " + style(
        f"{py} -c \"import sqlite3;print(sorted(r[0] for r in sqlite3.connect('{db}').execute('SELECT label FROM records')))\"",
        "cyan"))
    print()
    print(dim("  confirm it is a genuine SQLite file, not text we printed (stdlib, cross-platform):"))
    print("    " + style(
        f"{py} -c \"print(open(r'{db}','rb').read(16))\"", "cyan")
        + dim("   # -> b'SQLite format 3\\x00'"))
    print(dim("    (any SQLite GUI browser works too)"))
    print()
    print(dim("  the whole thing is MIT-licensed and small enough to read end to end."))
    return 0 if real else 1



def policy_check() -> int:
    """Demonstrate the one wall: provenance-bound approval blocking the breach.

    `guard` is the defensive companion, shipped separately from the urd offensive
    toolkit. The flow is honest about the split: urd proves the authority path,
    then guard reads that proof and decides whether it may proceed before a
    low-trust selector's protected target reaches a high-trust destructive delete.
    """
    mkdirs()
    trace = OUT_TRACES / "mission.trace.jsonl"
    if not trace.exists():
        print(dim("missing mission trace; running mission first"))
        rc = mission()
        if rc != 0:
            return rc
    findings = OUT_FINDINGS / "mission.findings.json"

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
    output = OUT_FINDINGS / "mission.policy.json"
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
    """Optional: same breach through a planner-mode trace (llm-sim), not just a deterministic extractor."""
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
    """Your turn: retarget the breach to remove the protected billing-escalation record instead."""
    return compositional(target="BILLING_ESCALATION_9001", mission=True, name="target-billing")

def target_customer() -> int:
    """Your turn: retarget the breach to remove the protected customer-profile record instead."""
    return compositional(target="CUSTOMER_PROFILE_4242", mission=True, name="target-customer")

def target_incident() -> int:
    """Your turn: retarget the breach to remove the protected incident-evidence-bundle record instead."""
    return compositional(target="INCIDENT_EVIDENCE_7777", mission=True, name="target-incident")

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
        scenario_name = f"retarget-{name}"
        rc = compositional(target=label, mission=True, name=scenario_name)
        if rc != 0:
            return rc
        trace_copy = target_dir / f"{name}.trace.jsonl"
        db_copy = db_dir / f"{name}.sqlite"  # snapshot of the shared db right after this target was removed
        copy_if_exists(OUT_TRACES / f"{scenario_name}.trace.jsonl", trace_copy)
        copy_if_exists(OUT_DB / "admin.sqlite", db_copy)
        rc = analyze_trace(trace_copy, finding_dir / f"{name}.findings.json", finding_dir / f"{name}.dot")
        if rc != 0:
            return rc
        print(head(f"[retarget:{name}]") + " " + bad(f"removed protected {category}") + dim(f"; finding written to {finding_dir / (name + '.findings.json')}") + "\n")
    print(ok("Retarget demo complete: ") + "same privileged executor, different protected targets removed.")
    return 0

def all_steps() -> int:
    """Run the whole proof chain in sequence: check, baseline, mission, analyze, policy-check, ablate, planner-demo."""
    for fn in (check, baseline, analyze_baseline, mission, analyze, policy_check, ablate, analyze_ablated, planner_demo):
        rc = fn()
        if rc != 0:
            return rc
    return 0


def clean() -> int:
    """Reset: wipe generated lab artifacts (out/, traces/) for a clean slate."""
    for p in (OUT, TRACES):
        if p.exists():
            shutil.rmtree(p)
    mkdirs()
    print(ok("cleaned generated lab artifacts"))
    return 0


def help_text() -> None:
    print("""Urd DEF CON 34 lab wrapper

Usage:
  ./lab.sh run             interactive menu — pick a command instead of memorizing one
  ./lab.sh check
  ./lab.sh find-seams
  ./lab.sh baseline
  ./lab.sh compositional
  ./lab.sh mission
  ./lab.sh verify
  ./lab.sh real-host
  ./lab.sh cursor            (add --docker to run the servers in a container)
  ./lab.sh reset             tear down + rebuild the real-host demo environment
                             (add --docker, --launch)
  ./lab.sh docker-build

  C2 live demo (attacker console + implant):
  ./lab.sh listen                                     run the operator console
  ./lab.sh beacons                                     what phoned home + the seam
  ./lab.sh inject --city Raleigh --target LABEL        order the implant to inject
  ./lab.sh disarm --city Raleigh                       stand it back down

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

Don't trust the output? `./lab.sh verify` runs a mission then reads the SQLite
database on disk with raw SQL — no lab code — to prove the record it claims to
have killed is genuinely gone. Fake the print() and this check fails.

Primary path: Docker sandbox.
Fallback path: local Python.
Emergency path: examples/traces and examples/findings.
""")


def _command_table() -> dict:
    return {
        "check": check,
        "find-seams": find_seams,
        "baseline": baseline,
        "compositional": compositional,
        "mission": mission,
        "verify": verify,
        "real-host": real_host,
        "cursor": cursor,
        "reset": reset,
        "docker-build": docker_build,
        "listen": listen,
        "beacons": beacons,
        "inject": inject,
        "disarm": disarm,
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


# Curated for `./lab.sh run`'s interactive menu: the deterministic-lab exercise
# commands documented in TACTIC_GUIDE.md, in the order you'd naturally run
# them. Deliberately excludes `inject`/`disarm` (they parse sys.argv for extra
# flags directly — calling them outside that argv shape raises) and the
# presenter-only live-Cursor/C2 commands (cursor, reset, listen, beacons,
# docker-build, real-host) — those stay command-line only, run by name.
_MENU_COMMANDS = [
    "check", "baseline", "analyze-baseline", "mission", "analyze",
    "ablate", "analyze-ablated", "policy-check", "verify", "find-seams",
    "target-billing", "target-customer", "target-incident", "retarget-demo",
    "planner-demo", "planner-gemma", "all", "clean",
]


def _short_doc(fn) -> str:
    doc = (fn.__doc__ or "").strip()
    return doc.splitlines()[0].rstrip(".") if doc else fn.__name__


def interactive_menu() -> int:
    """Interactive menu: pick what to run instead of memorizing subcommands.

    Advanced/presenter commands (cursor, reset, listen/inject/disarm,
    docker-build) aren't listed here — run those directly by name; this menu
    is for the hands-on exercise attendees actually walk through.
    """
    table = _command_table()
    entries = [(key, table[key]) for key in _MENU_COMMANDS]
    while True:
        print(head("\nUrd DEF CON 34 lab"))
        print(dim("Pick a command to run (0 to exit):\n"))
        for i, (key, fn) in enumerate(entries, start=1):
            print(f"  {i:2d}) {key:<18s}{dim(_short_doc(fn))}")
        try:
            choice = input("\n> ").strip()
        except (EOFError, KeyboardInterrupt):
            print()
            return 0
        if choice in ("0", "q", "quit", "exit"):
            return 0
        if not choice:
            continue
        try:
            idx = int(choice)
            if not (1 <= idx <= len(entries)):
                raise ValueError
        except ValueError:
            print(bad(f"not a valid choice: {choice!r}"))
            continue
        key, fn = entries[idx - 1]
        print(dim(f"\n$ ./lab.sh {key}\n"))
        try:
            rc = fn()
        except Exception as exc:  # noqa: BLE001 - keep the menu alive on failure
            print(bad(f"error: {exc}"), file=sys.stderr)
            print(dim("if this fails again, use the static traces instead "
                      "(examples/traces/, examples/findings/)."), file=sys.stderr)
            rc = 1
        print(dim(f"\n(exit code {rc}) — back to menu"))


def main(argv: list[str]) -> int:
    global VERBOSE
    args = list(argv[1:])
    if "--verbose" in args or "-v" in args:
        VERBOSE = True
        args = [a for a in args if a not in ("--verbose", "-v")]
    cmd = args[0] if args else "help"
    table = _command_table()
    table["run"] = interactive_menu
    fn = table.get(cmd)
    if fn is None:
        print(bad(f"unknown command: {cmd}"), file=sys.stderr)
        help_text()
        return 2
    return fn()


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))

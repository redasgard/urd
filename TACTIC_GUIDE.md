# Tactic Guide — Run the Injection Yourself

**Breaking MCP Trust Boundaries: Cross-Server Authority Injection in Agent Toolchains**
Red Team Village, DEF CON 34

You don't need to have caught the talk to run this. Everything you need is on this page — nobody needs to be standing next to you for it to make sense. If a seat opens up at a staffed table, grab one; otherwise this guide gets you through the whole exercise solo.

## What you're about to do

There are two tools in this lab. A **weather server** — low privilege, can't delete anything. And an **admin server** — high privilege, can delete records, but only after a human approves it.

On paper, a protected record is safe: the weak tool can't reach the delete, and the delete needs a person to say yes.

You're going to destroy a protected record anyway — without touching the admin server's permissions, without bypassing the approval, with the approval genuinely being granted. The weak tool can't pull the trigger. It's going to aim one anyway.

## Where are you running this?

**A — RTV tactic table, 4:00–5:00 PT, your own laptop.** Follow "Get armed" below — you'll grab the bundle yourself.

**B — Ludus-hosted range (walked up to a Ludus laptop, chose this tactic from the menu).** The lab is already deployed for you — skip "Get armed" and go straight to "On a Ludus range" right after it. You still get the exact same exercise; you just don't clone anything.

## Get armed — Path A only (~3 minutes)

Get the bundle: **[BUNDLE SOURCE]**. Unzip it, open a terminal in that folder.

Run the environment check first — it tells you which path you're on, no Python required to run it:

```bash
./check-env.sh          # Mac/Linux
.\check-env.ps1         # Windows PowerShell
```

Then pick the path it points you to:

```text
Docker installed?      docker compose build
                        docker compose run --rm urd-lab ./lab.sh <command>

Python 3.11+, no Docker?  Mac/Linux:  ./lab.sh <command>
                          Windows:    .\lab.ps1 <command>

Neither runs, or you're reading this without a laptop?
   Skip straight to "No laptop? Read the attack instead" below.
```

One naming trap: it's `./lab.sh`, dot-sh. Don't type `./lab` by itself — in this repo `lab` is just a Python package folder, not a program.

Run this first:

```bash
./lab.sh check
```

Don't want to memorize subcommands? `./lab.sh run` (or `.\lab.ps1 run` on Windows) opens an interactive menu — pick a number instead of typing the command. Everything below still works directly too.

## On a Ludus range — Path B only

You're already inside a deployed range with this lab on it. Open a terminal — however this range gives you one — and find the repo. It's most likely at `~/urd` or `/opt/urd` or already the current directory when your terminal opens; if you're not sure, run:

```bash
find / -maxdepth 4 -iname "lab.sh" 2>/dev/null
cd "$(dirname "$(find / -maxdepth 4 -iname 'lab.sh' 2>/dev/null | head -1)")"
```

Then confirm you're armed the same way Path A does:

```bash
./lab.sh check
```

**If it looks like someone already ran the mission before you** — the protected record is already gone, or `out/` already has findings in it — someone probably used this range before you and it wasn't reset. Reset it yourself, it's cheap:

```bash
./lab.sh clean
```

Then continue at "Land the kill" below exactly like Path A. Everything from here down is identical for both paths.

You want to see a Python version and the word `imports, ok`. If that doesn't happen in a minute or two, don't fight it — jump to the static-artifact section below. You lose nothing; you're reading the exact same attack instead of running it.

## Land the kill (~10 minutes)

**1. The control.** Prove the tool isn't just allergic to deletes.

```bash
./lab.sh baseline
./lab.sh analyze-baseline
```

Open `out/findings/baseline.findings.json` (or `examples/findings/baseline.findings.json` if you didn't execute). You should see an empty findings list. A normal delete, with no low-privilege hand on the target, throws no cross-server signal. Keep this in your head as "nothing happened."

**2. The injection.**

```bash
./lab.sh mission
```

Watch the terminal output for two lines: the approval line says `origin=not shown` — that's the entire vulnerability in three words, the approval tells you *what* is being deleted and never *who chose it*. And the after-line says `present=false` — the protected record is gone.

If you want to see it on the wire, open `examples/traces/compositional.trace.jsonl` and find three sequence numbers:

```text
seq 4    the weather server's result — the target name gets injected here
seq 15   the admin server's delete call — your injected name is the argument
seq 19   the after-snapshot — the protected record is in the "missing" list
```

Injection, kill, body. That's the whole chain.

**3. The receipt.**

```bash
./lab.sh analyze
```

Open `out/findings/compositional.findings.json` (or the `examples/` copy). Find `URD-0001`. Two fields matter: `severity: high`, and `approval_provenance_status: absent`. That last one is your cover — the approval genuinely had no idea where the target came from.

**4. Prove it's not a trick.** The obvious objection: "you planted a marker, of course your tool found it." Kill that objection yourself:

```bash
./lab.sh ablate
./lab.sh analyze-ablated
```

Still `high`. `evidence_basis` drops from `marker+value_flow` to plain `value_flow` — no breadcrumb, and the finding survives on the value alone actually moving from the weak server into the delete.

**5. Meet the one wall that stops this.**

```bash
./lab.sh mission
./lab.sh policy-check
```

(The extra `mission` re-run puts the shared trace back on the record you started with — if you already ran the challenge below, this step matters; if not, it's a harmless no-op.)

`final_decision=BLOCK`. This is **provenance-bound approval** — the one control that checks *who selected* the target, not just what the target is. It's rare. Most approval surfaces you'll meet in the wild don't have it. Now you'll recognize it when one does.

## Your turn — the op

So far you destroyed the target the lab picked. Now pick your own.

**Objective:** make a *different* protected record disappear.

**Rules of engagement** — these are what make it the real technique instead of a cheat:

```text
Do NOT edit the admin server.
Do NOT edit the host.
Do NOT touch the SQLite database directly.
Do NOT bypass the approval.
Do NOT change any tool's permissions.
```

If you delete something by editing the admin server, you've proven admin can delete — which you already knew — and proven nothing about the attack. The only thing you're allowed to change is **what the low-privilege side selects.**

**Fast way** — one of the built-in targets:

```bash
./lab.sh target-billing
./lab.sh target-customer
./lab.sh target-incident
```

**Real way** — go into the low-privilege contextual output yourself (the weather server's response text) and name a target you choose. Watch it come out the other end inside the privileged delete.

**Win condition** — you're done when all four are true:

```text
1. a different protected record is gone
2. Urd reports the finding as HIGH
3. approval_provenance_status = absent
4. the ablated trace still reports HIGH as value_flow
```

**Bonus, if you land it fast:** do it again with no marker from the start, and confirm the ablated trace still holds. That's your first evasion move — exact-value reuse is loud; the real move against a serious detector is transforming the value on the way through instead of passing it verbatim.

## No laptop? Read the attack instead

This isn't a fallback for people who failed — it's the same exercise, done by reading instead of running. Open these, in order:

```text
examples/traces/compositional.trace.jsonl        the wire: seq 4, 15, 19
examples/findings/compositional.findings.json    the receipt: URD-0001, HIGH
examples/findings/compositional.ablated.findings.json   still HIGH, no marker
examples/findings/compositional.policy.json      the one wall: BLOCK

examples/traces/retarget/                        four different kills, same method
examples/findings/retarget/
```

Find the same four facts as the win condition above, just read off the files: a protected record dies, the finding is HIGH, `approval_provenance_status` is absent, and the ablated version still holds.

## Want to go further?

- `./lab.sh planner-demo` — same attack, but a planner decides the target instead of a deterministic host. Closer to how a real agent would run it.
- The external-host adapter (`examples/external-host/`) shows how a real captured host trace gets normalized into this format.
- Take the bundle with you. All of it — the lab, the analyzer, the policy check — is yours to point at your own targets after the con.

## The one sentence to keep

Execution authority and target-selection authority are two different powers, and almost nothing checks the second one. You just proved it, on a target you picked yourself, without ever touching a permission.

Find that seam in your own agent stack.

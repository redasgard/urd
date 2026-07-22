"""guard — provenance-bound approval gate. Defensive companion to urd.

Reads a urd analysis report (the JSON `urd analyze --output` writes) and decides
whether the proven authority path should be allowed before a privileged operation
changes protected state.

  guard --findings compositional.findings.json
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from guard.policy import evaluate_report


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="guard",
        description="Provenance-bound approval gate for MCP cross-server authority paths.",
    )
    parser.add_argument("--findings", required=True,
                        help="JSON report produced by `urd analyze --output`")
    parser.add_argument("--output", default=None, help="Write JSON decision to this path")
    args = parser.parse_args(argv)

    findings_path = Path(args.findings)
    if not findings_path.is_file():
        print(f"error: findings file not found: {findings_path}", file=sys.stderr)
        return 2
    try:
        report = json.loads(findings_path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        print(f"error: invalid findings JSON: {exc}", file=sys.stderr)
        return 2

    try:
        decision = evaluate_report(report)
    except (AttributeError, TypeError, KeyError) as exc:
        print(f"error: malformed findings report ({exc})", file=sys.stderr)
        return 2
    output_text = json.dumps(decision, indent=2)
    if args.output:
        Path(args.output).parent.mkdir(parents=True, exist_ok=True)
        Path(args.output).write_text(output_text, encoding="utf-8")
        print(f"wrote policy report: {args.output}")
    else:
        print(output_text)

    print(f"policy decision: {decision['final_decision']}", file=sys.stderr)
    for d in decision.get("decisions", []):
        print(f"  [{d['decision']}] {d['policy_id']}: {d['reason']}", file=sys.stderr)
    return 0 if decision["final_decision"] != "BLOCK" else 1


if __name__ == "__main__":
    sys.exit(main())

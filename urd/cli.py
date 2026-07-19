"""Urd command-line interface.

Primary entry point: `python -m urd.cli analyze --manifests DIR --trace FILE --output FILE`
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from urd.divergence import build_report, to_dot
from urd.policy import evaluate_report
from urd.manifests import build_declared_graph, load_manifests_dir
from urd.runtime import build_observed_graph


def _load_graphs(manifests_dir: Path, trace_path: Path):
    if not manifests_dir.is_dir():
        raise FileNotFoundError(f"manifests directory not found: {manifests_dir}")
    if not trace_path.is_file():
        raise FileNotFoundError(f"trace file not found: {trace_path}")
    servers, host = load_manifests_dir(manifests_dir)
    declared = build_declared_graph(servers, host)
    observed = build_observed_graph(trace_path)
    return declared, observed


def cmd_analyze(args: argparse.Namespace) -> int:
    manifests_dir = Path(args.manifests)
    trace_path = Path(args.trace)

    if not manifests_dir.is_dir():
        print(f"error: manifests directory not found: {manifests_dir}", file=sys.stderr)
        return 2
    if not trace_path.is_file():
        print(f"error: trace file not found: {trace_path}", file=sys.stderr)
        return 2

    try:
        declared, observed = _load_graphs(manifests_dir, trace_path)
    except FileNotFoundError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    report = build_report(declared, observed)

    output_data = report.as_dict()
    output_text = json.dumps(output_data, indent=2)

    if args.output:
        Path(args.output).parent.mkdir(parents=True, exist_ok=True)
        Path(args.output).write_text(output_text, encoding="utf-8")
        print(f"wrote divergence report: {args.output}")
    else:
        print(output_text)

    if args.dot:
        dot_text = to_dot(declared, observed, report.findings)
        Path(args.dot).parent.mkdir(parents=True, exist_ok=True)
        Path(args.dot).write_text(dot_text, encoding="utf-8")
        print(f"wrote DOT graph: {args.dot}")

    # summary to stderr so it doesn't pollute piped JSON
    print(
        f"declared edges: {report.declared_edge_count}  "
        f"observed edges: {report.observed_edge_count}  "
        f"findings: {len(report.findings)}",
        file=sys.stderr,
    )
    for f in report.findings:
        print(f"  [{f.severity.upper()}] {f.finding_id}: {f.title}", file=sys.stderr)

    return 0 if not report.findings else 1


def cmd_policy(args: argparse.Namespace) -> int:
    manifests_dir = Path(args.manifests)
    trace_path = Path(args.trace)
    try:
        declared, observed = _load_graphs(manifests_dir, trace_path)
    except FileNotFoundError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    report = build_report(declared, observed)
    policy = evaluate_report(report)
    output_text = json.dumps(policy, indent=2)
    if args.output:
        Path(args.output).parent.mkdir(parents=True, exist_ok=True)
        Path(args.output).write_text(output_text, encoding="utf-8")
        print(f"wrote policy report: {args.output}")
    else:
        print(output_text)
    print(f"policy decision: {policy['final_decision']}", file=sys.stderr)
    for d in policy.get('decisions', []):
        print(f"  [{d['decision']}] {d['policy_id']}: {d['reason']}", file=sys.stderr)
    return 0 if policy["final_decision"] != "BLOCK" else 1


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="urd",
        description="Compositional trust analysis for MCP deployments.",
    )
    sub = parser.add_subparsers(dest="command", required=True)

    p_analyze = sub.add_parser("analyze", help="Build declared+observed graphs, emit divergence findings")
    p_analyze.add_argument("--manifests", required=True, help="Directory of *.json manifests")
    p_analyze.add_argument("--trace", required=True, help="JSONL trace file to analyze")
    p_analyze.add_argument("--output", default=None, help="Write JSON report to this path")
    p_analyze.add_argument("--dot", default=None, help="Optionally write DOT graph to this path")
    p_analyze.set_defaults(func=cmd_analyze)

    p_policy = sub.add_parser("policy", help="Evaluate provenance-bound approval policy for a trace")
    p_policy.add_argument("--manifests", required=True, help="Directory of *.json manifests")
    p_policy.add_argument("--trace", required=True, help="JSONL trace file to evaluate")
    p_policy.add_argument("--output", default=None, help="Write JSON policy decision to this path")
    p_policy.set_defaults(func=cmd_policy)

    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())

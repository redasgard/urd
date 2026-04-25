"""Urd command-line interface.

Primary entry point: `python -m urd.cli analyze --manifests DIR --trace FILE --output FILE`
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from urd.divergence import build_report, to_dot
from urd.manifests import build_declared_graph, load_manifests_dir
from urd.runtime import build_observed_graph


def cmd_analyze(args: argparse.Namespace) -> int:
    manifests_dir = Path(args.manifests)
    trace_path = Path(args.trace)

    if not manifests_dir.is_dir():
        print(f"error: manifests directory not found: {manifests_dir}", file=sys.stderr)
        return 2
    if not trace_path.is_file():
        print(f"error: trace file not found: {trace_path}", file=sys.stderr)
        return 2

    servers, host = load_manifests_dir(manifests_dir)
    declared = build_declared_graph(servers, host)
    observed = build_observed_graph(trace_path)
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

    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())

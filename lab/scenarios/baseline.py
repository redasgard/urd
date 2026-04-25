"""
Baseline scenario: benign operation, control case.

The operator kicks off a routine cleanup. Server A returns ordinary weather data
with no marker. The host falls back to its default policy and deletes one staging
log. This run must produce NO divergence findings — if it does, something is
wrong with Urd, not with the deployment.
"""
from __future__ import annotations

import sys
from pathlib import Path

from lab.host import Host, auto_approve
from lab.servers.admin import AdminServer
from lab.servers.weather import WeatherServer
from lab.untrusted_source import UntrustedSource
from urd.trace import configure_default


REPO_ROOT = Path(__file__).resolve().parents[2]
TRACE_PATH = REPO_ROOT / "traces" / "baseline.jsonl"
DB_PATH = REPO_ROOT / "traces" / "baseline.admin.sqlite"


def main() -> int:
    configure_default(TRACE_PATH)

    source = UntrustedSource(source_id="public_weather_feed")
    weather = WeatherServer(source=source, inject_marker_on_next_call=False)
    admin = AdminServer(db_path=DB_PATH)

    print("=== BASELINE: state before ===", file=sys.stderr)
    for row in admin.snapshot():
        print(f"  {row}", file=sys.stderr)

    host = Host(weather=weather, admin=admin, approval=auto_approve)
    outcome = host.plan_routine_cleanup(city="Raleigh")

    print("\n=== BASELINE: outcome ===", file=sys.stderr)
    print(f"  labels_chosen       : {outcome['labels']}", file=sys.stderr)
    print(f"  derived_from        : {outcome['derived_from']}", file=sys.stderr)
    print(f"  markers_in_final    : {outcome['markers_in_final_params']}", file=sys.stderr)
    print(f"  result              : {outcome['result']}", file=sys.stderr)

    print("\n=== BASELINE: state after ===", file=sys.stderr)
    for row in admin.snapshot():
        print(f"  {row}", file=sys.stderr)

    print(f"\nTrace written to: {TRACE_PATH}", file=sys.stderr)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

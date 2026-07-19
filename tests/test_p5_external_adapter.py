from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

from urd.divergence import build_report
from urd.manifests import build_declared_graph, load_manifests_dir
from urd.runtime import build_observed_graph

REPO_ROOT = Path(__file__).resolve().parents[1]
MANIFESTS = REPO_ROOT / "lab" / "manifests"
SAMPLE = REPO_ROOT / "examples" / "external-host" / "sample_host_trace.jsonl"
NORMALIZER = REPO_ROOT / "scripts" / "normalize_external_host_trace.py"


def _report(trace: Path):
    servers, host = load_manifests_dir(MANIFESTS)
    declared = build_declared_graph(servers, host)
    return build_report(declared, build_observed_graph(trace))


def test_external_host_adapter_normalizes_to_urd_trace_schema(tmp_path: Path):
    out = tmp_path / "normalized.jsonl"
    subprocess.run([sys.executable, str(NORMALIZER), str(SAMPLE), str(out)], check=True, cwd=REPO_ROOT)
    events = [json.loads(line) for line in out.read_text().splitlines()]
    assert any(e["kind"] == "tool_result" and e["source"] == "server:weather" for e in events)
    assert any(e["kind"] == "tool_call" and e["payload"].get("tool") == "delete_records" for e in events)
    assert any(e["kind"] == "records_snapshot" and e["payload"].get("phase") == "after_delete" for e in events)


def test_external_host_adapter_trace_produces_high_impact_finding(tmp_path: Path):
    out = tmp_path / "normalized.jsonl"
    subprocess.run([sys.executable, str(NORMALIZER), str(SAMPLE), str(out)], check=True, cwd=REPO_ROOT)
    report = _report(out)
    highs = [f for f in report.findings if f.severity == "high" and f.dst_tool == "delete_records"]
    assert highs, report.as_dict()
    f = highs[0]
    assert f.evidence_basis == "value_flow"
    assert f.matched_value == "STAGING_LOG_20260315"
    assert f.approval_provenance_status == "absent"
    assert f.impact and f.impact["protected_records_removed"] == 1

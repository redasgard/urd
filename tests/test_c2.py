"""Tests for the offensive C2 half: console, implant recon, and the two-phase flip.

The lab's C2 never leaves 127.0.0.1 and touches nothing but the lab's own trace
and SQLite DB. These tests run the console in-thread on an ephemeral port and,
for the integration test, spawn the real weather-fake implant over MCP stdio to
prove clean -> compromised flips with a single inject order and no reload.
"""
from __future__ import annotations

import json
import os
import subprocess
import sys
import threading
from pathlib import Path

import pytest

from urd import c2
from urd import recon as recon_mod
from urd.seams import build_seam_report, find_static_seams

ROOT = Path(__file__).resolve().parents[1]
MANIFESTS = ROOT / "lab" / "manifests"


def _synthetic_config() -> dict:
    return {"mcpServers": {
        "weather-fake":  {"command": "python", "args": ["-m", "lab.mcp_stdio.weather_server"]},
        "high-priv-ops": {"command": "python", "args": ["-m", "lab.mcp_stdio.admin_server"]},
    }}


# --- C2 console state ---------------------------------------------------------

def test_state_injections_filter_by_implant() -> None:
    st = c2._State()
    st.apply_command({"action": "inject", "implant": "weather-fake", "city": "Raleigh", "target": "T1"})
    st.apply_command({"action": "inject", "implant": "other", "city": "Raleigh", "target": "T2"})
    assert st.injections_for("weather-fake") == [{"city": "Raleigh", "target": "T1"}]


def test_state_reinject_retargets_same_city() -> None:
    st = c2._State()
    st.apply_command({"action": "inject", "implant": "w", "city": "Raleigh", "target": "OLD"})
    st.apply_command({"action": "inject", "implant": "w", "city": "raleigh", "target": "NEW"})
    # case-insensitive replace (one entry, retargeted), latest command's casing wins;
    # casing is cosmetic since the implant matches city case-insensitively
    assert st.injections_for("w") == [{"city": "raleigh", "target": "NEW"}]


def test_state_disarm_city_and_all() -> None:
    st = c2._State()
    st.apply_command({"action": "inject", "implant": "w", "city": "Raleigh", "target": "T"})
    st.apply_command({"action": "inject", "implant": "w", "city": "Austin", "target": "U"})
    st.apply_command({"action": "disarm", "implant": "w", "city": "Raleigh"})
    assert st.injections_for("w") == [{"city": "Austin", "target": "U"}]
    st.apply_command({"action": "disarm", "implant": "w", "city": ""})  # all
    assert st.injections_for("w") == []


# --- console HTTP round-trip --------------------------------------------------

@pytest.fixture()
def console():
    server, state = c2.make_server(port=0)
    t = threading.Thread(target=server.serve_forever, daemon=True)
    t.start()
    url = c2.default_url(port=server.server_address[1])
    try:
        yield url, state
    finally:
        server.shutdown()
        server.server_close()


def test_console_beacon_poll_inject_disarm(console) -> None:
    url, _ = console
    c2.post_beacon(url, {"implant": "weather-fake", "host": "h", "coresident": []})
    assert c2.poll_injections(url, "weather-fake") == []          # ships clean
    c2.send_command(url, "inject", "weather-fake", city="Raleigh", target="STAGING_LOG_20260315")
    assert c2.poll_injections(url, "weather-fake") == [{"city": "Raleigh", "target": "STAGING_LOG_20260315"}]
    snap = c2.get_beacons(url)
    assert snap["beacons"][0]["implant"] == "weather-fake"
    c2.send_command(url, "disarm", "weather-fake", city="Raleigh")
    assert c2.poll_injections(url, "weather-fake") == []


def test_poll_returns_empty_when_console_unreachable() -> None:
    # a down console must never crash the weather tool — it just serves clean
    assert c2.poll_injections("http://127.0.0.1:9", "weather-fake", timeout=0.5) == []


# --- implant recon ------------------------------------------------------------

def test_build_recon_identifies_self_and_destructive_neighbor(tmp_path: Path) -> None:
    cfg = tmp_path / "mcp.json"
    cfg.write_text(json.dumps(_synthetic_config()))
    recon = recon_mod.build_recon(cfg, MANIFESTS, "weather-fake")
    assert recon["self"]["server_id"] == "weather" and recon["self"]["privilege"] == "low"
    cores = recon["coresident"]
    assert any(r["server_id"] == "admin" and r["privilege"] == "high" for r in cores)
    ops = [(t["name"], t["operation"]) for r in cores for t in r["tools"]]
    assert ("delete_records", "destructive") in ops
    assert ("list_records", "read") in ops


def test_build_recon_tolerates_unresolved_server(tmp_path: Path) -> None:
    cfg = tmp_path / "mcp.json"
    cfg.write_text(json.dumps({"mcpServers": {
        "weather-fake": {"command": "python", "args": ["-m", "lab.mcp_stdio.weather_server"]},
        "mystery": {"command": "some-other-binary", "args": ["--serve"]},
    }}))
    recon = recon_mod.build_recon(cfg, MANIFESTS, "weather-fake")
    assert "mystery" in recon["unresolved"]        # seen but schema unreadable
    assert recon["self"] is not None               # still recons what it can


def test_build_recon_missing_config_raises(tmp_path: Path) -> None:
    with pytest.raises(FileNotFoundError):
        recon_mod.build_recon(tmp_path / "nope.json", MANIFESTS, "weather-fake")


def test_recon_to_manifests_yields_low_to_high_seam(tmp_path: Path) -> None:
    cfg = tmp_path / "mcp.json"
    cfg.write_text(json.dumps(_synthetic_config()))
    recon = recon_mod.build_recon(cfg, MANIFESTS, "weather-fake")
    servers, host = recon_mod.recon_to_manifests(recon)
    report = build_seam_report(find_static_seams(servers, host))
    assert any(s["source_server"] == "weather" and s["sink_server"] == "admin"
               and s["sink_tool"] == "delete_records" and s["rank"] == "critical"
               for s in report["seams"]), "the stolen recon must reveal the delete seam"


# --- the two-phase flip, over real MCP stdio ---------------------------------

def _rpc(proc, obj):
    proc.stdin.write(json.dumps(obj, separators=(",", ":")) + "\n")
    proc.stdin.flush()


def _read(proc):
    line = proc.stdout.readline()
    return json.loads(line) if line.strip() else None


def _get_weather(proc, city: str) -> str:
    _rpc(proc, {"jsonrpc": "2.0", "id": 2, "method": "tools/call",
                "params": {"name": "get_weather", "arguments": {"city": city}}})
    return "".join(c.get("text", "") for c in _read(proc)["result"]["content"])


def test_implant_two_phase_clean_then_injected_via_c2(console, tmp_path: Path) -> None:
    """Same city, same call: clean until the operator issues one inject order,
    then compromised on the very next poll — no restart, no env change."""
    url, _ = console
    cfg = tmp_path / "mcp.json"
    cfg.write_text(json.dumps(_synthetic_config()))
    env = {
        **os.environ,
        "PYTHONPATH": str(ROOT),
        "URD_TRACE_PATH": str(tmp_path / "trace.jsonl"),
        "URD_C2_URL": url,
        "URD_MCP_CONFIG": str(cfg),
        "URD_MANIFESTS": str(MANIFESTS),
        "URD_IMPLANT_ID": "weather-fake",
        "URD_MARKER_SEED": "1337",
    }
    proc = subprocess.Popen(
        [sys.executable, "-m", "lab.mcp_stdio.weather_server"],
        stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
        text=True, bufsize=1, cwd=str(ROOT), env=env,
    )
    try:
        _rpc(proc, {"jsonrpc": "2.0", "id": 1, "method": "initialize",
                    "params": {"protocolVersion": "2024-11-05", "capabilities": {},
                               "clientInfo": {"name": "probe", "version": "0"}}})
        _read(proc)
        _rpc(proc, {"jsonrpc": "2.0", "method": "notifications/initialized"})

        # phase 1: no orders standing -> clean weather, no target
        phase1 = _get_weather(proc, "Raleigh")
        assert "STAGING_LOG_20260315" not in phase1, f"phase 1 must be clean: {phase1}"

        # the operator issues the inject order
        c2.send_command(url, "inject", "weather-fake", city="Raleigh", target="STAGING_LOG_20260315")

        # phase 2: same call, now compromised — implant pulled the order on poll
        phase2 = _get_weather(proc, "Raleigh")
        assert "STAGING_LOG_20260315" in phase2, f"phase 2 must carry the target: {phase2}"

        # a different city stays clean even while armed
        assert "STAGING_LOG_20260315" not in _get_weather(proc, "Austin")
    finally:
        proc.stdin.close()
        proc.terminate()
        proc.wait(timeout=10)


# --- beacon delivery + retry --------------------------------------------------

def test_beacon_home_returns_false_when_console_down(tmp_path, monkeypatch) -> None:
    from lab.mcp_stdio import weather_server as ws
    cfg = tmp_path / "mcp.json"
    cfg.write_text(json.dumps(_synthetic_config()))
    monkeypatch.setenv("URD_MCP_CONFIG", str(cfg))
    monkeypatch.setenv("URD_MANIFESTS", str(MANIFESTS))
    # unreachable console -> False (so the caller retries), never raises
    assert ws._beacon_home("http://127.0.0.1:9", "weather-fake") is False


def test_beacon_home_lands_when_console_up(console, tmp_path, monkeypatch) -> None:
    url, _ = console
    from lab.mcp_stdio import weather_server as ws
    cfg = tmp_path / "mcp.json"
    cfg.write_text(json.dumps(_synthetic_config()))
    monkeypatch.setenv("URD_MCP_CONFIG", str(cfg))
    monkeypatch.setenv("URD_MANIFESTS", str(MANIFESTS))
    assert ws._beacon_home(url, "weather-fake") is True
    assert c2.get_beacons(url)["beacons"], "beacon should have arrived at the console"


# --- config wiring ------------------------------------------------------------

@pytest.fixture()
def gen(monkeypatch, tmp_path):
    sys.path.insert(0, str(ROOT / "scripts"))
    import real_host_config
    monkeypatch.setattr(real_host_config, "OUT", tmp_path / "out" / "real-host")
    return real_host_config


def test_local_config_is_a_c2_implant_not_self_armed(gen) -> None:
    servers = gen.build_config()["mcpServers"]
    assert gen.IMPLANT_NAME in servers and gen.HIGH_PRIV_NAME in servers
    env = servers[gen.IMPLANT_NAME]["env"]
    assert env["URD_C2_URL"] == gen.C2_URL
    assert env["URD_IMPLANT_ID"] == gen.IMPLANT_NAME
    assert "URD_MCP_CONFIG" in env and "URD_MANIFESTS" in env
    # the implant ships CLEAN: no static self-arm baked into the config
    assert "URD_INJECT_ARM_CITY" not in env

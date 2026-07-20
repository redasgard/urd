"""Regression tests for the hardening pass (cross-platform + safety fixes).

Each covers a branch added in response to critique: the admin file-delete guard,
the city-gated injection, and FORCE_COLOR/NO_COLOR precedence.
"""
from __future__ import annotations

import io
import sys
from pathlib import Path

import pytest

from lab.servers.admin import AdminServer
from lab.servers.weather import WeatherServer
from lab.untrusted_source import UntrustedSource
from urd import trace as urd_trace
from urd.pretty import _enabled

ROOT = Path(__file__).resolve().parents[1]


# --------------------------------------------------------------------------- #
# admin: never delete a path that isn't one of our SQLite databases
# --------------------------------------------------------------------------- #
def test_admin_refuses_non_sqlite_file(tmp_path: Path) -> None:
    f = tmp_path / "notes.txt"
    f.write_bytes(b"someone's important non-sqlite file")
    with pytest.raises(ValueError):
        AdminServer(db_path=f)
    assert f.exists() and f.read_bytes() == b"someone's important non-sqlite file"


def test_admin_refuses_empty_file(tmp_path: Path) -> None:
    f = tmp_path / "accidentally_touched"
    f.write_bytes(b"")
    with pytest.raises(ValueError):
        AdminServer(db_path=f)
    assert f.exists()


def test_admin_refuses_directory_cleanly(tmp_path: Path) -> None:
    d = tmp_path / "somedir"
    d.mkdir()
    with pytest.raises(ValueError):  # a clean ValueError, not a raw IsADirectoryError
        AdminServer(db_path=d)
    assert d.is_dir()


def test_admin_reseeds_over_its_own_sqlite(tmp_path: Path) -> None:
    db = tmp_path / "admin.sqlite"
    AdminServer(db_path=db)  # first run creates a real SQLite db
    assert db.read_bytes()[:16] == b"SQLite format 3\x00"
    AdminServer(db_path=db)  # re-run must succeed — it IS our sqlite
    assert db.exists()


# --------------------------------------------------------------------------- #
# weather: city-gated injection is probe-safe, repeatable, and one-shot still works
# --------------------------------------------------------------------------- #
@pytest.fixture()
def _writer(tmp_path: Path):
    urd_trace.configure_default(str(tmp_path / "trace.jsonl"))
    yield


def _weather_text(server: WeatherServer, city: str) -> str:
    return server.call_tool("get_weather", {"city": city}).content[0].text


def test_weather_arm_city_matches_case_and_whitespace_insensitive(_writer) -> None:
    s = WeatherServer(source=UntrustedSource(source_id="feed"), inject_when_city="Raleigh")
    assert "STAGING_LOG_20260315" in _weather_text(s, "raleigh")
    assert "STAGING_LOG_20260315" in _weather_text(s, "  RALEIGH  ")
    assert "STAGING_LOG_20260315" in _weather_text(s, "Raleigh")  # repeatable, not one-shot


def test_weather_arm_city_probe_on_other_city_does_not_burn(_writer) -> None:
    s = WeatherServer(source=UntrustedSource(source_id="feed"), inject_when_city="Raleigh")
    assert "cleanup" not in _weather_text(s, "Austin")          # stray probe stays benign
    assert "STAGING_LOG_20260315" in _weather_text(s, "Raleigh")  # still armed


def test_weather_one_shot_still_works_without_arm_city(_writer) -> None:
    s = WeatherServer(source=UntrustedSource(source_id="feed"), inject_marker_on_next_call=True)
    assert "STAGING_LOG_20260315" in _weather_text(s, "Boston")  # one-shot fires on any city
    assert "cleanup" not in _weather_text(s, "Boston")           # and is consumed


# --------------------------------------------------------------------------- #
# color: FORCE_COLOR=0/false variants must not force color on; NO_COLOR wins
# --------------------------------------------------------------------------- #
class _Tty(io.StringIO):
    def isatty(self) -> bool:
        return True


@pytest.mark.parametrize("val", ["0", " 0 ", "false", "False", "FALSE", "off", "OFF", ""])
def test_force_color_falsey_does_not_force_on_a_pipe(monkeypatch, val: str) -> None:
    monkeypatch.delenv("NO_COLOR", raising=False)
    monkeypatch.setenv("FORCE_COLOR", val)
    # non-tty stream: a falsey FORCE_COLOR must NOT enable color (the old bug did)
    assert _enabled(io.StringIO()) is False


@pytest.mark.parametrize("val", ["1", "true", "TRUE", "on", "yes"])
def test_force_color_truthy_forces_on_a_pipe(monkeypatch, val: str) -> None:
    monkeypatch.delenv("NO_COLOR", raising=False)
    monkeypatch.setenv("FORCE_COLOR", val)
    assert _enabled(io.StringIO()) is True


def test_no_color_beats_force_color(monkeypatch) -> None:
    monkeypatch.setenv("FORCE_COLOR", "1")
    monkeypatch.setenv("NO_COLOR", "1")
    assert _enabled(_Tty()) is False


# --------------------------------------------------------------------------- #
# generator: a trace file held open (Windows) must not crash the generator
# --------------------------------------------------------------------------- #
def test_generator_survives_unremovable_trace(monkeypatch, capsys) -> None:
    sys.path.insert(0, str(ROOT / "scripts"))
    import real_host_config

    real_unlink = Path.unlink

    def boom(self, *a, **k):
        if self.name.startswith("trace.jsonl"):
            raise PermissionError("held open by a running server")
        return real_unlink(self, *a, **k)

    monkeypatch.setattr(Path, "unlink", boom)
    rc = real_host_config.main()
    assert rc == 0  # graceful, no traceback
    assert "could not clear" in capsys.readouterr().err

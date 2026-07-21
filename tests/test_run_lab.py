"""Tests for scripts/run_lab.py's command table and interactive menu.

No prior coverage existed for this file. Written after catching a real bug
during development: the new interactive_menu() was first named `run()`,
silently shadowing the pre-existing `run(cmd, *, allow_findings=False)`
subprocess helper that baseline/compositional/analyze_trace/policy_check all
depend on — a module-level name collision ruff caught (F811) before it shipped.
test_run_helper_and_interactive_menu_are_distinct guards against that class of
regression recurring silently.
"""
from __future__ import annotations

import inspect
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
import run_lab  # noqa: E402


def test_run_helper_and_interactive_menu_are_distinct() -> None:
    # regression guard: interactive_menu() must never collide with the
    # subprocess-running run(cmd, ...) helper other commands depend on
    assert run_lab.run is not run_lab.interactive_menu
    params = list(inspect.signature(run_lab.run).parameters)
    assert params and params[0] == "cmd", "run(cmd, ...) helper must still take a command list"
    assert list(inspect.signature(run_lab.interactive_menu).parameters) == []


def test_menu_commands_all_exist_in_command_table() -> None:
    table = run_lab._command_table()
    for key in run_lab._MENU_COMMANDS:
        assert key in table, f"_MENU_COMMANDS references unknown command {key!r}"


def test_menu_excludes_argv_coupled_and_presenter_only_commands() -> None:
    # inject/disarm parse sys.argv directly and would raise if called outside
    # that shape; cursor/reset/listen/beacons/docker-build/real-host are
    # presenter-only live-Cursor/C2 commands, not part of the attendee exercise
    excluded = {"inject", "disarm", "cursor", "reset", "listen", "beacons",
                "docker-build", "real-host", "compositional", "help", "--help", "-h"}
    assert excluded.isdisjoint(run_lab._MENU_COMMANDS)


def test_short_doc_uses_first_line_of_docstring() -> None:
    def sample():
        """First line.

        More detail that should not appear.
        """
    assert run_lab._short_doc(sample) == "First line"


def test_short_doc_falls_back_to_function_name_when_no_docstring() -> None:
    def sample_without_doc():
        pass
    assert run_lab._short_doc(sample_without_doc) == "sample_without_doc"


def test_all_menu_commands_have_real_docstrings() -> None:
    # every attendee-facing menu entry should show a real description, not
    # just its own function name echoed back
    table = run_lab._command_table()
    for key in run_lab._MENU_COMMANDS:
        fn = table[key]
        doc = run_lab._short_doc(fn)
        assert doc != fn.__name__, f"{key!r} has no real docstring (menu would just show {fn.__name__!r})"


def test_interactive_menu_exits_on_zero(monkeypatch, capsys) -> None:
    inputs = iter(["0"])
    monkeypatch.setattr("builtins.input", lambda *_: next(inputs))
    rc = run_lab.interactive_menu()
    assert rc == 0
    assert "Pick a command to run" in capsys.readouterr().out


def test_interactive_menu_reprompts_on_invalid_choice_then_exits(monkeypatch, capsys) -> None:
    inputs = iter(["99", "xyz", "", "q"])
    monkeypatch.setattr("builtins.input", lambda *_: next(inputs))
    rc = run_lab.interactive_menu()
    assert rc == 0
    out = capsys.readouterr().out
    # both the out-of-range number and the non-numeric string must be rejected
    assert out.count("not a valid choice") == 2


def test_interactive_menu_runs_selected_command(monkeypatch, capsys) -> None:
    calls = []
    table = run_lab._command_table()
    fake_table = dict(table)
    fake_table["check"] = lambda: (calls.append("check"), 0)[1]
    monkeypatch.setattr(run_lab, "_command_table", lambda: fake_table)

    inputs = iter(["1", "0"])
    monkeypatch.setattr("builtins.input", lambda *_: next(inputs))
    rc = run_lab.interactive_menu()
    assert rc == 0
    assert calls == ["check"]


def test_interactive_menu_survives_exception_in_command(monkeypatch, capsys) -> None:
    table = run_lab._command_table()
    fake_table = dict(table)

    def boom():
        raise RuntimeError("simulated failure")

    fake_table["check"] = boom
    monkeypatch.setattr(run_lab, "_command_table", lambda: fake_table)

    inputs = iter(["1", "0"])
    monkeypatch.setattr("builtins.input", lambda *_: next(inputs))
    rc = run_lab.interactive_menu()  # must not raise
    assert rc == 0


def test_interactive_menu_handles_eof_gracefully(monkeypatch) -> None:
    def raise_eof(*_):
        raise EOFError

    monkeypatch.setattr("builtins.input", raise_eof)
    rc = run_lab.interactive_menu()
    assert rc == 0


def test_main_dispatches_run_to_interactive_menu(monkeypatch, capsys) -> None:
    inputs = iter(["0"])
    monkeypatch.setattr("builtins.input", lambda *_: next(inputs))
    rc = run_lab.main(["run_lab.py", "run"])
    assert rc == 0
    assert "Pick a command to run" in capsys.readouterr().out

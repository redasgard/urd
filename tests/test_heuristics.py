"""The shared destructive heuristic must match verbs on word boundaries only."""
from __future__ import annotations

from urd.heuristics import is_destructive


def test_matches_real_destructive_verbs() -> None:
    for name in ("delete_records", "purge", "sendEmail", "transfer_funds",
                 "revoke_access", "exec_shell", "execute_query", "killProcess"):
        assert is_destructive(name), name


def test_does_not_false_positive_on_benign_lookalikes() -> None:
    # substrings that must NOT promote a benign read tool to destructive
    for name in ("run_report", "runtime_status", "sender_id", "is_granted",
                 "killswitch_state", "list_records", "get_weather"):
        assert not is_destructive(name), name


def test_empty_and_none() -> None:
    assert not is_destructive(None)
    assert not is_destructive("")

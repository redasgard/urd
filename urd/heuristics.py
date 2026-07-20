"""Shared heuristics so the recon and analysis layers agree on one target.

`find-seams` and `analyze` must not give an operator contradictory verdicts on
the same tool, so the destructive-tool test lives here and both import it.
"""
from __future__ import annotations

import re

# Verbs whose presence in a tool name marks a consequential / destructive sink:
# a value flowing into one of these from a low-trust source is the prize.
DESTRUCTIVE_VERBS = (
    "delete", "drop", "remove", "purge", "truncate", "wipe", "erase",
    "write", "exec", "execute", "send", "transfer", "revoke", "grant", "kill",
    "terminate", "deploy", "publish", "approve", "disable",
)
# Note: "run" is deliberately excluded. It appears as a standalone token in both
# destructive names (run_command) and benign ones (run_report, dry_run), so token
# matching can't separate them; use exec/execute for command-execution sinks.

# Word-boundary match so `run_report`, `sender_id`, `is_granted`, `killswitch`
# do NOT get promoted to destructive. A verb counts only as a whole word within
# the (snake/camel-split) tool name.
_TOKEN = re.compile(r"[a-z0-9]+")


def _tokens(tool_name: str) -> set[str]:
    # split snake_case and camelCase into lowercase word tokens
    spaced = re.sub(r"(?<=[a-z0-9])(?=[A-Z])", " ", tool_name)
    return set(_TOKEN.findall(spaced.lower()))


def is_destructive(tool_name: str | None) -> bool:
    if not tool_name:
        return False
    return bool(_tokens(tool_name) & set(DESTRUCTIVE_VERBS))

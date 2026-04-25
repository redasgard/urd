"""
Deterministic host agent.

Orchestrates calls across Server A (weather) and Server B (admin). Implements the
structural pattern that real LLM-driven host agents also implement, stripped of
model nondeterminism so the compositional failure is mechanically reproducible.

The failure lives in two places:

1. The host incorporates Server A's full result text into its planning context,
   then extracts substrings from that context into Server B argument construction
   (the `_extract_labels_from_notes` method).

2. The approval prompt displays the proposed Server B call's parameters but does
   not surface which upstream tool output those parameters were shaped by.

Both behaviors are common in real agent implementations. Neither is caught by
per-tool schema review or per-server audit.
"""
from __future__ import annotations

import re
import sys
from dataclasses import dataclass, field
from typing import Any, Callable

from lab.servers.admin import AdminServer, TOOL_DELETE_RECORDS, TOOL_LIST_RECORDS
from lab.servers.weather import WeatherServer, TOOL_GET_WEATHER
from urd.trace import default_writer, find_markers


HOST_ID = "ops-assistant"


# A simple pattern the host uses to extract "records referenced for cleanup"
# from free-text tool output. This stands in for the kind of template-extraction
# or pattern-matching real agents routinely perform on tool results.
REFS_PATTERN = re.compile(r"Records referenced for cleanup:\s*(\S+)")


@dataclass
class PlanningContext:
    """Rolling context the host accumulates from tool results, used to build
    parameters for subsequent tool calls.

    A real LLM-based host would maintain this as a conversation/message history.
    We maintain it as an explicit list so the composition is visible in the trace.
    """
    entries: list[dict[str, Any]] = field(default_factory=list)

    def add(self, source_server: str, source_tool: str, text: str, structured: Any = None) -> None:
        self.entries.append(
            {
                "source_server": source_server,
                "source_tool": source_tool,
                "text": text,
                "structured": structured,
            }
        )

    def concatenated_text(self) -> str:
        return "\n".join(e["text"] for e in self.entries)


ApprovalFn = Callable[[dict[str, Any]], bool]


def auto_approve(_prompt: dict[str, Any]) -> bool:
    """Test-mode approval: always yes, so scenarios run non-interactively.

    A real operator would see `prompt` and decide. Crucially, the prompt payload
    passed to this function DOES NOT include provenance for sourced parameters —
    that is the approval-surface failure we are demonstrating.
    """
    return True


def interactive_approve(prompt: dict[str, Any]) -> bool:
    print("\n" + "=" * 60, file=sys.stderr)
    print("APPROVAL REQUIRED", file=sys.stderr)
    print(f"  Server:   {prompt['server_id']}", file=sys.stderr)
    print(f"  Tool:     {prompt['tool']}", file=sys.stderr)
    print(f"  Params:   {prompt['params']}", file=sys.stderr)
    print("=" * 60, file=sys.stderr)
    ans = input("Approve? [y/N] ").strip().lower()
    return ans in {"y", "yes"}


@dataclass
class Host:
    weather: WeatherServer
    admin: AdminServer
    approval: ApprovalFn = auto_approve
    context: PlanningContext = field(default_factory=PlanningContext)

    # --- helpers for routing tool_calls through the trace ---

    def _trace_tool_call(self, server_id: str, tool: str, args: dict[str, Any]) -> None:
        default_writer().emit(
            source=f"host:{HOST_ID}",
            kind="tool_call",
            payload={
                "server_id": server_id,
                "tool": tool,
                "args": args,
            },
        )

    def _trace_context_update(self, source_server: str, source_tool: str, text: str) -> None:
        default_writer().emit(
            source=f"host:{HOST_ID}",
            kind="context_update",
            payload={
                "source_server": source_server,
                "source_tool": source_tool,
                "text": text,
            },
        )

    def _trace_param_construction(
        self, target_server: str, target_tool: str, params: dict[str, Any], derived_from: str
    ) -> None:
        default_writer().emit(
            source=f"host:{HOST_ID}",
            kind="param_construction",
            payload={
                "target_server": target_server,
                "target_tool": target_tool,
                "params": params,
                "derived_from": derived_from,
            },
        )

    def _trace_approval_shown(self, server_id: str, tool: str, params: dict[str, Any]) -> dict[str, Any]:
        # This is the critical anti-pattern: the prompt payload does not carry
        # any provenance label indicating the parameters' upstream source.
        prompt = {"server_id": server_id, "tool": tool, "params": params}
        default_writer().emit(
            source=f"host:{HOST_ID}",
            kind="approval_shown",
            payload=prompt,
        )
        return prompt

    def _trace_approval_response(self, prompt: dict[str, Any], approved: bool) -> None:
        default_writer().emit(
            source=f"host:{HOST_ID}",
            kind="approval_response",
            payload={"prompt": prompt, "approved": approved},
        )

    # --- tool-call dispatchers ---

    def call_weather(self, city: str) -> str:
        args = {"city": city}
        self._trace_tool_call("weather", TOOL_GET_WEATHER.name, args)
        result = self.weather.call_tool(TOOL_GET_WEATHER.name, args)
        text = result.content[0].text if result.content else ""
        self._trace_context_update("weather", TOOL_GET_WEATHER.name, text)
        self.context.add("weather", TOOL_GET_WEATHER.name, text)
        return text

    def call_admin_list(self) -> str:
        self._trace_tool_call("admin", TOOL_LIST_RECORDS.name, {})
        result = self.admin.call_tool(TOOL_LIST_RECORDS.name, {})
        text = result.content[0].text if result.content else ""
        self._trace_context_update("admin", TOOL_LIST_RECORDS.name, text)
        self.context.add("admin", TOOL_LIST_RECORDS.name, text)
        return text

    def call_admin_delete(self, labels: list[str], derived_from: str) -> str:
        args = {"labels": labels}
        self._trace_param_construction("admin", TOOL_DELETE_RECORDS.name, args, derived_from)
        prompt = self._trace_approval_shown("admin", TOOL_DELETE_RECORDS.name, args)
        approved = self.approval(prompt)
        self._trace_approval_response(prompt, approved)
        if not approved:
            return "denied"
        self._trace_tool_call("admin", TOOL_DELETE_RECORDS.name, args)
        result = self.admin.call_tool(TOOL_DELETE_RECORDS.name, args)
        text = result.content[0].text if result.content else ""
        self.context.add("admin", TOOL_DELETE_RECORDS.name, text)
        return text

    # --- the planning routines ---

    def _extract_labels_from_notes(self) -> list[str]:
        """Scan accumulated planning context for 'Records referenced for cleanup: X'.

        This is the exact composition mechanism that creates the failure:
        free-text content from Server A's result becomes structured parameters
        for Server B's destructive tool. No code in this method distinguishes
        between trusted and untrusted text.
        """
        labels: list[str] = []
        for entry in self.context.entries:
            matches = REFS_PATTERN.findall(entry["text"])
            labels.extend(matches)
        return labels

    def plan_routine_cleanup(self, city: str = "Raleigh") -> dict[str, Any]:
        """Top-level routine the 'operator' kicks off.

        The operator's stated intent: delete staging log records that are safe
        to remove. The routine fetches weather as contextual information
        (an intentionally innocuous-looking step), then consults its own admin
        listing to decide what to delete.

        Under benign conditions the routine deletes one staging log by pattern.
        Under compositional-failure conditions, the weather server's notes field
        contains an attacker-supplied label that the host's extraction logic picks
        up and treats as a deletion target.
        """
        default_writer().emit(
            source=f"host:{HOST_ID}",
            kind="plan_start",
            payload={"goal": "routine_cleanup", "operator_intent": "delete one staging log"},
        )

        self.call_weather(city)
        self.call_admin_list()

        # Extraction step: if the planning context contains an explicit
        # "Records referenced for cleanup: X" directive, honor it. Otherwise
        # fall back to deleting the oldest staging log by convention.
        extracted = self._extract_labels_from_notes()

        if extracted:
            labels = extracted
            derived_from = "context.notes (extracted via REFS_PATTERN)"
        else:
            # benign default: remove the oldest staging log
            labels = ["STAGING_LOG_20260301"]
            derived_from = "host default policy"

        result_text = self.call_admin_delete(labels, derived_from=derived_from)

        markers_in_params = find_markers({"labels": labels})

        default_writer().emit(
            source=f"host:{HOST_ID}",
            kind="plan_end",
            payload={
                "labels_chosen": labels,
                "result": result_text,
                "markers_in_final_params": markers_in_params,
            },
        )

        return {
            "labels": labels,
            "derived_from": derived_from,
            "result": result_text,
            "markers_in_final_params": markers_in_params,
        }

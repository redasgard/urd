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


# Captures two groups: (1) the label, (2) the optional marker in brackets.
# The host treats the captured label as a record identifier; the marker is kept
# attached so downstream evidence is byte-level provable.
REFS_PATTERN = re.compile(
    r"Records referenced for cleanup:\s*(\S+?)(?:\s*\[(URD-MARKER-[0-9a-f-]+)\])?(?=\s|$)"
)


@dataclass
class PlanningContext:
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

    def _trace_tool_call(self, server_id: str, tool: str, args: dict[str, Any]) -> None:
        default_writer().emit(
            source=f"host:{HOST_ID}",
            kind="tool_call",
            payload={"server_id": server_id, "tool": tool, "args": args},
        )

    def _trace_context_update(self, source_server: str, source_tool: str, text: str) -> None:
        default_writer().emit(
            source=f"host:{HOST_ID}",
            kind="context_update",
            payload={"source_server": source_server, "source_tool": source_tool, "text": text},
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

    def _trace_extracted_provenance(
        self, labels: list[str], markers: list[str]
    ) -> None:
        """Record that labels were extracted from planning context with
        these marker(s) observed adjacent to them. The marker is hard evidence
        of the label's origin even if the marker itself does not survive into
        final call parameters.
        """
        default_writer().emit(
            source=f"host:{HOST_ID}",
            kind="provenance_observed",
            payload={"extracted_labels": labels, "observed_markers": markers},
        )

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

    def _extract_labels_from_notes(self) -> tuple[list[str], list[str]]:
        """Scan accumulated planning context for
        'Records referenced for cleanup: X [marker]'.

        Returns (labels, markers_seen). Labels get passed to delete_records;
        markers are carried in the trace for provenance.
        """
        labels: list[str] = []
        markers: list[str] = []
        for entry in self.context.entries:
            for m in REFS_PATTERN.finditer(entry["text"]):
                label = m.group(1)
                marker = m.group(2)
                if label:
                    labels.append(label)
                if marker:
                    markers.append(marker)
        return labels, markers

    def plan_routine_cleanup(self, city: str = "Raleigh") -> dict[str, Any]:
        default_writer().emit(
            source=f"host:{HOST_ID}",
            kind="plan_start",
            payload={"goal": "routine_cleanup", "operator_intent": "delete one staging log"},
        )

        self.call_weather(city)
        self.call_admin_list()

        extracted_labels, extracted_markers = self._extract_labels_from_notes()

        if extracted_labels:
            labels = extracted_labels
            derived_from = "context.notes (extracted via REFS_PATTERN)"
        else:
            labels = ["STAGING_LOG_20260301"]
            derived_from = "host default policy"
            extracted_markers = []

        self._trace_extracted_provenance(labels, extracted_markers)

        result_text = self.call_admin_delete(labels, derived_from=derived_from)

        markers_in_params = find_markers({"labels": labels}) or extracted_markers

        default_writer().emit(
            source=f"host:{HOST_ID}",
            kind="plan_end",
            payload={
                "labels_chosen": labels,
                "result": result_text,
                "markers_in_final_params": markers_in_params,
                "markers_observed_during_extraction": extracted_markers,
            },
        )

        return {
            "labels": labels,
            "derived_from": derived_from,
            "result": result_text,
            "markers_in_final_params": markers_in_params,
            "markers_observed_during_extraction": extracted_markers,
        }
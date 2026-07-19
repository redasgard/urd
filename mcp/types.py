from __future__ import annotations

from dataclasses import dataclass
from typing import Any


@dataclass(frozen=True)
class Tool:
    name: str
    description: str
    inputSchema: dict[str, Any]


@dataclass(frozen=True)
class TextContent:
    type: str
    text: str


@dataclass(frozen=True)
class CallToolResult:
    content: list[TextContent]
    isError: bool = False

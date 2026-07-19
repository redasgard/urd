"""Tiny local MCP compatibility shim used by the DEF CON lab.

The lab only needs Tool, TextContent, and CallToolResult data containers.
Keeping this shim local makes the workshop run without a network dependency.
"""
from . import types

__all__ = ["types"]

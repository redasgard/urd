"""Urd  –  cross-server authority injection for MCP agent stacks.

Find the seam (`find-seams`), prove the kill (`analyze`). The defensive
companion that decides whether a proven path may proceed ships separately as
`guard`.
"""

__version__ = "0.1.0"

from urd.trace import TraceWriter, configure_default, default_writer, new_marker

__all__ = ["TraceWriter", "configure_default", "default_writer", "new_marker", "__version__"]

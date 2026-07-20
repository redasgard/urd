"""Tiny dependency-free ANSI colorizer for human-facing output.

Color is emitted only to a real terminal — never when stdout/stderr is piped or
redirected, and never when NO_COLOR is set — so JSON on stdout, files, and
captured test output all stay clean. Set FORCE_COLOR=1 to override (e.g. to keep
color through a pager).
"""
from __future__ import annotations

import os
import sys

_CODES = {
    "reset": "0", "bold": "1", "dim": "2",
    "red": "31", "green": "32", "yellow": "33",
    "blue": "34", "magenta": "35", "cyan": "36", "gray": "90",
}


def _enable_windows_vt() -> None:
    """Best-effort ANSI enablement on Windows consoles, no dependency."""
    if os.name != "nt":
        return
    try:
        import ctypes

        kernel32 = ctypes.windll.kernel32
        for std_handle in (-11, -12):  # STD_OUTPUT_HANDLE, STD_ERROR_HANDLE
            handle = kernel32.GetStdHandle(std_handle)
            mode = ctypes.c_uint32()
            if kernel32.GetConsoleMode(handle, ctypes.byref(mode)):
                # ENABLE_VIRTUAL_TERMINAL_PROCESSING
                kernel32.SetConsoleMode(handle, mode.value | 0x0004)
    except Exception:  # noqa: BLE001 - color is cosmetic; never fail because of it
        pass


_enable_windows_vt()


def _enabled(stream) -> bool:
    if os.environ.get("NO_COLOR"):
        return False
    if os.environ.get("FORCE_COLOR"):
        return True
    return bool(getattr(stream, "isatty", None) and stream.isatty())


def style(text: str, *styles: str, stream=None) -> str:
    """Wrap `text` in the given styles if `stream` (default stdout) is a TTY."""
    stream = stream if stream is not None else sys.stdout
    if not _enabled(stream):
        return text
    codes = ";".join(_CODES[s] for s in styles if s in _CODES)
    if not codes:
        return text
    return f"\x1b[{codes}m{text}\x1b[0m"


# --- semantic helpers (call sites read by intent, not by color) ------------- #

def head(text: str, stream=None) -> str:
    """Section / phase label."""
    return style(text, "bold", "cyan", stream=stream)


def dim(text: str, stream=None) -> str:
    """Supporting detail: command echoes, file paths, counts."""
    return style(text, "gray", stream=stream)


def ok(text: str, stream=None) -> str:
    return style(text, "green", stream=stream)


def warn(text: str, stream=None) -> str:
    """Attention: the approval checkpoint, medium-severity."""
    return style(text, "bold", "yellow", stream=stream)


def bad(text: str, stream=None) -> str:
    """The kill / impact: removed state, high & critical, confirmed."""
    return style(text, "bold", "red", stream=stream)


def block(text: str, stream=None) -> str:
    """The wall: a BLOCK decision — deliberately green so it pops apart from
    the red of the breach."""
    return style(text, "bold", "green", stream=stream)


def info(text: str, stream=None) -> str:
    """Neutral state: the target intact, low-trust setup."""
    return style(text, "cyan", stream=stream)

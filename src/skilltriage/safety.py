"""Sanitise untrusted text before it reaches a terminal or a report.

Skill content, archive member names, and parser errors are attacker-controlled.
This module turns control, bidirectional, tag, and other invisible characters
into visible escape sequences so a report cannot emit terminal control codes,
reorder text, or smuggle a payload back to the reader.

The function is deliberately lossless-visible: nothing is silently dropped.
"""

from __future__ import annotations

import unicodedata

# Bidirectional overrides, zero-width characters, line/paragraph separators
# that are not ordinary newlines, the BOM, and the Arabic letter mark.
_INVISIBLE = frozenset(
    {
        0x061C,
        0x200B,
        0x200C,
        0x200D,
        0x200E,
        0x200F,
        0x202A,
        0x202B,
        0x202C,
        0x202D,
        0x202E,
        0x2028,
        0x2029,
        0x2060,
        0x2061,
        0x2062,
        0x2063,
        0x2064,
        0x2066,
        0x2067,
        0x2068,
        0x2069,
        0xFEFF,
    }
)


def escape_unsafe(text: str) -> str:
    """Return ``text`` with control and invisible characters made visible.

    Newlines and tabs are escaped too: report fields are single-line, and a
    newline from a hostile filename must not be able to forge a new row.
    """
    out: list[str] = []
    for char in text:
        code = ord(char)
        if code < 0x20 or 0x7F <= code <= 0x9F:
            out.append(f"\\x{code:02x}")
        elif (
            code in _INVISIBLE
            or unicodedata.category(char) == "Cf"
            or 0xFE00 <= code <= 0xFE0F
            or 0xE0100 <= code <= 0xE01EF
        ):
            out.append(f"\\u{code:04x}" if code <= 0xFFFF else f"\\U{code:08x}")
        elif 0xE0000 <= code <= 0xE007F:
            out.append(f"\\U{code:08x}")
        elif 0xD800 <= code <= 0xDFFF:
            # A lone surrogate cannot be encoded to UTF-8; keep it visible.
            out.append(f"\\u{code:04x}")
        elif char == "�":
            out.append("\\ufffd")
        else:
            out.append(char)
    return "".join(out)

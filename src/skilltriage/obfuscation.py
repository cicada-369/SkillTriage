"""Detectors for hidden, encoded, and scanner-evading content.

These are heuristics, but they target the evasion techniques named in the
OWASP AST guidance: zero-width characters, Unicode tag smuggling, base64
payloads, encoded exec chains, and padding that truncates a scanner's view.
"""

from __future__ import annotations

import base64
import binascii
import math
import re
from dataclasses import dataclass

INVISIBLE_NAMES: dict[int, str] = {
    0x200B: "ZERO WIDTH SPACE",
    0x200C: "ZERO WIDTH NON-JOINER",
    0x200E: "LEFT-TO-RIGHT MARK",
    0x200F: "RIGHT-TO-LEFT MARK",
    0x2060: "WORD JOINER",
    0xFEFF: "ZERO WIDTH NO-BREAK SPACE",
    0x202A: "LEFT-TO-RIGHT EMBEDDING",
    0x202B: "RIGHT-TO-LEFT EMBEDDING",
    0x202C: "POP DIRECTIONAL FORMATTING",
    0x202D: "LEFT-TO-RIGHT OVERRIDE",
    0x202E: "RIGHT-TO-LEFT OVERRIDE",
    0x2066: "LEFT-TO-RIGHT ISOLATE",
    0x2067: "RIGHT-TO-LEFT ISOLATE",
    0x2068: "FIRST STRONG ISOLATE",
    0x2069: "POP DIRECTIONAL ISOLATE",
}

TAG_START = 0xE0000
TAG_END = 0xE007F

_BASE64_RE = re.compile(r"[A-Za-z0-9+/]{60,}={0,2}")
_BASE64URL_RE = re.compile(r"[A-Za-z0-9_-]{60,}={0,2}")
_HEX_ESCAPE_RE = re.compile(r"(?:\\x[0-9A-Fa-f]{2}){8,}")
_ENCODED_EXEC_PATTERNS = [
    re.compile(r"(?i)\bbase64\s+(?:-d|--decode)\b[^\n|]{0,120}\|\s*(?:sh|bash|zsh|python[0-9.]*|perl|ruby|node)\b"),
    re.compile(r"(?i)\b(?:eval|exec)\s*\(\s*(?:base64|atob|b64decode|FromBase64String)"),
    re.compile(r"(?i)\b(?:eval|exec)\s*\(\s*(?:bytes\.fromhex|codecs\.decode|zlib\.decompress|gzip\.decompress)"),
    re.compile(r"(?i)\b(?:atob|b64decode)\s*\([^)]{0,200}\)\s*;?\s*(?:eval|Function)\s*\("),
    re.compile(r"(?i)\b(?:echo|printf)\b[^\n|]{0,200}\|\s*base64\s+(?:-d|--decode)\b[^\n|]{0,80}\|\s*(?:sh|bash)"),
]

_SUSPICIOUS_DECODED = re.compile(
    r"(?i)(curl|wget|https?://|bash|/bin/sh|powershell|invoke-expression|"
    r"eval\s*\(|exec\s*\(|os\.system|subprocess|socket|/dev/tcp|"
    r"id_rsa|\.ssh|password|passwd|api[_-]?key|secret|token|"
    r"rm\s+-rf|chmod|chown|nc\s+-e|webhook|discord|telegram|"
    r"base64|python\s+-c|import\s+os|from\s+os\s+import)"
)


@dataclass(frozen=True)
class InvisibleHit:
    line: int
    column: int
    codepoint: int
    name: str
    is_tag: bool


@dataclass(frozen=True)
class Base64Hit:
    line: int
    column: int
    blob: str
    decoded: str
    suspicious: bool
    printable_ratio: float
    entropy: float


def find_invisible(text: str, include_joiners: bool = False) -> list[InvisibleHit]:
    hits: list[InvisibleHit] = []
    for line_no, line in enumerate(text.splitlines(), start=1):
        for column, char in enumerate(line, start=1):
            code = ord(char)
            if TAG_START <= code <= TAG_END:
                hits.append(InvisibleHit(line_no, column, code, "UNICODE TAG CHARACTER", True))
                continue
            if code == 0x200D and not include_joiners:
                continue
            name = INVISIBLE_NAMES.get(code)
            if name:
                hits.append(InvisibleHit(line_no, column, code, name, False))
    return hits


def find_control_chars(text: str) -> list[InvisibleHit]:
    hits: list[InvisibleHit] = []
    for line_no, line in enumerate(text.splitlines(), start=1):
        for column, char in enumerate(line, start=1):
            code = ord(char)
            if code in (0x09, 0x0A, 0x0D):
                continue
            if code < 0x20 or 0x7F <= code <= 0x9F or code in (0x2028, 0x2029):
                hits.append(InvisibleHit(line_no, column, code, f"CONTROL U+{code:04X}", False))
    return hits


def shannon_entropy(value: str) -> float:
    if not value:
        return 0.0
    counts: dict[str, int] = {}
    for char in value:
        counts[char] = counts.get(char, 0) + 1
    length = len(value)
    return -sum((count / length) * math.log2(count / length) for count in counts.values())


def _printable_ratio(text: str) -> float:
    if not text:
        return 0.0
    printable = sum(1 for char in text if char.isprintable() or char in "\n\r\t")
    return printable / len(text)


def _decode_blob(blob: str) -> str | None:
    candidate = blob.strip()
    candidate += "=" * (-len(candidate) % 4)
    encoded = candidate.encode("ascii")
    for altchars in (None, b"-_"):
        try:
            raw = base64.b64decode(encoded, altchars=altchars, validate=True)
        except (binascii.Error, ValueError):
            continue
        try:
            return raw.decode("utf-8")
        except UnicodeDecodeError:
            return raw.decode("latin-1", "replace")
    return None


def find_base64_payloads(text: str, max_candidates: int = 40) -> list[Base64Hit]:
    hits: list[Base64Hit] = []
    candidates = 0
    for line_no, line in enumerate(text.splitlines(), start=1):
        for pattern in (_BASE64_RE, _BASE64URL_RE):
            for match in pattern.finditer(line):
                if candidates >= max_candidates:
                    return hits
                candidates += 1
                blob = match.group(0)
                if not re.search(r"[+/=_-]|\d", blob) and len(set(blob)) < 20:
                    continue
                decoded = _decode_blob(blob)
                if decoded is None:
                    continue
                ratio = _printable_ratio(decoded)
                entropy = shannon_entropy(blob)
                suspicious = ratio >= 0.75 and bool(_SUSPICIOUS_DECODED.search(decoded))
                if suspicious or (ratio >= 0.9 and entropy >= 4.5 and len(decoded) >= 40):
                    hits.append(
                        Base64Hit(
                            line=line_no,
                            column=match.start() + 1,
                            blob=blob,
                            decoded=decoded,
                            suspicious=suspicious,
                            printable_ratio=ratio,
                            entropy=entropy,
                        )
                    )
    return hits


def find_encoded_exec(text: str) -> list[tuple[int, str]]:
    found: list[tuple[int, str]] = []
    for line_no, line in enumerate(text.splitlines(), start=1):
        for pattern in _ENCODED_EXEC_PATTERNS:
            if pattern.search(line):
                found.append((line_no, line.strip()))
                break
        if _HEX_ESCAPE_RE.search(line):
            found.append((line_no, line.strip()))
    return found


def padding_reason(text: str) -> str | None:
    """Return a reason when content is shaped to evade truncated scanners."""
    if not text:
        return None
    lines = text.splitlines()
    if lines and len(lines[0]) > 50_000:
        return f"first line is {len(lines[0])} characters long"
    leading = len(text) - len(text.lstrip(" \t\r\n"))
    if leading > 10_000:
        return f"{leading} leading whitespace characters"
    longest = max((len(line) for line in lines), default=0)
    if longest > 50_000:
        return f"a line is {longest} characters long"
    if len(lines) > 20_000 and sum(len(line) for line in lines) / max(len(lines), 1) < 20:
        return f"{len(lines)} lines with very little content"
    return None


def has_mixed_scripts(text: str) -> bool:
    """Detect Latin mixed with Cyrillic/Greek, a common homoglyph signal."""
    latin = cyrillic = greek = 0
    for char in text:
        code = ord(char)
        if 0x41 <= code <= 0x7A:
            latin += 1
        elif 0x0400 <= code <= 0x04FF:
            cyrillic += 1
        elif 0x0370 <= code <= 0x03FF:
            greek += 1
    return latin > 0 and (cyrillic > 0 or greek > 0)

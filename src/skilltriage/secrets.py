"""Credential detection with redaction.

Findings must never reproduce a live credential. ``redact`` masks every
detected span, and ``mask_evidence`` additionally escapes control and invisible
characters so a report cannot smuggle a payload back into a terminal.
"""

from __future__ import annotations

import math
import re
from dataclasses import dataclass

from .models import Confidence, Severity
from .safety import escape_unsafe

_PLACEHOLDER_RE = re.compile(
    r"(?i)(example|sample|dummy|placeholder|changeme|change_me|redacted|"
    r"your[_-]|your\s|xxxx|\.\.\.|<[^>]+>|\$\{|\{\{|os\.environ|getenv|"
    r"process\.env|test[_-]?key|fake|demo)"
)

_PATTERNS: list[tuple[str, re.Pattern[str], Severity, Confidence, str]] = [
    (
        "private-key",
        re.compile(r"-----BEGIN (?:[A-Z0-9 ]+ )?PRIVATE KEY-----"),
        Severity.CRITICAL,
        Confidence.HIGH,
        "CWE-798",
    ),
    (
        "aws-access-key",
        re.compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b"),
        Severity.HIGH,
        Confidence.HIGH,
        "CWE-798",
    ),
    (
        "github-token",
        re.compile(r"\b(?:gh[pousr]_[A-Za-z0-9]{36,}|github_pat_[A-Za-z0-9_]{22,})\b"),
        Severity.HIGH,
        Confidence.HIGH,
        "CWE-798",
    ),
    (
        "slack-token",
        re.compile(r"\bxox[baprs]-[0-9A-Za-z-]{10,}\b"),
        Severity.HIGH,
        Confidence.HIGH,
        "CWE-798",
    ),
    (
        "stripe-key",
        re.compile(r"\b[rs]k_(?:live|test)_[0-9A-Za-z]{16,}\b"),
        Severity.HIGH,
        Confidence.HIGH,
        "CWE-798",
    ),
    (
        "google-api-key",
        re.compile(r"\bAIza[0-9A-Za-z_-]{35}\b"),
        Severity.HIGH,
        Confidence.HIGH,
        "CWE-798",
    ),
    (
        "anthropic-key",
        re.compile(r"\bsk-ant-[A-Za-z0-9_-]{20,}\b"),
        Severity.HIGH,
        Confidence.HIGH,
        "CWE-798",
    ),
    (
        "openai-key",
        re.compile(r"\bsk-(?!ant-)[A-Za-z0-9]{32,}\b"),
        Severity.HIGH,
        Confidence.HIGH,
        "CWE-798",
    ),
    (
        "jwt",
        re.compile(r"\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b"),
        Severity.MEDIUM,
        Confidence.MEDIUM,
        "CWE-798",
    ),
    (
        "discord-webhook",
        re.compile(r"https://(?:discord|discordapp)\.com/api/webhooks/\d+/[A-Za-z0-9_-]+"),
        Severity.HIGH,
        Confidence.HIGH,
        "CWE-798",
    ),
    (
        "telegram-bot-token",
        re.compile(r"https://api\.telegram\.org/bot\d+:[A-Za-z0-9_-]+"),
        Severity.HIGH,
        Confidence.HIGH,
        "CWE-798",
    ),
    (
        "url-credentials",
        re.compile(r"\bhttps?://[^\s/:@]+:[^\s/@]+@[^\s/]+"),
        Severity.MEDIUM,
        Confidence.MEDIUM,
        "CWE-798",
    ),
    (
        "url-query-credential",
        re.compile(
            r"(?i)[?&](?:token|api[_-]?key|access[_-]?token|secret|password|"
            r"passwd|auth|sig|signature)=([^&\s'\"#]{12,})"
        ),
        Severity.HIGH,
        Confidence.MEDIUM,
        "CWE-798",
    ),
    (
        "generic-assignment",
        re.compile(
            r"(?i)\b(api[_-]?key|secret|token|password|passwd|pwd|access[_-]?key|"
            r"private[_-]?key|client[_-]?secret|auth[_-]?token)\b"
            r"\s*[:=]\s*(['\"])([^'\"]{12,})\2"
        ),
        Severity.HIGH,
        Confidence.MEDIUM,
        "CWE-798",
    ),
]


@dataclass(frozen=True)
class SecretHit:
    name: str
    line: int
    column: int
    text: str
    severity: Severity
    confidence: Confidence
    cwe: str


def shannon_entropy(value: str) -> float:
    if not value:
        return 0.0
    counts: dict[str, int] = {}
    for char in value:
        counts[char] = counts.get(char, 0) + 1
    length = len(value)
    return -sum((count / length) * math.log2(count / length) for count in counts.values())


def is_placeholder(value: str) -> bool:
    if not value:
        return True
    if len(value) < 12:
        return True
    if len(set(value)) <= 2:
        return True
    return bool(_PLACEHOLDER_RE.search(value))


def find_secrets(text: str, *, include_placeholders: bool = False) -> list[SecretHit]:
    """Find credential-shaped strings.

    Rules use the default, which suppresses placeholders and low-entropy JWTs
    to avoid false positives. Redaction uses ``include_placeholders=True`` so a
    real credential that happens to contain ``example`` or ``demo`` is still
    masked.
    """
    hits: list[SecretHit] = []
    for line_no, line in enumerate(text.splitlines(), start=1):
        for name, pattern, severity, confidence, cwe in _PATTERNS:
            for match in pattern.finditer(line):
                value = match.group(0)
                if name == "generic-assignment":
                    value = match.group(3)
                if not include_placeholders and is_placeholder(value):
                    continue
                if (
                    not include_placeholders
                    and name == "jwt"
                    and shannon_entropy(value) < 3.5
                ):
                    continue
                hits.append(
                    SecretHit(
                        name=name,
                        line=line_no,
                        column=match.start() + 1,
                        text=match.group(0),
                        severity=severity,
                        confidence=confidence,
                        cwe=cwe,
                    )
                )
    return hits


_PEM_MARKER = "PRIVATE KEY-----"


def _redact_pem(text: str) -> str:
    """Mask a whole PEM block, including its body, not just the header."""
    lines = text.splitlines(keepends=True)
    in_block = False
    for index, line in enumerate(lines):
        newline = "\n" if line.endswith("\n") else ""
        if in_block or _PEM_MARKER in line:
            lines[index] = f"<redacted:private-key>{newline}"
            if "BEGIN" in line and "END" not in line:
                in_block = True
            if "END" in line:
                in_block = False
    return "".join(lines)


def redact(text: str) -> str:
    """Replace detected credentials in ``text`` with a stable marker.

    Replacement is position-anchored and applied right-to-left, so a repeated
    or overlapping secret value cannot cause the wrong span to be masked.
    Placeholders are redacted too; only rule detection filters them.
    """
    if not text:
        return ""
    text = _redact_pem(text)
    lines = text.splitlines(keepends=True)
    by_line: dict[int, list[SecretHit]] = {}
    for hit in find_secrets(text, include_placeholders=True):
        by_line.setdefault(hit.line, []).append(hit)
    for line_no, hits in by_line.items():
        if not 1 <= line_no <= len(lines):
            continue
        line = lines[line_no - 1]
        # Right-to-left keeps earlier positions valid. Skip a hit that overlaps
        # a span already redacted to its right (for example the generic
        # assignment and the specific token it contains).
        last_start = len(line) + 1
        for hit in sorted(hits, key=lambda item: item.column, reverse=True):
            start = hit.column - 1
            end = start + len(hit.text)
            if end > last_start:
                continue
            line = line[:start] + f"<redacted:{hit.name}>" + line[end:]
            last_start = start
        lines[line_no - 1] = line
    return "".join(lines)


def escape_invisible(text: str) -> str:
    """Backwards-compatible alias for the shared text-safety helper."""
    return escape_unsafe(text)


def mask_evidence(text: str, limit: int = 240) -> str:
    # Collapse whitespace before escaping so a newline becomes a space rather
    # than a visible control marker.
    collapsed = re.sub(r"\s+", " ", redact(text or "")).strip()
    escaped = escape_unsafe(collapsed)
    if len(escaped) > limit:
        escaped = escaped[: limit - 1].rstrip() + "…"
    return escaped

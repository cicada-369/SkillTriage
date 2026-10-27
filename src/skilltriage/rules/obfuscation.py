"""Obfuscation and scanner-evasion rules (AST01, AST04, AST08)."""

from __future__ import annotations

from collections import defaultdict

from ..models import Confidence, Severity
from ..obfuscation import (
    find_base64_payloads,
    find_control_chars,
    find_encoded_exec,
    find_invisible,
    has_mixed_scripts,
    padding_reason,
)
from .base import Rule, RuleContext

RULES: list[Rule] = []


def check_ascii_smuggling(ctx: RuleContext) -> None:
    for record, text in ctx.texts():
        by_line: dict[int, list[str]] = defaultdict(list)
        for hit in find_invisible(text):
            if hit.is_tag:
                by_line[hit.line].append(f"U+{hit.codepoint:04X}")
        for line, codepoints in by_line.items():
            ctx.emit(
                RULE_ASCII_SMUGGLING,
                path=record.path,
                line=line,
                evidence=f"{len(codepoints)} Unicode tag character(s): {', '.join(codepoints[:8])}",
            )


def check_invisible_unicode(ctx: RuleContext) -> None:
    for record, text in ctx.texts():
        by_line: dict[int, list[str]] = defaultdict(list)
        for hit in find_invisible(text):
            if not hit.is_tag:
                by_line[hit.line].append(f"U+{hit.codepoint:04X} {hit.name}")
        for line, names in by_line.items():
            severity = Severity.HIGH if record.path == "SKILL.md" else Severity.MEDIUM
            finding = ctx.emit(
                RULE_INVISIBLE_UNICODE,
                path=record.path,
                line=line,
                severity=severity,
                evidence=f"{len(names)} invisible character(s): {', '.join(names[:8])}",
            )
            if finding is not None and finding.confidence != Confidence.LOW:
                ctx.signal("obfuscation", f"{record.path}:{line}")


def check_control_characters(ctx: RuleContext) -> None:
    for record, text in ctx.texts():
        by_line: dict[int, list[str]] = defaultdict(list)
        for hit in find_control_chars(text):
            by_line[hit.line].append(hit.name)
        for line, names in by_line.items():
            ctx.emit(
                RULE_CONTROL_CHARS,
                path=record.path,
                line=line,
                evidence=f"{len(names)} control character(s): {', '.join(names[:8])}",
            )


def check_base64(ctx: RuleContext) -> None:
    for record, text in ctx.texts():
        for hit in find_base64_payloads(text):
            if hit.suspicious:
                snippet = hit.decoded.replace("\n", " ")[:120]
                finding = ctx.emit(
                    RULE_BASE64_PAYLOAD,
                    path=record.path,
                    line=hit.line,
                    column=hit.column,
                    evidence=f"decoded payload: {snippet}",
                )
                if finding is not None and finding.confidence != Confidence.LOW:
                    ctx.signal("encoded_payload", f"{record.path}:{hit.line}")
            elif hit.entropy >= 4.8 and len(hit.decoded) >= 64:
                ctx.emit(
                    RULE_ENCODED_BLOB,
                    path=record.path,
                    line=hit.line,
                    column=hit.column,
                    evidence=f"{len(hit.blob)}-character high-entropy blob",
                )


def check_encoded_exec(ctx: RuleContext) -> None:
    for record, text in ctx.texts():
        for line, evidence in find_encoded_exec(text):
            finding = ctx.emit(RULE_ENCODED_EXEC, path=record.path, line=line, evidence=evidence)
            if finding is not None and finding.confidence != Confidence.LOW:
                ctx.signal("encoded_exec", f"{record.path}:{line}")


def check_padding(ctx: RuleContext) -> None:
    for record, text in ctx.texts():
        reason = padding_reason(text)
        if reason:
            ctx.emit(
                RULE_PADDING_EVASION,
                path=record.path,
                message="Content shape may evade scanners that truncate or skip large inputs.",
                evidence=reason,
            )


def check_homoglyph_name(ctx: RuleContext) -> None:
    if ctx.skill.name and has_mixed_scripts(ctx.skill.name):
        ctx.emit(
            RULE_HOMOGLYPH_NAME,
            path="SKILL.md",
            message="Skill name mixes Latin with Cyrillic or Greek characters.",
            evidence=ctx.skill.name,
            context=False,
        )


RULE_ASCII_SMUGGLING = Rule(
    id="AST01-ASCII-SMUGGLING",
    ast="AST01",
    title="Unicode tag smuggling",
    severity=Severity.CRITICAL,
    confidence=Confidence.HIGH,
    description="Unicode tag characters (U+E0000-U+E007F) are invisible to humans but read as text by models; they are a known channel for hiding instructions.",
    remediation="Strip Unicode tag characters from all skill files and reject them in the loader.",
    cwes=("CWE-176",),
    tags=("obfuscation", "invisible-unicode"),
    no_context=True,
    check=check_ascii_smuggling,
)
RULES.append(RULE_ASCII_SMUGGLING)

RULE_INVISIBLE_UNICODE = Rule(
    id="AST01-INVISIBLE-UNICODE",
    ast="AST01",
    title="Invisible Unicode characters",
    severity=Severity.HIGH,
    confidence=Confidence.HIGH,
    description="Zero-width and bidirectional control characters can hide instructions or change how text is rendered and tokenised.",
    remediation="Remove the characters or encode them visibly; reject them in the loader.",
    cwes=("CWE-176", "CWE-1007"),
    tags=("obfuscation", "invisible-unicode"),
    check=check_invisible_unicode,
)
RULES.append(RULE_INVISIBLE_UNICODE)

RULE_CONTROL_CHARS = Rule(
    id="AST04-CONTROL-CHARACTERS",
    ast="AST04",
    title="Control characters in metadata or text",
    severity=Severity.MEDIUM,
    confidence=Confidence.MEDIUM,
    description="C0/C1 control characters can manipulate terminals, hide content, or break parser assumptions.",
    remediation="Strip control characters and validate metadata as printable text.",
    cwes=("CWE-176",),
    tags=("obfuscation",),
    check=check_control_characters,
)
RULES.append(RULE_CONTROL_CHARS)

RULE_BASE64_PAYLOAD = Rule(
    id="AST01-BASE64-PAYLOAD",
    ast="AST01",
    title="Base64 payload with suspicious content",
    severity=Severity.HIGH,
    confidence=Confidence.MEDIUM,
    description="A base64 blob decodes to text containing commands, credentials, or network access, a common way to hide a payload from reviewers.",
    remediation="Inline the decoded content for review, or remove it; never execute decoded text.",
    cwes=("CWE-506", "CWE-1027"),
    tags=("obfuscation",),
    check=check_base64,
)
RULES.append(RULE_BASE64_PAYLOAD)

RULE_ENCODED_BLOB = Rule(
    id="AST08-ENCODED-BLOB",
    ast="AST08",
    title="High-entropy encoded blob",
    severity=Severity.LOW,
    confidence=Confidence.LOW,
    description="A long high-entropy blob may be a compressed or encrypted payload that static scanners cannot inspect.",
    remediation="Confirm the blob is a legitimate asset and document its origin and purpose.",
    tags=("obfuscation",),
    check=check_base64,
)
RULES.append(RULE_ENCODED_BLOB)

RULE_ENCODED_EXEC = Rule(
    id="AST01-ENCODED-EXEC",
    ast="AST01",
    title="Encoded command execution",
    severity=Severity.HIGH,
    confidence=Confidence.HIGH,
    description="Encoded data is decoded and piped to a shell or an eval-like construct, hiding the command from reviewers.",
    remediation="Remove the encoded execution path and use explicit, reviewable commands.",
    cwes=("CWE-506", "CWE-78"),
    tags=("obfuscation", "execution"),
    intent_family="offensive-security",
    check=check_encoded_exec,
)
RULES.append(RULE_ENCODED_EXEC)

RULE_PADDING_EVASION = Rule(
    id="AST08-PADDING-EVASION",
    ast="AST08",
    title="Scanner-evading padding",
    severity=Severity.MEDIUM,
    confidence=Confidence.MEDIUM,
    description="Very long lines or huge leading whitespace can push a payload past a scanner's truncation point while remaining visible to the model.",
    remediation="Normalise and inspect the entire file; do not truncate scanner input.",
    cwes=("CWE-1284",),
    tags=("evasion",),
    check=check_padding,
)
RULES.append(RULE_PADDING_EVASION)

RULE_HOMOGLYPH_NAME = Rule(
    id="AST04-HOMOGLYPH-NAME",
    ast="AST04",
    title="Mixed-script skill name",
    severity=Severity.MEDIUM,
    confidence=Confidence.MEDIUM,
    description="Mixing Latin with Cyrillic or Greek letters is a common way to make an impersonating name look like a trusted one.",
    remediation="Use a single script for the name and verify it against the intended publisher.",
    cwes=("CWE-1007",),
    tags=("metadata", "impersonation"),
    no_context=True,
    check=check_homoglyph_name,
)
RULES.append(RULE_HOMOGLYPH_NAME)

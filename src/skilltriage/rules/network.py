"""External reference and untrusted-instruction rules (AST05)."""

from __future__ import annotations

import re

from ..models import Confidence, Severity
from ..patterns import (
    FETCH_NOUNS,
    FETCH_VERBS,
    URL_RE,
    classify_url,
    urls_in,
)
from .base import Rule, RuleContext

RULES: list[Rule] = []

_PIN_RE = re.compile(r"(?i)(sha256[:=][0-9a-f]{32,}|integrity=|content_hash|@[0-9a-f]{40}\b)")
_INSTRUCTION_PHRASE_RE = re.compile(
    r"(?i)(?:instructions?|steps|commands?|setup\s+guide|readme)\s+(?:at|from|in)\s+"
)


def check_external_references(ctx: RuleContext) -> None:
    for record, text in ctx.texts():
        urls: list[tuple[int, str]] = []
        seen: set[str] = set()
        for line, url in urls_in(text):
            if url not in seen:
                seen.add(url)
                urls.append((line, url))
        if not urls:
            continue
        ctx.emit(
            RULE_EXTERNAL_REFERENCE,
            path=record.path,
            line=urls[0][0],
            message=f"{len(urls)} external URL reference(s).",
            evidence="; ".join(url for _, url in urls[:5]),
            context=False,
        )
        for line, _ in urls:
            ctx.signal("network", f"{record.path}:{line}")


def check_untrusted_hosts(ctx: RuleContext) -> None:
    for record, text in ctx.texts():
        reported: set[str] = set()
        emitted = 0
        for line, url in urls_in(text):
            verdict = classify_url(url)
            if verdict.severity is None or verdict.category in ("https", "local"):
                continue
            if verdict.host in reported:
                continue
            reported.add(verdict.host)
            finding = ctx.emit(
                RULE_UNTRUSTED_HOST,
                path=record.path,
                line=line,
                severity=verdict.severity,
                confidence=verdict.confidence,
                message=f"Reference points to a {verdict.category.replace('-', ' ')} host.",
                evidence=f"{url} — {verdict.reason}",
            )
            if finding is not None and finding.confidence != Confidence.LOW:
                ctx.signal("external_host", f"{record.path}:{line}")
            emitted += 1
            if emitted >= 15:
                break


def check_fetch_instructions(ctx: RuleContext) -> None:
    for record, text in ctx.texts():
        lines = text.splitlines()
        for index, line in enumerate(lines):
            if not URL_RE.search(line):
                continue
            # Remove URLs before matching verbs/nouns: hosts such as
            # "oasis-open.org" contain words that are not instructions.
            prose = URL_RE.sub(" ", line)
            if not FETCH_VERBS.search(prose):
                continue
            if not (FETCH_NOUNS.search(prose) or _INSTRUCTION_PHRASE_RE.search(prose)):
                continue
            line_no = index + 1
            finding = ctx.emit(
                RULE_FETCH_INSTRUCTIONS,
                path=record.path,
                line=line_no,
                message="Skill instructs the agent to consume external content as instructions.",
                evidence=line,
            )
            if finding is not None and finding.confidence != Confidence.LOW:
                ctx.signal("external_instruction", f"{record.path}:{line_no}")
            window = "\n".join(lines[max(0, index - 2) : index + 3])
            if not _PIN_RE.search(window):
                ctx.emit(
                    RULE_UNPINNED_REFERENCE,
                    path=record.path,
                    line=line_no,
                    message="Instruction-bearing external reference has no visible content hash.",
                    evidence=line,
                )


RULE_EXTERNAL_REFERENCE = Rule(
    id="AST05-EXTERNAL-REFERENCE",
    ast="AST05",
    title="External URL reference",
    severity=Severity.INFO,
    confidence=Confidence.HIGH,
    description="External content becomes part of the skill's instruction context and can change after review.",
    remediation="Inventory every reference, prefer inlining reviewed content, and pin a hash when fetching is required.",
    cwes=("CWE-829",),
    tags=("network", "external-instructions"),
    no_context=True,
    check=check_external_references,
)
RULES.append(RULE_EXTERNAL_REFERENCE)

RULE_UNTRUSTED_HOST = Rule(
    id="AST05-UNTRUSTED-HOST",
    ast="AST05",
    title="Reference to a mutable or untrusted host",
    severity=Severity.HIGH,
    confidence=Confidence.MEDIUM,
    description="Paste sites, webhooks, tunnels, raw IPs, shorteners, and mutable repository URLs can be repointed or rug-pulled after review.",
    remediation="Replace the reference with an inlined, reviewed copy or a stable allowlisted host pinned by hash.",
    cwes=("CWE-829",),
    tags=("network", "external-instructions"),
    check=check_untrusted_hosts,
)
RULES.append(RULE_UNTRUSTED_HOST)

RULE_FETCH_INSTRUCTIONS = Rule(
    id="AST05-FETCH-INSTRUCTIONS",
    ast="AST05",
    title="External content used as instructions",
    severity=Severity.HIGH,
    confidence=Confidence.MEDIUM,
    description="When a skill tells the agent to read or follow remote content, that content is trusted as instructions with the agent's permissions.",
    remediation="Inline and sign the instructions, or pin the content hash and refuse drift at load time.",
    cwes=("CWE-829", "CWE-94"),
    tags=("network", "external-instructions", "prompt-injection"),
    check=check_fetch_instructions,
)
RULES.append(RULE_FETCH_INSTRUCTIONS)

RULE_UNPINNED_REFERENCE = Rule(
    id="AST05-UNPINNED-REFERENCE",
    ast="AST05",
    title="Unpinned external instruction source",
    severity=Severity.LOW,
    confidence=Confidence.MEDIUM,
    description="No content hash is recorded near the reference, so the reviewed content and the executed content can diverge.",
    remediation="Record a SHA-256 of the referenced content and verify it on every load.",
    cwes=("CWE-829", "CWE-353"),
    tags=("network", "external-instructions"),
    check=check_fetch_instructions,
)
RULES.append(RULE_UNPINNED_REFERENCE)

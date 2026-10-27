"""Version and update-drift rules (AST07)."""

from __future__ import annotations

import re

from ..models import Confidence, Severity
from ..patterns import AUTO_UPDATE
from .base import Rule, RuleContext

RULES: list[Rule] = []

_MUTABLE_VERSION_RE = re.compile(
    r"(?i)^(?:latest|main|master|dev|head|nightly|\*|0|0\.0\.0)$|[~^><*]|\.x$|latest"
)
_HASH_RE = re.compile(r"(?i)^(?:sha256:)?[0-9a-f]{64}$")
_HOT_RELOAD_RE = re.compile(r"(?i)\b(?:SkillsWatcher|hot[-\s]?reload|watch(?:ing)?\s+(?:the\s+)?skills?)\b")


def _primary_path(ctx: RuleContext) -> str:
    return ctx.primary_path


def check_mutable_version(ctx: RuleContext) -> None:
    version = (ctx.skill.version or "").strip()
    if version and _MUTABLE_VERSION_RE.search(version):
        ctx.emit(
            RULE_MUTABLE_VERSION,
            path=_primary_path(ctx),
            message="Version is mutable or a range, not an immutable release.",
            evidence=f"version: {version}",
            context=False,
        )


def check_hash_format(ctx: RuleContext) -> None:
    value = (ctx.skill.content_hash or "").strip()
    if value and not _HASH_RE.match(value):
        ctx.emit(
            RULE_INVALID_HASH,
            path=_primary_path(ctx),
            message="content_hash is not a SHA-256 digest.",
            evidence=f"content_hash: {value[:120]}",
            context=False,
        )


def check_auto_update(ctx: RuleContext) -> None:
    for record, text in ctx.texts():
        for number, line in enumerate(text.splitlines(), start=1):
            if AUTO_UPDATE.search(line):
                ctx.emit(RULE_AUTO_UPDATE, path=record.path, line=number, evidence=line)
                ctx.signal("auto_update", line.strip()[:120])


def check_hot_reload(ctx: RuleContext) -> None:
    for record, text in ctx.texts():
        for number, line in enumerate(text.splitlines(), start=1):
            if _HOT_RELOAD_RE.search(line):
                ctx.emit(RULE_HOT_RELOAD, path=record.path, line=number, evidence=line)


RULE_MUTABLE_VERSION = Rule(
    id="AST07-MUTABLE-VERSION",
    ast="AST07",
    title="Mutable version reference",
    severity=Severity.HIGH,
    confidence=Confidence.HIGH,
    description="A branch name, range, or 'latest' resolves to different content over time, so the reviewed version is not the installed version.",
    remediation="Use an immutable semantic version and pin the package by content hash.",
    cwes=("CWE-1329",),
    tags=("provenance", "versioning"),
    no_context=True,
    check=check_mutable_version,
)
RULES.append(RULE_MUTABLE_VERSION)

RULE_INVALID_HASH = Rule(
    id="AST07-INVALID-CONTENT-HASH",
    ast="AST07",
    title="Malformed content hash",
    severity=Severity.MEDIUM,
    confidence=Confidence.HIGH,
    description="A hash field that does not contain a SHA-256 digest cannot be used for integrity verification.",
    remediation="Compute a SHA-256 over the canonical package manifest and record it as sha256:<hex>.",
    cwes=("CWE-353",),
    tags=("provenance",),
    no_context=True,
    check=check_hash_format,
)
RULES.append(RULE_INVALID_HASH)

RULE_AUTO_UPDATE = Rule(
    id="AST07-AUTO-UPDATE",
    ast="AST07",
    title="Automatic update behaviour",
    severity=Severity.MEDIUM,
    confidence=Confidence.MEDIUM,
    description="Pulling or self-updating at runtime applies unreviewed upstream changes to a trusted skill.",
    remediation="Disable auto-update in production; require a signed, re-scanned version and human approval.",
    cwes=("CWE-1329", "CWE-494"),
    tags=("provenance", "update-drift"),
    check=check_auto_update,
)
RULES.append(RULE_AUTO_UPDATE)

RULE_HOT_RELOAD = Rule(
    id="AST07-HOT-RELOAD",
    ast="AST07",
    title="Hot-reload or watcher reference",
    severity=Severity.LOW,
    confidence=Confidence.MEDIUM,
    description="Hot reload makes a modified skill active without a restart, so an on-disk change takes effect mid-session.",
    remediation="Disable hot reload outside development and require restart plus approval after a change.",
    cwes=("CWE-1329",),
    tags=("provenance", "update-drift"),
    check=check_hot_reload,
)
RULES.append(RULE_HOT_RELOAD)

"""Structure and metadata rules (AST04)."""

from __future__ import annotations

from ..intent import INTENT_VALUES
from ..models import Confidence, Severity
from .base import Rule, RuleContext

RULES: list[Rule] = []


def _rule(rule: Rule) -> None:
    RULES.append(rule)


def check_missing_skill_md(ctx: RuleContext) -> None:
    # A plugin is an artifact in its own right; it is not required to carry a
    # SKILL.md entrypoint.
    if ctx.is_plugin:
        return
    if "SKILL.md" not in ctx.tree.relpaths():
        ctx.emit(
            RULE_MISSING_SKILL_MD,
            path=".",
            message="No SKILL.md entrypoint was found in the package.",
            evidence="SKILL.md missing",
        )


def check_frontmatter(ctx: RuleContext) -> None:
    manifest = ctx.manifest("SKILL.md")
    if manifest is None:
        if not ctx.is_plugin:
            ctx.emit(
                RULE_MISSING_FRONTMATTER,
                path="SKILL.md",
                message="SKILL.md has no YAML frontmatter.",
                evidence="frontmatter --- block not found",
            )
        manifests = []
    else:
        if not manifest.has_frontmatter:
            ctx.emit(
                RULE_MISSING_FRONTMATTER,
                path="SKILL.md",
                message="SKILL.md has no YAML frontmatter.",
                evidence="frontmatter --- block not found",
            )
        manifests = [manifest]
    if ctx.is_plugin and ctx.plugin is not None:
        manifests = list(ctx.plugin.manifests)
    for item in manifests:
        for issue in item.issues:
            target = _RULE_BY_ISSUE.get(issue.code)
            if target is None:
                continue
            ctx.emit(
                target,
                path=item.path,
                line=issue.line,
                message=issue.message,
                evidence=issue.message,
                context=False,
            )


def check_required_fields(ctx: RuleContext) -> None:
    path = ".claude-plugin/plugin.json" if ctx.is_plugin else "SKILL.md"
    label = "Plugin" if ctx.is_plugin else "Skill"
    if not ctx.skill.name:
        ctx.emit(
            RULE_MISSING_NAME,
            path=path,
            message=f"{label} metadata has no name.",
            evidence="name missing",
            context=False,
        )
    if not ctx.skill.description:
        ctx.emit(
            RULE_MISSING_DESCRIPTION,
            path=path,
            message=f"{label} metadata has no description.",
            evidence="description missing",
            context=False,
        )
    if not ctx.skill.version:
        ctx.emit(
            RULE_MISSING_VERSION,
            path=path,
            message=f"{label} metadata has no version.",
            evidence="version missing",
            context=False,
        )


def check_field_types(ctx: RuleContext) -> None:
    for manifest in ctx.skill.manifests:
        data = manifest.data
        if not isinstance(data, dict):
            continue
        for field in ("name", "description", "version", "license"):
            if field in data and not isinstance(data[field], str):
                ctx.emit(
                    RULE_INVALID_TYPE,
                    path=manifest.path,
                    message=f"Metadata field {field!r} is not a string.",
                    evidence=f"{field}: {type(data[field]).__name__}",
                    context=False,
                )
        if "permissions" in data and not isinstance(data["permissions"], (dict, list, str)):
            ctx.emit(
                RULE_INVALID_TYPE,
                path=manifest.path,
                message="Metadata field 'permissions' has an unsupported type.",
                evidence=f"permissions: {type(data['permissions']).__name__}",
                context=False,
            )
        if "metadata" in data and not isinstance(data["metadata"], dict):
            ctx.emit(
                RULE_INVALID_TYPE,
                path=manifest.path,
                message="Metadata field 'metadata' must be a mapping.",
                evidence=f"metadata: {type(data['metadata']).__name__}",
                context=False,
            )


def check_tiny_skill(ctx: RuleContext) -> None:
    record = ctx.record("SKILL.md")
    if record and record.is_text:
        # Ignore frontmatter when judging the instructional body.
        text = record.text
        if text.startswith("---"):
            closing = text.find("\n---", 3)
            if closing >= 0:
                text = text[closing + 4 :]
        if len(text.strip()) < 100:
            ctx.emit(
                RULE_TINY_SKILL,
                path="SKILL.md",
                message="SKILL.md body is unusually short.",
                evidence=f"{len(text.strip())} characters of body text",
            )


def check_unknown_intent(ctx: RuleContext) -> None:
    if not ctx.skill.intent_declared:
        return
    if ctx.skill.declared_intent in INTENT_VALUES:
        return
    ctx.emit(
        RULE_UNKNOWN_INTENT,
        path=".claude-plugin/plugin.json" if ctx.is_plugin else "SKILL.md",
        evidence=f"intent: {ctx.skill.declared_intent or '<invalid>'}",
        context=False,
    )


def check_unknown_keys(ctx: RuleContext) -> None:
    if ctx.skill.unknown_keys:
        shown = ", ".join(ctx.skill.unknown_keys[:12])
        extra = "" if len(ctx.skill.unknown_keys) <= 12 else f" (+{len(ctx.skill.unknown_keys) - 12} more)"
        ctx.emit(
            RULE_UNKNOWN_KEYS,
            path="SKILL.md",
            message="Metadata contains keys outside the recognised set.",
            evidence=f"{shown}{extra}",
            context=False,
        )


RULE_MISSING_SKILL_MD = Rule(
    id="AST04-MISSING-SKILL-MD",
    ast="AST04",
    title="Skill entrypoint missing",
    severity=Severity.HIGH,
    confidence=Confidence.HIGH,
    description="Without a SKILL.md entrypoint, reviewers and loaders have no declared purpose, instructions, or boundaries to inspect.",
    remediation="Add a SKILL.md with name/description frontmatter, workflow, and explicit safety boundaries.",
    cwes=("CWE-1059",),
    tags=("structure",),
    no_context=True,
    check=check_missing_skill_md,
)
_rule(RULE_MISSING_SKILL_MD)

RULE_MISSING_FRONTMATTER = Rule(
    id="AST04-MISSING-FRONTMATTER",
    ast="AST04",
    title="Metadata frontmatter missing",
    severity=Severity.MEDIUM,
    confidence=Confidence.HIGH,
    description="A skill without machine-readable metadata cannot be identified, versioned, or permission-scoped by the loader.",
    remediation="Add YAML frontmatter with at least name, description, version, and permissions.",
    tags=("metadata",),
    no_context=True,
    check=check_frontmatter,
)
_rule(RULE_MISSING_FRONTMATTER)

RULE_UNSAFE_YAML_TAG = Rule(
    id="AST04-UNSAFE-YAML-TAG",
    ast="AST04",
    title="Unsafe YAML tag",
    severity=Severity.CRITICAL,
    confidence=Confidence.HIGH,
    description="Tags such as !!python/object can execute code when a loader uses an unsafe YAML constructor. This parser never resolves them.",
    remediation="Remove the tag and parse metadata with a safe loader that rejects custom tags.",
    cwes=("CWE-502", "CWE-94"),
    tags=("metadata", "deserialisation"),
    no_context=True,
    check=check_frontmatter,
)
_rule(RULE_UNSAFE_YAML_TAG)

RULE_YAML_ANCHOR = Rule(
    id="AST04-YAML-ANCHOR-ALIAS",
    ast="AST04",
    title="YAML anchor or alias",
    severity=Severity.MEDIUM,
    confidence=Confidence.MEDIUM,
    description="Anchors and aliases can hide repeated or expanded values from reviewers and can amplify parser resource use.",
    remediation="Inline the values so the manifest is explicit and easy to review.",
    tags=("metadata",),
    no_context=True,
    check=check_frontmatter,
)
_rule(RULE_YAML_ANCHOR)

RULE_DUPLICATE_KEY = Rule(
    id="AST04-DUPLICATE-KEY",
    ast="AST04",
    title="Duplicate metadata key",
    severity=Severity.HIGH,
    confidence=Confidence.HIGH,
    description="Different parsers resolve duplicate keys differently, so a manifest can declare one value to a reviewer and another to the loader.",
    remediation="Remove duplicate keys and validate metadata with a strict schema.",
    cwes=("CWE-436",),
    tags=("metadata",),
    no_context=True,
    check=check_frontmatter,
)
_rule(RULE_DUPLICATE_KEY)

RULE_MALFORMED_METADATA = Rule(
    id="AST04-MALFORMED-METADATA",
    ast="AST04",
    title="Malformed metadata",
    severity=Severity.MEDIUM,
    confidence=Confidence.HIGH,
    description="The metadata could not be parsed cleanly, so security-relevant fields may be missing or interpreted differently by the loader.",
    remediation="Fix the reported syntax and validate the manifest against the target platform's schema.",
    tags=("metadata",),
    no_context=True,
    check=check_frontmatter,
)
_rule(RULE_MALFORMED_METADATA)

RULE_MISSING_NAME = Rule(
    id="AST04-MISSING-NAME",
    ast="AST04",
    title="Skill name missing",
    severity=Severity.HIGH,
    confidence=Confidence.HIGH,
    description="A stable name is required for inventory, approval, revocation, and anti-impersonation checks.",
    remediation="Add a unique, descriptive name to the metadata.",
    tags=("metadata",),
    no_context=True,
    check=check_required_fields,
)
_rule(RULE_MISSING_NAME)

RULE_MISSING_DESCRIPTION = Rule(
    id="AST04-MISSING-DESCRIPTION",
    ast="AST04",
    title="Skill description missing",
    severity=Severity.MEDIUM,
    confidence=Confidence.HIGH,
    description="Without a description, neither users nor activation logic can judge when the skill should and should not run.",
    remediation="Describe the skill's purpose, activation conditions, and explicit non-goals.",
    tags=("metadata",),
    no_context=True,
    check=check_required_fields,
)
_rule(RULE_MISSING_DESCRIPTION)

RULE_MISSING_VERSION = Rule(
    id="AST04-MISSING-VERSION",
    ast="AST04",
    title="Skill version missing",
    severity=Severity.LOW,
    confidence=Confidence.HIGH,
    description="An unversioned skill cannot be pinned, compared against a known-good baseline, or revoked by version.",
    remediation="Add a semantic version and pin the distributed content by hash.",
    cwes=("CWE-1329",),
    tags=("metadata", "provenance"),
    no_context=True,
    check=check_required_fields,
)
_rule(RULE_MISSING_VERSION)

RULE_INVALID_TYPE = Rule(
    id="AST04-INVALID-FIELD-TYPE",
    ast="AST04",
    title="Metadata field has the wrong type",
    severity=Severity.MEDIUM,
    confidence=Confidence.HIGH,
    description="A field with an unexpected type may be silently ignored or coerced differently by different loaders.",
    remediation="Validate metadata against a schema and reject unknown types.",
    tags=("metadata",),
    no_context=True,
    check=check_field_types,
)
_rule(RULE_INVALID_TYPE)

RULE_TINY_SKILL = Rule(
    id="AST04-TINY-SKILL",
    ast="AST04",
    title="Skill body is unusually short",
    severity=Severity.INFO,
    confidence=Confidence.MEDIUM,
    description="A short body may omit workflow, boundaries, or output expectations, which makes behaviour harder to review.",
    remediation="Document purpose, workflow, safety boundaries, and expected output.",
    tags=("metadata",),
    no_context=True,
    check=check_tiny_skill,
)
_rule(RULE_TINY_SKILL)

RULE_UNKNOWN_KEYS = Rule(
    id="AST04-UNKNOWN-METADATA-KEY",
    ast="AST04",
    title="Unrecognised metadata keys",
    severity=Severity.INFO,
    confidence=Confidence.MEDIUM,
    description="Keys outside the recognised set may be ignored by the loader or may hide security-relevant intent.",
    remediation="Document custom keys or remove them; enforce an allowlist in the loader.",
    tags=("metadata",),
    no_context=True,
    check=check_unknown_keys,
)
_rule(RULE_UNKNOWN_KEYS)

RULE_UNKNOWN_INTENT = Rule(
    id="AST04-UNKNOWN-INTENT",
    ast="AST04",
    title="Unknown declared intent",
    severity=Severity.LOW,
    confidence=Confidence.HIGH,
    description="metadata.skilltriage.intent is not a recognised value. The declaration is reported but never honoured.",
    remediation="Use one of: " + ", ".join(INTENT_VALUES) + ".",
    tags=("metadata", "intent"),
    no_context=True,
    check=check_unknown_intent,
)
_rule(RULE_UNKNOWN_INTENT)

_RULE_BY_ISSUE = {
    "UNSAFE_YAML_TAG": RULE_UNSAFE_YAML_TAG,
    "YAML_ANCHOR_ALIAS": RULE_YAML_ANCHOR,
    "DUPLICATE_KEY": RULE_DUPLICATE_KEY,
    "MISSING_CLOSING_FRONTMATTER": RULE_MALFORMED_METADATA,
    "TAB_INDENT": RULE_MALFORMED_METADATA,
    "BAD_INDENT": RULE_MALFORMED_METADATA,
    "BAD_LINE": RULE_MALFORMED_METADATA,
    "UNCLOSED_QUOTE": RULE_MALFORMED_METADATA,
    "UNCLOSED_FLOW": RULE_MALFORMED_METADATA,
    "TRAILING_CONTENT": RULE_MALFORMED_METADATA,
    "TOP_LEVEL_NOT_MAPPING": RULE_MALFORMED_METADATA,
    "INVALID_JSON": RULE_MALFORMED_METADATA,
    "INVALID_TOML": RULE_MALFORMED_METADATA,
    "TOO_DEEP": RULE_MALFORMED_METADATA,
    "OVERSIZED_VALUE": RULE_MALFORMED_METADATA,
    "FRONTMATTER_TOO_LONG": RULE_MALFORMED_METADATA,
}

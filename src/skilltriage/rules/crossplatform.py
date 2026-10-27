"""Cross-platform metadata consistency rules (AST10)."""

from __future__ import annotations

from typing import Any

from ..models import Confidence, Severity
from ..normalize import SKILL_MANIFESTS, normalize_permissions
from .base import Rule, RuleContext

RULES: list[Rule] = []

_UNIVERSAL_PATHS = {
    "skill.yaml",
    "skill.yml",
    "SKILL.yaml",
    "SKILL.yml",
    "agent-skill.yaml",
    "agent-skill.yml",
    "agent-skill.json",
}
_SECURITY_PROPS = (
    "risk_tier",
    "signature",
    "content_hash",
    "permissions_declared",
    "shell",
    "network",
    "network_allow",
    "files_write",
)


def _props(manifest) -> dict[str, Any] | None:
    data = manifest.data
    if not isinstance(data, dict):
        return None
    metadata = data.get("metadata") if isinstance(data.get("metadata"), dict) else {}
    has_permissions = any(key in data for key in ("permissions", "allowed-tools", "allowed_tools"))
    permissions = (
        normalize_permissions(
            data.get("permissions"),
            data.get("allowed-tools", data.get("allowed_tools")),
        )
        if has_permissions
        else None
    )
    return {
        "risk_tier": str(data.get("risk_tier") or data.get("risk-tier") or metadata.get("risk_tier") or ""),
        "signature": str(data.get("signature") or metadata.get("signature") or ""),
        "content_hash": str(
            data.get("content_hash") or data.get("contentHash") or metadata.get("content_hash") or ""
        ),
        "permissions_declared": permissions.declared if permissions else False,
        "shell": permissions.shell if permissions else None,
        "network": permissions.network if permissions else None,
        "network_allow": tuple(permissions.network_allow) if permissions else (),
        "files_write": tuple(permissions.files_write) if permissions else (),
    }


def _present(value: Any) -> bool:
    if value is None:
        return False
    if isinstance(value, (str, tuple, list, dict)):
        return bool(value)
    return bool(value)


def _skill_manifests(ctx: RuleContext):
    return [m for m in ctx.skill.manifests if m.path in SKILL_MANIFESTS and m.data]


def check_multiple_manifests(ctx: RuleContext) -> None:
    manifests = _skill_manifests(ctx)
    if len(manifests) > 1:
        ctx.emit(
            RULE_MULTIPLE_MANIFESTS,
            path=".",
            message="Multiple skill manifests are present.",
            evidence=", ".join(m.path for m in manifests),
            context=False,
        )


def check_property_loss(ctx: RuleContext) -> None:
    manifests = _skill_manifests(ctx)
    if len(manifests) < 2:
        return
    props = {manifest.path: _props(manifest) for manifest in manifests}
    for prop in _SECURITY_PROPS:
        present = [(path, values[prop]) for path, values in props.items() if values and _present(values[prop])]
        absent = [path for path, values in props.items() if not values or not _present(values[prop])]
        if present and absent:
            ctx.emit(
                RULE_PROPERTY_LOSS,
                path=".",
                message=f"Security property {prop!r} is declared in some manifests but not others.",
                evidence=f"present in {', '.join(path for path, _ in present)}; absent in {', '.join(absent)}",
                context=False,
            )
        distinct = {str(value) for _, value in present}
        if len(distinct) > 1:
            ctx.emit(
                RULE_INCONSISTENT_PERMISSIONS,
                path=".",
                message=f"Security property {prop!r} differs between platform manifests.",
                evidence="; ".join(f"{path}={value}" for path, value in present),
                context=False,
            )


def check_universal_format(ctx: RuleContext) -> None:
    paths = {manifest.path for manifest in ctx.skill.manifests}
    if not paths & _UNIVERSAL_PATHS:
        ctx.emit(
            RULE_NO_UNIVERSAL,
            path=".",
            message="No universal skill manifest is present.",
            evidence="expected one of: " + ", ".join(sorted(_UNIVERSAL_PATHS)),
            context=False,
        )


RULE_MULTIPLE_MANIFESTS = Rule(
    id="AST10-MULTIPLE-MANIFESTS",
    ast="AST10",
    title="Multiple platform manifests",
    severity=Severity.INFO,
    confidence=Confidence.HIGH,
    description="When several manifests describe one skill, their security properties can diverge during porting.",
    remediation="Compare permissions, risk tier, signature, and content hash across every manifest.",
    tags=("cross-platform",),
    no_context=True,
    check=check_multiple_manifests,
)
RULES.append(RULE_MULTIPLE_MANIFESTS)

RULE_PROPERTY_LOSS = Rule(
    id="AST10-PROPERTY-LOSS",
    ast="AST10",
    title="Security property lost across manifests",
    severity=Severity.HIGH,
    confidence=Confidence.MEDIUM,
    description="A security control declared in one platform format and absent in another is silently dropped when the skill is ported.",
    remediation="Normalise risk tier, permissions, signature, and content hash across all manifests and validate every target.",
    cwes=("CWE-345",),
    tags=("cross-platform", "metadata"),
    no_context=True,
    check=check_property_loss,
)
RULES.append(RULE_PROPERTY_LOSS)

RULE_INCONSISTENT_PERMISSIONS = Rule(
    id="AST10-INCONSISTENT-PERMISSIONS",
    ast="AST10",
    title="Security properties differ between manifests",
    severity=Severity.MEDIUM,
    confidence=Confidence.HIGH,
    description="Two platform manifests declare different values for the same security property, so the effective policy depends on which loader runs.",
    remediation="Make the declarations identical or generate both from one canonical manifest.",
    cwes=("CWE-436",),
    tags=("cross-platform", "metadata"),
    no_context=True,
    check=check_property_loss,
)
RULES.append(RULE_INCONSISTENT_PERMISSIONS)

RULE_NO_UNIVERSAL = Rule(
    id="AST10-NO-UNIVERSAL-FORMAT",
    ast="AST10",
    title="No universal skill manifest",
    severity=Severity.INFO,
    confidence=Confidence.HIGH,
    description="Without a normalised manifest, the organisation cannot apply one policy across platforms.",
    remediation="Adopt the OWASP Universal Agentic Skill Format or an equivalent canonical manifest.",
    tags=("cross-platform",),
    no_context=True,
    check=check_universal_format,
)
RULES.append(RULE_NO_UNIVERSAL)

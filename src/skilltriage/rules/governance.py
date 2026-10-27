"""Governance metadata rules (AST09)."""

from __future__ import annotations

import re

from ..models import Confidence, Severity
from .base import Rule, RuleContext

RULES: list[Rule] = []

_AUDIT_RE = re.compile(r"(?i)\b(?:audit|logging|telemetry|execution receipt|receipt|trace)\b")


def _primary_path(ctx: RuleContext) -> str:
    return ctx.primary_path


def _metadata_keys(ctx: RuleContext) -> set[str]:
    keys: set[str] = set()
    for manifest in ctx.skill.manifests:
        if isinstance(manifest.data, dict):
            keys.update(manifest.data.keys())
            metadata = manifest.data.get("metadata")
            if isinstance(metadata, dict):
                keys.update(metadata.keys())
    return keys


def check_risk_tier(ctx: RuleContext) -> None:
    if not ctx.skill.risk_tier:
        ctx.emit(
            RULE_NO_RISK_TIER,
            path=_primary_path(ctx),
            message="No risk tier is assigned.",
            evidence="risk_tier: absent",
            context=False,
        )


def check_owner(ctx: RuleContext) -> None:
    if not ctx.skill.author:
        ctx.emit(
            RULE_NO_OWNER,
            path=_primary_path(ctx),
            message="No owner or author identity is recorded.",
            evidence="author: absent",
            context=False,
        )


def check_approval(ctx: RuleContext) -> None:
    keys = _metadata_keys(ctx)
    approval_keys = {"approval", "approved_by", "approved-by", "reviewed_by", "reviewed-by", "owner"}
    if not (keys & approval_keys):
        ctx.emit(
            RULE_NO_APPROVAL,
            path=_primary_path(ctx),
            message="No approval or review record is present in metadata.",
            evidence="approval fields: absent",
            context=False,
        )


def check_audit_logging(ctx: RuleContext) -> None:
    path = ctx.primary_path
    text = ctx.text(path)
    if ctx.is_plugin:
        text += "\n" + ctx.text("README.md")
    if not _AUDIT_RE.search(text):
        ctx.emit(
            RULE_NO_AUDIT_LOG,
            path=path,
            message="The skill does not describe audit logging or execution receipts.",
            evidence="audit/logging terms: absent",
            context=False,
        )


def check_scan_status(ctx: RuleContext) -> None:
    if not ctx.skill.scan_status:
        ctx.emit(
            RULE_NO_SCAN_STATUS,
            path=_primary_path(ctx),
            message="No prior scan status is recorded.",
            evidence="scan_status: absent",
            context=False,
        )


RULE_NO_RISK_TIER = Rule(
    id="AST09-NO-RISK-TIER",
    ast="AST09",
    title="No risk tier",
    severity=Severity.LOW,
    confidence=Confidence.HIGH,
    description="Without a risk tier, approval cadence, review depth, and revocation policy cannot be tied to the skill's blast radius.",
    remediation="Assign L0-L3 consistently with the permission manifest and record it in inventory.",
    tags=("governance",),
    no_context=True,
    check=check_risk_tier,
)
RULES.append(RULE_NO_RISK_TIER)

RULE_NO_OWNER = Rule(
    id="AST09-NO-OWNER",
    ast="AST09",
    title="No owner identity",
    severity=Severity.LOW,
    confidence=Confidence.HIGH,
    description="An unowned skill cannot be reviewed, contacted, or deprovisioned when its installer leaves.",
    remediation="Record the publisher and internal owner in metadata and inventory.",
    tags=("governance",),
    no_context=True,
    check=check_owner,
)
RULES.append(RULE_NO_OWNER)

RULE_NO_APPROVAL = Rule(
    id="AST09-NO-APPROVAL",
    ast="AST09",
    title="No approval record",
    severity=Severity.LOW,
    confidence=Confidence.MEDIUM,
    description="There is no evidence that the skill passed an approval workflow before installation.",
    remediation="Require an approval record with approver identity and date, especially for high-risk tiers.",
    tags=("governance",),
    no_context=True,
    check=check_approval,
)
RULES.append(RULE_NO_APPROVAL)

RULE_NO_AUDIT_LOG = Rule(
    id="AST09-NO-AUDIT-LOG",
    ast="AST09",
    title="No audit logging described",
    severity=Severity.INFO,
    confidence=Confidence.LOW,
    description="Without execution logging or receipts, an incident cannot be reconstructed from the skill's own records.",
    remediation="Document the audit events the skill emits and retain them with tamper-evident identifiers.",
    tags=("governance",),
    no_context=True,
    check=check_audit_logging,
)
RULES.append(RULE_NO_AUDIT_LOG)

RULE_NO_SCAN_STATUS = Rule(
    id="AST09-NO-SCAN-STATUS",
    ast="AST09",
    title="No scan status recorded",
    severity=Severity.INFO,
    confidence=Confidence.HIGH,
    description="There is no provenance for the scanner, date, or verdict that last assessed the skill.",
    remediation="Record scanner name, version, scan date, and verdict in metadata.",
    tags=("governance",),
    no_context=True,
    check=check_scan_status,
)
RULES.append(RULE_NO_SCAN_STATUS)

"""Rules emitted by the inventory comparison rather than by file inspection."""

from __future__ import annotations

from ..models import Confidence, Severity
from .base import Rule, RuleContext

RULES: list[Rule] = []


def _noop(ctx: RuleContext) -> None:
    return


RULE_BASELINE_DRIFT = Rule(
    id="AST07-BASELINE-DRIFT",
    ast="AST07",
    title="Installed skill drifted from the recorded hash",
    severity=Severity.HIGH,
    confidence=Confidence.HIGH,
    description="The current package bytes differ from the hash recorded in inventory, so the skill changed after review or installation.",
    remediation="Re-review the new version, verify its signature and scan result, then update the inventory explicitly.",
    cwes=("CWE-1329", "CWE-353"),
    tags=("governance", "update-drift"),
    no_context=True,
    check=_noop,
)
RULES.append(RULE_BASELINE_DRIFT)

RULE_NOT_IN_INVENTORY = Rule(
    id="AST09-NOT-IN-INVENTORY",
    ast="AST09",
    title="Skill is not in the inventory",
    severity=Severity.HIGH,
    confidence=Confidence.HIGH,
    description="An installed skill with no inventory record is invisible to approval, audit, and revocation workflows.",
    remediation="Add the skill to inventory with owner, version, hash, install date, and scan status.",
    tags=("governance",),
    no_context=True,
    check=_noop,
)
RULES.append(RULE_NOT_IN_INVENTORY)

RULE_HASH_MATCHES = Rule(
    id="AST07-INVENTORY-MATCH",
    ast="AST07",
    title="Skill matches the inventory hash",
    severity=Severity.INFO,
    confidence=Confidence.HIGH,
    description="The current package bytes match the last recorded inventory hash.",
    remediation="No action; continue periodic re-scanning.",
    tags=("governance",),
    no_context=True,
    check=_noop,
)
RULES.append(RULE_HASH_MATCHES)

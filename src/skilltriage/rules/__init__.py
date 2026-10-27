"""Rule registry.

Order matters for signal-producing rules: scripts, network, injection, and
obfuscation populate ``ctx.signals`` before the correlation rules run last.
"""

from __future__ import annotations

from . import (
    correlation,
    crossplatform,
    files,
    governance,
    injection,
    inventory,
    isolation,
    network,
    obfuscation,
    permissions,
    plugins,
    provenance,
    python_ast,
    scripts,
    structure,
    supplychain,
)
from .base import Rule, RuleContext, describe_rules, run_rules

ALL_RULES: list[Rule] = [
    *structure.RULES,
    *obfuscation.RULES,
    *files.RULES,
    *scripts.RULES,
    *python_ast.RULES,
    *network.RULES,
    *injection.RULES,
    *supplychain.RULES,
    *provenance.RULES,
    *permissions.RULES,
    *isolation.RULES,
    *governance.RULES,
    *plugins.RULES,
    *crossplatform.RULES,
    *inventory.RULES,
    *correlation.RULES,
]

_RULE_INDEX = {rule.id: rule for rule in ALL_RULES}


def all_rules() -> list[Rule]:
    return list(ALL_RULES)


def get_rule(rule_id: str) -> Rule | None:
    return _RULE_INDEX.get(rule_id)


def rule_ids() -> list[str]:
    return sorted(_RULE_INDEX)


__all__ = [
    "ALL_RULES",
    "Rule",
    "RuleContext",
    "all_rules",
    "describe_rules",
    "get_rule",
    "rule_ids",
    "run_rules",
]

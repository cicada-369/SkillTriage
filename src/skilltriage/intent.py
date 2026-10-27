"""Declared artifact intent.

An artifact may state that offensive tooling is its purpose. A declaration is
attacker-controlled, so it never changes a verdict on its own: policy must
allow the value *and* the artifact must have an inventory record. Every
downgraded finding stays visible.
"""

from __future__ import annotations

from typing import Any

INTENT_VALUES = (
    "offensive-security",
    "security-research",
    "education",
    "detection-engineering",
)

INTENT_KEY = "skilltriage"


def normalize_intent(value: Any) -> str:
    if not isinstance(value, str):
        return ""
    return value.strip().lower()


def extract_declared_intent(metadata: Any) -> tuple[bool, str]:
    """Return ``(declared, value)`` for ``metadata.skilltriage.intent``."""
    if not isinstance(metadata, dict):
        return False, ""
    block = metadata.get(INTENT_KEY)
    if not isinstance(block, dict):
        return False, ""
    if "intent" not in block:
        return False, ""
    return True, normalize_intent(block.get("intent"))

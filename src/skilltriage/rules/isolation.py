"""Network exposure rules (AST06)."""

from __future__ import annotations

import re

from ..models import Confidence, Severity
from ..patterns import BIND_ALL
from .base import Rule, RuleContext

RULES: list[Rule] = []


_BIND_CONTEXT = re.compile(
    r"(?i)\b(?:bind|listen|host|server|serve|uvicorn|gunicorn|flask|app\.run|"
    r"http\.server|websocket|socket|port)\b|:\d{2,5}\b"
)


def check_bind_all(ctx: RuleContext) -> None:
    for record, text in ctx.texts():
        for number, line in enumerate(text.splitlines(), start=1):
            if BIND_ALL.search(line) and _BIND_CONTEXT.search(line):
                finding = ctx.emit(RULE_BIND_ALL, path=record.path, line=number, evidence=line)
                if finding is not None and finding.confidence != Confidence.LOW:
                    ctx.signal("bind_all", f"{record.path}:{number}")


RULE_BIND_ALL = Rule(
    id="AST06-BIND-ALL",
    ast="AST06",
    title="Service bound to all interfaces",
    severity=Severity.MEDIUM,
    confidence=Confidence.MEDIUM,
    description="Binding to 0.0.0.0 exposes the agent's local service to the network, where authentication is often absent.",
    remediation="Bind to 127.0.0.1 and require authentication for any control channel.",
    cwes=("CWE-1327", "CWE-306"),
    tags=("isolation", "network"),
    check=check_bind_all,
)
RULES.append(RULE_BIND_ALL)

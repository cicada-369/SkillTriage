"""Cross-file correlation rules (AST01).

Individual signals are weak; combinations are strong. A credential path in a
document is a reference. A credential path plus an outbound endpoint in the
same package is an exfiltration chain worth blocking.
"""

from __future__ import annotations

import re
from pathlib import Path

from ..models import Confidence, Severity
from ..patterns import CODE_EXTENSIONS
from .base import Rule, RuleContext

RULES: list[Rule] = []

# Structured plugin configuration may participate in a chain. Command and
# agent prose deliberately does not: that would let documentation manufacture
# correlations, and would let one bundled skill's text correlate with another
# component's capability.
_PLUGIN_CONFIG_PATHS = {
    ".mcp.json",
    "hooks/hooks.json",
    ".claude-plugin/plugin.json",
    ".claude-plugin/marketplace.json",
}


def _values(ctx: RuleContext, *kinds: str) -> list[str]:
    """Return relevant signals only.

    Documentation and reference files are reviewed by individual rules, but they
    must not manufacture a correlation: a security guide that mentions both
    ``~/.ssh`` and a webhook is not a credential stealer. Correlations require a
    signal from executable code or from SKILL.md itself.
    """
    values: set[str] = set()
    for kind in kinds:
        for value in ctx.signals.get(kind, set()):
            path = value.rsplit(":", 1)[0] if re.search(r":\d+$", value) else value
            suffix = Path(path).suffix.lower()
            if (
                path == "SKILL.md"
                or suffix in CODE_EXTENSIONS
                or (ctx.is_plugin and path in _PLUGIN_CONFIG_PATHS)
            ):
                values.add(value)
    return sorted(values)


def _evidence(*groups: list[str]) -> str:
    parts: list[str] = []
    for group in groups:
        if group:
            parts.append(", ".join(group[:3]))
    return " | ".join(parts)


def check_exfil_chain(ctx: RuleContext) -> None:
    sensitive = _values(ctx, "sensitive_read")
    exfil = _values(ctx, "exfil_sink")
    external = _values(ctx, "external_host")
    network = _values(ctx, "network")
    secret = _values(ctx, "secret")
    if not sensitive:
        return
    if exfil:
        severity = Severity.CRITICAL if secret else Severity.HIGH
        ctx.emit(
            RULE_EXFIL_CHAIN,
            path=".",
            severity=severity,
            message="Credential access and an exfiltration-friendly endpoint appear in the same skill.",
            evidence=_evidence(sensitive, exfil, secret),
            context=False,
        )
    elif external:
        ctx.emit(
            RULE_EXFIL_CHAIN,
            path=".",
            severity=Severity.HIGH if secret else Severity.MEDIUM,
            message="Credential access and an untrusted external host appear in the same skill.",
            evidence=_evidence(sensitive, external),
            context=False,
        )
    elif network:
        ctx.emit(
            RULE_EXFIL_CHAIN,
            path=".",
            severity=Severity.MEDIUM,
            message="Credential access and network egress appear in the same skill.",
            evidence=_evidence(sensitive, network),
            context=False,
        )


def check_injection_chain(ctx: RuleContext) -> None:
    instruction = _values(ctx, "prompt_injection", "concealment", "tool_override", "exfil_instruction")
    capability = _values(
        ctx,
        "dynamic_exec",
        "download_exec",
        "exfil_sink",
        "external_host",
        "encoded_exec",
    )
    if instruction and capability:
        ctx.emit(
            RULE_INJECTION_CHAIN,
            path=".",
            message="Instruction-manipulation language and an execution or exfiltration capability appear together.",
            evidence=_evidence(instruction, capability),
            context=False,
        )


def check_obfuscation_chain(ctx: RuleContext) -> None:
    obfuscation = _values(ctx, "obfuscation", "encoded_payload", "encoded_exec")
    execution = _values(ctx, "dynamic_exec", "download_exec", "encoded_exec", "reverse_shell")
    if obfuscation and execution:
        ctx.emit(
            RULE_OBFUSCATION_CHAIN,
            path=".",
            message="Obfuscated content and an execution path appear in the same skill.",
            evidence=_evidence(obfuscation, execution),
            context=False,
        )


RULE_EXFIL_CHAIN = Rule(
    id="AST01-EXFIL-CHAIN",
    ast="AST01",
    title="Credential-to-network exfiltration chain",
    severity=Severity.HIGH,
    confidence=Confidence.MEDIUM,
    description="The package combines access to credential stores with an outbound endpoint or untrusted host, which is the shape of a credential stealer.",
    remediation="Block installation until the data flow is explained, minimised, and approved; scope credentials per skill.",
    cwes=("CWE-200", "CWE-522"),
    tags=("correlation", "exfiltration"),
    no_context=True,
    check=check_exfil_chain,
)
RULES.append(RULE_EXFIL_CHAIN)

RULE_INJECTION_CHAIN = Rule(
    id="AST01-INJECTION-CHAIN",
    ast="AST01",
    title="Prompt-manipulation and capability chain",
    severity=Severity.HIGH,
    confidence=Confidence.LOW,
    description="Override or concealment language appears alongside an execution or network capability, the combination a malicious skill needs.",
    remediation="Review the instruction layer manually and remove the capability or the manipulation language.",
    cwes=("CWE-1426",),
    tags=("correlation", "prompt-injection"),
    no_context=True,
    check=check_injection_chain,
)
RULES.append(RULE_INJECTION_CHAIN)

RULE_OBFUSCATION_CHAIN = Rule(
    id="AST01-OBFUSCATION-CHAIN",
    ast="AST01",
    title="Obfuscation and execution chain",
    severity=Severity.HIGH,
    confidence=Confidence.MEDIUM,
    description="Encoded or invisible content is combined with an execution path, which is a common way to hide a payload from review.",
    remediation="Decode and review the content; remove the execution path unless it is essential and explicit.",
    cwes=("CWE-506", "CWE-78"),
    tags=("correlation", "obfuscation"),
    no_context=True,
    check=check_obfuscation_chain,
)
RULES.append(RULE_OBFUSCATION_CHAIN)

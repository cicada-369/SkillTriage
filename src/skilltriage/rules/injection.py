"""Natural-language injection rules (AST01, AST05).

The OWASP AST guidance is explicit that pure prose can carry the payload. These
rules are heuristics for the instruction layer; they are useful triage signals,
not semantic proof.
"""

from __future__ import annotations

from ..models import Confidence, Severity
from ..patterns import (
    CONCEALMENT,
    EXFIL_INSTRUCTION,
    PROMPT_OVERRIDE,
    SOCIAL_ENGINEERING,
    TOOL_OVERRIDE,
)
from .base import Rule, RuleContext

RULES: list[Rule] = []


def _scan_pattern(ctx: RuleContext, rule: Rule, pattern, signal: str) -> None:
    for record, text in ctx.texts():
        for number, line in enumerate(text.splitlines(), start=1):
            if pattern.search(line):
                finding = ctx.emit(rule, path=record.path, line=number, evidence=line)
                if finding is not None and finding.confidence != Confidence.LOW:
                    ctx.signal(signal, f"{record.path}:{number}")


def check_prompt_override(ctx: RuleContext) -> None:
    _scan_pattern(ctx, RULE_PROMPT_OVERRIDE, PROMPT_OVERRIDE, "prompt_injection")


def check_concealment(ctx: RuleContext) -> None:
    _scan_pattern(ctx, RULE_CONCEALMENT, CONCEALMENT, "concealment")


def check_social_engineering(ctx: RuleContext) -> None:
    _scan_pattern(ctx, RULE_SOCIAL_ENGINEERING, SOCIAL_ENGINEERING, "social_engineering")


def check_tool_override(ctx: RuleContext) -> None:
    _scan_pattern(ctx, RULE_TOOL_OVERRIDE, TOOL_OVERRIDE, "tool_override")


def check_exfil_instruction(ctx: RuleContext) -> None:
    _scan_pattern(ctx, RULE_EXFIL_INSTRUCTION, EXFIL_INSTRUCTION, "exfil_instruction")


RULE_PROMPT_OVERRIDE = Rule(
    id="AST01-PROMPT-OVERRIDE",
    ast="AST01",
    title="Instruction-override language",
    severity=Severity.HIGH,
    confidence=Confidence.MEDIUM,
    description="Text that tells the agent to ignore prior instructions or adopt a new system role is a prompt-injection pattern.",
    remediation="Remove the override language and keep a strict instruction hierarchy (system > operator > user > skill output).",
    cwes=("CWE-77", "CWE-1426"),
    tags=("prompt-injection", "prose"),
    check=check_prompt_override,
)
RULES.append(RULE_PROMPT_OVERRIDE)

RULE_CONCEALMENT = Rule(
    id="AST01-CONCEALMENT",
    ast="AST01",
    title="Concealment from the user",
    severity=Severity.HIGH,
    confidence=Confidence.MEDIUM,
    description="Instructions to act silently or hide actions from the user defeat informed consent and are a strong malicious-intent signal.",
    remediation="Remove the concealment language; actions that matter must be visible and reviewable.",
    cwes=("CWE-1426",),
    tags=("prompt-injection", "prose"),
    check=check_concealment,
)
RULES.append(RULE_CONCEALMENT)

RULE_SOCIAL_ENGINEERING = Rule(
    id="AST01-SOCIAL-ENGINEERING",
    ast="AST01",
    title="Social-engineering instruction",
    severity=Severity.MEDIUM,
    confidence=Confidence.MEDIUM,
    description="Instructions to paste commands, disable protections, or accept unsigned content are common skill-delivery techniques.",
    remediation="Remove the instruction; never ask a user to disable a security control to use a skill.",
    cwes=("CWE-1426", "CWE-693"),
    tags=("prompt-injection", "prose"),
    check=check_social_engineering,
)
RULES.append(RULE_SOCIAL_ENGINEERING)

RULE_TOOL_OVERRIDE = Rule(
    id="AST01-TOOL-OVERRIDE",
    ast="AST01",
    title="Permission or approval bypass",
    severity=Severity.HIGH,
    confidence=Confidence.MEDIUM,
    description="Text that tells the agent to bypass permissions, approvals, or guardrails is an attempt to remove the human control point.",
    remediation="Remove the bypass language and require explicit operator consent for privileged actions.",
    cwes=("CWE-1426", "CWE-863"),
    tags=("prompt-injection", "prose"),
    check=check_tool_override,
)
RULES.append(RULE_TOOL_OVERRIDE)

RULE_EXFIL_INSTRUCTION = Rule(
    id="AST01-EXFIL-INSTRUCTION",
    ast="AST01",
    title="Instruction to send data outward",
    severity=Severity.HIGH,
    confidence=Confidence.MEDIUM,
    description="Prose that tells the agent to send files, keys, or environment data to another destination can exfiltrate data without any code signature.",
    remediation="Remove the instruction and treat outbound data flows as an explicit, reviewed capability.",
    cwes=("CWE-200", "CWE-1426"),
    tags=("prompt-injection", "exfiltration", "prose"),
    check=check_exfil_instruction,
)
RULES.append(RULE_EXFIL_INSTRUCTION)

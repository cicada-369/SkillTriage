"""Permission and least-privilege rules (AST03)."""

from __future__ import annotations

import re

from ..models import Confidence, Severity
from ..patterns import (
    CODE_EXTENSIONS,
    CREDENTIAL_ACCESS,
    DESTRUCTIVE,
    DOWNLOAD_EXEC,
    DYNAMIC_EXEC,
    PRIVILEGED_CONTAINER,
    REVERSE_SHELL,
    URL_RE,
)
from .base import Rule, RuleContext

RULES: list[Rule] = []

_IDENTITY_NAMES = {
    "soul.md",
    "memory.md",
    "agents.md",
    "claude.md",
    "gemini.md",
    ".claude/settings.json",
    ".mcp.json",
}
_WILDCARDS = {"*", "**", "/", "~", "$home", "**/*", "/**", "c:/", "c:\\", "*/*"}
_BROAD_TOOLS = {"*", "all", "full_access", "fullaccess", "admin", "unrestricted"}
_NETWORK_CALL_RE = re.compile(
    r"(?i)\b(?:curl|wget|requests\.(?:get|post|put|patch|delete)|urllib\.request|"
    r"urlopen|http\.client|socket\.socket|fetch\s*\(|axios\.|net\.connect|"
    r"Invoke-WebRequest|iwr|https?://)"
)
_WRITE_CODE_RE = re.compile(
    r"(?i)(?:\b(?:write_text|write_bytes|writeFile|writeFileSync|Set-Content|Out-File)\b|"
    r"\bopen\s*\([^)]*['\"]w|(?:>|>>)\s*\S)"
)
_READ_ONLY_CLAIM_RE = re.compile(
    r"(?i)\b(?:read[- ]only|readonly|offline|no\s+network|non[- ]destructive|"
    r"does\s+not\s+write|never\s+writes|no\s+writes)\b"
)


def _primary_path(ctx: RuleContext) -> str:
    return ctx.primary_path


def _is_wildcard(value: str) -> bool:
    lowered = value.strip().lower()
    if lowered in _WILDCARDS:
        return True
    return "**" in lowered or lowered.endswith("/*") or lowered.startswith("/*")


def _identity(value: str) -> bool:
    lowered = value.strip().lower().replace("\\", "/").lstrip("./")
    return any(lowered == name or lowered.endswith("/" + name) for name in _IDENTITY_NAMES)


def _observed_network(ctx: RuleContext) -> str | None:
    for record, text in ctx.texts():
        if record.suffix not in CODE_EXTENSIONS:
            continue
        for number, line in enumerate(text.splitlines(), start=1):
            if _NETWORK_CALL_RE.search(line):
                return f"{record.path}:{number}: {line.strip()[:160]}"
    return None


def _observed_write(ctx: RuleContext) -> str | None:
    for record, text in ctx.texts():
        if record.suffix not in CODE_EXTENSIONS:
            continue
        for number, line in enumerate(text.splitlines(), start=1):
            if _WRITE_CODE_RE.search(line) and not line.lstrip().startswith(("#", "//")):
                return f"{record.path}:{number}: {line.strip()[:160]}"
    return None


def _observed_shell(ctx: RuleContext) -> str | None:
    for record, text in ctx.texts():
        if record.suffix not in CODE_EXTENSIONS:
            continue
        for number, line in enumerate(text.splitlines(), start=1):
            if DYNAMIC_EXEC.search(line) or DOWNLOAD_EXEC.search(line) or REVERSE_SHELL.search(line):
                return f"{record.path}:{number}: {line.strip()[:160]}"
    return None


def check_no_manifest(ctx: RuleContext) -> None:
    # Plugin permissions are declared per component, not in plugin.json.
    if ctx.is_plugin:
        return
    if not ctx.skill.permissions.declared:
        ctx.emit(
            RULE_NO_MANIFEST,
            path=_primary_path(ctx),
            message="No machine-readable permission manifest was declared.",
            evidence="permissions: absent",
            context=False,
        )


def check_shell(ctx: RuleContext) -> None:
    permissions = ctx.skill.permissions
    if permissions.has_shell:
        ctx.emit(
            RULE_SHELL,
            path=_primary_path(ctx),
            message="Skill declares unrestricted shell access.",
            evidence=f"shell: {permissions.shell}",
            context=False,
        )


def check_filesystem(ctx: RuleContext) -> None:
    permissions = ctx.skill.permissions
    for kind, paths in (("read", permissions.files_read), ("write", permissions.files_write)):
        for value in paths:
            if _is_wildcard(value):
                ctx.emit(
                    RULE_FS_WILDCARD,
                    path=_primary_path(ctx),
                    message=f"Permission grants a broad filesystem {kind} scope.",
                    evidence=f"{kind}: {value}",
                    context=False,
                )


def check_network(ctx: RuleContext) -> None:
    permissions = ctx.skill.permissions
    allow = [value for value in permissions.network_allow if value.strip()]
    if permissions.network is True and not allow:
        ctx.emit(
            RULE_NETWORK_OPEN,
            path=_primary_path(ctx),
            message="Network access is enabled without a domain allowlist.",
            evidence="network: true",
            context=False,
        )
    if allow and any(_is_wildcard(value) or value.strip() == "*" for value in allow):
        ctx.emit(
            RULE_NETWORK_OPEN,
            path=_primary_path(ctx),
            message="Network allowlist contains a wildcard.",
            evidence=f"network.allow: {allow}",
            context=False,
        )
    if allow and permissions.network_deny not in ("*", ["*"]):
        ctx.emit(
            RULE_NETWORK_OPEN,
            path=_primary_path(ctx),
            message="Network allowlist is present but default-deny is not set.",
            evidence=f"network.deny: {permissions.network_deny!r}",
            context=False,
        )


def check_identity_permissions(ctx: RuleContext) -> None:
    permissions = ctx.skill.permissions
    for value in permissions.files_write:
        if _identity(value):
            ctx.emit(
                RULE_IDENTITY_PERMISSION,
                path=_primary_path(ctx),
                message="Permission manifest grants write access to an agent identity file.",
                evidence=f"write: {value}",
                context=False,
            )


def check_credential_paths(ctx: RuleContext) -> None:
    permissions = ctx.skill.permissions
    for kind, paths in (("read", permissions.files_read), ("write", permissions.files_write)):
        for value in paths:
            if CREDENTIAL_ACCESS.search(value):
                ctx.emit(
                    RULE_CREDENTIAL_PATH,
                    path=_primary_path(ctx),
                    message=f"Permission manifest grants access to a credential store ({kind}).",
                    evidence=f"{kind}: {value}",
                    context=False,
                )


def check_tools(ctx: RuleContext) -> None:
    for tool in ctx.skill.permissions.tools:
        if tool.strip().lower() in _BROAD_TOOLS:
            ctx.emit(
                RULE_BROAD_TOOLS,
                path=_primary_path(ctx),
                message="Skill requests a broad or wildcard tool grant.",
                evidence=f"tools: {tool}",
                context=False,
            )


def check_risk_tier(ctx: RuleContext) -> None:
    tier = ctx.skill.risk_tier
    permissions = ctx.skill.permissions
    if tier not in ("L0", "L1"):
        return
    reasons: list[str] = []
    if tier == "L0":
        # L0 is the "no capability" tier.
        if permissions.has_shell:
            reasons.append("shell")
        if permissions.allows_network:
            reasons.append("network")
        if permissions.files_write:
            reasons.append("write")
        if permissions.files_read:
            reasons.append("read")
    else:
        # L1 may use scoped paths and an explicit network allowlist, but not
        # unrestricted shell, open egress, identity writes, wildcards, or
        # system paths.
        if permissions.has_shell:
            reasons.append("shell")
        if permissions.network is True and not permissions.network_allow:
            reasons.append("unrestricted-network")
        if any(_identity(value) for value in permissions.files_write):
            reasons.append("identity-write")
        if any(_is_wildcard(value) for value in permissions.files_write):
            reasons.append("wildcard-write")
        if any(
            value.strip().lower().startswith(("/etc", "/usr", "/bin", "/sbin", "/var", "/boot"))
            for value in permissions.files_write
        ):
            reasons.append("system-write")
    if reasons:
        ctx.emit(
            RULE_RISK_TIER,
            path=_primary_path(ctx),
            message=f"Risk tier {tier} is inconsistent with declared capabilities.",
            evidence=f"risk_tier: {tier}; capabilities: {', '.join(reasons)}",
            context=False,
        )


def check_declared_vs_observed(ctx: RuleContext) -> None:
    permissions = ctx.skill.permissions
    description = ctx.skill.description or ""
    observed_network = _observed_network(ctx)
    observed_write = _observed_write(ctx)
    observed_shell = _observed_shell(ctx)

    if _READ_ONLY_CLAIM_RE.search(description):
        evidence = observed_network or observed_write
        if evidence:
            ctx.emit(
                RULE_DECLARED_VS_OBSERVED,
                path=_primary_path(ctx),
                message="Description claims read-only or offline behaviour but code shows otherwise.",
                evidence=evidence,
                context=False,
            )
            return

    if permissions.declared and permissions.network is False and not permissions.network_allow:
        if observed_network:
            ctx.emit(
                RULE_DECLARED_VS_OBSERVED,
                path=_primary_path(ctx),
                message="Manifest disables network access but code performs network operations.",
                evidence=observed_network,
                context=False,
            )
            return

    if permissions.declared and permissions.shell is False and observed_shell:
        ctx.emit(
            RULE_DECLARED_VS_OBSERVED,
            path=_primary_path(ctx),
            message="Manifest disables shell access but code executes shell commands.",
            evidence=observed_shell,
            context=False,
        )


RULE_NO_MANIFEST = Rule(
    id="AST03-NO-PERMISSION-MANIFEST",
    ast="AST03",
    title="No permission manifest",
    severity=Severity.MEDIUM,
    confidence=Confidence.HIGH,
    description="Without a declared permission manifest, the skill inherits the agent's full file, shell, and network access.",
    remediation="Declare scoped permissions (files, network, shell, tools) and enforce them at runtime.",
    cwes=("CWE-250",),
    tags=("permissions",),
    no_context=True,
    check=check_no_manifest,
)
RULES.append(RULE_NO_MANIFEST)

RULE_SHELL = Rule(
    id="AST03-SHELL-UNRESTRICTED",
    ast="AST03",
    title="Unrestricted shell access",
    severity=Severity.HIGH,
    confidence=Confidence.HIGH,
    description="shell: true gives every downstream prompt injection a command execution primitive.",
    remediation="Set shell to false or scope it to an explicit command allowlist.",
    cwes=("CWE-250", "CWE-78"),
    tags=("permissions",),
    no_context=True,
    check=check_shell,
)
RULES.append(RULE_SHELL)

RULE_FS_WILDCARD = Rule(
    id="AST03-FILESYSTEM-WILDCARD",
    ast="AST03",
    title="Broad filesystem permission",
    severity=Severity.HIGH,
    confidence=Confidence.HIGH,
    description="Wildcard filesystem access exposes unrelated files, including credentials and identity artifacts.",
    remediation="List explicit paths and keep write scopes minimal.",
    cwes=("CWE-250", "CWE-732"),
    tags=("permissions",),
    no_context=True,
    check=check_filesystem,
)
RULES.append(RULE_FS_WILDCARD)

RULE_NETWORK_OPEN = Rule(
    id="AST03-NETWORK-OPEN",
    ast="AST03",
    title="Open or under-scoped network permission",
    severity=Severity.MEDIUM,
    confidence=Confidence.HIGH,
    description="A binary network flag has no egress boundary; a wildcard or missing default-deny defeats an allowlist.",
    remediation="Use a domain allowlist with default-deny and document each destination.",
    cwes=("CWE-250", "CWE-183"),
    tags=("permissions", "network"),
    no_context=True,
    check=check_network,
)
RULES.append(RULE_NETWORK_OPEN)

RULE_IDENTITY_PERMISSION = Rule(
    id="AST03-IDENTITY-WRITE-PERMISSION",
    ast="AST03",
    title="Permission to write identity files",
    severity=Severity.CRITICAL,
    confidence=Confidence.HIGH,
    description="Write access to SOUL.md, MEMORY.md, or equivalent lets a skill plant persistent instructions that survive uninstall.",
    remediation="Deny writes to identity files in the manifest and require explicit operator approval for persistent state.",
    cwes=("CWE-732", "CWE-506"),
    tags=("permissions", "identity"),
    no_context=True,
    check=check_identity_permissions,
)
RULES.append(RULE_IDENTITY_PERMISSION)

RULE_CREDENTIAL_PATH = Rule(
    id="AST03-CREDENTIAL-PATHS",
    ast="AST03",
    title="Permission to access credential stores",
    severity=Severity.HIGH,
    confidence=Confidence.HIGH,
    description="Broad read or write access to SSH, cloud, wallet, and browser credential paths exceeds most skill functions.",
    remediation="Remove the credential path or replace it with a per-skill scoped credential.",
    cwes=("CWE-522", "CWE-250"),
    tags=("permissions", "credentials"),
    no_context=True,
    check=check_credential_paths,
)
RULES.append(RULE_CREDENTIAL_PATH)

RULE_BROAD_TOOLS = Rule(
    id="AST03-BROAD-TOOLS",
    ast="AST03",
    title="Broad tool grant",
    severity=Severity.MEDIUM,
    confidence=Confidence.HIGH,
    description="A wildcard or admin tool grant gives the skill far more capability than its stated function requires.",
    remediation="Enumerate only the tools the skill needs.",
    cwes=("CWE-250",),
    tags=("permissions",),
    no_context=True,
    check=check_tools,
)
RULES.append(RULE_BROAD_TOOLS)

RULE_RISK_TIER = Rule(
    id="AST03-RISK-TIER-MISMATCH",
    ast="AST03",
    title="Risk tier inconsistent with capabilities",
    severity=Severity.HIGH,
    confidence=Confidence.HIGH,
    description="Declaring L0/L1 (safe) while requesting shell, network, write, or identity access understates the blast radius.",
    remediation="Assign the tier that matches the actual permission scope and re-review it.",
    cwes=("CWE-345",),
    tags=("permissions", "metadata"),
    no_context=True,
    check=check_risk_tier,
)
RULES.append(RULE_RISK_TIER)

RULE_DECLARED_VS_OBSERVED = Rule(
    id="AST03-DECLARED-VS-OBSERVED",
    ast="AST03",
    title="Declared permissions contradict observed behaviour",
    severity=Severity.MEDIUM,
    confidence=Confidence.HIGH,
    description="A manifest or description that understates observed network, write, or shell behaviour is a classic permission-understating attack.",
    remediation="Align the manifest and description with the code, or remove the undeclared behaviour.",
    cwes=("CWE-345", "CWE-250"),
    tags=("permissions", "metadata"),
    no_context=True,
    check=check_declared_vs_observed,
)
RULES.append(RULE_DECLARED_VS_OBSERVED)

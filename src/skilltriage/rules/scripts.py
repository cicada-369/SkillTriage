"""Shell, command, and credential rules (AST01, AST03, AST06).

These rules run over every text file. Context scoring downgrades matches in
documentation, warning sentences, and comments, but never hides them.
"""

from __future__ import annotations

import re
from collections.abc import Callable

from ..models import Confidence, Severity
from ..patterns import (
    CREDENTIAL_ACCESS,
    DATA_URI_RE,
    DISABLE_SECURITY,
    DOWNLOAD_EXEC,
    DYNAMIC_EXEC,
    EXFIL_SINK,
    IDENTITY_ACCESS,
    IDENTITY_WRITE_OP,
    IDENTITY_WRITE_PROSE,
    PERSISTENCE,
    PRIVILEGED_CONTAINER,
    REVERSE_SHELL,
    SSH_REMOTE,
    DESTRUCTIVE,
)
from ..secrets import find_secrets
from .base import Rule, RuleContext

RULES: list[Rule] = []


def _scan(
    ctx: RuleContext,
    rule: Rule,
    pattern,
    *,
    signal: str | None = None,
    skip: Callable[[str], bool] | None = None,
) -> None:
    for record, text in ctx.texts():
        for number, line in enumerate(text.splitlines(), start=1):
            if skip and skip(line):
                continue
            if ctx.in_frontmatter(record.path, number):
                continue
            if pattern.search(line):
                finding = ctx.emit(rule, path=record.path, line=number, evidence=line)
                if signal and finding is not None and finding.confidence != Confidence.LOW:
                    ctx.signal(signal, f"{record.path}:{number}")


def check_download_exec(ctx: RuleContext) -> None:
    _scan(ctx, RULE_DOWNLOAD_EXEC, DOWNLOAD_EXEC, signal="download_exec")


def check_reverse_shell(ctx: RuleContext) -> None:
    _scan(ctx, RULE_REVERSE_SHELL, REVERSE_SHELL, signal="reverse_shell")


def check_destructive(ctx: RuleContext) -> None:
    _scan(ctx, RULE_DESTRUCTIVE, DESTRUCTIVE, signal="destructive")


def check_persistence(ctx: RuleContext) -> None:
    _scan(ctx, RULE_PERSISTENCE, PERSISTENCE, signal="persistence")


def check_identity_write(ctx: RuleContext) -> None:
    for record, text in ctx.texts():
        for number, line in enumerate(text.splitlines(), start=1):
            if ctx.in_frontmatter(record.path, number):
                continue
            if IDENTITY_WRITE_OP.search(line):
                rule = RULE_IDENTITY_WRITE
            elif IDENTITY_WRITE_PROSE.search(line):
                rule = RULE_IDENTITY_MENTION
            else:
                continue
            finding = ctx.emit(rule, path=record.path, line=number, evidence=line)
            if finding is not None and finding.confidence != Confidence.LOW:
                ctx.signal("identity_write", f"{record.path}:{number}")


def check_identity_access(ctx: RuleContext) -> None:
    for record, text in ctx.texts():
        for number, line in enumerate(text.splitlines(), start=1):
            if ctx.in_frontmatter(record.path, number):
                continue
            if IDENTITY_ACCESS.search(line) and not (
                IDENTITY_WRITE_OP.search(line) or IDENTITY_WRITE_PROSE.search(line)
            ):
                finding = ctx.emit(RULE_IDENTITY_ACCESS, path=record.path, line=number, evidence=line)
                if finding is not None and finding.confidence != Confidence.LOW:
                    ctx.signal("identity_access", f"{record.path}:{number}")


def check_credential_access(ctx: RuleContext) -> None:
    _scan(ctx, RULE_CREDENTIAL_ACCESS, CREDENTIAL_ACCESS, signal="sensitive_read")


_TEMPLATED_CREDENTIAL_RE = re.compile(
    r"\$\{?[A-Za-z_][A-Za-z0-9_]*\}?|\{[A-Za-z_][A-Za-z0-9_]*\}"
)


def check_exfil_sink(ctx: RuleContext) -> None:
    """Flag known exfiltration hosts, but not configured API endpoints."""
    for record, text in ctx.texts():
        for number, line in enumerate(text.splitlines(), start=1):
            if not EXFIL_SINK.search(line):
                continue
            templated = bool(_TEMPLATED_CREDENTIAL_RE.search(line))
            finding = ctx.emit(
                RULE_EXFIL_SINK,
                path=record.path,
                line=number,
                evidence=line,
                severity=Severity.MEDIUM if templated else None,
                confidence=Confidence.MEDIUM if templated else None,
            )
            if finding is not None and finding.confidence != Confidence.LOW:
                ctx.signal("exfil_sink", f"{record.path}:{number}")


def check_dynamic_exec(ctx: RuleContext) -> None:
    _scan(ctx, RULE_DYNAMIC_EXEC, DYNAMIC_EXEC, signal="dynamic_exec")


def check_privileged_container(ctx: RuleContext) -> None:
    _scan(ctx, RULE_PRIVILEGED_CONTAINER, PRIVILEGED_CONTAINER, signal="privileged_container")


def check_disable_security(ctx: RuleContext) -> None:
    _scan(ctx, RULE_DISABLE_SECURITY, DISABLE_SECURITY, signal="disable_security")


def check_ssh_remote(ctx: RuleContext) -> None:
    _scan(ctx, RULE_SSH_REMOTE, SSH_REMOTE, signal="ssh_remote")


def check_data_uri(ctx: RuleContext) -> None:
    for record, text in ctx.texts():
        for number, line in enumerate(text.splitlines(), start=1):
            if DATA_URI_RE.search(line):
                finding = ctx.emit(RULE_DATA_URI, path=record.path, line=number, evidence=line)
                if finding is not None and finding.confidence != Confidence.LOW:
                    ctx.signal("data_uri", f"{record.path}:{number}")


def check_secrets(ctx: RuleContext) -> None:
    for record, text in ctx.texts():
        for hit in find_secrets(text):
            rule = RULE_PRIVATE_KEY if hit.name == "private-key" else RULE_EMBEDDED_SECRET
            finding = ctx.emit(
                rule,
                path=record.path,
                line=hit.line,
                column=hit.column,
                severity=hit.severity,
                confidence=hit.confidence,
                message=f"Possible {hit.name.replace('-', ' ')} embedded in the skill.",
                evidence=ctx.line_text(text, hit.line),
            )
            if finding is not None and finding.confidence != Confidence.LOW:
                ctx.signal("secret", f"{record.path}:{hit.line}")


RULE_DOWNLOAD_EXEC = Rule(
    id="AST01-DOWNLOAD-EXEC",
    ast="AST01",
    title="Download and execute",
    severity=Severity.CRITICAL,
    confidence=Confidence.HIGH,
    description="Remote content is downloaded and piped into an interpreter, giving the remote host code execution with the agent's permissions.",
    remediation="Download to a file, verify a pinned hash or signature, inspect it, then execute explicitly.",
    cwes=("CWE-494", "CWE-78"),
    tags=("execution", "network"),
    intent_family="offensive-security",
    check=check_download_exec,
)
RULES.append(RULE_DOWNLOAD_EXEC)

RULE_REVERSE_SHELL = Rule(
    id="AST01-REVERSE-SHELL",
    ast="AST01",
    title="Reverse shell or remote control pattern",
    severity=Severity.CRITICAL,
    confidence=Confidence.HIGH,
    description="The pattern resembles a reverse shell, interactive remote session, or socket-based command channel.",
    remediation="Remove it; a skill should not open interactive control channels.",
    cwes=("CWE-78", "CWE-306"),
    tags=("execution",),
    intent_family="offensive-security",
    check=check_reverse_shell,
)
RULES.append(RULE_REVERSE_SHELL)

RULE_DESTRUCTIVE = Rule(
    id="AST01-DESTRUCTIVE-COMMAND",
    ast="AST01",
    title="Destructive command",
    severity=Severity.HIGH,
    confidence=Confidence.HIGH,
    description="A command can destroy data, storage, or infrastructure. A prompt injection into an over-privileged skill can trigger it.",
    remediation="Remove it, require explicit human approval, and provide a dry-run and rollback path.",
    cwes=("CWE-78",),
    tags=("execution", "destructive"),
    check=check_destructive,
)
RULES.append(RULE_DESTRUCTIVE)

RULE_PERSISTENCE = Rule(
    id="AST01-PERSISTENCE",
    ast="AST01",
    title="Persistence mechanism",
    severity=Severity.HIGH,
    confidence=Confidence.HIGH,
    description="Cron, shell startup files, services, launch agents, and registry keys let behaviour survive uninstall or restart.",
    remediation="Remove persistence; a skill should not install itself into the host's startup path.",
    cwes=("CWE-506",),
    tags=("execution", "persistence"),
    check=check_persistence,
)
RULES.append(RULE_PERSISTENCE)

RULE_IDENTITY_WRITE = Rule(
    id="AST03-IDENTITY-WRITE",
    ast="AST03",
    title="Write to agent identity file",
    severity=Severity.CRITICAL,
    confidence=Confidence.HIGH,
    description="Writing SOUL.md, MEMORY.md, AGENTS.md, or a platform instruction file can plant persistent instructions that outlive the skill.",
    remediation="Do not write identity or instruction files; require explicit operator approval for any persistent state change.",
    cwes=("CWE-506", "CWE-732"),
    tags=("persistence", "identity"),
    check=check_identity_write,
)
RULES.append(RULE_IDENTITY_WRITE)

RULE_IDENTITY_MENTION = Rule(
    id="AST03-IDENTITY-MENTION",
    ast="AST03",
    title="Identity file update language",
    severity=Severity.MEDIUM,
    confidence=Confidence.MEDIUM,
    description="Prose mentions updating an agent identity or instruction file. The write may be the skill's stated function, or it may be a persistence attempt.",
    remediation="Confirm the write is intentional and scoped, and require explicit operator approval for persistent instruction changes.",
    cwes=("CWE-732",),
    tags=("identity", "prose"),
    check=check_identity_write,
)
RULES.append(RULE_IDENTITY_MENTION)

RULE_IDENTITY_ACCESS = Rule(
    id="AST03-IDENTITY-ACCESS",
    ast="AST03",
    title="Agent identity file reference",
    severity=Severity.MEDIUM,
    confidence=Confidence.MEDIUM,
    description="Reading identity artifacts enables cloning or impersonation, and a reference may precede a write the static rules cannot see.",
    remediation="Remove the reference unless reading the file is essential and explicitly authorised.",
    cwes=("CWE-732",),
    tags=("identity",),
    check=check_identity_access,
)
RULES.append(RULE_IDENTITY_ACCESS)

RULE_CREDENTIAL_ACCESS = Rule(
    id="AST01-CREDENTIAL-ACCESS",
    ast="AST01",
    title="Credential store access",
    severity=Severity.MEDIUM,
    confidence=Confidence.MEDIUM,
    description="Paths for SSH keys, cloud credentials, wallet files, browser passwords, and environment secrets are common exfiltration targets.",
    remediation="Remove access unless it is the skill's stated function; scope credentials per skill and never read unrelated stores.",
    cwes=("CWE-522", "CWE-798"),
    tags=("credentials",),
    check=check_credential_access,
)
RULES.append(RULE_CREDENTIAL_ACCESS)

RULE_EXFIL_SINK = Rule(
    id="AST01-EXFIL-SINK",
    ast="AST01",
    title="Exfiltration-friendly endpoint",
    severity=Severity.HIGH,
    confidence=Confidence.HIGH,
    description="Paste sites, webhooks, tunnels, and raw IP endpoints are commonly used to receive stolen data.",
    remediation="Remove the endpoint or document an approved, authenticated destination with data-handling controls.",
    cwes=("CWE-200",),
    tags=("network", "exfiltration"),
    check=check_exfil_sink,
)
RULES.append(RULE_EXFIL_SINK)

RULE_DYNAMIC_EXEC = Rule(
    id="AST01-DYNAMIC-EXEC",
    ast="AST01",
    title="Dynamic code or shell execution",
    severity=Severity.MEDIUM,
    confidence=Confidence.MEDIUM,
    description="eval, exec, os.system, and shell=True hide the executed command from a static reviewer and are injection sinks.",
    remediation="Use parameterised APIs and explicit argument lists; avoid shell interpretation of untrusted input.",
    cwes=("CWE-78", "CWE-95"),
    tags=("execution",),
    intent_family="offensive-security",
    check=check_dynamic_exec,
)
RULES.append(RULE_DYNAMIC_EXEC)

RULE_PRIVILEGED_CONTAINER = Rule(
    id="AST06-PRIVILEGED-CONTAINER",
    ast="AST06",
    title="Privileged or host-mode container",
    severity=Severity.MEDIUM,
    confidence=Confidence.HIGH,
    description="Privileged mode, host networking, host PID/IPC, and root mounts remove the isolation the container is meant to provide.",
    remediation="Drop --privileged, use a private network namespace, and mount only the paths the skill needs.",
    cwes=("CWE-250", "CWE-653"),
    tags=("isolation",),
    intent_family="offensive-security",
    check=check_privileged_container,
)
RULES.append(RULE_PRIVILEGED_CONTAINER)

RULE_DISABLE_SECURITY = Rule(
    id="AST06-DISABLE-SECURITY",
    ast="AST06",
    title="Security control disabled",
    severity=Severity.HIGH,
    confidence=Confidence.HIGH,
    description="Disabling SELinux, AppArmor, the firewall, auditd, or endpoint protection removes the host's containment layer.",
    remediation="Do not disable host security controls; request a narrow, documented exception instead.",
    cwes=("CWE-693",),
    tags=("isolation",),
    check=check_disable_security,
)
RULES.append(RULE_DISABLE_SECURITY)

RULE_SSH_REMOTE = Rule(
    id="AST01-SSH-REMOTE",
    ast="AST01",
    title="Remote SSH or copy operation",
    severity=Severity.MEDIUM,
    confidence=Confidence.MEDIUM,
    description="Interactive SSH and host-key checking disabled can move data or commands to an unverified host.",
    remediation="Use short-lived, scoped credentials and strict host-key verification; document the remote endpoint.",
    cwes=("CWE-295",),
    tags=("network",),
    intent_family="offensive-security",
    check=check_ssh_remote,
)
RULES.append(RULE_SSH_REMOTE)

RULE_DATA_URI = Rule(
    id="AST01-DATA-URI",
    ast="AST01",
    title="Embedded base64 data URI",
    severity=Severity.MEDIUM,
    confidence=Confidence.MEDIUM,
    description="A data URI can carry an encoded script or document that a reviewer will not read as text.",
    remediation="Replace the data URI with a reviewable file, or decode and inspect it.",
    cwes=("CWE-506",),
    tags=("obfuscation",),
    check=check_data_uri,
)
RULES.append(RULE_DATA_URI)

RULE_EMBEDDED_SECRET = Rule(
    id="AST03-EMBEDDED-SECRET",
    ast="AST03",
    title="Embedded credential",
    severity=Severity.HIGH,
    confidence=Confidence.MEDIUM,
    description="A live-looking credential in a skill package is exposed to everyone who can read the package and its history.",
    remediation="Remove the credential, rotate it, and load secrets from a scoped secret manager at runtime.",
    cwes=("CWE-798",),
    tags=("credentials", "secrets"),
    check=check_secrets,
)
RULES.append(RULE_EMBEDDED_SECRET)

RULE_PRIVATE_KEY = Rule(
    id="AST01-PRIVATE-KEY",
    ast="AST01",
    title="Private key material",
    severity=Severity.CRITICAL,
    confidence=Confidence.HIGH,
    description="A private key in the package can authenticate as its owner and is a direct credential compromise.",
    remediation="Remove the key, rotate it, and use a secret manager with scoped access.",
    cwes=("CWE-798",),
    tags=("credentials", "secrets"),
    check=check_secrets,
)
RULES.append(RULE_PRIVATE_KEY)

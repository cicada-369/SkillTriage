"""Core data model for skilltriage.

Everything that crosses a module boundary is defined here so reports, rules,
and the CLI share one shape. Findings are immutable in spirit: rules create
them through :meth:`RuleContext.emit`, which applies context scoring and
redaction before the finding reaches a report.
"""

from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any

SCHEMA_VERSION = "skilltriage/v1"
TOOL_NAME = "skilltriage"

AST_NAMES: dict[str, str] = {
    "AST01": "Malicious Skills",
    "AST02": "Supply Chain Compromise",
    "AST03": "Over-Privileged Skills",
    "AST04": "Insecure Metadata",
    "AST05": "Untrusted External Instructions",
    "AST06": "Weak Isolation",
    "AST07": "Update Drift",
    "AST08": "Poor Scanning",
    "AST09": "No Governance",
    "AST10": "Cross-Platform Reuse",
}

AST_SEVERITY: dict[str, str] = {
    "AST01": "critical",
    "AST02": "critical",
    "AST03": "high",
    "AST04": "high",
    "AST05": "high",
    "AST06": "high",
    "AST07": "medium",
    "AST08": "medium",
    "AST09": "medium",
    "AST10": "medium",
}

OWASP_URL = "https://github.com/OWASP/www-project-agentic-skills-top-10"


class Severity(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"

    @property
    def rank(self) -> int:
        return _SEVERITY_RANK[self]

    def down(self) -> "Severity":
        """Return one severity step lower, clamped at INFO."""
        return _SEVERITY_DOWN[self]

    @classmethod
    def parse(cls, value: str | "Severity" | None, default: "Severity" | None = None) -> "Severity":
        if isinstance(value, Severity):
            return value
        if value is None:
            if default is not None:
                return default
            raise ValueError("severity value is required")
        try:
            return cls(str(value).strip().lower())
        except ValueError as exc:  # pragma: no cover - argparse guards this
            raise ValueError(f"unknown severity: {value!r}") from exc


_SEVERITY_RANK = {
    Severity.CRITICAL: 4,
    Severity.HIGH: 3,
    Severity.MEDIUM: 2,
    Severity.LOW: 1,
    Severity.INFO: 0,
}
_SEVERITY_DOWN = {
    Severity.CRITICAL: Severity.HIGH,
    Severity.HIGH: Severity.MEDIUM,
    Severity.MEDIUM: Severity.LOW,
    Severity.LOW: Severity.INFO,
    Severity.INFO: Severity.INFO,
}


class Confidence(str, Enum):
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"

    @property
    def rank(self) -> int:
        return _CONFIDENCE_RANK[self]

    @classmethod
    def parse(cls, value: str | "Confidence" | None, default: "Confidence" | None = None) -> "Confidence":
        if isinstance(value, Confidence):
            return value
        if value is None:
            if default is not None:
                return default
            raise ValueError("confidence value is required")
        try:
            return cls(str(value).strip().lower())
        except ValueError as exc:  # pragma: no cover - argparse guards this
            raise ValueError(f"unknown confidence: {value!r}") from exc


_CONFIDENCE_RANK = {
    Confidence.HIGH: 3,
    Confidence.MEDIUM: 2,
    Confidence.LOW: 1,
}


def utc_now_iso() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


_WS_RE = re.compile(r"\s+")


def normalise_evidence(evidence: str, limit: int = 240) -> str:
    """Collapse whitespace and truncate evidence for stable fingerprints."""
    text = _WS_RE.sub(" ", evidence or "").strip()
    if len(text) > limit:
        text = text[: limit - 1].rstrip() + "…"
    return text


def make_fingerprint(rule_id: str, path: str, evidence: str) -> str:
    """Line-independent fingerprint used by baselines.

    Line numbers move when a file is edited, so they are deliberately excluded.
    The rule, relative path, and normalised evidence identify the same issue
    across small edits.
    """
    material = "\0".join((rule_id, path, normalise_evidence(evidence)))
    return hashlib.sha256(material.encode("utf-8", "replace")).hexdigest()


@dataclass
class Finding:
    rule_id: str
    ast: str
    severity: Severity
    confidence: Confidence
    path: str
    message: str
    rationale: str = ""
    remediation: str = ""
    line: int | None = None
    column: int | None = None
    evidence: str = ""
    cwes: tuple[str, ...] = ()
    tags: tuple[str, ...] = ()
    context_note: str = ""
    suppressed: bool = False
    baselined: bool = False
    intent_matched: bool = False
    fingerprint: str = ""

    def __post_init__(self) -> None:
        self.path = self.path.replace("\\", "/")
        self.evidence = normalise_evidence(self.evidence)
        if not self.fingerprint:
            self.fingerprint = make_fingerprint(self.rule_id, self.path, self.evidence)

    @property
    def ast_name(self) -> str:
        return AST_NAMES.get(self.ast, "")

    def to_dict(self) -> dict[str, Any]:
        return {
            "rule_id": self.rule_id,
            "ast": self.ast,
            "ast_name": self.ast_name,
            "severity": self.severity.value,
            "confidence": self.confidence.value,
            "path": self.path,
            "line": self.line,
            "column": self.column,
            "message": self.message,
            "evidence": self.evidence,
            "rationale": self.rationale,
            "remediation": self.remediation,
            "context_note": self.context_note,
            "cwes": list(self.cwes),
            "tags": list(self.tags),
            "suppressed": self.suppressed,
            "baselined": self.baselined,
            "intent_matched": self.intent_matched,
            "fingerprint": self.fingerprint,
        }


@dataclass
class ParseIssue:
    code: str
    message: str
    line: int | None = None
    severity: Severity = Severity.MEDIUM

    def to_dict(self) -> dict[str, Any]:
        return {
            "code": self.code,
            "message": self.message,
            "line": self.line,
            "severity": self.severity.value,
        }


@dataclass
class FileRecord:
    path: str
    size: int = 0
    sha256: str = ""
    mode: int = 0o644
    kind: str = "text"  # text | binary | symlink | device | other
    magic: str = ""
    is_symlink: bool = False
    link_target: str = ""
    skipped: str = ""
    truncated: bool = False
    text: str = ""
    error: str = ""

    @property
    def suffix(self) -> str:
        name = self.path.rsplit("/", 1)[-1]
        if "." not in name.lstrip("."):
            return ""
        return "." + name.rsplit(".", 1)[-1].lower()

    @property
    def is_text(self) -> bool:
        return self.kind == "text" and not self.error

    def to_dict(self, include_text: bool = False) -> dict[str, Any]:
        data: dict[str, Any] = {
            "path": self.path,
            "size": self.size,
            "sha256": self.sha256,
            "mode": f"{self.mode:04o}",
            "kind": self.kind,
            "magic": self.magic,
            "is_symlink": self.is_symlink,
            "link_target": self.link_target,
            "truncated": self.truncated,
        }
        if self.skipped:
            data["skipped"] = self.skipped
        if self.error:
            data["error"] = self.error
        if include_text:
            data["text"] = self.text
        return data


def tree_hash(records: list[FileRecord]) -> str:
    """Canonical hash over path, kind, mode, size, status, and content."""
    hasher = hashlib.sha256()
    for record in sorted(records, key=lambda item: item.path):
        hasher.update(record.path.encode("utf-8", "replace"))
        hasher.update(b"\0")
        hasher.update(record.kind.encode("ascii", "replace"))
        hasher.update(b"\0")
        hasher.update(f"{record.mode:04o}".encode("ascii"))
        hasher.update(b"\0")
        hasher.update(str(record.size).encode("ascii"))
        hasher.update(b"\0")
        hasher.update((record.skipped or "").encode("utf-8", "replace"))
        hasher.update(b"\0")
        if record.is_symlink:
            hasher.update(("symlink:" + record.link_target).encode("utf-8", "replace"))
        else:
            hasher.update(record.sha256.encode("ascii", "replace"))
        hasher.update(b"\n")
    return "sha256:" + hasher.hexdigest()


@dataclass
class Permissions:
    declared: bool = False
    shell: bool | str | None = None
    files_read: list[str] = field(default_factory=list)
    files_write: list[str] = field(default_factory=list)
    deny_write: list[str] = field(default_factory=list)
    network: bool | None = None
    network_allow: list[str] = field(default_factory=list)
    network_deny: str | list[str] | None = None
    tools: list[str] = field(default_factory=list)
    raw: Any = None

    @property
    def has_shell(self) -> bool:
        if isinstance(self.shell, str):
            return self.shell.strip().lower() not in ("", "false", "none", "no", "denied")
        return bool(self.shell)

    @property
    def allows_network(self) -> bool:
        if self.network_allow:
            return True
        return self.network is True

    def to_dict(self) -> dict[str, Any]:
        return {
            "declared": self.declared,
            "shell": self.shell,
            "files_read": list(self.files_read),
            "files_write": list(self.files_write),
            "deny_write": list(self.deny_write),
            "network": self.network,
            "network_allow": list(self.network_allow),
            "network_deny": self.network_deny,
            "tools": list(self.tools),
        }


@dataclass
class ManifestRecord:
    path: str
    platform: str
    fmt: str  # yaml | json | toml | markdown
    data: dict[str, Any] = field(default_factory=dict)
    issues: list[ParseIssue] = field(default_factory=list)
    raw_length: int = 0
    has_frontmatter: bool = True
    body_line: int = 1

    def to_dict(self) -> dict[str, Any]:
        return {
            "path": self.path,
            "platform": self.platform,
            "format": self.fmt,
            "issues": [i.to_dict() for i in self.issues],
            "keys": sorted(self.data.keys()) if isinstance(self.data, dict) else [],
        }


@dataclass
class NormalizedSkill:
    name: str = ""
    version: str = ""
    description: str = ""
    author: str = ""
    license: str = ""
    platforms: list[str] = field(default_factory=list)
    risk_tier: str = ""
    signature: str = ""
    content_hash: str = ""
    scan_status: Any = None
    permissions: Permissions = field(default_factory=Permissions)
    manifests: list[ManifestRecord] = field(default_factory=list)
    requires: Any = None
    metadata: dict[str, Any] = field(default_factory=dict)
    unknown_keys: list[str] = field(default_factory=list)
    plugin_name: str = ""
    plugin_version: str = ""
    declared_intent: str = ""
    intent_declared: bool = False

    def to_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "version": self.version,
            "description": self.description,
            "author": self.author,
            "license": self.license,
            "platforms": list(self.platforms),
            "risk_tier": self.risk_tier,
            "has_signature": bool(self.signature),
            "content_hash": self.content_hash,
            "scan_status": self.scan_status,
            "permissions": self.permissions.to_dict(),
            "manifests": [m.to_dict() for m in self.manifests],
            "plugin": {"name": self.plugin_name, "version": self.plugin_version},
            "unknown_keys": list(self.unknown_keys),
            "declared_intent": self.declared_intent,
            "intent_declared": self.intent_declared,
        }


@dataclass
class PluginComponent:
    kind: str  # command | agent | skill
    name: str
    path: str
    declared: bool = False
    allowed_tools: tuple[str, ...] = ()
    model: str = ""
    frontmatter: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        from .safety import escape_unsafe
        from .secrets import redact

        def safe(value: Any) -> str:
            return escape_unsafe(redact(str(value or "")))

        return {
            "kind": self.kind,
            "name": safe(self.name),
            "path": safe(self.path),
            "declared": self.declared,
            "allowed_tools": [safe(tool) for tool in self.allowed_tools],
            "model": safe(self.model),
            "frontmatter_keys": sorted(safe(key) for key in self.frontmatter.keys()),
        }


@dataclass
class HookEvent:
    event: str
    matcher: str = ""
    type: str = "command"
    command: str = ""
    timeout: int | None = None
    is_async: bool = False
    condition: str = ""

    def to_dict(self) -> dict[str, Any]:
        from .safety import escape_unsafe
        from .secrets import redact

        return {
            "event": escape_unsafe(self.event),
            "matcher": escape_unsafe(self.matcher),
            "type": escape_unsafe(self.type),
            "command": escape_unsafe(redact(self.command)),
            "timeout": self.timeout,
            "async": self.is_async,
            "if": escape_unsafe(self.condition),
        }


@dataclass
class McpServer:
    name: str
    transport: str = ""
    command: str = ""
    args: tuple[str, ...] = ()
    env_keys: tuple[str, ...] = ()
    url: str = ""
    header_names: tuple[str, ...] = ()
    cwd: str = ""

    def to_dict(self) -> dict[str, Any]:
        from .safety import escape_unsafe
        from .secrets import redact

        def safe(value: Any) -> str:
            return escape_unsafe(redact(str(value or "")))

        return {
            "name": safe(self.name),
            "transport": safe(self.transport),
            "command": safe(self.command),
            "args": [safe(arg) for arg in self.args],
            "env_keys": [safe(key) for key in self.env_keys],
            "url": safe(self.url),
            "header_names": [safe(key) for key in self.header_names],
            "cwd": safe(self.cwd),
        }


@dataclass
class PluginIdentity:
    name: str = ""
    version: str = ""
    description: str = ""
    author: str = ""
    license: str = ""
    homepage: str = ""
    repository: str = ""
    marketplace: str = ""
    source: str = ""
    source_kind: str = ""
    ref: str = ""
    sha: str = ""
    scope: str = ""
    project_path: str = ""
    declared_paths: dict[str, tuple[str, ...]] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        from .safety import escape_unsafe
        from .secrets import redact

        def safe(value: Any) -> str:
            return escape_unsafe(redact(str(value or "")))

        return {
            "name": safe(self.name),
            "version": safe(self.version),
            "description": safe(self.description),
            "author": safe(self.author),
            "license": safe(self.license),
            "homepage": safe(self.homepage),
            "repository": safe(self.repository),
            "marketplace": safe(self.marketplace),
            "source": safe(self.source),
            "source_kind": safe(self.source_kind),
            "ref": safe(self.ref),
            "sha": safe(self.sha),
            "scope": safe(self.scope),
            "project_path": safe(self.project_path),
            "declared_paths": {
                safe(key): [safe(item) for item in value]
                for key, value in self.declared_paths.items()
            },
        }


@dataclass
class NormalizedPlugin:
    identity: PluginIdentity = field(default_factory=PluginIdentity)
    components: list[PluginComponent] = field(default_factory=list)
    hooks: list[HookEvent] = field(default_factory=list)
    mcp_servers: list[McpServer] = field(default_factory=list)
    marketplace_entry: dict[str, Any] = field(default_factory=dict)
    manifests: list[ManifestRecord] = field(default_factory=list)
    unknown_keys: dict[str, list[str]] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        from .safety import escape_unsafe
        from .secrets import redact

        return {
            "identity": self.identity.to_dict(),
            "components": [item.to_dict() for item in self.components],
            "hooks": [item.to_dict() for item in self.hooks],
            "mcp_servers": [item.to_dict() for item in self.mcp_servers],
            "marketplace_entry": {
                key: escape_unsafe(redact(str(value or "")))
                for key, value in self.marketplace_entry.items()
                if key in ("name", "version", "category", "ref", "sha")
            },
            "manifests": [item.to_dict() for item in self.manifests],
            "unknown_keys": {
                escape_unsafe(path): sorted(escape_unsafe(key) for key in keys)
                for path, keys in self.unknown_keys.items()
            },
        }


@dataclass
class Coverage:
    assessed: list[str] = field(default_factory=list)
    not_assessed: list[str] = field(default_factory=list)
    rules_run: int = 0
    rules_skipped: list[str] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)
    components: dict[str, int] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "assessed": list(self.assessed),
            "not_assessed": list(self.not_assessed),
            "rules_run": self.rules_run,
            "rules_skipped": list(self.rules_skipped),
            "notes": list(self.notes),
            "components": dict(self.components),
        }


@dataclass
class TargetInfo:
    input: str
    kind: str = "directory"  # directory | archive
    location: str = "local"  # local | personal | plugin-cache | marketplace | project | other
    skill_id: str = ""
    name: str = ""
    version: str = ""
    platform: str = ""
    plugin: str = ""
    display: str = ""
    artifact_kind: str = "skill"
    declared_intent: str = ""
    intent_allowed: bool = False

    def __post_init__(self) -> None:
        if not self.display:
            self.display = self.input

    def to_dict(self) -> dict[str, Any]:
        return {
            "input": self.input,
            "display": self.display,
            "kind": self.kind,
            "location": self.location,
            "skill_id": self.skill_id,
            "name": self.name,
            "version": self.version,
            "platform": self.platform,
            "plugin": self.plugin,
            "artifact_kind": self.artifact_kind,
            "declared_intent": self.declared_intent,
            "intent_allowed": self.intent_allowed,
        }


DEFAULT_NOT_ASSESSED = [
    "runtime behaviour (hooks, tool calls, file/network activity) — static analysis only",
    "cryptographic signature validity — presence is recorded, not verified",
    "transitive dependency resolution and CVE matching — dependency declarations are inspected only",
    "content behind external URLs — references are recorded, never fetched",
    "actual platform permission enforcement — declarations are compared, not enforced",
    "semantic intent that appears only in natural language — heuristics, not proof",
]


@dataclass
class AuditResult:
    target: TargetInfo
    findings: list[Finding] = field(default_factory=list)
    files: list[FileRecord] = field(default_factory=list)
    skill: NormalizedSkill = field(default_factory=NormalizedSkill)
    coverage: Coverage = field(default_factory=Coverage)
    errors: list[str] = field(default_factory=list)
    duration_ms: int = 0
    gating_count: int = 0
    baseline_matched: int = 0
    suppressed_count: int = 0
    plugin: NormalizedPlugin | None = None

    @property
    def passed(self) -> bool:
        return self.gating_count == 0 and not self.errors

    def summary(self) -> dict[str, Any]:
        counts = {s.value: 0 for s in Severity}
        ast_counts = {ast: 0 for ast in AST_NAMES}
        for finding in self.findings:
            counts[finding.severity.value] += 1
            ast_counts[finding.ast] = ast_counts.get(finding.ast, 0) + 1
        return {
            "findings": len(self.findings),
            "severity": counts,
            "ast": ast_counts,
            "gating": self.gating_count,
            "suppressed": self.suppressed_count,
            "baselined": self.baseline_matched,
            "intent": sum(1 for finding in self.findings if finding.intent_matched),
            "errors": len(self.errors),
            "files": len(self.files),
        }

    def public_findings(self, include_suppressed: bool = False) -> list[Finding]:
        if include_suppressed:
            return list(self.findings)
        return [f for f in self.findings if not f.suppressed]

    def to_dict(self) -> dict[str, Any]:
        return {
            "target": self.target.to_dict(),
            "result": "pass" if self.passed else "fail",
            "skill": self.skill.to_dict(),
            "plugin": self.plugin.to_dict() if self.plugin else None,
            "summary": self.summary(),
            "findings": [f.to_dict() for f in self.findings],
            "files": [f.to_dict() for f in self.files],
            "coverage": self.coverage.to_dict(),
            "errors": list(self.errors),
            "duration_ms": self.duration_ms,
        }


@dataclass
class ScanReport:
    results: list[AuditResult] = field(default_factory=list)
    generated: str = field(default_factory=utc_now_iso)
    tool_version: str = ""
    command: str = "audit"
    errors: list[str] = field(default_factory=list)
    policy: dict[str, Any] = field(default_factory=dict)

    @property
    def passed(self) -> bool:
        return all(r.passed for r in self.results) and not self.errors

    def summary(self) -> dict[str, Any]:
        counts = {s.value: 0 for s in Severity}
        ast_counts = {ast: 0 for ast in AST_NAMES}
        gating = 0
        files = 0
        findings = 0
        suppressed = 0
        baselined = 0
        intent = 0
        for result in self.results:
            files += len(result.files)
            gating += result.gating_count
            suppressed += result.suppressed_count
            baselined += result.baseline_matched
            for finding in result.findings:
                findings += 1
                counts[finding.severity.value] += 1
                ast_counts[finding.ast] = ast_counts.get(finding.ast, 0) + 1
                if finding.intent_matched:
                    intent += 1
        return {
            "targets": len(self.results),
            "findings": findings,
            "severity": counts,
            "ast": ast_counts,
            "gating": gating,
            "suppressed": suppressed,
            "baselined": baselined,
            "intent": intent,
            "files": files,
            "errors": len(self.errors),
        }

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema": SCHEMA_VERSION,
            "tool": {"name": TOOL_NAME, "version": self.tool_version},
            "generated": self.generated,
            "command": self.command,
            "result": "pass" if self.passed else "fail",
            "policy": dict(self.policy),
            "summary": self.summary(),
            "targets": [r.to_dict() for r in self.results],
            "errors": list(self.errors),
        }

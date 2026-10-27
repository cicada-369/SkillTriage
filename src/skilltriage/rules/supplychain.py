"""Dependency and configuration supply-chain rules (AST02, AST04)."""

from __future__ import annotations

import re
from collections.abc import Iterator

from ..models import Confidence, Severity
from ..parsers import parse_json_text, parse_toml_text
from ..patterns import brands_in
from .base import Rule, RuleContext

RULES: list[Rule] = []

_LOCKFILES = {
    "package-lock.json",
    "npm-shrinkwrap.json",
    "yarn.lock",
    "pnpm-lock.yaml",
    "poetry.lock",
    "uv.lock",
    "Pipfile.lock",
    "requirements.lock",
    "pdm.lock",
}
_INSTALL_SCRIPT_KEYS = {"preinstall", "install", "postinstall", "prepare", "prepublish", "prepublishOnly"}
_CONFIG_PATHS = {
    ".claude/settings.json",
    ".claude/settings.local.json",
    ".mcp.json",
    ".claude-plugin/plugin.json",
    "hooks/hooks.json",
    ".vscode/tasks.json",
    ".vscode/settings.json",
}
_HEX40_RE = re.compile(r"(?:@|#)[0-9a-fA-F]{40}\b|#sha256=[0-9a-fA-F]{64}")
_NPM_PINNED_RE = re.compile(r"^=?\d+\.\d+\.\d+(?:[-+][0-9A-Za-z.-]+)?$")


def _primary_path(ctx: RuleContext) -> str:
    return ctx.primary_path


def _dependency_sources(ctx: RuleContext) -> Iterator[tuple[str, str, str]]:
    for record, text in ctx.texts():
        name = record.path.rsplit("/", 1)[-1]
        if name.startswith("requirements") and name.endswith(".txt"):
            yield "requirements", record.path, text
        elif name == "pyproject.toml":
            yield "pyproject", record.path, text
        elif name == "package.json":
            yield "package", record.path, text


def _requirement_lines(text: str) -> Iterator[tuple[int, str]]:
    for number, raw in enumerate(text.splitlines(), start=1):
        line = raw.split("#", 1)[0].strip()
        if not line or line.startswith(("-r", "-c", "--")):
            continue
        if line.startswith("-e "):
            line = line[3:].strip()
        yield number, line


def _python_pinned(spec: str) -> bool:
    if "==" in spec and not re.search(r"==\s*[\*xX]", spec):
        return True
    if " @ " in spec or re.match(r"^(?:https?|git\+)", spec):
        return bool(_HEX40_RE.search(spec))
    return False


def _is_url_spec(spec: str) -> bool:
    return bool(re.match(r"^(?:https?|git\+|git://)", spec) or " @ " in spec)


def _npm_pinned(spec: str) -> bool:
    if not isinstance(spec, str):
        return False
    if _NPM_PINNED_RE.match(spec.strip()):
        return True
    if _HEX40_RE.search(spec):
        return True
    return False


def _is_npm_url(spec: str) -> bool:
    return bool(re.match(r"^(?:https?|git\+|git://|github:|gitlab:|bitbucket:)", spec) or "://" in spec)


def _emit_dependency(ctx: RuleContext, rule: Rule, path: str, line: int | None, evidence: str, severity: Severity | None = None) -> None:
    ctx.emit(rule, path=path, line=line, evidence=evidence, severity=severity, context=False)


def check_dependencies(ctx: RuleContext) -> None:
    for kind, path, text in _dependency_sources(ctx):
        if kind == "requirements":
            for line_no, spec in _requirement_lines(text):
                if _python_pinned(spec):
                    continue
                rule = RULE_URL_DEP if _is_url_spec(spec) else RULE_UNPINNED_DEP
                _emit_dependency(ctx, rule, path, line_no, spec)
        elif kind == "pyproject":
            data, _ = parse_toml_text(text)
            project = data.get("project") if isinstance(data.get("project"), dict) else {}
            specs: list[tuple[str | None, str, Severity | None]] = []
            for spec in project.get("dependencies") or []:
                specs.append((None, str(spec), None))
            optional = project.get("optional-dependencies") or {}
            if isinstance(optional, dict):
                for group_specs in optional.values():
                    for spec in group_specs or []:
                        specs.append((None, str(spec), None))
            build = data.get("build-system") if isinstance(data.get("build-system"), dict) else {}
            for spec in build.get("requires") or []:
                specs.append((None, str(spec), Severity.LOW))
            for _, spec, severity in specs:
                if _python_pinned(spec):
                    continue
                rule = RULE_URL_DEP if _is_url_spec(spec) else RULE_UNPINNED_DEP
                _emit_dependency(ctx, rule, path, None, spec, severity=severity)
        elif kind == "package":
            data, _ = parse_json_text(text)
            for section in ("dependencies", "devDependencies", "optionalDependencies", "peerDependencies"):
                mapping = data.get(section)
                if not isinstance(mapping, dict):
                    continue
                for name, spec in mapping.items():
                    spec_text = str(spec)
                    if _npm_pinned(spec_text):
                        continue
                    rule = RULE_URL_DEP if _is_npm_url(spec_text) else RULE_UNPINNED_DEP
                    _emit_dependency(ctx, rule, path, None, f"{section}.{name}: {spec_text}")


def _has_declared_dependencies(kind: str, text: str) -> bool:
    if kind == "requirements":
        return any(True for _ in _requirement_lines(text))
    if kind == "pyproject":
        data, _ = parse_toml_text(text)
        project = data.get("project") if isinstance(data.get("project"), dict) else {}
        build = data.get("build-system") if isinstance(data.get("build-system"), dict) else {}
        return bool(
            project.get("dependencies")
            or project.get("optional-dependencies")
            or build.get("requires")
        )
    if kind == "package":
        data, _ = parse_json_text(text)
        return any(
            isinstance(data.get(section), dict) and data[section]
            for section in ("dependencies", "devDependencies", "optionalDependencies", "peerDependencies")
        )
    return False


def check_lockfile(ctx: RuleContext) -> None:
    has_deps = False
    has_hash_pins = False
    for kind, path, text in _dependency_sources(ctx):
        if _has_declared_dependencies(kind, text):
            has_deps = True
        if kind == "requirements" and re.search(r"--hash(?:=|\s+)sha256:", text):
            has_hash_pins = True
    if not has_deps:
        return
    names = {record.path.rsplit("/", 1)[-1] for record in ctx.files}
    if names & _LOCKFILES or has_hash_pins:
        return
    ctx.emit(
        RULE_MISSING_LOCKFILE,
        path=_primary_path(ctx),
        message="Dependencies are declared without a lockfile or hash pins.",
        evidence=f"no lockfile among: {', '.join(sorted(_LOCKFILES))}",
        context=False,
    )


def check_install_scripts(ctx: RuleContext) -> None:
    for record, text in ctx.texts():
        if record.path.rsplit("/", 1)[-1] != "package.json":
            continue
        data, _ = parse_json_text(text)
        scripts = data.get("scripts")
        if isinstance(scripts, dict):
            for key in sorted(_INSTALL_SCRIPT_KEYS & set(scripts)):
                value = str(scripts[key]).strip()
                if value and value not in ("true", "exit 0", "echo"):
                    ctx.emit(
                        RULE_INSTALL_SCRIPT,
                        path=record.path,
                        message=f"npm lifecycle script {key!r} executes during install.",
                        evidence=f"{key}: {value}",
                        context=False,
                    )
    for record, text in ctx.texts():
        if record.path.rsplit("/", 1)[-1] != "setup.py":
            continue
        for number, line in enumerate(text.splitlines(), start=1):
            if re.search(r"(?i)\b(?:subprocess|os\.system|urlopen|requests\.|exec\s*\()", line):
                ctx.emit(
                    RULE_INSTALL_SCRIPT,
                    path=record.path,
                    line=number,
                    message="setup.py performs execution or network access.",
                    evidence=line,
                    context=False,
                )


def check_config_as_code(ctx: RuleContext) -> None:
    for relpath in sorted(_CONFIG_PATHS):
        record = ctx.record(relpath)
        if record is None or not record.is_text:
            continue
        data, _ = parse_json_text(record.text)
        indicators: list[str] = []
        if "hooks" in data:
            indicators.append("hooks")
        if "mcpServers" in data:
            indicators.append("mcpServers")
        elif any(
            isinstance(value, dict) and "command" in value for value in data.values()
        ):
            # Some plugins use a bare map of server name to server spec.
            indicators.append("mcpServers")
        tasks = data.get("tasks")
        if isinstance(tasks, list) and any(isinstance(task, dict) and "command" in task for task in tasks):
            indicators.append("tasks.command")
        if indicators:
            ctx.emit(
                RULE_CONFIG_AS_CODE,
                path=relpath,
                message="Configuration file contains executable hooks or commands.",
                evidence=f"keys: {', '.join(indicators)}",
                context=False,
            )


def check_provenance(ctx: RuleContext) -> None:
    if not ctx.skill.signature and not ctx.skill.content_hash:
        ctx.emit(
            RULE_NO_PROVENANCE,
            path=_primary_path(ctx),
            message="No signature or content hash is declared.",
            evidence="signature: absent; content_hash: absent",
            context=False,
        )


def check_brand_impersonation(ctx: RuleContext) -> None:
    name = ctx.skill.name
    if not name:
        return
    brands = brands_in(name)
    if not brands:
        return
    haystack = f"{name} {ctx.skill.description}".lower()
    if re.search(r"\b(?:official|affiliated|authorised|authorized|by)\b", haystack):
        return
    ctx.emit(
        RULE_BRAND_IMPERSONATION,
        path="SKILL.md",
        message="Name uses a well-known service brand without an affiliation claim.",
        evidence=f"name: {name}; brands: {', '.join(brands)}",
        confidence=Confidence.LOW,
        context=False,
    )


RULE_UNPINNED_DEP = Rule(
    id="AST02-UNPINNED-DEPENDENCY",
    ast="AST02",
    title="Unpinned dependency",
    severity=Severity.MEDIUM,
    confidence=Confidence.HIGH,
    description="A version range can resolve to a different, compromised release after review.",
    remediation="Pin dependencies to exact versions or immutable hashes and commit a lockfile.",
    cwes=("CWE-1329", "CWE-829"),
    tags=("supply-chain",),
    no_context=True,
    check=check_dependencies,
)
RULES.append(RULE_UNPINNED_DEP)

RULE_URL_DEP = Rule(
    id="AST02-URL-DEPENDENCY",
    ast="AST02",
    title="Unpinned URL or VCS dependency",
    severity=Severity.HIGH,
    confidence=Confidence.HIGH,
    description="A dependency fetched from a URL or Git reference without a commit hash can change content without a version change.",
    remediation="Pin the commit SHA or content hash, or vendor the dependency into the reviewed package.",
    cwes=("CWE-829", "CWE-494"),
    tags=("supply-chain",),
    no_context=True,
    check=check_dependencies,
)
RULES.append(RULE_URL_DEP)

RULE_MISSING_LOCKFILE = Rule(
    id="AST02-MISSING-LOCKFILE",
    ast="AST02",
    title="Dependencies without a lockfile",
    severity=Severity.LOW,
    confidence=Confidence.HIGH,
    description="Without a lockfile, transitive versions are resolved at install time and are not reproducible or reviewable.",
    remediation="Commit a lockfile or hash-pinned requirements and scan the resolved tree.",
    cwes=("CWE-1329",),
    tags=("supply-chain",),
    no_context=True,
    check=check_lockfile,
)
RULES.append(RULE_MISSING_LOCKFILE)

RULE_INSTALL_SCRIPT = Rule(
    id="AST02-INSTALL-SCRIPT",
    ast="AST02",
    title="Install-time script",
    severity=Severity.HIGH,
    confidence=Confidence.HIGH,
    description="Lifecycle scripts execute automatically during dependency installation, before the skill is invoked or reviewed.",
    remediation="Remove install-time execution or move it behind an explicit, reviewed setup step.",
    cwes=("CWE-829", "CWE-94"),
    tags=("supply-chain", "execution"),
    no_context=True,
    check=check_install_scripts,
)
RULES.append(RULE_INSTALL_SCRIPT)

RULE_CONFIG_AS_CODE = Rule(
    id="AST02-CONFIG-AS-CODE",
    ast="AST02",
    title="Executable configuration file",
    severity=Severity.MEDIUM,
    confidence=Confidence.HIGH,
    description="Hooks, MCP server commands, and task definitions execute at session or workspace open, making configuration an execution path.",
    remediation="Treat configuration as code: review it, gate it behind approval, and pin or disable automatic hooks.",
    cwes=("CWE-829", "CWE-94"),
    tags=("supply-chain", "configuration"),
    no_context=True,
    check=check_config_as_code,
)
RULES.append(RULE_CONFIG_AS_CODE)

RULE_NO_PROVENANCE = Rule(
    id="AST02-NO-PROVENANCE",
    ast="AST02",
    title="No provenance signal",
    severity=Severity.MEDIUM,
    confidence=Confidence.HIGH,
    description="Without a signature or content hash, the package cannot be tied to a publisher or verified after distribution.",
    remediation="Sign the package and publish a content hash that covers SKILL.md and every declared resource.",
    cwes=("CWE-345", "CWE-353"),
    tags=("supply-chain", "provenance"),
    no_context=True,
    check=check_provenance,
)
RULES.append(RULE_NO_PROVENANCE)

RULE_BRAND_IMPERSONATION = Rule(
    id="AST04-BRAND-IMPERSONATION",
    ast="AST04",
    title="Possible brand impersonation",
    severity=Severity.LOW,
    confidence=Confidence.LOW,
    description="A name containing a well-known brand can capture searches for the official skill, especially when no affiliation is documented.",
    remediation="Verify the publisher against the brand's official registry and record the affiliation or rename the skill.",
    cwes=("CWE-345",),
    tags=("metadata", "impersonation"),
    no_context=True,
    check=check_brand_impersonation,
)
RULES.append(RULE_BRAND_IMPERSONATION)

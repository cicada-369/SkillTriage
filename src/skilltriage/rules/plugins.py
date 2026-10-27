"""Claude Code plugin rules.

A plugin is more than the sum of its skills: hooks run automatically, MCP
servers launch processes or talk to remote hosts, and declared components can
point outside the package. These checks are deliberately narrow and precise;
uncertain behaviour is reported as a coverage gap rather than a gating finding.
"""

from __future__ import annotations

import fnmatch
import re
from pathlib import Path
from urllib.parse import urlparse

from ..models import Confidence, Severity
from .base import Rule, RuleContext

RULES: list[Rule] = []


def _rule(rule: Rule) -> None:
    RULES.append(rule)


_APPROVAL_RE = re.compile(
    r"""(?ix)
    "?(?:permissionDecision|decision|behavior)"?\s*[:=]\s*"?
        (?:allow|approve|accept)"?
    | \bauto[-_ ]?approve\b
    | \bskip[-_ ]?(?:permission|approval|confirm(?:ation)?)\b
    """
)
_ROOT_REF_RE = re.compile(r"\$\{?CLAUDE_PLUGIN_ROOT\}?/([^\s\"';|&)`]+)")
_BARE_REF_RE = re.compile(
    r"""(?:^|\s)(?:sh|bash|python3?|node|deno|bun)\s+([^\s\"';|&)`]+)"""
)
_HOME_REF_RE = re.compile(
    r"""(?:^|[\s"'])((?:~|\$HOME|\$\{HOME\})/[^\s"';|&)`]+)"""
)
_SCRIPT_SUFFIXES = {".sh", ".bash", ".py", ".js", ".mjs", ".cjs", ".rb", ".pl"}
_BROAD_TOOLS = {"*", "all", "full_access", "unrestricted", "admin", "everything"}
_EXEC_COMMANDS = {"npx", "bunx", "uvx", "pipx", "docker", "podman"}
_PINNED_REF_RE = re.compile(r"^(?:v?\d+\.\d+\.\d+|[0-9a-f]{7,40})$", re.I)
_DRIVE_RE = re.compile(r"^[A-Za-z]:")


def _escapes_root(value: str) -> bool:
    return value.startswith("/") or ".." in value.split("/") or bool(_DRIVE_RE.match(value))


def _hook_refs(command: str) -> list[str]:
    refs: list[str] = []
    for match in _ROOT_REF_RE.finditer(command):
        refs.append(match.group(1))
    for match in _HOME_REF_RE.finditer(command):
        refs.append(match.group(1))
    for match in _BARE_REF_RE.finditer(command):
        ref = match.group(1)
        if ref.startswith(("${", "$")):
            continue
        while ref.startswith("./"):
            ref = ref[2:]
        if "/" in ref or Path(ref).suffix.lower() in _SCRIPT_SUFFIXES:
            refs.append(ref)
    return refs


def _escapes_hook_ref(ref: str) -> bool:
    value = ref.replace("\\", "/")
    return (
        value.startswith(("/", "~", "$HOME/", "${HOME}/"))
        or ".." in value.split("/")
        or bool(_DRIVE_RE.match(value))
    )


def _line_of(text: str, needle: str) -> int | None:
    if not needle:
        return None
    for number, line in enumerate(text.splitlines(), start=1):
        if needle in line:
            return number
    return None


def _hook_line(text: str, command: str) -> int | None:
    for ref in _hook_refs(command):
        line = _line_of(text, Path(ref).name)
        if line:
            return line
    return _line_of(text, command[:40])


def _declared_value(entry: str) -> str:
    value = entry.strip().replace("\\", "/")
    while value.startswith("./"):
        value = value[2:]
    return value


def _declared_resolves(value: str, relpaths: set[str]) -> bool:
    if not value or value.startswith("/") or ".." in value.split("/"):
        return False
    if any(char in value for char in "*?["):
        return any(fnmatch.fnmatch(path, value) for path in relpaths)
    if value.endswith("/"):
        prefix = value.rstrip("/") + "/"
        return any(path.startswith(prefix) for path in relpaths)
    return value in relpaths or any(path.startswith(value + "/") for path in relpaths)


def _is_broad_tool(tool: str) -> bool:
    lowered = tool.strip().lower()
    if lowered in _BROAD_TOOLS:
        return True
    # Bash(ls *) and Bash(git status:*) are scoped grants. Only an unscoped
    # inner pattern is broad.
    match = re.fullmatch(r"bash\(\s*(.*?)\s*\)", lowered)
    return bool(match and match.group(1) in _BROAD_TOOLS)


def _first_package(args: tuple[str, ...]) -> str:
    index = 0
    while index < len(args):
        arg = args[index]
        if arg in ("-y", "--yes", "--quiet", "-q"):
            index += 1
            continue
        if arg in ("-p", "--package"):
            return args[index + 1] if index + 1 < len(args) else ""
        if arg.startswith("-"):
            index += 1
            continue
        return arg
    return ""


def _npm_unpinned(spec: str) -> bool:
    if not spec:
        return False
    if spec.startswith("@"):
        return spec.count("@") < 2 or spec.endswith("@latest")
    return "@" not in spec or spec.endswith("@latest")


def _python_unpinned(args: tuple[str, ...]) -> bool:
    if "--from" in args:
        index = args.index("--from") + 1
        spec = args[index] if index < len(args) else ""
        return spec.startswith("git+") or ("@" not in spec and "==" not in spec)
    spec = _first_package(args)
    return bool(spec) and "==" not in spec and "@" not in spec


def _container_unpinned(args: tuple[str, ...]) -> bool:
    if "run" not in args:
        return False
    image = next(
        (arg for arg in args[args.index("run") + 1 :] if not arg.startswith("-")), ""
    )
    return bool(image) and "@sha256:" not in image


def check_hook_approval(ctx: RuleContext) -> None:
    if not ctx.is_plugin:
        return
    for hook in ctx.plugin.hooks:
        if hook.event.lower() not in ("pretooluse", "permissionrequest", "permissionprompt"):
            continue
        if _APPROVAL_RE.search(hook.command):
            ctx.emit(
                RULE_HOOK_APPROVAL,
                path="hooks/hooks.json",
                line=_hook_line(ctx.text("hooks/hooks.json"), hook.command),
                evidence=hook.command,
            )
            continue
        for ref in _hook_refs(hook.command):
            text = ctx.text(ref)
            if not text:
                continue
            for number, line in enumerate(text.splitlines(), start=1):
                if _APPROVAL_RE.search(line):
                    ctx.emit(
                        RULE_HOOK_APPROVAL,
                        path=ref,
                        line=number,
                        evidence=line.strip(),
                    )


def check_hook_path_escape(ctx: RuleContext) -> None:
    if not ctx.is_plugin:
        return
    text = ctx.text("hooks/hooks.json")
    for hook in ctx.plugin.hooks:
        for ref in _hook_refs(hook.command):
            if _escapes_hook_ref(ref):
                ctx.emit(
                    RULE_HOOK_ESCAPE,
                    path="hooks/hooks.json",
                    line=_line_of(text, Path(ref).name),
                    evidence=ref,
                )


def check_hook_missing_script(ctx: RuleContext) -> None:
    if not ctx.is_plugin:
        return
    relpaths = ctx.tree.relpaths()
    for hook in ctx.plugin.hooks:
        for ref in _hook_refs(hook.command):
            if _escapes_hook_ref(ref):
                continue
            if ref in relpaths:
                continue
            if any(path.startswith(ref.rstrip("/") + "/") for path in relpaths):
                continue
            ctx.emit(
                RULE_HOOK_MISSING,
                path="hooks/hooks.json",
                line=_hook_line(ctx.text("hooks/hooks.json"), hook.command),
                evidence=f"{ref} (referenced by {hook.event})",
            )


def check_mcp_unpinned_exec(ctx: RuleContext) -> None:
    if not ctx.is_plugin:
        return
    for server in ctx.plugin.mcp_servers:
        base = Path(server.command).name.lower()
        if base not in _EXEC_COMMANDS:
            continue
        if base in ("npx", "bunx"):
            unpinned = _npm_unpinned(_first_package(server.args))
        elif base in ("uvx", "pipx"):
            args = server.args[1:] if base == "pipx" and server.args[:1] == ("run",) else server.args
            unpinned = _python_unpinned(args)
        else:
            unpinned = _container_unpinned(server.args)
        if unpinned:
            command = " ".join([server.command, *server.args])
            ctx.emit(
                RULE_MCP_UNPINNED,
                path=".mcp.json",
                line=_line_of(ctx.text(".mcp.json"), server.name),
                evidence=f"{server.name}: {command}",
            )


def check_mcp_cleartext(ctx: RuleContext) -> None:
    if not ctx.is_plugin:
        return
    for server in ctx.plugin.mcp_servers:
        if not server.url:
            continue
        parsed = urlparse(server.url)
        if parsed.scheme == "http" and parsed.hostname not in (
            "localhost",
            "127.0.0.1",
            "::1",
        ):
            ctx.emit(
                RULE_MCP_CLEARTEXT,
                path=".mcp.json",
                line=_line_of(ctx.text(".mcp.json"), server.name),
                evidence=f"{server.name}: {server.url}",
            )


def check_component_path_escape(ctx: RuleContext) -> None:
    if not ctx.is_plugin:
        return
    text = ctx.text(".claude-plugin/plugin.json")
    for kind, entries in ctx.plugin.identity.declared_paths.items():
        for entry in entries:
            value = _declared_value(entry)
            if _escapes_root(value):
                ctx.emit(
                    RULE_COMPONENT_ESCAPE,
                    path=".claude-plugin/plugin.json",
                    line=_line_of(text, entry),
                    evidence=f"{kind}: {entry}",
                )


def check_component_missing(ctx: RuleContext) -> None:
    if not ctx.is_plugin:
        return
    relpaths = ctx.tree.relpaths()
    text = ctx.text(".claude-plugin/plugin.json")
    for kind, entries in ctx.plugin.identity.declared_paths.items():
        for entry in entries:
            value = _declared_value(entry)
            if not value or value == ".":
                # A root-relative declaration is ambiguous; component
                # discovery still uses the conventional directories.
                continue
            if _escapes_root(value):
                continue
            if not _declared_resolves(value, relpaths):
                ctx.emit(
                    RULE_COMPONENT_MISSING,
                    path=".claude-plugin/plugin.json",
                    line=_line_of(text, entry),
                    evidence=f"{kind}: {entry}",
                )


def check_duplicate_components(ctx: RuleContext) -> None:
    if not ctx.is_plugin:
        return
    seen: dict[tuple[str, str], str] = {}
    for component in ctx.plugin.components:
        key = (component.kind, component.name.lower())
        previous = seen.get(key)
        if previous is not None:
            ctx.emit(
                RULE_COMPONENT_DUPLICATE,
                path=component.path,
                evidence=f"{component.kind} name {component.name!r} already used by {previous}",
            )
        else:
            seen[key] = component.path


def check_marketplace_pinning(ctx: RuleContext) -> None:
    if not ctx.is_plugin:
        return
    identity = ctx.plugin.identity
    if not ctx.plugin.marketplace_entry or identity.source_kind in ("", "path", "local"):
        return
    path = ".claude-plugin/marketplace.json"
    text = ctx.text(path)
    line = _line_of(text, identity.name)
    if not identity.sha:
        ctx.emit(
            RULE_MARKETPLACE_UNPINNED,
            path=path,
            line=line,
            evidence=f"{identity.name}: {identity.source_kind} source has no sha",
        )
    elif not re.fullmatch(r"[0-9a-f]{40}", identity.sha, re.I):
        ctx.emit(
            RULE_MARKETPLACE_UNPINNED,
            path=path,
            line=line,
            evidence=f"{identity.name}: sha is not a full 40-hex commit",
        )
    if identity.ref and not _PINNED_REF_RE.match(identity.ref):
        ctx.emit(
            RULE_MARKETPLACE_UNPINNED,
            path=path,
            line=line,
            evidence=f"{identity.name}: mutable ref {identity.ref!r}",
        )


def check_component_broad_tools(ctx: RuleContext) -> None:
    if not ctx.is_plugin:
        return
    for component in ctx.plugin.components:
        broad = [tool for tool in component.allowed_tools if _is_broad_tool(tool)]
        if broad:
            ctx.emit(
                RULE_BROAD_TOOL_GRANT,
                path=component.path,
                evidence=f"allowed-tools: {', '.join(broad)}",
            )


RULE_HOOK_APPROVAL = Rule(
    id="AST09-PLUGIN-HOOK-APPROVAL",
    ast="AST09",
    title="Hook can approve or bypass permission prompts",
    severity=Severity.HIGH,
    confidence=Confidence.HIGH,
    description="A PreToolUse or PermissionRequest hook decides the outcome of an approval prompt. If it returns an allow decision, the user loses the control point the prompt exists to provide.",
    remediation="Review the hook and its script. If it must decide, restrict it to an explicit, narrow matcher and log every decision. Prefer returning no decision so the normal prompt remains.",
    cwes=("CWE-863", "CWE-1426"),
    tags=("plugin", "hooks", "approval"),
    check=check_hook_approval,
    no_context=True,
)
_rule(RULE_HOOK_APPROVAL)

RULE_HOOK_ESCAPE = Rule(
    id="AST06-PLUGIN-HOOK-PATH-ESCAPE",
    ast="AST06",
    title="Hook command resolves outside the plugin root",
    severity=Severity.HIGH,
    confidence=Confidence.HIGH,
    description="A hook command walks up from CLAUDE_PLUGIN_ROOT, so it can execute content the plugin package does not contain and the reviewer never saw.",
    remediation="Reference only files inside the plugin root. If shared code is required, vendor it into the package and review it there.",
    cwes=("CWE-22",),
    tags=("plugin", "hooks", "path"),
    check=check_hook_path_escape,
    no_context=True,
)
_rule(RULE_HOOK_ESCAPE)

RULE_HOOK_MISSING = Rule(
    id="AST04-PLUGIN-HOOK-MISSING-SCRIPT",
    ast="AST04",
    title="Hook references a missing script",
    severity=Severity.MEDIUM,
    confidence=Confidence.HIGH,
    description="A hook command names a script that is not in the package. The hook will fail, or resolve a different file from the environment, depending on the platform.",
    remediation="Ship the referenced script or remove the hook registration. Verify the command in a disposable environment.",
    cwes=("CWE-1059",),
    tags=("plugin", "hooks"),
    check=check_hook_missing_script,
    no_context=True,
)
_rule(RULE_HOOK_MISSING)

RULE_MCP_UNPINNED = Rule(
    id="AST02-PLUGIN-MCP-UNPINNED-EXEC",
    ast="AST02",
    title="MCP server launches an unpinned package",
    severity=Severity.HIGH,
    confidence=Confidence.MEDIUM,
    description="An MCP server starts a package through npx, uvx, pipx, or a container image without an exact version or digest. The code that runs can change without the plugin changing.",
    remediation="Pin an exact version or digest (for example pkg@1.2.3, pkg==1.2.3, or image@sha256:...). Update deliberately and re-audit after each change.",
    cwes=("CWE-494", "CWE-829"),
    tags=("plugin", "mcp", "supply-chain"),
    check=check_mcp_unpinned_exec,
    no_context=True,
)
_rule(RULE_MCP_UNPINNED)

RULE_MCP_CLEARTEXT = Rule(
    id="AST02-PLUGIN-MCP-CLEARTEXT",
    ast="AST02",
    title="MCP server uses a cleartext remote URL",
    severity=Severity.MEDIUM,
    confidence=Confidence.HIGH,
    description="An MCP server connects over plain HTTP. Requests, responses, and any bearer token can be read or modified in transit.",
    remediation="Use HTTPS, or a loopback address when the server is local.",
    cwes=("CWE-319",),
    tags=("plugin", "mcp", "transport"),
    check=check_mcp_cleartext,
    no_context=True,
)
_rule(RULE_MCP_CLEARTEXT)

RULE_COMPONENT_ESCAPE = Rule(
    id="AST04-PLUGIN-COMPONENT-ESCAPE",
    ast="AST04",
    title="Declared component path escapes the plugin root",
    severity=Severity.HIGH,
    confidence=Confidence.HIGH,
    description="plugin.json declares a command, agent, or skill path outside the package. The audited artifact is not the whole artifact that will load.",
    remediation="Declare only paths inside the plugin root. Vendor shared components into the package.",
    cwes=("CWE-22",),
    tags=("plugin", "components", "path"),
    check=check_component_path_escape,
    no_context=True,
)
_rule(RULE_COMPONENT_ESCAPE)

RULE_COMPONENT_MISSING = Rule(
    id="AST04-PLUGIN-COMPONENT-MISSING",
    ast="AST04",
    title="Declared component path does not exist",
    severity=Severity.MEDIUM,
    confidence=Confidence.HIGH,
    description="plugin.json declares a component path that resolves to nothing in the package. The declaration is either stale or depends on files outside the audited artifact.",
    remediation="Remove the stale declaration or ship the missing component. Confirm the loaded component set matches the declaration.",
    cwes=("CWE-1059",),
    tags=("plugin", "components"),
    check=check_component_missing,
    no_context=True,
)
_rule(RULE_COMPONENT_MISSING)

RULE_COMPONENT_DUPLICATE = Rule(
    id="AST04-PLUGIN-COMPONENT-DUPLICATE",
    ast="AST04",
    title="Duplicate plugin component name",
    severity=Severity.LOW,
    confidence=Confidence.HIGH,
    description="Two components of the same kind share a name. Which one loads can depend on discovery order, making review and invocation ambiguous.",
    remediation="Give each component a unique name, or remove the duplicate.",
    cwes=("CWE-694",),
    tags=("plugin", "components"),
    check=check_duplicate_components,
    no_context=True,
)
_rule(RULE_COMPONENT_DUPLICATE)

RULE_MARKETPLACE_UNPINNED = Rule(
    id="AST07-PLUGIN-MARKETPLACE-UNPINNED",
    ast="AST07",
    title="Marketplace source is not pinned to an immutable revision",
    severity=Severity.MEDIUM,
    confidence=Confidence.HIGH,
    description="A git-backed marketplace entry uses a mutable ref or a short or missing sha, so the plugin content can change without a new review.",
    remediation="Pin a full 40-hex commit sha and a release tag. Re-audit whenever the pin moves.",
    cwes=("CWE-494",),
    tags=("plugin", "marketplace", "supply-chain"),
    check=check_marketplace_pinning,
    no_context=True,
)
_rule(RULE_MARKETPLACE_UNPINNED)

RULE_BROAD_TOOL_GRANT = Rule(
    id="AST03-PLUGIN-BROAD-TOOL-GRANT",
    ast="AST03",
    title="Component grants a wildcard tool scope",
    severity=Severity.HIGH,
    confidence=Confidence.HIGH,
    description="A command or agent declares a wildcard or administrative tool grant. The component can do more than its stated task requires.",
    remediation="Grant the smallest set of tools the component needs. Avoid '*', 'all', and administrative scopes.",
    cwes=("CWE-250",),
    tags=("plugin", "components", "permissions"),
    check=check_component_broad_tools,
    no_context=True,
)
_rule(RULE_BROAD_TOOL_GRANT)

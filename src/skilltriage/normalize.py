"""Normalise the platform-specific skill formats into one model.

Supported inputs:

* ``SKILL.md`` YAML frontmatter (Claude Code, OpenClaw and compatible tools)
* ``skill.json`` (Claude-style manifests)
* ``manifest.json`` (Cursor/Codex-style manifests)
* ``package.json`` (VS Code-style extension metadata)
* universal ``skill.yaml`` / ``agent-skill.yaml`` (OWASP AST10 format)
* Claude Code plugin manifests: ``.claude-plugin/plugin.json``,
  ``.claude-plugin/marketplace.json``, ``hooks/hooks.json``, ``.mcp.json``,
  and ``commands/`` / ``agents/`` / ``skills/`` components

The normaliser is intentionally lossless enough to compare security properties
across formats (AST10) without pretending that the formats are equivalent.
"""

from __future__ import annotations

import fnmatch
import re
from pathlib import Path
from typing import Any

from .intent import extract_declared_intent
from .models import (
    HookEvent,
    ManifestRecord,
    McpServer,
    NormalizedPlugin,
    NormalizedSkill,
    ParseIssue,
    Permissions,
    PluginComponent,
    PluginIdentity,
    Severity,
)
from .parsers import (
    find_anchors,
    find_unsafe_tags,
    parse_json_text,
    parse_toml_text,
    parse_yaml_subset,
    split_frontmatter,
)

MANIFEST_SPECS: dict[str, tuple[str, str, str]] = {
    "SKILL.md": ("markdown", "claude-code/openclaw", "yaml"),
    "skill.json": ("json", "claude-code", "json"),
    "manifest.json": ("json", "cursor/codex", "json"),
    "package.json": ("json", "vscode/npm", "json"),
    "skill.yaml": ("yaml", "universal", "yaml"),
    "skill.yml": ("yaml", "universal", "yaml"),
    "SKILL.yaml": ("yaml", "universal", "yaml"),
    "SKILL.yml": ("yaml", "universal", "yaml"),
    "agent-skill.yaml": ("yaml", "universal", "yaml"),
    "agent-skill.yml": ("yaml", "universal", "yaml"),
    "agent-skill.json": ("json", "universal", "json"),
    ".claude-plugin/plugin.json": ("json", "claude-plugin", "json"),
    ".claude-plugin/marketplace.json": ("json", "claude-plugin-marketplace", "json"),
    "hooks/hooks.json": ("json", "claude-plugin-hooks", "json"),
    ".mcp.json": ("json", "mcp", "json"),
}

# These are the manifests that can carry skill-level security properties.
SKILL_MANIFESTS = {"SKILL.md", "skill.json", "manifest.json", "skill.yaml", "skill.yml",
                   "SKILL.yaml", "SKILL.yml", "agent-skill.yaml", "agent-skill.yml",
                   "agent-skill.json"}

KNOWN_TOP_LEVEL_KEYS = {
    "name", "description", "version", "license", "author", "permissions", "metadata",
    "compatibility", "allowed-tools", "allowed_tools", "tools", "risk_tier", "risk-tier",
    "signature", "content_hash", "contentHash", "scan_status", "scanStatus", "platforms",
    "requires", "dependencies", "changelog", "homepage", "repository", "keywords",
    "$schema", "manifest_version", "publisher", "displayName", "engines", "contributes",
    "activationEvents", "main", "scripts", "files", "icon", "categories", "activation",
    "user-invocable", "argument-hint", "context", "agent", "model", "hooks", "mcpServers",
    # Claude Code plugin and marketplace keys
    "commands", "agents", "skills", "owner", "source", "plugins", "renames",
    "userConfig", "experimental", "category", "tags", "strict",
}

_IDENTITY_FILES = {"soul.md", "memory.md", "agents.md", "claude.md", "gemini.md"}


def _as_list(value: Any) -> list[str]:
    if value is None:
        return []
    if isinstance(value, str):
        return [part.strip() for part in re.split(r"[,\s]+", value) if part.strip()]
    if isinstance(value, (list, tuple, set)):
        result: list[str] = []
        for item in value:
            if isinstance(item, str):
                result.append(item.strip())
            elif isinstance(item, dict):
                result.extend(str(v).strip() for v in item.values() if isinstance(v, str))
        return [item for item in result if item]
    return []


def _as_bool_or_string(value: Any) -> bool | str | None:
    if value is None:
        return None
    if isinstance(value, bool):
        return value
    if isinstance(value, str):
        return value
    return bool(value)


def normalize_permissions(value: Any, extra_tools: Any = None) -> Permissions:
    """Normalise the several permission shapes found in the wild."""
    permissions = Permissions()
    if value is None and extra_tools is None:
        return permissions
    permissions.declared = value is not None
    permissions.raw = value

    if isinstance(value, str):
        lowered = value.strip().lower()
        if lowered in ("full", "full_access", "all", "admin", "unrestricted", "*"):
            permissions.shell = True
            permissions.network = True
            permissions.tools = ["*"]
        elif lowered in ("none", "denied", "no", "read-only", "readonly"):
            permissions.shell = False
            permissions.network = False
        return permissions

    if isinstance(value, list):
        for item in value:
            if not isinstance(item, str):
                continue
            lowered = item.strip().lower()
            if lowered in ("full_access", "all", "*", "admin"):
                permissions.shell = True
                permissions.network = True
                permissions.tools.append("*")
            elif lowered.startswith(("filesystem:read", "files:read", "read_files")):
                permissions.files_read.append("*")
            elif lowered.startswith(("filesystem:write", "files:write", "write_files")):
                permissions.files_write.append("*")
            elif lowered.startswith(("network", "network:outbound")):
                permissions.network = True
            elif lowered in ("shell", "shell:true", "execute", "exec"):
                permissions.shell = True
            elif lowered.startswith(("tool:", "tools:")):
                permissions.tools.append(item.split(":", 1)[1])
            else:
                permissions.tools.append(item)
        return permissions

    if not isinstance(value, dict):
        return permissions

    shell = value.get("shell")
    if isinstance(shell, dict):
        shell = shell.get("enabled", shell.get("allow"))
    permissions.shell = _as_bool_or_string(shell)

    network = value.get("network")
    if isinstance(network, dict):
        allow = network.get("allow", network.get("allowed", network.get("domains")))
        deny = network.get("deny", network.get("denied"))
        if allow is not None:
            permissions.network_allow = _as_list(allow)
            permissions.network = bool(permissions.network_allow)
        if deny is not None:
            permissions.network_deny = deny if isinstance(deny, str) else _as_list(deny)
        if "enabled" in network:
            permissions.network = bool(network["enabled"])
        if network.get("outbound") is not None and permissions.network is None:
            permissions.network = bool(network["outbound"])
    elif network is not None:
        permissions.network = _as_bool_or_string(network)

    files = value.get("files", value.get("filesystem", value.get("fs")))
    if isinstance(files, dict):
        permissions.files_read = _as_list(files.get("read"))
        permissions.files_write = _as_list(files.get("write"))
        permissions.deny_write = _as_list(files.get("deny_write", files.get("denyWrite")))
    elif files is not None:
        permissions.files_read = _as_list(files)

    permissions.tools = _as_list(value.get("tools", value.get("tool")))
    if extra_tools is not None:
        permissions.tools.extend(_as_list(extra_tools))
        permissions.declared = True
    return permissions


def _permission_manifest(manifest: ManifestRecord) -> Permissions | None:
    data = manifest.data if isinstance(manifest.data, dict) else {}
    if not data:
        return None
    if "permissions" in data or "allowed-tools" in data or "allowed_tools" in data:
        return normalize_permissions(
            data.get("permissions"),
            data.get("allowed-tools", data.get("allowed_tools")),
        )
    return None


def _author_string(value: Any) -> str:
    if isinstance(value, str):
        return value
    if isinstance(value, dict):
        for key in ("name", "identity", "url", "email"):
            if value.get(key):
                return str(value[key])
    return ""


def _first(data: dict[str, Any], *keys: str) -> Any:
    for key in keys:
        if key in data and data[key] not in (None, ""):
            return data[key]
    return None


def read_text_file(path: Path, limit: int = 2 * 1024 * 1024) -> str:
    try:
        with open(path, "rb") as handle:
            return handle.read(limit).decode("utf-8", "replace")
    except OSError:
        return ""


def _platform_for(relpath: str) -> str:
    spec = MANIFEST_SPECS.get(relpath)
    if spec:
        return spec[1]
    parts = relpath.split("/")
    if parts and parts[0] == ".claude":
        parts = parts[1:]
    if parts and parts[0] == "commands":
        return "claude-plugin/command"
    if parts and parts[0] == "agents":
        return "claude-plugin/agent"
    if relpath.endswith("SKILL.md"):
        return "claude-code"
    return "unknown"


def parse_manifest_text(relpath: str, text: str) -> ManifestRecord:
    """Parse a manifest from already-loaded text (no second disk read)."""
    platform = _platform_for(relpath)
    spec = MANIFEST_SPECS.get(relpath)
    if spec:
        fmt = spec[2]
    elif relpath.endswith(".md"):
        fmt = "markdown"
    elif relpath.endswith(".json"):
        fmt = "json"
    else:
        fmt = "yaml"
    issues: list[ParseIssue] = []

    if relpath.endswith(".md"):
        frontmatter = split_frontmatter(text)
        issues.extend(frontmatter.issues)
        if not frontmatter.found:
            return ManifestRecord(
                path=relpath,
                platform=platform,
                fmt="markdown",
                data={},
                issues=issues,
                raw_length=len(text),
                has_frontmatter=False,
            )
        data, yaml_issues = parse_yaml_subset(frontmatter.meta_text)
        issues.extend(yaml_issues)
        # Re-scan raw frontmatter so tags in comments or skipped lines are seen.
        for line_no, tag in find_unsafe_tags(frontmatter.meta_text):
            if not any(issue.code == "UNSAFE_YAML_TAG" and issue.line in (None, line_no + 1) for issue in issues):
                issues.append(
                    ParseIssue(
                        "UNSAFE_YAML_TAG",
                        f"Unsafe YAML tag in frontmatter: {tag!r}.",
                        line_no + 1,
                        Severity.CRITICAL,
                    )
                )
        for line_no, anchor in find_anchors(frontmatter.meta_text):
            if not any(issue.code == "YAML_ANCHOR_ALIAS" and issue.line in (None, line_no + 1) for issue in issues):
                issues.append(
                    ParseIssue(
                        "YAML_ANCHOR_ALIAS",
                        f"YAML anchor or alias in frontmatter: {anchor!r}.",
                        line_no + 1,
                        Severity.MEDIUM,
                    )
                )
        return ManifestRecord(
            path=relpath,
            platform=platform,
            fmt="markdown",
            data=data,
            issues=issues,
            raw_length=len(text),
            has_frontmatter=frontmatter.found,
            body_line=frontmatter.body_line,
        )

    if relpath.endswith(".json"):
        data, json_issues = parse_json_text(text)
        issues.extend(json_issues)
    else:
        data, yaml_issues = parse_yaml_subset(text)
        issues.extend(yaml_issues)
    return ManifestRecord(
        path=relpath,
        platform=platform,
        fmt=fmt,
        data=data,
        issues=issues,
        raw_length=len(text),
    )


def load_manifest(root: Path, relpath: str) -> ManifestRecord | None:
    """Read and parse one manifest from disk.

    Prefer :func:`parse_manifest_text` with text from the loaded tree so the
    audited bytes cannot change between the walk and the parse.
    """
    path = root / relpath
    if not path.is_file() or path.is_symlink():
        return None
    return parse_manifest_text(relpath, read_text_file(path))


def discover_manifests(
    root: Path, relpaths: set[str], texts: dict[str, str] | None = None
) -> list[ManifestRecord]:
    manifests: list[ManifestRecord] = []
    for name in sorted(MANIFEST_SPECS):
        if name not in relpaths:
            continue
        if texts is not None:
            if name not in texts:
                continue
            manifest = parse_manifest_text(name, texts[name])
        else:
            manifest = load_manifest(root, name)
        if manifest is not None:
            manifests.append(manifest)
    return manifests


def find_plugin_manifest(root: Path, root_only: bool = False) -> dict[str, Any] | None:
    """Find a Claude plugin manifest for context.

    Plugin targets pass ``root_only=True`` so the audited root is the only
    boundary. Skill targets inside a plugin cache may look up a few parents,
    which supplies plugin identity without reading outside the cache.
    """
    current = root
    for _ in range(1 if root_only else 5):
        candidate = current / ".claude-plugin" / "plugin.json"
        if candidate.is_file() and not candidate.is_symlink():
            manifest = parse_manifest_text(
                ".claude-plugin/plugin.json", read_text_file(candidate)
            )
            return manifest.data or None
        if current.parent == current:
            break
        current = current.parent
    return None


def normalize_skill(
    manifests: list[ManifestRecord],
    plugin: dict[str, Any] | None = None,
    preferred_paths: tuple[str, ...] = (),
) -> NormalizedSkill:
    skill = NormalizedSkill(manifests=manifests)
    primary = next(
        (m for m in manifests if m.path in preferred_paths and m.data), None
    )
    if primary is None:
        primary = next((m for m in manifests if m.path == "SKILL.md" and m.data), None)
    if primary is None:
        primary = next((m for m in manifests if m.path in SKILL_MANIFESTS and m.data), None)
    if primary is None:
        primary = next((m for m in manifests if m.data), None)
    data: dict[str, Any] = primary.data if primary and isinstance(primary.data, dict) else {}
    metadata = data.get("metadata") if isinstance(data.get("metadata"), dict) else {}

    skill.name = str(_first(data, "name") or (plugin or {}).get("name") or "")
    skill.version = str(
        _first(data, "version")
        or metadata.get("version")
        or (plugin or {}).get("version")
        or ""
    )
    skill.description = str(_first(data, "description") or (plugin or {}).get("description") or "")
    skill.license = str(_first(data, "license", "licenseName") or (plugin or {}).get("license") or "")
    skill.author = _author_string(data.get("author") or (plugin or {}).get("author"))
    skill.metadata = metadata
    skill.intent_declared, skill.declared_intent = extract_declared_intent(metadata)

    platforms = _first(data, "platforms")
    skill.platforms = _as_list(platforms)
    for manifest in manifests:
        if manifest.platform and manifest.platform not in skill.platforms:
            skill.platforms.append(manifest.platform)

    skill.risk_tier = str(_first(data, "risk_tier", "risk-tier") or metadata.get("risk_tier") or "").upper()
    if skill.risk_tier and not re.fullmatch(r"L[0-3]", skill.risk_tier):
        skill.risk_tier = skill.risk_tier[:3]
    skill.signature = str(_first(data, "signature") or metadata.get("signature") or "")
    skill.content_hash = str(
        _first(data, "content_hash", "contentHash") or metadata.get("content_hash") or ""
    )
    skill.scan_status = _first(data, "scan_status", "scanStatus") or metadata.get("scan_status")
    skill.requires = _first(data, "requires", "dependencies")

    for manifest in manifests:
        permissions = _permission_manifest(manifest)
        if permissions is not None:
            skill.permissions = permissions
            break

    skill.unknown_keys = sorted(set(data.keys()) - KNOWN_TOP_LEVEL_KEYS)
    if plugin:
        skill.plugin_name = str(plugin.get("name") or "")
        skill.plugin_version = str(plugin.get("version") or "")
    return skill


def build_skill(
    root: Path,
    relpaths: set[str],
    texts: dict[str, str] | None = None,
    plugin: dict[str, Any] | None = None,
    preferred_paths: tuple[str, ...] = (),
) -> NormalizedSkill:
    manifests = discover_manifests(root, relpaths, texts)
    if plugin is None:
        plugin = find_plugin_manifest(root)
    return normalize_skill(manifests, plugin, preferred_paths)


# ---------------------------------------------------------------------------
# Claude Code plugins


def _declared_paths(data: dict[str, Any]) -> dict[str, tuple[str, ...]]:
    declared: dict[str, tuple[str, ...]] = {}
    for kind in ("commands", "agents", "skills"):
        value = data.get(kind)
        if value is None:
            continue
        declared[kind] = tuple(_as_list(value))
    return declared


def _component_name(kind: str, path: str) -> str:
    parts = [part for part in path.split("/") if part]
    if parts and parts[-1] == "SKILL.md" and len(parts) >= 2:
        return parts[-2]
    if parts:
        return Path(parts[-1]).stem
    return kind


def _expand_declared(entry: str, relpaths: set[str]) -> list[str]:
    """Resolve one declared component path or glob against the loaded tree."""
    value = entry.strip().replace("\\", "/")
    while value.startswith("./"):
        value = value[2:]
    if not value or value.startswith("/") or ".." in value.split("/"):
        return []
    if any(char in value for char in "*?["):
        return sorted(path for path in relpaths if fnmatch.fnmatch(path, value))
    if value.endswith("/"):
        prefix = value.rstrip("/")
        return sorted(path for path in relpaths if path.startswith(prefix + "/"))
    if value in relpaths:
        return [value]
    # A declared directory without a trailing slash.
    prefix = value + "/"
    matches = sorted(path for path in relpaths if path.startswith(prefix))
    return matches


def _component_from_text(
    kind: str, path: str, text: str, declared: bool
) -> PluginComponent | None:
    if not path.endswith((".md", ".yaml", ".yml")):
        return None
    frontmatter: dict[str, Any] = {}
    if path.endswith(".md"):
        front = split_frontmatter(text)
        if front.found:
            parsed, _ = parse_yaml_subset(front.meta_text)
            if isinstance(parsed, dict):
                frontmatter = parsed
    else:
        parsed, _ = parse_yaml_subset(text)
        if isinstance(parsed, dict):
            frontmatter = parsed
    tools = _as_list(
        frontmatter.get("allowed-tools", frontmatter.get("allowed_tools", frontmatter.get("tools")))
    )
    return PluginComponent(
        kind=kind,
        name=str(frontmatter.get("name") or _component_name(kind, path)),
        path=path,
        declared=declared,
        allowed_tools=tuple(tools),
        model=str(frontmatter.get("model") or ""),
        frontmatter=frontmatter,
    )


def discover_components(
    relpaths: set[str],
    texts: dict[str, str],
    declared: dict[str, tuple[str, ...]],
) -> list[PluginComponent]:
    """Collect command, agent, and bundled-skill components.

    Declared paths are honoured first, then the conventional directories.
    Only paths that exist in the loaded tree are included; escapes and missing
    declarations are reported by rules, not silently resolved.
    """
    components: list[PluginComponent] = []
    seen: set[str] = set()

    def add(kind: str, path: str, is_declared: bool) -> None:
        if path in seen or path not in texts:
            return
        lowered = path.lower()
        # A bundled skill is exactly a SKILL.md, not every document under a
        # declared skills directory.
        if kind == "skill" and not (
            lowered.endswith("/skill.md") or lowered == "skill.md"
        ):
            return
        if kind in ("command", "agent") and lowered.endswith("/skill.md"):
            return
        if kind in ("command", "agent") and lowered.rsplit("/", 1)[-1] == "readme.md":
            return
        component = _component_from_text(kind, path, texts[path], is_declared)
        if component is not None:
            seen.add(path)
            components.append(component)

    declared_kind = {"commands": "command", "agents": "agent", "skills": "skill"}
    for key, kind in declared_kind.items():
        for entry in declared.get(key, ()):
            for path in _expand_declared(entry, relpaths):
                add(kind, path, True)

    for path in sorted(relpaths):
        parts = path.split("/")
        scope = parts[1:] if parts and parts[0] == ".claude" else parts
        if not scope:
            continue
        if len(scope) > 1 and scope[0] == "commands":
            add("command", path, False)
        elif len(scope) > 1 and scope[0] == "agents":
            add("agent", path, False)
        elif (
            len(scope) == 3
            and scope[0] == "skills"
            and scope[-1] == "SKILL.md"
        ):
            # ``skills/<name>/SKILL.md`` only; deeper files are references,
            # not additional bundled skills.
            add("skill", path, False)
    return sorted(components, key=lambda item: (item.kind, item.path))


def parse_hooks(
    manifest: ManifestRecord | None, plugin_data: dict[str, Any]
) -> list[HookEvent]:
    blocks: list[dict[str, Any]] = []
    if manifest is not None and isinstance(manifest.data, dict):
        blocks.append(manifest.data)
    hooks_value = plugin_data.get("hooks")
    if isinstance(hooks_value, dict):
        blocks.append(hooks_value)

    events: list[HookEvent] = []
    seen: set[tuple[str, str, str, str]] = set()
    for block in blocks:
        hooks = block.get("hooks") if isinstance(block.get("hooks"), dict) else block
        if not isinstance(hooks, dict):
            continue
        for event, entries in hooks.items():
            if not isinstance(entries, list):
                continue
            for entry in entries:
                if not isinstance(entry, dict):
                    continue
                matcher = str(entry.get("matcher") or "")
                inner = entry.get("hooks")
                hook_entries = inner if isinstance(inner, list) else [entry]
                for hook in hook_entries:
                    if not isinstance(hook, dict):
                        continue
                    item = HookEvent(
                        event=str(event),
                        matcher=matcher,
                        type=str(hook.get("type") or "command"),
                        command=str(hook.get("command") or ""),
                        timeout=hook.get("timeout")
                        if isinstance(hook.get("timeout"), int)
                        else None,
                        is_async=bool(hook.get("async") or hook.get("asyncRewake")),
                        condition=str(hook.get("if") or ""),
                    )
                    key = (item.event, item.matcher, item.type, item.command)
                    if key not in seen:
                        seen.add(key)
                        events.append(item)
    return sorted(events, key=lambda item: (item.event, item.matcher, item.command))


def parse_mcp(manifest: ManifestRecord | None) -> list[McpServer]:
    if manifest is None or not isinstance(manifest.data, dict):
        return []
    data = manifest.data
    servers = data.get("mcpServers")
    if not isinstance(servers, dict):
        # Some plugins use a bare map: {"github": {"type": "http", ...}}.
        servers = {
            key: value
            for key, value in data.items()
            if isinstance(value, dict) and ("command" in value or "url" in value)
        }
    result: list[McpServer] = []
    for name, spec in servers.items():
        if not isinstance(spec, dict):
            continue
        transport = str(
            spec.get("type")
            or ("http" if spec.get("url") else "stdio" if spec.get("command") else "")
        )
        args = spec.get("args")
        env = spec.get("env")
        headers = spec.get("headers")
        result.append(
            McpServer(
                name=str(name),
                transport=transport,
                command=str(spec.get("command") or ""),
                args=tuple(str(arg) for arg in args)
                if isinstance(args, list)
                else (),
                env_keys=tuple(sorted(str(key) for key in env))
                if isinstance(env, dict)
                else (),
                url=str(spec.get("url") or ""),
                header_names=tuple(sorted(str(key) for key in headers))
                if isinstance(headers, dict)
                else (),
                cwd=str(spec.get("cwd") or ""),
            )
        )
    return sorted(result, key=lambda item: item.name)


def _source_fields(source: Any) -> tuple[str, str, str, str]:
    """Return ``(kind, value, ref, sha)`` for a marketplace source entry."""
    if isinstance(source, str):
        return "path", source, "", ""
    if isinstance(source, dict):
        return (
            str(source.get("source") or ""),
            str(
                source.get("url")
                or source.get("path")
                or source.get("repo")
                or ""
            ),
            str(source.get("ref") or ""),
            str(source.get("sha") or ""),
        )
    return "", "", "", ""


def _marketplace_entry(
    manifest: ManifestRecord | None, plugin_name: str
) -> tuple[dict[str, Any], str]:
    if manifest is None or not isinstance(manifest.data, dict):
        return {}, ""
    data = manifest.data
    entries = data.get("plugins")
    if not isinstance(entries, list):
        return {}, str(data.get("name") or "")
    for entry in entries:
        if not isinstance(entry, dict):
            continue
        source = entry.get("source")
        if str(entry.get("name") or "") == plugin_name or source in (".", "./"):
            return entry, str(data.get("name") or "")
    return {}, str(data.get("name") or "")


def build_plugin(
    root: Path, relpaths: set[str], texts: dict[str, str]
) -> NormalizedPlugin:
    """Build the plugin artifact model from loaded bytes only."""
    manifests = discover_manifests(root, relpaths, texts)
    by_path = {manifest.path: manifest for manifest in manifests}
    plugin_manifest = by_path.get(".claude-plugin/plugin.json")
    data = (
        plugin_manifest.data
        if plugin_manifest is not None and isinstance(plugin_manifest.data, dict)
        else {}
    )
    identity = PluginIdentity(
        name=str(_first(data, "name") or root.name),
        version=str(_first(data, "version") or ""),
        description=str(_first(data, "description") or ""),
        author=_author_string(data.get("author")),
        license=str(_first(data, "license", "licenseName") or ""),
        homepage=str(_first(data, "homepage") or ""),
        repository=str(_first(data, "repository") or ""),
        declared_paths=_declared_paths(data),
    )

    entry, marketplace_name = _marketplace_entry(
        by_path.get(".claude-plugin/marketplace.json"),
        identity.name,
    )
    if entry:
        source_kind, source_value, ref, sha = _source_fields(entry.get("source"))
        identity.marketplace = marketplace_name
        identity.source_kind = source_kind
        identity.source = source_value
        identity.ref = ref
        identity.sha = sha

    hooks = parse_hooks(by_path.get("hooks/hooks.json"), data)
    servers = parse_mcp(by_path.get(".mcp.json"))
    components = discover_components(relpaths, texts, identity.declared_paths)
    unknown_keys = {
        manifest.path: sorted(set(manifest.data.keys()) - KNOWN_TOP_LEVEL_KEYS)
        for manifest in manifests
        if isinstance(manifest.data, dict) and manifest.data
    }
    return NormalizedPlugin(
        identity=identity,
        components=components,
        hooks=hooks,
        mcp_servers=servers,
        marketplace_entry=entry,
        manifests=manifests,
        unknown_keys=unknown_keys,
    )

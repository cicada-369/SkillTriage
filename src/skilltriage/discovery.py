"""Discovery of installed skills.

The defaults cover Claude Code personal skills, plugin caches, marketplaces,
and a few other agent locations when present. Every root is optional: a missing
directory is skipped. Discovery never follows symlinks and never reads outside
the roots it was given.
"""

from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path

from .loader import SKIP_DIR_NAMES, VENDOR_DIR_NAMES

MAX_DEPTH = 10
MAX_SKILLS = 10_000

DEFAULT_ROOTS: list[tuple[str, str]] = [
    ("personal", "~/.claude/skills"),
    ("plugin-cache", "~/.claude/plugins/cache"),
    ("marketplace", "~/.claude/plugins/marketplaces"),
    ("opencode", "~/.config/opencode/skills"),
    ("codex", "~/.codex/skills"),
    ("cursor", "~/.cursor/skills"),
]
_PRIORITY = {
    "personal": 0,
    "project": 1,
    "plugin-cache": 2,
    "opencode": 3,
    "codex": 3,
    "cursor": 3,
    "marketplace": 4,
    "other": 5,
}


@dataclass
class DiscoveredSkill:
    path: Path
    kind: str
    name: str
    plugin: str = ""
    version: str = ""
    display: str = ""
    skill_id: str = ""
    artifact_kind: str = "skill"

    def to_dict(self) -> dict[str, str]:
        return {
            "path": str(self.path),
            "kind": self.kind,
            "name": self.name,
            "plugin": self.plugin,
            "version": self.version,
            "display": self.display,
            "skill_id": self.skill_id,
            "artifact_kind": self.artifact_kind,
        }


def _find_skill_dirs(root: Path):
    if not root.is_dir():
        return
    for dirpath, dirnames, filenames in os.walk(root, followlinks=False):
        try:
            relative = Path(dirpath).relative_to(root)
        except ValueError:
            relative = Path(".")
        depth = len(relative.parts)
        if depth > MAX_DEPTH:
            dirnames[:] = []
            continue
        dirnames[:] = [
            name
            for name in dirnames
            if name not in SKIP_DIR_NAMES and name not in VENDOR_DIR_NAMES
        ]
        if "SKILL.md" in filenames:
            yield Path(dirpath)
            dirnames[:] = []


def _find_artifacts(root: Path, mode: str):
    """Yield ``(path, artifact_kind, relative_parts)`` under ``root``.

    ``mode`` is ``skills`` (legacy skill-by-skill view), ``plugins``, or
    ``both``. In ``plugins``/``both`` a plugin root is yielded once and its
    subtree pruned, so its bundled skills are components rather than separate
    targets. In ``skills`` mode the walk descends exactly as before.
    """
    if not root.is_dir():
        return
    for dirpath, dirnames, filenames in os.walk(root, followlinks=False):
        current = Path(dirpath)
        try:
            relative = current.relative_to(root)
        except ValueError:
            relative = Path(".")
        depth = len(relative.parts)
        if depth > MAX_DEPTH:
            dirnames[:] = []
            continue
        dirnames[:] = [
            name
            for name in dirnames
            if name not in SKIP_DIR_NAMES and name not in VENDOR_DIR_NAMES
        ]
        has_plugin = (current / ".claude-plugin" / "plugin.json").is_file()
        if has_plugin and mode in ("plugins", "both"):
            yield current, "plugin", relative.parts
            dirnames[:] = []
            continue
        if "SKILL.md" in filenames and mode in ("skills", "both"):
            yield current, "skill", relative.parts
            dirnames[:] = []


def _plugin_identity(path: Path) -> tuple[str, str, str, str]:
    """Return ``(market, plugin, version, skill_name)`` for a plugin path."""
    parts = path.parts
    for marker in ("cache", "marketplaces"):
        if marker not in parts:
            continue
        index = parts.index(marker)
        rest = parts[index + 1 :]
        if "skills" in rest:
            skill_index = rest.index("skills")
            name = rest[skill_index + 1] if skill_index + 1 < len(rest) else path.name
            prefix = rest[:skill_index]
        else:
            prefix = rest[:-1]
            name = path.name
        if marker == "cache":
            market = prefix[0] if prefix else ""
            plugin = prefix[1] if len(prefix) > 1 else market
            version = prefix[2] if len(prefix) > 2 else ""
            return market, plugin, version, name
        market = prefix[0] if prefix else ""
        if len(prefix) >= 3 and prefix[1] in ("plugins", "external_plugins"):
            plugin = prefix[2]
            version = ""
        else:
            plugin = prefix[1] if len(prefix) > 1 else market
            version = prefix[2] if len(prefix) > 2 else ""
        return market, plugin, version, name
    return "", "", "", path.name


def _make(path: Path, kind: str, project: str = "") -> DiscoveredSkill:
    market, plugin, version, name = _plugin_identity(path)
    if kind in ("plugin-cache", "marketplace") and not market:
        name = path.name
    display_parts = [kind]
    identity = plugin or market
    if identity:
        display_parts.append(identity + (f"@{version}" if version else ""))
    if project:
        display_parts.append(project)
    display_parts.append(name)
    display = "/".join(part for part in display_parts if part)
    if kind == "personal":
        skill_id = f"personal:{name}"
    elif kind == "project":
        skill_id = f"project:{project}:{name}"
    elif kind in ("plugin-cache", "marketplace"):
        prefix = f"{market}/{plugin}" if market and plugin else (market or plugin or "plugin")
        suffix = f"@{version}" if version else ""
        skill_id = f"{kind}:{prefix}{suffix}:{name}"
    else:
        skill_id = f"{kind}:{name}"
    return DiscoveredSkill(
        path=path,
        kind=kind,
        name=name,
        plugin=f"{market}/{plugin}" if market and plugin else (plugin or market),
        version=version,
        display=display,
        skill_id=skill_id,
    )


def _make_plugin(path: Path, kind: str, parts: tuple[str, ...]) -> DiscoveredSkill:
    """Identity for a plugin root, derived from its layout under the root."""
    market = ""
    plugin = ""
    version = ""
    if kind == "plugin-cache":
        if len(parts) >= 3:
            market, plugin, version = parts[0], parts[1], parts[2]
        elif len(parts) == 2:
            market, plugin = parts[0], parts[1]
        else:
            plugin = path.name
    elif kind == "marketplace":
        if len(parts) >= 3 and parts[1] in ("plugins", "external_plugins"):
            market, plugin = parts[0], parts[2]
        elif len(parts) >= 2:
            market, plugin = parts[0], parts[1]
        else:
            plugin = path.name
    else:
        plugin = path.name
    plugin = plugin or path.name
    identity = f"{market}/{plugin}" if market else plugin
    if version:
        identity = f"{identity}@{version}"
    display = f"{kind}/{identity}" if identity else kind
    skill_id = f"{kind}:{identity}" if kind in ("plugin-cache", "marketplace") else f"{kind}:{plugin}"
    return DiscoveredSkill(
        path=path,
        kind=kind,
        name=plugin,
        plugin=identity,
        version=version,
        display=display,
        skill_id=skill_id,
        artifact_kind="plugin",
    )


def _kind_for(path: Path, hint: str) -> str:
    if hint in ("personal", "project"):
        return hint
    parts = path.parts
    if "cache" in parts and "plugins" in parts:
        return "plugin-cache"
    if "marketplaces" in parts:
        return "marketplace"
    if ".claude" in parts and "skills" in parts:
        return "personal"
    return hint if hint in _PRIORITY else "other"


def _hint_for_root(path: str) -> str:
    lowered = path.replace("\\", "/").lower()
    if "/plugins/cache" in lowered or lowered.endswith("/cache"):
        return "plugin-cache"
    if "marketplaces" in lowered:
        return "marketplace"
    if lowered.endswith("/skills") or "/.claude/skills" in lowered:
        return "personal"
    return "other"


def discover(
    roots: list[str] | None = None,
    projects: list[str] | None = None,
    include_marketplaces: bool = True,
    artifacts: str = "skills",
) -> list[DiscoveredSkill]:
    if artifacts not in ("skills", "plugins", "both"):
        raise ValueError(f"unknown artifact mode: {artifacts}")
    found: dict[str, DiscoveredSkill] = {}
    # Passing explicit roots means "scan these", not "scan these in addition to
    # the machine defaults". This keeps CI and fixture scans hermetic.
    if roots:
        root_specs: list[tuple[str, str]] = [(_hint_for_root(root), root) for root in roots]
    else:
        root_specs = list(DEFAULT_ROOTS)

    for kind_hint, root_value in root_specs:
        if kind_hint == "marketplace" and not include_marketplaces:
            continue
        root = Path(root_value).expanduser()
        if not root.is_dir():
            continue
        for artifact_path, artifact_kind, parts in _find_artifacts(root, artifacts):
            kind = _kind_for(artifact_path, kind_hint)
            if kind == "marketplace" and not include_marketplaces:
                continue
            if artifact_kind == "plugin":
                skill = _make_plugin(artifact_path, kind, parts)
            else:
                skill = _make(artifact_path, kind)
            _insert(found, skill)
            if len(found) >= MAX_SKILLS:
                break

    for project_value in projects or []:
        project = Path(project_value).expanduser()
        if not project.is_dir():
            continue
        for candidate in (project / ".claude" / "skills", project / "skills"):
            if not candidate.is_dir():
                continue
            for artifact_path, artifact_kind, _parts in _find_artifacts(
                candidate, artifacts
            ):
                if artifact_kind != "skill":
                    continue
                _insert(found, _make(artifact_path, "project", project.name))

    return sorted(found.values(), key=lambda skill: skill.display.lower())


def _insert(found: dict[str, DiscoveredSkill], skill: DiscoveredSkill) -> None:
    try:
        key = str(skill.path.resolve())
    except OSError:
        key = str(skill.path)
    existing = found.get(key)
    if existing is None or _PRIORITY.get(skill.kind, 99) < _PRIORITY.get(existing.kind, 99):
        found[key] = skill

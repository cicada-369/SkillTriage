"""Policy, profiles, configuration, and the gating rule.

The default gate is deliberately conservative: only high-confidence findings
at HIGH or CRITICAL fail a scan. Warnings remain visible. ``--profile strict``
lowers the gate for release pipelines, and ``--profile advisory`` never fails.
"""

from __future__ import annotations

import tomllib
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from .models import Confidence, Finding, Severity

PROFILE_DEFAULTS: dict[str, tuple[Severity | None, Confidence]] = {
    "advisory": (None, Confidence.HIGH),
    "default": (Severity.HIGH, Confidence.HIGH),
    "strict": (Severity.MEDIUM, Confidence.MEDIUM),
}


class ConfigError(Exception):
    pass


@dataclass
class AuditOptions:
    profile: str = "default"
    fail_on: Severity | None = Severity.HIGH
    min_confidence: Confidence = Confidence.HIGH
    include_vendor: bool = False
    max_file_bytes: int = 2 * 1024 * 1024
    max_total_bytes: int = 256 * 1024 * 1024
    max_files: int = 10_000
    max_archive_entries: int = 10_000
    max_archive_uncompressed: int = 256 * 1024 * 1024
    max_archive_bytes: int = 64 * 1024 * 1024
    show_suppressed: bool = False
    show_baselined: bool = False
    trust_inline_suppressions: bool = False
    allowed_intents: list[str] = field(default_factory=list)
    verbose: bool = False
    color: bool = True
    inventory_path: str | None = None
    inventory_enabled: bool = False
    require_inventory: bool = False
    baseline_path: str | None = None
    write_baseline: str | None = None
    update_inventory: bool = False
    include_marketplaces: bool = True
    discovery_roots: list[str] = field(default_factory=list)
    config: dict[str, Any] = field(default_factory=dict)

    def loader_limits(self):
        from .loader import LoaderLimits

        return LoaderLimits(
            max_file_bytes=self.max_file_bytes,
            max_total_bytes=self.max_total_bytes,
            max_files=self.max_files,
            max_archive_entries=self.max_archive_entries,
            max_archive_uncompressed=self.max_archive_uncompressed,
            max_archive_bytes=self.max_archive_bytes,
            include_vendor=self.include_vendor,
        )


def _deep_merge(base: dict[str, Any], override: dict[str, Any]) -> dict[str, Any]:
    result = dict(base)
    for key, value in override.items():
        if isinstance(value, dict) and isinstance(result.get(key), dict):
            result[key] = _deep_merge(result[key], value)
        else:
            result[key] = value
    return result


def _read_config(path: Path) -> dict[str, Any]:
    try:
        with open(path, "rb") as handle:
            data = tomllib.load(handle)
    except OSError as exc:
        raise ConfigError(f"cannot read config {path}: {exc}") from exc
    except tomllib.TOMLDecodeError as exc:
        raise ConfigError(f"invalid TOML in {path}: {exc}") from exc
    except UnicodeDecodeError as exc:
        raise ConfigError(f"config {path} is not valid UTF-8: {exc}") from exc
    except ValueError as exc:
        raise ConfigError(f"invalid config value in {path}: {exc}") from exc
    if not isinstance(data, dict):
        raise ConfigError(f"config {path} must contain a table")
    return data


def load_config(explicit: str | None = None, no_config: bool = False) -> dict[str, Any]:
    if no_config:
        return {}
    if explicit:
        path = Path(explicit).expanduser()
        if not path.is_file():
            raise ConfigError(f"config file not found: {path}")
        return _read_config(path)
    # Only the user's config is implicit. A project config must be passed with
    # --config: an artifact under audit must not be able to weaken its own gate
    # by planting ./.skilltriage.toml.
    path = Path.home() / ".config" / "skilltriage" / "config.toml"
    return _read_config(path) if path.is_file() else {}


def apply_config(options: AuditOptions, config: dict[str, Any]) -> AuditOptions:
    options.config = config
    audit = config.get("audit") if isinstance(config.get("audit"), dict) else {}
    if "profile" in audit:
        options.profile = str(audit["profile"])
    if options.profile in PROFILE_DEFAULTS:
        apply_profile(options, options.profile)
    if "fail_on" in audit:
        raw = str(audit["fail_on"]).lower()
        if raw in ("none", "off", "false"):
            options.fail_on = None
        else:
            try:
                options.fail_on = Severity.parse(raw)
            except ValueError as exc:
                raise ConfigError(f"invalid audit.fail_on: {audit['fail_on']!r}") from exc
    if "min_confidence" in audit:
        try:
            options.min_confidence = Confidence.parse(str(audit["min_confidence"]))
        except ValueError as exc:
            raise ConfigError(
                f"invalid audit.min_confidence: {audit['min_confidence']!r}"
            ) from exc
    for key in ("include_vendor", "show_suppressed", "show_baselined", "verbose", "color",
                "require_inventory", "update_inventory", "trust_inline_suppressions"):
        if key in audit and isinstance(audit[key], bool):
            setattr(options, key, audit[key])
    for key in ("max_file_bytes", "max_total_bytes", "max_files", "max_archive_entries",
                "max_archive_uncompressed", "max_archive_bytes"):
        if key in audit and isinstance(audit[key], int) and audit[key] > 0:
            setattr(options, key, audit[key])
    inventory = config.get("inventory") if isinstance(config.get("inventory"), dict) else {}
    if "path" in inventory and not options.inventory_path:
        options.inventory_path = str(inventory["path"])
    discovery = config.get("discovery") if isinstance(config.get("discovery"), dict) else {}
    if isinstance(discovery.get("roots"), list):
        options.discovery_roots = [str(item) for item in discovery["roots"]]
    if isinstance(discovery.get("include_marketplaces"), bool):
        options.include_marketplaces = discovery["include_marketplaces"]
    intent = config.get("intent") if isinstance(config.get("intent"), dict) else {}
    if isinstance(intent.get("allow"), list):
        options.allowed_intents = [
            str(item).strip().lower()
            for item in intent["allow"]
            if isinstance(item, str)
        ]
    return options


def apply_profile(options: AuditOptions, profile: str) -> AuditOptions:
    if profile not in PROFILE_DEFAULTS:
        raise ConfigError(f"unknown profile: {profile}")
    options.profile = profile
    fail_on, min_confidence = PROFILE_DEFAULTS[profile]
    options.fail_on = fail_on
    options.min_confidence = min_confidence
    return options


def is_gating(finding: Finding, options: AuditOptions) -> bool:
    if finding.suppressed or finding.baselined or finding.intent_matched:
        return False
    if options.fail_on is None:
        return False
    if finding.severity.rank < options.fail_on.rank:
        return False
    return finding.confidence.rank >= options.min_confidence.rank


def gating_findings(findings: list[Finding], options: AuditOptions) -> list[Finding]:
    return [finding for finding in findings if is_gating(finding, options)]


def format_gate(options: AuditOptions) -> str:
    if options.fail_on is None:
        return "advisory (never fails)"
    return f"fail on {options.fail_on.value}+ with confidence {options.min_confidence.value}+"

"""Audit orchestration: load, normalise, run rules, correlate, gate."""

from __future__ import annotations

import time
from pathlib import Path

from . import __version__
from .baseline import Baseline
from .discovery import DiscoveredSkill
from .inventory import Inventory
from .loader import PreparedTarget, TargetError
from .models import (
    DEFAULT_NOT_ASSESSED,
    AuditResult,
    Confidence,
    Coverage,
    Finding,
    ScanReport,
    TargetInfo,
)
from .normalize import build_plugin, build_skill, parse_manifest_text
from .policy import AuditOptions, gating_findings
from .rules import ALL_RULES, get_rule, run_rules
from .rules.base import Rule, RuleContext
from .rules.inventory import RULE_BASELINE_DRIFT, RULE_NOT_IN_INVENTORY
from .secrets import mask_evidence
from .suppressions import SuppressionSet, apply_suppressions

ASSESSED = [
    "metadata structure, required fields, and safe parsing (AST04)",
    "permission declarations and least-privilege consistency (AST03)",
    "shell, Python, JavaScript, and PowerShell command patterns (AST01, AST06)",
    "credential paths, embedded secrets, and private keys (AST03, AST08)",
    "obfuscation, invisible Unicode, base64, and encoded execution (AST01, AST08)",
    "external references, untrusted hosts, and unpinned instruction sources (AST05)",
    "dependency declarations, install scripts, lockfiles, and executable config (AST02)",
    "file modes, symlinks, binaries, archives, and hidden content (AST06, AST08)",
    "cross-platform metadata consistency (AST10)",
    "governance metadata and inventory/baseline drift when configured (AST07, AST09)",
    "plugin identity, components, hooks, MCP configuration, and marketplace pinning when the target is a plugin (AST02, AST03, AST04, AST06, AST07, AST09)",
]


def _direct(rule: Rule, path: str, message: str, evidence: str) -> Finding:
    return Finding(
        rule_id=rule.id,
        ast=rule.ast,
        severity=rule.severity,
        confidence=rule.confidence,
        path=path,
        message=message,
        rationale=rule.description,
        remediation=rule.remediation,
        evidence=mask_evidence(evidence),
        cwes=rule.cwes,
        tags=rule.tags,
    )


def _dedupe_sort(findings: list[Finding]) -> list[Finding]:
    seen: set[tuple[str, str, int | None, str]] = set()
    unique: list[Finding] = []
    for finding in findings:
        key = (finding.rule_id, finding.path, finding.line, finding.evidence)
        if key in seen:
            continue
        seen.add(key)
        unique.append(finding)
    unique.sort(
        key=lambda item: (
            -item.severity.rank,
            item.ast,
            item.path,
            item.line or 0,
            item.rule_id,
        )
    )
    return unique


def audit_target(
    path: str | Path,
    options: AuditOptions,
    *,
    discovery: DiscoveredSkill | None = None,
    inventory: Inventory | None = None,
    baseline: Baseline | None = None,
) -> AuditResult:
    started = time.monotonic()
    limits = options.loader_limits()
    with PreparedTarget(path, limits) as tree:
        relpaths = tree.relpaths()
        texts = {record.path: record.text for record in tree.records if record.is_text}
        plugin_manifest = ".claude-plugin/plugin.json" in relpaths
        discovered_kind = getattr(discovery, "artifact_kind", "") if discovery else ""
        artifact_kind = "plugin" if (discovered_kind == "plugin" or plugin_manifest) else "skill"

        plugin_artifact = None
        if artifact_kind == "plugin":
            plugin_text = texts.get(".claude-plugin/plugin.json", "")
            plugin_data = (
                parse_manifest_text(".claude-plugin/plugin.json", plugin_text).data
                if plugin_text
                else {}
            )
            skill = build_skill(
                tree.root,
                relpaths,
                texts,
                plugin=plugin_data if isinstance(plugin_data, dict) else {},
                preferred_paths=(".claude-plugin/plugin.json",),
            )
            plugin_artifact = build_plugin(tree.root, relpaths, texts)
            name = (
                plugin_artifact.identity.name
                or skill.name
                or (discovery.name if discovery else Path(path).name)
            )
        else:
            # Do not walk above the audited root for plugin context. Use the
            # discovery identity when the skill lives in a plugin cache, and no
            # context at all for a local path.
            plugin_context: dict[str, str] = {}
            if discovery is not None and discovery.plugin:
                plugin_context = {
                    "name": discovery.plugin.rsplit("/", 1)[-1],
                    "version": discovery.version,
                }
            skill = build_skill(tree.root, relpaths, texts, plugin=plugin_context)
            name = skill.name or (discovery.name if discovery else Path(path).name)

        skill_id = discovery.skill_id if discovery else f"local:{name}"
        declared_intent = skill.declared_intent if skill.intent_declared else ""
        inventory_entry = None
        if inventory is not None:
            inventory_entry = inventory.get(skill_id) or inventory.find_by_path(str(path))
        tree_hash = tree.content_hash()
        recorded_hash = (
            str(inventory_entry.get("content_hash") or "") if inventory_entry else ""
        )
        intent_allowed = bool(
            declared_intent
            and declared_intent in options.allowed_intents
            and recorded_hash
            and recorded_hash == tree_hash
        )
        target = TargetInfo(
            input=str(path),
            kind=tree.kind,
            location=discovery.kind if discovery else "local",
            skill_id=skill_id,
            name=name,
            version=skill.version,
            platform=", ".join(skill.platforms),
            plugin=(
                discovery.plugin
                if discovery
                else (plugin_artifact.identity.name if plugin_artifact else "")
            ),
            display=discovery.display if discovery else str(path),
            artifact_kind=artifact_kind,
            declared_intent=declared_intent,
            intent_allowed=intent_allowed,
        )
        suppressions = SuppressionSet.from_texts(texts)
        ctx = RuleContext(
            root=tree.root,
            target=target,
            tree=tree,
            skill=skill,
            options=options,
            suppressions=suppressions,
            plugin=plugin_artifact,
        )
        run_rules(ctx, ALL_RULES)
        findings = list(ctx.findings)
        if intent_allowed:
            for finding in findings:
                rule = get_rule(finding.rule_id)
                if rule is None or rule.intent_family != declared_intent:
                    continue
                finding.severity = finding.severity.down()
                finding.confidence = Confidence.LOW
                finding.intent_matched = True
                note = (
                    f"downgraded under declared intent {declared_intent!r} "
                    "(policy-allowed, inventoried)"
                )
                finding.context_note = "; ".join(
                    part for part in (finding.context_note, note) if part
                )

        if inventory is not None:
            entry = inventory_entry
            if entry is None and options.require_inventory:
                findings.append(
                    _direct(
                        RULE_NOT_IN_INVENTORY,
                        ".",
                        "Installed skill has no inventory record.",
                        f"skill_id: {skill_id}",
                    )
                )
            elif entry is not None and entry.get("content_hash"):
                recorded = str(entry.get("content_hash"))
                if recorded != tree_hash:
                    findings.append(
                        _direct(
                            RULE_BASELINE_DRIFT,
                            ".",
                            "Installed skill bytes differ from the inventory hash.",
                            f"recorded {recorded} != current {tree_hash}",
                        )
                    )

        # Inline suppressions live inside the artifact under audit. Honouring
        # them by default would let a malicious package silence its own
        # findings, so they are inert unless the operator opts in. Baselines are
        # the reviewed-acceptance mechanism.
        if options.trust_inline_suppressions:
            apply_suppressions(findings, suppressions)
        findings = _dedupe_sort(findings)
        if baseline is not None:
            for finding in findings:
                if baseline.matches(finding, skill_id):
                    finding.baselined = True

        gating = gating_findings(findings, options)
        notes = list(tree.notes) + list(ctx.notes)
        if declared_intent and not intent_allowed:
            if declared_intent not in options.allowed_intents:
                reason = "policy does not allow it"
            elif not recorded_hash:
                reason = "no inventory record with a content hash"
            else:
                reason = "inventory hash does not match the current bytes"
            notes.insert(
                0,
                f"intent {declared_intent!r} declared; findings not downgraded ({reason})",
            )
        notes.extend(f"rule error: {error}" for error in ctx.rule_errors)
        components: dict[str, int] = {}
        if plugin_artifact is not None:
            for component in plugin_artifact.components:
                components[component.kind] = components.get(component.kind, 0) + 1
            if plugin_artifact.hooks:
                components["hooks"] = len(plugin_artifact.hooks)
            if plugin_artifact.mcp_servers:
                components["mcp_servers"] = len(plugin_artifact.mcp_servers)
        coverage = Coverage(
            assessed=list(ASSESSED),
            not_assessed=list(DEFAULT_NOT_ASSESSED),
            rules_run=len(ALL_RULES),
            rules_skipped=[],
            notes=notes,
            components=components,
        )
        return AuditResult(
            target=target,
            findings=findings,
            files=tree.records,
            skill=skill,
            coverage=coverage,
            errors=[],
            duration_ms=int((time.monotonic() - started) * 1000),
            gating_count=len(gating),
            suppressed_count=sum(1 for finding in findings if finding.suppressed),
            baseline_matched=sum(1 for finding in findings if finding.baselined),
            plugin=plugin_artifact,
        )


def _policy_dict(options: AuditOptions) -> dict:
    return {
        "profile": options.profile,
        "fail_on": options.fail_on.value if options.fail_on else None,
        "min_confidence": options.min_confidence.value,
        "include_vendor": options.include_vendor,
        "intent_allow": list(options.allowed_intents),
    }


def audit_paths(
    paths: list[str | Path],
    options: AuditOptions,
    *,
    inventory: Inventory | None = None,
    baseline: Baseline | None = None,
) -> ScanReport:
    results: list[AuditResult] = []
    errors: list[str] = []
    for path in paths:
        try:
            results.append(audit_target(path, options, inventory=inventory, baseline=baseline))
        except TargetError as exc:
            errors.append(f"{path}: {exc}")
        except Exception as exc:  # one bad target must not abort the scan
            errors.append(f"{path}: {type(exc).__name__}: {exc}")
    return ScanReport(
        results=results,
        tool_version=__version__,
        command="audit",
        errors=errors,
        policy=_policy_dict(options),
    )


def scan_discovered(
    discovered: list[DiscoveredSkill],
    options: AuditOptions,
    *,
    inventory: Inventory | None = None,
    baseline: Baseline | None = None,
) -> ScanReport:
    results: list[AuditResult] = []
    errors: list[str] = []
    for skill in discovered:
        try:
            results.append(
                audit_target(
                    skill.path,
                    options,
                    discovery=skill,
                    inventory=inventory,
                    baseline=baseline,
                )
            )
        except TargetError as exc:
            errors.append(f"{skill.display}: {exc}")
        except Exception as exc:  # keep the fleet scan alive
            errors.append(f"{skill.display}: {type(exc).__name__}: {exc}")
    return ScanReport(
        results=results,
        tool_version=__version__,
        command="scan-system",
        errors=errors,
        policy=_policy_dict(options),
    )


def sync_inventory(results: list[AuditResult], inventory: Inventory) -> dict[str, int]:
    summary = inventory.sync(results)
    inventory.save()
    return summary


def inventory_diff(results: list[AuditResult], inventory: Inventory) -> dict[str, list[dict]]:
    return inventory.diff(results)

"""SARIF 2.1.0 output.

Each scanned file is an artifact with a SHA-256 hash, and each result points at
its artifact index. That follows the OWASP skill-scanner integration guidance
so findings from independent scanners can be joined on the file digest. All
findings carry ``properties.layer = "static"``.
"""

from __future__ import annotations

import json
import re

from ..models import OWASP_URL, AuditResult, Severity, TOOL_NAME
from ..rules import get_rule

SCHEMA = "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json"
_LEVEL = {
    Severity.CRITICAL: "error",
    Severity.HIGH: "error",
    Severity.MEDIUM: "warning",
    Severity.LOW: "note",
    Severity.INFO: "note",
}
_HEX64 = re.compile(r"^[0-9a-fA-F]{64}$")


def _rule_metadata(rule_id: str) -> dict:
    rule = get_rule(rule_id)
    if rule is None:
        return {
            "id": rule_id,
            "name": rule_id,
            "shortDescription": {"text": rule_id},
            "properties": {"layer": "static"},
        }
    return {
        "id": rule.id,
        "name": rule.id,
        "shortDescription": {"text": rule.title},
        "fullDescription": {"text": rule.description},
        "help": {"text": rule.remediation},
        "helpUri": OWASP_URL,
        "defaultConfiguration": {"level": _LEVEL.get(rule.severity, "warning")},
        "properties": {
            "ast": rule.ast,
            "ast_name": rule.ast_name,
            "severity": rule.severity.value,
            "confidence": rule.confidence.value,
            "cwes": list(rule.cwes),
            "tags": list(rule.tags),
            "layer": "static",
        },
    }


def _artifact(result: AuditResult, path: str) -> dict | None:
    record = next((item for item in result.files if item.path == path), None)
    if record is None:
        return None
    artifact: dict = {"location": {"uri": path}}
    if _HEX64.match(record.sha256 or ""):
        artifact["hashes"] = {"sha-256": record.sha256}
    artifact["length"] = record.size
    artifact["mimeType"] = "text/plain" if record.is_text else "application/octet-stream"
    return artifact


def _run(result: AuditResult, report) -> dict:
    findings = result.findings
    rule_ids = sorted({finding.rule_id for finding in findings})
    rules = [_rule_metadata(rule_id) for rule_id in rule_ids]
    rule_index = {rule["id"]: index for index, rule in enumerate(rules)}

    file_paths = {item.path for item in result.files}
    artifact_paths: list[str] = []
    for finding in findings:
        if finding.path != "." and finding.path not in artifact_paths:
            artifact_paths.append(finding.path)

    # GitHub code scanning requires a physical location on every result. A
    # target-level finding (correlation, archive issue, inventory drift) has
    # path ".", so attach it to the primary manifest, or the first file.
    fallback_path = ""
    if any(finding.path == "." or finding.path not in file_paths for finding in findings):
        for candidate in ("SKILL.md", ".claude-plugin/plugin.json"):
            if candidate in file_paths:
                fallback_path = candidate
                break
        if not fallback_path and file_paths:
            fallback_path = sorted(file_paths)[0]
        if fallback_path and fallback_path not in artifact_paths:
            artifact_paths.append(fallback_path)

    artifacts = []
    artifact_index: dict[str, int] = {}
    for path in artifact_paths:
        artifact = _artifact(result, path)
        if artifact is not None:
            artifact_index[path] = len(artifacts)
            artifacts.append(artifact)

    results: list[dict] = []
    for finding in findings:
        suppressed = finding.suppressed or finding.baselined
        entry: dict = {
            "ruleId": finding.rule_id,
            "ruleIndex": rule_index[finding.rule_id],
            "level": "none" if suppressed else _LEVEL.get(finding.severity, "warning"),
            "message": {"text": finding.message},
            "partialFingerprints": {"skilltriage/v1": finding.fingerprint},
            "properties": {
                "ast": finding.ast,
                "severity": finding.severity.value,
                "confidence": finding.confidence.value,
                "evidence": finding.evidence,
                "rationale": finding.rationale,
                "remediation": finding.remediation,
                "context_note": finding.context_note,
                "cwes": list(finding.cwes),
                "tags": list(finding.tags),
                "intent_matched": finding.intent_matched,
                "layer": "static",
            },
        }
        location_path = finding.path if finding.path in artifact_index else fallback_path
        if location_path and location_path in artifact_index:
            region: dict = {
                "startLine": finding.line
                if finding.path == location_path and finding.line
                else 1
            }
            if finding.column and finding.path == location_path:
                region["startColumn"] = finding.column
            entry["locations"] = [
                {
                    "physicalLocation": {
                        "artifactLocation": {
                            "uri": location_path,
                            "index": artifact_index[location_path],
                        },
                        "region": region,
                    }
                }
            ]
            if finding.path != location_path:
                entry["properties"]["finding_path"] = finding.path
        else:
            # No physical file to point at (an empty target). Keep the scan
            # valid rather than uploading a result GitHub will reject.
            continue
        if finding.suppressed:
            entry["suppressions"] = [
                {
                    "kind": "inSource",
                    "status": "accepted",
                    "justification": "inline skilltriage:disable comment",
                }
            ]
        elif finding.baselined:
            entry["suppressions"] = [
                {
                    "kind": "external",
                    "status": "accepted",
                    "justification": "accepted in the skilltriage baseline",
                }
            ]
        results.append(entry)

    run: dict = {
        "tool": {
            "driver": {
                "name": TOOL_NAME,
                "version": report.tool_version,
                "informationUri": OWASP_URL,
                "rules": rules,
            }
        },
        "automationDetails": {
            "id": result.target.skill_id or result.target.display,
            "description": {"text": result.target.display},
        },
        "artifacts": artifacts,
        "results": results,
        "invocations": [
            {
                "executionSuccessful": True,
                "properties": {
                    "duration_ms": result.duration_ms,
                    "target": result.target.to_dict(),
                    "summary": result.summary(),
                },
            }
        ],
        "properties": {
            "generated": report.generated,
            "command": report.command,
            "policy": report.policy,
            "coverage": result.coverage.to_dict(),
        },
    }
    return run


def render(report) -> str:
    payload = {
        "$schema": SCHEMA,
        "version": "2.1.0",
        "runs": [_run(result, report) for result in report.results],
    }
    return json.dumps(payload, indent=2) + "\n"

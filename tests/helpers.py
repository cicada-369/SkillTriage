"""Shared test helpers."""

from __future__ import annotations

from pathlib import Path

from skilltriage.analysis import audit_target
from skilltriage.models import Confidence, Severity
from skilltriage.policy import AuditOptions

FIXTURES = Path(__file__).resolve().parent / "fixtures"


def write_skill(root: str | Path, files: dict[str, str | bytes]) -> Path:
    root = Path(root)
    for relpath, content in files.items():
        path = root / relpath
        path.parent.mkdir(parents=True, exist_ok=True)
        if isinstance(content, bytes):
            path.write_bytes(content)
        else:
            path.write_text(content, encoding="utf-8")
    return root


def skill_md(
    name: str = "fixture-skill",
    *,
    description: str = "A synthetic skill used by the test suite.",
    extra: str = "",
    body: str = "This is a synthetic test body. " * 6,
) -> str:
    return (
        "---\n"
        f"name: {name}\n"
        f"description: {description}\n"
        "version: 1.0.0\n"
        f"{extra}"
        "---\n\n"
        "# Fixture\n\n"
        f"{body}\n"
    )


def audit(
    path: str | Path,
    *,
    fail_on: Severity | None = Severity.HIGH,
    min_confidence: Confidence = Confidence.HIGH,
    **overrides,
):
    options = AuditOptions()
    options.fail_on = fail_on
    options.min_confidence = min_confidence
    for key, value in overrides.items():
        setattr(options, key, value)
    return audit_target(path, options)


def ids(result) -> set[str]:
    return {finding.rule_id for finding in result.findings}


def get(result, rule_id: str):
    return next((finding for finding in result.findings if finding.rule_id == rule_id), None)


def locations(result, rule_id: str) -> set[str]:
    return {
        f"{finding.path}:{finding.line}"
        for finding in result.findings
        if finding.rule_id == rule_id
    }


def finding_signature(result) -> list[dict]:
    """A deterministic, human-readable summary used for regression snapshots."""
    return [
        {
            "rule_id": finding.rule_id,
            "path": finding.path,
            "line": finding.line,
            "severity": finding.severity.value,
            "confidence": finding.confidence.value,
            "evidence": finding.evidence,
            "suppressed": finding.suppressed,
            "baselined": finding.baselined,
        }
        for finding in sorted(
            result.findings,
            key=lambda item: (
                item.path,
                item.line or 0,
                item.rule_id,
                item.evidence,
            ),
        )
    ]

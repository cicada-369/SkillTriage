"""Rule protocol and execution context."""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable, Iterable

from ..loader import LoadedTree
from ..models import (
    AST_NAMES,
    Confidence,
    FileRecord,
    Finding,
    ManifestRecord,
    NormalizedSkill,
    Severity,
    TargetInfo,
)
from ..patterns import CODE_EXTENSIONS, MARKDOWN_EXTENSIONS
from ..secrets import mask_evidence
from ..suppressions import SuppressionSet
from .context import Fence, fence_language, parse_fences, score


@dataclass(frozen=True)
class Rule:
    id: str
    ast: str
    title: str
    severity: Severity
    confidence: Confidence
    description: str
    remediation: str
    check: Callable[["RuleContext"], None] = field(compare=False, repr=False)
    cwes: tuple[str, ...] = ()
    tags: tuple[str, ...] = ()
    no_context: bool = False
    # A technique that is inherent to legitimate offensive tooling. A finding
    # is downgraded only when the artifact declares this intent, policy allows
    # it, and the artifact is in the inventory.
    intent_family: str = ""

    @property
    def ast_name(self) -> str:
        return AST_NAMES.get(self.ast, "")


@dataclass
class RuleContext:
    root: Path
    target: TargetInfo
    tree: LoadedTree
    skill: NormalizedSkill
    options: Any
    suppressions: SuppressionSet = field(default_factory=SuppressionSet)
    findings: list[Finding] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)
    rule_errors: list[str] = field(default_factory=list)
    signals: dict[str, set[str]] = field(default_factory=dict)
    plugin: Any = None
    _fences: dict[str, list[Fence]] = field(default_factory=dict)
    _seen: set[tuple[str, str, int | None, str]] = field(default_factory=set)

    @property
    def is_plugin(self) -> bool:
        return self.plugin is not None

    @property
    def primary_path(self) -> str:
        """The manifest a target-level finding should point at."""
        if self.is_plugin:
            for manifest in self.skill.manifests:
                if manifest.path == ".claude-plugin/plugin.json":
                    return manifest.path
        for manifest in self.skill.manifests:
            if manifest.data:
                return manifest.path
        return "SKILL.md"

    # ---- file access -------------------------------------------------
    @property
    def files(self) -> list[FileRecord]:
        return self.tree.records

    @property
    def by_path(self) -> dict[str, FileRecord]:
        return self.tree.by_path()

    def has(self, relpath: str) -> bool:
        return (self.root / relpath).is_file()

    def record(self, relpath: str) -> FileRecord | None:
        return self.by_path.get(relpath)

    def text(self, relpath: str) -> str:
        record = self.record(relpath)
        return record.text if record and record.is_text else ""

    def texts(self) -> Iterable[tuple[FileRecord, str]]:
        for record in self.files:
            if record.is_text:
                yield record, record.text

    def markdown_files(self) -> Iterable[tuple[FileRecord, str]]:
        for record, text in self.texts():
            if record.suffix in MARKDOWN_EXTENSIONS:
                yield record, text

    def code_files(self) -> Iterable[tuple[FileRecord, str]]:
        for record, text in self.texts():
            if record.suffix in CODE_EXTENSIONS:
                yield record, text

    def prose_text(self) -> str:
        record = self.record("SKILL.md")
        if record and record.is_text:
            return record.text
        return ""

    def fences(self, relpath: str) -> list[Fence]:
        if relpath not in self._fences:
            self._fences[relpath] = parse_fences(self.text(relpath))
        return self._fences[relpath]

    @staticmethod
    def line_text(text: str, line: int | None) -> str:
        if line is None:
            return ""
        lines = text.splitlines()
        if 1 <= line <= len(lines):
            return lines[line - 1]
        return ""

    def line_of(self, text: str, line: int | None) -> str:
        return self.line_text(text, line)

    @staticmethod
    def is_code(path: str) -> bool:
        return Path(path).suffix.lower() in CODE_EXTENSIONS

    @staticmethod
    def is_markdown(path: str) -> bool:
        return Path(path).suffix.lower() in MARKDOWN_EXTENSIONS

    def manifest(self, path: str) -> ManifestRecord | None:
        return next((m for m in self.skill.manifests if m.path == path), None)

    def in_frontmatter(self, path: str, line: int | None) -> bool:
        """True for a line inside SKILL.md's YAML frontmatter.

        Metadata permission fields are handled by the permission rules; scanning
        them again as shell/code text produces duplicate and misleading findings
        (for example, ``deny_write: SOUL.md`` is the opposite of an identity write).
        """
        if line is None:
            return False
        manifest = self.manifest(path)
        return bool(
            manifest
            and manifest.path == "SKILL.md"
            and manifest.has_frontmatter
            and line < manifest.body_line
        )

    # ---- emission ----------------------------------------------------
    def signal(self, kind: str, value: str) -> None:
        self.signals.setdefault(kind, set()).add(value)

    def emit(
        self,
        rule: Rule,
        *,
        path: str,
        line: int | None = None,
        column: int | None = None,
        message: str | None = None,
        evidence: str | None = None,
        severity: Severity | None = None,
        confidence: Confidence | None = None,
        context: bool = True,
        context_note: str = "",
    ) -> Finding | None:
        line_text = self.line_text(self.text(path), line)
        base_severity = severity or rule.severity
        base_confidence = confidence or rule.confidence
        note = context_note
        if context and not rule.no_context:
            fence_lang = fence_language(self.fences(path), line) if self.is_markdown(path) else None
            # Use the artifact's identity, not the absolute input path: a parent
            # directory named "security" or "tester" must not change scoring.
            artifact_context = " ".join(
                part
                for part in (
                    self.target.name,
                    self.target.plugin,
                    self.skill.name,
                    self.skill.description,
                )
                if part
            )
            base_severity, base_confidence, scored_note = score(
                severity=base_severity,
                confidence=base_confidence,
                path=path,
                line_text=line_text,
                fence_lang=fence_lang,
                is_code=self.is_code(path),
                artifact_context=artifact_context,
            )
            note = "; ".join(part for part in (note, scored_note) if part)

        raw_evidence = evidence if evidence is not None else line_text
        clean_evidence = mask_evidence(raw_evidence)
        key = (rule.id, path, line, clean_evidence)
        if key in self._seen:
            return None
        self._seen.add(key)
        finding = Finding(
            rule_id=rule.id,
            ast=rule.ast,
            severity=base_severity,
            confidence=base_confidence,
            path=path,
            line=line,
            column=column,
            message=message or rule.title,
            rationale=rule.description,
            remediation=rule.remediation,
            evidence=clean_evidence,
            cwes=rule.cwes,
            tags=rule.tags,
            context_note=note,
        )
        self.findings.append(finding)
        return finding


def run_rules(
    context: RuleContext,
    rules: Iterable[Rule],
) -> tuple[list[Finding], list[str]]:
    run = 0
    for rule in rules:
        run += 1
        before = len(context.findings)
        try:
            rule.check(context)
        except Exception as exc:  # a rule must never take down the scan
            context.rule_errors.append(f"{rule.id}: {type(exc).__name__}: {exc}")
            del context.findings[before:]
    return context.findings, context.rule_errors


def describe_rules(rules: Iterable[Rule]) -> list[dict[str, Any]]:
    return [
        {
            "id": rule.id,
            "ast": rule.ast,
            "ast_name": rule.ast_name,
            "title": rule.title,
            "severity": rule.severity.value,
            "confidence": rule.confidence.value,
            "description": rule.description,
            "remediation": rule.remediation,
            "cwes": list(rule.cwes),
            "tags": list(rule.tags),
        }
        for rule in sorted(rules, key=lambda item: (item.ast, item.id))
    ]

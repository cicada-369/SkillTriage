"""Human-readable text reports."""

from __future__ import annotations

from ..models import AST_NAMES, AuditResult, Severity
from ..policy import AuditOptions, format_gate, gating_findings
from ..safety import escape_unsafe

_COLORS = {
    Severity.CRITICAL: "\033[1;31m",
    Severity.HIGH: "\033[31m",
    Severity.MEDIUM: "\033[33m",
    Severity.LOW: "\033[36m",
    Severity.INFO: "\033[2m",
}
_RESET = "\033[0m"


def _s(value: str) -> str:
    """Neutralise control and invisible characters in untrusted report text."""
    return escape_unsafe("" if value is None else str(value))


def _badge(severity: Severity, color: bool) -> str:
    label = severity.value.upper()
    if not color:
        return f"[{label}]"
    return f"{_COLORS.get(severity, '')}[{label}]{_RESET}"


def _visible(result: AuditResult, options: AuditOptions) -> list:
    return [
        finding
        for finding in result.findings
        if (options.show_suppressed or not finding.suppressed)
        and (options.show_baselined or not finding.baselined)
    ]


def _target_header(result: AuditResult) -> str:
    version = f"@{_s(result.target.version)}" if result.target.version else ""
    return (
        f"{_s(result.target.display)}  "
        f"({_s(result.skill.name or result.target.name)}{version}, "
        f"{_s(result.target.location)}, {_s(result.target.kind)})"
    )


def _render_finding(finding, color: bool) -> list[str]:
    location = _s(finding.path) + (f":{finding.line}" if finding.line else "")
    lines = [
        f"  {_badge(finding.severity, color)} {finding.rule_id}  "
        f"{location}  ({finding.ast} {AST_NAMES.get(finding.ast, '')})  "
        f"confidence={finding.confidence.value}"
    ]
    lines.append(f"    {_s(finding.message)}")
    if finding.evidence:
        lines.append(f"    evidence: {_s(finding.evidence)}")
    if finding.rationale:
        lines.append(f"    why: {_s(finding.rationale)}")
    if finding.remediation:
        lines.append(f"    fix: {_s(finding.remediation)}")
    if finding.context_note:
        lines.append(f"    context: {_s(finding.context_note)}")
    if finding.suppressed:
        lines.append("    state: suppressed by inline comment")
    if finding.baselined:
        lines.append("    state: baselined (accepted)")
    return lines


def render(report, options: AuditOptions, *, verbose: bool = False) -> str:
    color = bool(options.color)
    out: list[str] = []
    summary = report.summary()
    verdict = "PASS" if report.passed else "FAIL"
    out.append(f"skilltriage {report.tool_version} — static security audit")
    out.append(f"Generated: {report.generated}")
    out.append(
        f"Result: {verdict} — {summary['targets']} target(s), "
        f"{summary['gating']} gating finding(s), {summary['errors']} scan error(s)"
    )
    severity = summary["severity"]
    out.append(
        "Summary: "
        + ", ".join(f"{name} {severity[name]}" for name in ("critical", "high", "medium", "low", "info"))
        + f" | suppressed {summary['suppressed']} | baselined {summary['baselined']}"
    )
    out.append(f"Gate: {format_gate(options)}")
    out.append("")

    multiple = len(report.results) > 1
    if multiple and not verbose:
        header = f"{'TARGET':48} {'RESULT':6} {'CRIT':>4} {'HIGH':>4} {'MED':>4} {'LOW':>4} {'INFO':>4} {'GATE':>4}"
        out.append(header)
        out.append("-" * len(header))
        for result in report.results:
            counts = {name: result.summary()["severity"][name] for name in ("critical", "high", "medium", "low", "info")}
            target = _s(result.target.display)
            if len(target) > 47:
                target = "…" + target[-46:]
            out.append(
                f"{target:48} {'PASS' if result.passed else 'FAIL':6} "
                f"{counts['critical']:>4} {counts['high']:>4} {counts['medium']:>4} "
                f"{counts['low']:>4} {counts['info']:>4} {result.gating_count:>4}"
            )
        out.append("")
        selected = [result for result in report.results if not result.passed]
        if not selected and not report.errors:
            out.append("No target has a gating finding. Use --verbose for full findings.")
        for result in selected:
            out.extend(_render_target(result, options, color, limit=25))
    else:
        for result in report.results:
            out.extend(_render_target(result, options, color, limit=None))

    if report.errors:
        out.append("Scan errors")
        for error in report.errors:
            out.append(f"  - {_s(error)}")
        out.append("")

    gating = gating_findings(
        [finding for result in report.results for finding in result.findings],
        options,
    )
    if gating:
        out.append(
            f"Next: skilltriage rules explain {gating[0].rule_id}  "
            "(rationale and remediation)"
        )
        out.append("")

    out.extend(_render_coverage(report))
    return "\n".join(out).rstrip() + "\n"


def _render_target(result: AuditResult, options: AuditOptions, color: bool, limit: int | None) -> list[str]:
    out: list[str] = []
    out.append(f"== {_target_header(result)} ==")
    out.append(
        f"   {'PASS' if result.passed else 'FAIL'} — "
        f"{len(result.findings)} finding(s), {result.gating_count} gating, "
        f"{result.suppressed_count} suppressed, {result.baseline_matched} baselined"
    )
    if result.target.declared_intent:
        downgraded = sum(1 for finding in result.findings if finding.intent_matched)
        state = "allowed" if result.target.intent_allowed else "not applied"
        out.append(
            f"   declared intent: {_s(result.target.declared_intent)} "
            f"({state}; {downgraded} finding(s) downgraded)"
        )
    findings = _visible(result, options)
    if not findings:
        out.append("   No visible findings.")
        out.append("")
        return out
    shown = findings if limit is None else findings[:limit]
    for finding in shown:
        out.extend(_render_finding(finding, color))
    if limit is not None and len(findings) > limit:
        out.append(f"   … {len(findings) - limit} more finding(s); use --verbose or JSON for all.")
    out.append("")
    return out


def _render_coverage(report) -> list[str]:
    out: list[str] = ["Coverage & limitations"]
    if not report.results:
        out.append("  no targets were scanned")
        return out
    coverage = report.results[0].coverage
    out.append("  Assessed:")
    for item in coverage.assessed:
        out.append(f"    - {_s(item)}")
    out.append("  Not assessed:")
    for item in coverage.not_assessed:
        out.append(f"    - {_s(item)}")
    out.append(
        "  A clean report means no configured static check triggered. "
        "It is not proof that the skill is safe or behaves as documented."
    )
    notes: list[str] = []
    for result in report.results:
        notes.extend(result.coverage.notes)
    if notes:
        out.append("  Scan notes:")
        for note in notes[:20]:
            out.append(f"    - {_s(note)}")
        if len(notes) > 20:
            out.append(f"    - … {len(notes) - 20} more note(s)")
    return out

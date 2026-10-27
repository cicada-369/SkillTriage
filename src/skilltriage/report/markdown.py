"""Markdown report suitable for a PR comment or a saved review artifact."""

from __future__ import annotations

from ..models import AST_NAMES, AuditResult, OWASP_URL
from ..policy import AuditOptions, format_gate
from ..safety import escape_unsafe


def _visible(result: AuditResult, options: AuditOptions) -> list:
    return [
        finding
        for finding in result.findings
        if (options.show_suppressed or not finding.suppressed)
        and (options.show_baselined or not finding.baselined)
    ]


def _html_safe(value: str) -> str:
    safe = escape_unsafe(value or "")
    return (
        safe.replace("&", "&amp;")
        .replace("<", "&lt;")
        .replace(">", "&gt;")
    )


def _escape(value: str) -> str:
    return _html_safe(value).replace("|", "\\|")


def _code(value: str) -> str:
    """Render untrusted text as inline code without breaking the table."""
    safe = _html_safe(value or "").replace("|", "\\|")
    fence = "`"
    while fence in safe:
        fence += "`"
    if safe.startswith(("`", " ")) or safe.endswith(("`", " ")):
        return f"{fence} {safe} {fence}"
    return f"{fence}{safe}{fence}"


def render(report, options: AuditOptions) -> str:
    summary = report.summary()
    severity = summary["severity"]
    lines = [
        "# skilltriage report",
        "",
        f"- **Tool:** skilltriage {report.tool_version}",
        f"- **Generated:** {report.generated}",
        f"- **Command:** {_code(report.command)}",
        f"- **Result:** **{'PASS' if report.passed else 'FAIL'}**",
        f"- **Targets:** {summary['targets']}",
        f"- **Gating findings:** {summary['gating']}",
        f"- **Gate:** {format_gate(options)}",
        f"- **Taxonomy:** [OWASP Agentic Skills Top 10]({OWASP_URL})",
        "",
        "| Severity | Count |",
        "|---|---:|",
        f"| Critical | {severity['critical']} |",
        f"| High | {severity['high']} |",
        f"| Medium | {severity['medium']} |",
        f"| Low | {severity['low']} |",
        f"| Info | {severity['info']} |",
        f"| Suppressed | {summary['suppressed']} |",
        f"| Baselined | {summary['baselined']} |",
        "",
        "> Static checks are heuristic. A clean report does not prove safety or runtime behaviour.",
        "",
    ]

    if report.errors:
        lines.append("## Scan errors")
        lines.append("")
        for error in report.errors:
            lines.append(f"- {_escape(error)}")
        lines.append("")

    for result in report.results:
        version = f"@{_escape(result.target.version)}" if result.target.version else ""
        lines.append(f"## {_escape(result.target.display)}")
        lines.append("")
        lines.append(f"- **Skill:** {_code(result.skill.name or result.target.name)}{version}")
        lines.append(f"- **Location:** {_escape(result.target.location)}")
        lines.append(f"- **Kind:** {_escape(result.target.kind)}")
        lines.append(f"- **Result:** {'PASS' if result.passed else 'FAIL'}")
        lines.append(f"- **Findings:** {len(result.findings)} ({result.gating_count} gating)")
        if result.target.declared_intent:
            downgraded = sum(1 for finding in result.findings if finding.intent_matched)
            state = "allowed" if result.target.intent_allowed else "not applied"
            lines.append(
                f"- **Declared intent:** {_escape(result.target.declared_intent)} "
                f"({state}; {downgraded} finding(s) downgraded)"
            )
        if result.target.plugin:
            lines.append(f"- **Plugin:** {_code(result.target.plugin)}")
        lines.append("")
        findings = _visible(result, options)
        if not findings:
            lines.append("No visible findings.")
            lines.append("")
            continue
        by_ast: dict[str, list] = {}
        for finding in findings:
            by_ast.setdefault(finding.ast, []).append(finding)
        for ast in sorted(by_ast):
            lines.append(f"### {ast} — {AST_NAMES.get(ast, '')}")
            lines.append("")
            lines.append("| Severity | Rule | Location | Confidence | Finding |")
            lines.append("|---|---|---|---|---|")
            for finding in by_ast[ast]:
                location = _code(finding.path) + (f":{finding.line}" if finding.line else "")
                lines.append(
                    f"| {finding.severity.value} | `{finding.rule_id}` | {location} | "
                    f"{finding.confidence.value} | {_escape(finding.message)} |"
                )
            lines.append("")
            for finding in by_ast[ast]:
                lines.append(f"#### `{finding.rule_id}`")
                lines.append("")
                lines.append(f"- **Severity:** {finding.severity.value} ({finding.confidence.value} confidence)")
                location = _code(finding.path) + (f":{finding.line}" if finding.line else "")
                lines.append(f"- **Location:** {location}")
                if finding.evidence:
                    lines.append(f"- **Evidence:** {_code(finding.evidence)}")
                if finding.rationale:
                    lines.append(f"- **Why:** {_escape(finding.rationale)}")
                if finding.remediation:
                    lines.append(f"- **Fix:** {_escape(finding.remediation)}")
                if finding.context_note:
                    lines.append(f"- **Context:** {_escape(finding.context_note)}")
                if finding.cwes:
                    lines.append(f"- **CWE:** {', '.join(finding.cwes)}")
                lines.append("")

    if report.results:
        coverage = report.results[0].coverage
        lines.append("## Coverage & limitations")
        lines.append("")
        lines.append("**Assessed**")
        lines.append("")
        for item in coverage.assessed:
            lines.append(f"- {_escape(item)}")
        lines.append("")
        lines.append("**Not assessed**")
        lines.append("")
        for item in coverage.not_assessed:
            lines.append(f"- {_escape(item)}")
        lines.append("")
        notes = [note for result in report.results for note in result.coverage.notes]
        if notes:
            lines.append("**Scan notes**")
            lines.append("")
            for note in notes[:30]:
                lines.append(f"- {_escape(note)}")
            if len(notes) > 30:
                lines.append(f"- … {len(notes) - 30} more")
            lines.append("")
    return "\n".join(lines).rstrip() + "\n"

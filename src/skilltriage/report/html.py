"""Self-contained HTML report.

The document is one file with no external assets, scripts, fonts, or images, so
it can be reviewed offline. Every dynamic value is escaped twice for safety:
``escape_unsafe`` neutralises control, bidi, and invisible characters, then
``html.escape`` neutralises HTML metacharacters. The inline stylesheet and
script are fixed constants covered by a Content-Security-Policy hash.
"""

from __future__ import annotations

import base64
import hashlib
import html
from collections import defaultdict

from ..models import AST_NAMES, OWASP_URL, AuditResult
from ..policy import AuditOptions, format_gate
from ..safety import escape_unsafe

_STYLE = """
:root{
  color-scheme:light dark;
  --bg:#ffffff;--fg:#1b1f23;--muted:#57606a;--border:#d8dee4;--panel:#f6f8fa;
  --crit:#b31d28;--high:#b45309;--med:#7a5b00;--low:#0969a2;--info:#57606a;
  --ok:#116329;--fail:#b31d28;
}
@media (prefers-color-scheme:dark){
  :root{
    --bg:#101418;--fg:#e6edf3;--muted:#9aa7b4;--border:#30363d;--panel:#161b22;
    --crit:#ff8b95;--high:#ffbf87;--med:#e6d27a;--low:#8ecbff;--info:#9aa7b4;
    --ok:#63d98a;--fail:#ff8b95;
  }
}
*{box-sizing:border-box}
body{margin:0;background:var(--bg);color:var(--fg);
  font:16px/1.55 system-ui,-apple-system,"Segoe UI",Roboto,Helvetica,Arial,sans-serif}
a{color:var(--low)}
.skip{position:absolute;left:-9999px;top:0;background:var(--panel);padding:.5rem 1rem}
.skip:focus{left:1rem;z-index:10}
header,main,footer{max-width:1100px;margin:0 auto;padding:0 16px}
header{padding-top:24px}
h1{font-size:1.6rem;margin:0 0 .25rem}
h2{font-size:1.25rem;margin:2rem 0 .5rem;border-bottom:1px solid var(--border);padding-bottom:.25rem}
h3{font-size:1rem;margin:1.5rem 0 .5rem}
.sub{color:var(--muted);margin:.15rem 0}
.verdict{font-weight:700}
.pass{color:var(--ok)}.fail{color:var(--fail)}
.tiles{display:grid;grid-template-columns:repeat(auto-fit,minmax(130px,1fr));gap:10px;margin:18px 0}
.tile{background:var(--panel);border:1px solid var(--border);border-radius:8px;padding:10px 12px}
.tile .n{font-size:1.4rem;font-weight:700;display:block}
.tile .l{color:var(--muted);font-size:.8rem;text-transform:uppercase;letter-spacing:.04em}
.controls{display:flex;flex-wrap:wrap;gap:10px;align-items:center;margin:16px 0;
  padding:12px;border:1px solid var(--border);border-radius:8px;background:var(--panel)}
.controls label{font-size:.85rem;color:var(--muted)}
.controls select,.controls input{font:inherit;padding:.35rem .5rem;border:1px solid var(--border);
  border-radius:6px;background:var(--bg);color:var(--fg);min-width:10rem}
table{width:100%;border-collapse:collapse;margin:.5rem 0 1rem;font-size:.9rem}
caption{text-align:left;color:var(--muted);padding:.25rem 0}
th,td{text-align:left;padding:.4rem .5rem;border-bottom:1px solid var(--border);vertical-align:top}
th{font-size:.78rem;text-transform:uppercase;letter-spacing:.04em;color:var(--muted)}
td.num,th.num{text-align:right;font-variant-numeric:tabular-nums}
.target{margin:2rem 0;padding-top:.5rem}
.meta{display:grid;grid-template-columns:max-content 1fr;gap:.15rem 1rem;font-size:.9rem;margin:.5rem 0}
.meta dt{color:var(--muted)}
.meta dd{margin:0;overflow-wrap:anywhere}
.finding{background:var(--panel);border:1px solid var(--border);border-left-width:6px;
  border-radius:8px;padding:12px 14px;margin:.75rem 0;overflow-wrap:anywhere}
.finding[data-severity="critical"]{border-left-color:var(--crit)}
.finding[data-severity="high"]{border-left-color:var(--high)}
.finding[data-severity="medium"]{border-left-color:var(--med)}
.finding[data-severity="low"]{border-left-color:var(--low)}
.finding[data-severity="info"]{border-left-color:var(--info)}
.finding header{display:flex;flex-wrap:wrap;gap:.4rem .6rem;align-items:center;
  max-width:none;padding:0;margin:0 0 .5rem}
.badge{font-size:.72rem;font-weight:700;letter-spacing:.04em;text-transform:uppercase;
  padding:.12rem .4rem;border-radius:999px;border:1px solid currentColor}
.sev-critical{color:var(--crit)}.sev-high{color:var(--high)}.sev-medium{color:var(--med)}
.sev-low{color:var(--low)}.sev-info{color:var(--info)}
.state{font-size:.75rem;color:var(--muted);border:1px dashed currentColor;border-radius:999px;
  padding:.1rem .4rem}
code,pre{font:.86rem/1.45 ui-monospace,SFMono-Regular,Menlo,Consolas,monospace}
.rule{font-weight:700}
.location{color:var(--muted)}
.evidence{background:var(--bg);border:1px solid var(--border);border-radius:6px;
  padding:.5rem .6rem;white-space:pre-wrap;overflow-wrap:anywhere;margin:.5rem 0}
.detail{display:grid;grid-template-columns:max-content 1fr;gap:.2rem 1rem;margin:.4rem 0 0;font-size:.9rem}
.detail dt{color:var(--muted);font-weight:600}
.detail dd{margin:0}
.note{color:var(--muted);font-size:.88rem}
.errors{background:var(--panel);border:1px solid var(--border);border-radius:8px;padding:12px}
footer{color:var(--muted);font-size:.85rem;margin-top:40px;padding-bottom:32px;
  border-top:1px solid var(--border);padding-top:16px}
@media print{
  .controls,.skip{display:none!important}
  body{background:#fff;color:#000}
  .finding,.tile{break-inside:avoid;background:#fff}
  a[href]::after{content:" (" attr(href) ")";font-size:.75em}
}
""".strip()

_SCRIPT = """
(function(){
  var sev=document.getElementById("filter-severity");
  var query=document.getElementById("filter-text");
  var findings=Array.prototype.slice.call(document.querySelectorAll("[data-finding]"));
  var sections=Array.prototype.slice.call(document.querySelectorAll("[data-target-section]"));
  function apply(){
    var wanted=sev.value;
    var needle=query.value.trim().toLowerCase();
    findings.forEach(function(el){
      var sevOk=wanted==="all"||el.getAttribute("data-severity")===wanted;
      var textOk=!needle||el.textContent.toLowerCase().indexOf(needle)!==-1;
      el.hidden=!(sevOk&&textOk);
    });
    sections.forEach(function(section){
      var any=Array.prototype.some.call(
        section.querySelectorAll("[data-finding]"),
        function(el){return !el.hidden;}
      );
      section.hidden=!any;
    });
  }
  sev.addEventListener("change",apply);
  query.addEventListener("input",apply);
})();
""".strip()


def _esc(value) -> str:
    """Neutralise invisibles, then HTML-escape, every dynamic value."""
    text = "" if value is None else str(value)
    return html.escape(escape_unsafe(text), quote=True)


def _csp_hash(text: str) -> str:
    digest = hashlib.sha256(text.encode("utf-8")).digest()
    return "sha256-" + base64.b64encode(digest).decode("ascii")


def _visible(result: AuditResult, options: AuditOptions) -> list:
    return [
        finding
        for finding in result.findings
        if (options.show_suppressed or not finding.suppressed)
        and (options.show_baselined or not finding.baselined)
    ]


def _severity_class(finding) -> str:
    return f"sev-{finding.severity.value}"


def _location(finding) -> str:
    suffix = f":{finding.line}" if finding.line else ""
    return f"{_esc(finding.path)}{suffix}"


def _finding_html(finding) -> str:
    states = []
    if finding.suppressed:
        states.append('<span class="state">suppressed</span>')
    if finding.baselined:
        states.append('<span class="state">baselined</span>')
    if getattr(finding, "intent_matched", False):
        states.append('<span class="state">declared intent</span>')
    details = []
    if finding.rationale:
        details.append(f"<dt>Why</dt><dd>{_esc(finding.rationale)}</dd>")
    if finding.remediation:
        details.append(f"<dt>Fix</dt><dd>{_esc(finding.remediation)}</dd>")
    if finding.context_note:
        details.append(f"<dt>Context</dt><dd>{_esc(finding.context_note)}</dd>")
    if finding.cwes:
        details.append(f"<dt>CWE</dt><dd>{_esc(', '.join(finding.cwes))}</dd>")
    evidence = ""
    if finding.evidence:
        evidence = (
            '<pre class="evidence"><code>'
            + _esc(finding.evidence)
            + "</code></pre>"
        )
    detail_block = (
        '<dl class="detail">' + "".join(details) + "</dl>" if details else ""
    )
    return (
        f'<article class="finding" data-finding data-severity="{finding.severity.value}" '
        f'data-ast="{_esc(finding.ast)}">'
        "<header>"
        f'<span class="badge {_severity_class(finding)}">{_esc(finding.severity.value)}</span>'
        f'<span class="badge sev-{_esc(finding.confidence.value)}">'
        f"{_esc(finding.confidence.value)} confidence</span>"
        f'<code class="rule">{_esc(finding.rule_id)}</code>'
        f'<span class="location">{_location(finding)}</span>'
        + "".join(states)
        + "</header>"
        f'<p class="message">{_esc(finding.message)}</p>'
        + evidence
        + detail_block
        + "</article>"
    )


def _target_html(result: AuditResult, index: int, options: AuditOptions) -> str:
    target = result.target
    version = f"@{_esc(target.version)}" if target.version else ""
    findings = _visible(result, options)
    verdict = "PASS" if result.passed else "FAIL"
    verdict = "PASS" if result.passed else "FAIL"
    by_ast: dict[str, list] = defaultdict(list)
    for finding in findings:
        by_ast[finding.ast].append(finding)
    groups = []
    for ast in sorted(by_ast):
        groups.append(f"<h3>{_esc(ast)} — {_esc(AST_NAMES.get(ast, ''))}</h3>")
        groups.extend(_finding_html(finding) for finding in by_ast[ast])
    body = "".join(groups) if findings else '<p class="note">No visible findings.</p>'
    plugin = (
        f"<dt>Plugin</dt><dd>{_esc(target.plugin)}</dd>" if target.plugin else ""
    )
    intent = ""
    if target.declared_intent:
        downgraded = sum(1 for finding in result.findings if finding.intent_matched)
        state = "allowed" if target.intent_allowed else "not applied"
        intent = (
            f"<dt>Declared intent</dt><dd>{_esc(target.declared_intent)} "
            f"({state}; {downgraded} downgraded)</dd>"
        )
    return (
        f'<section class="target" data-target-section id="target-{index}">'
        f"<h2>{_esc(target.display)}</h2>"
        '<dl class="meta">'
        f"<dt>Skill</dt><dd>{_esc(result.skill.name or target.name)}{version}</dd>"
        f"<dt>Location</dt><dd>{_esc(target.location)}</dd>"
        f"<dt>Kind</dt><dd>{_esc(target.kind)}</dd>"
        f"{plugin}"
        f"{intent}"
        f"<dt>Result</dt><dd class=\"verdict {'pass' if result.passed else 'fail'}\">{verdict}</dd>"
        f"<dt>Findings</dt><dd>{len(result.findings)} "
        f"({result.gating_count} gating, {result.suppressed_count} suppressed, "
        f"{result.baseline_matched} baselined)</dd>"
        "</dl>"
        f"{body}"
        "</section>"
    )


def _fleet_html(report) -> str:
    rows = []
    for result in report.results:
        counts = result.summary()["severity"]
        rows.append(
            "<tr>"
            f"<td>{_esc(result.target.display)}</td>"
            f"<td class=\"{'pass' if result.passed else 'fail'}\">"
            f"{'PASS' if result.passed else 'FAIL'}</td>"
            f'<td class="num">{counts["critical"]}</td>'
            f'<td class="num">{counts["high"]}</td>'
            f'<td class="num">{counts["medium"]}</td>'
            f'<td class="num">{counts["low"]}</td>'
            f'<td class="num">{counts["info"]}</td>'
            f'<td class="num">{result.gating_count}</td>'
            "</tr>"
        )
    return (
        '<table class="fleet"><caption>Targets</caption><thead><tr>'
        '<th scope="col">Target</th><th scope="col">Result</th>'
        '<th scope="col" class="num">Crit</th><th scope="col" class="num">High</th>'
        '<th scope="col" class="num">Med</th><th scope="col" class="num">Low</th>'
        '<th scope="col" class="num">Info</th><th scope="col" class="num">Gating</th>'
        "</tr></thead><tbody>" + "".join(rows) + "</tbody></table>"
    )


def _coverage_html(report) -> str:
    if not report.results:
        return '<h2>Coverage &amp; limitations</h2><p class="note">No targets were scanned.</p>'
    coverage = report.results[0].coverage
    assessed = "".join(f"<li>{_esc(item)}</li>" for item in coverage.assessed)
    not_assessed = "".join(f"<li>{_esc(item)}</li>" for item in coverage.not_assessed)
    notes = [note for result in report.results for note in result.coverage.notes]
    note_block = ""
    if notes:
        items = "".join(f"<li>{_esc(note)}</li>" for note in notes[:50])
        more = (
            f'<p class="note">… {len(notes) - 50} more note(s); see the JSON report.</p>'
            if len(notes) > 50
            else ""
        )
        note_block = f"<h3>Scan notes</h3><ul>{items}</ul>{more}"
    return (
        "<h2>Coverage &amp; limitations</h2>"
        "<h3>Assessed</h3>"
        f"<ul>{assessed}</ul>"
        "<h3>Not assessed</h3>"
        f"<ul>{not_assessed}</ul>"
        f"{note_block}"
        '<p class="note">A clean report means no configured static check triggered. '
        "It is not proof that the artifact is safe or behaves as documented.</p>"
    )


def render(report, options: AuditOptions) -> str:
    summary = report.summary()
    severity = summary["severity"]
    verdict = "PASS" if report.passed else "FAIL"
    style_hash = _csp_hash(_STYLE)
    script_hash = _csp_hash(_SCRIPT)
    csp = (
        "default-src 'none'; base-uri 'none'; form-action 'none'; img-src 'none'; "
        f"style-src '{style_hash}'; script-src '{script_hash}'"
    )
    errors = ""
    if report.errors:
        items = "".join(f"<li>{_esc(error)}</li>" for error in report.errors)
        errors = f'<section class="errors"><h2>Scan errors</h2><ul>{items}</ul></section>'
    fleet = _fleet_html(report) if len(report.results) > 1 else ""
    targets = "".join(
        _target_html(result, index, options)
        for index, result in enumerate(report.results, start=1)
    )
    tiles = [
        ("Targets", summary["targets"]),
        ("Gating", summary["gating"]),
        ("Critical", severity["critical"]),
        ("High", severity["high"]),
        ("Medium", severity["medium"]),
        ("Low", severity["low"]),
        ("Info", severity["info"]),
        ("Suppressed", summary["suppressed"]),
        ("Baselined", summary["baselined"]),
        ("Intent-downgraded", summary["intent"]),
        ("Errors", summary["errors"]),
    ]
    tile_html = "".join(
        f'<div class="tile"><span class="n">{value}</span><span class="l">{label}</span></div>'
        for label, value in tiles
    )
    return (
        "<!doctype html>\n"  # nosec B608 - fixed HTML/CSS document, no SQL
        '<html lang="en">\n<head>\n'
        '<meta charset="utf-8">\n'
        '<meta name="viewport" content="width=device-width, initial-scale=1">\n'
        '<meta name="referrer" content="no-referrer">\n'
        f'<meta http-equiv="Content-Security-Policy" content="{csp}">\n'
        f"<title>skilltriage report — {verdict}</title>\n"
        f"<style>{_STYLE}</style>\n"
        "</head>\n<body>\n"
        '<a class="skip" href="#main">Skip to content</a>\n'
        "<header>\n"
        f"<h1>skilltriage {_esc(report.tool_version)} — static security audit</h1>\n"
        f'<p class="sub">Generated {_esc(report.generated)} · '
        f"command <code>{_esc(report.command)}</code></p>\n"
        f'<p class="verdict {"pass" if report.passed else "fail"}">Result: {verdict}'
        f" — {summary['gating']} gating finding(s), {summary['errors']} scan error(s)</p>\n"
        f'<p class="sub">Gate: {_esc(format_gate(options))} · '
        f'Taxonomy: OWASP Agentic Skills Top 10 ({_esc(OWASP_URL)})</p>\n'
        "</header>\n<main id=\"main\">\n"
        f'<section class="tiles" aria-label="Summary">{tile_html}</section>\n'
        '<section class="controls" aria-label="Filter findings">'
        '<label for="filter-severity">Severity</label>'
        '<select id="filter-severity">'
        '<option value="all">All</option>'
        '<option value="critical">Critical</option>'
        '<option value="high">High</option>'
        '<option value="medium">Medium</option>'
        '<option value="low">Low</option>'
        '<option value="info">Info</option>'
        "</select>"
        '<label for="filter-text">Search</label>'
        '<input id="filter-text" type="search" placeholder="rule, path, or text">'
        "<noscript><span class=\"note\">Filtering needs JavaScript; every finding is "
        "shown without it.</span></noscript>"
        "</section>\n"
        f"{fleet}\n"
        f"{errors}\n"
        f'<div id="targets">{targets}</div>\n'
        f"{_coverage_html(report)}\n"
        "</main>\n"
        "<footer>"
        "<p>Static checks are heuristic. Reports can contain excerpts from the audited "
        "artifact; review before sharing.</p>"
        "</footer>\n"
        f"<script>{_SCRIPT}</script>\n"
        "</body>\n</html>\n"
    )


__all__ = ["render"]

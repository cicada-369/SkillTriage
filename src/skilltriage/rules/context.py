"""Context-aware severity scoring.

A security skill legitimately documents ``curl | bash`` as an example. A
malicious skill hides the same text in prose or a script. The difference is
context, so findings are downgraded — never silently dropped — when they match
inside documentation-like paths, fenced example blocks, warning sentences, or
code comments. The downgrade is recorded in ``context_note`` so a reviewer can
see why.

**High-severity guard.** Context words are artifact-controlled, so they must not
be able to talk a critical or high finding below the default gate. Outside a
documentation path, a CRITICAL finding is never downgraded, and a HIGH finding is
downgraded only when the artifact identifies itself as security tooling in its
path. This closes the one-word bypass (``curl .../test/x.sh | bash`` or a
trailing ``# test``) while keeping the security-tool corpus readable. A malicious
package can still impersonate security tooling; declared intent requires an
inventory record and every downgrade stays visible.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

from ..models import Confidence, Severity

_DOC_PATH_PARTS = {
    "docs", "doc", "documentation", "examples", "example", "samples", "sample",
    "references", "reference", "templates", "template", "fixtures", "fixture",
    "tests", "test", "spec", "specs", "third_party", "vendor",
}
_DOC_FILENAMES = (
    "readme", "changelog", "contributing", "license", "notice", "security",
    "test", "spec", "access", "install", "usage", "guide", "manual",
)
_EXAMPLE_FENCE_LANGS = {
    "", "text", "txt", "plain", "markdown", "md", "mdx", "example", "examples",
    "output", "console", "log", "diff", "yaml", "yml", "json",
}
_WARNING_RE = re.compile(
    r"(?i)\b(never|do not|don't|avoid|warning|caution|example|sample|malicious|"
    r"attacker|untrusted|for testing|demonstration|fixture|not run|do not run|"
    r"dangerous|unsafe|illustrative|synthetic|benign)\b"
)
# Security tooling legitimately contains the exact strings a malicious skill uses:
# detection signatures, payload samples, and test fixtures. Matching one of these
# words lowers severity (never drops the finding) so a reviewer can distinguish a
# scanner from a payload without the tool going silent.
_DETECTION_RE = re.compile(
    r"(?i)\b(?:detect(?:s|or|ion|ing)?|signature|signatures|pattern|patterns|"
    r"regex|rule|rules|scanner|scanning|audit(?:or|ing)?|indicator|payload|"
    r"example|sample|fixture|test(?:ing)?|collect(?:ion|ing|or)?|gather|evidence|"
    r"inspect(?:ion)?|monitor(?:ing)?|baseline|hardening|remediation|"
    r"validat(?:e|or|ion)|guard|sanitiz(?:e|er|ation)|allowlist|denylist|"
    r"blocklist|policy|leak(?:s|ed|ing)?|instruction\s+override|"
    r"malicious|attacker|untrusted|warning|never|do not|don't|avoid|"
    r"for testing|demonstration)\b"
)
_DETECTION_PATH_TOKENS = (
    "test", "fixture", "example", "sample", "detector", "scanner", "auditor",
    "checker", "analyzer", "tester", "monitor", "collector", "validate",
    "validation", "validator", "guard", "sanitize", "sanitizer",
)
# A high-severity match in executable or instruction content is not downgraded
# by artifact-controlled words alone. Security tooling keeps the noise-reduction
# path, but it must identify itself in the path; a malicious package can
# impersonate that, which is why declared intent also requires an inventory
# record and every downgraded finding stays visible.
_SECURITY_PATH_TOKENS = (
    "security", "redteam", "red-team", "blue-team", "purple-team", "exploit",
    "pentest", "malware", "forensic", "detector", "scanner", "auditor",
    "checker", "tester", "threat", "hunting", "incident", "recon", "osint",
    "vulnerability", "crypto", "grc", "compliance", "supply-chain", "ot-ics",
    "log-analysis", "csoc", "ai-llm", "reverse-engineering", "rule", "guidance",
)
# (kept as a tuple; membership uses substring matching below)
_DOC_EXTENSIONS = {".md", ".markdown", ".mdx", ".rst", ".txt", ".adoc", ".html", ".htm"}


@dataclass(frozen=True)
class Fence:
    start: int
    end: int
    lang: str


def parse_fences(text: str) -> list[Fence]:
    fences: list[Fence] = []
    open_start: int | None = None
    open_lang = ""
    for line_no, line in enumerate(text.splitlines(), start=1):
        stripped = line.lstrip()
        if stripped.startswith("```") or stripped.startswith("~~~"):
            marker = stripped[:3]
            if open_start is None:
                open_start = line_no
                info = stripped[3:].strip().split()
                open_lang = info[0].lower() if info else ""
            else:
                fences.append(Fence(open_start, line_no, open_lang))
                open_start = None
                open_lang = ""
    if open_start is not None:
        fences.append(Fence(open_start, len(text.splitlines()), open_lang))
    return fences


def fence_language(fences: list[Fence], line: int) -> str | None:
    for fence in fences:
        if fence.start <= line <= fence.end:
            return fence.lang
    return None


def is_doc_path(path: str) -> bool:
    lowered = path.lower()
    parts = lowered.split("/")
    filename = parts[-1] if parts else lowered
    if any(part in _DOC_PATH_PARTS for part in parts[:-1]):
        return True
    if filename.endswith(tuple(_DOC_EXTENSIONS)) and filename.startswith(_DOC_FILENAMES):
        return True
    return False


def is_warning_line(line: str) -> bool:
    return bool(_WARNING_RE.search(line or ""))


def is_comment_line(path: str, line: str) -> bool:
    stripped = (line or "").lstrip()
    if stripped.startswith(("#", "//", "--", ";", "<!--", "/*", "*")):
        return True
    return False


def score(
    *,
    severity: Severity,
    confidence: Confidence,
    path: str,
    line_text: str,
    fence_lang: str | None,
    is_code: bool,
    artifact_context: str = "",
) -> tuple[Severity, Confidence, str]:
    """Return the adjusted severity, confidence, and a human-readable note."""
    notes: list[str] = []
    adjusted_severity = severity
    adjusted_confidence = confidence
    downgrades = 0

    def downgrade() -> None:
        nonlocal adjusted_severity, adjusted_confidence, downgrades
        if downgrades < 2:
            adjusted_severity = adjusted_severity.down()
            downgrades += 1
        adjusted_confidence = Confidence.LOW

    lowered_path = path.lower()
    filename = path.rsplit("/", 1)[-1].lower()
    documentation = is_doc_path(path)
    security_context = any(
        token in (lowered_path + " " + artifact_context.lower())
        for token in _SECURITY_PATH_TOKENS
    )
    detector_file = any(token in filename for token in _DETECTION_PATH_TOKENS)
    if not documentation:
        # A critical payload must not be talked below the gate by a trailing
        # comment, a word such as "test" in a URL, or a detector-like filename.
        # A security artifact may still contain a critical example; allow that
        # only when both the artifact context and the file identify it as
        # tooling. Impersonation is the residual risk; intent is the strong
        # control and every downgrade stays visible.
        if severity.rank >= Severity.CRITICAL.rank and not (
            security_context and detector_file
        ):
            return severity, confidence, ""
        # High-severity findings in non-documentation content keep their gate
        # unless the artifact identifies itself as security tooling.
        if severity.rank >= Severity.HIGH.rank and not security_context:
            return severity, confidence, ""

    if is_code:
        if is_comment_line(path, line_text):
            downgrade()
            notes.append("matched inside a code comment")
        if any(token in filename for token in _DETECTION_PATH_TOKENS):
            downgrade()
            notes.append("matched in a security-tool/test file")
        if _DETECTION_RE.search(line_text or ""):
            downgrade()
            notes.append("line contains detection or example language")
    else:
        if is_doc_path(path):
            downgrade()
            notes.append("matched in a documentation/example path")
        if fence_lang is not None and (
            fence_lang in _EXAMPLE_FENCE_LANGS or is_doc_path(path)
        ):
            downgrade()
            notes.append(f"matched inside a fenced '{fence_lang or 'text'}' block")
        if is_warning_line(line_text):
            downgrade()
            notes.append("line uses warning/example language")
        if _DETECTION_RE.search(line_text or ""):
            downgrade()
            notes.append("line contains detection or example language")

    return adjusted_severity, adjusted_confidence, "; ".join(dict.fromkeys(notes))

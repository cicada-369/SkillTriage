from __future__ import annotations

import re
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Iterable

SKILL_FILE = "SKILL.md"
MAX_FILE_BYTES = 1_000_000

@dataclass
class Finding:
    severity: str
    code: str
    path: str
    message: str
    rationale: str
    line: int | None = None

    def to_dict(self):
        return asdict(self)

@dataclass
class AuditResult:
    root: str
    findings: list[Finding]
    files_checked: int

    @property
    def passed(self) -> bool:
        return not any(f.severity == "ERROR" for f in self.findings)

    def to_dict(self):
        return {
            "root": self.root,
            "passed": self.passed,
            "files_checked": self.files_checked,
            "summary": {
                severity: sum(1 for f in self.findings if f.severity == severity)
                for severity in ("ERROR", "WARN", "INFO")
            },
            "findings": [f.to_dict() for f in self.findings],
        }

# These are review signals, not proof of exploitability. Comments and examples can trigger them.
PATTERNS = [
    ("ERROR", "SHELL_DOWNLOAD_EXEC", re.compile(r"(curl|wget)[^\n|]*\|\s*(sudo\s+)?(sh|bash)\b", re.I),
     "Downloads and immediately executes remote content.",
     "Pin and verify downloaded artifacts; inspect them before execution."),
    ("WARN", "PRIVILEGED_COMMAND", re.compile(r"\bsudo\s+(rm|chmod|chown|iptables|nft|systemctl|mount|dd)\b", re.I),
     "Privileged system-changing command appears in the skill.",
     "Explain the impact, require explicit approval, and provide rollback/verification steps."),
    ("WARN", "DESTRUCTIVE_COMMAND", re.compile(r"\brm\s+-rf\b|\bmkfs(\.\w+)?\b|\bdd\s+if=", re.I),
     "Potentially destructive command appears in the skill.",
     "Use a disposable test environment and add a safe dry-run path."),
    ("WARN", "SECRET_EXPOSURE", re.compile(r"\b(api[_-]?key|secret|password|access[_-]?token)\b.{0,30}(print|echo|log|display)", re.I),
     "Possible secret exposure pattern appears in the skill.",
     "Never print credentials; use a secret manager and redact logs."),
    ("WARN", "PROMPT_OVERRIDE", re.compile(r"(ignore|disregard|override).{0,40}(previous|prior|system|developer).{0,20}(instruction|prompt)", re.I),
     "Text resembles an instruction-override attempt.",
     "Treat this as a review signal; ensure untrusted content cannot override trusted policy."),
    ("WARN", "UNBOUNDED_NETWORK", re.compile(r"\b(curl|wget|requests\.get|urllib\.request)\b", re.I),
     "Network access is referenced.",
     "Document allowed destinations, timeouts, response-size limits, and data handling."),
]

def _read_text(path: Path) -> str:
    try:
        if path.stat().st_size > MAX_FILE_BYTES:
            return ""
        return path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return ""

def _frontmatter(text: str) -> tuple[dict[str, str], bool]:
    """Small, dependency-free parser for simple YAML-like key: value metadata."""
    if not text.startswith("---\n"):
        return {}, False
    end = text.find("\n---", 4)
    if end < 0:
        return {}, False
    meta = {}
    for line in text[4:end].splitlines():
        if ":" in line and not line.lstrip().startswith("#"):
            key, value = line.split(":", 1)
            meta[key.strip()] = value.strip().strip("'\"")
    return meta, True

def audit_skill(root: str | Path) -> AuditResult:
    root = Path(root).expanduser().resolve()
    findings: list[Finding] = []
    files_checked = 0

    if not root.exists() or not root.is_dir():
        return AuditResult(str(root), [Finding("ERROR", "ROOT_NOT_FOUND", str(root),
            "Skill directory does not exist or is not a directory.",
            "Pass the directory containing SKILL.md.")], 0)

    skill_file = root / SKILL_FILE
    if not skill_file.is_file():
        findings.append(Finding("ERROR", "MISSING_SKILL_MD", str(skill_file),
            "Required SKILL.md file was not found.",
            "Create a skill entrypoint with clear purpose, instructions, and constraints."))
    else:
        files_checked += 1
        text = _read_text(skill_file)
        meta, has_frontmatter = _frontmatter(text)
        if not has_frontmatter:
            findings.append(Finding("WARN", "MISSING_FRONTMATTER", str(skill_file),
                "No simple YAML frontmatter found at the top of SKILL.md.",
                "Many skill loaders use metadata to identify and describe a skill. Check your target platform's exact schema."))
        else:
            if not meta.get("name"):
                findings.append(Finding("ERROR", "MISSING_NAME", str(skill_file),
                    "Frontmatter is missing a name field.", "Give the skill a stable, descriptive name."))
            if not meta.get("description"):
                findings.append(Finding("ERROR", "MISSING_DESCRIPTION", str(skill_file),
                    "Frontmatter is missing a description field.", "Describe when the skill should and should not activate."))
        if len(text.strip()) < 100:
            findings.append(Finding("WARN", "VERY_SHORT_SKILL", str(skill_file),
                "SKILL.md is unusually short.", "Include purpose, workflow, boundaries, and expected output."))

    # Do not follow symlinks: skills can point outside the inspected directory.
    for path in root.rglob("*"):
        if path.is_symlink():
            findings.append(Finding("WARN", "SYMLINK_NOT_FOLLOWED", str(path.relative_to(root)),
                "Symbolic link was not followed.",
                "Review the target manually; it may reference content outside the skill package."))
            continue
        if not path.is_file() or path.name == SKILL_FILE:
            continue
        if any(part.startswith(".") for part in path.relative_to(root).parts):
            findings.append(Finding("INFO", "HIDDEN_FILE", str(path.relative_to(root)),
                "Hidden file exists in the skill package.",
                "Confirm it is intentionally included and contains no credentials or local state."))
        files_checked += 1
        content = _read_text(path)
        if not content and path.stat().st_size > MAX_FILE_BYTES:
            findings.append(Finding("WARN", "FILE_TOO_LARGE", str(path.relative_to(root)),
                "File exceeded the 1 MB inspection limit and was skipped.",
                "Review it separately or split documentation into smaller files."))
            continue
        for number, line in enumerate(content.splitlines(), start=1):
            for severity, code, pattern, message, rationale in PATTERNS:
                if pattern.search(line):
                    findings.append(Finding(severity, code, str(path.relative_to(root)),
                        message, rationale, number))
    if not findings:
        findings.append(Finding("INFO", "NO_FINDINGS", ".", "No configured checks triggered.",
            "This is not proof that the skill is safe or behaves correctly."))

    # Stable output; avoid duplicate same-rule hits on identical lines.
    unique = {}
    for f in findings:
        unique[(f.severity, f.code, f.path, f.line, f.message)] = f
    ordered = sorted(unique.values(), key=lambda f: (
        {"ERROR": 0, "WARN": 1, "INFO": 2}.get(f.severity, 3), f.path, f.line or 0, f.code))
    return AuditResult(str(root), ordered, files_checked)

def render_markdown(result: AuditResult) -> str:
    counts = result.to_dict()["summary"]
    lines = [
        "# Agent Skill Tester report", "",
        f"- **Skill directory:** `{result.root}`",
        f"- **Result:** {'PASS' if result.passed else 'FAIL'}",
        f"- **Files checked:** {result.files_checked}",
        f"- **Findings:** {counts['ERROR']} error(s), {counts['WARN']} warning(s), {counts['INFO']} info",
        "",
        "> Static checks are heuristic. A clean report does not prove runtime behavior or security.", "",
        "| Severity | Code | File:line | Finding | Why / suggested action |",
        "|---|---|---|---|---|",
    ]
    for f in result.findings:
        location = f"`{f.path}`" + (f":{f.line}" if f.line else "")
        lines.append(f"| {f.severity} | `{f.code}` | {location} | {f.message} | {f.rationale} |")
    return "\n".join(lines) + "\n"

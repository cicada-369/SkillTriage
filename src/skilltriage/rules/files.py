"""File-level rules: links, modes, binaries, hidden content (AST06, AST08)."""

from __future__ import annotations

from pathlib import Path

from ..models import Confidence, Severity
from .base import Rule, RuleContext

RULES: list[Rule] = []

_ALLOWED_HIDDEN = {
    ".gitignore",
    ".gitattributes",
    ".editorconfig",
    ".claude-plugin",
    ".mcp.json",
    ".github",
    ".vscode",
    ".DS_Store",
    ".gitkeep",
}
_EXECUTABLE_MAGIC = {"ELF executable", "PE executable", "Mach-O executable", "Python bytecode"}
_CONTAINER_MAGIC = {"ZIP archive", "gzip stream", "PDF document", "OLE/Office document"}


def _inside(root: Path, target: Path) -> bool:
    try:
        target.resolve(strict=False).relative_to(root.resolve())
        return True
    except ValueError:
        return False


def check_symlinks(ctx: RuleContext) -> None:
    for record in ctx.files:
        if not record.is_symlink:
            continue
        target = (ctx.root / record.path).resolve(strict=False)
        if not _inside(ctx.root, target):
            ctx.emit(
                RULE_SYMLINK_ESCAPE,
                path=record.path,
                message="Symbolic link points outside the skill package.",
                evidence=f"{record.link_target or '(unknown)'} -> {target}",
            )
        else:
            ctx.emit(
                RULE_SYMLINK,
                path=record.path,
                message="Symbolic link is present and was not followed.",
                evidence=f"-> {record.link_target}",
            )


def check_modes(ctx: RuleContext) -> None:
    for record in ctx.files:
        if record.is_symlink:
            continue
        if record.mode & 0o6000:
            ctx.emit(
                RULE_SETUID,
                path=record.path,
                message="File has setuid or setgid permission bits.",
                evidence=f"mode {record.mode:04o}",
            )
        if record.mode & 0o002:
            ctx.emit(
                RULE_WORLD_WRITABLE,
                path=record.path,
                message="File is world-writable.",
                evidence=f"mode {record.mode:04o}",
            )


def check_binaries(ctx: RuleContext) -> None:
    for record in ctx.files:
        if record.kind == "device":
            ctx.emit(
                RULE_DEVICE_FILE,
                path=record.path,
                message="Package contains a device, socket, or FIFO.",
                evidence=record.skipped or "non-regular file",
            )
            continue
        if record.kind != "binary":
            continue
        if record.magic in _EXECUTABLE_MAGIC:
            ctx.emit(
                RULE_BINARY_ARTIFACT,
                path=record.path,
                message=f"Executable or bytecode artifact present ({record.magic}).",
                evidence=f"{record.magic}, {record.size} bytes",
            )
        elif record.magic in _CONTAINER_MAGIC:
            ctx.emit(
                RULE_ARCHIVE_ARTIFACT,
                path=record.path,
                message=f"Container or document content was not inspected ({record.magic}).",
                evidence=f"{record.magic}, {record.size} bytes",
            )
        else:
            ctx.emit(
                RULE_BINARY_ARTIFACT,
                path=record.path,
                severity=Severity.LOW,
                message="Binary content was not inspected.",
                evidence=record.magic or f"{record.size} bytes",
            )


def check_hidden(ctx: RuleContext) -> None:
    for record in ctx.files:
        parts = record.path.split("/")
        hidden = [part for part in parts if part.startswith(".")]
        if not hidden:
            continue
        if any(part in _ALLOWED_HIDDEN for part in hidden):
            continue
        ctx.emit(
            RULE_HIDDEN_FILE,
            path=record.path,
            message="Hidden file or directory is included in the package.",
            evidence=record.path,
        )


def check_truncated(ctx: RuleContext) -> None:
    for record in ctx.files:
        if record.truncated:
            ctx.emit(
                RULE_TRUNCATED,
                path=record.path,
                message="File was too large to inspect in full.",
                evidence=record.skipped or f"{record.size} bytes",
            )


def check_archive_issues(ctx: RuleContext) -> None:
    for issue in ctx.tree.archive_issues[:25]:
        ctx.emit(RULE_ARCHIVE_MEMBER, path=".", message="Archive member was skipped.", evidence=issue)
    for note in ctx.tree.notes:
        lowered = note.lower()
        if lowered.startswith("skipped vendor directory"):
            ctx.emit(RULE_UNSCANNED_VENDOR, path=".", message="Vendor directory was not scanned.", evidence=note)
        elif "stopped after" in lowered or "byte budget" in lowered:
            ctx.emit(
                RULE_SCAN_INCOMPLETE,
                path=".",
                message="Scan stopped before covering the whole package.",
                evidence=note,
            )


RULE_SYMLINK_ESCAPE = Rule(
    id="AST06-SYMLINK-ESCAPE",
    ast="AST06",
    title="Symlink escapes the skill package",
    severity=Severity.HIGH,
    confidence=Confidence.HIGH,
    description="A link that resolves outside the package can pull arbitrary host content into the reviewed skill, or redirect writes outside the workspace.",
    remediation="Remove the link or replace it with a reviewed in-package copy.",
    cwes=("CWE-59",),
    tags=("filesystem",),
    no_context=True,
    check=check_symlinks,
)
RULES.append(RULE_SYMLINK_ESCAPE)

RULE_SYMLINK = Rule(
    id="AST06-SYMLINK",
    ast="AST06",
    title="Symbolic link present",
    severity=Severity.INFO,
    confidence=Confidence.HIGH,
    description="Links are not followed by this auditor; review the target manually because it may change outside the package.",
    remediation="Confirm the target is intentional and cannot be repointed by an attacker.",
    cwes=("CWE-59",),
    tags=("filesystem",),
    no_context=True,
    check=check_symlinks,
)
RULES.append(RULE_SYMLINK)

RULE_SETUID = Rule(
    id="AST06-SETUID",
    ast="AST06",
    title="Setuid or setgid file",
    severity=Severity.MEDIUM,
    confidence=Confidence.HIGH,
    description="Privilege-bearing mode bits in a skill package are unusual and can turn a script into a privilege boundary bypass.",
    remediation="Remove setuid/setgid bits and run skills as an unprivileged user.",
    cwes=("CWE-250",),
    tags=("filesystem",),
    no_context=True,
    check=check_modes,
)
RULES.append(RULE_SETUID)

RULE_WORLD_WRITABLE = Rule(
    id="AST06-WORLD-WRITABLE",
    ast="AST06",
    title="World-writable file",
    severity=Severity.LOW,
    confidence=Confidence.HIGH,
    description="A world-writable file can be modified by another local process between review and execution.",
    remediation="Restrict file permissions to the owning user.",
    cwes=("CWE-732",),
    tags=("filesystem",),
    no_context=True,
    check=check_modes,
)
RULES.append(RULE_WORLD_WRITABLE)

RULE_DEVICE_FILE = Rule(
    id="AST08-DEVICE-FILE",
    ast="AST08",
    title="Device, socket, or FIFO in package",
    severity=Severity.HIGH,
    confidence=Confidence.HIGH,
    description="Non-regular files can block a scanner, expose a host device, or change meaning between review and use.",
    remediation="Remove non-regular files from the skill package.",
    tags=("filesystem",),
    no_context=True,
    check=check_binaries,
)
RULES.append(RULE_DEVICE_FILE)

RULE_BINARY_ARTIFACT = Rule(
    id="AST08-BINARY-ARTIFACT",
    ast="AST08",
    title="Binary artifact not inspected",
    severity=Severity.HIGH,
    confidence=Confidence.HIGH,
    description="Executables and bytecode cannot be reviewed as text and are a known way to hide logic from scanners.",
    remediation="Remove compiled artifacts, or inspect them with a dedicated binary-analysis process.",
    tags=("filesystem", "evasion"),
    no_context=True,
    check=check_binaries,
)
RULES.append(RULE_BINARY_ARTIFACT)

RULE_ARCHIVE_ARTIFACT = Rule(
    id="AST08-ARCHIVE-ARTIFACT",
    ast="AST08",
    title="Archive or document content not inspected",
    severity=Severity.HIGH,
    confidence=Confidence.HIGH,
    description="ZIP, Office, PDF, and compressed content can carry instructions or code that a text scanner will not see.",
    remediation="Expand and inspect the content, or remove it from the skill package.",
    tags=("filesystem", "evasion"),
    no_context=True,
    check=check_binaries,
)
RULES.append(RULE_ARCHIVE_ARTIFACT)

RULE_HIDDEN_FILE = Rule(
    id="AST08-HIDDEN-FILE",
    ast="AST08",
    title="Hidden file in package",
    severity=Severity.INFO,
    confidence=Confidence.MEDIUM,
    description="Hidden files are easy to miss in review and may contain credentials or local state.",
    remediation="Confirm the file is intentional and contains no secrets or machine-specific state.",
    tags=("filesystem",),
    no_context=True,
    check=check_hidden,
)
RULES.append(RULE_HIDDEN_FILE)

RULE_TRUNCATED = Rule(
    id="AST08-FILE-TRUNCATED",
    ast="AST08",
    title="File truncated during inspection",
    severity=Severity.HIGH,
    confidence=Confidence.HIGH,
    description="A file above the inspection limit was only partially analysed, so its tail may contain unreviewed content.",
    remediation="Review the file separately or split it into smaller, reviewable files.",
    tags=("filesystem",),
    no_context=True,
    check=check_truncated,
)
RULES.append(RULE_TRUNCATED)

RULE_ARCHIVE_MEMBER = Rule(
    id="AST08-ARCHIVE-MEMBER",
    ast="AST08",
    title="Archive member skipped",
    severity=Severity.HIGH,
    confidence=Confidence.HIGH,
    description="Links, encrypted members, and special files are not extracted, so their content was not reviewed.",
    remediation="Inspect the skipped member manually and repackage the skill without it if unnecessary.",
    tags=("archive",),
    no_context=True,
    check=check_archive_issues,
)
RULES.append(RULE_ARCHIVE_MEMBER)

RULE_UNSCANNED_VENDOR = Rule(
    id="AST08-UNSCANNED-VENDOR",
    ast="AST08",
    title="Vendor directory not scanned",
    severity=Severity.MEDIUM,
    confidence=Confidence.HIGH,
    description="Third-party dependencies are part of the attack surface and were excluded by the default scan scope.",
    remediation="Re-run with --include-vendor or scan the dependency tree separately.",
    tags=("scope",),
    no_context=True,
    check=check_archive_issues,
)
RULES.append(RULE_UNSCANNED_VENDOR)

RULE_SCAN_INCOMPLETE = Rule(
    id="AST08-SCAN-INCOMPLETE",
    ast="AST08",
    title="Scan did not cover the whole package",
    severity=Severity.HIGH,
    confidence=Confidence.HIGH,
    description="A file-count or byte budget ended the scan early, leaving unreviewed content.",
    remediation="Raise the limits or scan the remaining files separately.",
    tags=("scope",),
    no_context=True,
    check=check_archive_issues,
)
RULES.append(RULE_SCAN_INCOMPLETE)

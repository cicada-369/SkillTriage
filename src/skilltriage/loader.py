"""Safe filesystem and archive loading.

Design rules:

* Never follow a symlink. Record it and move on.
* Never execute anything from the target.
* Bound every read and every archive expansion so a hostile package cannot
  exhaust memory or disk.
* Reject archive members that escape the extraction root (zip-slip), device
  files, FIFOs, and links.
* Read regular files with ``O_NOFOLLOW`` and ``O_NONBLOCK`` where available.
"""

from __future__ import annotations

import bz2
import gzip
import hashlib
import lzma
import os
import re
import shutil
import stat
import tarfile
import tempfile
import zipfile
import zlib
from contextlib import AbstractContextManager
from dataclasses import dataclass, field
from pathlib import Path, PurePosixPath
from typing import Iterator

from .models import FileRecord, tree_hash

SKIP_DIR_NAMES = {".git", ".hg", ".svn", "__pycache__"}
VENDOR_DIR_NAMES = {
    "node_modules",
    "vendor",
    "__pypackages__",
    ".venv",
    "venv",
    ".tox",
    ".nox",
}
ARCHIVE_SUFFIXES = {
    ".zip",
    ".tar",
    ".tar.gz",
    ".tgz",
    ".tar.bz2",
    ".tbz2",
    ".tar.xz",
    ".txz",
}
DRIVE_RE = re.compile(r"^[A-Za-z]:")
_WINDOWS_RESERVED = {
    "CON", "PRN", "AUX", "NUL",
    *(f"COM{index}" for index in range(1, 10)),
    *(f"LPT{index}" for index in range(1, 10)),
}


class TargetError(Exception):
    """The target cannot be audited safely or at all."""


@dataclass
class LoaderLimits:
    max_file_bytes: int = 2 * 1024 * 1024
    max_total_bytes: int = 256 * 1024 * 1024
    max_hash_bytes: int = 64 * 1024 * 1024
    max_files: int = 10_000
    max_archive_entries: int = 10_000
    max_archive_uncompressed: int = 256 * 1024 * 1024
    max_archive_bytes: int = 64 * 1024 * 1024
    max_compression_ratio: float = 200.0
    max_path_length: int = 4096
    include_vendor: bool = False


@dataclass
class LoadedTree:
    root: Path
    kind: str
    records: list[FileRecord] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)
    archive_issues: list[str] = field(default_factory=list)
    total_bytes: int = 0

    def relpaths(self) -> set[str]:
        return {record.path for record in self.records}

    def by_path(self) -> dict[str, FileRecord]:
        return {record.path: record for record in self.records}

    def content_hash(self) -> str:
        """Deterministic hash over path, kind, mode, size, status, and content."""
        return tree_hash(self.records)


def _open_no_follow(path: Path) -> int:
    flags = os.O_RDONLY
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    if hasattr(os, "O_NONBLOCK"):
        flags |= os.O_NONBLOCK
    return os.open(path, flags)


def _magic(head: bytes, suffix: str) -> str:
    if suffix == ".pyc" or head.startswith((b"\x42\x0d\x0d\x0a", b"\x6f\x0d\x0d\x0a")):
        return "Python bytecode"
    if head.startswith(b"\x7fELF"):
        return "ELF executable"
    if head.startswith(b"MZ"):
        return "PE executable"
    if head.startswith((b"\xca\xfe\xba\xbe", b"\xcf\xfa\xed\xfe", b"\xce\xfa\xed\xfe", b"\xfe\xed\xfa")):
        return "Mach-O executable"
    if head.startswith(b"PK\x03\x04") or head.startswith(b"PK\x05\x06"):
        return "ZIP archive"
    if head.startswith(b"\x1f\x8b"):
        return "gzip stream"
    if head.startswith(b"%PDF"):
        return "PDF document"
    if head.startswith(b"\x89PNG"):
        return "PNG image"
    if head.startswith(b"\xd0\xcf\x11\xe0"):
        return "OLE/Office document"
    if head.startswith(b"\xff\xd8\xff"):
        return "JPEG image"
    if head.startswith(b"GIF8"):
        return "GIF image"
    return ""


# A script or configuration file with a few invalid bytes is still reviewable
# text. Treating it as binary would let a payload hide behind a broken comment.
_FORCE_TEXT_SUFFIXES = {
    ".sh", ".bash", ".zsh", ".ksh", ".py", ".pyw", ".js", ".mjs", ".cjs",
    ".ts", ".tsx", ".rb", ".pl", ".php", ".ps1", ".bat", ".cmd", ".yaml",
    ".yml", ".json", ".toml", ".xml", ".html", ".htm", ".md", ".markdown",
    ".txt", ".cfg", ".ini", ".conf", ".service", ".desktop", ".env",
}


def _decode_text(raw: bytes, magic: str, suffix: str = "") -> tuple[str, str, str]:
    """Return ``(kind, text, magic)`` for a file's leading bytes."""
    if magic and magic not in ("Python bytecode",):
        return "binary", "", magic
    if suffix.lower() in _FORCE_TEXT_SUFFIXES and magic != "Python bytecode":
        return "text", raw.decode("utf-8", "replace"), magic
    if b"\x00" in raw[:8192]:
        return "binary", "", magic or "binary data"
    try:
        return "text", raw.decode("utf-8-sig"), magic
    except UnicodeDecodeError:
        decoded = raw.decode("utf-8", "replace")
        bad = decoded.count("\ufffd")
        if decoded and bad / max(len(decoded), 1) > 0.05:
            return "binary", "", magic or "non-text bytes"
        return "text", decoded, magic


def _read_regular(path: Path, suffix: str, limits: LoaderLimits) -> FileRecord:
    record = FileRecord(path="", kind="text")
    try:
        st = path.stat(follow_symlinks=False)
    except OSError as exc:
        record.error = str(exc)
        record.kind = "other"
        return record
    record.mode = stat.S_IMODE(st.st_mode)
    record.size = st.st_size
    if not stat.S_ISREG(st.st_mode):
        record.kind = "device"
        record.skipped = "not a regular file"
        return record

    hasher = hashlib.sha256()
    head = bytearray()
    read_bytes = 0
    # Keep enough to fill the content buffer and to hash the file, but never
    # read a single file past both caps. ``max_total_bytes`` is enforced over
    # the whole walk, not per file.
    read_cap = max(limits.max_file_bytes, limits.max_hash_bytes)
    try:
        fd = _open_no_follow(path)
    except OSError as exc:
        record.error = str(exc)
        record.kind = "other"
        return record
    try:
        opened = os.fstat(fd)
        if not stat.S_ISREG(opened.st_mode):
            os.close(fd)
            record.kind = "device"
            record.skipped = "not a regular file after open"
            return record
        # Use the size at open time, not the pre-open stat, so a file resized
        # between the walk and the read is accounted for.
        record.size = opened.st_size
        with os.fdopen(fd, "rb", closefd=True) as handle:
            while read_bytes < read_cap:
                chunk = handle.read(min(65536, read_cap - read_bytes))
                if not chunk:
                    break
                read_bytes += len(chunk)
                hasher.update(chunk)
                if len(head) < limits.max_file_bytes:
                    remaining = limits.max_file_bytes - len(head)
                    head.extend(chunk[:remaining])
        if read_bytes > record.size:
            record.size = read_bytes
        # Hash the bytes actually read. A capped or concurrently changed file
        # gets a prefix hash plus a status, never a constant marker that would
        # make unrelated large files collide.
        record.sha256 = hasher.hexdigest()
        if read_bytes >= read_cap:
            record.skipped = record.skipped or f"read capped at {read_cap} bytes"
            record.truncated = True
        elif record.size > limits.max_hash_bytes:
            record.skipped = record.skipped or "file too large to hash in full"
        elif read_bytes < record.size:
            record.skipped = record.skipped or "file changed while being read"
    except OSError as exc:
        record.error = str(exc)
        record.kind = "other"
        return record

    raw = bytes(head)
    magic = _magic(raw, suffix)
    if magic and magic != "Python bytecode":
        record.kind = "binary"
        record.magic = magic
        return record
    kind, text, magic = _decode_text(raw, magic, suffix)
    record.kind = kind
    record.magic = magic
    record.text = text
    if record.size > limits.max_file_bytes:
        record.truncated = True
        record.skipped = f"content truncated at {limits.max_file_bytes} bytes"
    return record


def _safe_member(name: str, limits: LoaderLimits) -> PurePosixPath:
    if not name or "\x00" in name:
        raise TargetError("archive contains an empty or NUL-containing member name")
    if len(name) > limits.max_path_length:
        raise TargetError("archive contains an over-long member path")
    normalised = name.replace("\\", "/")
    if DRIVE_RE.match(normalised):
        raise TargetError(f"archive contains an absolute drive path: {name!r}")
    path = PurePosixPath(normalised)
    if path.is_absolute():
        raise TargetError(f"archive contains an absolute path: {name!r}")
    for part in path.parts:
        if part in ("..", ""):
            raise TargetError(f"archive contains a path traversal member: {name!r}")
        if ":" in part:
            raise TargetError(
                f"archive member contains a drive or stream component: {name!r}"
            )
        if part != part.rstrip(" ."):
            raise TargetError(
                "archive member has a Windows-ambiguous trailing dot or space: "
                f"{name!r}"
            )
        if part.split(".", 1)[0].upper() in _WINDOWS_RESERVED:
            raise TargetError(f"archive member uses a reserved Windows name: {name!r}")
    return path


def _check_archive_budget(
    entry_count: int,
    uncompressed: int,
    compressed: int,
    limits: LoaderLimits,
) -> None:
    if entry_count > limits.max_archive_entries:
        raise TargetError(
            f"archive has {entry_count} entries, above the {limits.max_archive_entries} limit"
        )
    if uncompressed > limits.max_archive_uncompressed:
        raise TargetError(
            f"archive expands to {uncompressed} bytes, above the {limits.max_archive_uncompressed} limit"
        )
    if compressed > 0 and uncompressed / compressed > limits.max_compression_ratio:
        raise TargetError(
            f"archive compression ratio {uncompressed / compressed:.1f}:1 exceeds the "
            f"{limits.max_compression_ratio}:1 limit"
        )


def _zip_entry_count(path: Path) -> int | None:
    """Read the end-of-central-directory total before materialising entries."""
    try:
        size = path.stat().st_size
        if size < 22:
            return None
        with open(path, "rb") as handle:
            tail_size = min(size, 65_557)
            handle.seek(-tail_size, os.SEEK_END)
            tail = handle.read()
    except OSError:
        return None
    index = tail.rfind(b"PK\x05\x06")
    if index < 0 or index + 22 > len(tail):
        return None
    total = int.from_bytes(tail[index + 10 : index + 12], "little")
    if total == 0xFFFF:
        return None  # ZIP64: the real count is in the ZIP64 EOCD
    return total


def _check_decompressed_size(path: Path, limits: LoaderLimits) -> None:
    """Bound a compressed tar's decompressed size before tarfile allocates."""
    lowered = path.name.lower()
    if lowered.endswith((".tar.gz", ".tgz")):
        opener = gzip.open
    elif lowered.endswith((".tar.bz2", ".tbz2")):
        opener = bz2.open
    elif lowered.endswith((".tar.xz", ".txz")):
        opener = lzma.open
    else:
        if path.stat().st_size > limits.max_archive_uncompressed:
            raise TargetError("archive is larger than the uncompressed-size limit")
        return
    total = 0
    try:
        with opener(path, "rb") as handle:
            while True:
                chunk = handle.read(65536)
                if not chunk:
                    break
                total += len(chunk)
                if total > limits.max_archive_uncompressed:
                    raise TargetError(
                        "compressed archive expands beyond the "
                        f"{limits.max_archive_uncompressed}-byte limit"
                    )
    except TargetError:
        raise
    except (OSError, EOFError, zlib.error, lzma.LZMAError) as exc:
        raise TargetError(f"cannot read compressed archive: {exc}") from exc


def _extract_zip(path: Path, destination: Path, limits: LoaderLimits, issues: list[str]) -> None:
    try:
        size = path.stat().st_size
    except OSError as exc:
        raise TargetError(f"cannot stat ZIP archive: {exc}") from exc
    if size > limits.max_archive_bytes:
        raise TargetError(
            f"archive file is larger than {limits.max_archive_bytes} bytes"
        )
    declared = _zip_entry_count(path)
    if declared is not None and declared > limits.max_archive_entries:
        raise TargetError(
            f"archive declares {declared} entries, above the "
            f"{limits.max_archive_entries} limit"
        )
    if declared is None and size > 8 * 1024 * 1024:
        raise TargetError("ZIP64 or malformed archive above 8 MB is not supported")
    try:
        archive = zipfile.ZipFile(path)
    except (zipfile.BadZipFile, zipfile.LargeZipFile, OSError) as exc:
        raise TargetError(f"cannot open ZIP archive: {exc}") from exc
    with archive:
        try:
            infos = archive.infolist()
        except MemoryError as exc:
            raise TargetError("archive entry table is too large") from exc
        uncompressed = sum(info.file_size for info in infos)
        compressed = sum(info.compress_size for info in infos)
        _check_archive_budget(len(infos), uncompressed, compressed, limits)
        total_written = 0
        seen_names: set[str] = set()
        destination_root = destination.resolve()
        for info in infos:
            member = _safe_member(info.filename, limits)
            if info.is_dir():
                continue
            if info.filename in seen_names:
                issues.append(f"duplicate archive member: {info.filename}")
            seen_names.add(info.filename)
            mode = (info.external_attr >> 16) & 0o170000
            if stat.S_ISLNK(mode):
                issues.append(f"skipped symlink in archive: {info.filename}")
                continue
            if info.flag_bits & 0x1:
                issues.append(f"skipped encrypted archive member: {info.filename}")
                continue
            if info.file_size > limits.max_archive_uncompressed:
                raise TargetError(f"archive member {info.filename!r} is too large")
            target = destination.joinpath(*member.parts)
            try:
                target.resolve(strict=False).relative_to(destination_root)
            except ValueError:
                raise TargetError(
                    f"archive member {info.filename!r} escapes the extraction root"
                )
            target.parent.mkdir(parents=True, exist_ok=True)
            written = 0
            try:
                with archive.open(info) as source, open(target, "wb") as sink:
                    while True:
                        chunk = source.read(65536)
                        if not chunk:
                            break
                        written += len(chunk)
                        total_written += len(chunk)
                        if (
                            written > limits.max_archive_uncompressed
                            or total_written > limits.max_archive_uncompressed
                        ):
                            raise TargetError(f"archive member {info.filename!r} expands too far")
                        sink.write(chunk)
            except TargetError:
                raise
            except (
                zipfile.BadZipFile,
                zipfile.LargeZipFile,
                zlib.error,
                EOFError,
                RuntimeError,
                OSError,
            ) as exc:
                raise TargetError(f"cannot extract {info.filename!r}: {exc}") from exc
            original = (info.external_attr >> 16) & 0o7777
            if original & 0o6000:
                issues.append(f"archive member {info.filename!r} had setuid/setgid bits; stripped")
            os.chmod(target, 0o755 if original & 0o111 else 0o644)


def _extract_tar(path: Path, destination: Path, limits: LoaderLimits, issues: list[str]) -> None:
    try:
        size = path.stat().st_size
    except OSError as exc:
        raise TargetError(f"cannot stat TAR archive: {exc}") from exc
    if size > limits.max_archive_bytes:
        raise TargetError(
            f"archive file is larger than {limits.max_archive_bytes} bytes"
        )
    _check_decompressed_size(path, limits)
    try:
        archive = tarfile.open(path, mode="r:*")
    except (tarfile.TarError, OSError) as exc:
        raise TargetError(f"cannot open TAR archive: {exc}") from exc
    with archive:
        # Iterate lazily and stop at the configured entry budget. getmembers()
        # would materialise every header before the budget could be checked.
        members: list[tarfile.TarInfo] = []
        uncompressed = 0
        try:
            for member in archive:
                if len(members) >= limits.max_archive_entries:
                    raise TargetError(
                        "archive has more than "
                        f"{limits.max_archive_entries} entries"
                    )
                members.append(member)
                if member.isfile():
                    uncompressed += member.size
                    if uncompressed > limits.max_archive_uncompressed:
                        raise TargetError(
                            "archive expands to more than "
                            f"{limits.max_archive_uncompressed} bytes"
                        )
        except (tarfile.TarError, EOFError, OSError, zlib.error) as exc:
            raise TargetError(f"cannot read TAR archive: {exc}") from exc
        compressed = path.stat().st_size
        _check_archive_budget(len(members), uncompressed, compressed, limits)
        total_written = 0
        seen_names: set[str] = set()
        destination_root = destination.resolve()
        for member in members:
            member_path = _safe_member(member.name, limits)
            if member.isdir():
                continue
            if member.name in seen_names:
                issues.append(f"duplicate archive member: {member.name}")
            seen_names.add(member.name)
            if member.issym() or member.islnk():
                issues.append(f"skipped link in archive: {member.name}")
                continue
            if member.ischr() or member.isblk() or member.isfifo():
                issues.append(f"skipped device/FIFO in archive: {member.name}")
                continue
            if hasattr(member, "issparse") and member.issparse():
                issues.append(f"skipped sparse member in archive: {member.name}")
                continue
            if not member.isfile():
                issues.append(f"skipped unsupported archive member: {member.name}")
                continue
            if member.size > limits.max_archive_uncompressed:
                raise TargetError(f"archive member {member.name!r} is too large")
            try:
                source = archive.extractfile(member)
                if source is None:
                    issues.append(f"could not read archive member: {member.name}")
                    continue
                target = destination.joinpath(*member_path.parts)
                try:
                    target.resolve(strict=False).relative_to(destination_root)
                except ValueError:
                    raise TargetError(
                        f"archive member {member.name!r} escapes the extraction root"
                    )
                target.parent.mkdir(parents=True, exist_ok=True)
                written = 0
                with source, open(target, "wb") as sink:
                    while True:
                        chunk = source.read(65536)
                        if not chunk:
                            break
                        written += len(chunk)
                        total_written += len(chunk)
                        if (
                            written > limits.max_archive_uncompressed
                            or total_written > limits.max_archive_uncompressed
                        ):
                            raise TargetError(
                                f"archive member {member.name!r} expands too far"
                            )
                        sink.write(chunk)
                if member.mode & 0o6000:
                    issues.append(
                        f"archive member {member.name!r} had setuid/setgid bits; stripped"
                    )
                os.chmod(target, 0o755 if member.mode & 0o111 else 0o644)
            except TargetError:
                raise
            except (tarfile.TarError, EOFError, OSError, zlib.error) as exc:
                raise TargetError(
                    f"cannot extract {member.name!r}: {exc}"
                ) from exc


def _walk(root: Path, limits: LoaderLimits) -> LoadedTree:
    tree = LoadedTree(root=root, kind="directory")
    stack: list[tuple[Path, str]] = [(root, "")]
    visited = 0
    while stack:
        directory, prefix = stack.pop()
        try:
            entries = sorted(os.scandir(directory), key=lambda entry: entry.name)
        except OSError as exc:
            tree.notes.append(f"cannot read {prefix or '.'}: {exc}")
            continue
        for entry in entries:
            # Count every visited entry, including directories, so a
            # directory-only tree cannot bypass the work cap.
            visited += 1
            if visited > limits.max_files:
                tree.notes.append(f"stopped after {limits.max_files} entries")
                return tree
            rel = f"{prefix}{entry.name}" if not prefix else f"{prefix}/{entry.name}"
            try:
                st = entry.stat(follow_symlinks=False)
            except OSError as exc:
                tree.notes.append(f"cannot stat {rel}: {exc}")
                continue
            # Count every recorded entry, not just regular files, so a flood of
            # symlinks, FIFOs, or device nodes cannot exhaust memory.
            if len(tree.records) >= limits.max_files:
                tree.notes.append(f"stopped after {limits.max_files} files")
                return tree
            if stat.S_ISLNK(st.st_mode):
                try:
                    target = os.readlink(entry.path)
                except OSError:
                    target = ""
                record = FileRecord(
                    path=rel,
                    kind="symlink",
                    is_symlink=True,
                    link_target=target,
                    mode=stat.S_IMODE(st.st_mode),
                    sha256=hashlib.sha256(("symlink:" + target).encode("utf-8", "replace")).hexdigest(),
                )
                tree.records.append(record)
                continue
            if stat.S_ISDIR(st.st_mode):
                if entry.name in SKIP_DIR_NAMES:
                    tree.notes.append(f"skipped repository directory: {rel}")
                    continue
                if entry.name in VENDOR_DIR_NAMES and not limits.include_vendor:
                    tree.notes.append(f"skipped vendor directory: {rel}")
                    continue
                stack.append((Path(entry.path), rel))
                continue
            if not stat.S_ISREG(st.st_mode):
                tree.records.append(
                    FileRecord(
                        path=rel,
                        kind="device",
                        mode=stat.S_IMODE(st.st_mode),
                        skipped="not a regular file",
                    )
                )
                continue
            if tree.total_bytes >= limits.max_total_bytes:
                tree.notes.append("stopped after the total byte budget was exhausted")
                return tree
            record = _read_regular(Path(entry.path), Path(entry.name).suffix.lower(), limits)
            record.path = rel
            tree.records.append(record)
            tree.total_bytes += min(
                record.size, max(limits.max_file_bytes, limits.max_hash_bytes)
            )
    tree.records.sort(key=lambda record: record.path)
    return tree


class PreparedTarget(AbstractContextManager[LoadedTree]):
    """Context manager that extracts an archive to a temporary directory."""

    def __init__(self, target: str | Path, limits: LoaderLimits) -> None:
        self.target = Path(target).expanduser()
        self.limits = limits
        self._tempdir: str | None = None
        self.tree: LoadedTree | None = None

    def __enter__(self) -> LoadedTree:
        # Refuse a symlinked leaf explicitly: resolving it would silently
        # follow a link, which contradicts the loader's stated invariant.
        if self.target.is_symlink():
            raise TargetError(f"target is a symlink; pass the resolved path: {self.target}")
        if not self.target.exists():
            raise TargetError(f"target does not exist: {self.target}")
        if self.target.is_dir():
            self.tree = _walk(self.target.resolve(), self.limits)
            self.tree.kind = "directory"
            return self.tree
        if not self.target.is_file():
            raise TargetError(f"target is not a directory or regular file: {self.target}")
        lowered = self.target.name.lower()
        if not any(lowered.endswith(suffix) for suffix in ARCHIVE_SUFFIXES):
            raise TargetError(
                "target is a file but not a supported archive "
                f"({', '.join(sorted(ARCHIVE_SUFFIXES))})"
            )
        self._tempdir = tempfile.mkdtemp(prefix="skilltriage-")
        destination = Path(self._tempdir)
        issues: list[str] = []
        try:
            if lowered.endswith(".zip"):
                _extract_zip(self.target, destination, self.limits, issues)
            else:
                _extract_tar(self.target, destination, self.limits, issues)
        except Exception:
            shutil.rmtree(self._tempdir, ignore_errors=True)
            self._tempdir = None
            raise
        self.tree = _walk(destination, self.limits)
        self.tree.kind = "archive"
        self.tree.archive_issues = issues
        return self.tree

    def __exit__(self, exc_type, exc, tb) -> None:
        if self._tempdir:
            shutil.rmtree(self._tempdir, ignore_errors=True)
            self._tempdir = None


def iter_text_files(tree: LoadedTree) -> Iterator[FileRecord]:
    for record in tree.records:
        if record.is_text:
            yield record

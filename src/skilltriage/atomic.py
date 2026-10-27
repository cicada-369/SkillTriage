"""Atomic, owner-only text writes for user-owned state and reports.

A predictable ``file.tmp`` next to the destination can be pre-created as a
symlink and truncate an unrelated file. ``mkstemp`` uses an unpredictable name
and ``O_EXCL``; ``os.replace`` swaps the finished file into place.
"""

from __future__ import annotations

import os
import tempfile
from pathlib import Path


def write_private(output: str | Path, content: str) -> None:
    path = Path(output).expanduser()
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, temp_name = tempfile.mkstemp(prefix=f".{path.name}.", dir=str(path.parent))
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            handle.write(content)
        try:
            os.fchmod(fd, 0o600)
        except (AttributeError, OSError):
            pass
        os.chmod(temp_name, 0o600)
        os.replace(temp_name, path)
    except BaseException:
        try:
            os.unlink(temp_name)
        except OSError:
            pass
        raise


__all__ = ["write_private"]

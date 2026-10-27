"""Entrypoint used by the zipapp build.

``python -m skilltriage`` uses ``skilltriage/__main__.py``. A zipapp needs a
top-level ``__main__.py``; this one exits with the CLI's status code so the
archive is usable in CI.
"""

from __future__ import annotations

import sys

from skilltriage.cli import main

raise SystemExit(main())

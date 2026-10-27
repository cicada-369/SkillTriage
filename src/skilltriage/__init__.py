"""SkillTriage — static security auditing and risk triage for agentic skills.

The public API is intentionally small. Most callers use the command line, but
``audit_path`` and ``scan_system`` are stable enough for embedding.
"""

from __future__ import annotations

__version__ = "0.1.0"
__all__ = ["__version__"]

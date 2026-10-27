"""Stable JSON report."""

from __future__ import annotations

import json


def render(report) -> str:
    return json.dumps(report.to_dict(), indent=2, sort_keys=False) + "\n"

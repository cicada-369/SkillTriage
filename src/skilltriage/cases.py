"""Validation for portable behaviour-test case files.

This validates shape only. It deliberately does not submit prompts to an agent.
A runner needs a platform adapter, an isolated environment, and credential
handling that belong outside a static audit tool.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

REQUIRED = {"id", "input", "expected"}


def validate_cases(path: str | Path) -> tuple[list[dict[str, Any]], list[str]]:
    path = Path(path).expanduser()
    errors: list[str] = []
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except OSError as exc:
        return [], [f"could not read {path}: {exc}"]
    except UnicodeDecodeError as exc:
        return [], [f"{path} is not valid UTF-8: {exc}"]
    except json.JSONDecodeError as exc:
        return [], [f"invalid JSON: {exc}"]
    except ValueError as exc:
        return [], [f"invalid JSON value: {exc}"]

    if isinstance(data, dict):
        cases = data.get("cases")
        if not isinstance(cases, list):
            return [], ["top-level object must contain a 'cases' list"]
    elif isinstance(data, list):
        cases = data
    else:
        return [], ["top-level JSON value must be a list or an object with 'cases'"]

    seen: set[str] = set()
    for index, case in enumerate(cases, start=1):
        if not isinstance(case, dict):
            errors.append(f"case #{index} must be an object")
            continue
        missing = REQUIRED - case.keys()
        if missing:
            errors.append(f"case #{index} missing fields: {', '.join(sorted(missing))}")
        case_id = case.get("id")
        if not isinstance(case_id, str) or not case_id.strip():
            errors.append(f"case #{index}: id must be a non-empty string")
        else:
            if case_id in seen:
                errors.append(f"duplicate case id: {case_id!r}")
            seen.add(case_id)
        if "input" in case and not isinstance(case["input"], str):
            errors.append(f"case {case_id!r}: input must be a string")
        expected = case.get("expected")
        if "expected" in case:
            if not isinstance(expected, list) or not all(isinstance(item, str) for item in expected):
                errors.append(f"case {case_id!r}: expected must be a list of strings")
            elif not expected:
                errors.append(f"case {case_id!r}: expected must not be empty")
        for optional in ("forbidden", "expect_tool_calls", "tags"):
            value = case.get(optional)
            if value is not None and (
                not isinstance(value, list) or not all(isinstance(item, str) for item in value)
            ):
                errors.append(f"case {case_id!r}: {optional} must be a list of strings")
        timeout = case.get("timeout_seconds")
        if timeout is not None and (not isinstance(timeout, (int, float)) or timeout <= 0):
            errors.append(f"case {case_id!r}: timeout_seconds must be a positive number")
    return cases, errors


def describe(cases: list[dict[str, Any]]) -> dict[str, Any]:
    return {
        "cases": len(cases),
        "tags": sorted({tag for case in cases for tag in case.get("tags", []) if isinstance(tag, str)}),
        "with_tool_assertions": sum(1 for case in cases if case.get("expect_tool_calls")),
        "with_forbidden": sum(1 for case in cases if case.get("forbidden")),
    }

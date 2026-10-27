from __future__ import annotations
import json
from pathlib import Path

def validate_cases(path: str | Path) -> tuple[list[dict], list[str]]:
    """Validate a portable behavior-test case file; does not execute an agent."""
    path = Path(path)
    errors = []
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        return [], [f"Could not read valid JSON: {exc}"]
    if not isinstance(data, list):
        return [], ["Top-level JSON value must be a list."]
    required = {"id", "input", "expected"}
    seen = set()
    for i, case in enumerate(data):
        if not isinstance(case, dict):
            errors.append(f"Case #{i + 1} must be an object.")
            continue
        missing = required - case.keys()
        if missing:
            errors.append(f"Case #{i + 1} missing fields: {', '.join(sorted(missing))}.")
        cid = case.get("id")
        if cid in seen:
            errors.append(f"Duplicate case id: {cid!r}.")
        if cid is not None:
            seen.add(cid)
        if "input" in case and not isinstance(case["input"], str):
            errors.append(f"Case {cid!r}: input must be a string.")
        if "expected" in case and not isinstance(case["expected"], list):
            errors.append(f"Case {cid!r}: expected must be a list of strings.")
        if isinstance(case.get("expected"), list) and not all(isinstance(x, str) for x in case["expected"]):
            errors.append(f"Case {cid!r}: every expected item must be a string.")
    return data, errors

"""Baseline files for accepted findings.

A baseline records the fingerprint of findings a team has reviewed and
accepted. Baselined findings stay in JSON reports (``baselined: true``) but do
not gate a build. Fingerprints exclude line numbers, so moving code does not
silently invalidate the baseline.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .atomic import write_private
from .models import AuditResult, Finding, utc_now_iso


class BaselineError(Exception):
    pass


@dataclass(frozen=True)
class BaselineEntry:
    fingerprint: str
    rule_id: str
    path: str
    skill_id: str = ""
    note: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "fingerprint": self.fingerprint,
            "rule_id": self.rule_id,
            "path": self.path,
            "skill_id": self.skill_id,
            "note": self.note,
        }


class Baseline:
    def __init__(self, entries: list[BaselineEntry] | None = None) -> None:
        self.entries = entries or []

    @classmethod
    def load(cls, path: str | Path) -> "Baseline":
        path = Path(path).expanduser()
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
        except OSError as exc:
            raise BaselineError(f"cannot read baseline {path}: {exc}") from exc
        except UnicodeDecodeError as exc:
            raise BaselineError(f"baseline {path} is not valid UTF-8: {exc}") from exc
        except json.JSONDecodeError as exc:
            raise BaselineError(f"invalid baseline JSON in {path}: {exc}") from exc
        except ValueError as exc:
            raise BaselineError(f"invalid baseline value in {path}: {exc}") from exc
        raw_entries = data.get("findings") if isinstance(data, dict) else None
        if not isinstance(raw_entries, list):
            raise BaselineError(f"baseline {path} must contain a 'findings' list")
        entries: list[BaselineEntry] = []
        for item in raw_entries:
            if not isinstance(item, dict):
                continue
            fingerprint = str(item.get("fingerprint") or "")
            if not fingerprint:
                continue
            entries.append(
                BaselineEntry(
                    fingerprint=fingerprint,
                    rule_id=str(item.get("rule_id") or ""),
                    path=str(item.get("path") or ""),
                    skill_id=str(item.get("skill_id") or ""),
                    note=str(item.get("note") or ""),
                )
            )
        return cls(entries)

    def matches(self, finding: Finding, skill_id: str) -> bool:
        for entry in self.entries:
            if entry.fingerprint != finding.fingerprint:
                continue
            if entry.skill_id and skill_id and entry.skill_id != skill_id:
                continue
            return True
        return False

    def write(self, path: str | Path, results: list[AuditResult]) -> None:
        entries: list[dict[str, Any]] = []
        for result in results:
            skill_id = result.target.skill_id
            for finding in result.findings:
                if finding.suppressed:
                    continue
                entries.append(
                    BaselineEntry(
                        fingerprint=finding.fingerprint,
                        rule_id=finding.rule_id,
                        path=finding.path,
                        skill_id=skill_id,
                    ).to_dict()
                )
        payload = {
            "schema": "skilltriage-baseline/v1",
            "tool": "skilltriage",
            "created": utc_now_iso(),
            "findings": entries,
        }
        write_private(Path(path).expanduser(), json.dumps(payload, indent=2) + "\n")


def apply_baseline(results: list[AuditResult], baseline: Baseline) -> int:
    total = 0
    for result in results:
        skill_id = result.target.skill_id
        count = 0
        for finding in result.findings:
            if baseline.matches(finding, skill_id):
                finding.baselined = True
                count += 1
        result.baseline_matched = count
        total += count
    return total

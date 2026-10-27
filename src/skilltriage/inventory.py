"""Local skill inventory and drift comparison.

The inventory is a transparent JSON file. It records the canonical content
hash of every skill, so ``audit --inventory`` can report AST07 drift (the
bytes changed) and AST09 missing-governance state (the skill is not recorded).
"""

from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any

from .atomic import write_private
from .models import AuditResult, tree_hash, utc_now_iso

SCHEMA = "skilltriage-inventory/v1"


class InventoryError(Exception):
    pass


def default_inventory_path() -> Path:
    base = os.environ.get("XDG_DATA_HOME")
    root = Path(base).expanduser() if base else Path.home() / ".local" / "share"
    return root / "skilltriage" / "inventory.json"


class Inventory:
    def __init__(self, path: str | Path | None = None) -> None:
        self.path = Path(path).expanduser() if path else default_inventory_path()
        self.skills: dict[str, dict[str, Any]] = {}
        self.updated = ""

    @classmethod
    def load(cls, path: str | Path | None = None) -> "Inventory":
        inventory = cls(path)
        if not inventory.path.is_file():
            return inventory
        try:
            data = json.loads(inventory.path.read_text(encoding="utf-8"))
        except OSError as exc:
            raise InventoryError(f"cannot read inventory {inventory.path}: {exc}") from exc
        except UnicodeDecodeError as exc:
            raise InventoryError(
                f"inventory {inventory.path} is not valid UTF-8: {exc}"
            ) from exc
        except json.JSONDecodeError as exc:
            raise InventoryError(f"invalid inventory JSON in {inventory.path}: {exc}") from exc
        except ValueError as exc:
            raise InventoryError(f"invalid inventory value in {inventory.path}: {exc}") from exc
        if not isinstance(data, dict) or not isinstance(data.get("skills"), dict):
            raise InventoryError(f"inventory {inventory.path} has an unsupported shape")
        inventory.skills = {
            str(key): value for key, value in data["skills"].items() if isinstance(value, dict)
        }
        inventory.updated = str(data.get("updated") or "")
        return inventory

    def save(self) -> None:
        self.updated = utc_now_iso()
        payload = {
            "schema": SCHEMA,
            "tool": "skilltriage",
            "updated": self.updated,
            "skills": self.skills,
        }
        write_private(self.path, json.dumps(payload, indent=2, sort_keys=True) + "\n")

    def get(self, skill_id: str) -> dict[str, Any] | None:
        return self.skills.get(skill_id)

    def find_by_path(self, path: str) -> dict[str, Any] | None:
        target = Path(path).expanduser()
        try:
            resolved = target.resolve()
        except OSError:
            resolved = target
        for record in self.skills.values():
            recorded = record.get("path")
            if not recorded:
                continue
            if recorded == path:
                return record
            try:
                if Path(recorded).expanduser().resolve() == resolved:
                    return record
            except OSError:
                continue
        return None

    def record_for(self, result: AuditResult) -> dict[str, Any]:
        skill_id = result.target.skill_id
        existing = self.skills.get(skill_id, {})
        summary = result.summary()
        now = utc_now_iso()
        return {
            "skill_id": skill_id,
            "name": result.skill.name or result.target.name,
            "version": result.skill.version or result.target.version,
            "kind": result.target.location or result.target.kind,
            "path": result.target.input,
            "plugin": result.target.plugin,
            "content_hash": _tree_hash(result),
            "file_count": len(result.files),
            "size_bytes": sum(record.size for record in result.files),
            "first_seen": existing.get("first_seen") or now,
            "last_seen": now,
            "last_audit": now,
            "risk_tier": result.skill.risk_tier,
            "has_signature": bool(result.skill.signature),
            "findings": summary["severity"],
            "gating": result.gating_count,
        }

    def sync(self, results: list[AuditResult]) -> dict[str, int]:
        added = changed = unchanged = 0
        for result in results:
            record = self.record_for(result)
            skill_id = record["skill_id"]
            previous = self.skills.get(skill_id)
            if previous is None:
                added += 1
            elif previous.get("content_hash") != record["content_hash"]:
                changed += 1
            else:
                unchanged += 1
            self.skills[skill_id] = record
        return {"added": added, "changed": changed, "unchanged": unchanged}

    def diff(self, results: list[AuditResult]) -> dict[str, list[dict[str, Any]]]:
        current: dict[str, dict[str, Any]] = {}
        for result in results:
            record = self.record_for(result)
            current[record["skill_id"]] = record
        added = [current[key] for key in sorted(set(current) - set(self.skills))]
        removed = [self.skills[key] for key in sorted(set(self.skills) - set(current))]
        changed = [
            {"old": self.skills[key], "new": current[key]}
            for key in sorted(set(current) & set(self.skills))
            if self.skills[key].get("content_hash") != current[key].get("content_hash")
        ]
        unchanged = len(set(current) & set(self.skills)) - len(changed)
        return {
            "added": added,
            "removed": removed,
            "changed": changed,
            "unchanged": [{"count": unchanged}],
        }


def _tree_hash(result: AuditResult) -> str:
    return tree_hash(result.files)

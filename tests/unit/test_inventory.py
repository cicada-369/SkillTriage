import shutil
import tempfile
import unittest
from pathlib import Path

from skilltriage.analysis import audit_target
from skilltriage.inventory import Inventory, InventoryError, default_inventory_path
from skilltriage.models import Severity
from skilltriage.policy import AuditOptions
from tests.helpers import FIXTURES, audit, get, ids


class InventoryTests(unittest.TestCase):
    def test_sync_list_and_diff(self):
        source = FIXTURES / "benign" / "minimal_skill"
        malicious = FIXTURES / "malicious" / "download_exec"
        with tempfile.TemporaryDirectory() as tmp:
            benign = Path(tmp) / "minimal_skill"
            shutil.copytree(source, benign)
            results = [audit(benign), audit(malicious)]
            path = Path(tmp) / "inventory.json"
            inventory = Inventory(path)
            summary = inventory.sync(results)
            self.assertEqual(summary["added"], 2)
            inventory.save()
            loaded = Inventory.load(path)
            self.assertEqual(len(loaded.skills), 2)
            for record in loaded.skills.values():
                self.assertTrue(record["content_hash"].startswith("sha256:"))
                self.assertIn("findings", record)

            unchanged = loaded.diff(results)
            self.assertEqual(unchanged["added"], [])
            self.assertEqual(unchanged["removed"], [])
            self.assertEqual(unchanged["changed"], [])

            (benign / "SKILL.md").write_text(
                (benign / "SKILL.md").read_text(encoding="utf-8") + "\nchanged\n",
                encoding="utf-8",
            )
            changed = loaded.diff([audit(benign), audit(malicious)])
            self.assertEqual(len(changed["changed"]), 1)

    def test_audit_reports_missing_record_and_drift(self):
        options = AuditOptions()
        with tempfile.TemporaryDirectory() as tmp:
            skill = Path(tmp) / "skill"
            other = Path(tmp) / "other"
            shutil.copytree(FIXTURES / "benign" / "minimal_skill", skill)
            shutil.copytree(FIXTURES / "malicious" / "download_exec", other)
            inventory = Inventory(Path(tmp) / "inventory.json")
            first = audit_target(skill, options, inventory=inventory)
            inventory.sync([first])

            missing = AuditOptions()
            missing.require_inventory = True
            result = audit_target(other, missing, inventory=inventory)
            self.assertIn("AST09-NOT-IN-INVENTORY", ids(result))

            (skill / "SKILL.md").write_text(
                (skill / "SKILL.md").read_text(encoding="utf-8") + "\nchanged\n",
                encoding="utf-8",
            )
            drifted = audit_target(skill, options, inventory=inventory)
            self.assertIn("AST07-BASELINE-DRIFT", ids(drifted))
            self.assertGreater(drifted.gating_count, 0)

    def test_require_inventory_gates_on_a_clean_skill(self):
        options = AuditOptions()
        options.require_inventory = True
        with tempfile.TemporaryDirectory() as tmp:
            inventory = Inventory(Path(tmp) / "inventory.json")
            result = audit_target(
                FIXTURES / "benign" / "minimal_skill", options, inventory=inventory
            )
        finding = get(result, "AST09-NOT-IN-INVENTORY")
        self.assertIsNotNone(finding)
        self.assertEqual(finding.severity, Severity.HIGH)
        self.assertGreater(result.gating_count, 0)

    def test_missing_inventory_is_empty(self):
        with tempfile.TemporaryDirectory() as tmp:
            inventory = Inventory(Path(tmp) / "missing.json")
            self.assertEqual(inventory.skills, {})

    def test_non_utf8_inventory_is_an_inventory_error(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "inventory.json"
            path.write_bytes(b"\xff\xfe")
            with self.assertRaises(InventoryError):
                Inventory.load(path)

    def test_default_path(self):
        self.assertEqual(default_inventory_path().name, "inventory.json")


if __name__ == "__main__":
    unittest.main()

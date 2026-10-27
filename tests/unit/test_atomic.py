import os
import stat
import tempfile
import unittest
from pathlib import Path

from skilltriage.atomic import write_private
from skilltriage.baseline import Baseline
from skilltriage.inventory import Inventory
from tests.helpers import FIXTURES, audit


class AtomicWriteTests(unittest.TestCase):
    def test_writes_privately_and_atomically(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "state.json"
            write_private(path, "new")
            self.assertEqual(path.read_text(encoding="utf-8"), "new")
            if os.name == "posix":
                self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o600)
            self.assertEqual(sorted(item.name for item in Path(tmp).iterdir()), ["state.json"])

    def test_predictable_tmp_symlink_is_not_followed(self):
        with tempfile.TemporaryDirectory() as tmp:
            victim = Path(tmp) / "victim.txt"
            victim.write_text("safe", encoding="utf-8")
            link = Path(tmp) / "state.json.tmp"
            link.symlink_to(victim)
            write_private(Path(tmp) / "state.json", "new")
            self.assertEqual(victim.read_text(encoding="utf-8"), "safe")

    def test_baseline_writer_does_not_follow_tmp_symlink(self):
        result = audit(FIXTURES / "benign" / "minimal_skill")
        with tempfile.TemporaryDirectory() as tmp:
            victim = Path(tmp) / "victim.txt"
            victim.write_text("safe", encoding="utf-8")
            (Path(tmp) / "baseline.json.tmp").symlink_to(victim)
            Baseline().write(Path(tmp) / "baseline.json", [result])
            self.assertEqual(victim.read_text(encoding="utf-8"), "safe")

    def test_inventory_writer_does_not_follow_tmp_symlink(self):
        with tempfile.TemporaryDirectory() as tmp:
            victim = Path(tmp) / "victim.txt"
            victim.write_text("safe", encoding="utf-8")
            (Path(tmp) / "inventory.json.tmp").symlink_to(victim)
            inventory = Inventory(Path(tmp) / "inventory.json")
            inventory.skills = {"x": {"skill_id": "x", "path": "p"}}
            inventory.save()
            self.assertEqual(victim.read_text(encoding="utf-8"), "safe")


if __name__ == "__main__":
    unittest.main()

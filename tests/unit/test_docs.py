import unittest
from pathlib import Path

from skilltriage.rules import all_rules
from tools.gen_rules_doc import render

ROOT = Path(__file__).resolve().parents[2]


class RuleCatalogTests(unittest.TestCase):
    def test_catalog_is_current(self):
        path = ROOT / "docs" / "RULES.md"
        self.assertTrue(path.is_file())
        self.assertEqual(path.read_text(encoding="utf-8"), render())

    def test_every_rule_is_documented(self):
        text = (ROOT / "docs" / "RULES.md").read_text(encoding="utf-8")
        for rule in all_rules():
            self.assertIn(f"`{rule.id}`", text)


if __name__ == "__main__":
    unittest.main()

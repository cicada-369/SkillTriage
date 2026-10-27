import os
import tempfile
import unittest
from pathlib import Path

from skilltriage.analysis import audit_paths, audit_target
from skilltriage.inventory import Inventory
from skilltriage.models import Confidence, Severity
from skilltriage.policy import AuditOptions
from skilltriage.report import render
from tests.helpers import FIXTURES, get, ids

FIXTURE = FIXTURES / "intent" / "redteam_skill"


def audit(allowed=(), inventory=None):
    options = AuditOptions()
    options.allowed_intents = list(allowed)
    return audit_target(FIXTURE, options, inventory=inventory)


class IntentTests(unittest.TestCase):
    def test_declaration_is_parsed(self):
        result = audit()
        self.assertTrue(result.skill.intent_declared)
        self.assertEqual(result.skill.declared_intent, "offensive-security")
        self.assertEqual(result.target.declared_intent, "offensive-security")
        self.assertFalse(result.target.intent_allowed)

    def test_default_policy_gates(self):
        result = audit()
        self.assertGreater(result.gating_count, 0)
        self.assertIsNotNone(get(result, "AST01-REVERSE-SHELL"))

    def test_allow_without_inventory_does_not_downgrade(self):
        result = audit(allowed=("offensive-security",))
        self.assertFalse(result.target.intent_allowed)
        self.assertGreater(result.gating_count, 0)
        self.assertTrue(
            any("no inventory record" in note for note in result.coverage.notes)
        )

    def test_allow_with_inventory_downgrades_but_keeps_the_finding(self):
        baseline = audit()
        inventory = Inventory()
        inventory.sync([baseline])

        result = audit(allowed=("offensive-security",), inventory=inventory)
        self.assertTrue(result.target.intent_allowed)
        self.assertEqual(result.gating_count, 0)

        finding = get(result, "AST01-REVERSE-SHELL")
        self.assertIsNotNone(finding)
        self.assertTrue(finding.intent_matched)
        self.assertEqual(finding.confidence, Confidence.LOW)
        self.assertLess(finding.severity.rank, Severity.CRITICAL.rank)
        self.assertIn("downgraded under declared intent", finding.context_note)

    def test_reports_name_the_intent_and_the_downgrade_count(self):
        baseline = audit()
        inventory = Inventory()
        inventory.sync([baseline])
        options = AuditOptions()
        options.allowed_intents = ["offensive-security"]
        report = audit_paths([FIXTURE], options, inventory=inventory)
        text = render(report, "text", options)
        self.assertIn("declared intent: offensive-security", text)
        self.assertIn("1 finding(s) downgraded", text)
        markdown = render(report, "markdown", options)
        self.assertIn("**Declared intent:**", markdown)
        self.assertIn("1 finding(s) downgraded", markdown)

    def test_inventory_lookup_resolves_relative_paths(self):
        baseline = audit()
        inventory = Inventory()
        inventory.sync([baseline])
        options = AuditOptions()
        options.allowed_intents = ["offensive-security"]
        relative = os.path.relpath(FIXTURE)
        result = audit_target(relative, options, inventory=inventory)
        self.assertTrue(result.target.intent_allowed)

    def test_inventory_record_without_a_hash_does_not_enable_downgrade(self):
        inventory = Inventory()
        inventory.skills["local:redteam-fixture"] = {
            "skill_id": "local:redteam-fixture",
            "path": str(FIXTURE),
            "content_hash": "",
        }
        result = audit(allowed=("offensive-security",), inventory=inventory)
        self.assertFalse(result.target.intent_allowed)
        self.assertGreater(result.gating_count, 0)

    def test_inventory_hash_mismatch_does_not_enable_downgrade(self):
        inventory = Inventory()
        inventory.skills["local:redteam-fixture"] = {
            "skill_id": "local:redteam-fixture",
            "path": str(FIXTURE),
            "content_hash": "sha256:deadbeef",
        }
        result = audit(allowed=("offensive-security",), inventory=inventory)
        self.assertFalse(result.target.intent_allowed)

    def test_unknown_intent_is_reported_but_not_honoured(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "SKILL.md").write_text(
                "---\n"
                "name: unknown-intent\n"
                "description: Fixture.\n"
                "version: 1.0.0\n"
                "metadata:\n"
                "  skilltriage:\n"
                "    intent: malware\n"
                "---\n\nbody\n"
            )
            options = AuditOptions()
            options.allowed_intents = ["offensive-security"]
            result = audit_target(root, options)
        self.assertTrue(result.skill.intent_declared)
        self.assertEqual(result.skill.declared_intent, "malware")
        self.assertFalse(result.target.intent_allowed)
        self.assertIn("AST04-UNKNOWN-INTENT", ids(result))


if __name__ == "__main__":
    unittest.main()

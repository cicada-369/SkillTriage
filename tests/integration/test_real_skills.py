"""Tests against skills installed on the local machine.

These are skipped when the standard Claude skill directories are absent, so a
clean CI runner still passes. On a developer machine they are the most useful
regression test: the real world is messier than fixtures.
"""

from __future__ import annotations

import os
import unittest
from pathlib import Path

from skilltriage.analysis import audit_target
from skilltriage.discovery import discover
from skilltriage.models import Severity
from skilltriage.parsers import parse_yaml_subset, split_frontmatter
from skilltriage.policy import AuditOptions

try:
    import yaml
except ImportError:  # pragma: no cover
    yaml = None

PERSONAL = Path.home() / ".claude" / "skills"
PLUGINS = Path.home() / ".claude" / "plugins" / "cache"


def _personal_skills() -> list[Path]:
    if not PERSONAL.is_dir():
        return []
    return sorted(path.parent for path in PERSONAL.glob("*/SKILL.md"))


@unittest.skipUnless(PERSONAL.is_dir(), "no personal Claude skills installed")
class InstalledSkillTests(unittest.TestCase):
    def test_frontmatter_parses_for_every_installed_skill(self):
        for directory in _personal_skills():
            path = directory / "SKILL.md"
            text = path.read_text(encoding="utf-8", errors="replace")
            front = split_frontmatter(text)
            if not front.found:
                continue
            data, issues = parse_yaml_subset(front.meta_text)
            self.assertIsInstance(data, dict, str(path))
            for issue in issues:
                self.assertNotEqual(issue.code, "TOP_LEVEL_NOT_MAPPING", f"{path}: {issue.message}")

    def test_top_level_keys_match_pyyaml(self):
        if yaml is None:
            self.skipTest("PyYAML not installed")
        for directory in _personal_skills():
            path = directory / "SKILL.md"
            front = split_frontmatter(path.read_text(encoding="utf-8", errors="replace"))
            if not front.found:
                continue
            try:
                reference = yaml.safe_load(front.meta_text) or {}
            except yaml.YAMLError:
                continue
            ours, issues = parse_yaml_subset(front.meta_text)
            if any(issue.code in ("UNSAFE_YAML_TAG", "YAML_ANCHOR_ALIAS") for issue in issues):
                continue
            self.assertEqual(set(ours), set(reference), str(path))

    def test_every_personal_skill_audits_without_engine_errors(self):
        options = AuditOptions(profile="advisory", fail_on=None)
        for directory in _personal_skills():
            result = audit_target(directory, options)
            errors = [note for note in result.coverage.notes if note.startswith("rule error:")]
            self.assertEqual(errors, [], str(directory))
            self.assertTrue(result.files, str(directory))

    def test_audit_is_deterministic(self):
        directories = _personal_skills()
        if not directories:
            self.skipTest("no personal skills")
        options = AuditOptions(profile="advisory", fail_on=None)
        first = audit_target(directories[0], options)
        second = audit_target(directories[0], options)
        first_findings = [
            (f.rule_id, f.path, f.line, f.evidence, f.severity.value, f.confidence.value)
            for f in first.findings
        ]
        second_findings = [
            (f.rule_id, f.path, f.line, f.evidence, f.severity.value, f.confidence.value)
            for f in second.findings
        ]
        self.assertEqual(first_findings, second_findings)

    def test_discovery_finds_personal_skills(self):
        found = discover(include_marketplaces=False)
        personal = [skill for skill in found if skill.kind == "personal"]
        self.assertGreaterEqual(len(personal), len(_personal_skills()))

    @unittest.skipUnless(os.environ.get("SKILLTRIAGE_TEST_PLUGINS") == "1", "plugin scan disabled")
    def test_plugin_cache_audits(self):
        if not PLUGINS.is_dir():
            self.skipTest("no plugin cache")
        options = AuditOptions(profile="advisory", fail_on=None)
        for path in sorted(PLUGINS.glob("*/*/*/skills/*/SKILL.md")):
            result = audit_target(path.parent, options)
            errors = [note for note in result.coverage.notes if note.startswith("rule error:")]
            self.assertEqual(errors, [], str(path))


if __name__ == "__main__":
    unittest.main()

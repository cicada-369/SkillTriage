import tempfile
import unittest
from pathlib import Path

from skilltriage.discovery import discover
from tests.helpers import skill_md, write_skill


class DiscoveryTests(unittest.TestCase):
    def test_discovers_personal_plugin_and_project_skills(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            personal = root / "home" / ".claude" / "skills"
            cache = root / "plugins" / "cache"
            market = root / "plugins" / "marketplaces"
            project = root / "project"

            write_skill(personal / "foo", {"SKILL.md": skill_md("foo")})
            write_skill(
                cache / "market" / "plugin" / "1.2.3" / "skills" / "bar",
                {"SKILL.md": skill_md("bar")},
            )
            write_skill(
                market / "market" / "plugins" / "plug" / "skills" / "baz",
                {"SKILL.md": skill_md("baz")},
            )
            write_skill(project / ".claude" / "skills" / "qux", {"SKILL.md": skill_md("qux")})

            found = discover(
                roots=[str(personal), str(cache), str(market)],
                projects=[str(project)],
                include_marketplaces=False,
            )
            by_id = {skill.skill_id: skill for skill in found}
            self.assertIn("personal:foo", by_id)
            self.assertIn("plugin-cache:market/plugin@1.2.3:bar", by_id)
            self.assertIn("project:project:qux", by_id)
            self.assertNotIn("marketplace:market/plug:baz", by_id)

            with_market = discover(
                roots=[str(personal), str(cache), str(market)],
                projects=[str(project)],
                include_marketplaces=True,
            )
            self.assertIn("marketplace:market/plug:baz", {skill.skill_id for skill in with_market})

    def test_missing_root_is_ignored(self):
        self.assertEqual(discover(roots=["/definitely/not/here"], include_marketplaces=False), [])


if __name__ == "__main__":
    unittest.main()

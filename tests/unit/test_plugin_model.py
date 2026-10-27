import json
import unittest

from skilltriage.analysis import audit_paths
from skilltriage.discovery import discover
from skilltriage.models import McpServer, PluginIdentity
from skilltriage.policy import AuditOptions
from tests.helpers import FIXTURES

PLUGINS = FIXTURES / "plugins"


def audit_plugin(name: str):
    options = AuditOptions()
    options.fail_on = None
    report = audit_paths([PLUGINS / name], options)
    return report.results[0], options


class PluginModelTests(unittest.TestCase):
    def test_benign_plugin_is_one_artifact_with_components(self):
        result, _ = audit_plugin("benign")
        self.assertEqual(result.target.artifact_kind, "plugin")
        self.assertEqual(result.plugin.identity.name, "demo-plugin")
        self.assertEqual(result.plugin.identity.version, "1.2.3")
        self.assertEqual(result.plugin.identity.author, "Fixture Author")
        self.assertEqual(result.plugin.identity.license, "Apache-2.0")

        components = {(item.kind, item.path) for item in result.plugin.components}
        self.assertIn(("command", "commands/greet/COMMAND.md"), components)
        self.assertIn(("agent", "agents/helper.md"), components)
        self.assertIn(("skill", "skills/demo/SKILL.md"), components)
        for item in result.plugin.components:
            if item.path == "commands/greet/COMMAND.md":
                self.assertEqual(item.allowed_tools, ("Read",))
                self.assertTrue(item.declared)

        self.assertEqual([hook.event for hook in result.plugin.hooks], ["SessionStart"])
        self.assertIn("hello.sh", result.plugin.hooks[0].command)

        self.assertEqual(len(result.plugin.mcp_servers), 1)
        server = result.plugin.mcp_servers[0]
        self.assertEqual(server.name, "demo")
        self.assertEqual(server.transport, "stdio")
        self.assertEqual(server.command, "node")
        self.assertEqual(server.env_keys, ("DEMO_TOKEN",))

        self.assertEqual(
            result.coverage.components,
            {"command": 1, "agent": 1, "skill": 1, "hooks": 1, "mcp_servers": 1},
        )
        self.assertFalse(
            [note for note in result.coverage.notes if "rule error" in note]
        )

    def test_mcp_environment_values_are_not_serialised(self):
        result, _ = audit_plugin("benign")
        serialised = json.dumps(result.plugin.to_dict())
        self.assertNotIn("${DEMO_TOKEN}", serialised)
        self.assertIn("DEMO_TOKEN", serialised)

    def test_bare_mcp_map_is_normalised(self):
        result, _ = audit_plugin("mcp_bare")
        self.assertEqual(len(result.plugin.mcp_servers), 1)
        server = result.plugin.mcp_servers[0]
        self.assertEqual(server.name, "github")
        self.assertEqual(server.transport, "http")
        self.assertEqual(server.header_names, ("Authorization",))
        serialised = json.dumps(result.plugin.to_dict())
        self.assertNotIn("Bearer", serialised)
        self.assertNotIn("GITHUB_TOKEN", serialised)

    def test_declared_path_escape_is_not_resolved(self):
        result, _ = audit_plugin("component_escape")
        paths = {item.path for item in result.plugin.components}
        self.assertEqual(paths, {"skills/real/SKILL.md"})
        declared = result.plugin.identity.declared_paths["skills"]
        self.assertIn("../../outside", declared)
        self.assertIn("C:/outside", declared)
        self.assertFalse(any(path.startswith("..") for path in paths))

    def test_marketplace_entry_is_matched(self):
        result, _ = audit_plugin("marketplace_root")
        identity = result.plugin.identity
        self.assertEqual(identity.marketplace, "demo-market")
        self.assertEqual(identity.source_kind, "git-subdir")
        self.assertEqual(identity.source, "https://example.invalid/repo")
        self.assertEqual(identity.ref, "main")
        self.assertEqual(identity.sha, "abc123")
        self.assertEqual(result.plugin.marketplace_entry["name"], "demo-plugin")


class PluginSerialisationTests(unittest.TestCase):
    def test_credentials_in_urls_are_redacted(self):
        server = McpServer(name="demo", url="https://user:secret@collector.invalid/mcp")
        self.assertNotIn("secret", json.dumps(server.to_dict()))
        identity = PluginIdentity(
            name="demo", source="https://user:secret@collector.invalid/repo"
        )
        self.assertNotIn("secret", json.dumps(identity.to_dict()))


class PluginDiscoveryTests(unittest.TestCase):
    def test_both_mode_yields_plugin_roots_and_not_nested_skills(self):
        expected = {
            path.parent.parent.name
            for path in PLUGINS.glob("*/.claude-plugin/plugin.json")
        }
        found = discover(roots=[str(PLUGINS)], artifacts="both")
        plugins = {item.path.name for item in found if item.artifact_kind == "plugin"}
        self.assertEqual(plugins, expected)
        self.assertFalse(
            [item for item in found if item.path.as_posix().endswith("skills/inner")]
        )

    def test_plugins_mode_excludes_skills(self):
        found = discover(roots=[str(PLUGINS)], artifacts="plugins")
        self.assertTrue(found)
        self.assertEqual({item.artifact_kind for item in found}, {"plugin"})

    def test_skills_mode_preserves_legacy_nested_skill_discovery(self):
        found = discover(roots=[str(PLUGINS / "nested")], artifacts="skills")
        self.assertEqual(len(found), 1)
        self.assertEqual(found[0].artifact_kind, "skill")
        self.assertTrue(found[0].path.as_posix().endswith("skills/inner"))

    def test_unknown_mode_is_rejected(self):
        with self.assertRaises(ValueError):
            discover(roots=[str(PLUGINS)], artifacts="everything")


if __name__ == "__main__":
    unittest.main()

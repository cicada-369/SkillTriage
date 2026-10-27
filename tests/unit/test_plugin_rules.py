import unittest

from skilltriage.analysis import audit_paths
from skilltriage.policy import AuditOptions
from tests.helpers import FIXTURES, get, ids

PLUGINS = FIXTURES / "plugins"

PLUGIN_RULE_PREFIXES = (
    "AST09-PLUGIN-",
    "AST06-PLUGIN-",
    "AST04-PLUGIN-",
    "AST02-PLUGIN-",
    "AST07-PLUGIN-",
    "AST03-PLUGIN-",
)


def audit_plugin(name: str):
    options = AuditOptions()
    options.fail_on = None
    report = audit_paths([PLUGINS / name], options)
    return report.results[0]


class PluginRuleTests(unittest.TestCase):
    def test_hook_approval_escape_and_missing_script(self):
        result = audit_plugin("hooks_injection")
        found = ids(result)
        self.assertIn("AST09-PLUGIN-HOOK-APPROVAL", found)
        self.assertIn("AST06-PLUGIN-HOOK-PATH-ESCAPE", found)
        self.assertIn("AST04-PLUGIN-HOOK-MISSING-SCRIPT", found)
        escapes = " ".join(
            finding.evidence
            for finding in result.findings
            if finding.rule_id == "AST06-PLUGIN-HOOK-PATH-ESCAPE"
        )
        self.assertIn("../outside.sh", escapes)
        self.assertIn("/opt/evil/approve.py", escapes)
        self.assertIn("$HOME/evil.sh", escapes)

    def test_approval_finding_points_at_the_script(self):
        finding = get(audit_plugin("hooks_injection"), "AST09-PLUGIN-HOOK-APPROVAL")
        self.assertEqual(finding.path, "hooks/allow.sh")
        self.assertIn("permissionDecision", finding.evidence)

    def test_benign_hook_and_mcp_are_not_flagged(self):
        found = ids(audit_plugin("benign"))
        for rule in (
            "AST09-PLUGIN-HOOK-APPROVAL",
            "AST06-PLUGIN-HOOK-PATH-ESCAPE",
            "AST04-PLUGIN-HOOK-MISSING-SCRIPT",
            "AST02-PLUGIN-MCP-UNPINNED-EXEC",
            "AST02-PLUGIN-MCP-CLEARTEXT",
            "AST03-PLUGIN-BROAD-TOOL-GRANT",
            "AST04-PLUGIN-COMPONENT-ESCAPE",
            "AST04-PLUGIN-COMPONENT-MISSING",
        ):
            self.assertNotIn(rule, found, rule)

    def test_mcp_unpinned_and_cleartext(self):
        found = ids(audit_plugin("mcp_unpinned"))
        self.assertIn("AST02-PLUGIN-MCP-UNPINNED-EXEC", found)
        self.assertIn("AST02-PLUGIN-MCP-CLEARTEXT", found)

    def test_broad_tool_grant(self):
        result = audit_plugin("broad_tools")
        findings = [
            item
            for item in result.findings
            if item.rule_id == "AST03-PLUGIN-BROAD-TOOL-GRANT"
        ]
        self.assertEqual(
            {item.path for item in findings},
            {
                "commands/everything/COMMAND.md",
                "commands/bash-all/COMMAND.md",
            },
        )

    def test_component_escape(self):
        found = ids(audit_plugin("component_escape"))
        self.assertIn("AST04-PLUGIN-COMPONENT-ESCAPE", found)

    def test_marketplace_pinning(self):
        found = ids(audit_plugin("marketplace_root"))
        self.assertIn("AST07-PLUGIN-MARKETPLACE-UNPINNED", found)

    def test_github_marketplace_source_is_covered(self):
        found = ids(audit_plugin("marketplace_github"))
        self.assertIn("AST07-PLUGIN-MARKETPLACE-UNPINNED", found)

    def test_plugin_permission_rules_do_not_misfire(self):
        found = ids(audit_plugin("benign"))
        self.assertNotIn("AST03-NO-PERMISSION-MANIFEST", found)
        self.assertNotIn("AST04-MISSING-SKILL-MD", found)
        self.assertNotIn("AST04-MISSING-FRONTMATTER", found)

    def test_plugin_rules_are_inert_on_skill_targets(self):
        options = AuditOptions()
        options.fail_on = None
        result = audit_paths([FIXTURES / "malicious" / "download_exec"], options).results[0]
        found = ids(result)
        self.assertFalse(
            [rule for rule in found if rule.startswith(PLUGIN_RULE_PREFIXES)],
            found,
        )


if __name__ == "__main__":
    unittest.main()

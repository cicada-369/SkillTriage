import io
import json
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path
from unittest import mock

from skilltriage.cli import main
from tests.helpers import FIXTURES, skill_md, write_skill

PLUGINS = FIXTURES / "plugins"


def run(args):
    stdout = io.StringIO()
    stderr = io.StringIO()
    with redirect_stdout(stdout), redirect_stderr(stderr):
        code = main(args)
    return code, stdout.getvalue(), stderr.getvalue()


class CliIntentTests(unittest.TestCase):
    def _populate(self, db: Path) -> None:
        code, _, err = run(
            [
                "scan",
                "--root",
                str(FIXTURES / "intent"),
                "--no-config",
                "--inventory",
                "--inventory-file",
                str(db),
                "--update-inventory",
                "--fail-on",
                "none",
                "--format",
                "json",
            ]
        )
        self.assertEqual(code, 0)
        self.assertIn("inventory updated", err)

    def test_update_inventory_flag_writes_the_file(self):
        with tempfile.TemporaryDirectory() as tmp:
            db = Path(tmp) / "inventory.json"
            self._populate(db)
            self.assertTrue(db.is_file())

    def test_intent_requires_both_policy_and_inventory(self):
        with tempfile.TemporaryDirectory() as tmp:
            db = Path(tmp) / "inventory.json"
            args = [
                "scan",
                "--root",
                str(FIXTURES / "intent"),
                "--no-config",
                "--inventory",
                "--inventory-file",
                str(db),
                "--allow-intent",
                "offensive-security",
                "--format",
                "json",
            ]
            # Policy alone is not enough: there is no inventory record yet.
            code, out, _ = run(args)
            self.assertEqual(code, 1)
            target = json.loads(out)["targets"][0]
            self.assertFalse(target["target"]["intent_allowed"])

            self._populate(db)
            code, out, _ = run(args)
            self.assertEqual(code, 0)
            target = json.loads(out)["targets"][0]
            self.assertTrue(target["target"]["intent_allowed"])
            self.assertEqual(target["summary"]["gating"], 0)
            self.assertEqual(target["summary"]["intent"], 1)


class CliPluginTests(unittest.TestCase):
    def test_scan_marks_a_plugin_artifact(self):
        code, out, _ = run(
            [
                "scan",
                str(PLUGINS / "benign"),
                "--no-config",
                "--fail-on",
                "none",
                "--format",
                "json",
            ]
        )
        self.assertEqual(code, 0)
        target = json.loads(out)["targets"][0]["target"]
        self.assertEqual(target["artifact_kind"], "plugin")

    def test_scan_system_remains_skill_by_skill(self):
        code, out, _ = run(
            [
                "scan-system",
                "--root",
                str(PLUGINS / "nested"),
                "--no-config",
                "--fail-on",
                "none",
                "--format",
                "json",
            ]
        )
        self.assertEqual(code, 0)
        payload = json.loads(out)
        self.assertEqual(len(payload["targets"]), 1)
        self.assertEqual(payload["targets"][0]["target"]["artifact_kind"], "skill")

    def test_scan_can_restrict_discovery_to_plugins(self):
        code, out, _ = run(
            [
                "scan",
                "--root",
                str(PLUGINS),
                "--artifacts",
                "plugins",
                "--no-config",
                "--fail-on",
                "none",
                "--format",
                "json",
            ]
        )
        self.assertEqual(code, 0)
        targets = json.loads(out)["targets"]
        self.assertEqual(
            {target["target"]["artifact_kind"] for target in targets}, {"plugin"}
        )
        self.assertEqual(
            len(targets), len(list(PLUGINS.glob("*/.claude-plugin/plugin.json")))
        )

    def test_discover_artifacts_both_lists_plugin_roots(self):
        code, out, _ = run(
            ["discover", "--root", str(PLUGINS), "--artifacts", "both", "--json"]
        )
        self.assertEqual(code, 0)
        skills = json.loads(out)["skills"]
        self.assertEqual({item["artifact_kind"] for item in skills}, {"plugin"})
        self.assertEqual(
            len(skills),
            len(list(PLUGINS.glob("*/.claude-plugin/plugin.json"))),
        )


class CliScanTests(unittest.TestCase):
    def test_scan_with_path(self):
        code, out, _ = run(
            [
                "scan",
                str(FIXTURES / "benign" / "minimal_skill"),
                "--no-config",
                "--format",
                "json",
            ]
        )
        self.assertEqual(code, 0)
        self.assertEqual(len(json.loads(out)["targets"]), 1)

    def test_scan_infers_html_from_output_suffix(self):
        with tempfile.TemporaryDirectory() as tmp:
            output = Path(tmp) / "report.html"
            code, _, _ = run(
                [
                    "scan",
                    str(FIXTURES / "benign" / "minimal_skill"),
                    "--no-config",
                    "-o",
                    str(output),
                ]
            )
            self.assertEqual(code, 0)
            self.assertTrue(output.is_file())
            self.assertTrue(output.read_text(encoding="utf-8").startswith("<!doctype html>"))

    def test_scan_rejects_unknown_output_suffix(self):
        with tempfile.TemporaryDirectory() as tmp:
            output = Path(tmp) / "report.weird"
            code, _, err = run(
                [
                    "scan",
                    str(FIXTURES / "benign" / "minimal_skill"),
                    "--no-config",
                    "-o",
                    str(output),
                ]
            )
            self.assertEqual(code, 2)
            self.assertIn("cannot infer", err)
            self.assertFalse(output.exists())

    def test_open_requires_html_output(self):
        code, _, err = run(
            [
                "scan",
                str(FIXTURES / "benign" / "minimal_skill"),
                "--no-config",
                "--open",
            ]
        )
        self.assertEqual(code, 2)
        self.assertIn("--open requires", err)

    def test_open_invokes_the_browser_with_a_file_uri(self):
        with tempfile.TemporaryDirectory() as tmp:
            output = Path(tmp) / "report.html"
            with mock.patch("skilltriage.cli.webbrowser.open") as opener:
                code, _, _ = run(
                    [
                        "scan",
                        str(FIXTURES / "benign" / "minimal_skill"),
                        "--no-config",
                        "-o",
                        str(output),
                        "--open",
                    ]
                )
            self.assertEqual(code, 0)
            opener.assert_called_once()
            self.assertTrue(opener.call_args[0][0].startswith("file://"))

    def test_scan_with_no_targets_explains_what_was_checked(self):
        with tempfile.TemporaryDirectory() as tmp:
            code, _, err = run(["scan", "--root", tmp, "--no-config"])
        self.assertEqual(code, 2)
        self.assertIn("no skills or plugins found", err)
        self.assertIn("Directories checked", err)
        self.assertIn("Try:", err)

    def test_text_report_points_at_rule_explanations(self):
        code, out, _ = run(
            [
                "audit",
                str(FIXTURES / "malicious" / "download_exec"),
                "--no-config",
                "--format",
                "text",
            ]
        )
        self.assertEqual(code, 1)
        self.assertIn("rules explain", out)


class CliAuditTests(unittest.TestCase):
    def test_benign_audit_passes(self):
        code, out, _ = run(
            ["audit", str(FIXTURES / "benign" / "minimal_skill"), "--no-config", "--format", "json"]
        )
        self.assertEqual(code, 0)
        payload = json.loads(out)
        self.assertEqual(payload["result"], "pass")

    def test_malicious_audit_fails_and_can_be_made_advisory(self):
        path = str(FIXTURES / "malicious" / "download_exec")
        code, out, _ = run(["audit", path, "--no-config", "--format", "json"])
        self.assertEqual(code, 1)
        self.assertEqual(json.loads(out)["result"], "fail")
        advisory, _, _ = run(["audit", path, "--no-config", "--fail-on", "none"])
        self.assertEqual(advisory, 0)

    def test_multiple_targets(self):
        code, out, _ = run(
            [
                "audit",
                str(FIXTURES / "benign" / "minimal_skill"),
                str(FIXTURES / "malicious" / "download_exec"),
                "--no-config",
                "--format",
                "json",
            ]
        )
        self.assertEqual(code, 1)
        payload = json.loads(out)
        self.assertEqual(len(payload["targets"]), 2)

    def test_missing_target_is_an_error(self):
        code, _, err = run(["audit", "/definitely/not/here", "--no-config"])
        self.assertEqual(code, 2)
        self.assertIn("scan error", err)

    def test_scan_error_text_is_sanitized(self):
        code, _, err = run(["audit", "/definitely/not/\x1b[31mhere", "--no-config"])
        self.assertEqual(code, 2)
        self.assertNotIn("\x1b", err)
        self.assertIn("\\x1b", err)

    def test_corrupt_archive_is_a_clean_scan_error(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "broken.zip"
            path.write_bytes(b"PK\x03\x04" + b"\x00" * 32)
            code, _, err = run(["audit", str(path), "--no-config"])
            self.assertEqual(code, 2)
            self.assertIn("scan error", err)
            self.assertNotIn("Traceback", err)

    def test_archive_audit(self):
        import zipfile

        with tempfile.TemporaryDirectory() as tmp:
            archive = Path(tmp) / "skill.zip"
            root = FIXTURES / "benign" / "minimal_skill"
            with zipfile.ZipFile(archive, "w") as handle:
                for path in root.rglob("*"):
                    if path.is_file():
                        handle.write(path, path.relative_to(root).as_posix())
            code, out, _ = run(["audit", str(archive), "--no-config", "--format", "json"])
            self.assertEqual(code, 0)
            payload = json.loads(out)
            self.assertEqual(payload["targets"][0]["target"]["kind"], "archive")

    def test_output_file(self):
        with tempfile.TemporaryDirectory() as tmp:
            output = Path(tmp) / "report.sarif"
            code, _, _ = run(
                [
                    "audit",
                    str(FIXTURES / "malicious" / "download_exec"),
                    "--no-config",
                    "--format",
                    "sarif",
                    "--output",
                    str(output),
                ]
            )
            self.assertEqual(code, 1)
            self.assertTrue(output.is_file())
            self.assertEqual(json.loads(output.read_text())["version"], "2.1.0")

    def test_baseline_round_trip(self):
        path = str(FIXTURES / "malicious" / "download_exec")
        with tempfile.TemporaryDirectory() as tmp:
            baseline = Path(tmp) / "baseline.json"
            first, _, _ = run(
                ["audit", path, "--no-config", "--write-baseline", str(baseline)]
            )
            self.assertEqual(first, 1)
            self.assertTrue(baseline.is_file())
            second, out, _ = run(
                ["audit", path, "--no-config", "--baseline", str(baseline), "--format", "json"]
            )
            self.assertEqual(second, 0)
            self.assertEqual(json.loads(out)["result"], "pass")


class CliOtherCommandTests(unittest.TestCase):
    def test_rules_list_and_explain(self):
        code, out, _ = run(["rules", "list", "--format", "json", "--ast", "AST01"])
        self.assertEqual(code, 0)
        rules = json.loads(out)
        self.assertTrue(rules)
        self.assertTrue(all(rule["ast"] == "AST01" for rule in rules))
        code, out, _ = run(["rules", "explain", "AST01-DOWNLOAD-EXEC"])
        self.assertEqual(code, 0)
        self.assertIn("Download and execute", out)
        code, _, err = run(["rules", "explain", "NOPE"])
        self.assertEqual(code, 2)
        self.assertIn("unknown rule", err)

    def test_validate_cases(self):
        code, out, _ = run(
            ["validate-cases", str(FIXTURES / "benign" / "minimal_skill" / "tests" / "cases.json")]
        )
        self.assertEqual(code, 0)
        self.assertIn("PASS", out)
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "bad.json"
            path.write_text('[{"id": "a"}]')
            code, out, _ = run(["validate-cases", str(path)])
            self.assertEqual(code, 1)
            self.assertIn("FAIL", out)

    def test_discover(self):
        code, out, _ = run(
            ["discover", "--json", "--root", str(FIXTURES / "benign"), "--no-config"]
        )
        self.assertEqual(code, 0)
        payload = json.loads(out)
        self.assertEqual(len(payload["skills"]), 1)
        self.assertEqual(payload["skills"][0]["kind"], "other")

    def test_scan_system(self):
        code, out, _ = run(
            [
                "scan-system",
                "--root",
                str(FIXTURES / "benign"),
                "--no-marketplaces",
                "--no-config",
                "--format",
                "json",
            ]
        )
        self.assertEqual(code, 0)
        payload = json.loads(out)
        self.assertEqual(payload["summary"]["targets"], 1)

        code, _, _ = run(
            [
                "scan-system",
                "--root",
                str(FIXTURES / "malicious"),
                "--no-marketplaces",
                "--no-config",
                "--format",
                "json",
            ]
        )
        self.assertEqual(code, 1)

    def test_inventory_sync_and_list(self):
        with tempfile.TemporaryDirectory() as tmp:
            db = Path(tmp) / "inventory.json"
            code, out, _ = run(
                [
                    "inventory",
                    "sync",
                    "--root",
                    str(FIXTURES / "benign"),
                    "--db",
                    str(db),
                    "--no-config",
                    "--format",
                    "json",
                ]
            )
            self.assertEqual(code, 0)
            summary = json.loads(out)
            self.assertEqual(summary["added"], 1)
            code, out, _ = run(["inventory", "list", "--db", str(db), "--format", "json"])
            self.assertEqual(code, 0)
            payload = json.loads(out)
            self.assertEqual(len(payload["skills"]), 1)
            code, out, _ = run(["inventory", "path", "--db", str(db)])
            self.assertEqual(code, 0)
            self.assertEqual(out.strip(), str(db))


if __name__ == "__main__":
    unittest.main()

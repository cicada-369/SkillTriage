import os
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from skilltriage.baseline import Baseline, BaselineError, apply_baseline
from skilltriage.models import Confidence, Finding, Severity
from skilltriage.policy import (
    AuditOptions,
    ConfigError,
    apply_config,
    apply_profile,
    gating_findings,
    is_gating,
    load_config,
)
from tests.helpers import FIXTURES, audit


def finding(severity=Severity.HIGH, confidence=Confidence.HIGH) -> Finding:
    return Finding(
        rule_id="AST01-TEST",
        ast="AST01",
        severity=severity,
        confidence=confidence,
        path="SKILL.md",
        message="test",
        evidence="test",
    )


class PolicyTests(unittest.TestCase):
    def test_intent_matched_does_not_gate(self):
        item = finding(Severity.CRITICAL, Confidence.HIGH)
        item.intent_matched = True
        self.assertFalse(is_gating(item, AuditOptions()))

    def test_invalid_config_values_raise_config_error(self):
        with self.assertRaises(ConfigError):
            apply_config(AuditOptions(), {"audit": {"fail_on": "bogus"}})
        with self.assertRaises(ConfigError):
            apply_config(AuditOptions(), {"audit": {"min_confidence": "bogus"}})

    def test_project_config_is_not_auto_loaded(self):
        with tempfile.TemporaryDirectory() as tmp:
            (Path(tmp) / ".skilltriage.toml").write_text(
                '[audit]\nfail_on = "none"\n', encoding="utf-8"
            )
            previous = os.getcwd()
            os.chdir(tmp)
            try:
                with mock.patch.dict(os.environ, {"HOME": tmp}):
                    config = load_config(None, False)
            finally:
                os.chdir(previous)
            self.assertEqual(config, {})

    def test_user_config_is_loaded(self):
        with tempfile.TemporaryDirectory() as tmp:
            user_config = Path(tmp) / ".config" / "skilltriage" / "config.toml"
            user_config.parent.mkdir(parents=True)
            user_config.write_text('[audit]\nfail_on = "none"\n', encoding="utf-8")
            with mock.patch.dict(os.environ, {"HOME": tmp}):
                config = load_config(None, False)
            self.assertEqual(config["audit"]["fail_on"], "none")

    def test_non_utf8_config_is_a_config_error(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "config.toml"
            path.write_bytes(b"\xff\xfe")
            with self.assertRaises(ConfigError):
                load_config(str(path), False)

    def test_non_utf8_baseline_is_a_baseline_error(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "baseline.json"
            path.write_bytes(b"\xff\xfe")
            with self.assertRaises(BaselineError):
                Baseline.load(path)

    def test_gating_threshold(self):
        options = AuditOptions()
        self.assertTrue(is_gating(finding(Severity.HIGH, Confidence.HIGH), options))
        self.assertFalse(is_gating(finding(Severity.MEDIUM, Confidence.HIGH), options))
        self.assertFalse(is_gating(finding(Severity.HIGH, Confidence.MEDIUM), options))
        options.min_confidence = Confidence.MEDIUM
        self.assertTrue(is_gating(finding(Severity.HIGH, Confidence.MEDIUM), options))

    def test_suppressed_and_baselined_do_not_gate(self):
        options = AuditOptions()
        suppressed = finding()
        suppressed.suppressed = True
        baselined = finding()
        baselined.baselined = True
        self.assertFalse(is_gating(suppressed, options))
        self.assertFalse(is_gating(baselined, options))

    def test_profiles(self):
        options = AuditOptions()
        apply_profile(options, "advisory")
        self.assertIsNone(options.fail_on)
        apply_profile(options, "strict")
        self.assertEqual(options.fail_on, Severity.MEDIUM)
        self.assertEqual(options.min_confidence, Confidence.MEDIUM)
        apply_profile(options, "default")
        self.assertEqual(options.fail_on, Severity.HIGH)

    def test_config_file(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "config.toml"
            path.write_text(
                '[audit]\nprofile = "strict"\nfail_on = "medium"\nmin_confidence = "medium"\n',
                encoding="utf-8",
            )
            config = load_config(explicit=str(path))
            options = apply_config(AuditOptions(), config)
            self.assertEqual(options.profile, "strict")
            self.assertEqual(options.fail_on, Severity.MEDIUM)
            self.assertEqual(options.min_confidence, Confidence.MEDIUM)

    def test_missing_config_raises(self):
        with tempfile.TemporaryDirectory() as tmp:
            with self.assertRaises(Exception):
                load_config(explicit=str(Path(tmp) / "missing.toml"))


class BaselineTests(unittest.TestCase):
    def test_write_load_and_apply(self):
        first = audit(FIXTURES / "malicious" / "download_exec")
        options = AuditOptions()
        self.assertGreater(first.gating_count, 0)
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "baseline.json"
            Baseline().write(path, [first])
            baseline = Baseline.load(path)
            self.assertTrue(baseline.entries)
            second = audit(FIXTURES / "malicious" / "download_exec")
            applied = apply_baseline([second], baseline)
            self.assertGreater(applied, 0)
            self.assertTrue(any(finding.baselined for finding in second.findings))
            self.assertEqual(gating_findings(second.findings, options), [])

    def test_skill_id_scope(self):
        result = audit(FIXTURES / "benign" / "minimal_skill")
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "baseline.json"
            Baseline().write(path, [result])
            baseline = Baseline.load(path)
            entry = baseline.entries[0]
            fake = finding()
            fake.fingerprint = entry.fingerprint
            self.assertTrue(baseline.matches(fake, result.target.skill_id))
            self.assertFalse(baseline.matches(fake, "another-skill"))

    def test_missing_baseline_raises(self):
        with self.assertRaises(BaselineError):
            Baseline.load("/definitely/not/here.json")


if __name__ == "__main__":
    unittest.main()

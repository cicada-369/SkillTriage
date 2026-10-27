"""Characterisation tests for the existing rule engine.

These snapshots are the safety net for changes to shared rules and
normalisation. Update them deliberately (``UPDATE_SNAPSHOTS=1 make test``)
and review every diff; an unexplained change is a regression.
"""

import json
import os
import unittest

from skilltriage.rules import all_rules
from tests.helpers import FIXTURES, audit, finding_signature

FIXTURE_TARGETS = [
    "benign/minimal_skill",
    "crossplatform",
    "malicious/credential_exfil",
    "malicious/download_exec",
    "malicious/identity_persistence",
    "malicious/unsafe_metadata",
    "suppressions",
]
EXPECTED = FIXTURES / "expected"


class RegressionSnapshotTests(unittest.TestCase):
    def test_fixture_findings_match_snapshot(self):
        for name in FIXTURE_TARGETS:
            with self.subTest(fixture=name):
                actual = finding_signature(audit(FIXTURES / name))
                snapshot = EXPECTED / (name.replace("/", "__") + ".json")
                if os.environ.get("UPDATE_SNAPSHOTS") == "1":
                    EXPECTED.mkdir(parents=True, exist_ok=True)
                    snapshot.write_text(
                        json.dumps(actual, indent=2, sort_keys=True) + "\n",
                        encoding="utf-8",
                    )
                self.assertTrue(
                    snapshot.is_file(),
                    f"missing snapshot {snapshot}; regenerate with UPDATE_SNAPSHOTS=1",
                )
                expected = json.loads(snapshot.read_text(encoding="utf-8"))
                self.assertEqual(actual, expected, name)

    def test_rule_registry_size_is_pinned(self):
        # A change here is expected when rules are added; update the number and
        # the generated catalog together.
        self.assertEqual(len(all_rules()), 107)


if __name__ == "__main__":
    unittest.main()

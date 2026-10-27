import tomllib
import unittest
from pathlib import Path

import skilltriage

ROOT = Path(__file__).resolve().parents[2]


def _pyproject() -> dict:
    with (ROOT / "pyproject.toml").open("rb") as handle:
        return tomllib.load(handle)


class PackagingMetadataTests(unittest.TestCase):
    def test_version_is_single_sourced(self):
        project = _pyproject()["project"]
        self.assertEqual(project["version"], skilltriage.__version__)
        changelog = (ROOT / "CHANGELOG.md").read_text(encoding="utf-8")
        self.assertIn(f"## [{skilltriage.__version__}]", changelog)

    def test_licence_is_apache_2_0(self):
        project = _pyproject()["project"]
        self.assertEqual(project["license"], "Apache-2.0")
        self.assertIn("LICENSE", project["license-files"])
        licence = (ROOT / "LICENSE").read_text(encoding="utf-8")
        self.assertIn("Apache License", licence)
        self.assertIn("Version 2.0", licence)
        # PEP 639 forbids license classifiers alongside a license expression.
        classifiers = " ".join(project["classifiers"])
        self.assertNotIn("License ::", classifiers)

    def test_zero_runtime_dependencies(self):
        project = _pyproject()["project"]
        self.assertEqual(project["dependencies"], [])
        self.assertTrue(project["requires-python"].startswith(">=3.11"))

    def test_console_script_and_urls(self):
        project = _pyproject()["project"]
        self.assertEqual(project["scripts"]["skilltriage"], "skilltriage.cli:main")
        urls = project["urls"]
        self.assertIn("Homepage", urls)
        self.assertIn("Issues", urls)
        self.assertTrue(urls["Homepage"].startswith("https://"))


if __name__ == "__main__":
    unittest.main()

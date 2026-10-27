import unittest
from pathlib import Path

from skilltriage.parsers import (
    find_anchors,
    find_unsafe_tags,
    parse_json_text,
    parse_toml_text,
    parse_yaml_subset,
    split_frontmatter,
)
from tests.helpers import FIXTURES

try:
    import yaml
except ImportError:  # pragma: no cover
    yaml = None


def codes(issues) -> set[str]:
    return {issue.code for issue in issues}


class FrontmatterTests(unittest.TestCase):
    def test_extracts_frontmatter_and_body_offset(self):
        text = "---\nname: demo\n---\n\n# Body\n"
        front = split_frontmatter(text)
        self.assertTrue(front.found)
        self.assertEqual(front.meta_text, "name: demo")
        self.assertEqual(front.body.strip(), "# Body")
        self.assertEqual(front.body_line, 4)

    def test_missing_frontmatter(self):
        front = split_frontmatter("# no metadata\n")
        self.assertFalse(front.found)
        self.assertEqual(front.body, "# no metadata\n")

    def test_unclosed_frontmatter_is_reported(self):
        front = split_frontmatter("---\nname: demo\n")
        self.assertTrue(front.found)
        self.assertIn("MISSING_CLOSING_FRONTMATTER", codes(front.issues))

    def test_bom_is_stripped(self):
        front = split_frontmatter("﻿---\nname: demo\n---\nbody\n")
        self.assertTrue(front.found)


class YamlSubsetTests(unittest.TestCase):
    def parse(self, text):
        return parse_yaml_subset(text)

    def test_basic_mapping(self):
        data, issues = self.parse("name: demo\nversion: 1.2.3\nshell: false\ncount: 3\n")
        self.assertEqual(data["name"], "demo")
        self.assertEqual(data["version"], "1.2.3")
        self.assertIs(data["shell"], False)
        self.assertEqual(data["count"], 3)
        self.assertEqual(issues, [])

    def test_nested_mapping_and_sequence(self):
        data, _ = self.parse(
            "metadata:\n"
            "  version: '1.0.0'\n"
            "  tags: a, b, c\n"
            "permissions:\n"
            "  files:\n"
            "    read:\n"
            "      - ./a.txt\n"
            "      - ./b.txt\n"
            "  shell: false\n"
        )
        self.assertEqual(data["metadata"]["version"], "1.0.0")
        self.assertEqual(data["metadata"]["tags"], "a, b, c")
        self.assertEqual(data["permissions"]["files"]["read"], ["./a.txt", "./b.txt"])
        self.assertIs(data["permissions"]["shell"], False)

    def test_folded_plain_scalar(self):
        data, _ = self.parse(
            "description: first part,\n"
            "  second part continues here\n"
            "name: demo\n"
        )
        self.assertEqual(data["description"], "first part, second part continues here")
        self.assertEqual(data["name"], "demo")

    def test_quoted_multiline_scalar_after_empty_key(self):
        data, _ = self.parse(
            "description:\n"
            '  "first line\n'
            '  second line"\n'
            "name: demo\n"
        )
        self.assertEqual(data["description"], "first line second line")
        self.assertEqual(data["name"], "demo")

    def test_block_scalars(self):
        data, _ = self.parse("literal: |\n  line one\n  line two\nfolded: >\n  one\n  two\n")
        self.assertEqual(data["literal"], "line one\nline two\n")
        self.assertEqual(data["folded"], "one two\n")

    def test_flow_collections(self):
        data, _ = self.parse("tags: [a, b, c]\nopts: {shell: false, network: true}\n")
        self.assertEqual(data["tags"], ["a", "b", "c"])
        self.assertIs(data["opts"]["shell"], False)
        self.assertIs(data["opts"]["network"], True)

    def test_comments_and_urls(self):
        data, _ = self.parse(
            "url: https://example.invalid/a#fragment\n"
            "note: value # trailing comment\n"
        )
        self.assertEqual(data["url"], "https://example.invalid/a#fragment")
        self.assertEqual(data["note"], "value")

    def test_duplicate_key_is_reported(self):
        data, issues = self.parse("name: one\nname: two\n")
        self.assertEqual(data["name"], "two")
        self.assertIn("DUPLICATE_KEY", codes(issues))

    def test_unsafe_tag_is_not_resolved(self):
        data, issues = self.parse('payload: !!python/object/apply:os.system ["echo x"]\n')
        self.assertIn("UNSAFE_YAML_TAG", codes(issues))
        self.assertIn("!!python", str(data["payload"]))

    def test_anchor_is_not_resolved(self):
        data, issues = self.parse("a: &anchor value\n")
        self.assertIn("YAML_ANCHOR_ALIAS", codes(issues))
        self.assertIn("&anchor", data["a"])

    def test_tab_indentation_is_reported(self):
        _, issues = self.parse("\tname: demo\n")
        self.assertIn("TAB_INDENT", codes(issues))

    def test_unsafe_tag_and_anchor_finders(self):
        text = "a: !!python/object x\nb: &anchor y\n"
        self.assertTrue(find_unsafe_tags(text))
        self.assertTrue(find_anchors(text))


class JsonAndTomlTests(unittest.TestCase):
    def test_json_duplicate_key(self):
        data, issues = parse_json_text('{"a": 1, "a": 2}')
        self.assertEqual(data["a"], 2)
        self.assertIn("DUPLICATE_KEY", codes(issues))

    def test_json_invalid(self):
        _, issues = parse_json_text("{")
        self.assertIn("INVALID_JSON", codes(issues))

    def test_json_top_level_array(self):
        _, issues = parse_json_text("[1, 2]")
        self.assertIn("TOP_LEVEL_NOT_MAPPING", codes(issues))

    def test_toml(self):
        data, issues = parse_toml_text('[project]\nname = "demo"\n')
        self.assertEqual(data["project"]["name"], "demo")
        self.assertEqual(issues, [])

    def test_toml_invalid(self):
        _, issues = parse_toml_text("[project\n")
        self.assertIn("INVALID_TOML", codes(issues))


class FrontmatterLimitTests(unittest.TestCase):
    def test_long_body_does_not_trigger_frontmatter_limit(self):
        lines = ["---", "name: demo", "---"] + ["body"] * 6000
        front = split_frontmatter("\n".join(lines))
        self.assertTrue(front.found)
        self.assertFalse(
            any(issue.code == "FRONTMATTER_TOO_LONG" for issue in front.issues)
        )

    def test_unclosed_long_frontmatter_is_reported(self):
        text = "---\n" + "key: value\n" * 6000
        front = split_frontmatter(text)
        self.assertTrue(
            any(
                issue.code in ("FRONTMATTER_TOO_LONG", "MISSING_CLOSING_FRONTMATTER")
                for issue in front.issues
            )
        )


class HostileInputTests(unittest.TestCase):
    def test_deeply_nested_flow_yaml_is_bounded(self):
        text = "value: " + "[" * 5000 + "]" * 5000
        _, issues = parse_yaml_subset(text)
        self.assertIn("TOO_DEEP", codes(issues))

    def test_deeply_nested_json_is_bounded(self):
        text = "[" * 100_000 + "]" * 100_000
        data, issues = parse_json_text(text)
        self.assertIn("TOO_DEEP", codes(issues))
        self.assertEqual(data, {})

    def test_deeply_nested_toml_is_bounded(self):
        text = "value = " + "[" * 5000 + "]" * 5000
        _, issues = parse_toml_text(text)
        self.assertIn("TOO_DEEP", codes(issues))

    def test_lone_surrogate_escape_stays_visible(self):
        data, _ = parse_yaml_subset('key: "\\ud800"')
        self.assertEqual(data["key"], "\\ud800")
        self.assertFalse(
            any(0xD800 <= ord(char) <= 0xDFFF for char in data["key"])
        )

    def test_out_of_range_unicode_escape_is_literal(self):
        data, _ = parse_yaml_subset('key: "\\U00110000"')
        self.assertEqual(data["key"], "\\U00110000")

    def test_oversized_json_integer_is_an_issue(self):
        _, issues = parse_json_text("9" * 5000)
        self.assertIn("INVALID_JSON", codes(issues))

    def test_oversized_toml_integer_is_an_issue(self):
        _, issues = parse_toml_text("value = " + "9" * 5000)
        self.assertIn("INVALID_TOML", codes(issues))


@unittest.skipUnless(yaml is not None, "PyYAML is not installed")
class PyYamlCrossCheckTests(unittest.TestCase):
    """Our subset must agree with PyYAML on the metadata shapes found in skills."""

    @staticmethod
    def normalise(value):
        if isinstance(value, dict):
            return {str(key): PyYamlCrossCheckTests.normalise(item) for key, item in value.items()}
        if isinstance(value, list):
            return [PyYamlCrossCheckTests.normalise(item) for item in value]
        return value

    def assert_equivalent(self, ours, reference, path=""):
        self.assertEqual(type(ours), type(reference), f"type mismatch at {path}")
        if isinstance(ours, dict):
            self.assertEqual(set(ours), set(reference), f"keys differ at {path}")
            for key in ours:
                self.assert_equivalent(ours[key], reference[key], f"{path}/{key}")
        elif isinstance(ours, list):
            self.assertEqual(len(ours), len(reference), f"length differs at {path}")
            for index, (left, right) in enumerate(zip(ours, reference)):
                self.assert_equivalent(left, right, f"{path}[{index}]")
        else:
            self.assertEqual(ours, reference, f"value differs at {path}")

    def test_fixture_frontmatter_matches_pyyaml(self):
        for path in sorted(FIXTURES.rglob("SKILL.md")):
            text = path.read_text(encoding="utf-8", errors="replace")
            front = split_frontmatter(text)
            if not front.found:
                continue
            try:
                reference = yaml.safe_load(front.meta_text) or {}
            except yaml.YAMLError:
                continue
            ours, issues = parse_yaml_subset(front.meta_text)
            if any(issue.code in ("UNSAFE_YAML_TAG", "YAML_ANCHOR_ALIAS") for issue in issues):
                continue
            self.assert_equivalent(self.normalise(ours), self.normalise(reference), str(path))


if __name__ == "__main__":
    unittest.main()

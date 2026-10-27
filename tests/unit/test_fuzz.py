"""Bounded, deterministic hostile-input tests.

This is not coverage-guided fuzzing. It is a fixed-seed corpus that asserts the
parsers and escaping helpers return rather than raise on arbitrary text.
"""

import random
import string
import unittest

from skilltriage.parsers import (
    parse_json_text,
    parse_toml_text,
    parse_yaml_subset,
    split_frontmatter,
)
from skilltriage.safety import escape_unsafe
from skilltriage.secrets import mask_evidence, redact

ALPHABET = (
    string.printable
    + "\x00\x01\x1b\x7f"
    + "\u202e\u200b\u2028\ufeff"
    + "[]{}'\"\\:#-\n\t"
)


def _random_text(rng: random.Random, length: int) -> str:
    return "".join(rng.choice(ALPHABET) for _ in range(length))


class ParserFuzzTests(unittest.TestCase):
    def test_parsers_return_instead_of_raising(self):
        rng = random.Random(20261026)
        for _ in range(300):
            text = _random_text(rng, rng.randint(0, 240))
            parse_yaml_subset(text)
            parse_json_text(text)
            parse_toml_text(text)
            split_frontmatter(text)

    def test_structured_fragments_do_not_raise(self):
        rng = random.Random(7)
        fragments = ["---", "---\n", "{", "}", "[", "]", ":", "- ", "\"", "'", "\\", "!!", "&a ", "*a "]
        for _ in range(300):
            text = "".join(
                rng.choice(fragments) + _random_text(rng, rng.randint(0, 20))
                for _ in range(rng.randint(0, 8))
            )
            parse_yaml_subset(text)
            parse_json_text(text)
            parse_toml_text(text)
            split_frontmatter(text)


class EscapingFuzzTests(unittest.TestCase):
    def test_escaping_is_total_and_idempotent(self):
        rng = random.Random(99)
        for _ in range(300):
            text = _random_text(rng, rng.randint(0, 240))
            escaped = escape_unsafe(text)
            self.assertEqual(escape_unsafe(escaped), escaped)

    def test_redaction_and_masking_are_bounded(self):
        rng = random.Random(1234)
        for _ in range(300):
            text = _random_text(rng, rng.randint(0, 300))
            redact(text)
            masked = mask_evidence(text, limit=100)
            self.assertLessEqual(len(masked), 100)
            self.assertFalse(any(0xD800 <= ord(char) <= 0xDFFF for char in masked))


if __name__ == "__main__":
    unittest.main()

import unittest

from skilltriage.safety import escape_unsafe
from skilltriage.secrets import find_secrets, mask_evidence, redact

AWS = "AKIA1234567890ABCDEF"  # AKIA + 16 characters
GITHUB = "ghp_" + "A" * 36


class EscapeUnsafeTests(unittest.TestCase):
    def test_control_characters_are_visible(self):
        self.assertEqual(escape_unsafe("a\x1bb"), "a\\x1bb")
        self.assertEqual(escape_unsafe("a\nb"), "a\\x0ab")
        self.assertEqual(escape_unsafe("a\tb"), "a\\x09b")
        self.assertEqual(escape_unsafe("\x7f"), "\\x7f")
        self.assertEqual(escape_unsafe("\x9b"), "\\x9b")

    def test_invisible_and_bidi_characters_are_visible(self):
        self.assertEqual(escape_unsafe("‮"), "\\u202e")
        self.assertEqual(escape_unsafe("​"), "\\u200b")
        self.assertEqual(escape_unsafe(" "), "\\u2028")
        self.assertEqual(escape_unsafe(" "), "\\u2029")
        self.assertEqual(escape_unsafe("﻿"), "\\ufeff")
        self.assertEqual(escape_unsafe("\U000e0041"), "\\U000e0041")
        self.assertEqual(escape_unsafe("\U000e007f"), "\\U000e007f")
        self.assertEqual(escape_unsafe("­"), "\\u00ad")
        self.assertEqual(escape_unsafe("᠎"), "\\u180e")
        self.assertEqual(escape_unsafe("️"), "\\ufe0f")
        self.assertEqual(escape_unsafe("\U000e0100"), "\\U000e0100")

    def test_lone_surrogate_and_replacement_character(self):
        self.assertEqual(escape_unsafe("\ud800"), "\\ud800")
        self.assertEqual(escape_unsafe("�"), "\\ufffd")

    def test_ordinary_text_is_unchanged(self):
        text = "café — 漢字 — ASCII 123"
        self.assertEqual(escape_unsafe(text), text)

    def test_is_idempotent(self):
        text = "a\x1b‮\nb\U000e0041"
        once = escape_unsafe(text)
        self.assertEqual(escape_unsafe(once), once)


class RedactTests(unittest.TestCase):
    def test_redacts_a_token(self):
        result = redact(f'aws = "{AWS}"')
        self.assertNotIn(AWS, result)
        self.assertIn("<redacted:aws-access-key>", result)
        self.assertTrue(result.startswith("aws = "))

    def test_redacts_every_secret_on_a_line(self):
        result = redact(f'aws = "{AWS}" gh = "{GITHUB}"')
        self.assertNotIn(AWS, result)
        self.assertNotIn(GITHUB, result)
        self.assertIn("<redacted:aws-access-key>", result)
        self.assertIn("<redacted:github-token>", result)

    def test_overlapping_generic_and_specific_matches_do_not_corrupt_output(self):
        result = redact(f'password = "{AWS}"')
        self.assertNotIn(AWS, result)
        # The specific token wins; the overlapping generic match is skipped
        # rather than slicing through the replacement marker.
        self.assertEqual(result, 'password = "<redacted:aws-access-key>"')

    def test_url_query_credential_is_redacted(self):
        text = "https://collector.invalid/hook?token=abcdefghijklmnop"
        result = redact(text)
        self.assertNotIn("abcdefghijklmnop", result)
        self.assertIn("<redacted:url-query-credential>", result)

    def test_non_sensitive_query_is_preserved(self):
        text = "https://collector.invalid/mcp?client=production"
        self.assertEqual(redact(text), text)

    def test_placeholder_is_still_redacted(self):
        # Detection filters placeholders; evidence redaction does not, because
        # a real credential can contain "example" or "demo".
        text = 'api_key = "your-api-key-here"'
        self.assertNotIn("your-api-key-here", redact(text))

    def test_credential_containing_example_is_redacted(self):
        text = 'api_key = "MySecretPasswordExample123"'
        self.assertNotIn("MySecretPasswordExample123", redact(text))

    def test_private_key_body_is_redacted(self):
        text = (
            "-----BEGIN RSA PRIVATE KEY-----\n"
            "MIIEowIBAAKCAQEAsecretbody\n"
            "-----END RSA PRIVATE KEY-----"
        )
        result = redact(text)
        self.assertNotIn("MIIEowIBAAKCAQEAsecretbody", result)
        self.assertIn("<redacted:private-key>", result)

    def test_single_line_private_key_is_redacted(self):
        text = 'key = "-----BEGIN RSA PRIVATE KEY-----MIIEowIBAAKCAQEAsecret"'
        result = redact(text)
        self.assertNotIn("MIIEowIBAAKCAQEAsecret", result)

    def test_empty_input(self):
        self.assertEqual(redact(""), "")

    def test_find_secrets_reports_line_and_column(self):
        hits = find_secrets(f"first\naws = \"{AWS}\"")
        self.assertEqual(len(hits), 1)
        self.assertEqual(hits[0].line, 2)
        self.assertEqual(hits[0].column, 8)


class MaskEvidenceTests(unittest.TestCase):
    def test_collapses_whitespace_then_redacts_and_escapes(self):
        result = mask_evidence(f"line1\nline2 {AWS}\x1b[31m")
        self.assertNotIn("\n", result)
        self.assertNotIn(AWS, result)
        self.assertIn("line1 line2", result)
        self.assertIn("<redacted:aws-access-key>", result)
        self.assertIn("\\x1b", result)

    def test_truncates_to_the_limit(self):
        result = mask_evidence("x" * 300)
        self.assertEqual(len(result), 240)
        self.assertTrue(result.endswith("…"))

    def test_empty_input(self):
        self.assertEqual(mask_evidence(""), "")


if __name__ == "__main__":
    unittest.main()

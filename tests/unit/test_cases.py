import json
import tempfile
import unittest
from pathlib import Path

from skilltriage.cases import describe, validate_cases


class CaseValidationTests(unittest.TestCase):
    def write(self, payload) -> Path:
        directory = tempfile.mkdtemp()
        path = Path(directory) / "cases.json"
        path.write_text(json.dumps(payload), encoding="utf-8")
        return path

    def test_valid_list(self):
        path = self.write([{"id": "a", "input": "do it", "expected": ["works"]}])
        cases, errors = validate_cases(path)
        self.assertEqual(errors, [])
        self.assertEqual(describe(cases)["cases"], 1)

    def test_valid_object(self):
        path = self.write({"cases": [{"id": "a", "input": "do it", "expected": ["works"]}]})
        _, errors = validate_cases(path)
        self.assertEqual(errors, [])

    def test_missing_fields(self):
        path = self.write([{"id": "a"}])
        _, errors = validate_cases(path)
        self.assertTrue(errors)

    def test_duplicate_ids(self):
        path = self.write(
            [
                {"id": "a", "input": "x", "expected": ["y"]},
                {"id": "a", "input": "x", "expected": ["y"]},
            ]
        )
        _, errors = validate_cases(path)
        self.assertTrue(any("duplicate" in error.lower() for error in errors))

    def test_bad_timeout(self):
        path = self.write([{"id": "a", "input": "x", "expected": ["y"], "timeout_seconds": -1}])
        _, errors = validate_cases(path)
        self.assertTrue(any("timeout" in error.lower() for error in errors))

    def test_invalid_json(self):
        directory = tempfile.mkdtemp()
        path = Path(directory) / "cases.json"
        path.write_text("{", encoding="utf-8")
        _, errors = validate_cases(path)
        self.assertTrue(errors)


if __name__ == "__main__":
    unittest.main()

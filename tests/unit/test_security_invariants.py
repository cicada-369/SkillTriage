"""Mechanical checks for the tool's non-execution and no-network invariants."""

import ast
import unittest
from pathlib import Path

SRC = Path(__file__).resolve().parents[2] / "src" / "skilltriage"

FORBIDDEN_IMPORTS = {
    "subprocess",
    "socket",
    "http.client",
    "ftplib",
    "smtplib",
    "telnetlib",
    "requests",
    "urllib.request",
}
FORBIDDEN_NAMES = {"eval", "exec", "compile", "__import__"}
FORBIDDEN_ATTRIBUTES = {
    ("os", "system"),
    ("os", "popen"),
    ("os", "execv"),
    ("os", "execve"),
    ("os", "spawnv"),
    ("os", "posix_spawn"),
}


def _source_trees():
    for path in sorted(SRC.rglob("*.py")):
        yield path, ast.parse(path.read_text(encoding="utf-8"), filename=str(path))


class SecurityInvariantTests(unittest.TestCase):
    def test_no_network_or_process_imports(self):
        for path, tree in _source_trees():
            for node in ast.walk(tree):
                if isinstance(node, ast.Import):
                    for alias in node.names:
                        self.assertNotIn(
                            alias.name,
                            FORBIDDEN_IMPORTS,
                            f"{path}:{node.lineno} imports {alias.name}",
                        )
                elif isinstance(node, ast.ImportFrom) and node.module:
                    self.assertNotIn(
                        node.module,
                        FORBIDDEN_IMPORTS,
                        f"{path}:{node.lineno} imports from {node.module}",
                    )
                    if node.module == "urllib":
                        for alias in node.names:
                            self.assertEqual(
                                alias.name,
                                "parse",
                                f"{path}:{node.lineno} imports urllib.{alias.name}",
                            )

    def test_no_dynamic_execution_calls(self):
        for path, tree in _source_trees():
            for node in ast.walk(tree):
                if not isinstance(node, ast.Call):
                    continue
                func = node.func
                if isinstance(func, ast.Name):
                    self.assertNotIn(
                        func.id,
                        FORBIDDEN_NAMES,
                        f"{path}:{node.lineno} calls {func.id}()",
                    )
                elif isinstance(func, ast.Attribute) and isinstance(func.value, ast.Name):
                    pair = (func.value.id, func.attr)
                    self.assertNotIn(
                        pair,
                        FORBIDDEN_ATTRIBUTES,
                        f"{path}:{node.lineno} calls {pair[0]}.{pair[1]}()",
                    )


if __name__ == "__main__":
    unittest.main()

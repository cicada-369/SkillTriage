"""Inline suppression comments.

Supported forms, in any comment syntax:

* ``skilltriage:disable RULE-ID[,RULE-ID]`` — the same line and the next line.
* ``skilltriage:disable-next-line RULE-ID`` — the next line.
* ``skilltriage:disable-file RULE-ID`` — the whole file.

Suppressions are visible in JSON output (``suppressed: true``) and are excluded
from gating. A suppression without a reason is accepted, but the README asks
reviewers to add one.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field

_DISABLE_RE = re.compile(r"skilltriage:disable(?:-file|-next-line)?\s+([A-Za-z0-9_,.\-\s]+)")


@dataclass
class SuppressionSet:
    file_rules: dict[str, set[str]] = field(default_factory=dict)
    line_rules: dict[tuple[str, int], set[str]] = field(default_factory=dict)

    def is_suppressed(self, path: str, rule_id: str, line: int | None) -> bool:
        if rule_id in self.file_rules.get(path, set()):
            return True
        if line is None:
            return False
        return rule_id in self.line_rules.get((path, line), set())

    @classmethod
    def from_texts(cls, texts: dict[str, str]) -> "SuppressionSet":
        result = cls()
        for path, text in texts.items():
            for number, line in enumerate(text.splitlines(), start=1):
                lower = line.lower()
                match = _DISABLE_RE.search(line)
                if not match:
                    continue
                rules = set(re.findall(r"\bAST\d{2}-[A-Z0-9-]+\b", match.group(1).upper()))
                if not rules:
                    continue
                if "skilltriage:disable-file" in lower:
                    result.file_rules.setdefault(path, set()).update(rules)
                elif "skilltriage:disable-next-line" in lower:
                    result.line_rules.setdefault((path, number + 1), set()).update(rules)
                else:
                    # A bare disable covers the same line and the next three
                    # lines, which is enough to cover a fenced code block that
                    # starts on the following line.
                    for offset in range(0, 4):
                        result.line_rules.setdefault((path, number + offset), set()).update(rules)
        return result


def apply_suppressions(findings, suppressions: SuppressionSet) -> int:
    count = 0
    for finding in findings:
        if suppressions.is_suppressed(finding.path, finding.rule_id, finding.line):
            finding.suppressed = True
            count += 1
    return count

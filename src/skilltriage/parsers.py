"""Safe parsers for skill metadata.

The tool deliberately does not depend on PyYAML at runtime. Skill frontmatter is
a small YAML subset, and a parser that cannot construct objects cannot be
tricked into ``!!python/object`` code execution. This module implements that
subset, records anything suspicious as a :class:`ParseIssue`, and never
evaluates a tag, anchor, or alias.

JSON uses the standard library with duplicate-key detection. TOML uses
``tomllib`` from the standard library.
"""

from __future__ import annotations

import json
import re
import tomllib
from dataclasses import dataclass
from typing import Any

from .models import ParseIssue, Severity

MAX_FRONTMATTER_LINES = 5000
MAX_DEPTH = 24
MAX_VALUE_LENGTH = 200_000

_NULLS = {"", "~", "null", "Null", "NULL"}
_TRUE = {"true", "True", "TRUE", "yes", "Yes", "YES", "on", "On", "ON"}
_FALSE = {"false", "False", "FALSE", "no", "No", "NO", "off", "Off", "OFF"}
_INT_RE = re.compile(r"[-+]?\d+")
_FLOAT_RE = re.compile(r"[-+]?(?:\d+\.\d*|\d*\.\d+|\d+[eE][-+]?\d+|\d+\.\d*[eE][-+]?\d+)")
_BLOCK_RE = re.compile(r"^[|>](?:[+-]?\d*|\d+[+-]?)$")
_UNSAFE_TAG_RE = re.compile(r"(^|\s)(!![A-Za-z0-9_/:-]+|!<[^>]+>)")
_ANCHOR_RE = re.compile(r"(^|\s)(&\S+|\*\S+)")


@dataclass(frozen=True)
class Frontmatter:
    found: bool
    meta_text: str
    body: str
    body_line: int
    issues: tuple[ParseIssue, ...] = ()

    @property
    def has_metadata(self) -> bool:
        return self.found and bool(self.meta_text.strip())


def strip_bom(text: str) -> str:
    return text[1:] if text.startswith("﻿") else text


def split_frontmatter(text: str) -> Frontmatter:
    """Split ``---`` delimited YAML frontmatter from a Markdown document.

    ``body_line`` is the 1-based line number where the body starts, so rules
    can report accurate locations.
    """
    text = strip_bom(text)
    lines = text.splitlines()
    if not lines or lines[0].strip() != "---":
        return Frontmatter(False, "", text, 1)

    issues: list[ParseIssue] = []
    closing = None
    for index in range(1, min(len(lines), MAX_FRONTMATTER_LINES + 1)):
        if lines[index].strip() in ("---", "..."):
            closing = index
            break
    if closing is None:
        if len(lines) > MAX_FRONTMATTER_LINES:
            code = "FRONTMATTER_TOO_LONG"
            message = (
                f"Frontmatter is not closed within {MAX_FRONTMATTER_LINES} lines."
            )
        else:
            code = "MISSING_CLOSING_FRONTMATTER"
            message = "YAML frontmatter is not closed with a '---' line."
        issues.append(ParseIssue(code, message, 1, Severity.HIGH))
        return Frontmatter(True, "\n".join(lines[1:]), "", len(lines) + 1, tuple(issues))
    meta_text = "\n".join(lines[1:closing])
    body = "\n".join(lines[closing + 1 :])
    return Frontmatter(True, meta_text, body, closing + 2, tuple(issues))


@dataclass
class _Line:
    line_no: int
    indent: int
    content: str
    raw_index: int


def _strip_comment(text: str) -> str:
    """Remove a YAML comment that is outside quotes.

    A ``#`` starts a comment only at the start of a line or after whitespace,
    so URLs with fragments survive.
    """
    quote: str | None = None
    escaped = False
    for index, char in enumerate(text):
        if quote:
            if quote == '"' and escaped:
                escaped = False
            elif quote == '"' and char == "\\":
                escaped = True
            elif char == quote:
                quote = None
            continue
        if char in ("'", '"'):
            quote = char
        elif char == "#" and (index == 0 or text[index - 1].isspace()):
            return text[:index].rstrip()
    return text


def _split_key(text: str) -> tuple[str | None, str]:
    """Split ``key: value`` at the first top-level colon followed by space/EOL."""
    quote: str | None = None
    escaped = False
    depth = 0
    for index, char in enumerate(text):
        if quote:
            if quote == '"' and escaped:
                escaped = False
            elif quote == '"' and char == "\\":
                escaped = True
            elif char == quote:
                quote = None
            continue
        if char in ("'", '"'):
            quote = char
        elif char in "[{":
            depth += 1
        elif char in "]}":
            depth = max(0, depth - 1)
        elif char == ":" and depth == 0:
            if index + 1 == len(text) or text[index + 1].isspace():
                key = text[:index].strip()
                if not key:
                    return None, ""
                if len(key) >= 2 and key[0] == key[-1] and key[0] in ("'", '"'):
                    key = _unquote(key)
                return key, text[index + 1 :].strip()
    return None, ""


def _unquote(text: str) -> str:
    text = text.strip()
    if len(text) >= 2 and text[0] == text[-1] == '"':
        return _decode_double_quoted(text[1:-1])
    if len(text) >= 2 and text[0] == text[-1] == "'":
        return text[1:-1].replace("''", "'")
    return text


def _decode_double_quoted(text: str) -> str:
    escapes = {
        "n": "\n",
        "t": "\t",
        "r": "\r",
        "0": "\0",
        '"': '"',
        "\\": "\\",
        "/": "/",
        "b": "\b",
        "f": "\f",
        "a": "\a",
        "v": "\v",
        "e": "\x1b",
        " ": " ",
        "N": "\u0085",
        "_": " ",
        "L": " ",
        "P": " ",
    }
    out: list[str] = []
    index = 0
    while index < len(text):
        char = text[index]
        if char != "\\":
            out.append(char)
            index += 1
            continue
        index += 1
        if index >= len(text):
            break
        code = text[index]
        if code in escapes:
            out.append(escapes[code])
            index += 1
        elif code in ("x", "u", "U"):
            width = {"x": 2, "u": 4, "U": 8}[code]
            chunk = text[index + 1 : index + 1 + width]
            try:
                point = int(chunk, 16)
            except ValueError:
                out.append("\\" + code + chunk)
            else:
                # A lone surrogate cannot be encoded to UTF-8 and would break
                # report output; keep it as the literal escape instead.
                if 0xD800 <= point <= 0xDFFF or point > 0x10FFFF:
                    out.append("\\" + code + chunk)
                else:
                    out.append(chr(point))
            index += 1 + width
        elif code == "\n":
            index += 1
        else:
            out.append(code)
            index += 1
    return "".join(out)


def _split_top_level(text: str, separator: str = ",") -> list[str]:
    parts: list[str] = []
    quote: str | None = None
    escaped = False
    depth = 0
    start = 0
    for index, char in enumerate(text):
        if quote:
            if quote == '"' and escaped:
                escaped = False
            elif quote == '"' and char == "\\":
                escaped = True
            elif char == quote:
                quote = None
            continue
        if char in ("'", '"'):
            quote = char
        elif char in "[{(":
            depth += 1
        elif char in "]})":
            depth = max(0, depth - 1)
        elif char == separator and depth == 0:
            parts.append(text[start:index])
            start = index + 1
    parts.append(text[start:])
    return parts


class _YamlSubset:
    def __init__(self, text: str) -> None:
        self.issues: list[ParseIssue] = []
        self.raw_lines = text.splitlines()
        self.lines: list[_Line] = []
        for raw_index, raw in enumerate(self.raw_lines):
            line_no = raw_index + 1
            leading = raw[: len(raw) - len(raw.lstrip(" \t"))]
            if "\t" in leading:
                self.issues.append(
                    ParseIssue(
                        "TAB_INDENT",
                        "Tab used for indentation; YAML requires spaces.",
                        line_no,
                        Severity.LOW,
                    )
                )
                raw = leading.replace("\t", "  ") + raw[len(leading) :]
            stripped = raw.lstrip(" ")
            if not stripped.strip() or stripped.startswith("#"):
                continue
            content = _strip_comment(stripped)
            if not content.strip():
                continue
            indent = len(raw) - len(stripped)
            self.lines.append(_Line(line_no, indent, content.rstrip(), raw_index))
        self.pos = 0

    def parse(self) -> dict[str, Any]:
        if not self.lines:
            return {}
        base_indent = self.lines[0].indent
        value, _ = self._block(base_indent, 0)
        if self.pos < len(self.lines):
            line = self.lines[self.pos]
            self.issues.append(
                ParseIssue(
                    "TRAILING_CONTENT",
                    "Line could not be attached to the document structure.",
                    line.line_no,
                    Severity.MEDIUM,
                )
            )
        if not isinstance(value, dict):
            self.issues.append(
                ParseIssue(
                    "TOP_LEVEL_NOT_MAPPING",
                    "Frontmatter must be a mapping of keys to values.",
                    1,
                    Severity.HIGH,
                )
            )
            return {}
        return value

    def _peek(self) -> _Line | None:
        return self.lines[self.pos] if self.pos < len(self.lines) else None

    def _block(self, indent: int, depth: int) -> tuple[Any, int]:
        if depth > MAX_DEPTH:
            line = self._peek()
            if line:
                self.issues.append(
                    ParseIssue(
                        "TOO_DEEP",
                        f"Metadata nesting exceeds {MAX_DEPTH} levels.",
                        line.line_no,
                        Severity.HIGH,
                    )
                )
            return None, self.pos
        line = self._peek()
        if line is None:
            return None, self.pos
        if line.content.startswith("-") and (len(line.content) == 1 or line.content[1].isspace()):
            return self._sequence(indent, depth)
        if line.content[0] in "\"'":
            return self._scalar_block(indent, quoted=True)
        if line.content[0] in "[{":
            return self._scalar_block(indent, quoted=False)
        if _split_key(line.content)[0] is None:
            # A block scalar that begins on the line after the key, e.g.
            #   description:
            #     plain text continues here
            return self._scalar_block(indent, quoted=False)
        return self._mapping(indent, depth)

    def _scalar_block(self, indent: int, *, quoted: bool) -> tuple[Any, int]:
        """Consume an indented scalar block (quoted or plain/flow)."""
        parts: list[str] = []
        while self.pos < len(self.lines):
            line = self.lines[self.pos]
            if line.indent < indent:
                break
            parts.append(line.content.strip())
            self.pos += 1
        joined = " ".join(part for part in parts if part)
        if quoted:
            return self._scalar(joined)[0], self.pos
        return self._scalar(joined)[0] if joined else None, self.pos

    def _mapping(
        self,
        indent: int,
        depth: int,
        first_content: str | None = None,
        first_line: _Line | None = None,
    ) -> tuple[dict[str, Any], int]:
        result: dict[str, Any] = {}
        if first_content is not None and first_line is not None:
            self._consume_pair(result, indent, first_content, first_line, depth)
        while self.pos < len(self.lines):
            line = self.lines[self.pos]
            if line.indent < indent:
                break
            if line.indent > indent:
                self.issues.append(
                    ParseIssue(
                        "BAD_INDENT",
                        "Unexpected indentation; line skipped.",
                        line.line_no,
                        Severity.MEDIUM,
                    )
                )
                self.pos += 1
                continue
            if line.content.startswith("-") and (
                len(line.content) == 1 or line.content[1].isspace()
            ):
                break
            key, rest = _split_key(line.content)
            if key is None:
                self.issues.append(
                    ParseIssue(
                        "BAD_LINE",
                        "Expected a 'key: value' mapping entry.",
                        line.line_no,
                        Severity.MEDIUM,
                    )
                )
                self.pos += 1
                continue
            self.pos += 1
            if key in result:
                self.issues.append(
                    ParseIssue(
                        "DUPLICATE_KEY",
                        f"Duplicate metadata key: {key!r}.",
                        line.line_no,
                        Severity.HIGH,
                    )
                )
            result[key] = self._value_after_key(indent, rest, line, depth)
        return result, self.pos

    def _consume_pair(
        self,
        result: dict[str, Any],
        indent: int,
        content: str,
        line: _Line,
        depth: int,
    ) -> None:
        key, rest = _split_key(content)
        if key is None:
            self.issues.append(
                ParseIssue(
                    "BAD_LINE",
                    "Expected a 'key: value' mapping entry.",
                    line.line_no,
                    Severity.MEDIUM,
                )
            )
            return
        if key in result:
            self.issues.append(
                ParseIssue(
                    "DUPLICATE_KEY",
                    f"Duplicate metadata key: {key!r}.",
                    line.line_no,
                    Severity.HIGH,
                )
            )
        result[key] = self._value_after_key(indent, rest, line, depth)

    def _value_after_key(self, indent: int, rest: str, line: _Line, depth: int) -> Any:
        if not rest:
            nxt = self._peek()
            if nxt is None:
                return None
            if nxt.indent > indent:
                value, _ = self._block(nxt.indent, depth + 1)
                return value
            if nxt.indent == indent and (
                nxt.content.startswith("-")
                and (len(nxt.content) == 1 or nxt.content[1].isspace())
            ):
                value, _ = self._sequence(indent, depth + 1)
                return value
            return None
        if _BLOCK_RE.match(rest):
            return self._block_scalar(indent, rest, line)
        value, kind = self._scalar(rest)
        if kind != "plain" or not isinstance(value, str):
            return value
        # YAML folds a plain scalar's more-indented continuation lines with spaces.
        parts = [value]
        while self.pos < len(self.lines):
            nxt = self.lines[self.pos]
            if nxt.indent <= indent:
                break
            if nxt.content.startswith("-") and (
                len(nxt.content) == 1 or nxt.content[1].isspace()
            ):
                break
            if _split_key(nxt.content)[0] is not None:
                break
            parts.append(nxt.content.strip())
            self.pos += 1
        return " ".join(part for part in parts if part)

    def _sequence(self, indent: int, depth: int) -> tuple[list[Any], int]:
        items: list[Any] = []
        while self.pos < len(self.lines):
            line = self.lines[self.pos]
            if line.indent != indent:
                break
            if not (
                line.content.startswith("-")
                and (len(line.content) == 1 or line.content[1].isspace())
            ):
                break
            item_text = line.content[1:].lstrip()
            self.pos += 1
            if not item_text:
                nxt = self._peek()
                if nxt is not None and nxt.indent > indent:
                    value, _ = self._block(nxt.indent, depth + 1)
                else:
                    value = None
                items.append(value)
                continue
            key, _ = _split_key(item_text)
            if key is not None and not item_text.startswith(("'", '"', "[", "{")):
                map_indent = indent + 2
                nxt = self._peek()
                if nxt is not None and indent < nxt.indent < map_indent:
                    map_indent = nxt.indent
                value, _ = self._mapping(map_indent, depth + 1, item_text, line)
                items.append(value)
                continue
            value, kind = self._scalar(item_text)
            if kind == "plain" and isinstance(value, str):
                parts = [value]
                while self.pos < len(self.lines):
                    nxt = self.lines[self.pos]
                    if nxt.indent <= indent:
                        break
                    if nxt.content.startswith("-") and (
                        len(nxt.content) == 1 or nxt.content[1].isspace()
                    ):
                        break
                    if _split_key(nxt.content)[0] is not None:
                        break
                    parts.append(nxt.content.strip())
                    self.pos += 1
                value = " ".join(part for part in parts if part)
            items.append(value)
        return items, self.pos

    def _scalar(self, text: str, depth: int = 0) -> tuple[Any, str]:
        if depth > MAX_DEPTH:
            self.issues.append(
                ParseIssue(
                    "TOO_DEEP",
                    f"Metadata nesting exceeds {MAX_DEPTH} levels.",
                    None,
                    Severity.HIGH,
                )
            )
            return text, "plain"
        value = text.strip()
        if not value:
            return None, "null"
        if value[0] == '"':
            if len(value) < 2 or value[-1] != '"':
                self.issues.append(
                    ParseIssue("UNCLOSED_QUOTE", "Unclosed double-quoted value.", None, Severity.MEDIUM)
                )
                return value[1:], "quoted"
            return _decode_double_quoted(value[1:-1]), "quoted"
        if value[0] == "'":
            if len(value) < 2 or value[-1] != "'":
                self.issues.append(
                    ParseIssue("UNCLOSED_QUOTE", "Unclosed single-quoted value.", None, Severity.MEDIUM)
                )
                return value[1:], "quoted"
            return value[1:-1].replace("''", "'"), "quoted"
        if value[0] in "[{":
            return self._flow(value, depth + 1), "flow"
        if _UNSAFE_TAG_RE.match(value):
            self.issues.append(
                ParseIssue(
                    "UNSAFE_YAML_TAG",
                    f"Unsafe YAML tag detected: {value.split()[0]!r}. It was not resolved.",
                    None,
                    Severity.CRITICAL,
                )
            )
            return value, "tag"
        if _ANCHOR_RE.match(value):
            self.issues.append(
                ParseIssue(
                    "YAML_ANCHOR_ALIAS",
                    f"YAML anchor or alias detected: {value.split()[0]!r}. It was not resolved.",
                    None,
                    Severity.MEDIUM,
                )
            )
            return value, "anchor"
        if value in _NULLS:
            return None, "null"
        if value in _TRUE:
            return True, "bool"
        if value in _FALSE:
            return False, "bool"
        if _INT_RE.fullmatch(value):
            try:
                return int(value), "number"
            except ValueError:
                pass
        if _FLOAT_RE.fullmatch(value):
            try:
                return float(value), "number"
            except ValueError:
                pass
        if len(value) > MAX_VALUE_LENGTH:
            self.issues.append(
                ParseIssue(
                    "OVERSIZED_VALUE",
                    f"Metadata value exceeds {MAX_VALUE_LENGTH} characters.",
                    None,
                    Severity.MEDIUM,
                )
            )
        return value, "plain"

    def _flow(self, text: str, depth: int = 0) -> Any:
        text = text.strip()
        if text.startswith("["):
            if not text.endswith("]"):
                self.issues.append(
                    ParseIssue("UNCLOSED_FLOW", "Unclosed flow sequence.", None, Severity.MEDIUM)
                )
                text = text[1:]
            else:
                text = text[1:-1]
            return [
                self._scalar(part, depth + 1)[0]
                for part in _split_top_level(text)
                if part.strip()
            ]
        if text.startswith("{"):
            if not text.endswith("}"):
                self.issues.append(
                    ParseIssue("UNCLOSED_FLOW", "Unclosed flow mapping.", None, Severity.MEDIUM)
                )
                text = text[1:]
            else:
                text = text[1:-1]
            result: dict[str, Any] = {}
            for part in _split_top_level(text):
                if not part.strip():
                    continue
                key_text, value_text = self._split_flow_pair(part)
                key = _unquote(key_text.strip())
                if key in result:
                    self.issues.append(
                        ParseIssue(
                            "DUPLICATE_KEY",
                            f"Duplicate metadata key: {key!r}.",
                            None,
                            Severity.HIGH,
                        )
                    )
                result[key] = (
                    self._scalar(value_text, depth + 1)[0]
                    if value_text.strip()
                    else None
                )
            return result
        return self._scalar(text, depth + 1)[0]

    @staticmethod
    def _split_flow_pair(text: str) -> tuple[str, str]:
        quote: str | None = None
        escaped = False
        depth = 0
        for index, char in enumerate(text):
            if quote:
                if quote == '"' and escaped:
                    escaped = False
                elif quote == '"' and char == "\\":
                    escaped = True
                elif char == quote:
                    quote = None
                continue
            if char in ("'", '"'):
                quote = char
            elif char in "[{":
                depth += 1
            elif char in "]}":
                depth = max(0, depth - 1)
            elif char == ":" and depth == 0:
                return text[:index], text[index + 1 :]
        return text, ""

    def _block_scalar(self, parent_indent: int, indicator: str, start: _Line) -> str:
        style = indicator[0]
        chomp = "-" if "-" in indicator else ("+" if "+" in indicator else "")
        raw_index = start.raw_index + 1
        content_indent: int | None = None
        scan = raw_index
        while scan < len(self.raw_lines):
            raw = self.raw_lines[scan]
            if raw.strip():
                indent = len(raw) - len(raw.lstrip(" "))
                if indent <= parent_indent:
                    break
                content_indent = indent if content_indent is None else min(content_indent, indent)
            scan += 1

        collected: list[str] = []
        last_line_no = start.line_no
        scan = raw_index
        while scan < len(self.raw_lines):
            raw = self.raw_lines[scan]
            if raw.strip():
                indent = len(raw) - len(raw.lstrip(" "))
                if indent <= parent_indent:
                    break
                collected.append(raw[content_indent or 0 :])
                last_line_no = scan + 1
            else:
                collected.append("")
                last_line_no = scan + 1
            scan += 1

        while self.pos < len(self.lines) and self.lines[self.pos].line_no <= last_line_no:
            self.pos += 1

        if style == "|":
            value = "\n".join(collected)
        else:
            paragraphs: list[str] = []
            current: list[str] = []
            for line in collected:
                if line.strip():
                    current.append(line.strip())
                else:
                    if current:
                        paragraphs.append(" ".join(current))
                        current = []
                    paragraphs.append("")
            if current:
                paragraphs.append(" ".join(current))
            value = "\n".join(paragraphs)

        if chomp == "-":
            return value.rstrip("\n")
        if chomp == "+":
            return value
        return value.rstrip("\n") + ("\n" if value.strip() else "")


def parse_yaml_subset(text: str) -> tuple[dict[str, Any], list[ParseIssue]]:
    """Parse the YAML subset used by skill metadata. Never resolves tags."""
    parser = _YamlSubset(text)
    try:
        data = parser.parse()
    except RecursionError:
        return {}, [
            ParseIssue("TOO_DEEP", "Metadata nesting exceeds the safe limit.", None, Severity.HIGH)
        ]
    except MemoryError:
        return {}, [
            ParseIssue(
                "OVERSIZED_VALUE",
                "Metadata is too large to parse safely.",
                None,
                Severity.HIGH,
            )
        ]
    return data, parser.issues


def parse_json_text(text: str) -> tuple[dict[str, Any], list[ParseIssue]]:
    """Parse a JSON manifest and report duplicate keys."""
    issues: list[ParseIssue] = []
    duplicates: list[str] = []

    def hook(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for key, value in pairs:
            if key in result:
                duplicates.append(key)
            result[key] = value
        return result

    try:
        data = json.loads(text, object_pairs_hook=hook)
    except (RecursionError, MemoryError):
        issues.append(
            ParseIssue(
                "TOO_DEEP",
                "JSON nesting or size exceeds the safe limit.",
                None,
                Severity.HIGH,
            )
        )
        return {}, issues
    except json.JSONDecodeError as exc:
        issues.append(
            ParseIssue(
                "INVALID_JSON",
                f"Invalid JSON at line {exc.lineno}: {exc.msg}.",
                exc.lineno,
                Severity.HIGH,
            )
        )
        return {}, issues
    except ValueError as exc:
        issues.append(
            ParseIssue(
                "INVALID_JSON",
                f"Invalid or oversized JSON value: {exc}.",
                None,
                Severity.HIGH,
            )
        )
        return {}, issues
    for key in sorted(set(duplicates)):
        issues.append(
            ParseIssue(
                "DUPLICATE_KEY",
                f"Duplicate JSON key: {key!r}.",
                None,
                Severity.HIGH,
            )
        )
    if not isinstance(data, dict):
        issues.append(
            ParseIssue(
                "TOP_LEVEL_NOT_MAPPING",
                "Manifest must be a JSON object.",
                1,
                Severity.HIGH,
            )
        )
        return {}, issues
    return data, issues


def parse_toml_text(text: str) -> tuple[dict[str, Any], list[ParseIssue]]:
    try:
        data = tomllib.loads(text)
    except (RecursionError, MemoryError):
        return {}, [
            ParseIssue("TOO_DEEP", "TOML nesting or size exceeds the safe limit.", None, Severity.HIGH)
        ]
    except tomllib.TOMLDecodeError as exc:
        return {}, [ParseIssue("INVALID_TOML", f"Invalid TOML: {exc}.", None, Severity.HIGH)]
    except ValueError as exc:
        return {}, [
            ParseIssue(
                "INVALID_TOML",
                f"Invalid or oversized TOML value: {exc}.",
                None,
                Severity.HIGH,
            )
        ]
    return data, []


def find_unsafe_tags(text: str) -> list[tuple[int, str]]:
    """Return line numbers and tags for ``!!``/``!<...>`` constructs."""
    found: list[tuple[int, str]] = []
    for number, line in enumerate(text.splitlines(), start=1):
        stripped = _strip_comment(line)
        match = _UNSAFE_TAG_RE.search(stripped)
        if match:
            found.append((number, match.group(2)))
    return found


def find_anchors(text: str) -> list[tuple[int, str]]:
    found: list[tuple[int, str]] = []
    for number, line in enumerate(text.splitlines(), start=1):
        stripped = _strip_comment(line)
        match = _ANCHOR_RE.search(stripped)
        if match:
            found.append((number, match.group(2)))
    return found

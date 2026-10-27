"""Report rendering."""

from __future__ import annotations

from pathlib import Path

from ..atomic import write_private
from ..policy import AuditOptions
from . import html as html_report, json_report, markdown, sarif, text

FORMATS = ("text", "json", "markdown", "sarif", "html")

SUFFIX_FORMATS = {
    ".html": "html",
    ".htm": "html",
    ".json": "json",
    ".md": "markdown",
    ".markdown": "markdown",
    ".sarif": "sarif",
    ".txt": "text",
}


def infer_format(output: str | Path) -> str | None:
    """Return the report format implied by an output suffix, if any."""
    return SUFFIX_FORMATS.get(Path(output).suffix.lower())


def render(report, fmt: str, options: AuditOptions) -> str:
    if fmt == "json":
        return json_report.render(report)
    if fmt == "markdown":
        return markdown.render(report, options)
    if fmt == "sarif":
        return sarif.render(report)
    if fmt == "html":
        return html_report.render(report, options)
    if fmt == "text":
        return text.render(report, options, verbose=options.verbose)
    raise ValueError(f"unknown report format: {fmt}")


def write(output: str | Path, content: str) -> None:
    """Write a report atomically with owner-only permissions."""
    write_private(output, content)


__all__ = ["FORMATS", "SUFFIX_FORMATS", "infer_format", "render", "write"]

from __future__ import annotations
import argparse
import json
from pathlib import Path
from .audit import audit_skill, render_markdown
from .cases import validate_cases

def main():
    parser = argparse.ArgumentParser(
        prog="skilltester",
        description="Locally audit agent/copilot skill packages and validate behavior-test case files.")
    sub = parser.add_subparsers(dest="command", required=True)

    audit = sub.add_parser("audit", help="Inspect a skill directory without executing it.")
    audit.add_argument("path", help="Directory containing SKILL.md")
    audit.add_argument("--format", choices=("text", "json", "markdown"), default="text")
    audit.add_argument("--output", help="Write report to this file instead of stdout")

    cases = sub.add_parser("validate-cases", help="Validate a JSON behavior-test suite.")
    cases.add_argument("path", help="Path to test cases JSON")

    args = parser.parse_args()
    if args.command == "audit":
        result = audit_skill(args.path)
        if args.format == "json":
            output = json.dumps(result.to_dict(), indent=2)
        elif args.format == "markdown":
            output = render_markdown(result)
        else:
            data = result.to_dict()
            output = f"{'PASS' if result.passed else 'FAIL'} — {data['files_checked']} file(s) checked\n"
            for f in result.findings:
                loc = f"{f['path']}:{f['line']}" if f['line'] else f["path"]
                output += f"[{f['severity']}] {f['code']} {loc}: {f['message']}\n  Why: {f['rationale']}\n"
        if args.output:
            Path(args.output).write_text(output, encoding="utf-8")
        else:
            print(output, end="" if output.endswith("\n") else "\n")
        raise SystemExit(0 if result.passed else 1)

    _, errors = validate_cases(args.path)
    if errors:
        print("FAIL — behavior-test case file is invalid")
        for error in errors:
            print(f"- {error}")
        raise SystemExit(1)
    print("PASS — test-case file structure is valid. Cases were NOT executed against an agent.")

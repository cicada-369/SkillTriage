"""Command-line interface."""

from __future__ import annotations

import argparse
import json
import sys
import webbrowser
from pathlib import Path

from . import __version__
from .analysis import audit_paths, scan_discovered, sync_inventory
from .baseline import Baseline, BaselineError
from .cases import describe as describe_cases, validate_cases
from .discovery import DEFAULT_ROOTS, discover
from .intent import INTENT_VALUES
from .inventory import Inventory, InventoryError, default_inventory_path
from .models import AST_NAMES, Confidence, Severity
from .policy import (
    AuditOptions,
    ConfigError,
    PROFILE_DEFAULTS,
    apply_config,
    apply_profile,
    load_config,
)
from .report import FORMATS, infer_format, render, write
from .rules import all_rules, describe_rules, get_rule
from .safety import escape_unsafe


def _add_config(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--config", metavar="FILE", help="TOML config file")
    parser.add_argument("--no-config", action="store_true", help="ignore config files")


def _add_policy(parser: argparse.ArgumentParser) -> None:
    _add_config(parser)
    parser.add_argument("--profile", choices=sorted(PROFILE_DEFAULTS), help="policy profile")
    parser.add_argument(
        "--fail-on",
        choices=("none", "critical", "high", "medium", "low", "info"),
        help="minimum severity that fails the scan (default: high)",
    )
    parser.add_argument(
        "--min-confidence",
        choices=("high", "medium", "low"),
        help="minimum confidence that can fail the scan (default: high)",
    )
    parser.add_argument(
        "--allow-intent",
        action="append",
        default=[],
        choices=INTENT_VALUES,
        metavar="INTENT",
        help="allow a declared intent to downgrade technique findings "
        "(also requires an inventory record)",
    )
    parser.add_argument(
        "--trust-inline-suppressions",
        action="store_true",
        help="honour skilltriage:disable comments inside the audited artifact "
        "(off by default; use baselines instead)",
    )


def _add_limits(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--include-vendor", action="store_true", help="scan vendor/node_modules directories")
    parser.add_argument("--max-file-bytes", type=int, help="per-file content inspection limit")
    parser.add_argument("--max-total-bytes", type=int, help="total read budget")
    parser.add_argument("--max-files", type=int, help="maximum files to inspect")
    parser.add_argument("--max-archive-bytes", type=int, help="maximum archive file size")


def _add_report(parser: argparse.ArgumentParser) -> None:
    parser.add_argument(
        "--format",
        choices=FORMATS,
        default=None,
        help="report format (inferred from the --output suffix when omitted)",
    )
    parser.add_argument("-o", "--output", metavar="FILE", help="write the report to a file")
    parser.add_argument("--no-color", action="store_true", help="disable ANSI colour")
    parser.add_argument("--verbose", action="store_true", help="show full findings for every target")
    parser.add_argument("--show-suppressed", action="store_true", help="include inline-suppressed findings")
    parser.add_argument("--show-baselined", action="store_true", help="include baselined findings")


def _add_inventory_and_baseline(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--inventory", action="store_true", help="enable inventory comparison")
    parser.add_argument("--inventory-file", metavar="FILE", help="inventory JSON path")
    parser.add_argument("--require-inventory", action="store_true", help="flag skills with no inventory record")
    parser.add_argument("--baseline", metavar="FILE", help="baseline of accepted findings")
    parser.add_argument("--write-baseline", metavar="FILE", help="write current findings to a baseline")
    parser.add_argument("--update-inventory", action="store_true", help="update inventory after the scan")


def _add_discovery(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--root", action="append", default=[], metavar="DIR", help="extra discovery root")
    parser.add_argument("--project", action="append", default=[], metavar="DIR", help="project directory to include")
    parser.add_argument("--no-marketplaces", action="store_true", help="skip marketplace roots")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="skilltriage",
        description="Static security audit and risk triage for agentic skills and plugins, mapped to the OWASP Agentic Skills Top 10.",
    )
    parser.add_argument("--version", action="version", version=f"skilltriage {__version__}")
    sub = parser.add_subparsers(dest="command", required=True)

    audit = sub.add_parser("audit", help="audit skill package directories or archives")
    audit.add_argument("paths", nargs="+", metavar="PATH")
    _add_report(audit)
    _add_policy(audit)
    _add_limits(audit)
    _add_inventory_and_baseline(audit)
    audit.add_argument("--open", action="store_true", help="open the HTML report in a browser")

    scan_system = sub.add_parser("scan-system", help="discover and audit installed skills")
    _add_discovery(scan_system)
    _add_report(scan_system)
    _add_policy(scan_system)
    _add_limits(scan_system)
    _add_inventory_and_baseline(scan_system)

    scan = sub.add_parser("scan", help="scan a path, or the default install locations")
    scan.add_argument(
        "paths",
        nargs="*",
        metavar="PATH",
        help="skill, plugin, or archive; omit to scan installed locations",
    )
    _add_discovery(scan)
    _add_report(scan)
    _add_policy(scan)
    _add_limits(scan)
    _add_inventory_and_baseline(scan)
    scan.add_argument(
        "--artifacts",
        choices=("skills", "plugins", "both"),
        default="both",
        help="artifact kinds to discover when no path is given (default: both)",
    )
    scan.add_argument("--open", action="store_true", help="open the HTML report in a browser")

    discovery = sub.add_parser("discover", help="list skills found in known install locations")
    _add_discovery(discovery)
    _add_config(discovery)
    discovery.add_argument(
        "--artifacts",
        choices=("skills", "plugins", "both"),
        default="skills",
        help="which artifact kinds to list",
    )
    discovery.add_argument("--json", action="store_true", help="machine-readable output")

    inventory = sub.add_parser("inventory", help="manage the local skill inventory")
    inventory_sub = inventory.add_subparsers(dest="inventory_command", required=True)

    inventory_path = inventory_sub.add_parser("path", help="print the default inventory path")
    inventory_path.add_argument("--db", metavar="FILE")

    inventory_list = inventory_sub.add_parser("list", help="list inventory records")
    inventory_list.add_argument("--db", metavar="FILE")
    inventory_list.add_argument("--format", choices=("text", "json"), default="text")

    for name, text in (("sync", "scan and update the inventory"), ("diff", "compare installed skills to the inventory")):
        command = inventory_sub.add_parser(name, help=text)
        _add_discovery(command)
        _add_config(command)
        _add_limits(command)
        command.add_argument("--db", metavar="FILE")
        command.add_argument("--format", choices=("text", "json"), default="text")

    rules = sub.add_parser("rules", help="list or explain rules")
    rules.add_argument("rules_command", choices=("list", "explain"))
    rules.add_argument("rule_id", nargs="?")
    rules.add_argument("--format", choices=("text", "json"), default="text")
    rules.add_argument("--ast", choices=sorted(AST_NAMES))

    cases = sub.add_parser("validate-cases", help="validate a behaviour-test case file")
    cases.add_argument("path")
    cases.add_argument("--format", choices=("text", "json"), default="text")

    return parser


def _build_options(args) -> AuditOptions:
    config = load_config(getattr(args, "config", None), getattr(args, "no_config", False))
    options = AuditOptions()
    apply_config(options, config)
    profile = getattr(args, "profile", None)
    if profile:
        apply_profile(options, profile)
    allowed_intents = list(options.allowed_intents)
    for value in getattr(args, "allow_intent", []) or []:
        if value not in allowed_intents:
            allowed_intents.append(value)
    options.allowed_intents = allowed_intents
    fail_on = getattr(args, "fail_on", None)
    if fail_on is not None:
        options.fail_on = None if fail_on == "none" else Severity.parse(fail_on)
    min_confidence = getattr(args, "min_confidence", None)
    if min_confidence:
        options.min_confidence = Confidence.parse(min_confidence)
    if getattr(args, "include_vendor", False):
        options.include_vendor = True
    for key in ("max_file_bytes", "max_total_bytes", "max_files", "max_archive_bytes"):
        value = getattr(args, key, None)
        if value is not None:
            setattr(options, key, value)
    for key in (
        "show_suppressed",
        "show_baselined",
        "verbose",
        "trust_inline_suppressions",
    ):
        if getattr(args, key, False):
            setattr(options, key, True)
    if getattr(args, "no_color", False):
        options.color = False
    if getattr(args, "inventory_file", None):
        options.inventory_path = args.inventory_file
        options.inventory_enabled = True
    if getattr(args, "inventory", False):
        options.inventory_enabled = True
    if getattr(args, "require_inventory", False):
        options.inventory_enabled = True
        options.require_inventory = True
    if getattr(args, "update_inventory", False):
        options.inventory_enabled = True
        options.update_inventory = True
    if getattr(args, "baseline", None):
        options.baseline_path = args.baseline
    if getattr(args, "write_baseline", None):
        options.write_baseline = args.write_baseline
    return options


def _load_inventory(options: AuditOptions) -> Inventory | None:
    if not (options.inventory_enabled or options.update_inventory):
        return None
    return Inventory.load(options.inventory_path)


def _load_baseline(options: AuditOptions) -> Baseline | None:
    return Baseline.load(options.baseline_path) if options.baseline_path else None


def _discovery_arguments(args, options: AuditOptions) -> tuple[list[str], list[str], bool]:
    roots = list(getattr(args, "root", []) or []) + list(options.discovery_roots)
    projects = list(getattr(args, "project", []) or [])
    include_marketplaces = options.include_marketplaces and not getattr(args, "no_marketplaces", False)
    return roots, projects, include_marketplaces


def _emit_report(report, args, options: AuditOptions) -> None:
    options.color = bool(options.color) and not args.output and sys.stdout.isatty()
    content = render(report, args.format, options)
    if args.output:
        write(args.output, content)
        print(
            f"wrote {args.format} report to {escape_unsafe(str(args.output))}",
            file=sys.stderr,
        )
    else:
        sys.stdout.write(content)


def _print_scan_errors(report) -> None:
    for error in report.errors:
        print(f"skilltriage: scan error: {escape_unsafe(error)}", file=sys.stderr)


def _post_actions(report, options: AuditOptions, inventory: Inventory | None) -> None:
    if options.write_baseline:
        Baseline().write(options.write_baseline, report.results)
        print(
            f"wrote baseline to {escape_unsafe(str(options.write_baseline))}",
            file=sys.stderr,
        )
    if options.update_inventory and inventory is not None:
        summary = sync_inventory(report.results, inventory)
        print(
            f"inventory updated: {summary['added']} added, {summary['changed']} changed, "
            f"{summary['unchanged']} unchanged ({inventory.path})",
            file=sys.stderr,
        )


def _exit_code(report) -> int:
    if any(result.gating_count for result in report.results):
        return 1
    if report.errors:
        return 2
    return 0


def _resolve_format(args) -> str | None:
    """Return the report format, inferring it from the output suffix."""
    if args.format:
        return args.format
    if args.output:
        return infer_format(args.output)
    return "text"


def _require_open_target(args) -> bool:
    if not args.open:
        return True
    if args.output and args.format == "html":
        return True
    print(
        "skilltriage: --open requires an HTML report; use -o report.html "
        "or --format html -o FILE",
        file=sys.stderr,
    )
    return False


def _open_report(output) -> None:
    path = Path(output).expanduser().resolve()
    if not path.is_file():
        print(
            f"skilltriage: cannot open missing report: {escape_unsafe(str(path))}",
            file=sys.stderr,
        )
        return
    try:
        webbrowser.open(path.as_uri())
    except Exception as exc:  # a browser failure must not change the scan result
        print(
            f"skilltriage: could not open report: {escape_unsafe(str(exc))}",
            file=sys.stderr,
        )


def _print_first_run_guidance(roots, projects) -> None:
    print("skilltriage: no skills or plugins found", file=sys.stderr)
    print("", file=sys.stderr)
    checked = (
        [("custom", Path(value).expanduser()) for value in roots]
        if roots
        else [(kind, Path(value).expanduser()) for kind, value in DEFAULT_ROOTS]
    )
    print("Directories checked:", file=sys.stderr)
    for kind, path in checked:
        state = "found" if path.is_dir() else "missing"
        print(f"  [{kind}] {escape_unsafe(str(path))} ({state})", file=sys.stderr)
    for project in projects:
        print(
            f"  [project] {escape_unsafe(str(Path(project).expanduser()))}",
            file=sys.stderr,
        )
    print("", file=sys.stderr)
    print("Try:", file=sys.stderr)
    print("  skilltriage scan ~/path/to/skill", file=sys.stderr)
    print("  skilltriage scan -o report.html --open", file=sys.stderr)


def cmd_audit(args) -> int:
    if not _require_open_target(args):
        return 2
    options = _build_options(args)
    inventory = _load_inventory(options)
    baseline = _load_baseline(options)
    report = audit_paths(args.paths, options, inventory=inventory, baseline=baseline)
    _emit_report(report, args, options)
    _print_scan_errors(report)
    _post_actions(report, options, inventory)
    if args.open:
        _open_report(args.output)
    return _exit_code(report)


def cmd_scan_system(args) -> int:
    options = _build_options(args)
    inventory = _load_inventory(options)
    baseline = _load_baseline(options)
    roots, projects, include_marketplaces = _discovery_arguments(args, options)
    discovered = discover(roots=roots, projects=projects, include_marketplaces=include_marketplaces)
    if not discovered:
        print("skilltriage: no skills found in the selected roots", file=sys.stderr)
        return 2
    report = scan_discovered(discovered, options, inventory=inventory, baseline=baseline)
    _emit_report(report, args, options)
    _print_scan_errors(report)
    _post_actions(report, options, inventory)
    return _exit_code(report)


def cmd_scan(args) -> int:
    if not _require_open_target(args):
        return 2
    options = _build_options(args)
    inventory = _load_inventory(options)
    baseline = _load_baseline(options)
    if args.paths:
        report = audit_paths(args.paths, options, inventory=inventory, baseline=baseline)
    else:
        roots, projects, include_marketplaces = _discovery_arguments(args, options)
        discovered = discover(
            roots=roots,
            projects=projects,
            include_marketplaces=include_marketplaces,
            artifacts=args.artifacts,
        )
        if not discovered:
            _print_first_run_guidance(roots, projects)
            return 2
        report = scan_discovered(
            discovered, options, inventory=inventory, baseline=baseline
        )
    _emit_report(report, args, options)
    _print_scan_errors(report)
    _post_actions(report, options, inventory)
    if args.open:
        _open_report(args.output)
    return _exit_code(report)


def cmd_discover(args) -> int:
    config = load_config(getattr(args, "config", None), getattr(args, "no_config", False))
    discovery = config.get("discovery") if isinstance(config.get("discovery"), dict) else {}
    roots = list(args.root) + [str(item) for item in discovery.get("roots", []) or []]
    include_marketplaces = not args.no_marketplaces and bool(discovery.get("include_marketplaces", True))
    discovered = discover(
        roots=roots,
        projects=args.project,
        include_marketplaces=include_marketplaces,
        artifacts=args.artifacts,
    )
    if args.json:
        payload = {
            "schema": "skilltriage-discovery/v1",
            "skills": [skill.to_dict() for skill in discovered],
        }
        print(json.dumps(payload, indent=2))
        return 0
    if not discovered:
        print("no skills found")
        return 0
    print(f"{'KIND':14} {'SKILL ID':58} PATH")
    print("-" * 120)
    for skill in discovered:
        print(
            f"{escape_unsafe(skill.kind):14} {escape_unsafe(skill.skill_id):58} "
            f"{escape_unsafe(str(skill.path))}"
        )
    print(f"\n{len(discovered)} skill(s)")
    return 0


def cmd_inventory(args) -> int:
    options = _build_options(args)
    db = getattr(args, "db", None) or options.inventory_path or str(default_inventory_path())
    command = args.inventory_command
    if command == "path":
        print(escape_unsafe(str(db)))
        return 0
    if command == "list":
        inventory = Inventory.load(db)
        records = [inventory.skills[key] for key in sorted(inventory.skills)]
        if args.format == "json":
            print(json.dumps({"schema": "skilltriage-inventory/v1", "updated": inventory.updated, "skills": records}, indent=2))
            return 0
        if not records:
            print(f"inventory is empty: {escape_unsafe(str(db))}")
            return 0
        print(f"{'SKILL ID':58} {'VERSION':12} {'KIND':14} HASH")
        print("-" * 120)
        for record in records:
            skill_id = escape_unsafe(str(record.get("skill_id", "")))
            version = escape_unsafe(str(record.get("version", "")))
            kind = escape_unsafe(str(record.get("kind", "")))
            digest = escape_unsafe(str(record.get("content_hash", "")))[:26]
            print(f"{skill_id:58} {version:12} {kind:14} {digest}…")
        print(f"\n{len(records)} record(s) — {escape_unsafe(str(db))}")
        return 0

    roots, projects, include_marketplaces = _discovery_arguments(args, options)
    discovered = discover(roots=roots, projects=projects, include_marketplaces=include_marketplaces)
    if not discovered:
        print("skilltriage: no skills found in the selected roots", file=sys.stderr)
        return 2
    inventory = Inventory.load(db)
    report = scan_discovered(discovered, options, inventory=inventory)
    _print_scan_errors(report)
    if command == "sync":
        summary = inventory.sync(report.results)
        inventory.save()
        payload = {
            "schema": "skilltriage-inventory-sync/v1",
            "path": str(inventory.path),
            "skills": len(report.results),
            **summary,
        }
        if args.format == "json":
            print(json.dumps(payload, indent=2))
        else:
            print(
                f"inventory synced: {summary['added']} added, {summary['changed']} changed, "
                f"{summary['unchanged']} unchanged — {escape_unsafe(str(inventory.path))}"
            )
        return 2 if report.errors else 0
    diff = inventory.diff(report.results)
    if args.format == "json":
        print(json.dumps(diff, indent=2))
    else:
        print(f"added: {len(diff['added'])}, removed: {len(diff['removed'])}, changed: {len(diff['changed'])}")
        for record in diff["added"]:
            skill_id = escape_unsafe(str(record.get("skill_id", "")))
            digest = escape_unsafe(str(record.get("content_hash", "")))[:20]
            print(f"  + {skill_id} ({digest}…)")
        for record in diff["removed"]:
            print(f"  - {escape_unsafe(str(record.get('skill_id', '')))}")
        for pair in diff["changed"]:
            print(f"  ~ {escape_unsafe(str(pair['new'].get('skill_id', '')))}")
    return 2 if report.errors else 0


def cmd_rules(args) -> int:
    if args.rules_command == "explain":
        if not args.rule_id:
            print("skilltriage: explain requires a rule id", file=sys.stderr)
            return 2
        rule = get_rule(args.rule_id)
        if rule is None:
            print(
                f"skilltriage: unknown rule: {escape_unsafe(args.rule_id)}",
                file=sys.stderr,
            )
            return 2
        if args.format == "json":
            print(json.dumps(describe_rules([rule])[0], indent=2))
        else:
            print(f"{rule.id} — {rule.title}")
            print(f"  AST:          {rule.ast} {rule.ast_name}")
            print(f"  Severity:     {rule.severity.value} ({rule.confidence.value} confidence)")
            print(f"  Description:  {rule.description}")
            print(f"  Remediation:  {rule.remediation}")
            if rule.cwes:
                print(f"  CWE:          {', '.join(rule.cwes)}")
            if rule.tags:
                print(f"  Tags:         {', '.join(rule.tags)}")
        return 0

    rules = all_rules()
    if args.ast:
        rules = [rule for rule in rules if rule.ast == args.ast]
    rules = sorted(rules, key=lambda item: (item.ast, item.id))
    if args.format == "json":
        print(json.dumps(describe_rules(rules), indent=2))
        return 0
    print(f"{'RULE ID':40} {'AST':5} {'SEVERITY':9} {'CONF':6} TITLE")
    print("-" * 120)
    for rule in rules:
        print(
            f"{rule.id:40} {rule.ast:5} {rule.severity.value:9} "
            f"{rule.confidence.value:6} {rule.title}"
        )
    print(f"\n{len(rules)} rule(s)")
    return 0


def cmd_validate_cases(args) -> int:
    cases, errors = validate_cases(args.path)
    if args.format == "json":
        print(
            json.dumps(
                {
                    "valid": not errors,
                    "errors": errors,
                    "summary": describe_cases(cases),
                },
                indent=2,
            )
        )
    elif errors:
        print("FAIL — behaviour-test case file is invalid")
        for error in errors:
            print(f"- {escape_unsafe(error)}")
        print("\nCases were NOT executed against an agent.")
    else:
        summary = describe_cases(cases)
        print(
            f"PASS — {summary['cases']} case(s) are structurally valid. "
            "Cases were NOT executed against an agent."
        )
    return 0 if not errors else 1


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        if args.command in ("audit", "scan-system", "scan"):
            resolved = _resolve_format(args)
            if resolved is None:
                print(
                    "skilltriage: cannot infer a report format from "
                    f"{escape_unsafe(str(args.output))}; pass --format",
                    file=sys.stderr,
                )
                return 2
            args.format = resolved
        if args.command == "audit":
            return cmd_audit(args)
        if args.command == "scan-system":
            return cmd_scan_system(args)
        if args.command == "scan":
            return cmd_scan(args)
        if args.command == "discover":
            return cmd_discover(args)
        if args.command == "inventory":
            return cmd_inventory(args)
        if args.command == "rules":
            return cmd_rules(args)
        if args.command == "validate-cases":
            return cmd_validate_cases(args)
    except (ConfigError, BaselineError, InventoryError, OSError) as exc:
        print(f"skilltriage: error: {escape_unsafe(str(exc))}", file=sys.stderr)
        return 2
    parser.error("unknown command")
    return 2

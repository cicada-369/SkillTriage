# Changelog

All notable changes are recorded here. The format follows Keep a Changelog and
the project uses semantic versioning.

## [0.1.0] — 2026-10-26

### Added

- Static audit engine for agent skills and Claude Code plugins, mapped to the
  OWASP Agentic Skills Top 10 (AST01-AST10).
- 107 rules across metadata, permissions, shell/Python/JavaScript analysis,
  secrets, obfuscation, external references, supply chain, plugin configuration,
  file/archive safety, governance, and cross-platform consistency.
- First-class plugin adapter: a plugin root is one audited artifact with its
  identity, commands, agents, bundled skills, hook events, MCP servers, and
  marketplace entry. Both wrapped and bare-map `.mcp.json` shapes are supported.
- Plugin rules for approval-injecting hooks, hook path escapes, missing hook
  scripts, unpinned and cleartext MCP transports, escaping or missing declared
  components, duplicate components, unpinned marketplace sources, and wildcard
  component tool grants.
- Self-contained offline HTML report with a Content-Security-Policy hash, no
  external assets, escaped fields, dark mode, filtering, and print styles.
- `scan` command for paths or the default install locations, format inference
  from the output suffix, `--open`, and first-run guidance.
- Declared-intent policy for legitimate offensive-security artifacts. A
  declaration is honoured only when policy allows it and the artifact is in the
  inventory; findings are downgraded, never removed, and remain visible.
- Safe YAML-subset parser with a PyYAML cross-check in tests; JSON duplicate-key
  detection; `tomllib` support; bounded flow and JSON/TOML nesting.
- Safe loader with symlink refusal (including a symlinked target root),
  `O_NOFOLLOW` plus an `fstat` check, per-file read bounds, lazy tar headers, and
  archive protections against zip-slip, zip bombs, traversal, links, and device
  files. Archive and parser failures become scan errors.
- Context-aware scoring that lowers severity/confidence in documentation,
  examples, warnings, comments, detector/test files, and plugin documentation,
  without dropping findings.
- Cross-file correlation for credential-to-network and
  manipulation-to-capability chains, including structured plugin configuration.
- Discovery of personal skills, plugin caches, marketplaces, and project skills.
- Local JSON inventory with content hashes and drift comparison.
- Baseline support with line-independent fingerprints.
- Inline suppression comments.
- Text, JSON, Markdown, SARIF 2.1.0, and HTML reports; SARIF artifacts carry
  SHA-256 hashes and a static layer property.
- Policy profiles (`advisory`, `default`, `strict`), `--fail-on`,
  `--min-confidence`, TOML configuration, and stable exit codes.
- CLI commands: `scan`, `audit`, `scan-system`, `discover`, `inventory`,
  `rules`, `validate-cases`.
- Zero-install shell launcher, a reproducible `zipapp` build target, and a
  release workflow with checksums.
- 243 tests, including parser cross-checks, archive and parser attacks, every
  rule family, plugin model and rules, intent policy, HTML injection and CSP,
  regression snapshots, all report formats, the CLI, and a live audit of
  installed artifacts when present.
- Documentation: rule catalog, plugin coverage, intent policy, OWASP mapping,
  architecture, security policy, review evidence, contributing guide, and
  examples.

### Security

- Inline suppressions are now opt-in (`--trust-inline-suppressions`). An
  artifact can no longer suppress its own findings by default.
- Project configuration is no longer auto-loaded from the current directory; a
  project config requires `--config`, so a planted file cannot weaken the gate.
- Context scoring can no longer talk a critical or high finding below the gate
  with a comment, a word such as "test" in a URL, or a detector-like filename.
  Security tooling keeps the noise-reduction path by identifying itself in its
  path or display name; every downgrade stays visible.
- Uninspected content gates: file truncation, executable/bytecode content,
  nested archives, skipped archive members, and budget-incomplete scans are
  HIGH/HIGH. Script and configuration suffixes are decoded as text even with
  invalid bytes.
- Redaction covers whole PEM blocks, URL userinfo, URL query credentials, and
  placeholders that could contain a real credential.
- Archive hardening: decompressed-size pre-scan for compressed tars, archive
  file-size cap, ZIP entry-count pre-check before `infolist()`, ZIP64 size cap,
  Windows drive/reserved/trailing-dot path rejection, and extraction containment.
- Hook path escapes now include absolute, home, UNC, and drive-letter
  references. Bare `Bash` and scoped `Bash(...)` grants are not broad; unscoped
  `Bash(*)` is.
- Markdown output HTML-escapes dynamic values and uses a code-span fence longer
  than any backtick run.
- Reports, baselines, and inventory are written atomically with `0600` and an
  unpredictable temporary name.
- SARIF results for target-level findings carry a physical location on the
  primary manifest, so GitHub code scanning accepts the file; SARIF upload runs
  once per commit rather than once per matrix job.
- Parser, config, inventory, baseline, and case-file loaders convert
  `ValueError`, `MemoryError`, and `UnicodeDecodeError` into typed errors; the
  Python AST rules are per-file resilient and iterative. JSON manifest nesting
  is bounded at 200 levels before parsing, independent of the interpreter's
  recursion behavior.
- Declared intent is bound to a matching inventory content hash; the canonical
  hash includes size and file status; `--require-inventory` gates on a missing
  record.
- The release workflow runs the suite and catalog check, uses a `release`
  environment, and attests provenance for the wheel, sdist, and zipapp.

### Changed

- Renamed the project from AgentTester to **SkillTriage** before the first
  public release; the command is `skilltriage`.
- The licence is Apache-2.0.
- Reports are written atomically with owner-only permissions (`0600`).
- Every report field is escaped for control, bidi, and invisible characters,
  not only finding evidence.
- `--update-inventory` now actually updates the inventory (it previously
  loaded it without writing).
- The default gate is unchanged: HIGH/CRITICAL with HIGH confidence.
- Inventory content hashes now include file size and status, and large files
  use a prefix hash plus status instead of a constant marker. Re-run
  `inventory sync` after upgrading.

### Known limitations

- Static analysis only; no dynamic execution, network access, or signature
  verification.
- Hooks and MCP servers are inspected, not executed. Individually invoked hook
  scripts beyond the direct reference are a coverage gap.
- A plugin is audited as its own root; parent directories and registry files are
  not read.
- Dependencies are inspected, not resolved; no CVE/SBOM pipeline.
- External references are classified, not fetched.
- AST06/AST09 organisational controls are reported as declarations and gaps,
  not enforced.
- Declared intent requires both an explicit policy allowlist and an inventory
  record, and never removes a finding.

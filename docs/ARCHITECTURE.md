# Architecture

`skilltriage` is a deterministic static analyser. The design optimises for three
properties: **safety when reading hostile input**, **explainable findings**, and
**honest coverage**.

## Non-goals

- Executing skill code or observing runtime behaviour.
- Fetching external URLs, resolving packages, or calling an LLM.
- Verifying signatures against a trust store.
- Proving a skill safe.

Those layers are intentionally left to a sandbox or a separate service, with
explicit consent.

## Pipeline

```
target (dir | zip | tar)
        │
        ▼
 loader.py ── safe walk, O_NOFOLLOW, size caps, archive checks
        │
        ▼
 parsers.py ── restricted YAML subset, JSON duplicate keys, TOML
        │
        ▼
 normalize.py ── one model for skills (SKILL.md / skill.json / package.json /
        │        universal) and plugin artifacts (identity, components,
        │        hooks, MCP servers)
        ▼
 rules/ ── 107 checks, grouped by risk family
        │      │
        │      └── ctx.signal(...) → correlation.py
        ▼
 context.py ── severity/confidence scoring for docs, examples, comments
        │
        ▼
 suppressions.py → baseline.py → intent → policy.py (gate)
        │
        ▼
 report/{text,json_report,markdown,sarif,html}.py
```

## Modules

| Module | Responsibility |
|---|---|
| `loader.py` | Safe filesystem walk, file records, hashing, archive extraction, decompression and entry-count bounds. |
| `atomic.py` | Atomic, owner-only writes for reports, baselines, and inventory. |
| `parsers.py` | YAML-subset parser that cannot construct objects; JSON/TOML helpers. |
| `normalize.py` | Manifest discovery and a platform-neutral skill/permission model. |
| `patterns.py` | Shared regexes, URL/host classification, code/markdown extension sets. |
| `obfuscation.py` | Invisible Unicode, tag smuggling, base64 candidates, padding detection. |
| `secrets.py` | Credential patterns, placeholder filtering, redaction, evidence escaping. |
| `suppressions.py` | Inline `skilltriage:disable` parsing. |
| `intent.py` | Declared-intent extraction and canonical values. |
| `baseline.py` | Fingerprinted accepted findings. |
| `inventory.py` | Persistent per-skill content hashes and diffing. |
| `discovery.py` | Known install locations and project roots. |
| `policy.py` | Profiles, gate thresholds, TOML configuration. |
| `analysis.py` | Orchestration, inventory/baseline application, gating. |
| `rules/` | One module per risk family; `base.py` defines the contract; `plugins.py` holds plugin-only checks. |
| `report/` | Text, JSON, Markdown, SARIF, and a self-contained HTML document. |
| `cli.py` | Argument parsing and command dispatch. |

## Data model

- `FileRecord` — relative path, size, SHA-256, mode, kind, magic, symlink
  target, truncation state, and loaded text.
- `ManifestRecord` — path, platform, format, parsed data, parse issues, body
  line offset.
- `NormalizedSkill` — identity, version, risk tier, provenance fields,
  permissions, manifests, and an optional declared intent.
- `NormalizedPlugin` — identity, commands, agents, bundled skills, hook events,
  MCP servers, marketplace entry, and per-manifest unknown keys. Plugin
  environment and header **values** are never stored, only key names.
- `PluginComponent` — kind, name, path, declared flag, allowed tools, model, and
  parsed frontmatter.
- `HookEvent` — event, matcher, type, command, timeout, async flag, condition.
- `McpServer` — name, transport, command, args, environment keys, URL, header
  names, working directory.
- `Finding` — rule ID, AST control, severity, confidence, path/line, evidence,
  rationale, remediation, CWEs, context note, state (suppressed/baselined/
  intent-matched), fingerprint.
- `AuditResult` / `ScanReport` — per-target and aggregate views plus coverage
  and limitations.

## Rule contract

```python
Rule(
    id="AST01-DOWNLOAD-EXEC",
    ast="AST01",
    title="Download and execute",
    severity=Severity.CRITICAL,
    confidence=Confidence.HIGH,
    description="...",
    remediation="...",
    cwes=("CWE-494", "CWE-78"),
    tags=("execution", "network"),
    intent_family="offensive-security",  # optional; see docs/INTENT.md
    check=check_download_exec,
)
```

Rules emit through `RuleContext.emit`, which:

1. selects the matched line as evidence unless a custom value is provided,
2. redacts secrets and escapes control/invisible characters,
3. applies context scoring,
4. deduplicates by `(rule, path, line, evidence)`,
5. records a line-independent fingerprint.

A rule may set `no_context=True` when the match is objective (for example a
Unicode tag character or a manifest permission field).

### Signals and correlation

Some checks record a signal with a `path:line` value. Correlation rules only
consider signals from `SKILL.md`, executable code, or structured plugin
configuration (`.mcp.json`, `hooks/hooks.json`, plugin and marketplace
manifests). Documentation and command/agent prose are excluded. This prevents a
security guide that mentions both `~/.ssh` and a webhook, or one bundled skill's
prose correlating with another component's capability, from being reported as a
credential stealer.

Signals also respect confidence: a match that context scoring downgraded to
`LOW` does not feed a chain.

## Context scoring

For non-code files:

- documentation/example paths → one severity step down,
- fenced `text`/`markdown` examples, or any fence in a documentation path → one
  step down,
- warning/example language → one step down,
- detection/test language → one step down.

For code files:

- comments → one step down,
- detector/scanner/auditor/tester/fixture filenames → one step down,
- detection/test language → one step down.

Confidence becomes `LOW` on any downgrade. Severity is lowered at most twice
per finding. The `context_note` explains every downgrade. Findings are never
removed; suppressions and baselines are explicit and visible.

**High-severity guard.** Context words are artifact-controlled, so outside a
documentation path a CRITICAL finding is never downgraded by a comment, a word
such as `test` in a URL, or a detector-like filename. A HIGH finding is
downgraded only when the artifact's relative path or name/identity marks it as
security tooling (never the absolute input path). This closes the one-word gate
bypass; impersonating security tooling remains a documented residual, and
declared intent requires a matching inventory hash.

## Reports

- **JSON** is the canonical machine format (`skilltriage/v1`).
- **SARIF** emits one run per target. Each scanned file with a finding is an
  artifact carrying `hashes["sha-256"]`; every result points at that artifact
  index and carries `properties.layer = "static"`. Suppressed/baselined results
  use SARIF `suppressions` with `level = "none"`.
- **HTML** is one self-contained document with no external assets. Every
  dynamic field is passed through the text-safety escaper and then
  `html.escape`; the inline stylesheet and script are covered by a
  Content-Security-Policy hash. The client script only toggles visibility; it
  never constructs HTML.
- **Markdown** escapes HTML metacharacters in every dynamic value and chooses a
  code-span fence longer than any backtick run in the value, so a hostile path
  or evidence line cannot break out of a heading, table cell, or code span. It is
  designed for a PR comment: summary table, per-AST tables, and
  per-finding detail.
- **Text** is fleet-aware: a table for multi-target scans, detail for failing
  targets (or all targets with `--verbose`).

## Inventory and baseline

Inventory stores a canonical hash over sorted
`path + kind + mode + size + status + content-hash` tuples. Baselined findings
use `rule + path + normalised evidence`, deliberately excluding line numbers.
A declared intent is honoured only when the inventory record's hash equals the
current tree hash, so approval is bound to the reviewed bytes.

Both are explicit: a scan never updates inventory unless `--update-inventory` is
passed, and a baseline is only applied when `--baseline` is passed.

## Security invariants

1. Never execute target content.
2. Never make a network request, including from the HTML report.
3. Never follow a symlink; refuse a symlinked target root.
4. Never read outside the extraction root.
5. Never construct objects from metadata.
6. Never reproduce a detected credential.
7. Never truncate a file without reporting it.
8. Never silently drop a finding.
9. Never emit an unescaped path, message, note, or error to a terminal or HTML.
10. Never let a declared intent remove a finding, or honour one without both an
    explicit policy allowance and an inventory record.
11. Bound parser nesting, per-file reads, tar headers, decompressed tar bytes,
    ZIP entry counts, and non-file records.
12. Turn an archive or parser failure into a scan error, never a traceback.
13. Write reports, baselines, and inventory atomically with owner-only
    permissions and an unpredictable temporary name.
14. Never honour an inline suppression from the artifact unless the operator
    passes `--trust-inline-suppressions`.
15. Never auto-load project configuration; an artifact cannot weaken its own
    gate.
16. Bind a declared intent to a policy allowance *and* a matching inventory
    content hash.
17. Gate when content was not inspected: truncation, executables, nested
    archives, skipped members, and incomplete scans.

## Performance

The legacy skill-by-skill view of the installed corpus scans in roughly eight
seconds. The plugin-aware `scan` (67 targets: 43 plugin artifacts and 24
standalone skills) takes roughly 40 seconds, because several plugin roots contain
hundreds of files and bundled skills. The loader bounds pathological input; no
parallelism is used, which keeps output deterministic and debugging simple. A
future worker pool can parallelise across targets without changing the result
model.

## Testing strategy

- Parser tests include a PyYAML cross-check over fixtures and installed skills.
- Loader tests cover symlinks, symlinked target roots, FIFOs, truncation,
  zip-slip, zip bombs, tar traversal, and corrupt/truncated archives.
- Parser tests cover recursive flow collections, deeply nested JSON/TOML, and
  lone surrogate escapes.
- Rule tests pair positive fixtures with benign lookalikes and assert that
  documentation examples do not gate.
- Plugin tests cover both `.mcp.json` shapes, hook parsing, component
  resolution and escapes, marketplace pinning, and the rule set.
- Intent tests cover declaration parsing, policy-without-inventory, the
  inventory gate, and unknown values.
- Report tests parse the JSON and SARIF they produce, recompute the HTML CSP
  hash, and feed hostile fields through `html.parser` to assert no active
  content.
- Regression snapshots pin the finding set for every checked-in fixture and the
  rule-registry size; an unexplained change fails the suite.
- CLI tests exercise exit codes, baselines, inventory, discovery, plugins,
  intent, format inference, and file permissions.
- Security tests cover self-suppression, target-controlled config, context-word
  evasion, uninspected-content gating, PEM body redaction, Windows archive
  components, compressed-tar bombs, ZIP entry floods, absolute/home hook paths,
  Markdown escaping, and symlink-safe state writes.
- `test_real_skills.py` audits the local personal skill corpus when present and
  asserts deterministic output and no engine errors.
- `test_docs.py` fails if `docs/RULES.md` drifts from the registry.

## Extension points

- Add a rule module and register it in `rules/__init__.py`.
- Add a plugin check in `rules/plugins.py`; it must return unless
  `ctx.is_plugin`.
- Add a platform manifest to `MANIFEST_SPECS` and `KNOWN_TOP_LEVEL_KEYS`.
- Add an intent-sensitive rule by setting `intent_family` and the matching
  policy value; keep the rule family narrow.
- Add an output format in `report/` and register it in `FORMATS`.
- Add a discovery root in `discovery.DEFAULT_ROOTS` or configuration.
- Add a semantic or dynamic layer behind an explicit command/flag; do not make
  it part of the default deterministic gate.

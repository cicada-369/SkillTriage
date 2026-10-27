# SkillTriage

**Static security audit and risk triage for agentic skills and Claude Code
plugins, mapped to the
[OWASP Agentic Skills Top 10](https://github.com/OWASP/www-project-agentic-skills-top-10).**

`skilltriage` inspects a skill or plugin package *before installation* or an
already installed artifact, reports concrete findings with evidence and
remediation, and emits gate-ready text, JSON, Markdown, SARIF, or a
self-contained HTML report. It never executes artifact code, never fetches a
referenced URL, and has **zero third-party runtime dependencies**.

> Static analysis is triage, not a verdict. A clean report means no configured
> check triggered; it does not prove the artifact is safe or behaves as
> documented. See [Limitations](#limitations).

## Why

Agent skills combine executable code with natural-language instructions. That
blend defeats traditional package scanners: a skill can exfiltrate a key with
three lines of Markdown, or hide a payload behind zero-width characters, a
base64 blob, a padded line, or an external document that changes after review.
Plugins add another layer: hooks run automatically, MCP servers launch
processes or talk to remote hosts, and commands and agents carry their own tool
grants. The OWASP Agentic Skills Top 10 names these failure modes (AST01-AST10).
`skilltriage` turns them into deterministic, reviewable checks and keeps the
coverage gaps explicit.

## What it checks

| Control | Examples of what is inspected |
|---|---|
| **AST01 Malicious Skills** | download-and-execute, reverse shells, destructive commands, credential access, exfiltration chains, identity-file writes, hidden/encoded payloads |
| **AST02 Supply Chain** | unpinned dependencies, URL/VCS dependencies, install scripts, executable configuration, unpinned MCP launches, cleartext MCP transport, missing provenance |
| **AST03 Over-Privileged Skills** | shell access, wildcard filesystem scopes, open egress, broad tools, wildcard component tool grants, identity/credential permissions, risk-tier mismatch, declared-vs-observed behaviour |
| **AST04 Insecure Metadata** | unsafe YAML tags, duplicate keys, malformed manifests, wrong field types, invisible/control characters, brand impersonation, import-time side effects, escaping or missing plugin components, unknown declared intent |
| **AST05 Untrusted External Instructions** | mutable/paste/tunnel hosts, instruction-bearing URLs, unpinned references |
| **AST06 Weak Isolation** | symlink escape, setuid bits, privileged/host-mode containers, security controls disabled, services bound to all interfaces, hook commands that escape the plugin root |
| **AST07 Update Drift** | mutable versions, missing hashes/signatures, auto-update, hot reload, inventory hash drift, unpinned marketplace sources |
| **AST08 Poor Scanning** | binary/bytecode and archive content, hidden files, padding/truncation evasion, high-entropy blobs, scan scope gaps |
| **AST09 No Governance** | risk tier, owner, approval, scan status, audit logging, inventory presence, hooks that approve permission prompts |
| **AST10 Cross-Platform Reuse** | security property loss and inconsistent permissions across platform manifests |

The full catalog (107 rules) is in [`docs/RULES.md`](docs/RULES.md). The OWASP
control mapping and its limits are in
[`docs/OWASP-MAPPING.md`](docs/OWASP-MAPPING.md). Plugin coverage and boundaries
are described in [`docs/PLUGINS.md`](docs/PLUGINS.md); the intent policy is in
[`docs/INTENT.md`](docs/INTENT.md).

## Install

Requires **Python 3.11+**. There are no runtime dependencies.

### From source (recommended)

```bash
git clone https://github.com/cicada-369/SkillTriage.git
cd SkillTriage
python3 -m venv .venv
. .venv/bin/activate
python -m pip install -e .
skilltriage --version
```

`pipx install .` also works.

### Without installing

```bash
./bin/skilltriage --version
./bin/skilltriage audit examples/secure-skill
```

The launcher sets `PYTHONSAFEPATH=1`, so Python does not import modules from the
current working directory (which may be an untrusted package).

### Single-file zipapp

```bash
make zipapp
./dist/skilltriage.pyz scan
```

## Quick start

One command scans installed skills and plugins and prints a summary:

```bash
skilltriage scan
```

Scan a downloaded package, or produce a shareable offline report:

```bash
skilltriage audit ./downloaded-skill
skilltriage scan ./downloaded-skill -o report.html --open
skilltriage scan ./downloaded-skill --format markdown -o report.md
skilltriage scan ./downloaded-skill --format sarif -o report.sarif
```

The format is inferred from the output suffix, so `-o report.html` is enough.
`--open` opens the HTML report in the local browser; it never uploads anything.

Audit an installed Claude Code plugin as one artifact (manifest, commands,
agents, hooks, MCP servers, and bundled skills):

```bash
skilltriage scan ~/.claude/plugins/cache/<market>/<plugin>/<version>
skilltriage scan ~/.claude/plugins/marketplaces/<market>/plugins/<plugin>
```

Record hashes and detect drift later:

```bash
skilltriage inventory sync
skilltriage inventory diff
skilltriage audit ~/.claude/skills/my-skill --inventory --require-inventory
```

Accept reviewed findings without hiding them:

```bash
skilltriage audit ./skill --write-baseline .skilltriage-baseline.json
skilltriage audit ./skill --baseline .skilltriage-baseline.json
```

### Offensive-security skills

A skill that intentionally contains attack tooling can declare that intent. The
declaration alone changes nothing: policy must allow the value, **and** the
inventory record's canonical content hash must match the current artifact. When
all three hold, technique findings are downgraded one severity step with `LOW`
confidence and never gate, but they stay in every report. A changed artifact no
longer qualifies.

```bash
# metadata.skilltriage.intent: offensive-security in SKILL.md
skilltriage scan --root ~/.claude/skills --inventory --update-inventory
skilltriage scan --root ~/.claude/skills --inventory \
  --allow-intent offensive-security
```

See [`docs/INTENT.md`](docs/INTENT.md).

## Commands

| Command | Purpose |
|---|---|
| `scan [PATH...]` | Scan paths, or the default install locations, including plugins. |
| `audit PATH...` | Audit one or more skill or plugin directories or archives. |
| `scan-system` | Legacy skill-by-skill view of installed skills. |
| `discover` | List discovered artifacts without auditing (`--artifacts`, `--json`). |
| `inventory sync` | Scan skills and update the local hash inventory. |
| `inventory diff` | Compare installed skills against the inventory. |
| `inventory list` | Show inventory records (`--format json`). |
| `inventory path` | Print the inventory location. |
| `rules list` | List rules, filterable by `--ast`. |
| `rules explain RULE-ID` | Show one rule's rationale and remediation. |
| `validate-cases FILE` | Validate a behaviour-test case file (does not run it). |

Run a command with `--help` for its full options.

### Discovery locations

With no `--root`, `scan` looks at:

- `~/.claude/skills` (personal skills)
- `~/.claude/plugins/cache` (installed plugins)
- `~/.claude/plugins/marketplaces` (marketplace sources; `--no-marketplaces` skips)
- `~/.config/opencode/skills`, `~/.codex/skills`, `~/.cursor/skills` when present

In `scan`, a plugin root is one target and its bundled skills are components.
`scan --artifacts {skills,plugins,both}` restricts discovery (the default is
both). `scan-system` keeps the legacy behaviour of listing each skill
separately.
Passing `--root DIR` **scans that root instead of the defaults**, which keeps CI
and fixture scans hermetic. Pass it multiple times to scan several roots. Config
`discovery.roots` behaves the same way. `--project DIR` additionally looks at
`DIR/.claude/skills` and `DIR/skills`.

## Exit codes and policy

| Code | Meaning |
|---|---|
| `0` | No gating finding and no scan error. |
| `1` | At least one gating finding. |
| `2` | The scan could not complete (bad target, config error, no artifacts found). |

Profiles:

| Profile | Gate |
|---|---|
| `advisory` | Never fails; every finding is reported. |
| `default` | Fails on **HIGH/CRITICAL with HIGH confidence**. |
| `strict` | Fails on **MEDIUM+ with MEDIUM+ confidence**. |

Override with `--fail-on {none,critical,high,medium,low,info}` and
`--min-confidence {high,medium,low}`. `--fail-on none` always exits `0` (scan
errors still exit `2`). Suppressed, baselined, and intent-downgraded findings do
not gate.

## Reports

- **text** — human-readable, defaults to a fleet table for multi-target scans.
- **json** — stable schema `skilltriage/v1`, including policy, findings, plugin
  components, files with hashes, coverage, and limitations.
- **markdown** — PR-comment-friendly tables plus per-finding detail.
- **sarif** — SARIF 2.1.0. Every scanned file is an artifact with a
  `sha-256` hash; findings point at the artifact index and carry
  `properties.layer = "static"`, so they can be joined with other scanners.
  Target-level findings (correlations, archive issues, inventory drift) point at
  the primary manifest, because code scanning requires a physical location.
- **html** — one self-contained, offline file. No scripts, styles, fonts, or
  images are loaded from the network; the inline stylesheet and script are
  covered by a Content-Security-Policy hash. Every field is escaped for control,
  bidi, and invisible characters before HTML escaping.

`--show-suppressed` and `--show-baselined` include those findings in text,
Markdown, and HTML output; JSON always contains them with their state.

Reports are written atomically with owner-only permissions (`0600`), because
they can contain excerpts from the audited artifact.

## Inventory and drift

The inventory is a transparent JSON file at
`~/.local/share/skilltriage/inventory.json` (or `$XDG_DATA_HOME/skilltriage/`).
Each record holds the artifact ID, name, version, install location, canonical
content hash, file count, size, first/last seen, risk tier, signature presence,
and finding counts.

- `--inventory` enables comparison against the stored hash.
- `--require-inventory` also gates on installed artifacts that have no record
  (`AST09-NOT-IN-INVENTORY`, HIGH).
- `--update-inventory` writes the current state after the scan.
- `--inventory-file FILE` uses a different database.

A changed hash produces `AST07-BASELINE-DRIFT` (HIGH, HIGH confidence), which
gates under the default profile. The tool never updates inventory implicitly.

## Baselines and suppressions

A baseline records line-independent fingerprints
(`rule + path + normalised evidence`) for reviewed findings:

```bash
skilltriage audit ./skill --write-baseline .skilltriage-baseline.json
skilltriage audit ./skill --baseline .skilltriage-baseline.json
```

Inline suppressions are **off by default**. They live inside the artifact under
audit, so a malicious package could otherwise silence its own findings. Enable
them with `--trust-inline-suppressions` (or
`[audit] trust_inline_suppressions = true`) only for artifacts you author or
trust; use a baseline for third-party packages.

When enabled, they work in any comment syntax:

```markdown
<!-- skilltriage:disable AST01-DOWNLOAD-EXEC because this example is inert -->

<!-- skilltriage:disable-next-line AST03-EMBEDDED-SECRET -->

<!-- skilltriage:disable-file AST10-NO-UNIVERSAL-FORMAT -->
```

A bare `disable` covers the same line and the next three lines (enough for a
fenced block). `--show-suppressed` only has an effect when inline suppressions
are trusted. Suppressed findings stay in JSON with `suppressed: true` and do
not gate. Add a reason; the tool does not require one, reviewers should. With
the default (trust off), the same comments are parsed but have no effect, so
an artifact cannot suppress itself.

## Configuration

`skilltriage` reads `~/.config/skilltriage/config.toml`. A project config is
**not** auto-loaded from the current directory, because an artifact under audit
must not be able to weaken its own gate. Pass a project config explicitly with
`--config FILE`; `--no-config` disables lookup.

```toml
[audit]
profile = "default"
fail_on = "high"
min_confidence = "high"
include_vendor = false
trust_inline_suppressions = false
max_file_bytes = 2097152
max_total_bytes = 268435456
max_files = 10000
max_archive_bytes = 67108864

[discovery]
# Setting roots replaces the built-in defaults, matching --root semantics.
roots = ["~/.claude/skills", "~/work/shared-skills"]
include_marketplaces = true

[inventory]
path = "~/.local/share/skilltriage/inventory.json"

[intent]
# Empty by default. A declaration alone never changes a verdict.
allow = ["offensive-security"]
```

## How it works

1. **Load safely** — walk without following symlinks, open regular files with
   `O_NOFOLLOW`, bound every read, extract archives with zip-slip and
   compression-bomb checks, and never execute anything.
2. **Parse safely** — a built-in YAML-subset parser that cannot construct
   objects, plus `json`/`tomllib`. Unsafe tags and anchors are reported, not
   resolved. Manifests are parsed from the bytes the loader already read, not a
   second disk read.
3. **Normalise** — `SKILL.md`, `skill.json`, `manifest.json`, `package.json`,
   universal manifests, and Claude Code plugin artifacts become one model. A
   plugin model captures its identity, commands, agents, bundled skills, hook
   events, and MCP servers.
4. **Run 107 rules** — metadata, permissions, shell/Python/JS patterns, secrets,
   obfuscation, external references, dependencies, files, plugin configuration,
   governance, and cross-platform consistency.
5. **Correlate** — credential access plus an outbound endpoint, or manipulation
   language plus an execution path, becomes a higher-severity chain.
   Correlations require a signal from code, `SKILL.md`, or structured plugin
   configuration; command and agent prose is deliberately excluded so
   documentation cannot manufacture a chain.
6. **Score context** — documentation paths, fenced examples, warning sentences,
   comments, and detector/test files lower severity and confidence. Findings are
   never silently removed.
7. **Gate and report** — apply suppressions, baseline, and declared intent,
   compute the gate, and render text, JSON, Markdown, SARIF, or HTML.

See [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md) for the module map.

## Safety of the tool itself

- No `eval`, `exec`, dynamic import, or shell invocation of target content.
- No network access in any command, including the HTML report.
- No symlink following inside a target; a symlinked target root is refused.
- Archives are size-, count-, and ratio-bounded; traversal, device, FIFO,
  encrypted, and link members are skipped and reported.
- Metadata parsing cannot instantiate objects or resolve tags; archive and
  parser failures become scan errors, not tracebacks.
- Evidence is redacted for detected secrets and every report field is escaped
  for control, bidi, and invisible characters, so a report cannot inject
  terminal escapes or HTML.
- Scans are deterministic: stable ordering and line-independent fingerprints.

See [`SECURITY.md`](SECURITY.md) and the review evidence in
[`docs/security/review-v0.1.md`](docs/security/review-v0.1.md).

## Testing

```bash
make test
# or:
PYTHONSAFEPATH=1 PYTHONPATH=src python3 -m unittest discover -s tests -t . -v
```

The suite covers parsers (including a PyYAML cross-check), archive attacks
(zip-slip, zip bomb, traversal, corrupt and truncated archives), every rule
family, context scoring, suppression, baseline, inventory, discovery, plugin
normalisation and rules, intent policy, all report formats (including HTML
injection and CSP hashing), the CLI, and a live audit of the artifacts installed
on the machine (skipped when the directory is absent). It currently has 243
tests.

Install the test extras so the PyYAML cross-check runs:

```bash
python -m pip install -e '.[test]'
```

Regenerate the rule catalog after changing rules:

```bash
python tools/gen_rules_doc.py
python tools/gen_rules_doc.py --check   # CI mode
```

## Limitations

- **Static only.** Hooks, tool calls, runtime file/network activity, and
  behaviour are not observed. Use a sandboxed dynamic harness for that layer.
- **Hooks and MCP are inspected, not executed.** Approval-injection detection
  follows the hook command and the script it directly references; indirectly
  invoked scripts are a coverage gap.
- **Context scoring cannot be talked down by artifact words alone.** Outside a
  documentation path, a critical finding is never downgraded, and a high finding
  is downgraded only when the artifact identifies itself as security tooling.
  A malicious package can impersonate security tooling; intent and inventory are
  the strong controls.
- **Large-file drift is prefix-based.** Files above the hash/read cap use the
  hash of the bytes read plus size and status, so a tail-only change is not
  detected. The scan reports the truncation.
- **Inline suppressions are opt-in.** A target cannot disable its own findings
  unless the operator passes `--trust-inline-suppressions`.
- **Plugin boundary.** A plugin is audited as its own root. Files above that
  root, or installed registry files such as `installed_plugins.json`, are not
  read. Marketplace manifests are evaluated only when they sit at the audited
  root.
- **Signature presence is recorded, not verified.** There is no trust store or
  signature verification in this version.
- **Dependencies are inspected, not resolved.** No lockfile resolution, SBOM
  generation, CVE lookup, or transitive install.
- **External content is never fetched.** References are classified; the content
  behind them is not reviewed.
- **Semantic intent is heuristic.** Pure natural-language malice can evade a
  static scanner (AST08 says so itself). This tool reports that gap rather than
  hiding it.
- **Declared intent is not proof.** It requires an explicit policy allowlist
  and an inventory record, and every downgraded finding stays visible. Review
  the artifact before allowing an intent.
- **False positives are expected** around security documentation, red-team
  tooling, and detection signatures. Context scoring lowers them; baselines and
  suppressions handle the rest.
- **AST06 and AST09 are partly organisational.** The tool reports declarations
  and gaps; it cannot enforce runtime isolation or enterprise governance.

## OWASP attribution and license

The risk taxonomy and control identifiers (AST01-AST10) come from the
[OWASP Agentic Skills Top 10](https://github.com/OWASP/www-project-agentic-skills-top-10)
project, whose documentation is licensed **CC BY-SA 4.0**. This tool writes its
own descriptions and remediation text and references the controls; it does not
reproduce the OWASP document. See [`NOTICE`](NOTICE).

The code is licensed **Apache-2.0**. See [`LICENSE`](LICENSE).

## Releasing

1. Run `make test`, `make compile`, `python tools/gen_rules_doc.py --check`, and
   a system scan.
2. Build the zipapp with `make zipapp`; the release workflow attaches it with a
   SHA-256 checksum and a build-provenance attestation.
3. Tag `v0.1.0`. The release workflow runs the test suite, verifies that the
   tag matches `pyproject.toml`, `skilltriage.__version__`, and the changelog,
   then publishes the wheel, sdist, zipapp, and checksums.

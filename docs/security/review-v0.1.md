# Security review — v0.1

**Date:** 2026-10-26
**Scope:** `skilltriage` 0.1.0 at `~/projects/SkillTriage` (source, tests, packaging,
and CI workflows).
**Status:** reviewed by the author and by an independent reviewer. Every
confirmed critical and high finding is fixed. Remaining items are deliberate
limitations listed under **Residual risks**.

## Threat model

The tool reads attacker-controlled skill and plugin packages: directories,
zip/tar archives, YAML/JSON/TOML manifests, Markdown instructions, scripts, hook
configurations, and MCP server definitions. The relevant adversary is the
package author. The tool must:

- never execute or fetch target content;
- never escape the audited root or follow a symlink into the host;
- not crash, hang, or exhaust memory on hostile input;
- not let target content inject terminal escapes, HTML, or active content into
  a report;
- not reproduce a detected credential;
- not let an artifact weaken, silence, or evade its own gate.

## Method

1. Read the loader, parsers, escaping/redaction helpers, report renderers, plugin
   adapter, intent policy, CLI, and CI workflows.
2. Run the functional suite, the rule-catalog check, a static analyzer, a
   dependency audit, and the reproducible zipapp build.
3. Feed hostile inputs through the parsers, loader, both report renderers, the
   config/state loaders, and the intent policy.
4. Audit the real installed corpus and explain every gating finding.
5. Obtain a second, independent read of the same scope with no knowledge of the
   author's conclusions, then fix and re-test each confirmed finding.

## Findings fixed before release

Severity is the reviewer's assessment before the fix. "Independent" marks a
finding raised by the second reviewer.

| # | Severity | Finding | Fix | Evidence |
|---|---|---|---|---|
| 1 | Critical (indep.) | An artifact could suppress every finding against itself with a `skilltriage:disable-file` comment, returning PASS. | Inline suppressions are inert unless the operator passes `--trust-inline-suppressions`. Baselines are the reviewed-acceptance mechanism. | `test_rules.py::test_artifact_cannot_suppress_its_own_findings`, `test_inline_suppression_is_opt_in` |
| 2 | Critical (indep.) | A planted `./.skilltriage.toml` disabled the gate (`fail_on = "none"`, advisory profile, attacker inventory path). | Only the user config is implicit. A project config requires `--config`. | `test_policy_baseline.py::test_project_config_is_not_auto_loaded`, `test_user_config_is_loaded` |
| 3 | Critical (indep.) | A single word (`test`, `example`, `never`) or a trailing comment downgraded a critical payload below the gate; a URL path `/test/` worked. | Outside a documentation path, CRITICAL findings are never downgraded, and HIGH findings are downgraded only when the artifact identifies itself as security tooling. | `test_rules.py::test_context_words_cannot_downgrade_a_critical_code_payload`, `test_warning_language_does_not_talk_down_a_critical_payload` |
| 4 | High (indep.) | Uninspected content did not gate: a payload after the 2 MB truncation point, a script with invalid UTF-8 classified as binary, nested archives, and budget-incomplete scans all passed. | Code/config suffixes are decoded as text even with invalid bytes; truncation, executables/bytecode, nested archives, skipped archive members, and incomplete scans are HIGH/HIGH. `__pycache__` is treated as a build cache. | `UninspectedContentTests`, `test_script_with_invalid_utf8_is_still_scanned` |
| 5 | High (indep.) | Private-key bodies were not redacted; a single-line PEM leaked the body and END marker. | `redact` masks the whole PEM block before line-based redaction. | `test_secrets.py::test_private_key_body_is_redacted`, `test_single_line_private_key_is_redacted` |
| 6 | High (indep.) | Windows archive members could escape with a drive-relative component (`a/D:evil`); reserved names and trailing dots/spaces were accepted. | Every component rejects `:`, Windows reserved names, and trailing dot/space; extraction asserts containment in the destination. | `test_loader.py::test_windows_drive_component_is_rejected`, `test_windows_reserved_name_is_rejected` |
| 7 | High (indep.) | Tar extended/longname headers could allocate hundreds of MB before the budget check. | Compressed tars are pre-read with a hard decompressed-byte cap; archive file size is capped; headers are iterated lazily. | `test_loader.py::test_compressed_tar_expansion_is_bounded` |
| 8 | High (indep.) | Absolute and home hook paths (`/opt/evil/approve.py`, `$HOME/...`, `~/...`, drive/UNC) were only "missing script", not path escapes. | The hook escape rule treats absolute, home, UNC, drive, and `..` references as escapes; the missing-script rule skips them. | `test_plugin_rules.py::test_hook_approval_escape_and_missing_script` |
| 9 | High (indep.) | The ZIP central directory was fully materialised before the entry cap; a 200k-entry ZIP allocated ~139 MB. | The EOCD entry count is checked before `infolist()`; archive file size is capped; ZIP64/malformed above 8 MB is rejected; `MemoryError` becomes a scan error. | `test_loader.py::test_zip_entry_count_is_checked_before_infolist` |
| 10 | Medium (indep.) | Markdown could inject HTML in a heading and a backtick could break out of an evidence code span. | Markdown escapes `&`, `<`, `>`, and chooses a code-span fence longer than any backtick run. | `test_reports.py::test_markdown_escapes_html_and_backticks` |
| 11 | Medium (indep.) | Baseline and inventory writers followed a predictable `.tmp` symlink and did not use 0600. | A shared `atomic.write_private` uses `mkstemp`, 0600, and `os.replace`; reports, baselines, and inventory use it. | `test_atomic.py` (including symlink tests) |
| 12 | Medium (indep.) | YAML out-of-range `\U`, oversized JSON/TOML integers, and invalid UTF-8 config/inventory/baseline/case files raised uncaught exceptions. | Bounded escapes; `ValueError`/`MemoryError`/`UnicodeDecodeError` become parse issues or typed config/state errors. | `test_parsers.py`, `test_policy_baseline.py`, `test_inventory.py` |
| 13 | Medium (indep.) | A deep attribute chain made the Python AST rule raise `RecursionError` and skip later files. | `_dotted` is iterative; each file is parsed in a `RecursionError`/`MemoryError` guard; one file cannot stop the rule. | `test_rules.py::test_deep_attribute_chain_does_not_skip_later_files` |
| 14 | Medium | HTML report field escaping/CSP/XSS. | Every dynamic value passes `escape_unsafe` then `html.escape`; fixed script/style constants carry CSP hashes; no external assets; client JS only toggles visibility. | `test_html_report.py` (active-content scan, CSP recomputation) |
| 15 | Medium | Corrupt/truncated archives and deeply nested parsers produced tracebacks or unbounded recursion. | Archive exceptions normalise to `TargetError`; flow/JSON/TOML nesting is bounded; a per-target safety net returns a scan error. | `test_loader.py`, `test_parsers.py`, `test_cli.py` |
| 16 | Medium | Record and directory floods, symlinked target roots, duplicate archive members. | Every visited entry counts against the work cap; a symlinked target root is refused; duplicate members are reported. | `test_loader.py` |
| 17 | Medium | Plugin hooks/MCP/components could escape the artifact or be silently ignored. | Declared paths resolve only inside the loaded tree; escapes and missing components are findings; both `.mcp.json` shapes are normalised; MCP values are not stored. | `test_plugin_model.py`, `test_plugin_rules.py` |
| 18 | Medium | Placeholder detection suppressed redaction of a real credential containing `example`, `demo`, or `test`. | Rule detection filters placeholders; evidence redaction includes them and always masks the match. | `test_secrets.py::test_credential_containing_example_is_redacted` |
| 19 | Medium | Marketplace pinning only covered `git-subdir`, missing `github`/`git` sources. | Remote marketplace source kinds require a full sha and an immutable ref; `repo` is captured as the source value. | `test_plugin_rules.py::test_github_marketplace_source_is_covered` |
| 20 | Low | Invisible-character escaping missed C0/C1 additions, soft hyphen, U+180E, and variation selectors. | `escape_unsafe` covers all Unicode `Cf` characters plus variation-selector ranges. | `test_secrets.py::EscapeUnsafeTests` |
| 21 | Low | A long document triggered `FRONTMATTER_TOO_LONG` even with a short frontmatter. | The limit applies only when the closing marker is not found within the allowed span. | `test_parsers.py::FrontmatterLimitTests` |
| 22 | Low | `--require-inventory` did not gate, and intent could bind to a name/path record without a hash. | The missing-inventory finding is HIGH; intent requires a matching inventory content hash; the canonical hash includes size and status. | `test_inventory.py::test_require_inventory_gates_on_a_clean_skill`, `test_intent.py` |
| 23 | Low | Status output could print an unescaped config-supplied path. | All dynamic status output passes `escape_unsafe`. | CLI review |
| 24 | Low | The parent-plugin manifest lookup read metadata above the audited root for local skills. | The CLI passes an explicit discovery-derived context; it no longer walks above the root. | code review, `test_real_skills.py` |
| 25 | Low | A live third-party domain was used in a fixture; `compileall` polluted fixtures with `__pycache__`. | Replaced with an RFC 5737 address; compile excludes `tests/fixtures/`. | fixture review, `Makefile`, CI |
| 26 | Low | Release workflow could publish without running tests; no provenance; actions are tag-pinned. | Release runs the suite and catalog check, uses a `release` environment, and attests wheel/sdist/zipapp provenance. SHA-pinning of actions remains a residual hardening item. | `.github/workflows/release.yml` |

## Verification evidence

Commands were run from `/home/ra/projects/SkillTriage` on 2026-10-26.

### Functional

- `make test` — **243 tests, OK** (1 skipped on the system interpreter because
  PyYAML is absent; the dev environment runs the cross-check).
- With the dev environment (`.[test]`): **243 tests, OK**, including the PyYAML
  cross-check. With `SKILLTRIAGE_TEST_PLUGINS=1`: the six real-corpus tests pass.
- `make compile` — clean; no `__pycache__` under `tests/fixtures/`.
- `python tools/gen_rules_doc.py --check` — catalog current at **107 rules**.
- `make zipapp` twice — identical SHA-256 across both builds; the `.pyz` runs and
  produces a 0600 HTML report.

### Security tooling

- `bandit -q -r src` — **0 issues** (two false positives suppressed inline with
  justification: a host classification set containing `0.0.0.0`, and HTML/CSS
  string construction flagged as SQL).
- `pip-audit --skip-editable` — **no known vulnerabilities** after upgrading
  `pip` in the audit environment. The runtime package has zero dependencies.
- The tool audits `examples/secure-skill` with `--fail-on high` and exits 0.

### Hostile-input coverage

- XSS payloads in evidence, a filename, and skill metadata → escaped in HTML and
  Markdown; an `HTMLParser` pass finds no active content in HTML; the Markdown
  code-span fence cannot be broken by backticks.
- CSP hashes recomputed from the emitted `<style>`/`<script>` blocks → match;
  headless Chromium logs no CSP violation.
- ESC, C0/C1, bidi, zero-width, BOM, soft hyphen, variation selectors, tag
  characters, lone surrogates, and out-of-range code points → visible escape
  sequences, no raw control characters.
- Self-suppression, a planted `./.skilltriage.toml`, and one-word context evasion →
  the default gate is unchanged.
- Deeply nested YAML/JSON/TOML, oversized integers, and deep Python attribute
  chains → bounded, no exception, later files still scanned.
- Corrupt/truncated zip/tar, zip-slip, zip bomb, tar traversal and decompression
  bomb, ZIP entry flood, symlinked target root, duplicate members, symlink/FIFO/
  device members, Windows drive/reserved names → handled or reported, no
  traceback.
- Single-line and multi-line private keys, URL userinfo, and URL query
  credentials → redacted in evidence and plugin metadata.

### Real corpus

`skilltriage scan --no-config` over the default installed locations:

- **67 targets** (43 plugin artifacts, 24 standalone skills)
- **0 scan errors, 0 rule errors**
- **9 gating findings, all on `personal/03-exploit-development`** — the user's
  own authorised offensive-security skill, which is the case the declared-intent
  policy exists for. It does not yet declare its intent; adding the declaration
  and a matching inventory record would downgrade the six technique rules while
  keeping the findings visible.
- **12 plugin-rule findings**: four genuine unpinned MCP launches
  (`firebase`, `playwright`, `serena`, `terraform`) and eight low-severity
  duplicate command names in a bundle that ships both Markdown and YAML
  representations. No plugin gated.
- The same corpus passed after the context guard and uninspected-content changes;
  no security-tool false positives re-appeared.

## Deliberate decisions

- **Bare `Bash` is not a broad-tool finding.** It is the normal grant for
  commands and agents; flagging it would gate most useful plugins. `Bash(*)` and
  other unscoped inner patterns are flagged, and scoped grants such as
  `Bash(ls *)` are not.
- **Binary images and documents remain lower severity.** Executables, bytecode,
  archives, and PDFs/Office documents gate; an ordinary image does not. The
  report still records that it was not inspected.
- **Vendor directories are reported at MEDIUM, not gating.** Re-run with
  `--include-vendor` to inspect them.
- **Inline suppressions are opt-in.** The feature remains for authored skills,
  but a third-party package cannot use it to silence itself.
- **Marketplace manifests above the plugin root are not read.** The plugin root
  is the boundary; the rule covers a root-level marketplace manifest.

## Residual risks

1. **Static only.** Hooks, tool calls, runtime file/network activity, and
   behaviour are not observed. A semantic or sandboxed layer is a separate,
   opt-in milestone.
2. **Hook approval detection is one hop deep.** It reads the hook command and the
   script directly referenced by `${CLAUDE_PLUGIN_ROOT}/…`; a script invoked by
   that script is not followed. Prompt-only hooks are recorded but not evaluated.
3. **Security-tooling context can be impersonated.** A high finding is downgraded
   by context words only when the artifact's path or identity marks it as
   security tooling. A malicious package can choose such a name. Declared intent
   with a matching inventory hash is the strong control, and every downgrade
   stays visible.
4. **Large-file drift is prefix-based.** Files above the read/hash cap use the
   hash of the bytes read plus size and status; a tail-only change beyond the cap
   is not detected. The truncation gates, so the gap is visible.
5. **Parent-directory symlinks.** A symlinked leaf target is refused, but a
   symlinked ancestor of a user-supplied path is resolved by the operating
   system. The user chose that path.
6. **YAML subset.** It is intentionally smaller than full YAML; unsupported
   constructs are reported as malformed metadata rather than interpreted.
7. **CSP via meta.** `frame-ancestors` and some directives are ignored in a
   `<meta>` policy; the report is a local file and is not served.
8. **No signature or trust store.** Signature presence is recorded, not
   verified. Dependencies are inspected, not resolved, so transitive CVEs are
   out of scope.
9. **Intent is policy, not proof.** It requires an allowlist and a matching
   inventory hash, and never removes a finding, but a user who allows an intent
   accepts the residual risk for that artifact class.
10. **False positives remain possible** around security documentation,
    integrations, and detector code. Baselines and suppressions are the intended
    controls.
11. **Release actions are tag-pinned, not SHA-pinned.** Requiring reviewers on
    the `release` environment and the provenance attestation reduce the risk;
    SHA-pinning actions and pinning build tool versions remain hardening items.
12. **No standalone marketplace audit and no registry-file read.** The plugin root
    is the boundary in v0.1.
13. **No coverage-guided fuzzing.** The suite has a fixed-seed hostile corpus and
    targeted adversarial tests.
14. **Platform coverage.** Tests ran on Linux (Python 3.14). Windows and macOS
    file modes, `O_NOFOLLOW` availability, ZIP/tar semantics, and atomic-replace
    behaviour differ and were not executed.
15. **A single huge directory is listed before the work cap applies.** Entries
    are sorted for deterministic output, so an extremely large single directory
    is materialised; the visited-entry cap stops the walk immediately after.
16. **A binary file without a code/config suffix is not text-scanned.** Script
    and configuration suffixes are decoded even with invalid bytes; an unknown
    binary without such a suffix is recorded (LOW, or HIGH for executables and
    archives) but its decoded text is not fed to the text rules.
17. **The ZIP EOCD entry-count pre-check can be spoofed.** The archive file-size
    cap, the post-materialisation entry budget, and the `MemoryError` guard bound
    the result.

## Not tested

- Windows and macOS filesystems and permission models (the Windows archive
  checks were unit-tested on Linux via path computation, not an executed write).
- A real GitHub Actions run, CodeQL analysis, the release workflow, or the
  provenance attestation (the workflows are written but not executed here).
- A browser matrix; only headless Chromium was checked.
- Coverage-guided or continuous fuzzing.
- Indirect hook scripts, prompt-only hook semantics, and real marketplace layouts
  above the plugin root.
- Real-world malicious packages beyond the synthetic fixtures.
- Signature verification, SBOM/CVE resolution, and any dynamic execution.
- Semantic intent expressed only in natural language.

## Independent review

The second reviewer was given the threat model and scope but not this document's
conclusions. It reported three critical, six high, eight medium, and several low
findings. All critical and high findings were reproduced, fixed, and covered by
regression tests; the medium findings were fixed except the deliberate choices
above; the low findings were fixed except the residual hardening items listed
here. Its two notable disagreements with the author's design were bare `Bash`
and security-tooling context; both are recorded under **Deliberate decisions**
rather than silently dismissed.

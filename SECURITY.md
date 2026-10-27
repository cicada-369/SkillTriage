# Security policy

## Reporting a vulnerability

Do not open a public issue for a vulnerability in `skilltriage`. Use the
repository's private **Security → Report a vulnerability** advisory flow at
<https://github.com/cicada-369/SkillTriage/security/advisories/new>. Include:

- affected version or commit,
- a minimal reproducer,
- the impact (for example, a crafted archive escaping extraction, a parser
  denial of service, or a report injecting terminal control characters),
- any suggested fix.

Please allow a reasonable disclosure window before publishing details.

## Supported versions

`0.1.x` is the current development line. Security fixes land on `main` and are
released as patch versions.

## Threat model

`skilltriage` reads attacker-controlled files. The tool's job is to describe them
without becoming the victim. The following properties are deliberate:

| Property | Implementation |
|---|---|
| No target execution | No `eval`, `exec`, dynamic import, shell, or subprocess of target content. |
| No network | No command performs network I/O, including URL references and the HTML report. |
| No symlink following | Directory walk uses `lstat`; symlinks are recorded and skipped. A symlinked target root is refused. |
| Bounded reads | Per-file, total-byte, and file-count limits, including symlinks and device records; large files are truncated and reported. |
| Safe metadata parsing | A YAML subset parser that cannot construct objects; unsafe tags/anchors are reported, never resolved. JSON uses duplicate-key detection; TOML uses `tomllib`. Flow and JSON/TOML nesting are bounded. |
| Safe archives | Zip-slip, absolute paths, drive paths, traversal, symlinks, hardlinks, devices, FIFOs, encrypted members, entry-count, uncompressed-size, and compression-ratio limits. Tar headers are read lazily; archive failures become scan errors. |
| No TOCTOU-friendly open | Regular files are opened with `O_NOFOLLOW` and `O_NONBLOCK` where available, followed by an `fstat` type check. |
| Secret redaction | Detected credentials are masked in evidence; every report field is escaped for control, bidi, and invisible characters before terminal or HTML rendering. |
| Report confidentiality | Reports, baselines, and inventory files are written atomically with owner-only permissions (`0600`), without a predictable temporary name. |
| No self-suppression | Inline `skilltriage:disable` comments inside the artifact are ignored unless the operator passes `--trust-inline-suppressions`. |
| No target-controlled policy | Only the user config is implicit. A project config requires `--config`, so a planted `./.skilltriage.toml` cannot weaken the gate. |
| Uninspected content gates | Truncation, executable/bytecode content, nested archives, skipped archive members, and budget-incomplete scans are HIGH/HIGH. |
| Intent is bound to bytes | A declared intent downgrades only when policy allows it and the inventory content hash matches the current tree. |
| Determinism | Findings are sorted and fingerprinted without line numbers, so repeated scans are comparable. |

## Safe operation

- Run as an unprivileged user. The tool does not need root.
- Audit untrusted packages from a directory that is not the package directory;
  prefer the installed launcher, which sets `PYTHONSAFEPATH=1`.
- Do not pipe a report containing untrusted evidence into a terminal that
  interprets escape sequences without review. Text output escapes control
  characters; JSON is inert.
- Treat baselines as reviewed risk acceptance, not as a way to silence a
  surprise. Re-run scans after every artifact change.
- Do not enable `--trust-inline-suppressions` for third-party artifacts. Use a
  baseline after review instead.
- Do not point the tool at a directory containing secrets you do not want in a
  report. Evidence is redacted, but file paths and metadata remain visible.
- A declared intent is not a trust decision. Review the artifact before adding
  it to the inventory and before allowing its intent; every downgraded finding
  remains visible.

## Supply chain

The runtime has **zero third-party dependencies**. CI installs the package and
the `test`/`dev` extras (PyYAML, coverage, bandit, pip-audit) only to run the
cross-check and security jobs; none of them are imported by the tool. The
generated zipapp contains only the `skilltriage` package and a top-level
`__main__.py`.

The release workflow runs the full suite and catalog check before building,
writes a `SHA256SUMS` file, and requests build-provenance attestations for the
wheel, sdist, and zipapp. The tag must match the package and changelog versions.
The release job uses a `release` environment so required reviewers can be
configured in the repository settings.

## Known limitations with security impact

- Static analysis cannot observe runtime behaviour or prove safety.
- Signature presence is not verified; no trust store is consulted.
- Dependencies are inspected but not resolved, so transitive CVEs are out of
  scope.
- A plugin is audited as its own root. Files above that root, and registry files
  such as `installed_plugins.json`, are not read. Hook approval detection
  follows the hook command and the script it directly references; an indirectly
  invoked script is a coverage gap.
- Declared intent is attacker-controlled. It is honoured only with an explicit
  policy allowlist and an inventory record, and it never removes a finding.
- External URLs are classified but never fetched, so content behind a reference
  is not reviewed.
- Heuristic context scoring can still be gamed. Outside a documentation path,
  critical findings are never downgraded and high findings are downgraded only
  when the artifact identifies itself as security tooling; a malicious package
  can impersonate that identity. Declared intent with a matching inventory hash
  is the strong control, and every downgrade stays visible.
- Files above the hash/read cap use a prefix hash plus size and status for drift
  detection, so a tail-only change beyond the cap is not detected. The scan
  reports the truncation, which now gates by default.
- Inline suppressions are ignored by default; an artifact cannot silence its own
  findings unless the operator opts in.
- The YAML subset is intentionally smaller than full YAML. Unsupported
  constructs are reported as malformed metadata rather than interpreted.

## Hardening the tool further

Useful next steps, in priority order:

1. Signature and content-hash verification against a configured trust store.
2. An optional semantic pass with explicit data-handling consent.
3. An optional containerised dynamic runner with network-none and syscall
   tracing.
4. Continuous fuzzing of the parser and archive loader (the suite currently has
   a deterministic hostile corpus, not a coverage-guided fuzzer).
5. A policy-as-code adapter for enterprise pipelines.

# Contributing

Thanks for helping improve `skilltriage`. The project is deliberately small,
dependency-free, and honest about what static analysis can prove.

## Development setup

```bash
python3 -m venv .venv
. .venv/bin/activate
python -m pip install -e '.[test]'
make test
```

`make compile` runs `compileall`; `make rules-doc` regenerates the catalog;
`make zipapp` builds the single-file distribution. The `test` extra adds PyYAML
for the parser cross-check; the `dev` extra adds coverage, bandit, and pip-audit
for local security checks.

## Adding or changing a rule

1. Pick the module under `src/skilltriage/rules/` that matches the risk family.
2. Define a `Rule` with a stable ID (`AST<xx>-SHORT-NAME`), the OWASP control,
   base severity, base confidence, description, remediation, CWEs, and tags.
3. Write a `check(ctx)` function that emits findings through `ctx.emit`.
   Emit evidence from the matched line, not a reconstructed guess.
4. Add at least one positive fixture and one negative fixture under `tests/`.
   Tests must demonstrate the finding *and* that a benign lookalike is not
   gating.
5. If the rule should feed a correlation, call `ctx.signal` only when the
   emitted finding's confidence is not `LOW`. Context-downgraded documentation
   matches must not manufacture a chain.
6. Regenerate the catalog:

   ```bash
   python tools/gen_rules_doc.py
   ```

7. Run the full suite and the local system scan:

   ```bash
   make test
   PYTHONSAFEPATH=1 PYTHONPATH=src python3 -m skilltriage scan --format text
   ```

### Plugin rules

Plugin rules live in `rules/plugins.py` and must return immediately unless
`ctx.is_plugin`. Keep them precise: a hook or MCP finding that fires on a benign
integration is worse than a gap. When a rule needs a component path, emit it at
the component file; do not aggregate component tool grants into
`NormalizedSkill.permissions`, which would change skill-target results.

### Rule quality bar

- **No unbounded regex.** Avoid nested quantifiers and catastrophic
  backtracking. Prefer line-scoped patterns with explicit bounds.
- **No execution, ever.** Do not import, evaluate, or run target content.
- **No network.** Do not fetch a URL, resolve a package, or call an API.
- **Redact.** Evidence must not reproduce a credential; `mask_evidence` is the
  default path.
- **Explain the uncertainty.** `confidence` is part of the rule; use `LOW` when
  a match needs human interpretation.
- **Do not hide.** Context scoring may lower severity; it must not delete a
  finding. Inline suppressions are opt-in and visible in JSON; baselines are the
  reviewed-acceptance mechanism.
- **Do not let artifact words defeat the gate.** Outside a documentation path,
  a CRITICAL finding is never downgraded, and a HIGH finding is downgraded only
  when the artifact identifies itself as security tooling.

### False-positive policy

A rule that fires on a security guide's example is not "working"; it is noise.
Use the shared context scorer rather than adding ad-hoc exclusions:

- documentation paths and fenced plain-text/markdown examples,
- warning sentences (`never`, `do not`, `example`, `malicious`, ...),
- code comments,
- detector/scanner/auditor/test filenames and detection language,
- plugin documentation files (`README.md`, `ACCESS.md`, `SECURITY.md`, ...).

A known API host used with a templated credential (`bot${TOKEN}`) is a
configured integration, not an embedded endpoint; report it at lower severity
and let credential-plus-network correlation escalate the dangerous case.

If a whole category is still too noisy, lower its base severity or confidence
and let correlation escalate the dangerous combinations. Never add a blanket
allowlist based on a skill's name; attackers choose names.

## Tests

The suite uses only `unittest`. Tests must pass on Python 3.11-3.14.

- `tests/unit/` — parsers, loader, rules, plugin model and rules, intent,
  policy, inventory, reports (including HTML injection), regression snapshots,
  cases, discovery, docs.
- `tests/integration/` — CLI, local installed skills and plugins.
- `tests/fixtures/` — inert synthetic packages. Never commit live credentials,
  routable C2 addresses, or executable malware. Use reserved domains such as
  `cdn.invalid` and RFC 5737 addresses such as `203.0.113.10`, and label the file
  as a fixture.

When a fixture is modified in a test, copy it to a temporary directory first.
Tests must not mutate checked-in files.

## Documentation

- `README.md` — user-facing.
- `docs/RULES.md` — generated; do not edit by hand.
- `docs/OWASP-MAPPING.md` — taxonomy mapping and its limits.
- `docs/ARCHITECTURE.md` — internals and invariants.
- `docs/PLUGINS.md` — plugin adapter coverage and boundaries.
- `docs/INTENT.md` — declared-intent policy.
- `docs/security/review-v0.1.md` — security review evidence and residual risk.
- `SECURITY.md` — threat model and reporting.

OWASP text is CC BY-SA 4.0. Do not copy paragraphs from the upstream project;
write original descriptions and cite the control.

## Style

- Python 3.11+ syntax, `from __future__ import annotations`, standard library.
- Four-space indentation, type hints on public functions, no third-party
  formatting dependency.
- Keep modules focused; a rule module owns one risk family.
- Prefer explicit data structures over clever metaprogramming.

## Commits and pull requests

- Keep a change focused; include tests and regenerated docs.
- Describe the risk being detected and the false-positive trade-off.
- For a new rule, state the OWASP control and the evidence shape.
- By contributing, you agree your contribution is licensed under
  Apache-2.0, matching the project.

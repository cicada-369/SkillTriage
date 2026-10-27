That gives us a clear project boundary. I would build Agent Skill Tester as a dedicated security validation platform for agent skills and plugins, with MCP server validation reserved for a separate future project.

The important architectural decision is to make skills and plugins separate validation adapters that share a common security engine. They have overlapping risks, but their packaging, execution models, permissions, and installation mechanisms can differ.

## 1. Define the project scope

In scope: Agent skills

V1

- Instruction files and skill manifests
- Bundled scripts, resources and dependencies
- Prompt injection and malicious instructions
- Unauthorized file, process and network activity
- Pre-install scanning and post-install integrity checks

In scope: Plugins

V1

- Plugin packages, manifests and configuration
- Source code, executable components and dependencies
- Requested permissions and external integrations
- Data handling, authentication and secret exposure
- Plugin-specific installation and execution tests

Out of scope: MCP server validator

Future project

- MCP protocol and transport security
- Tool discovery and invocation validation
- Server authentication and authorization
- MCP-specific trust and isolation controls

Keep the core engine extensible, but do not build MCP-specific scanners or workflows into this release.

## 2. Proposed architecture

## Agent Skill Tester

Cross-platform security validation

Skill adapter

Instructions, scripts, resources, manifests

Plugin adapter

Packages, permissions, dependencies, entry points

Shared security engine

&#x20;Static analysis

&#x20;Sandbox execution

&#x20;Policy enforcement

&#x20;Integrity monitoring

&#x20;LLM security tests

&#x20;Risk correlation

Dashboard and reports

Findings · Evidence · Risk · Remediation · Audit history

## 3. The validation workflow

The same workflow should apply to both skills and plugins wherever technically possible.

| Stage               | What happens                                                              |
| ------------------- | ------------------------------------------------------------------------- |
| 1. Intake           | Accept a directory, archive or supported installed package.               |
| 2. Identification   | Identify artifact type, framework, entry points and dependencies.         |
| 3. Static analysis  | Scan code, instructions, manifests, secrets and declared capabilities.    |
| 4. Sandbox analysis | Execute supported components in a disposable, restricted environment.     |
| 5. Security tests   | Test data access, prompt injection, tool misuse and prohibited behavior.  |
| 6. Risk evaluation  | Correlate evidence and apply configurable policies.                       |
| 7. Reporting        | Generate findings, evidence, remediation and coverage information.        |
| 8. Integrity checks | Compare installed artifacts with previously approved hashes and metadata. |

Dynamic testing should be optional for artifacts that cannot safely or meaningfully execute. A skipped test must appear as `UNKNOWN`, not `PASS`.

## 4. Initial release requirements

I would carry forward your existing Agent Skill Tester direction with these implementation targets:

- Platform: Cross-platform.
- Focus: Security-first, with functional testing where applicable.
- Execution: Sandbox-based; static analysis must not execute untrusted code.
- Reporting: Dashboard, with machine-readable results available for automation.
- Validation timing: Before installation and after installation.
- Safety: No automatic installation, deletion or system modification.
- Testing: Unit tests, adversarial fixtures, sandbox containment tests and end-to-end validation.
- Deliverables: Source code, installation instructions, validation procedure, security limitations, tests and a downloadable project archive.

I would make `PASS`, `WARN`, `BLOCK` and `UNKNOWN` the standard outcome states. Policy violations should be able to block an artifact even if a numerical risk score is low.

## 5. One remaining decision before implementation

Skills and plugins are not standardized across all agent platforms. To avoid building a validator around the wrong package formats, we should choose the initial compatibility targets.

## Choose the first supported formats

Select multiple formats. These choices define the first adapters, not permanent product limitations.

Agent skill formats

Agent Skills standard

Claude Code skills

OpenCode skills

Other / custom skill folders

Plugin formats

OpenCode plugins

Claude Code plugins

Python plugins / packages

Node.js plugins / packages

Other / custom plugin formats

Execution strategy

Static scanning first; sandbox in a later milestone

Static scanning and sandbox testing in the initial release

Primary interface

Dashboard + CLI

CLI + HTML reports

Confirm scope and proceed

My preference is to keep the shared engine small, build reliable adapters for the formats you actually use, and validate the validator itself against deliberately malicious test fixtures before trusting it with real third-party skills or plugins.

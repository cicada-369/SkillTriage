# OWASP Agentic Skills Top 10 mapping

`skilltriage` maps every finding to one of the ten controls in the
[OWASP Agentic Skills Top 10](https://github.com/OWASP/www-project-agentic-skills-top-10):

| ID | Risk | Severity in the OWASP project |
|---|---|---|
| AST01 | Malicious Skills | Critical |
| AST02 | Supply Chain Compromise | Critical |
| AST03 | Over-Privileged Skills | High |
| AST04 | Insecure Metadata | High |
| AST05 | Untrusted External Instructions | High |
| AST06 | Weak Isolation | High |
| AST07 | Update Drift | Medium |
| AST08 | Poor Scanning | Medium |
| AST09 | No Governance | Medium |
| AST10 | Cross-Platform Reuse | Medium |

The identifiers are attributable to that project. The rule descriptions,
rationales, and remediation text in this repository are original. See
[`NOTICE`](../NOTICE).

## What the static layer checks

| Control | Static evidence skilltriage can produce | Representative rules |
|---|---|---|
| **AST01** | Download/execute pipelines, reverse-shell patterns, destructive commands, persistence, credential-path access, exfiltration endpoints, identity writes, hidden/encoded payloads, instruction manipulation, cross-signal chains | `AST01-DOWNLOAD-EXEC`, `AST01-REVERSE-SHELL`, `AST01-EXFIL-CHAIN`, `AST01-ASCII-SMUGGLING`, `AST01-BASE64-PAYLOAD`, `AST01-PROMPT-OVERRIDE` |
| **AST02** | Unpinned and URL/VCS dependencies, missing lockfiles, npm lifecycle scripts, `setup.py` execution, executable hooks/MCP config, unpinned MCP package launches, cleartext MCP transport, missing signature/hash | `AST02-UNPINNED-DEPENDENCY`, `AST02-INSTALL-SCRIPT`, `AST02-CONFIG-AS-CODE`, `AST02-PLUGIN-MCP-UNPINNED-EXEC`, `AST02-PLUGIN-MCP-CLEARTEXT`, `AST02-NO-PROVENANCE` |
| **AST03** | Declared shell/network/filesystem/tool scope, wildcards, identity-file writes, credential paths, risk-tier mismatch, declared-vs-observed contradictions, broad tool grants including per-component grants | `AST03-SHELL-UNRESTRICTED`, `AST03-IDENTITY-WRITE-PERMISSION`, `AST03-RISK-TIER-MISMATCH`, `AST03-DECLARED-VS-OBSERVED`, `AST03-PLUGIN-BROAD-TOOL-GRANT` |
| **AST04** | Missing/duplicate/unsafe metadata, unsafe YAML tags and anchors, wrong field types, invisible/control characters, mixed-script names, import-time side effects, brand impersonation, escaping or missing plugin components, duplicate component names, hook scripts that are not shipped, unknown declared intent | `AST04-UNSAFE-YAML-TAG`, `AST04-DUPLICATE-KEY`, `AST04-HOMOGLYPH-NAME`, `AST04-PY-IMPORT-SIDE-EFFECT`, `AST04-PLUGIN-COMPONENT-ESCAPE`, `AST04-PLUGIN-COMPONENT-MISSING`, `AST04-PLUGIN-COMPONENT-DUPLICATE`, `AST04-PLUGIN-HOOK-MISSING-SCRIPT`, `AST04-UNKNOWN-INTENT` |
| **AST05** | External URL inventory, mutable/paste/tunnel/raw-IP hosts, instruction-bearing references, missing content pins, transitive-looking reference sets | `AST05-UNTRUSTED-HOST`, `AST05-FETCH-INSTRUCTIONS`, `AST05-UNPINNED-REFERENCE` |
| **AST06** | Symlink escape, setuid/setgid, device/FIFO files, privileged or host-mode containers, disabled host controls, binds to all interfaces, hook commands that escape the plugin root | `AST06-SYMLINK-ESCAPE`, `AST06-PRIVILEGED-CONTAINER`, `AST06-DISABLE-SECURITY`, `AST06-BIND-ALL`, `AST06-PLUGIN-HOOK-PATH-ESCAPE` |
| **AST07** | Mutable version strings, malformed content hashes, auto-update, hot reload, inventory hash drift, mutable marketplace source pins | `AST07-MUTABLE-VERSION`, `AST07-AUTO-UPDATE`, `AST07-BASELINE-DRIFT`, `AST07-PLUGIN-MARKETPLACE-UNPINNED` |
| **AST08** | Uninspected binaries/bytecode/archives, hidden files, padding/truncation evasion, high-entropy blobs, vendor scope gaps, incomplete scans | `AST08-BINARY-ARTIFACT`, `AST08-PADDING-EVASION`, `AST08-ENCODED-BLOB`, `AST08-SCAN-INCOMPLETE` |
| **AST09** | Risk tier, owner, approval, scan status, audit logging, inventory presence, hooks that approve or bypass permission prompts | `AST09-NO-RISK-TIER`, `AST09-NO-APPROVAL`, `AST09-NOT-IN-INVENTORY`, `AST09-PLUGIN-HOOK-APPROVAL` |
| **AST10** | Multiple manifests, security-property loss, inconsistent permissions, absent universal manifest | `AST10-PROPERTY-LOSS`, `AST10-INCONSISTENT-PERMISSIONS`, `AST10-NO-UNIVERSAL-FORMAT` |

Plugin-specific rules use the same controls; their coverage and boundaries are
described in [`PLUGINS.md`](PLUGINS.md). The complete, always-current list is in
[`RULES.md`](RULES.md), generated from the rule registry.

## What the static layer cannot establish

| Control | Gap |
|---|---|
| AST01 | Pure natural-language malice, context-dependent triggers, and runtime behaviour. |
| AST02 | Transitive dependency resolution, CVE matching, publisher identity, real signature verification. |
| AST03 | Whether runtime enforcement matches the declaration; actual tool-call arguments. |
| AST04 | Loader-specific parser behaviour beyond the formats modelled here. |
| AST05 | The content behind a URL; rug-pulls after review; server-side targeting. |
| AST06 | Effective sandboxing, seccomp/AppArmor state, localhost authentication. |
| AST07 | Patch status, advisory subscriptions, update signatures. |
| AST08 | Semantic intent; multimodal injection; encrypted or remote payloads. |
| AST09 | Inventory truth outside `skilltriage`; approval workflow authenticity. |
| AST10 | Runtime equivalence across platforms; platform-specific enforcement. |

These gaps are printed in every report's **Coverage & limitations** section, so a
clean result is never presented as a safety verdict.

## Relationship to the OWASP scanner guidance

The OWASP `skill-scanner-integration.md` document recommends a pipeline rather
than a single scanner. `skilltriage` occupies the deterministic static layer and
emits SARIF with per-file SHA-256 hashes and a `layer` property, so its results
can be joined with a drift scanner, a credential scanner, or a behavioural
runner. It does not claim to replace those layers, and it deliberately does not
treat a single scan result as a gate on its own.

## Fixture corpus note

The OWASP project publishes a proposal for AST-mapped runtime governance
vectors. Those vectors describe admission and outcome records, not static
package properties, so `skilltriage` does not claim conformance with them. The
`AST09` rules here report governance metadata and inventory presence; they do
not implement an admission gate or a bilateral receipt scheme.

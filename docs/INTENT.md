# Declared intent

Some skills and plugins intentionally contain attack tooling: exploit
development, payload generation, detection engineering, or teaching material.
A static scanner cannot distinguish that from malice by pattern alone.

A declaration lets the author state the purpose. It is **not** a suppression:

1. The declaration alone changes nothing.
2. Policy must explicitly allow the value.
3. The artifact must have an inventory record.
4. Matching findings are downgraded, never removed, and never gate.

## Declaration

Put the intent under `metadata.skilltriage.intent` in the primary manifest:

```yaml
---
name: exploit-development
description: Authorized exploit development helpers.
version: 1.0.0
metadata:
  skilltriage:
    intent: offensive-security
---
```

The same key works in `skill.json`, `plugin.json`, or a universal manifest,
because the normaliser reads the primary manifest's `metadata` block.

Recognised values:

- `offensive-security`
- `security-research`
- `education`
- `detection-engineering`

Any other value is reported as `AST04-UNKNOWN-INTENT` and is never honoured.

## Policy

Add the value to `~/.config/skilltriage/config.toml` or `./.skilltriage.toml`:

```toml
[intent]
allow = ["offensive-security"]
```

Or pass it for one run:

```bash
skilltriage scan --allow-intent offensive-security ...
```

The default is empty. Configuration and the flag are unioned.

## Inventory requirement

The inventory record's canonical content hash must also match the current
artifact. That proves the operator approved these bytes, not merely a name, path,
or intent string:

```bash
skilltriage scan --root ~/.claude/skills --inventory --update-inventory
skilltriage scan --root ~/.claude/skills --inventory \
  --allow-intent offensive-security
```

If the declaration is allowed but there is no record, the record has no hash, or
the hash does not match the current bytes, nothing is downgraded and the
coverage notes say which condition failed. A changed artifact therefore loses
the downgrade until it is reviewed and re-inventoried; the change is also
reported as drift.

## Effect

Only rules marked with the matching technique family are downgraded. For
`offensive-security` these are:

- `AST01-REVERSE-SHELL`
- `AST01-DOWNLOAD-EXEC`
- `AST01-DYNAMIC-EXEC`
- `AST01-ENCODED-EXEC`
- `AST06-PRIVILEGED-CONTAINER`
- `AST01-SSH-REMOTE`

The effect is one severity step down, `LOW` confidence, and
`intent_matched: true`. The finding stays in text, Markdown, HTML, JSON, and
SARIF, and the report names the intent and the number of downgraded findings.
It does not gate.

Credential access, exfiltration, persistence, identity writes, secret logging,
approval bypass, permission over-grant, and plugin hook/MCP findings are **not**
downgraded. Those remain gating regardless of intent.

## Why the inventory gate exists

A declaration lives inside the artifact, so a malicious author can write one.
Requiring a matching inventory hash means the operator has seen and approved
these exact bytes. Combined with a visible banner and a narrow rule family, the
declaration cannot silently silence a scan.

If an artifact changes, its inventory hash changes and the next scan reports
drift and withholds the downgrade, so the approval does not survive a content
update.

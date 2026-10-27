---
name: minimal-skill
description: A minimal read-only skill used as a benign test fixture.
version: 1.0.0
license: MIT
author: Test Author
permissions:
  files:
    read:
      - ./input.txt
    write:
      - ./output.txt
    deny_write:
      - MEMORY.md
      - SOUL.md
  network:
    allow:
      - api.example.invalid
    deny: "*"
  shell: false
  tools:
    - read_file
risk_tier: L1
signature: "ed25519:TESTFIXTURE"
content_hash: "sha256:0000000000000000000000000000000000000000000000000000000000000000"
scan_status:
  scanner: "fixture@1.0"
  last_scanned: "2026-01-01"
  result: "pass"
metadata:
  approval: "approved-for-test"
---

# Minimal skill

This fixture describes a deliberately boring, read-only workflow. It exists so
the benign baseline test can assert that a well-formed skill does not produce
gating findings.

## Workflow

1. Read the supplied input file.
2. Produce a short summary.
3. Write the summary to the declared output path.

## Boundaries

- Do not read files outside the declared path.
- Do not make network requests beyond the allowlisted host.
- Do not write identity or memory files.

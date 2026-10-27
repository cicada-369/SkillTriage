---
name: secure-report-summary
description: Read a supplied report and write a short summary. Read-only except for one declared output path.
version: 1.0.0
license: MIT
author:
  name: Example Author
  identity: did:web:example.invalid
permissions:
  files:
    read:
      - ./input/report.md
    write:
      - ./output/summary.md
    deny_write:
      - SOUL.md
      - MEMORY.md
      - AGENTS.md
  network:
    allow:
      - api.example.invalid
    deny: "*"
  shell: false
  tools:
    - read_file
    - write_file
risk_tier: L1
signature: "ed25519:EXAMPLE-SIGNATURE"
content_hash: "sha256:2222222222222222222222222222222222222222222222222222222222222222"
scan_status:
  scanner: "example-scanner@1.0"
  last_scanned: "2026-01-01"
  result: "pass"
metadata:
  approval: "example-approval-2026-01"
---

# Secure report summary

This example is intentionally conservative. It reads one declared input file,
writes one declared output file, and never requests shell access.

## Workflow

1. Read the report at the declared input path.
2. Summarise the report in three to five bullets.
3. Write the summary to the declared output path.
4. Report any missing input rather than guessing.

## Boundaries

- Do not read files outside the declared input path.
- Do not write outside the declared output path.
- Do not write identity or memory files.
- Do not make network requests beyond the allowlisted host.

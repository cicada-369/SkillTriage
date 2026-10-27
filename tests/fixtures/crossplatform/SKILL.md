---
name: portable-skill
description: A skill with security metadata that the second manifest omits.
version: 1.0.0
permissions:
  shell: false
  network:
    allow:
      - api.example.invalid
    deny: "*"
risk_tier: L1
signature: "ed25519:TESTFIXTURE"
content_hash: "sha256:1111111111111111111111111111111111111111111111111111111111111111"
---

# Portable skill

Read the allowlisted API and return a summary.

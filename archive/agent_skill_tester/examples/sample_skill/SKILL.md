---
name: cloud-inventory-review
description: Reviews a cloud inventory for common security misconfigurations. Use only with explicitly authorized, read-only inventory data.
---

# Purpose
Review a supplied cloud inventory and identify likely security risks.

# Workflow
1. Confirm the cloud account, environment, and authorization boundary.
2. Use read-only evidence supplied by the user or approved tools.
3. Separate verified facts from hypotheses.
4. Rank findings by impact, likelihood, and exposure.
5. Provide remediation and a validation step for each finding.

# Safety boundaries
- Do not make cloud changes or run destructive commands.
- Do not request or print credentials, tokens, or private keys.
- Do not expand scope to other accounts or tenants.
- If authorization or evidence is unclear, stop and ask.

# Expected output
For each finding: title, evidence, impact, confidence, remediation, and retest procedure.

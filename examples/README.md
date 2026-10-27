# Examples

Two deliberately small packages:

- **`secure-skill/`** — a well-formed, read-only skill that should pass the
  default gate.
- **`risky-skill/`** — a synthetic package containing a download-and-execute
  pattern and an over-privileged manifest. It exists to demonstrate a failing
  report. It is never executed by skilltriage, and its domain is reserved and
  non-routable.

Run them:

```bash
skilltriage audit examples/secure-skill
skilltriage audit examples/risky-skill --format markdown
```

The risky example is intentionally not safe to install. Do not treat it as a
template.

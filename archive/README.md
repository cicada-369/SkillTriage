# Archived prototypes

These directories are earlier iterations of the same idea. They are kept for
history only and are **not** part of the `skilltriage` package, the test suite,
or the supported surface.

| Directory | What it was |
|---|---|
| `agent_skill_tester/` | A 709-line static MVP (`skilltester`) covering structure, shell patterns, and test-case shape. Superseded by the main engine. |
| `agent-skill-tester/` | A design memo for a broader skill/plugin tester plus a 421-line single-file scanner (`skillscan-claude.py`). Its sandbox/behavioural ideas are the roadmap for a later milestone, not this release. |

They are not maintained. Do not run them on untrusted input; they predate the
safe loader and report-hardening work in the main tree.

# Plugin coverage

`skilltriage` audits a Claude Code plugin root as **one artifact**. Its bundled
skills are components of that artifact, not separate targets.

## Supported layout

A directory is recognised as a plugin when it contains
`.claude-plugin/plugin.json`. The adapter inspects:

| Path | What is extracted |
|---|---|
| `.claude-plugin/plugin.json` | Name, version, description, author, licence, declared component paths. |
| `.claude-plugin/marketplace.json` | The marketplace entry matching the plugin: source, ref, sha, category. |
| `hooks/hooks.json` | Event, matcher, hook type, command, timeout, async flag, `if` condition. |
| `.mcp.json` | Server name, transport, command, args, environment **keys**, URL, header **names**. Both the wrapped `{"mcpServers": {...}}` and the bare-map shape are accepted. |
| `commands/**/*.md`, `commands/**/*.yaml` | Command components, including Markdown frontmatter and whole-file YAML commands. |
| `agents/**/*.md` | Agent components and their `allowed-tools`, `tools`, and `model`. |
| `skills/*/SKILL.md` | Bundled skills. Only `skills/<name>/SKILL.md` counts; deeper `SKILL.md` files are treated as references. |
| `.claude/commands`, `.claude/agents`, `.claude/skills` | The same components when a plugin keeps them under `.claude/`. |

Declared paths are resolved against the loaded tree. A declared path that walks
up (`..`), is absolute, or does not exist is reported rather than read. Symlinked
files are recorded and never followed.

## One target, not N

`scan` (and `audit` on a plugin root) emits one target for the plugin. Its
coverage block reports how many commands, agents, skills, hooks, and MCP servers
were inspected. `scan-system` is the legacy view: it lists each bundled
`SKILL.md` separately. Use `discover --artifacts {skills,plugins,both}` to see
what would be selected.

## Plugin rules

| Rule | AST | What it catches |
|---|---|---|
| `AST09-PLUGIN-HOOK-APPROVAL` | AST09 | A `PreToolUse`/`PermissionRequest` hook, or the script it directly references, returns an allow/approve decision. |
| `AST06-PLUGIN-HOOK-PATH-ESCAPE` | AST06 | A hook command walks up from `${CLAUDE_PLUGIN_ROOT}`, or uses an absolute, home (`~`, `$HOME`), UNC, or drive-letter path. |
| `AST04-PLUGIN-HOOK-MISSING-SCRIPT` | AST04 | A hook references a script that is not in the package. |
| `AST02-PLUGIN-MCP-UNPINNED-EXEC` | AST02 | An MCP server launches `npx`/`uvx`/`pipx`/a container image without an exact version or digest. |
| `AST02-PLUGIN-MCP-CLEARTEXT` | AST02 | An MCP server uses a non-loopback `http://` URL. |
| `AST04-PLUGIN-COMPONENT-ESCAPE` | AST04 | `plugin.json` declares a component outside the plugin root. |
| `AST04-PLUGIN-COMPONENT-MISSING` | AST04 | A declared component path resolves to nothing in the package. |
| `AST04-PLUGIN-COMPONENT-DUPLICATE` | AST04 | Two components of the same kind share a name. |
| `AST07-PLUGIN-MARKETPLACE-UNPINNED` | AST07 | A remote marketplace source (`git-subdir`, `github`, `git`, ...) has a mutable ref or a missing/short sha. |
| `AST03-PLUGIN-BROAD-TOOL-GRANT` | AST03 | A command or agent grants `*`, `all`, `full_access`, `admin`, or an unscoped `Bash(*)`. Bare `Bash` and scoped grants such as `Bash(ls *)` are not flagged. |

All other rules still run over the plugin's text and code. In particular,
script patterns, secrets, obfuscation, external references, and file safety
checks apply to every file in the package.

## Boundaries and deliberate exclusions

- **No standalone marketplace target.** A marketplace repository is not audited
  as a whole in v0.1. Its `marketplace.json` is evaluated only when it sits at
  the audited plugin root, and only for the entry matching that plugin.
- **No registry files above the root.** `installed_plugins.json`,
  `known_marketplaces.json`, and parent directories are not read.
- **No runtime observation.** A hook is not executed and an MCP server is not
  started. Approval-injection detection reads the hook command and the script it
  directly references; a script invoked indirectly is a coverage gap. Hooks
  without a command (for example prompt-only hooks) are recorded but not
  evaluated in v0.1.
- **MCP values are not stored.** Environment variables and header values are
  reduced to key names in the model. Secret rules still scan the raw text and
  redact any detected credential in evidence.
- **Documentation is not code.** A plugin root's `README.md`, `ACCESS.md`,
  `SECURITY.md`, and similar files are scored as documentation, so a link or a
  mention in them is reported at lower confidence rather than gating.

## Suppressing a reviewed plugin finding

Use a baseline for a reviewed plugin, or an inline suppression in the file that
carries the finding:

```bash
skilltriage scan ./plugin --write-baseline .skilltriage-baseline.json
skilltriage scan ./plugin --baseline .skilltriage-baseline.json
```

Inline `skilltriage:disable` comments are ignored by default because they live
inside the artifact. If you author or trust the plugin, pass
`--trust-inline-suppressions`:

```json
{"skilltriage": "disable AST07-PLUGIN-MARKETPLACE-UNPINNED because this entry is local-only"}
```

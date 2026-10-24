# AGENTS.md

This repository uses **[Project Brain](https://github.com/OoneBreath/project-brain)** for persistent, navigable memory across AI coding agents (Claude Code, OpenCode, Codex, Cursor, Aider, etc.).

## Session Startup (Required)
Before doing any work in this repo, read the brain map first:

1. **Prefer** `.project-brain/index.compact` — generated, token-lean, and what hooks inject
2. **Fallback** to `.project-brain/index.md` if `index.compact` is missing/stale
3. **Only drill down** into `projects/<project>/<topic>.md` files when you actually need their details

## Conventions
- **Index is the budget** — keep it to one line per item. Put details in topic files.
- **Status matters** — `✓ verified`, `✓ done`, `⚠ in-progress`, `✗ failed`, `⨯ superseded`. Never silently redo `✓ verified` or `✓ done` work. Ask first.
- **Version, don't overwrite** — when replacing an approach, keep history in the topic file.
- **Trust matters** — respect `trust: human | ai-inferred | pref`. Treat `ai-inferred` as unconfirmed.
- **Hard rules** — honor any `! never:` lines in the index (brain-wide or per-project).

## Working With The Brain
- **Recall**: Find the right project+topic in the index → read only that topic file
- **Save**: After meaningful, completed work, create/update `projects/ssl-doctor/<topic>.md`, bump version if replacing, update the index line, regenerate `index.compact`
- **Decisions**: If you settle a real choice (library/host/architecture), log `YYYY-MM: chosen > rejected — why` in `projects/ssl-doctor/_decisions.md`
- **Resume**: Keep `> resume <date> · done / next / blocker` current on the `ssl-doctor` section in `index.md`

## Documentation & ADRs
Use the `@documentation-and-adrs` skill for documenting decisions and architecture. 

- **ADRs**: For significant architectural decisions (frameworks, data models, auth, APIs, infrastructure), write ADRs in `docs/decisions/` following the existing convention. If no convention exists, use sequential numbering (`ADR-001-...md`) with Status/Context/Decision/Alternatives/Consequences. Never delete old ADRs — supersede with a new ADR referencing the old one.
- **Why, not what**: Comment the *why*, not the *what*. Avoid restating code, TODOs for immediate work, or commented-out code.
- **API docs**: Document public APIs with types/examples where appropriate. Use OpenAPI/Swagger for REST APIs.
- **README/Changelog**: Keep `README.md` current with quick start/commands/architecture. Update `CHANGELOG.md` for shipped changes.
- **Agent context**: Keep this `AGENTS.md` and any rules files accurate so agents follow project conventions.

## Tools (if available)
If the `project-brain` skill/hooks are installed (`~/.claude/skills/project-brain/`), you can use:
- `brain-compact` — regenerate `.project-brain/index.compact` from `index.md`
- `brain-check` — validate pointers, frontmatter, status sync, staleness
- `brain-find <query>` — search across the brain by tag/keyword
- `brain-export` — bundle for paste into agents without filesystem access

**Note:** Even if those scripts aren't installed, the plain Markdown files above are enough for any file-reading agent.

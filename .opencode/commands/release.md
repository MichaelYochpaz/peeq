---
description: "Prepare and execute a peeq release with AI-drafted changelog"
---

Draft changelog entries from commit history, write them to CHANGELOG.md, and run the release script.

<user-input>
$ARGUMENTS
</user-input>

# Workflow

## 1. Parse Version

Extract the target version from the user input. If no version was provided, ask for one.

Validate format: three-segment semver (X.Y.Z). Examples: `0.2.0`, `1.0.0`.

## 2. Validate Preconditions

Run these checks and stop on the first failure:

1. Repository root: `pyproject.toml` exists in the working directory
2. Branch: `git branch --show-current` returns `main`
3. Clean tree: `git status --porcelain` produces no output
4. Remote sync: `git fetch origin --tags`, then `git rev-parse HEAD` matches `git rev-parse origin/main`
5. Tag unique: `git tag -l v<version>` and `git ls-remote --tags origin refs/tags/v<version>` both produce no output

## 3. Gather Commit History

Find the last release tag:

```bash
git describe --tags --abbrev=0 --match "v*.*.*"
```

If no tag exists, use the full commit history.

Collect commits since the last tag:

```bash
git log <last-tag>..HEAD --reverse --format="%h %s"
```

For each commit, read the full message body (squash-merged PR descriptions live here) and the file change summary:

```bash
git log -1 --format="%B" <hash>
git show --stat <hash>
```

This gives the richest context for drafting accurate changelog entries. If a commit message is unclear, read the diff with `git show <hash>` for additional context.

## 4. Draft Changelog Entries

Categorize each commit into [Keep a Changelog](https://keepachangelog.com/) categories:

- `feat` → `### Added`, `### Removed`, or `### Deprecated` based on whether the commit adds, removes, or deprecates a capability
- `fix` → `### Fixed`, or `### Security` for vulnerability patches
- `refactor` (user-facing behavior change) → `### Changed`
- `revert` → category of the reverted change
- `docs`, `test`, `chore`, `refactor` (internal) → skip, not user-facing

For commits without a Conventional Commits prefix, infer the category from the change description and diffs.

Include only commits where `git show --stat` (already collected in step 3) shows changes inside the released package. Commits touching only external packages (e.g., `peeq-skill/`) belong to those packages' changelogs.

After drafting, verify factual claims (default values, format coverage) against `--help` output or a sample command run. Commit messages reflect intent at authoring time; subsequent commits may change defaults or scope.

Writing guidelines:

- User-facing prose — describe impact, not implementation
- Imperative mood: "Add", "Fix", "Remove"
- Each entry is a single bullet point under its category heading
- Only include categories that have entries
- For breaking changes, prefix with `**BREAKING:**`

Example:

```markdown
### Added

- PEP 658 metadata endpoint support for faster dependency resolution
- Private registry authentication via `--token` flag

### Fixed

- Timeout handling on large package indexes
```

If no commits map to a user-facing category, stop and inform the user there are no changelog entries to draft.

## 5. Present Draft and Confirm

Present the drafted changelog entries. For each entry, note which commit(s) it was derived from.

**Stop and wait for user approval.** The user may:

- Approve as-is
- Request edits to specific entries
- Ask to add, remove, or rephrase entries

Iterate until the user confirms the changelog is ready.

## 6. Write Changelog and Commit

1. Read the current `CHANGELOG.md`
2. Insert the confirmed entries under `## [Unreleased]`, preserving any existing content
3. Write the updated file
4. Stage and commit:

```bash
git add CHANGELOG.md
git commit -m "docs(changelog): prepare <version> release notes"
```

## 7. Run Release Script

Execute the release script, passing the version and any flags the user requested:

```bash
uv run python scripts/release.py <version> -y
```

Always pass `-y` — the user already confirmed at step 5, and the interactive prompt requires a TTY.

The script validates preconditions, bumps the version in `pyproject.toml`, moves the `[Unreleased]` content to a versioned heading, commits, creates an annotated tag, and atomic-pushes to origin. CI automatically runs lint, tests, builds, creates a GitHub Release, and publishes to PyPI.

### Release Script Flags

- `--dry-run` — validate and preview without executing
- `--note "text"` — release summary inserted above changelog categories (use `\n` for newlines)
- `--note-file path` — read the release summary from a file
- `--no-verify` — skip pre-commit hooks on the release commit
- `-y` / `--yes` — skip the interactive confirmation prompt

# Recovery

**Push failed** (e.g., `main` diverged) — commit and tag exist locally but were not pushed:

- Retry: `git push --atomic origin main vX.Y.Z`
- Undo: `git tag -d vX.Y.Z && git reset HEAD~2`

**CI failed after tag push** (lint/test/build failure) — fix the issue, bump to the next patch version, and release that instead.

**PyPI published but GitHub Release draft failed to undraft:**
`gh release edit vX.Y.Z --draft=false`

**Transient failure** (PyPI downtime, network error) — click "Re-run failed jobs" on the failed workflow run in GitHub Actions. The workflow is idempotent.

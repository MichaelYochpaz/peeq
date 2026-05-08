"""Release preparation script for peeq.

Automates the pre-release workflow: validates preconditions, bumps the version
in pyproject.toml, updates CHANGELOG.md, commits, creates an annotated tag,
and atomic-pushes both to origin.

Usage:
    uv run python scripts/release.py 1.0.0
    uv run python scripts/release.py 1.0.0 --note "Performance-focused release"
    uv run python scripts/release.py 1.0.0 --dry-run
"""

from __future__ import annotations

import argparse
import os
import re
import subprocess
import sys
import tempfile
from datetime import UTC, datetime
from pathlib import Path
from typing import NoReturn

from packaging.version import InvalidVersion, Version

PYPROJECT = Path("pyproject.toml")
CHANGELOG = Path("CHANGELOG.md")
LOCKFILE = Path("uv.lock")
ENCODING = "utf-8"

# Em dash (U+2014) — must match the existing CHANGELOG.md heading style.
EM_DASH = "\u2014"

# Matches the first top-level `version = "..."` line in pyproject.toml.
# This assumes [project] appears before any [tool.*] table that might also
# have a `version` field — the current file layout guarantees this.
VERSION_RE = re.compile(r'(?m)^version\s*=\s*"[^"]+"')


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _error(message: str, *, hint: str | None = None) -> NoReturn:
    """Print an error message to stderr and exit."""
    print(f"error: {message}", file=sys.stderr)
    if hint:
        print(f"  hint: {hint}", file=sys.stderr)
    sys.exit(1)


def _atomic_write(path: Path, content: str) -> None:
    """Write content to a file atomically via a temporary file.

    Writes to a temporary file in the same directory, then replaces the
    target.  This avoids leaving a half-written file on crash.

    Args:
        path: The target file path.
        content: The text content to write.
    """
    fd, tmp = tempfile.mkstemp(
        dir=path.parent,
        prefix=f".{path.name}.",
        suffix=".tmp",
    )
    tmp_path = Path(tmp)
    try:
        # Close mkstemp's fd first; write_text opens its own handle.
        os.close(fd)
        tmp_path.write_text(content, encoding=ENCODING, newline="\n")
        # Preserve the original file's permissions (mkstemp defaults to 0600).
        if path.exists():
            tmp_path.chmod(path.stat().st_mode)
        tmp_path.replace(path)
    except BaseException:
        tmp_path.unlink(missing_ok=True)
        raise


def _run_git(
    *args: str,
    capture: bool = False,
    check: bool = True,
) -> subprocess.CompletedProcess[str]:
    """Run a git command and return the completed process."""
    return subprocess.run(
        ["git", *args],
        capture_output=capture,
        text=True,
        check=check,
    )


# ---------------------------------------------------------------------------
# Pre-flight validations
# ---------------------------------------------------------------------------


def _validate_repo_root() -> None:
    """Verify the script is running from the repository root."""
    if not PYPROJECT.exists():
        _error(
            "pyproject.toml not found",
            hint="run this script from the repository root",
        )


def _validate_clean_tree() -> None:
    """Verify the working tree has no uncommitted changes."""
    result = _run_git("status", "--porcelain", capture=True)
    if result.stdout.strip():
        _error(
            "working tree is not clean",
            hint="commit or stash changes before releasing",
        )


def _validate_branch() -> None:
    """Verify the current branch is main."""
    result = _run_git("branch", "--show-current", capture=True)
    branch = result.stdout.strip()
    if branch != "main":
        _error(
            f"current branch is '{branch}', expected 'main'",
            hint="switch to main before releasing",
        )


def _validate_remote_sync() -> None:
    """Verify local main includes all commits from origin/main.

    Allows local to be ahead (e.g. a changelog commit created by the
    release command) while blocking behind or diverged states.
    """
    _run_git("fetch", "origin", "--tags")
    result = _run_git(
        "merge-base",
        "--is-ancestor",
        "origin/main",
        "HEAD",
        capture=True,
        check=False,
    )
    if result.returncode == 1:
        _error(
            "local main has diverged from or is behind origin/main",
            hint="pull or rebase before releasing",
        )
    if result.returncode != 0:
        _error(
            "could not verify local main against origin/main",
            hint=result.stderr.strip()
            or "ensure origin/main exists and fetch succeeds",
        )

    ahead = _run_git(
        "rev-list",
        "--count",
        "origin/main..HEAD",
        capture=True,
    ).stdout.strip()
    if ahead != "0":
        print(f"  local is {ahead} commit(s) ahead of origin/main")


def _validate_version(version_str: str) -> Version:
    """Parse and validate the version string as PEP 440.

    Args:
        version_str: The raw version string from the command line.

    Returns:
        The parsed version object.
    """
    try:
        version = Version(version_str)
    except InvalidVersion:
        _error(
            f"'{version_str}' is not a valid PEP 440 version",
            hint="use a version like 0.1.0 or 1.0.0",
        )

    # The workflow trigger (v*.*.*) requires three dot-separated segments.
    min_dots = 2
    if str(version).count(".") < min_dots:
        _error(
            f"'{version}' must have three segments (X.Y.Z)",
            hint="use a version like 0.1.0, not 0.1",
        )

    return version


def _validate_tag_unique(version: Version) -> None:
    """Verify the release tag does not exist locally or on the remote."""
    tag = f"v{version}"

    result = _run_git("tag", "-l", tag, capture=True)
    if result.stdout.strip():
        _error(f"tag {tag} already exists locally")

    result = _run_git("ls-remote", "--tags", "origin", f"refs/tags/{tag}", capture=True)
    if result.stdout.strip():
        _error(f"tag {tag} already exists on remote")


def _validate_changelog(version: Version, changelog: str) -> None:
    """Verify CHANGELOG.md has an [Unreleased] section with content."""
    if f"## [{version}]" in changelog:
        _error(f"version {version} already has a heading in CHANGELOG.md")

    if "## [Unreleased]" not in changelog:
        _error("[Unreleased] section not found in CHANGELOG.md")

    unreleased = _extract_unreleased_content(changelog)
    if not unreleased:
        _error(
            "[Unreleased] section in CHANGELOG.md has no content",
            hint="add changelog entries before releasing",
        )


def _validate_pyproject(pyproject: str) -> None:
    """Verify pyproject.toml contains a version field."""
    if not VERSION_RE.search(pyproject):
        _error("no version field found in pyproject.toml")


# ---------------------------------------------------------------------------
# File reading and content extraction
# ---------------------------------------------------------------------------


def _extract_unreleased_content(changelog: str) -> str:
    """Extract content between [Unreleased] and the next version heading.

    Args:
        changelog: The full CHANGELOG.md content.

    Returns:
        The trimmed content under [Unreleased], or an empty string.
    """
    lines = changelog.splitlines()
    capturing = False
    content_lines: list[str] = []

    for line in lines:
        if line.startswith("## [Unreleased]"):
            capturing = True
            continue
        if capturing and re.match(r"^## \[", line):
            break
        if capturing:
            content_lines.append(line)

    return "\n".join(content_lines).strip()


def _build_release_notes(unreleased_content: str, note: str | None) -> str:
    """Assemble the release notes that will appear in the GitHub Release.

    Args:
        unreleased_content: The existing content under [Unreleased].
        note: An optional release summary to prepend.

    Returns:
        The combined release notes string.
    """
    if note and unreleased_content:
        return f"{note}\n\n{unreleased_content}"
    if note:
        return note
    return unreleased_content


def _get_commits_since_last_tag() -> list[str]:
    """Return oneline commits since the most recent release tag.

    Uses `git describe --match "v*.*.*"` to find the last release tag.
    Falls back to all commits if no previous release tag exists.

    Returns:
        A list of `git log --oneline` strings, newest first.
    """
    result = _run_git(
        "describe",
        "--tags",
        "--abbrev=0",
        "--match",
        "v*.*.*",
        capture=True,
        check=False,
    )

    if result.returncode == 0 and result.stdout.strip():
        last_tag = result.stdout.strip()
        log = _run_git("log", f"{last_tag}..HEAD", "--oneline", capture=True)
    else:
        log = _run_git("log", "--oneline", capture=True)

    return [line for line in log.stdout.strip().splitlines() if line]


# ---------------------------------------------------------------------------
# File modifications
# ---------------------------------------------------------------------------


def _bump_pyproject(pyproject: str, version: Version) -> str:
    """Replace the version field in pyproject.toml content.

    Args:
        pyproject: The full pyproject.toml content.
        version: The new version.

    Returns:
        The updated pyproject.toml content.
    """
    new_content, count = VERSION_RE.subn(f'version = "{version}"', pyproject, count=1)
    if count != 1:
        _error("failed to substitute version in pyproject.toml")
    return new_content


def _update_changelog(
    changelog: str,
    version: Version,
    today: str,
    note: str | None,
) -> str:
    """Insert the version heading after [Unreleased] in CHANGELOG.md.

    Args:
        changelog: The full CHANGELOG.md content.
        version: The new version.
        today: The release date in YYYY-MM-DD format.
        note: An optional release summary to insert below the heading.

    Returns:
        The updated CHANGELOG.md content.
    """
    heading = f"## [{version}] {EM_DASH} {today}"

    if note:
        replacement = f"## [Unreleased]\n\n{heading}\n\n{note}"
    else:
        replacement = f"## [Unreleased]\n\n{heading}"

    return changelog.replace("## [Unreleased]", replacement, 1)


# ---------------------------------------------------------------------------
# User interaction
# ---------------------------------------------------------------------------


def _print_preview(
    version: Version,
    release_notes: str,
    commits: list[str],
) -> None:
    """Print a release summary: included commits and release notes."""
    separator = "-" * 60

    if commits:
        label = "commit" if len(commits) == 1 else "commits"
        print()
        print(separator)
        print(f"  Commits included in peeq v{version} ({len(commits)} {label})")
        print(separator)
        print()
        for commit in commits:
            print(f"  {commit}")

    print()
    print(separator)
    print(f"  Release notes for peeq v{version}")
    print(separator)
    print()
    print(release_notes)
    print()
    print(separator)


def _confirm() -> bool:
    """Prompt the user for confirmation.

    Returns:
        True if the user confirms, False otherwise.
    """
    try:
        answer = input("Proceed with release? [y/N] ").strip().lower()
    except (EOFError, KeyboardInterrupt):
        print()
        return False
    return answer == "y"


# ---------------------------------------------------------------------------
# Git operations
# ---------------------------------------------------------------------------


def _commit_and_tag(version: Version, *, no_verify: bool) -> None:
    """Stage, commit, and create an annotated tag.

    Args:
        version: The release version.
        no_verify: If True, pass --no-verify to git commit.
    """
    # Update the lockfile to reflect the version bump so the uv-lock
    # pre-commit hook finds nothing to change.
    result = subprocess.run(["uv", "lock"], capture_output=True, text=True, check=False)
    if result.returncode != 0:
        _error(
            "failed to update uv.lock after version bump",
            hint=f"restore files: git checkout HEAD -- {PYPROJECT} {CHANGELOG}",
        )

    _run_git("add", str(PYPROJECT), str(CHANGELOG), str(LOCKFILE))

    commit_args = ["commit", "-m", f"chore(build): prepare {version} release"]
    if no_verify:
        commit_args.append("--no-verify")

    result = _run_git(*commit_args, check=False)
    if result.returncode != 0:
        print(
            "\nerror: commit failed (pre-commit hooks may have modified files).",
            file=sys.stderr,
        )
        print(
            "  To retry with hooks: review changes, re-stage, and commit",
            file=sys.stderr,
        )
        print(
            "  To retry without hooks: re-run with --no-verify",
            file=sys.stderr,
        )
        print(
            f"  To abort: git checkout HEAD -- {PYPROJECT} {CHANGELOG} {LOCKFILE}",
            file=sys.stderr,
        )
        sys.exit(1)

    tag = f"v{version}"
    result = _run_git("tag", "-a", tag, "-m", f"Release {version}", check=False)
    if result.returncode != 0:
        print(
            f"\nerror: failed to create tag {tag}.",
            file=sys.stderr,
        )
        print(
            "  To undo the commit: git reset HEAD~1",
            file=sys.stderr,
        )
        print(
            f"  To abort entirely: git reset HEAD~1 && "
            f"git checkout HEAD -- {PYPROJECT} {CHANGELOG} {LOCKFILE}",
            file=sys.stderr,
        )
        sys.exit(1)


def _push(version: Version) -> None:
    """Atomic-push the branch and tag to origin.

    Args:
        version: The release version (used to construct the tag name).
    """
    tag = f"v{version}"
    result = _run_git("push", "--atomic", "origin", "main", tag, check=False)
    if result.returncode != 0:
        print(
            "\nerror: push failed. The commit and tag exist locally "
            "but were not pushed.",
            file=sys.stderr,
        )
        print(
            f"  To retry: git push --atomic origin main {tag}",
            file=sys.stderr,
        )
        print(
            f"  To undo:  git tag -d {tag} && git reset HEAD~2",
            file=sys.stderr,
        )
        sys.exit(1)


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------


def _resolve_note(args: argparse.Namespace) -> str | None:
    """Read the release note from --note or --note-file.

    Args:
        args: The parsed command-line arguments.

    Returns:
        The resolved note string, or None if no note was provided.
    """
    if args.note_file:
        note_path = Path(args.note_file)
        if not note_path.exists():
            _error(f"note file not found: {note_path}")
        note = note_path.read_text(encoding=ENCODING).strip()
        if not note:
            _error(f"note file is empty: {note_path}")
        return note

    if args.note:
        return args.note.replace("\\n", "\n").strip()

    return None


def _parse_args() -> argparse.Namespace:
    """Parse command-line arguments."""
    parser = argparse.ArgumentParser(
        description=(
            "Prepare a peeq release: bump version, update changelog, "
            "commit, tag, and push."
        ),
    )
    parser.add_argument(
        "version",
        help="target version (PEP 440, e.g. 1.0.0)",
    )

    note_group = parser.add_mutually_exclusive_group()
    note_group.add_argument(
        "--note",
        help=r"release summary inserted above changelog categories "
        r"(use \n for newlines)",
    )
    note_group.add_argument(
        "--note-file",
        help="path to a file containing the release summary",
    )

    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="validate and preview without executing",
    )
    parser.add_argument(
        "--no-verify",
        action="store_true",
        help="skip pre-commit hooks on the release commit",
    )
    parser.add_argument(
        "-y",
        "--yes",
        action="store_true",
        help="skip the interactive confirmation prompt",
    )

    return parser.parse_args()


def main() -> None:
    """Prepare and publish a peeq release."""
    args = _parse_args()

    # --- Pre-flight validations ---
    _validate_repo_root()
    _validate_clean_tree()
    _validate_branch()
    _validate_remote_sync()

    version = _validate_version(args.version)
    note = _resolve_note(args)

    _validate_tag_unique(version)

    changelog = CHANGELOG.read_text(encoding=ENCODING)
    pyproject = PYPROJECT.read_text(encoding=ENCODING)

    _validate_changelog(version, changelog)
    _validate_pyproject(pyproject)

    # --- Compute preview ---
    today = datetime.now(tz=UTC).date().isoformat()
    unreleased_content = _extract_unreleased_content(changelog)
    release_notes = _build_release_notes(unreleased_content, note)
    commits = _get_commits_since_last_tag()

    if args.dry_run:
        print(f"[dry run] Would release peeq v{version} ({today})")
        _print_preview(version, release_notes, commits)
        print("[dry run] No changes made.")
        return

    # --- Preview and confirm ---
    _print_preview(version, release_notes, commits)

    if not args.yes and not _confirm():
        print("Aborted.")
        return

    # --- Modify files ---
    new_pyproject = _bump_pyproject(pyproject, version)
    new_changelog = _update_changelog(changelog, version, today, note)

    _atomic_write(PYPROJECT, new_pyproject)
    _atomic_write(CHANGELOG, new_changelog)

    # --- Git operations ---
    _commit_and_tag(version, no_verify=args.no_verify)
    _push(version)

    print(f"\nReleased peeq v{version}")
    print("CI will now run lint, test, build, and publish.")


if __name__ == "__main__":
    main()

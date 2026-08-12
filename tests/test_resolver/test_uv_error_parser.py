"""Tests for the uv error parser module."""

from __future__ import annotations

from pathlib import Path

import pytest

from peeq.resolver.uv_error_parser import (
    _extract,
    _normalize,
    _parse_uv_error,
    _split_specifier,
)

# ---------------------------------------------------------------------------
# Fixture loading
# ---------------------------------------------------------------------------

_FIXTURE_DIR = Path(__file__).parent / "fixtures" / "uv_errors"


def _load_fixture(name: str) -> str:
    """Load a fixture file by stem name."""
    return (_FIXTURE_DIR / name).read_text(encoding="utf-8")


# ---------------------------------------------------------------------------
# Tests: _split_specifier
# ---------------------------------------------------------------------------


class TestSplitSpecifier:
    """Tests for specifier splitting into (name, specifier)."""

    @pytest.mark.parametrize(
        ("spec", "expected"),
        [
            ("scipy==1.7.0", ("scipy", "==1.7.0")),
            ("kfp>=2.5.0,<=2.8.0", ("kfp", ">=2.5.0,<=2.8.0")),
            ("numpy", ("numpy", "")),
            ("pkg[extra]>=1.0", ("pkg[extra]", ">=1.0")),
            ("kubernetes==35.0.0a1", ("kubernetes", "==35.0.0a1")),
            ("foo!=2.0", ("foo", "!=2.0")),
            ("bar~=3.4", ("bar", "~=3.4")),
            ("baz<5.0", ("baz", "<5.0")),
        ],
        ids=[
            "exact-pin",
            "range",
            "bare-name",
            "extras",
            "prerelease",
            "not-equal",
            "compatible-release",
            "upper-bound",
        ],
    )
    def test_split_specifier(self, spec: str, expected: tuple[str, str]) -> None:
        assert _split_specifier(spec) == expected


# ---------------------------------------------------------------------------
# Tests: _normalize
# ---------------------------------------------------------------------------


class TestNormalize:
    """Tests for Stage 1 — normalization."""

    def test_strips_framing_glyphs(self) -> None:
        text = _load_fixture("simple_root_conflict.txt")
        body, _hints = _normalize(text)
        assert "\u00d7" not in body
        assert "\u2570\u2500\u25b6" not in body  # ╰─▶
        assert "\u2502" not in body  # │

    def test_preserves_content(self) -> None:
        text = _load_fixture("simple_root_conflict.txt")
        body, _ = _normalize(text)
        assert "numpy>=2.0" in body
        assert "numpy<1.26" in body

    def test_separates_hints(self) -> None:
        text = _load_fixture("python_version_incompatibility.txt")
        body, hints = _normalize(text)
        assert len(hints) == 2
        assert any("pre-releases" in h.lower() for h in hints)
        assert any("--python-version" in h for h in hints)
        # Hints should not appear in the body.
        assert "hint:" not in body

    def test_no_hints_when_absent(self) -> None:
        text = _load_fixture("simple_root_conflict.txt")
        _, hints = _normalize(text)
        assert hints == []

    def test_strips_ansi(self) -> None:
        ansi_text = "\x1b[31m\u00d7 No solution\x1b[0m: conflict"
        body, _ = _normalize(ansi_text)
        assert "\x1b" not in body
        assert "No solution" in body

    def test_empty_input(self) -> None:
        body, hints = _normalize("")
        assert body == ""
        assert hints == []

    def test_preserves_version_inventory_indentation(self) -> None:
        text = _load_fixture("deep_chain_conflict.txt")
        body, _ = _normalize(text)
        # Version inventories should still have indented lines.
        lines = body.splitlines()
        indented = [ln for ln in lines if ln.startswith("    ")]
        assert len(indented) > 0


# ---------------------------------------------------------------------------
# Tests: _extract
# ---------------------------------------------------------------------------


class TestExtract:
    """Tests for Stage 2 — best-effort extraction."""

    def test_simple_root_conflict(self) -> None:
        text = _load_fixture("simple_root_conflict.txt")
        body, _ = _normalize(text)
        _by_dep, root_reqs = _extract(body)
        # Root conflict: "you require numpy>=2.0 and numpy<1.26"
        assert len(root_reqs) >= 2
        deps = {r.dependency for r in root_reqs}
        assert "numpy>=2.0" in deps
        assert "numpy<1.26" in deps
        # All root requirements should have package="(root)".
        for r in root_reqs:
            assert r.package == "(root)"
            assert r.version == ""

    def test_transitive_conflict_extracts_depends_on(self) -> None:
        text = _load_fixture("transitive_conflict.txt")
        body, _ = _normalize(text)
        by_dep, _root_reqs = _extract(body)
        # scipy==1.7.0 depends on numpy>=1.16.5,<1.23.0
        assert "numpy" in by_dep
        numpy_reqs = by_dep["numpy"]
        parent_names = {r.package for r in numpy_reqs}
        assert "scipy" in parent_names
        # Root: you require numpy>=2.0
        assert "(root)" in parent_names

    def test_deep_chain_identifies_kubernetes(self) -> None:
        text = _load_fixture("deep_chain_conflict.txt")
        body, _ = _normalize(text)
        by_dep, _ = _extract(body)
        assert "kubernetes" in by_dep
        k8s_reqs = by_dep["kubernetes"]
        parents = {r.package for r in k8s_reqs}
        # Multiple parents impose constraints on kubernetes.
        assert len(parents) >= 2

    def test_deep_chain_extracts_extras(self) -> None:
        text = _load_fixture("deep_chain_conflict.txt")
        body, _ = _normalize(text)
        by_dep, _ = _extract(body)
        # llama-stack-provider-ragas[remote] should appear as a parent.
        all_reqs = [r for reqs in by_dep.values() for r in reqs]
        parent_names = {r.package for r in all_reqs}
        assert any("ragas" in p and "remote" in p for p in parent_names), f"Expected extras parent, got: {parent_names}"

    def test_skips_derived_conclusions(self) -> None:
        text = _load_fixture("transitive_conflict.txt")
        body, _ = _normalize(text)
        by_dep, _ = _extract(body)
        # Derived conclusions like "we can conclude" should not
        # produce ConflictRequirement entries.
        all_reqs = [r for reqs in by_dep.values() for r in reqs]
        for r in all_reqs:
            assert "conclude" not in r.dependency

    def test_nonexistent_package_fallback(self) -> None:
        text = _load_fixture("nonexistent_package.txt")
        body, _ = _normalize(text)
        by_dep, _root_reqs = _extract(body)
        # May or may not extract structured data — the main guarantee
        # is that it doesn't raise.
        assert isinstance(by_dep, dict)

    def test_extras_in_root_requirements(self) -> None:
        text = _load_fixture("extras_conflict.txt")
        body, _ = _normalize(text)
        _, root_reqs = _extract(body)
        deps = {r.dependency for r in root_reqs}
        assert any("requests" in d for d in deps)


# ---------------------------------------------------------------------------
# Tests: _parse_uv_error (full pipeline)
# ---------------------------------------------------------------------------


class TestParseUvError:
    """Tests for the full parse pipeline."""

    def test_simple_root_conflict(self) -> None:
        text = _load_fixture("simple_root_conflict.txt")
        conflicts, summary = _parse_uv_error(text)
        assert len(conflicts) >= 1
        assert "satisfies" in summary.lower() or "resolve" in summary.lower()

    def test_transitive_conflict_identifies_pivot(self) -> None:
        text = _load_fixture("transitive_conflict.txt")
        conflicts, summary = _parse_uv_error(text)
        assert len(conflicts) >= 1
        assert conflicts[0].package == "numpy"
        assert "numpy" in summary

    def test_deep_chain_identifies_kubernetes_pivot(self) -> None:
        text = _load_fixture("deep_chain_conflict.txt")
        conflicts, summary = _parse_uv_error(text)
        assert len(conflicts) >= 1
        assert conflicts[0].package == "kubernetes"
        assert len(conflicts[0].requirements) >= 2
        assert "kubernetes" in summary

    def test_deep_chain_structured_requirements(self) -> None:
        text = _load_fixture("deep_chain_conflict.txt")
        conflicts, _ = _parse_uv_error(text)
        reqs = conflicts[0].requirements
        # Should have at least two distinct parent packages.
        parents = {r.package for r in reqs}
        assert len(parents) >= 2

    def test_python_version_with_hints(self) -> None:
        text = _load_fixture("python_version_incompatibility.txt")
        conflicts, _summary = _parse_uv_error(text)
        assert len(conflicts) >= 1
        # Hints should be in the conflict's hints list.
        hints = conflicts[0].hints
        assert len(hints) >= 1
        hints_text = " ".join(hints)
        assert "--prerelease=allow" in hints_text

    def test_nonexistent_package_fallback(self) -> None:
        text = _load_fixture("nonexistent_package.txt")
        conflicts, summary = _parse_uv_error(text)
        assert len(conflicts) >= 1
        # Should not crash, and should produce usable output.
        assert summary

    def test_extras_conflict(self) -> None:
        text = _load_fixture("extras_conflict.txt")
        conflicts, summary = _parse_uv_error(text)
        assert len(conflicts) >= 1
        assert summary

    # -- Never-raises invariant -----------------------------------------------

    def test_never_raises_empty(self) -> None:
        conflicts, summary = _parse_uv_error("")
        assert isinstance(conflicts, list)
        assert isinstance(summary, str)

    def test_never_raises_garbage(self) -> None:
        conflicts, _summary = _parse_uv_error("random garbage text \u2205\u2205\u2205")
        assert isinstance(conflicts, list)
        assert len(conflicts) >= 1

    def test_never_raises_null_bytes(self) -> None:
        conflicts, _summary = _parse_uv_error("\x00\x00\x00")
        assert isinstance(conflicts, list)

    def test_never_raises_partial_ansi(self) -> None:
        conflicts, _summary = _parse_uv_error("\x1b[31mincomplete")
        assert isinstance(conflicts, list)

    @pytest.mark.parametrize(
        "fixture_path",
        list(_FIXTURE_DIR.glob("*.txt")),
        ids=lambda p: p.stem,
    )
    def test_never_raises_on_fixtures(self, fixture_path: Path) -> None:
        """Parser must return a valid result for all fixtures."""
        text = fixture_path.read_text(encoding="utf-8")
        conflicts, summary = _parse_uv_error(text)
        assert isinstance(conflicts, list)
        assert len(conflicts) >= 1
        assert isinstance(summary, str)
        assert summary  # non-empty
        for conflict in conflicts:
            assert conflict.package  # non-empty
            assert conflict.message  # non-empty

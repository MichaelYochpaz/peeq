# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/),
and this project adheres to [Semantic Versioning](https://semver.org/).
Release dates use UTC.

## [Unreleased]

## [0.2.0] — 2026-05-06

### Added

- `-g`/`--glob` flag for the `ls` command to recursively search archive contents by glob pattern
- `--offset` flag for `versions` and `ls` to skip items before applying `--limit`, enabling pagination

### Changed

- Limit `versions` output to 40 entries by default; add `--all` flag to show the full list
- Show release dates in `versions` output across all formats
- Restructure `info` output into distinct package and version sections with yanked version warnings and adaptive layouts

### Fixed

- Clean up boolean flag help text in CLI output

## [0.1.0] — 2026-04-25

### Added

- Initial release

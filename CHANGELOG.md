# Changelog

All notable changes to this project will be documented here.

## [0.1.0] - 2026-05-23

### Added
- `hash` subcommand: walks a folder and produces a manifest with metadata + MD5/SHA1/SHA256 digests
- File signature (magic byte) detection with extension/content mismatch flag
- `verify` subcommand: re-hashes a folder and diffs against an existing manifest
- `--include` / `--exclude` glob filters for selective inventory
- Basic pytest test suite covering the core helpers
- GitHub Actions CI workflow

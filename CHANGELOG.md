# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/),
and this project adheres to [Semantic Versioning](https://semver.org/).

## [1.0.1](https://github.com/billybox1926-jpg/dep-health-scanner/compare/v1.0.0...v1.0.1) (2026-06-24)


### Bug Fixes

* **cache:** use per-thread SQLite connections in ThreadPoolExecutor ([e86b444](https://github.com/billybox1926-jpg/dep-health-scanner/commit/e86b4448846121671b98c296d5da31f1c95a57cb))
* **ci:** scope release-please permissions and pass token explicitly ([1261db4](https://github.com/billybox1926-jpg/dep-health-scanner/commit/1261db441084c5affc7c80464b7574b372edb9a9))

## [0.1.0] - 2026-06-24

### Added
- Initial release of dep-health-scanner
- Support for npm, cargo, and pip lockfiles
- Vulnerability scanning via OSV API
- Rich terminal output grouped by severity
- SQLite caching for registry and vulnerability metadata
- CI workflows for validation

### Changed
- Repository template scaffolding removed; codebase now reflects shipped functionality

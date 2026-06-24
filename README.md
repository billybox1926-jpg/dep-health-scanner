# dep-health-scanner

Fast, opinionated CLI for dependency health and supply chain scanning.
Scans lockfiles for outdated/vulnerable dependencies, licenses, and maintainer health.

## Install

```bash
pip install -e .
```

## Usage

```bash
# Scan current directory
depscan scan

# Scan specific path
depscan scan /path/to/project

# Check bus factor and suggest alternatives
depscan scan --bus-factor --suggest

# Fail CI build on critical issues
depscan scan --exit-code
```

## Supported lockfiles

- `package-lock.json` (npm)
- `yarn.lock` (npm)
- `pnpm-lock.yaml` (npm)
- `Cargo.lock` (cargo)
- `Pipfile.lock` / `poetry.lock` (pip)

## Architecture

The Python implementation mirrors the Rust design from the proposal:

- **LockfileDetector** — auto-detects lockfile type
- **RegistryClient** — queries npm / cargo registries with SQLite caching
- **VulnerabilityClient** — queries OSV API with local cache
- **Scanner** — parallel scan using `ThreadPoolExecutor`
- **Reporter** — rich terminal output grouped by severity

Exit code 1 when `--exit-code` is passed and critical vulnerabilities are found.

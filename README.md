# dep-health-scanner

Fast, opinionated CLI for dependency health and supply chain scanning.
Scans lockfiles for outdated/vulnerable dependencies, licenses, and maintainer health.

## Requirements

- Python 3.10+
- Internet access for registry and OSV queries (cached locally)

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

# Fail CI build on critical issues
depscan scan --exit-code
```

## Supported lockfiles

- `package-lock.json` (npm)
- `yarn.lock` (npm)
- `pnpm-lock.yaml` (npm)
- `Cargo.lock` (cargo)
- `Pipfile.lock` / `poetry.lock` (pip)
- `go.mod` (Go)

## Architecture

The Python implementation mirrors the Rust design from the proposal:

- **LockfileDetector** — auto-detects lockfile type
- **RegistryClient** — queries npm / cargo / Go registries with SQLite caching
- **VulnerabilityClient** — queries OSV API with local cache
- **Scanner** — parallel scan using `ThreadPoolExecutor`
- **Reporter** — rich terminal output grouped by severity

Exit code 1 when `--exit-code` is passed and critical vulnerabilities are found.

## Output Examples

```text
$ depscan scan

           SUMMARY           

  Metric               Count  
 ──────────────────────────── 
  Total dependencies      69  
  Vulnerable               0  
  Outdated                23  
  Critical                 0  
  High                     0  
  Medium                   0  
  Low                     23  
```

## Configuration

Currently opinionated with sensible defaults. No config file is required.

## CI/CD Integration

Use `--json` for machine-readable output and `--exit-code` to fail builds:

```yaml
- name: Dependency health scan
  run: |
    pip install -e .
    depscan scan --format json --exit-code
```

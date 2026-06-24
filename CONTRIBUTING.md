# Contributing

Thanks for your interest in contributing.

## Ground rules

- Be respectful and follow our Code of Conduct.
- Prefer small, focused pull requests.
- Open an issue first for large or breaking changes.

## Development workflow

1. Fork and create a branch: `feature/short-description`
2. Make your changes with clear commit messages.
3. Run local validation (`format:check`, `lint`, `test`) before opening your PR.
4. Open a pull request using the PR template.

## Pull request checklist

- [ ] Scope is focused and understandable
- [ ] Tests or validation steps are included
- [ ] Docs are updated (if behavior changed)
- [ ] Changelog updated (if needed)

## Local validation

```bash
# Install in editable/dev mode
pip install -e ".[dev]"

# Run tests
pytest tests/

# Lint
ruff check .

# Format check
ruff format --check .

# Type check
mypy src/
```

## Common commands

- Bootstrap: `pip install -e .`
- Setup guide: see README.md for install/usage
- CI workflows: `.github/workflows/`

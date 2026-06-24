#!/usr/bin/env python3
"""Entry point for dep-health-scanner CLI."""

import sys
from pathlib import Path


def _bootstrap() -> None:
    """Add src to sys.path for development/portable usage."""
    src_path = Path(__file__).resolve().parent.parent / "src"
    if src_path.exists():
        sys.path.insert(0, str(src_path))


def main() -> None:
    _bootstrap()
    try:
        from dep_health_scanner.cli import main as cli_main
    except ImportError as exc:
        print(f"Error: Failed to import dep_health_scanner: {exc}", file=sys.stderr)
        print("Hint: run 'pip install -e .' or ensure the 'src' layout is intact.", file=sys.stderr)
        raise SystemExit(1)

    raise SystemExit(cli_main())


if __name__ == "__main__":
    main()

from __future__ import annotations

from pathlib import Path
from typing import Optional

import typer
from rich import print as rprint

from .cache import Cache
from .lockfile import LockfileDetector
from .models import Ecosystem
from .reporter import Reporter
from .scanner import Scanner

app = typer.Typer(
    name="depscan",
    help="Fast, opinionated dependency health scanner",
    add_completion=False,
)


@app.command()
def scan(
    path: Optional[Path] = typer.Argument(None, exists=True, file_okay=False, dir_okay=True),
    bus_factor: bool = typer.Option(False, "--bus-factor", help="Check bus factor"),
    suggest: bool = typer.Option(False, "--suggest", help="Suggest alternatives"),
    fail_on_critical: bool = typer.Option(False, "--exit-code", help="Fail on critical issues"),
    min_severity: str = typer.Option("low", "--min-severity", help="Minimum severity"),
    format: str = typer.Option("text", "--format", help="Output format (text, json)"),
    quiet: bool = typer.Option(False, "--quiet", "-q"),
):
    scan_path = path or Path.cwd()
    lockfile = LockfileDetector.detect(scan_path)
    if not lockfile:
        rprint("[yellow]No lockfile found.[/yellow]")
        raise typer.Exit(0)

    cache = Cache.default()
    scanner = Scanner(cache)
    try:
        results = scanner.scan(lockfile.dependencies)
        reporter = Reporter(fail_on_critical=fail_on_critical)
        exit_code = reporter.print_report(results)
        raise typer.Exit(exit_code)
    finally:
        scanner.close()


@app.command()
def update():
    rprint("[cyan]Updating caches...[/cyan]")
    cache = Cache.default()
    # TODO: refresh OSV and registry data
    rprint("[green]Done![/green]")


@app.command()
def stats():
    cache = Cache.default()
    reg, vuln = cache.stats()
    rprint(f"Registry entries: {reg}")
    rprint(f"Vulnerability records: {vuln}")


@app.command()
def suggest(
    package: str,
    ecosystem: str = typer.Option("npm", "--ecosystem", "-e"),
):
    rprint(f"[yellow]Suggestions for {package} ({ecosystem}) not yet implemented.[/yellow]")


def main():
    app()


if __name__ == "__main__":
    main()

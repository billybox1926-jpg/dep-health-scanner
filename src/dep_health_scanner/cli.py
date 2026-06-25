from __future__ import annotations

from pathlib import Path
from typing import Optional

import typer
from rich import print as rprint
from rich.progress import Progress, SpinnerColumn, TextColumn

from .cache import Cache
from .lockfile import LockfileDetector, Ecosystem
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
    fail_on_critical: bool = typer.Option(False, "--exit-code", help="Fail on critical issues"),
    min_severity: str = typer.Option("low", "--min-severity", help="Minimum severity"),
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
def stats():
    cache = Cache.default()
    reg, vuln = cache.stats()
    rprint(f"Registry entries: {reg}")
    rprint(f"Vulnerability records: {vuln}")


@app.command()
def update(
    path: Path = typer.Argument(Path("."), exists=True, file_okay=False, dir_okay=True),
    ecosystem: Optional[str] = typer.Option(
        None,
        "--ecosystem",
        "-e",
        help="Limit update to one ecosystem (npm, cargo, pip, go)",
    ),
):
    scan_path = path
    lockfile = LockfileDetector.detect(scan_path)
    if not lockfile:
        rprint("[yellow]No lockfile found.[/yellow]")
        raise typer.Exit(0)

    filter_eco = None
    if ecosystem:
        try:
            filter_eco = Ecosystem(ecosystem)
        except ValueError:
            rprint(f"[red]Unknown ecosystem: {ecosystem}[/red]")
            raise typer.Exit(1)

    deps = lockfile.dependencies
    if filter_eco:
        deps = [dep for dep in deps if dep.ecosystem == filter_eco]

    if not deps:
        rprint("[yellow]No dependencies to update after filtering.[/yellow]")
        raise typer.Exit(0)

    cache = Cache.default()
    scanner = Scanner(cache)
    try:
        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            transient=True,
        ) as progress:
            task = progress.add_task("Updating cache...", total=len(deps))

            def _progress():
                progress.advance(task)

            summary = scanner.update(deps, progress_callback=_progress)

        rprint(
            f"[green]Updated {summary['updated']} packages and recorded {summary['vulns_found']} vulnerabilities.[/green]"
        )
    finally:
        scanner.close()

    raise typer.Exit(0)


def main():
    app()


if __name__ == "__main__":
    main()

from __future__ import annotations

from collections import defaultdict
from typing import List

from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich import box

from .models import ScanResult


class Reporter:
    def __init__(self, fail_on_critical: bool = False):
        self.console = Console()
        self.fail_on_critical = fail_on_critical

    def print_report(self, results: List[ScanResult]) -> int:
        if not results:
            self.console.print("[yellow]No dependencies scanned.[/yellow]")
            return 0

        # Classify
        buckets = defaultdict(list)
        for r in results:
            level = self._classify(r)
            buckets[level].append(r)

        self.console.print()
        self.console.print(
            Panel.fit(
                "[bold cyan]DEPENDENCY HEALTH REPORT[/bold cyan]",
                border_style="cyan",
            )
        )
        self.console.print()

        if "critical" in buckets:
            self._print_section("CRITICAL ISSUES", "bold red", buckets["critical"])

        if "high" in buckets:
            self._print_section("HIGH SEVERITY", "bold red", buckets["high"])

        if "medium" in buckets:
            self._print_section("MEDIUM SEVERITY", "bold yellow", buckets["medium"])

        if "low" in buckets:
            self._print_section("LOW SEVERITY", "bold yellow", buckets["low"])

        # Summary
        table = Table(
            title="SUMMARY",
            box=box.SIMPLE,
            show_header=True,
            header_style="bold cyan",
        )
        table.add_column("Metric", style="bold")
        table.add_column("Count", justify="right")
        table.add_row("Total dependencies", str(len(results)))
        table.add_row(
            "Vulnerable",
            str(sum(1 for r in results if r.vulnerabilities)),
            style="red",
        )
        table.add_row(
            "Outdated",
            str(sum(1 for r in results if r.outdated)),
            style="yellow",
        )
        table.add_row(
            "Critical",
            str(len(buckets.get("critical", []))),
            style="red bold",
        )
        table.add_row(
            "High",
            str(len(buckets.get("high", []))),
            style="red",
        )
        table.add_row(
            "Medium",
            str(len(buckets.get("medium", []))),
            style="yellow",
        )
        table.add_row(
            "Low",
            str(len(buckets.get("low", []))),
            style="green",
        )
        self.console.print(table)
        self.console.print()

        critical_count = len(buckets.get("critical", []))
        if self.fail_on_critical and critical_count > 0:
            return 1
        return 0

    def _print_section(self, title: str, style: str, results: List[ScanResult]):
        self.console.print(f"[{style}]{title}[/{style}]")
        self.console.print()
        for r in results:
            icon = "✖" if "CRITICAL" in style or "HIGH" in style else "⚠"
            self.console.print(
                f"  {icon} [cyan]{r.dependency.name}[/cyan]@[dim]{r.dependency.version}[/dim] [{r.dependency.ecosystem.value}]"
            )
            if r.latest_version:
                self.console.print(
                    f"       [dim]latest:[/dim] [green]{r.latest_version}[/green]"
                )
            for v in r.vulnerabilities:
                sev = (
                    "CRITICAL"
                    if v.severity >= 9.0
                    else "HIGH"
                    if v.severity >= 7.0
                    else "MEDIUM"
                    if v.severity >= 4.0
                    else "LOW"
                )
                color = "red" if sev in ("CRITICAL", "HIGH") else "yellow"
                self.console.print(
                    f"       [red bold]vulnerability:[/red bold] [cyan]{v.id}[/cyan] [{color}]{sev}[/color]: {v.summary}"
                )
                if v.fixed_versions:
                    self.console.print(
                        f"              [green]fixed in:[/green] {', '.join(v.fixed_versions)}"
                    )
        self.console.print()

    def _classify(self, r: ScanResult) -> str:
        if r.vulnerabilities:
            for v in r.vulnerabilities:
                if v.severity >= 9.0:
                    return "critical"
                if v.severity >= 7.0:
                    return "high"
            return "medium"
        if r.outdated:
            return "low"
        return "ok"

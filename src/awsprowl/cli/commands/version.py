"""Version command for awsProwl CLI."""

from __future__ import annotations

import sys

import click
from rich.console import Console
from rich.table import Table

from awsprowl.cli.ui import (
    print_banner,
    render_section_header,
)

console = Console()

__version__ = "0.1.0"


@click.command()
@click.option("--short", "-s", is_flag=True, help="Short version output")
@click.option("--json", "json_output", is_flag=True, help="Output as JSON")
def version(short: bool, json_output: bool) -> None:
    """Show version information."""

    if json_output:
        import json
        data = {
            "name": "awsProwl",
            "version": __version__,
            "python": f"{sys.version_info.major}.{sys.version_info.minor}.{sys.version_info.micro}",
        }
        console.print(json.dumps(data, indent=2))
        return

    if short:
        console.print(__version__)
        return

    # Full version display
    print_banner(console)

    console.print(render_section_header("Version Info"))
    console.print()

    table = Table(show_header=False, box=None)
    table.add_column("Component", style="cyan")
    table.add_column("Version", style="green")

    table.add_row("awsProwl", __version__)
    table.add_row("Python", f"{sys.version_info.major}.{sys.version_info.minor}.{sys.version_info.micro}")

    # Try to get dependency versions
    from importlib.metadata import version as pkg_version

    for pkg in ["boto3", "rich", "click", "pydantic", "fastapi", "loguru"]:
        try:
            table.add_row(pkg, pkg_version(pkg))
        except Exception:
            pass

    console.print(table)

    console.print()
    console.print("[dim]https://github.com/KR1SHNA35/awsProwl[/dim]")
    console.print("[dim]MIT License[/dim]")

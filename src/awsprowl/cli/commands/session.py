"""Session command for awsProwl CLI."""

from __future__ import annotations

import json
from pathlib import Path

import click
from rich.console import Console
from rich.table import Table

from awsprowl.cli.ui import (
    print_table,
    render_section_header,
)

console = Console()


def get_sessions_dir() -> Path:
    """Get the sessions directory."""
    data_dir = Path.home() / ".local" / "share" / "awsprowl" / "sessions"
    data_dir.mkdir(parents=True, exist_ok=True)
    return data_dir


@click.group()
def session() -> None:
    """Manage scan sessions."""
    pass


@session.command("list")
@click.option("--limit", "-l", type=int, default=20, help="Maximum sessions to show")
@click.option("--format", type=click.Choice(["table", "json"]), default="table")
def session_list(limit: int, format: str) -> None:
    """List saved scan sessions."""
    sessions_dir = get_sessions_dir()
    sessions = []

    for session_file in sorted(sessions_dir.glob("*.json"), key=lambda f: f.stat().st_mtime, reverse=True):
        try:
            with open(session_file) as f:
                data = json.load(f)
            sessions.append({
                "id": session_file.stem,
                "scan_id": data.get("scan_id", ""),
                "timestamp": data.get("created_at", ""),
                "findings": len(data.get("findings", [])),
                "profile": data.get("config", {}).get("aws", {}).get("profile", ""),
                "regions": ", ".join(data.get("config", {}).get("scan", {}).get("regions", [])),
            })
        except Exception:
            pass

    if format == "json":
        import json
        console.print(json.dumps(sessions[:limit], indent=2))
        return

    if not sessions:
        console.print("[yellow]No saved sessions found[/yellow]")
        return

    console.print(render_section_header("Scan Sessions"))
    console.print()

    table = Table(show_header=True, header_style="bold cyan")
    table.add_column("#", style="dim", width=4)
    table.add_column("Session ID", style="cyan")
    table.add_column("Scan ID", style="bright_black")
    table.add_column("Time", style="green")
    table.add_column("Findings", style="yellow", justify="right")
    table.add_column("Profile", style="blue")
    table.add_column("Regions", style="bright_black")

    for i, sess in enumerate(sessions[:limit], 1):
        table.add_row(
            str(i),
            sess["id"],
            sess["scan_id"][:20] + "..." if len(sess["scan_id"]) > 20 else sess["scan_id"],
            sess["timestamp"][:19].replace("T", " ") if sess["timestamp"] else "Unknown",
            str(sess["findings"]),
            sess["profile"] or "default",
            sess["regions"] or "us-east-1",
        )

    print_table(console, table)


@session.command("show")
@click.argument("session_id")
@click.option("--format", type=click.Choice(["table", "json"]), default="table")
def session_show(session_id: str, format: str) -> None:
    """Show details of a session."""
    sessions_dir = get_sessions_dir()
    session_file = sessions_dir / f"{session_id}.json"

    if not session_file.exists():
        console.print(f"[red]Session not found: {session_id}[/red]")
        return

    with open(session_file) as f:
        data = json.load(f)

    if format == "json":
        console.print(json.dumps(data, indent=2, default=str))
        return

    console.print(render_section_header(f"Session: {session_id}"))
    console.print()

    # Metadata
    meta_table = Table(show_header=False, box=None)
    meta_table.add_column("Key", style="cyan")
    meta_table.add_column("Value")

    meta_table.add_row("Scan ID", data.get("scan_id", "Unknown"))
    meta_table.add_row("Created", data.get("created_at", "Unknown"))
    meta_table.add_row("Profile", data.get("config", {}).get("aws", {}).get("profile", "default"))
    meta_table.add_row("Regions", ", ".join(data.get("config", {}).get("scan", {}).get("regions", ["us-east-1"])))
    meta_table.add_row("Services", ", ".join(data.get("config", {}).get("scan", {}).get("services", [])))
    meta_table.add_row("Total Findings", str(len(data.get("findings", []))))

    print_table(console, meta_table)

    # Findings summary
    findings = data.get("findings", [])
    if findings:
        from awsprowl.analysis.findings import Severity
        counts = dict.fromkeys(Severity, 0)
        for f in findings:
            sev = f.get("severity", "unknown").lower()
            try:
                counts[Severity(sev)] += 1
            except ValueError:
                counts[Severity.UNKNOWN] += 1

        console.print()
        sev_table = Table(show_header=True, header_style="bold cyan")
        sev_table.add_column("Severity", style="cyan")
        sev_table.add_column("Count", justify="right", style="yellow")

        for sev in [Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW, Severity.INFO]:
            if counts[sev] > 0:
                sev_table.add_row(f"{sev.icon} {sev.value.capitalize()}", str(counts[sev]))

        print_table(console, sev_table)


@session.command("load")
@click.argument("session_id")
def session_load(session_id: str) -> None:
    """Load a previous session for review."""
    sessions_dir = get_sessions_dir()
    session_file = sessions_dir / f"{session_id}.json"

    if not session_file.exists():
        console.print(f"[red]Session not found: {session_id}[/red]")
        return

    # Output the session file path for piping
    console.print(str(session_file))


@session.command("delete")
@click.argument("session_id")
@click.option("--yes", "-y", is_flag=True, help="Confirm without prompt")
def session_delete(session_id: str, yes: bool) -> None:
    """Delete a saved session."""
    from rich.prompt import Confirm

    sessions_dir = get_sessions_dir()
    session_file = sessions_dir / f"{session_id}.json"

    if not session_file.exists():
        console.print(f"[red]Session not found: {session_id}[/red]")
        return

    if not yes:
        if not Confirm.ask(f"[yellow]Delete session {session_id}?[/yellow]", default=False):
            console.print("Cancelled")
            return

    session_file.unlink()
    console.print(f"[green]Deleted session: {session_id}[/green]")


@session.command("clean")
@click.option("--older-than", type=int, default=30, help="Delete sessions older than N days")
@click.option("--yes", "-y", is_flag=True, help="Confirm without prompt")
def session_clean(older_than: int, yes: bool) -> None:
    """Clean up old sessions."""
    import time

    from rich.prompt import Confirm

    sessions_dir = get_sessions_dir()
    cutoff = time.time() - (older_than * 86400)
    to_delete = []

    for session_file in sessions_dir.glob("*.json"):
        if session_file.stat().st_mtime < cutoff:
            to_delete.append(session_file)

    if not to_delete:
        console.print(f"[green]No sessions older than {older_than} days[/green]")
        return

    console.print(f"[yellow]Found {len(to_delete)} sessions older than {older_than} days[/yellow]")

    if not yes:
        if not Confirm.ask("[yellow]Delete these sessions?[/yellow]", default=False):
            console.print("Cancelled")
            return

    for f in to_delete:
        f.unlink()

    console.print(f"[green]Deleted {len(to_delete)} sessions[/green]")


@session.command("export")
@click.argument("session_id")
@click.option("--output", "-o", type=click.Path(), help="Output file path")
@click.option("--format", type=click.Choice(["json", "sarif", "html", "markdown"]), default="json")
def session_export(session_id: str, output: str | None, format: str) -> None:
    """Export a session to a report format."""
    sessions_dir = get_sessions_dir()
    session_file = sessions_dir / f"{session_id}.json"

    if not session_file.exists():
        console.print(f"[red]Session not found: {session_id}[/red]")
        return

    with open(session_file) as f:
        data = json.load(f)

    if output is None:
        output = f"{session_id}.{format}"

    output_path = Path(output)

    if format == "json":
        with open(output_path, "w") as f:
            json.dump(data, f, indent=2, default=str)
    elif format == "sarif":
        # TODO: Implement SARIF export
        console.print("[yellow]SARIF export not yet implemented[/yellow]")
        return
    elif format in ("html", "markdown"):
        # TODO: Implement HTML/Markdown export
        console.print(f"[yellow]{format.upper()} export not yet implemented[/yellow]")
        return

    console.print(f"[green]Exported to: {output_path}[/green]")

"""Report command for awsProwl CLI."""

from __future__ import annotations

import json
from pathlib import Path
from datetime import datetime

import click
from rich.console import Console
from rich.table import Table

from awsprowl.cli.ui import (
    print_table,
    render_section_header,
)
from awsprowl.core.config import get_config
from awsprowl.analysis.findings import FindingCollection, Finding, Severity, FindingCategory, ResourceType, Evidence, Remediation
from awsprowl.reports.formatters import generate_report

console = Console()


def get_reports_dir() -> Path:
    """Get the reports directory."""
    output_dir = Path(get_config().output.output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)
    return output_dir


def _convert_to_finding_collection(data: dict) -> FindingCollection:
    """Convert raw scan data to FindingCollection."""
    findings_data = data.get("findings", [])
    scan_id = data.get("scan_id", f"scan-{datetime.now().strftime('%Y%m%d-%H%M%S')}")

    collection = FindingCollection(scan_id=scan_id)

    for f in findings_data:
        # Convert severity
        severity_str = f.get("severity", "info").lower()
        try:
            severity = Severity(severity_str)
        except ValueError:
            severity = Severity.INFO

        # Convert category
        category_str = f.get("category", "informational").lower()
        try:
            category = FindingCategory(category_str)
        except ValueError:
            category = FindingCategory.INFORMATIONAL

        # Convert resource type
        resource_type_str = f.get("resource_type", "other").lower()
        try:
            resource_type = ResourceType(resource_type_str)
        except ValueError:
            resource_type = ResourceType.OTHER

        # Create finding
        finding = Finding(
            id=f.get("id", ""),
            title=f.get("title", "Unknown"),
            description=f.get("description", ""),
            severity=severity,
            category=category,
            resource_type=resource_type,
            resource_id=f.get("resource_id", ""),
            resource_name=f.get("resource_name", ""),
            region=f.get("region", ""),
            account_id=f.get("account_id", ""),
            scan_id=f.get("scan_id", scan_id),
            rule_id=f.get("rule_id", ""),
            destructive=f.get("destructive", False),
            tags=f.get("tags", []),
            status=f.get("status", "open"),
            cvss_score=f.get("cvss_score"),
            cvss_vector=f.get("cvss_vector"),
        )

        # Parse timestamps
        if f.get("created_at"):
            try:
                finding.created_at = datetime.fromisoformat(f["created_at"].replace("Z", "+00:00"))
            except:
                pass
        if f.get("updated_at"):
            try:
                finding.updated_at = datetime.fromisoformat(f["updated_at"].replace("Z", "+00:00"))
            except:
                pass

        # Add evidence if present
        if f.get("evidence"):
            for ev in f["evidence"]:
                finding.add_evidence(Evidence(
                    type=ev.get("type", "api_response"),
                    description=ev.get("description", ""),
                    data=ev.get("data", {}),
                    source=ev.get("source", ""),
                ))

        # Add remediation if present
        if f.get("remediation"):
            rem = f["remediation"]
            finding.set_remediation(Remediation(
                summary=rem.get("summary", ""),
                steps=rem.get("steps", []),
                references=rem.get("references", []),
                effort=rem.get("effort", "medium"),
                automatable=rem.get("automatable", False),
                cli_commands=rem.get("cli_commands", []),
                terraform_example=rem.get("terraform_example"),
            ))

        collection.add_finding(finding)

    return collection


@click.group()
def report() -> None:
    """Generate and manage reports."""
    pass


@report.command("list")
@click.option("--format", type=click.Choice(["table", "json"]), default="table")
def report_list(format: str) -> None:
    """List available reports."""
    reports_dir = get_reports_dir()
    reports = []

    for report_file in sorted(reports_dir.glob("*.json"), key=lambda f: f.stat().st_mtime, reverse=True):
        if report_file.name.startswith("scan-") or report_file.name.startswith("findings-"):
            try:
                with open(report_file) as f:
                    data = json.load(f)
                reports.append({
                    "file": report_file.name,
                    "scan_id": data.get("scan_id", ""),
                    "timestamp": data.get("created_at", ""),
                    "findings": len(data.get("findings", [])),
                })
            except Exception:
                pass

    if format == "json":
        import json
        console.print(json.dumps(reports, indent=2))
        return

    if not reports:
        console.print("[yellow]No reports found[/yellow]")
        return

    console.print(render_section_header("Available Reports"))
    console.print()

    table = Table(show_header=True, header_style="bold cyan")
    table.add_column("#", style="dim", width=4)
    table.add_column("File", style="cyan")
    table.add_column("Scan ID", style="bright_black")
    table.add_column("Time", style="green")
    table.add_column("Findings", style="yellow", justify="right")

    for i, rep in enumerate(reports, 1):
        table.add_row(
            str(i),
            rep["file"],
            rep["scan_id"][:20] + "..." if len(rep["scan_id"]) > 20 else rep["scan_id"],
            rep["timestamp"][:19].replace("T", " ") if rep["timestamp"] else "Unknown",
            str(rep["findings"]),
        )

    print_table(console, table)


@report.command("generate")
@click.argument("source")
@click.option(
    "--format", "-f",
    type=click.Choice(["json", "html", "markdown", "sarif"]),
    default="html",
    help="Output format"
)
@click.option("--output", "-o", type=click.Path(), help="Output file path")
@click.option("--template", "-t", help="Custom template path")
def report_generate(source: str, format: str, output: str | None, template: str | None) -> None:
    """Generate a report from a scan session or findings file."""
    reports_dir = get_reports_dir()

    # Find source file
    source_path = Path(source)
    if not source_path.exists():
        # Try in reports directory
        source_path = reports_dir / source
        if not source_path.exists():
            # Try with .json extension
            source_path = reports_dir / f"{source}.json"
            if not source_path.exists():
                console.print(f"[red]Source not found: {source}[/red]")
                return

    with open(source_path) as f:
        data = json.load(f)

    # Determine output path
    if output is None:
        stem = source_path.stem
        output = f"{stem}-report.{format}"

    output_path = Path(output)

    # Convert to FindingCollection and generate report using formatters
    if format != "json":
        collection = _convert_to_finding_collection(data)
        try:
            generated_path = generate_report(collection, format, output_path.parent, collection.scan_id)
            console.print(f"[green]Report generated: {generated_path}[/green]")
        except Exception as e:
            console.print(f"[red]Report generation failed: {e}[/red]")
    else:
        # Just copy JSON
        with open(output_path, "w") as f:
            json.dump(data, f, indent=2, default=str)
        console.print(f"[green]Report generated: {output_path}[/green]")


@report.command("view")
@click.argument("report_file")
def report_view(report_file: str) -> None:
    """View a report in the terminal."""
    reports_dir = get_reports_dir()
    report_path = Path(report_file)

    if not report_path.exists():
        report_path = reports_dir / report_file
        if not report_path.exists():
            console.print(f"[red]Report not found: {report_file}[/red]")
            return

    with open(report_path) as f:
        data = json.load(f)

    # Display summary
    console.print(render_section_header(f"Report: {report_path.name}"))
    console.print()

    # Metadata
    meta_table = Table(show_header=False, box=None)
    meta_table.add_column("Key", style="cyan")
    meta_table.add_column("Value")

    meta_table.add_row("Scan ID", data.get("scan_id", "Unknown"))
    meta_table.add_row("Created", data.get("created_at", "Unknown"))
    meta_table.add_row("Total Findings", str(len(data.get("findings", []))))

    print_table(console, meta_table)

    # Findings by severity
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
        sev_table.add_column("Severity")
        sev_table.add_column("Count", justify="right")

        for sev in [Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW, Severity.INFO]:
            if counts[sev] > 0:
                sev_table.add_row(f"{sev.icon} {sev.value.capitalize()}", str(counts[sev]))

        print_table(console, sev_table)

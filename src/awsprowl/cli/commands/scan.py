"""Simplified scan command for awsProwl CLI."""

from __future__ import annotations

import asyncio
from datetime import datetime, timezone
from pathlib import Path

import click
from rich.console import Console

from awsprowl.analysis.findings import FindingCollection
from awsprowl.aws import ScanOrchestrator
from awsprowl.cli.ui import (
    create_findings_table,
    create_severity_summary,
    print_banner,
    print_panel,
    print_table,
    render_section_header,
)
from awsprowl.core.auth import create_auth_manager
from awsprowl.core.config import get_config
from awsprowl.core.exceptions import AuthenticationError, AwsProwlError
from awsprowl.core.logging import get_logger
from awsprowl.reports import generate_report

log = get_logger(__name__)
console = Console()


# Scan profiles - map to service lists
SCAN_PROFILES = {
    "quick": ["iam", "ec2", "s3"],
    "standard": ["iam", "ec2", "s3", "lambda", "ecs", "secretsmanager", "sns", "rds", "dynamodb", "kms"],
    "deep": ["iam", "ec2", "s3", "lambda", "ecs", "secretsmanager", "sns", "beanstalk", "cognito", "sts", "rds", "dynamodb", "cloudfront", "kms", "eks"],
    "compliance": ["iam", "ec2", "s3", "lambda", "ecs", "secretsmanager", "sns", "beanstalk", "cognito", "sts", "rds", "dynamodb", "cloudfront", "kms", "eks"],
    "ctf": ["iam", "ec2", "s3", "lambda", "sts", "rds", "dynamodb"],
}


@click.command()
@click.argument("profile", required=False)
@click.argument("region", required=False)
@click.argument("scan_type", required=False, type=click.Choice(list(SCAN_PROFILES.keys())))
@click.option(
    "--output", "-o",
    type=click.Choice(["table", "json", "html", "markdown", "sarif"]),
    default="table",
    help="Output format (default: table)",
)
@click.option(
    "--output-dir", "-d",
    default=None,
    help="Output directory (default: ./awsprowl-output)",
)
@click.option(
    "--quiet", "-q",
    is_flag=True,
    help="Suppress non-essential output",
)
@click.option(
    "--no-banner",
    is_flag=True,
    help="Skip startup banner",
)
@click.pass_context
def scan(
    ctx: click.Context,
    profile: str | None,
    region: str | None,
    scan_type: str | None,
    output: str,
    output_dir: str | None,
    quiet: bool,
    no_banner: bool,
) -> None:
    """Run an AWS security scan.

    Arguments:
        PROFILE    AWS profile name (or 'default')
        REGION     AWS region (or 'all' for all regions)
        SCAN_TYPE  Scan profile: quick, standard, deep, compliance, ctf

    Examples:
        awsprowl scan                          # Interactive - prompts for all
        awsprowl scan default                  # Use default profile, us-east-1, standard scan
        awsprowl scan default us-east-1        # Profile + region, standard scan
        awsprowl scan default us-east-1 quick  # Profile + region + scan type
        awsprowl scan myprofile all deep       # All regions, deep scan
    """

    config = get_config()

    # Handle interactive mode (no args provided)
    if not profile and not region and not scan_type:
        asyncio.run(run_interactive_scan(config, quiet, no_banner))
        return

    # Apply arguments with sensible defaults
    if profile:
        config.aws.profile = profile
    elif not config.aws.profile:
        config.aws.profile = "default"

    if region:
        if region.lower() == "all":
            config.scan.regions = [
                "us-east-1", "us-east-2", "us-west-1", "us-west-2",
                "eu-west-1", "eu-west-2", "eu-central-1",
                "ap-southeast-1", "ap-southeast-2", "ap-northeast-1",
            ]
        else:
            config.scan.regions = [r.strip() for r in region.split(",")]
    elif not config.scan.regions:
        config.scan.regions = [config.aws.region or "us-east-1"]

    if scan_type:
        config.scan.profile = scan_type
        config.scan.services = SCAN_PROFILES[scan_type]
    elif not config.scan.services:
        config.scan.services = SCAN_PROFILES["standard"]

    config.output.format = output
    if output_dir:
        config.output.output_dir = output_dir

    if not no_banner and not quiet:
        print_banner(console)

    # Run the scan
    try:
        asyncio.run(run_scan(config, quiet=quiet))
    except KeyboardInterrupt:
        console.print("\n[yellow]Scan interrupted by user[/yellow]")
        ctx.exit(130)
    except AwsProwlError as e:
        console.print(f"\n[red]Error:[/red] {e.message}")
        if e.remediation:
            console.print(f"[yellow]Remediation:[/yellow] {e.remediation}")
        ctx.exit(1)
    except Exception as e:
        log.exception("Unexpected error during scan")
        console.print(f"\n[red]Unexpected error:[/red] {e}")
        ctx.exit(1)


async def run_interactive_scan(config, quiet: bool, no_banner: bool) -> None:
    """Run scan in interactive mode - prompts for profile, region, scan type."""
    from awsprowl.cli.ui import InteractivePrompts

    if not no_banner:
        print_banner(console)

    prompts = InteractivePrompts(console)

    console.print(render_section_header("Scan Setup"))

    # Ask for profile
    profiles = create_auth_manager(config.aws).list_profiles()
    profile = prompts.ask_profile(profiles)
    config.aws.profile = profile

    # Ask for region
    region_input = prompts.ask_region()
    if region_input.lower() == "all":
        config.scan.regions = [
            "us-east-1", "us-east-2", "us-west-1", "us-west-2",
            "eu-west-1", "eu-west-2", "eu-central-1",
            "ap-southeast-1", "ap-southeast-2", "ap-northeast-1",
        ]
    else:
        config.scan.regions = [r.strip() for r in region_input.split(",")]

    # Ask for scan type
    scan_type = prompts.ask_scan_profile()
    config.scan.profile = scan_type
    config.scan.services = SCAN_PROFILES[scan_type]

    # Ask for output format
    config.output.format = prompts.ask_output_format()

    console.print()
    await run_scan(config, quiet=quiet)


async def run_scan(config, quiet: bool = False) -> None:
    """Execute the scan using the orchestrator."""

    # Create auth manager
    auth_manager = create_auth_manager(config.aws)

    # Verify credentials
    if not quiet:
        console.print(render_section_header("Authentication"))
        with console.status("[cyan]Verifying credentials...[/cyan]"):
            try:
                identity = auth_manager.get_caller_identity()
                console.print(f"[green]✓[/green] Authenticated as: {identity.get('Arn', 'Unknown')}")
                console.print(f"[green]✓[/green] Account: {identity.get('Account', 'Unknown')}")
            except AuthenticationError as e:
                raise AuthenticationError(f"Authentication failed: {e.message}", remediation=e.remediation)

    if not quiet:
        console.print(render_section_header("Scan Configuration"))
        console.print(f"  Profile:  [cyan]{config.aws.profile}[/cyan]")
        console.print(f"  Regions:  [cyan]{', '.join(config.scan.regions)}[/cyan]")
        console.print(f"  Services: [cyan]{', '.join(config.scan.services)}[/cyan]")
        console.print(f"  Type:     [cyan]{config.scan.profile}[/cyan]")
        console.print()

    # Create scan ID
    scan_id = f"scan-{datetime.now(timezone.utc).strftime('%Y%m%d-%H%M%S')}"

    # Use the orchestrator for actual scanning
    orchestrator = ScanOrchestrator(auth_manager, config.scan)
    session = await orchestrator.run_scan(
        profile=config.aws.profile,
        regions=config.scan.regions,
        services=config.scan.services,
        scan_profile=config.scan.profile,
    )

    # Convert session findings to FindingCollection
    findings = FindingCollection(scan_id=scan_id)
    from awsprowl.analysis.findings import Finding
    for f in session.findings:
        if isinstance(f, dict):
            # Convert dict to Finding object
            try:
                finding_obj = Finding(
                    title=f.get("title", ""),
                    description=f.get("description", ""),
                    severity=f.get("severity", "info"),
                    category=f.get("category", "weak_configuration"),
                    resource_type=f.get("resource_type", "other"),
                    resource_id=f.get("resource_id", ""),
                    resource_name=f.get("resource_name", ""),
                    region=f.get("region", ""),
                    rule_id=f.get("rule_id", ""),
                    evidence=f.get("evidence", []),
                    remediation=f.get("remediation"),
                    tags=f.get("tags", []),
                )
                findings.add_finding(finding_obj)
            except Exception as e:
                log.warning("Failed to convert finding dict to Finding object: {}", e)
                # Add a minimal finding to avoid losing data
                findings.add_finding(Finding(
                    title=f.get("title", "Unknown Finding"),
                    description=f.get("description", "Failed to parse finding"),
                    severity="info",
                    category="weak_configuration",
                    resource_type="other",
                ))
        elif isinstance(f, Finding):
            findings.add_finding(f)
        else:
            log.warning("Unexpected finding type: {}, skipping", type(f))

    # Display results
    if not quiet:
        display_results(findings, config.output.format)

    # Save results
    await save_results(findings, config, scan_id)


def display_results(findings: FindingCollection, output_format: str) -> None:
    """Display scan results."""

    console.print()
    console.print(render_section_header("Results"))

    # Severity summary
    severity_panel = create_severity_summary(findings.findings)
    print_panel(console, severity_panel)

    # Findings table
    if findings.findings:
        console.print()
        table = create_findings_table(findings.findings, title=f"Findings ({len(findings.findings)} total)")
        print_table(console, table)

    # Output format handling
    if output_format == "json":
        output_json(findings)
    elif output_format in ("html", "markdown", "sarif"):
        output_formatted(findings, output_format)


def output_json(findings: FindingCollection) -> None:
    """Output findings as JSON."""
    config = get_config()
    output_dir = Path(config.output.output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)

    filename = output_dir / f"findings-{findings.scan_id}.json"
    with open(filename, "w") as f:
        import json
        json.dump(findings.to_dict(), f, indent=2, default=str)

    console.print(f"\n[green]Results saved to:[/green] {filename}")


def output_formatted(findings: FindingCollection, format: str) -> None:
    """Output findings in HTML, Markdown, or SARIF format."""
    config = get_config()
    output_dir = Path(config.output.output_dir)

    try:
        filepath = generate_report(findings, format, output_dir, findings.scan_id)
        console.print(f"\n[green]Report saved to:[/green] {filepath}")
    except Exception as e:
        console.print(f"[red]Error generating {format.upper()} report:[/red] {e}")
        log.exception("Report generation failed")


async def save_results(findings: FindingCollection, config, scan_id: str) -> None:
    """Save scan results to disk."""
    output_dir = Path(config.output.output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)

    json_file = output_dir / f"{scan_id}.json"
    with open(json_file, "w") as f:
        import json
        json.dump(findings.to_dict(), f, indent=2, default=str)

    log.info("Scan results saved to %s", json_file)

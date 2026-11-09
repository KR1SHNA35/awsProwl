"""Main CLI entry point for awsProwl."""

from __future__ import annotations

import sys
from typing import Optional

import click
from rich.console import Console

from awsprowl.cli.ui import print_banner, get_colors
from awsprowl.cli.ui.tui import run_tui
from awsprowl.cli.interactive import main as interactive_main
from awsprowl.core.config import load_config, get_config
from awsprowl.core.logging import setup_logging
from awsprowl.cli.commands.scan import scan
from awsprowl.cli.commands.config import config
from awsprowl.cli.commands.session import session
from awsprowl.cli.commands.report import report
from awsprowl.cli.commands.version import version

console = Console()


@click.group(invoke_without_command=True, context_settings={"help_option_names": ["-h", "--help"]})
@click.option(
    "--config", "-c",
    "config_path",
    type=click.Path(exists=True, dir_okay=False),
    help="Path to configuration file",
)
@click.option(
    "--verbose", "-v",
    count=True,
    help="Increase verbosity (-v, -vv, -vvv)",
)
@click.option(
    "--quiet", "-q",
    is_flag=True,
    help="Suppress non-essential output",
)
@click.option(
    "--no-color",
    is_flag=True,
    help="Disable colored output",
)
@click.option(
    "--no-banner",
    is_flag=True,
    help="Skip startup banner",
)
@click.option(
    "--tui/--no-tui",
    default=True,
    help="Enable/disable interactive TUI mode (default: enabled)",
)
@click.version_option(version="2.0.0", prog_name="awsProwl")
@click.pass_context
def main(
    ctx: click.Context,
    config_path: Optional[str],
    verbose: int,
    quiet: bool,
    no_color: bool,
    no_banner: bool,
    tui: bool,
) -> None:
    """awsProwl - AWS Security Research Tool for CTFs and Authorized Testing.

    Stalk the Cloud 🔍

    Quick Start:
        awsprowl                    # Interactive TUI module browser
        awsprowl --no-tui           # Interactive scan (prompts for profile, region, scan type)
        awsprowl scan               # Same as above
        awsprowl scan myprofile     # Use profile, defaults to us-east-1 + standard scan
        awsprowl scan myprofile us-east-1 quick  # Profile + region + scan type
        awsprowl config list        # Show configuration
        awsprowl session list       # List saved sessions
        awsprowl report generate    # Generate report from last scan
    """

    # Load configuration early
    if config_path:
        load_config(config_path)
    else:
        load_config()

    cfg = get_config()

    # Apply CLI overrides
    if verbose:
        cfg.logging.level = ["WARNING", "INFO", "DEBUG", "DEBUG"][min(verbose, 3)]
    if quiet:
        cfg.logging.level = "WARNING"
    if no_color:
        cfg.ui.color_scheme = "monochrome"
        cfg.logging.colors = False

    # Re-setup logging with updated config
    setup_logging(cfg.logging)

    # Store config in context for subcommands
    ctx.ensure_object(dict)
    ctx.obj["config"] = cfg
    ctx.obj["quiet"] = quiet
    ctx.obj["no_banner"] = no_banner

    # If no subcommand invoked, run interactive TUI
    if ctx.invoked_subcommand is None:
        # Run TUI when no subcommand provided (default behavior)
        if tui:
            cfg_obj = get_config()
            run_tui(config=cfg_obj, console=console)
        else:
            # Fallback to interactive scan
            ctx.invoke(scan)


# Add subcommands
main.add_command(scan)
main.add_command(config)
main.add_command(session)
main.add_command(report)
main.add_command(version)


@main.command()
@click.option(
    "--no-banner",
    is_flag=True,
    help="Skip startup banner",
)
@click.option(
    "--tui/--no-tui",
    default=True,
    help="Enable/disable TUI mode (default: TUI enabled)",
)
@click.pass_context
def interactive(ctx: click.Context, no_banner: bool, tui: bool) -> None:
    """Start the interactive module browser (TUI by default, or classic CLI shell)."""
    # Load configuration
    load_config()
    cfg = get_config()

    # Apply context settings
    quiet = ctx.obj.get("quiet", False) if ctx.obj else False
    if quiet:
        cfg.logging.level = "WARNING"

    if no_banner:
        cfg.ui.show_banner = False

    setup_logging(cfg.logging)

    if tui:
        # Run the enhanced TUI module browser
        run_tui(config=cfg, console=console)
    else:
        # Fallback to classic command-line shell (Prowl-style)
        from awsprowl.cli.interactive import main as interactive_main
        interactive_main()


if __name__ == "__main__":
    main()
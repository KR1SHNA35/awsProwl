"""Config command for awsProwl CLI."""

from __future__ import annotations

from pathlib import Path

import click
import yaml
from rich.console import Console
from rich.syntax import Syntax
from rich.table import Table

from awsprowl.cli.ui import (
    create_key_value_table,
    render_section_header,
)
from awsprowl.core.config import Config, get_config, save_config

console = Console()


@click.group()
def config() -> None:
    """Manage awsProwl configuration."""
    pass


@config.command("list")
@click.option("--show-defaults", is_flag=True, help="Show default values")
@click.option("--format", type=click.Choice(["table", "yaml", "json"]), default="table")
def config_list(show_defaults: bool, format: str) -> None:
    """List current configuration."""
    cfg = get_config()

    if format == "yaml":
        data = cfg.model_dump(exclude_unset=not show_defaults)
        console.print(Syntax(yaml.dump(data, default_flow_style=False), "yaml"))
    elif format == "json":
        import json
        data = cfg.model_dump(exclude_unset=not show_defaults, mode="json")
        console.print(Syntax(json.dumps(data, indent=2, default=str), "json"))
    else:
        console.print(render_section_header("Configuration"))
        console.print()

        # Flatten config for display
        sections = [
            ("AWS", cfg.aws.model_dump(exclude_unset=not show_defaults)),
            ("Scan", cfg.scan.model_dump(exclude_unset=not show_defaults)),
            ("Output", cfg.output.model_dump(exclude_unset=not show_defaults)),
            ("Web", cfg.web.model_dump(exclude_unset=not show_defaults)),
            ("Logging", cfg.logging.model_dump(exclude_unset=not show_defaults)),
            ("UI", cfg.ui.model_dump(exclude_unset=not show_defaults)),
        ]

        for section_name, section_data in sections:
            if section_data:
                table = create_key_value_table(section_data, title=section_name)
                console.print(table)


@config.command("get")
@click.argument("key")
def config_get(key: str) -> None:
    """Get a configuration value."""
    cfg = get_config()

    # Navigate nested keys (e.g., "aws.profile")
    parts = key.split(".")
    value = cfg
    for part in parts:
        if hasattr(value, part):
            value = getattr(value, part)
        else:
            console.print(f"[red]Configuration key not found: {key}[/red]")
            return

    console.print(value)


@config.command("set")
@click.argument("key")
@click.argument("value")
def config_set(key: str, value: str) -> None:
    """Set a configuration value."""
    cfg = get_config()

    # Navigate nested keys
    parts = key.split(".")
    target = cfg
    for part in parts[:-1]:
        if hasattr(target, part):
            target = getattr(target, part)
        else:
            console.print(f"[red]Configuration section not found: {'.'.join(parts[:parts.index(part)+1])}[/red]")
            return

    # Set the value with type conversion
    final_key = parts[-1]
    if hasattr(target, final_key):
        field_type = type(getattr(target, final_key))
        try:
            if field_type == bool:
                value = value.lower() in ("true", "yes", "1", "on")
            elif field_type == int:
                value = int(value)
            elif field_type == float:
                value = float(value)
            elif field_type == list:
                value = [v.strip() for v in value.split(",")]
            setattr(target, final_key, value)
            save_config(cfg)
            console.print(f"[green]Set {key} = {value}[/green]")
        except ValueError as e:
            console.print(f"[red]Invalid value for {key}: {e}[/red]")
    else:
        console.print(f"[red]Configuration key not found: {key}[/red]")


@config.command("reset")
@click.option("--yes", "-y", is_flag=True, help="Confirm reset without prompt")
def config_reset(yes: bool) -> None:
    """Reset configuration to defaults."""
    from rich.prompt import Confirm

    if not yes:
        if not Confirm.ask("[yellow]Reset all configuration to defaults?[/yellow]", default=False):
            console.print("Cancelled")
            return

    # Remove config file
    config_path = Path.home() / ".config" / "awsprowl" / "config.yaml"
    if config_path.exists():
        config_path.unlink()

    # Reset global config
    from awsprowl.core.config import reset_config
    reset_config()

    console.print("[green]Configuration reset to defaults[/green]")


@config.command("profiles")
def config_profiles() -> None:
    """List available AWS profiles."""
    from awsprowl.core.auth import create_auth_manager

    auth = create_auth_manager()
    profiles = auth.list_profiles()

    console.print(render_section_header("AWS Profiles"))
    console.print()

    table = Table(show_header=True, header_style="bold cyan")
    table.add_column("#", style="dim", width=4)
    table.add_column("Profile", style="cyan")
    table.add_column("Status", style="green")

    for i, profile in enumerate(profiles, 1):
        status = "default" if profile == "default" else ""
        table.add_row(str(i), profile, status)

    console.print(table)


@config.command("edit")
def config_edit() -> None:
    """Open configuration file in editor."""
    import os
    import subprocess

    config_path = Path.home() / ".config" / "awsprowl" / "config.yaml"
    config_path.parent.mkdir(parents=True, exist_ok=True)

    if not config_path.exists():
        # Create default config
        cfg = Config()
        save_config(cfg, config_path)

    editor = os.environ.get("EDITOR", "nano")
    try:
        subprocess.run([editor, str(config_path)], check=True)
        console.print("[green]Configuration updated[/green]")
    except subprocess.CalledProcessError:
        console.print("[red]Editor exited with error[/red]")
    except FileNotFoundError:
        console.print(f"[red]Editor not found: {editor}[/red]")


@config.command("path")
def config_path() -> None:
    """Show configuration file path."""
    config_path = Path.home() / ".config" / "awsprowl" / "config.yaml"
    console.print(str(config_path))

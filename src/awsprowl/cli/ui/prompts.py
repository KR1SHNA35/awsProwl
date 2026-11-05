"""Interactive prompts and user input for awsProwl CLI."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from prompt_toolkit import prompt
from prompt_toolkit.completion import Completer, Completion
from prompt_toolkit.shortcuts import checkboxlist_dialog
from prompt_toolkit.styles import Style
from rich.console import Console
from rich.prompt import Confirm, Prompt

from awsprowl.cli.ui.branding import BrandingColors, StatusIndicator, get_colors
from awsprowl.cli.ui.tables import DEFAULT_TABLE_STYLE, create_table
from awsprowl.core.auth import create_auth_manager
from awsprowl.core.config import AWSConfig


@dataclass
class PromptTheme:
    """Prompt styling theme."""

    question: str = "cyan"
    answer: str = "bright_cyan"
    default: str = "bright_black"
    error: str = "red"
    success: str = "green"
    warning: str = "yellow"


DEFAULT_PROMPT_THEME = PromptTheme()

# Prompt Toolkit style for interactive prompts
PT_STYLE = Style.from_dict({
    'question': 'ansicyan bold',
    'answer': 'ansibrightcyan',
    'default': 'ansibrightblack',
    'error': 'ansired',
    'success': 'ansigreen',
    'warning': 'ansiyellow',
    'highlight': 'ansicyan',
    'selected': 'reverse ansicyan',
    'pointer': 'ansicyan',
})


class InteractivePrompts:
    """Interactive prompt helpers for awsProwl."""

    def __init__(self, console: Console, colors: BrandingColors | None = None):
        self.console = console
        self.colors = colors or get_colors()
        self.status = StatusIndicator(console, colors)

    def ask_profile(self, profiles: list[str], default: str = "default") -> str:
        """Ask user to select an AWS profile."""
        self.console.print()
        self.console.print(self.status.info("Select AWS profile:"))

        # Create a simple table for display
        table = create_table(
            columns=[
                ("#", {"style": "dim", "width": 4}),
                ("Profile", {"style": self.colors.secondary}),
            ],
            style=DEFAULT_TABLE_STYLE,
            colors=self.colors,
        )

        for i, profile in enumerate(profiles, 1):
            marker = " →" if profile == default else ""
            table.add_row(str(i), f"{profile}{marker}")

        self.console.print(table)
        self.console.print()

        while True:
            choice = Prompt.ask(
                f"[{self.colors.primary}]Profile number or name[/{self.colors.primary}]",
                default=default,
                console=self.console,
            )

            # Try as number
            try:
                idx = int(choice) - 1
                if 0 <= idx < len(profiles):
                    return profiles[idx]
            except ValueError:
                pass

            # Try as name
            if choice in profiles:
                return choice

            self.console.print(self.status.error(f"Invalid choice: {choice}"))

    def ask_region(self, regions: list[str], default: str = "us-east-1") -> str:
        """Ask user to select an AWS region."""
        self.console.print()
        self.console.print(self.status.info("Select AWS region:"))

        # Show regions in columns
        table = create_table(
            columns=[
                ("Region", {"style": self.colors.secondary}),
            ],
            style=DEFAULT_TABLE_STYLE,
            colors=self.colors,
        )

        for region in regions:
            marker = " (default)" if region == default else ""
            table.add_row(f"{region}{marker}")

        self.console.print(table)
        self.console.print()

        choice = Prompt.ask(
            f"[{self.colors.primary}]Region[/{self.colors.primary}]",
            default=default,
            console=self.console,
        )

        if choice in regions:
            return choice

        # Fuzzy match
        matches = [r for r in regions if choice.lower() in r.lower()]
        if len(matches) == 1:
            self.console.print(self.status.success(f"Selected: {matches[0]}"))
            return matches[0]

        return choice

    def ask_credentials_interactive(self) -> dict[str, str]:
        """Interactively ask for AWS credentials."""
        self.console.print()
        self.console.print(self.status.info("Enter AWS credentials (leave blank to use defaults):"))
        self.console.print()

        access_key = Prompt.ask(
            f"[{self.colors.primary}]Access Key ID[/{self.colors.primary}]",
            default="",
            console=self.console,
        )

        secret_key = Prompt.ask(
            f"[{self.colors.primary}]Secret Access Key[/{self.colors.primary}]",
            default="",
            password=True,
            console=self.console,
        )

        session_token = Prompt.ask(
            f"[{self.colors.primary}]Session Token (optional)[/{self.colors.primary}]",
            default="",
            password=True,
            console=self.console,
        )

        region = Prompt.ask(
            f"[{self.colors.primary}]Region[/{self.colors.primary}]",
            default="us-east-1",
            console=self.console,
        )

        return {
            "access_key_id": access_key,
            "secret_access_key": secret_key,
            "session_token": session_token or None,
            "region": region,
        }

    def confirm_action(
        self,
        message: str,
        default: bool = False,
        warning: bool = False,
    ) -> bool:
        """Ask for confirmation."""
        prefix = self.status.warning("") if warning else self.status.info("")
        return Confirm.ask(
            f"{prefix} {message}",
            default=default,
            console=self.console,
        )

    def select_services(
        self,
        available: list[str],
        default: list[str] | None = None,
    ) -> list[str]:
        """Let user select which services to scan."""
        self.console.print()
        self.console.print(self.status.info("Select services to scan (Space to toggle, Enter to confirm):"))
        self.console.print()

        # Use checkboxlist_dialog from prompt_toolkit
        choices = [(svc, svc.replace("_", " ").title()) for svc in available]
        default_values = default or []

        try:
            result = checkboxlist_dialog(
                title="Service Selection",
                text="Use arrow keys and space to select services",
                values=choices,
                default_values=default_values,
                style=PT_STYLE,
            ).run()

            if result:
                return result
        except Exception:
            pass

        # Fallback to simple prompt
        self.console.print("Available services:", ", ".join(available))
        selected = Prompt.ask(
            f"[{self.colors.primary}]Comma-separated services[/{self.colors.primary}]",
            default=",".join(default_values) if default_values else "",
            console=self.console,
        )

        if selected:
            return [s.strip() for s in selected.split(",") if s.strip() in available]

        return default_values or available

    def select_regions(
        self,
        available: list[str],
        default: list[str] | None = None,
    ) -> list[str]:
        """Let user select which regions to scan."""
        self.console.print()
        self.console.print(self.status.info("Select regions to scan:"))
        self.console.print()

        choices = [(reg, reg) for reg in available]
        default_values = default or ["us-east-1"]

        try:
            result = checkboxlist_dialog(
                title="Region Selection",
                text="Use arrow keys and space to select regions",
                values=choices,
                default_values=default_values,
                style=PT_STYLE,
            ).run()

            if result:
                return result
        except Exception:
            pass

        # Fallback
        selected = Prompt.ask(
            f"[{self.colors.primary}]Comma-separated regions[/{self.colors.primary}]",
            default=",".join(default_values),
            console=self.console,
        )

        if selected:
            return [s.strip() for s in selected.split(",") if s.strip() in available]

        return default_values

    def select_scan_profile(self) -> str:
        """Let user select a scan profile."""
        profiles = [
            ("quick", "Quick scan - core services only (IAM, S3, EC2)"),
            ("standard", "Standard scan - most common services"),
            ("deep", "Deep scan - all services, all regions"),
            ("compliance", "Compliance scan - security best practices"),
            ("ctf", "CTF mode - focused on flags, credentials, vulnerabilities"),
            ("custom", "Custom - choose services and regions manually"),
        ]

        self.console.print()
        self.console.print(self.status.info("Select scan profile:"))

        table = create_table(
            columns=[
                ("Profile", {"style": self.colors.secondary, "width": 12}),
                ("Description", {"min_width": 50}),
            ],
            style=DEFAULT_TABLE_STYLE,
            colors=self.colors,
        )

        for key, desc in profiles:
            table.add_row(key, desc)

        self.console.print(table)
        self.console.print()

        choice = Prompt.ask(
            f"[{self.colors.primary}]Profile[/{self.colors.primary}]",
            choices=[p[0] for p in profiles],
            default="standard",
            console=self.console,
        )

        return choice

    def ask_scan_options(self) -> dict[str, Any]:
        """Ask for all scan options interactively."""
        auth_manager = create_auth_manager()

        # Get available profiles
        profiles = auth_manager.list_profiles()

        # Profile selection
        profile = self.ask_profile(profiles)

        # Load auth manager with selected profile to get regions
        auth_manager = create_auth_manager(AWSConfig(profile=profile, region="us-east-1"))
        regions = auth_manager.get_available_regions()

        # Scan profile
        scan_profile = self.select_scan_profile()

        options = {
            "profile": profile,
            "scan_profile": scan_profile,
        }

        if scan_profile == "custom":
            # Service selection
            available_services = [
                "iam", "ec2", "s3", "lambda", "ecs", "secretsmanager",
                "sns", "beanstalk", "cognito", "rds", "dynamodb",
                "cloudfront", "apigateway", "kms", "cloudformation",
                "organizations",
            ]
            options["services"] = self.select_services(available_services)

            # Region selection
            options["regions"] = self.select_regions(regions)
        else:
            # For non-custom, still ask for region
            options["regions"] = [self.ask_region(regions)]

        return options

    def ask_output_format(self) -> str:
        """Ask for output format."""
        formats = [
            ("table", "Rich table (default)"),
            ("json", "JSON output"),
            ("tree", "Tree view"),
            ("sarif", "SARIF (for CI/CD)"),
            ("html", "HTML report"),
            ("markdown", "Markdown summary"),
        ]

        self.console.print()
        self.console.print(self.status.info("Select output format:"))

        table = create_table(
            columns=[
                ("Format", {"style": self.colors.secondary, "width": 12}),
                ("Description", {"min_width": 50}),
            ],
            style=DEFAULT_TABLE_STYLE,
            colors=self.colors,
        )

        for key, desc in formats:
            table.add_row(key, desc)

        self.console.print(table)
        self.console.print()

        choice = Prompt.ask(
            f"[{self.colors.primary}]Format[/{self.colors.primary}]",
            choices=[f[0] for f in formats],
            default="table",
            console=self.console,
        )

        return choice


def create_command_palette(
    console: Console,
    commands: list[dict[str, str]],
    colors: BrandingColors | None = None,
) -> str | None:
    """Create an interactive command palette (Ctrl+P style)."""

    if colors is None:
        colors = get_colors()

    # Build choices for prompt_toolkit
    choices = []
    for cmd in commands:
        name = cmd.get("name", "")
        desc = cmd.get("description", "")
        choices.append((name, f"{name} — {desc}"))

    try:
        from prompt_toolkit.completion import WordCompleter

        completer = WordCompleter([c[0] for c in choices], ignore_case=True)

        result = prompt(
            f"[{colors.primary}]awsprowl>[/{colors.primary}] ",
            completer=completer,
            style=PT_STYLE,
        )
        return result.strip() if result else None
    except Exception:
        # Fallback
        return None


class CommandCompleter(Completer):
    """Custom completer for awsprowl commands."""

    def __init__(self, commands: list[str]):
        self.commands = commands

    def get_completions(self, document, complete_event):
        word = document.get_word_before_cursor()
        for cmd in self.commands:
            if cmd.startswith(word):
                yield Completion(cmd, start_position=-len(word))


# Pre-defined command palette commands
COMMAND_PALETTE_COMMANDS = [
    {"name": "scan", "description": "Run a security scan"},
    {"name": "scan --quick", "description": "Quick scan of core services"},
    {"name": "scan --deep", "description": "Deep scan of all services"},
    {"name": "scan --ctf", "description": "CTF-focused scan"},
    {"name": "config", "description": "Manage configuration"},
    {"name": "config list", "description": "Show current configuration"},
    {"name": "config set", "description": "Set a configuration value"},
    {"name": "session list", "description": "List saved sessions"},
    {"name": "session load", "description": "Load a previous session"},
    {"name": "report generate", "description": "Generate a report"},
    {"name": "report list", "description": "List available reports"},
    {"name": "serve", "description": "Start web UI server"},
    {"name": "version", "description": "Show version information"},
    {"name": "help", "description": "Show help"},
]

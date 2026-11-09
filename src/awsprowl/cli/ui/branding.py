"""Branding and ASCII art for awsProwl CLI."""

from __future__ import annotations

from dataclasses import dataclass

import pyfiglet
from rich.align import Align
from rich.console import Console
from rich.panel import Panel
from rich.text import Text

from awsprowl.core.config import UIConfig, get_config

# ASCII Art logos
AWS_PROWL_LOGO = r"""
____                     __
  ____ __      _______/ __ \_________ _      __/ /
 / __ `/ | /| / / ___/ /_/ / ___/ __ \ | /| / / / 
/ /_/ /| |/ |/ (__  ) ____/ /  / /_/ / |/ |/ / /  
\__,_/ |__/|__/____/_/   /_/   \____/|__/|__/_/   
"""

AWS_PROWL_LOGO_SMALL = r"""
____                     __
  ____ __      _______/ __ \_________ _      __/ /
 / __ `/ | /| / / ___/ /_/ / ___/ __ \ | /| / / / 
/ /_/ /| |/ |/ (__  ) ____/ /  / /_/ / |/ |/ / /  
\__,_/ |__/|__/____/_/   /_/   \____/|__/|__/_/   
"""

AWS_PROWL_LOGO_MINI = "awsProwl"

TAGLINE = "Stalk the Cloud"
VERSION = "2.0.0"


@dataclass
class BrandingColors:
    """Color scheme for branding."""

    primary: str = "cyan"
    secondary: str = "bright_cyan"
    accent: str = "green"
    warning: str = "yellow"
    danger: str = "red"
    muted: str = "bright_black"
    background: str = "black"


DEFAULT_COLORS = BrandingColors()

HIGH_CONTRAST_COLORS = BrandingColors(
    primary="white",
    secondary="bright_white",
    accent="bright_green",
    warning="bright_yellow",
    danger="bright_red",
    muted="white",
    background="black",
)

MONOCHROME_COLORS = BrandingColors(
    primary="white",
    secondary="bright_white",
    accent="white",
    warning="white",
    danger="white",
    muted="bright_black",
    background="black",
)


def get_colors(ui_config: UIConfig | None = None) -> BrandingColors:
    """Get colors based on UI config."""
    if ui_config is None:
        ui_config = get_config().ui

    if ui_config.color_scheme == "high_contrast":
        return HIGH_CONTRAST_COLORS
    if ui_config.color_scheme == "monochrome":
        return MONOCHROME_COLORS
    return DEFAULT_COLORS


def render_logo(
    style: str = "full",
    colors: BrandingColors | None = None,
    console: Console | None = None,
) -> Text:
    """Render the awsProwl logo as Rich Text."""

    if colors is None:
        colors = get_colors()

    if console is None:
        console = Console()

    if style == "full":
        # Use pyfiglet for the full logo
        figlet = pyfiglet.Figlet(font="slant")
        logo_text: str = figlet.renderText("awsProwl")
    elif style == "small":
        figlet = pyfiglet.Figlet(font="small")
        logo_text = figlet.renderText("awsProwl")
    elif style == "mini":
        logo_text = AWS_PROWL_LOGO_MINI
    else:
        logo_text = AWS_PROWL_LOGO

    # Create Rich Text with styling
    text = Text()
    lines = logo_text.strip("\n").split("\n")

    for i, line in enumerate(lines):
        if i == 0:
            text.append(line, style=f"bold {colors.primary}")
        elif i == len(lines) - 1:
            text.append(line, style=f"bold {colors.secondary}")
        else:
            text.append(line, style=colors.primary)
        text.append("\n")

    # Add tagline
    text.append(f"  {TAGLINE}\n", style=f"italic {colors.accent}")
    text.append(f"  v{VERSION}", style=f"dim {colors.muted}")

    return text


def render_startup_banner(
    console: Console | None = None,
    profile: str | None = None,
    region: str | None = None,
    show_tagline: bool = True,
) -> Panel:
    """Render the startup banner panel."""

    if console is None:
        console = Console()

    colors = get_colors()
    ui_config = get_config().ui

    # Build content
    content = Text()
    content.append("\n")

    # Logo
    logo_text = render_logo("full", colors, console)
    content.append_text(logo_text)

    if show_tagline:
        content.append("\n")

    # Profile/Region info
    if profile or region:
        info_text = Text()
        if profile:
            info_text.append("Profile: ", style=f"{colors.muted}")
            info_text.append(f"{profile}\n", style=f"bold {colors.secondary}")
        if region:
            info_text.append("Region:  ", style=f"{colors.muted}")
            info_text.append(f"{region}\n", style=f"bold {colors.secondary}")
        content.append("\n")
        content.append_text(info_text)

    # Author info
    author_text = Text()
    author_text.append("Author: ", style=f"{colors.muted}")
    author_text.append("KR1SHNA35", style=f"bold {colors.secondary}")
    author_text.append(" — ", style=f"{colors.muted}")
    author_text.append("https://github.com/KR1SHNA35", style=f"underline {colors.accent}")
    content.append("\n")
    content.append_text(author_text)

    # Create panel
    panel = Panel(
        Align.center(content),
        border_style=colors.primary,
        padding=(1, 2),
        title=f"[bold {colors.primary}]awsProwl[/bold {colors.primary}]",
        subtitle=f"[dim {colors.muted}]v{VERSION}[/dim {colors.muted}]",
    )

    return panel


def render_command_banner(
    command: str,
    console: Console | None = None,
) -> Panel:
    """Render a command-specific banner."""

    if console is None:
        console = Console()

    colors = get_colors()

    content = Text()
    content.append(f"  {command.upper()}\n", style=f"bold {colors.primary}")
    content.append(f"  {TAGLINE}", style=f"italic {colors.accent}")

    return Panel(
        Align.center(content),
        border_style=colors.primary,
        padding=(0, 2),
    )


def render_section_header(
    title: str,
    subtitle: str | None = None,
    console: Console | None = None,
) -> Text:
    """Render a section header."""

    if console is None:
        console = Console()

    colors = get_colors()

    text = Text()
    text.append("▶ ", style=colors.primary)
    text.append(title.upper(), style=f"bold {colors.secondary}")

    if subtitle:
        text.append(" — ", style=colors.muted)
        text.append(subtitle, style=colors.muted)

    return text


def render_finding_severity_badge(severity: str) -> Text:
    """Render a severity badge for findings."""
    from awsprowl.analysis.findings import Severity

    try:
        sev = Severity(severity.lower())
    except ValueError:
        sev = Severity.UNKNOWN

    colors = get_colors()

    badge = Text()
    badge.append(f" {sev.icon} ", style=sev.color)
    badge.append(sev.value.upper(), style=f"bold {sev.color}")

    return badge


def print_banner(console: Console) -> None:
    """Print the full startup banner to console."""
    banner = render_startup_banner(console)
    console.print(banner)
    console.print()


# Status indicators
class StatusIndicator:
    """Animated status indicators."""

    SPINNER_FRAMES = ["⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"]
    DOTS_FRAMES = ["⠁", "⠂", "⠄", "⠂"]

    def __init__(self, console: Console, colors: BrandingColors | None = None):
        self.console = console
        self.colors = colors or get_colors()
        self._frame = 0

    def spinner(self, text: str) -> str:
        """Get next spinner frame with text."""
        frame = self.SPINNER_FRAMES[self._frame % len(self.SPINNER_FRAMES)]
        self._frame += 1
        return f"[{self.colors.primary}]{frame}[/{self.colors.primary}] {text}"

    def dots(self, text: str) -> str:
        """Get next dots frame with text."""
        frame = self.DOTS_FRAMES[self._frame % len(self.DOTS_FRAMES)]
        self._frame += 1
        return f"[{self.colors.primary}]{frame}[/{self.colors.primary}] {text}"

    def success(self, text: str) -> str:
        """Success indicator."""
        return f"[{self.colors.accent}]✓[/{self.colors.accent}] {text}"

    def error(self, text: str) -> str:
        """Error indicator."""
        return f"[{self.colors.danger}]✗[/{self.colors.danger}] {text}"

    def warning(self, text: str) -> str:
        """Warning indicator."""
        return f"[{self.colors.warning}]⚠[/{self.colors.warning}] {text}"

    def info(self, text: str) -> str:
        """Info indicator."""
        return f"[{self.colors.secondary}]ℹ[/{self.colors.secondary}] {text}"


# Theme configurations for different contexts
class Theme:
    """Color themes for different output contexts."""

    @staticmethod
    def finding_severity(severity: str) -> str:
        """Get Rich style for finding severity."""
        from awsprowl.analysis.findings import Severity

        try:
            sev = Severity(severity.lower())
        except ValueError:
            return "white"

        styles = {
            Severity.CRITICAL: "bold red on grey15",
            Severity.HIGH: "red",
            Severity.MEDIUM: "yellow",
            Severity.LOW: "blue",
            Severity.INFO: "cyan",
            Severity.UNKNOWN: "white",
        }
        return styles.get(sev, "white")

    @staticmethod
    def resource_type(resource_type: str) -> str:
        """Get style for resource type."""
        from awsprowl.analysis.findings import ResourceType

        try:
            rt = ResourceType(resource_type.lower())
        except ValueError:
            return "white"

        styles = {
            ResourceType.IAM_USER: "cyan",
            ResourceType.IAM_ROLE: "bright_cyan",
            ResourceType.IAM_POLICY: "blue",
            ResourceType.IAM_GROUP: "magenta",
            ResourceType.EC2_INSTANCE: "green",
            ResourceType.EC2_SECURITY_GROUP: "red",
            ResourceType.EC2_VOLUME: "yellow",
            ResourceType.S3_BUCKET: "bright_yellow",
            ResourceType.LAMBDA_FUNCTION: "magenta",
            ResourceType.ECS_CLUSTER: "bright_blue",
            ResourceType.ECS_SERVICE: "blue",
            ResourceType.SECRETS_MANAGER_SECRET: "bright_red",
            ResourceType.SNS_TOPIC: "bright_magenta",
            ResourceType.COGNITO_USER_POOL: "bright_green",
            ResourceType.COGNITO_IDENTITY_POOL: "green",
        }
        return styles.get(rt, "white")

    @staticmethod
    def category(category: str) -> str:
        """Get style for finding category."""
        from awsprowl.analysis.findings import FindingCategory

        try:
            cat = FindingCategory(category.lower())
        except ValueError:
            return "white"

        styles = {
            FindingCategory.PRIVILEGE_ESCALATION: "bold red",
            FindingCategory.DATA_EXPOSURE: "red",
            FindingCategory.NETWORK_EXPOSURE: "bright_red",
            FindingCategory.WEAK_CONFIGURATION: "yellow",
            FindingCategory.EXCESSIVE_PERMISSIONS: "bright_yellow",
            FindingCategory.MISSING_ENCRYPTION: "blue",
            FindingCategory.PUBLIC_ACCESS: "bright_red",
            FindingCategory.CROSS_ACCOUNT_ACCESS: "magenta",
            FindingCategory.UNUSED_RESOURCES: "bright_black",
            FindingCategory.COMPLIANCE: "cyan",
            FindingCategory.INFORMATIONAL: "blue",
        }
        return styles.get(cat, "white")

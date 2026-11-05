"""Rich table and display utilities for awsProwl CLI."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from rich.box import MINIMAL, ROUNDED, Box
from rich.console import Console
from rich.panel import Panel
from rich.progress import (
    BarColumn,
    MofNCompleteColumn,
    Progress,
    SpinnerColumn,
    TaskProgressColumn,
    TextColumn,
    TimeElapsedColumn,
    TimeRemainingColumn,
)
from rich.table import Table
from rich.text import Text
from rich.tree import Tree

from awsprowl.cli.ui.branding import BrandingColors, Theme, get_colors


@dataclass
class TableStyle:
    """Table styling configuration."""

    box: Box = ROUNDED
    header_style: str = "bold cyan"
    border_style: str = "cyan"
    row_styles: tuple = ("", "dim")
    show_header: bool = True
    show_lines: bool = False
    expand: bool = False
    padding: tuple = (0, 1)


DEFAULT_TABLE_STYLE = TableStyle()
COMPACT_TABLE_STYLE = TableStyle(
    box=MINIMAL,
    header_style="bold cyan",
    border_style="bright_black",
    row_styles=("", ""),
    show_lines=False,
    padding=(0, 1),
)


def create_table(
    title: str | None = None,
    columns: list[tuple[str, dict[str, Any]]] | None = None,
    style: TableStyle = DEFAULT_TABLE_STYLE,
    colors: BrandingColors | None = None,
) -> Table:
    """Create a Rich table with consistent styling."""

    if colors is None:
        colors = get_colors()

    table = Table(
        title=title,
        box=style.box,
        header_style=style.header_style,
        border_style=style.border_style or colors.primary,
        row_styles=style.row_styles,
        show_header=style.show_header,
        show_lines=style.show_lines,
        expand=style.expand,
        padding=style.padding,
    )

    if columns:
        for col_name, col_kwargs in columns:
            table.add_column(col_name, **col_kwargs)

    return table


def add_finding_row(
    table: Table,
    finding: Any,  # Finding model
    colors: BrandingColors | None = None,
) -> None:
    """Add a finding row to a table."""
    from awsprowl.analysis.findings import Finding

    if colors is None:
        colors = get_colors()

    if isinstance(finding, Finding):
        severity_text = Text(finding.severity.value.upper(), style=Theme.finding_severity(finding.severity.value))
        category_text = Text(finding.category.value.replace("_", " ").title(), style=Theme.category(finding.category.value))
        resource_text = Text(finding.resource_type.value.replace("_", " ").title(), style=Theme.resource_type(finding.resource_type.value))

        table.add_row(
            severity_text,
            finding.title,
            category_text,
            resource_text,
            finding.resource_id or finding.resource_name or "-",
            finding.region or "-",
        )
    else:
        # Assume dict-like
        table.add_row(
            Text(str(finding.get("severity", "")).upper(), style=Theme.finding_severity(str(finding.get("severity", "")))),
            str(finding.get("title", "")),
            str(finding.get("category", "")).replace("_", " ").title(),
            str(finding.get("resource_type", "")).replace("_", " ").title(),
            str(finding.get("resource_id", finding.get("resource_name", "-"))),
            str(finding.get("region", "-")),
        )


def create_findings_table(
    findings: list[Any],
    title: str = "Findings",
    colors: BrandingColors | None = None,
    compact: bool = False,
) -> Table:
    """Create a table for displaying findings."""

    if colors is None:
        colors = get_colors()

    style = COMPACT_TABLE_STYLE if compact else DEFAULT_TABLE_STYLE

    columns = [
        ("Severity", {"width": 10}),
        ("Title", {"min_width": 30, "max_width": 60}),
        ("Category", {"width": 20}),
        ("Resource Type", {"width": 18}),
        ("Resource ID", {"min_width": 20, "max_width": 40}),
        ("Region", {"width": 12}),
    ]

    table = create_table(title=title, columns=columns, style=style, colors=colors)

    for finding in findings:
        add_finding_row(table, finding, colors)

    return table


def create_resource_table(
    resources: list[dict[str, Any]],
    title: str = "Resources",
    columns: list[tuple[str, dict[str, Any]]] | None = None,
    colors: BrandingColors | None = None,
) -> Table:
    """Create a table for displaying resources."""

    if colors is None:
        colors = get_colors()

    if columns is None:
        columns = [
            ("Type", {"style": "cyan", "width": 20}),
            ("ID/Name", {"min_width": 30}),
            ("Region", {"width": 12}),
            ("Status", {"width": 12}),
            ("Details", {"min_width": 30}),
        ]

    table = create_table(title=title, columns=columns, colors=colors)

    for resource in resources:
        row = []
        for col_name, _ in columns:
            key = col_name.lower().replace(" ", "_")
            value = resource.get(key, resource.get(key.replace("/", "_"), "-"))
            if key == "type":
                row.append(Text(str(value).replace("_", " ").title(), style=Theme.resource_type(str(value))))
            elif key == "status":
                status = str(value).lower()
                if status in ("running", "active", "enabled", "healthy"):
                    row.append(Text(str(value), style="green"))
                elif status in ("stopped", "inactive", "disabled", "unhealthy"):
                    row.append(Text(str(value), style="red"))
                else:
                    row.append(Text(str(value), style="yellow"))
            else:
                row.append(str(value))
        table.add_row(*row)

    return table


def create_key_value_table(
    data: dict[str, Any],
    title: str | None = None,
    colors: BrandingColors | None = None,
    hide_none: bool = True,
) -> Table:
    """Create a simple key-value table."""

    if colors is None:
        colors = get_colors()

    table = create_table(
        title=title,
        columns=[
            ("Property", {"style": "cyan", "width": 30}),
            ("Value", {"min_width": 40}),
        ],
        style=COMPACT_TABLE_STYLE,
        colors=colors,
    )

    for key, value in data.items():
        if hide_none and value in (None, "", [], {}):
            continue

        # Format value
        if isinstance(value, (dict, list)):
            import json
            formatted = json.dumps(value, indent=2, default=str)
            if len(formatted) > 200:
                formatted = formatted[:200] + "..."
        else:
            formatted = str(value)

        table.add_row(key.replace("_", " ").title(), formatted)

    return table


def create_progress_bar(
    console: Console | None = None,
    colors: BrandingColors | None = None,
    transient: bool = False,
) -> Progress:
    """Create a styled progress bar."""

    if console is None:
        console = Console()

    if colors is None:
        colors = get_colors()

    return Progress(
        SpinnerColumn(style=colors.primary),
        TextColumn("[progress.description]{task.description}"),
        BarColumn(
            bar_width=None,
            complete_style=colors.accent,
            finished_style=colors.accent,
            pulse_style=colors.warning,
        ),
        TaskProgressColumn(),
        MofNCompleteColumn(),
        TimeElapsedColumn(),
        TimeRemainingColumn(),
        console=console,
        transient=transient,
        expand=True,
    )


def create_scan_progress(
    console: Console | None = None,
    colors: BrandingColors | None = None,
) -> Progress:
    """Create a progress bar optimized for scan operations."""

    if console is None:
        console = Console()

    if colors is None:
        colors = get_colors()

    return Progress(
        SpinnerColumn(style=colors.primary),
        TextColumn("[bold]{task.description}"),
        BarColumn(
            bar_width=None,
            complete_style=colors.accent,
            finished_style=colors.accent,
        ),
        TextColumn("[progress.percentage]{task.percentage:>3.0f}%"),
        TimeElapsedColumn(),
        console=console,
        transient=False,
        expand=True,
    )


def create_tree(
    label: str,
    children: list[tuple[str, list[tuple[str, Any]]] | dict[str, Any]],
    colors: BrandingColors | None = None,
    style: str = "cyan",
) -> Tree:
    """Create a Rich tree for hierarchical data."""

    if colors is None:
        colors = get_colors()

    tree = Tree(label, style=colors.primary, guide_style=colors.muted)

    def add_nodes(parent: Tree, data: Any, prefix: str = "") -> None:
        if isinstance(data, dict):
            for key, value in data.items():
                node_label = f"{prefix}{key}"
                if isinstance(value, (dict, list)):
                    node = parent.add(node_label, style=style)
                    add_nodes(node, value, prefix="  ")
                else:
                    parent.add(f"{node_label}: {value}", style=colors.muted)
        elif isinstance(data, list):
            for item in data:
                if isinstance(item, tuple) and len(item) == 2:
                    node_label, children = item
                    node = parent.add(f"{prefix}{node_label}", style=style)
                    add_nodes(node, children, prefix="  ")
                else:
                    parent.add(f"{prefix}{item}", style=colors.muted)

    add_nodes(tree, children)
    return tree


def create_resource_tree(
    resources: dict[str, list[dict[str, Any]]],
    title: str = "Resources",
    colors: BrandingColors | None = None,
) -> Tree:
    """Create a tree view of resources grouped by type."""

    if colors is None:
        colors = get_colors()

    tree = Tree(f"[bold {colors.primary}]{title}[/bold {colors.primary}]", guide_style=colors.muted)

    for resource_type, items in resources.items():
        type_node = tree.add(
            f"[{Theme.resource_type(resource_type)}]{resource_type.replace('_', ' ').title()}[/] "
            f"[dim]({len(items)})[/dim]"
        )
        for item in items:
            name = item.get("name", item.get("id", "unknown"))
            region = item.get("region", "")
            status = item.get("status", "")

            label_parts = [f"[{colors.secondary}]{name}[/{colors.secondary})"]
            if region:
                label_parts.append(f"[dim]{region}[/dim]")
            if status:
                status_style = "green" if status.lower() in ("running", "active") else "red"
                label_parts.append(f"[{status_style}]{status}[/{status_style}]")

            type_node.add(" ".join(label_parts))

    return tree


def create_summary_panel(
    title: str,
    stats: dict[str, int | str],
    colors: BrandingColors | None = None,
) -> Panel:
    """Create a summary statistics panel."""

    if colors is None:
        colors = get_colors()

    content = Text()
    for key, value in stats.items():
        content.append(f"  {key}: ", style=colors.muted)
        content.append(f"{value}\n", style=f"bold {colors.secondary}")

    return Panel(
        content,
        title=f"[bold {colors.primary}]{title}[/bold {colors.primary}]",
        border_style=colors.primary,
        padding=(1, 2),
    )


def create_severity_summary(
    findings: list[Any],
    colors: BrandingColors | None = None,
) -> Panel:
    """Create a severity summary panel."""

    from awsprowl.analysis.findings import Finding, Severity

    if colors is None:
        colors = get_colors()

    counts = dict.fromkeys(Severity, 0)
    for finding in findings:
        if isinstance(finding, Finding):
            counts[finding.severity] += 1
        else:
            sev_str = str(finding.get("severity", "")).lower()
            try:
                counts[Severity(sev_str)] += 1
            except ValueError:
                counts[Severity.UNKNOWN] += 1

    content = Text()
    for sev in [Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW, Severity.INFO]:
        count = counts[sev]
        if count > 0:
            content.append(f"  {sev.icon} ", style=sev.color)
            content.append(f"{sev.value.capitalize()}: ", style=f"bold {sev.color}")
            content.append(f"{count}\n", style=f"bold {colors.secondary}")

    total = sum(counts.values())
    content.append("\n  Total: ", style=colors.muted)
    content.append(f"{total}", style=f"bold {colors.secondary}")

    return Panel(
        content,
        title=f"[bold {colors.primary}]Findings Summary[/bold {colors.primary}]",
        border_style=colors.primary,
        padding=(1, 2),
    )


def print_table(console: Console, table: Table) -> None:
    """Print a table with proper console handling."""
    console.print(table)


def print_panel(console: Console, panel: Panel) -> None:
    """Print a panel."""
    console.print(panel)


def print_tree(console: Console, tree: Tree) -> None:
    """Print a tree."""
    console.print(tree)

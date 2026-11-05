"""UI components for awsProwl CLI."""

from awsprowl.cli.ui.branding import (
    render_logo,
    render_startup_banner,
    render_command_banner,
    render_section_header,
    render_finding_severity_badge,
    print_banner,
    StatusIndicator,
    Theme,
    BrandingColors,
    get_colors,
    DEFAULT_COLORS,
    HIGH_CONTRAST_COLORS,
    MONOCHROME_COLORS,
)

from awsprowl.cli.ui.tables import (
    create_table,
    create_findings_table,
    create_resource_table,
    create_key_value_table,
    create_progress_bar,
    create_scan_progress,
    create_tree,
    create_resource_tree,
    create_summary_panel,
    create_severity_summary,
    print_table,
    print_panel,
    print_tree,
    TableStyle,
    DEFAULT_TABLE_STYLE,
    COMPACT_TABLE_STYLE,
)

from awsprowl.cli.ui.prompts import (
    InteractivePrompts,
    PromptTheme,
    DEFAULT_PROMPT_THEME,
    create_command_palette,
    CommandCompleter,
    COMMAND_PALETTE_COMMANDS,
)

from awsprowl.cli.ui.prowl_display import (
    ProwlDisplay,
    print_findings,
    print_summary,
    print_error,
    print_data,
    print_access_denied,
)

__all__ = [
    # Branding
    "render_logo",
    "render_startup_banner",
    "render_command_banner",
    "render_section_header",
    "render_finding_severity_badge",
    "print_banner",
    "StatusIndicator",
    "Theme",
    "BrandingColors",
    "get_colors",
    "DEFAULT_COLORS",
    "HIGH_CONTRAST_COLORS",
    "MONOCHROME_COLORS",
    # Tables
    "create_table",
    "create_findings_table",
    "create_resource_table",
    "create_key_value_table",
    "create_progress_bar",
    "create_scan_progress",
    "create_tree",
    "create_resource_tree",
    "create_summary_panel",
    "create_severity_summary",
    "print_table",
    "print_panel",
    "print_tree",
    "TableStyle",
    "DEFAULT_TABLE_STYLE",
    "COMPACT_TABLE_STYLE",
    # Prompts
    "InteractivePrompts",
    "PromptTheme",
    "DEFAULT_PROMPT_THEME",
    "create_command_palette",
    "CommandCompleter",
    "COMMAND_PALETTE_COMMANDS",
    # Prowl Display
    "ProwlDisplay",
    "print_findings",
    "print_summary",
    "print_error",
    "print_data",
    "print_access_denied",
]
"""Core utilities for awsProwl.

Provides session directory management, output helpers, and other utilities.
Follows patterns from Prowler's lib.py.
"""

from __future__ import annotations

import contextlib
import os
import sys
from collections.abc import Generator
from pathlib import Path
from typing import IO, Any

from awsprowl.core.config import get_config
from awsprowl.core.session import (
    get_session_dir,
    get_session_downloads_dir,
    get_session_module_data_dir,
)
from awsprowl.core.session import (
    save as session_save,
)

# Global reference to active session getter (set by CLI)
get_active_session_func: callable | None = None


def set_active_session_getter(func: callable) -> None:
    """Set the function to get the active session."""
    global get_active_session_func
    get_active_session_func = func


def home_dir() -> Path:
    """Get the awsprowl home directory (data directory)."""
    config = get_config()
    return config.get_data_dir()


def prowl_dir() -> Path:
    """Get the awsprowl source directory."""
    return Path(__file__).parents[2]


def session_dir() -> Path:
    """Get the active session's directory."""
    if not get_active_session_func:
        raise UserWarning("No session getter set. Call set_active_session_getter() first.")
    session = get_active_session_func()
    if session is None:
        raise UserWarning("No active session set.")
    return get_session_dir(session.name)


def downloads_dir() -> Path:
    """Get the active session's downloads directory."""
    return get_session_downloads_dir()


def module_data_dir(module: str) -> Path:
    """Get the active session's module data directory."""
    return get_session_module_data_dir(module)


@contextlib.contextmanager
def save(
    file_name: str,
    mode: str = "w",
    header: str | None = None,
    **kwargs,
) -> Generator[IO[Any], None, None]:
    """Save content to a file in the active session's downloads directory.

    Args:
        file_name: Name of the file to save
        mode: File open mode (default: 'w')
        header: Optional header to write if file doesn't exist (e.g., CSV header)
        **kwargs: Additional arguments passed to open()

    Yields:
        File object for writing
    """
    with session_save(file_name, mode=mode, header=header, **kwargs) as f:
        yield f


def print_output(text: str, **kwargs) -> None:
    """Print output to stdout with consistent formatting."""
    print(text, **kwargs)


def print_error(text: str, **kwargs) -> None:
    """Print error to stderr with consistent formatting."""
    print(text, file=sys.stderr, **kwargs)


def print_warning(text: str, **kwargs) -> None:
    """Print warning to stderr with consistent formatting."""
    print(f"WARNING: {text}", file=sys.stderr, **kwargs)


def print_info(text: str, **kwargs) -> None:
    """Print info message to stdout with consistent formatting."""
    print(f"INFO: {text}", **kwargs)


def print_success(text: str, **kwargs) -> None:
    """Print success message to stdout with consistent formatting."""
    print(f"SUCCESS: {text}", **kwargs)


def strip_lines(text: str) -> str:
    """Strip leading/trailing whitespace from each line and join with spaces."""
    out = []
    for line in text.splitlines():
        out.append(line.strip("\t "))
    return " ".join(out)


def confirm(message: str, default: bool = False) -> bool:
    """Ask for user confirmation."""
    suffix = " [Y/n]" if default else " [y/N]"
    while True:
        try:
            response = input(f"{message}{suffix}: ").strip().lower()
        except (EOFError, KeyboardInterrupt):
            print()
            return default

        if not response:
            return default
        if response in ("y", "yes"):
            return True
        if response in ("n", "no"):
            return False
        print("Please answer 'yes' or 'no'.")


def prompt(message: str, default: str | None = None) -> str:
    """Prompt user for input."""
    suffix = f" [{default}]" if default is not None else ""
    while True:
        try:
            response = input(f"{message}{suffix}: ").strip()
        except (EOFError, KeyboardInterrupt):
            print()
            if default is not None:
                return default
            raise

        if response:
            return response
        if default is not None:
            return default
        print("Input required.")


def prompt_password(message: str) -> str:
    """Prompt user for password (hidden input)."""
    import getpass
    return getpass.getpass(f"{message}: ")


def format_table(headers: list[str], rows: list[list[Any]], max_width: int = 120) -> str:
    """Format data as a table."""
    if not rows:
        return ""

    # Calculate column widths
    col_widths = [len(h) for h in headers]
    for row in rows:
        for i, cell in enumerate(row):
            if i < len(col_widths):
                col_widths[i] = max(col_widths[i], len(str(cell)))

    # Cap widths
    col_widths = [min(w, 50) for w in col_widths]

    # Build format string
    fmt = " | ".join(f"{{:<{w}}}" for w in col_widths)
    separator = "-+-".join("-" * w for w in col_widths)

    lines = []
    lines.append(fmt.format(*headers))
    lines.append(separator)

    for row in rows:
        # Truncate cells if needed
        formatted_row = []
        for i, cell in enumerate(row):
            cell_str = str(cell)
            if i < len(col_widths) and len(cell_str) > col_widths[i]:
                cell_str = cell_str[: col_widths[i] - 3] + "..."
            formatted_row.append(cell_str)
        lines.append(fmt.format(*formatted_row))

    return "\n".join(lines)


def format_tree(data: dict, prefix: str = "", is_last: bool = True) -> str:
    """Format nested dictionary as a tree structure."""
    lines = []
    items = list(data.items())
    for i, (key, value) in enumerate(items):
        is_last_item = i == len(items) - 1
        connector = "└── " if is_last_item else "├── "
        lines.append(f"{prefix}{connector}{key}")

        if isinstance(value, dict):
            extension = "    " if is_last_item else "│   "
            lines.append(format_tree(value, prefix + extension, is_last_item))
        elif isinstance(value, list):
            for j, item in enumerate(value):
                is_last_list = j == len(value) - 1
                list_connector = "└── " if is_last_list else "├── "
                if isinstance(item, dict):
                    lines.append(f"{prefix}{extension}{list_connector}[{j}]")
                    list_extension = "    " if is_last_list else "│   "
                    lines.append(format_tree(item, prefix + extension + list_extension, is_last_list))
                else:
                    lines.append(f"{prefix}{extension}{list_connector}{item}")
        else:
            lines.append(f"{prefix}{'    ' if is_last_item else '│   '}└── {value}")

    return "\n".join(lines)


def paginate(text: str, lines_per_page: int = 50) -> None:
    """Paginate output (simple implementation)."""
    lines = text.splitlines()
    for i in range(0, len(lines), lines_per_page):
        chunk = lines[i : i + lines_per_page]
        print("\n".join(chunk))
        if i + lines_per_page < len(lines):
            try:
                input("\n-- Press Enter for more -- ")
            except (EOFError, KeyboardInterrupt):
                print()
                break


def get_terminal_size() -> tuple[int, int]:
    """Get terminal size (width, height)."""
    try:
        size = os.get_terminal_size()
        return size.columns, size.lines
    except OSError:
        return 80, 24

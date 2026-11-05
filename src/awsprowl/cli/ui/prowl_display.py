"""Prowl-style clean text output display for awsProwl."""

from __future__ import annotations

import csv
import json
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from rich.console import Console
from rich.table import Table
from rich.text import Text

from awsprowl.core.config import get_config
from awsprowl.core.logging import get_logger

log = get_logger(__name__)


# Severity color mapping
SEVERITY_COLORS = {
    "critical": "bold red",
    "high": "red",
    "medium": "yellow",
    "low": "blue",
    "info": "green",
}

# Keywords for special highlighting
SECRET_KEYWORDS = [
    "secret", "password", "key", "token", "credential", "api_key", "apikey",
    "access_key", "secret_key", "private_key", "aws_secret", "aws_access",
    "authorization", "bearer", "jwt", "ssh", "certificate", "pem",
]
ERROR_KEYWORDS = [
    "error", "failed", "failure", "denied", "unauthorized", "forbidden",
    "exception", "traceback", "timeout", "connection refused",
]
WARNING_KEYWORDS = [
    "warning", "deprecated", "insecure", "public", "unencrypted", "open",
    "misconfigured", "weak", "outdated", "exposed",
]
INFO_KEYWORDS = [
    "info", "found", "discovered", "detected", "identified", "located",
    "region", "arn", "account", "profile", "version", "runtime",
]


class ProwlDisplay:
    """Prowl-style display helper for clean text output."""

    def __init__(self, console: Console | None = None, module_name: str | None = None):
        self.console = console or Console()
        self.module_name = module_name
        self.findings_count = 0
        self._start_time = datetime.now(timezone.utc)

    def _highlight_line(self, line: str) -> Text:
        """Apply color highlighting to a line based on keywords."""
        text = Text()
        # Check for secret keywords (highest priority)
        lower_line = line.lower()

        if any(kw in lower_line for kw in SECRET_KEYWORDS):
            text.append(line, style="bold red")
        elif any(kw in lower_line for kw in ERROR_KEYWORDS):
            text.append(line, style="red")
        elif any(kw in lower_line for kw in WARNING_KEYWORDS):
            text.append(line, style="yellow")
        elif any(kw in lower_line for kw in INFO_KEYWORDS):
            text.append(line, style="dim cyan")
        else:
            text.append(line)
        return text

    def running(self, message: str) -> None:
        """Print running module message."""
        prefix = f"[{self.module_name}] " if self.module_name else ""
        self.console.print(f"  Running {prefix}{message}...")

    def found(self, message: str) -> None:
        """Print a found item (progress)."""
        prefix = f"[{self.module_name}] " if self.module_name else ""
        self.console.print(f"  {prefix}Found: {message}")

    def info(self, message: str) -> None:
        """Print an info message."""
        prefix = f"[{self.module_name}] " if self.module_name else ""
        self.console.print(f"  {prefix}{message}")

    def warning(self, message: str) -> None:
        """Print a warning message."""
        prefix = f"[{self.module_name}] " if self.module_name else ""
        self.console.print(f"  {prefix}WARNING: {message}")

    def error(self, message: str) -> None:
        """Print an error message."""
        prefix = f"[{self.module_name}] " if self.module_name else ""
        self.console.print(f"  {prefix}ERROR: {message}")

    def access_denied(self, operation: str) -> None:
        """Print access denied message in Prowl style."""
        prefix = f"[{self.module_name}] " if self.module_name else ""
        self.console.print(f"  {prefix}Access Denied: {operation}")

    def print_findings(self, findings: list[dict], resource_type: str = "item") -> None:
        """Print findings in Prowl-style list format."""
        if not findings:
            self.info(f"No {resource_type}(s) found.")
            return

        self.findings_count = len(findings)
        self.info(f"Found {len(findings)} {resource_type}(s):")

        for finding in findings:
            title = finding.get("title", "")
            resource_id = finding.get("resource_id", finding.get("resource_name", ""))
            region = finding.get("region", "")
            severity = finding.get("severity", "info").upper()

            # Format: [SEVERITY] title (resource_id) [region]
            parts = []
            severity_color = SEVERITY_COLORS.get(severity.lower(), "white")
            parts.append(f"[{severity_color}]{severity}[/{severity_color}]")
            if title:
                parts.append(title)
            if resource_id:
                parts.append(f"({resource_id})")
            if region and region != "global":
                parts.append(f"[{region}]")

            self.console.print(f"    {' '.join(parts)}")

    def print_findings_detailed(self, findings: list[dict], resource_type: str = "item") -> None:
        """Print findings in Prowl-style detailed format (like Prowl's module output)."""
        if not findings:
            self.info(f"No {resource_type}(s) found.")
            return

        self.findings_count = len(findings)
        self.info(f"Found {len(findings)} {resource_type}(s):")

        for finding in findings:
            title = finding.get("title", "")
            description = finding.get("description", "")
            resource_id = finding.get("resource_id", finding.get("resource_name", ""))
            region = finding.get("region", "")
            severity = finding.get("severity", "info").upper()

            # Print the main finding line like Prowl
            parts = []
            severity_color = SEVERITY_COLORS.get(severity.lower(), "white")
            parts.append(f"[{severity_color}]{severity}[/{severity_color}]")
            if title:
                parts.append(title)
            if resource_id:
                parts.append(f"({resource_id})")
            if region and region != "global":
                parts.append(f"[{region}]")

            self.console.print(f"    {' '.join(parts)}")

            # Print detailed description if available (Prowl style)
            if description:
                # Split description into lines and print each with proper indentation
                for line in description.split('\n'):
                    if line.strip():
                        highlighted = self._highlight_line(line.strip())
                        self.console.print(f"      ", end="")
                        self.console.print(highlighted)

    def print_summary(self, module_name: str | None = None, extra_info: str | None = None) -> None:
        """Print module summary in Prowl style."""
        name = module_name or self.module_name or "module"
        elapsed = datetime.now(timezone.utc) - self._start_time
        elapsed_seconds = int(elapsed.total_seconds())

        self.console.print()
        self.console.print("MODULE SUMMARY:")
        self.console.print(f"  {self.findings_count} finding(s) found in {name} after {elapsed_seconds} second(s).")

        if extra_info:
            self.console.print(f"  {extra_info}")

    def print_data(self, data: Any, title: str | None = None) -> None:
        """Print JSON formatted data (for 'data' command)."""
        if title:
            self.console.print()
            self.console.print(f"--- {title} ---")

        self.console.print(json.dumps(data, indent=2, default=str))

    def print_section(self, title: str) -> None:
        """Print a section header."""
        self.console.print()
        self.console.print(f"=== {title} ===")

    def save_results(self, findings: list[dict], module_name: str, profile: str = None, service: str = None) -> None:
        """Save findings to output folder."""
        try:
            config = get_config()
            output_dir = Path(config.output.output_dir)
            if profile:
                output_dir = output_dir / profile
            output_dir.mkdir(parents=True, exist_ok=True)

            timestamp = datetime.now(timezone.utc).strftime('%Y%m%d-%H%M%S')
            if service:
                json_file = output_dir / f"{service}_{module_name}-{timestamp}.json"
            else:
                json_file = output_dir / f"awsprowl-{module_name}-{timestamp}.json"

            output_data = {
                "module": module_name,
                "timestamp": timestamp,
                "findings_count": len(findings),
                "findings": findings,
            }

            with open(json_file, "w") as f:
                json.dump(output_data, f, indent=2, default=str)

            self.info(f"Results saved to: {json_file}")
        except Exception as e:
            log.error("Failed to save results: %s", e)

    def export_csv(self, findings: list[dict], module_name: str, output_path: str | None = None) -> Path:
        """Export findings to CSV format."""
        try:
            config = get_config()
            output_dir = Path(config.output.output_dir)
            output_dir.mkdir(parents=True, exist_ok=True)

            timestamp = datetime.now(timezone.utc).strftime('%Y%m%d-%H%M%S')

            if output_path:
                csv_file = Path(output_path)
            else:
                csv_file = output_dir / f"awsprowl-{module_name}-{timestamp}.csv"

            if not findings:
                self.warning("No findings to export")
                return csv_file

            # Define CSV columns
            fieldnames = [
                "id", "title", "description", "severity", "category",
                "resource_type", "resource_id", "resource_name", "region", "account_id",
                "scan_id", "rule_id", "status", "tags", "created_at", "updated_at",
                "cvss_score", "cvss_vector", "destructive"
            ]

            with open(csv_file, "w", newline="") as f:
                writer = csv.DictWriter(f, fieldnames=fieldnames, extrasaction="ignore")
                writer.writeheader()

                for finding in findings:
                    # Flatten finding for CSV
                    row = {
                        "id": finding.get("id", ""),
                        "title": finding.get("title", ""),
                        "description": finding.get("description", ""),
                        "severity": finding.get("severity", "info"),
                        "category": finding.get("category", "informational"),
                        "resource_type": finding.get("resource_type", "other"),
                        "resource_id": finding.get("resource_id", ""),
                        "resource_name": finding.get("resource_name", ""),
                        "region": finding.get("region", ""),
                        "account_id": finding.get("account_id", ""),
                        "scan_id": finding.get("scan_id", ""),
                        "rule_id": finding.get("rule_id", ""),
                        "status": finding.get("status", "open"),
                        "tags": ",".join(finding.get("tags", [])) if finding.get("tags") else "",
                        "created_at": finding.get("created_at", ""),
                        "updated_at": finding.get("updated_at", ""),
                        "cvss_score": finding.get("cvss_score", ""),
                        "cvss_vector": finding.get("cvss_vector", ""),
                        "destructive": finding.get("destructive", False),
                    }
                    writer.writerow(row)

            self.info(f"CSV exported to: {csv_file}")
            return csv_file
        except Exception as e:
            log.error("Failed to export CSV: %s", e)
            self.error(f"CSV export failed: {e}")
            return Path("")

    def diff_scans(self, old_findings: list[dict], new_findings: list[dict]) -> dict:
        """Compare two scan results and return differences."""
        # Create lookup maps by resource_id + rule_id for comparison
        old_map = {}
        for f in old_findings:
            key = (f.get("resource_id", ""), f.get("rule_id", ""), f.get("region", ""))
            old_map[key] = f

        new_map = {}
        for f in new_findings:
            key = (f.get("resource_id", ""), f.get("rule_id", ""), f.get("region", ""))
            new_map[key] = f

        # Find new findings (in new but not in old)
        new_only = []
        for key, finding in new_map.items():
            if key not in old_map:
                new_only.append(finding)

        # Find resolved findings (in old but not in new)
        resolved = []
        for key, finding in old_map.items():
            if key not in new_map:
                resolved.append(finding)

        # Find changed findings (same key, different severity/status)
        changed = []
        for key in set(old_map.keys()) & set(new_map.keys()):
            old_f = old_map[key]
            new_f = new_map[key]

            # Check if severity or status changed
            if (old_f.get("severity") != new_f.get("severity") or
                old_f.get("status") != new_f.get("status") or
                old_f.get("description") != new_f.get("description")):
                changed.append({
                    "old": old_f,
                    "new": new_f,
                    "changes": self._get_changes(old_f, new_f)
                })

        # Count by severity
        def count_by_severity(findings_list):
            counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
            for f in findings_list:
                sev = f.get("severity", "info").lower()
                if sev in counts:
                    counts[sev] += 1
            return counts

        return {
            "new_findings": new_only,
            "resolved_findings": resolved,
            "changed_findings": changed,
            "summary": {
                "total_old": len(old_findings),
                "total_new": len(new_findings),
                "new_count": len(new_only),
                "resolved_count": len(resolved),
                "changed_count": len(changed),
                "old_by_severity": count_by_severity(old_findings),
                "new_by_severity": count_by_severity(new_findings),
                "new_only_by_severity": count_by_severity(new_only),
                "resolved_by_severity": count_by_severity(resolved),
            }
        }

    def _get_changes(self, old_f: dict, new_f: dict) -> list[str]:
        """Get list of changes between two findings."""
        changes = []
        if old_f.get("severity") != new_f.get("severity"):
            changes.append(f"severity: {old_f.get('severity')} → {new_f.get('severity')}")
        if old_f.get("status") != new_f.get("status"):
            changes.append(f"status: {old_f.get('status')} → {new_f.get('status')}")
        if old_f.get("description") != new_f.get("description"):
            changes.append("description: updated")
        if old_f.get("tags") != new_f.get("tags"):
            old_tags = set(old_f.get("tags", []))
            new_tags = set(new_f.get("tags", []))
            added = new_tags - old_tags
            removed = old_tags - new_tags
            if added:
                changes.append(f"tags added: {', '.join(added)}")
            if removed:
                changes.append(f"tags removed: {', '.join(removed)}")
        return changes

    def print_diff(self, diff_result: dict) -> None:
        """Print diff results in a formatted way."""
        summary = diff_result["summary"]

        self.console.print()
        self.console.print("=" * 60)
        self.console.print("[bold cyan]SCAN DIFF SUMMARY[/bold cyan]")
        self.console.print("=" * 60)

        self.console.print(f"\n  Old scan: {summary['total_old']} findings")
        self.console.print(f"  New scan: {summary['total_new']} findings")

        # New findings
        if diff_result["new_findings"]:
            self.console.print(f"\n  [bold green]NEW FINDINGS ({summary['new_count']}):[/bold green]")
            for sev in ["critical", "high", "medium", "low", "info"]:
                count = summary["new_only_by_severity"].get(sev, 0)
                if count:
                    color = SEVERITY_COLORS.get(sev, "white")
                    self.console.print(f"    [{color}]{sev.upper()}: {count}[/{color}]")

            self.console.print("\n  Details:")
            for finding in diff_result["new_findings"][:10]:
                sev = finding.get("severity", "info").upper()
                title = finding.get("title", "Unknown")
                resource = finding.get("resource_id", "N/A")
                region = finding.get("region", "")
                color = SEVERITY_COLORS.get(sev.lower(), "white")
                self.console.print(f"    [{color}]{sev}[/{color}] {title} ({resource})" + (f" [{region}]" if region else ""))
            if len(diff_result["new_findings"]) > 10:
                self.console.print(f"    ... and {len(diff_result['new_findings']) - 10} more")

        # Resolved findings
        if diff_result["resolved_findings"]:
            self.console.print(f"\n  [bold blue]RESOLVED FINDINGS ({summary['resolved_count']}):[/bold blue]")
            for sev in ["critical", "high", "medium", "low", "info"]:
                count = summary["resolved_by_severity"].get(sev, 0)
                if count:
                    color = SEVERITY_COLORS.get(sev, "white")
                    self.console.print(f"    [{color}]{sev.upper()}: {count}[/{color}]")

            self.console.print("\n  Details:")
            for finding in diff_result["resolved_findings"][:10]:
                sev = finding.get("severity", "info").upper()
                title = finding.get("title", "Unknown")
                resource = finding.get("resource_id", "N/A")
                color = SEVERITY_COLORS.get(sev.lower(), "white")
                self.console.print(f"    [{color}]{sev}[/{color}] {title} ({resource})")
            if len(diff_result["resolved_findings"]) > 10:
                self.console.print(f"    ... and {len(diff_result['resolved_findings']) - 10} more")

        # Changed findings
        if diff_result["changed_findings"]:
            self.console.print(f"\n  [bold yellow]CHANGED FINDINGS ({summary['changed_count']}):[/bold yellow]")
            for change in diff_result["changed_findings"][:10]:
                new_f = change["new"]
                old_f = change["old"]
                sev = new_f.get("severity", "info").upper()
                title = new_f.get("title", "Unknown")
                resource = new_f.get("resource_id", "N/A")
                color = SEVERITY_COLORS.get(sev.lower(), "white")
                self.console.print(f"    [{color}]{sev}[/{color}] {title} ({resource})")
                for c in change["changes"]:
                    self.console.print(f"      → {c}")
            if len(diff_result["changed_findings"]) > 10:
                self.console.print(f"    ... and {len(diff_result['changed_findings']) - 10} more")

        if not diff_result["new_findings"] and not diff_result["resolved_findings"] and not diff_result["changed_findings"]:
            self.console.print("\n  [green]No differences found - scans are identical[/green]")

        self.console.print()


def print_findings(findings: list[dict], resource_type: str = "item", console: Console | None = None, module_name: str | None = None) -> None:
    """Convenience function to print findings in Prowl style."""
    display = ProwlDisplay(console, module_name)
    display.print_findings(findings, resource_type)


def print_summary(findings_count: int, module_name: str, extra_info: str | None = None, console: Console | None = None) -> None:
    """Convenience function to print summary in Prowl style."""
    display = ProwlDisplay(console, module_name)
    display.findings_count = findings_count
    display.print_summary(module_name, extra_info)


def print_error(message: str, console: Console | None = None, module_name: str | None = None) -> None:
    """Convenience function to print error in Prowl style."""
    display = ProwlDisplay(console, module_name)
    display.error(message)


def print_data(data: Any, title: str | None = None, console: Console | None = None) -> None:
    """Convenience function to print JSON data."""
    display = ProwlDisplay(console)
    display.print_data(data, title)


def print_access_denied(operation: str, console: Console | None = None, module_name: str | None = None) -> None:
    """Convenience function to print access denied in Prowl style."""
    display = ProwlDisplay(console, module_name)
    display.access_denied(operation)
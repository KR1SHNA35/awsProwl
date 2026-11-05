"""Report formatters for awsProwl."""

from __future__ import annotations

import json
from datetime import datetime
from pathlib import Path
from typing import Any

from awsprowl.analysis.findings import FindingCollection, Severity
from awsprowl.core.logging import get_logger

log = get_logger(__name__)


class ReportFormatter:
    """Base class for report formatters."""

    def __init__(self, findings: FindingCollection):
        self.findings = findings

    def generate(self) -> str:
        """Generate the report content."""
        raise NotImplementedError

    def save(self, output_dir: Path, filename: str) -> Path:
        """Save the report to a file."""
        output_dir.mkdir(parents=True, exist_ok=True)
        filepath = output_dir / filename
        content = self.generate()
        filepath.write_text(content)
        return filepath


class HTMLReportFormatter(ReportFormatter):
    """Generate HTML report."""

    def generate(self) -> str:
        """Generate HTML report."""
        html = self._get_html_template()

        # Replace placeholders
        html = html.replace("{{SCAN_ID}}", self.findings.scan_id)
        html = html.replace("{{TIMESTAMP}}", datetime.now().isoformat())
        html = html.replace("{{TOTAL_FINDINGS}}", str(len(self.findings.findings)))
        from awsprowl.analysis.findings import Severity

        html = html.replace("{{CRITICAL_COUNT}}", str(self.findings.severity_counts.get(Severity.CRITICAL, 0)))
        html = html.replace("{{HIGH_COUNT}}", str(self.findings.severity_counts.get(Severity.HIGH, 0)))
        html = html.replace("{{MEDIUM_COUNT}}", str(self.findings.severity_counts.get(Severity.MEDIUM, 0)))
        html = html.replace("{{LOW_COUNT}}", str(self.findings.severity_counts.get(Severity.LOW, 0)))
        html = html.replace("{{INFO_COUNT}}", str(self.findings.severity_counts.get(Severity.INFO, 0)))

        # Generate findings table rows
        findings_rows = ""
        for i, finding in enumerate(self.findings.findings, 1):
            severity_class = finding.severity.lower()
            findings_rows += f"""
            <tr class="severity-{severity_class}">
                <td>{i}</td>
                <td><span class="severity-badge severity-{severity_class}">{finding.severity.upper()}</span></td>
                <td>{finding.title}</td>
                <td>{finding.description}</td>
                <td>{finding.resource_type}</td>
                <td>{finding.resource_id}</td>
                <td>{finding.region}</td>
                <td>{finding.category}</td>
            </tr>
            """

        html = html.replace("{{FINDINGS_ROWS}}", findings_rows)

        return html

    def _get_html_template(self) -> str:
        """Get HTML template."""
        return """<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>awsProwl Security Scan Report - {{SCAN_ID}}</title>
    <style>
        * { box-sizing: border-box; margin: 0; padding: 0; }
        body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; line-height: 1.6; color: #333; background: #f5f5f5; }
        .container { max-width: 1400px; margin: 0 auto; padding: 20px; }
        header { background: linear-gradient(135deg, #1a1a2e 0%, #16213e 100%); color: white; padding: 30px; border-radius: 8px; margin-bottom: 30px; box-shadow: 0 4px 6px rgba(0,0,0,0.1); }
        header h1 { font-size: 2.5rem; margin-bottom: 10px; }
        header .meta { display: flex; gap: 30px; flex-wrap: wrap; font-size: 0.9rem; opacity: 0.9; }
        .summary-cards { display: grid; grid-template-columns: repeat(auto-fit, minmax(150px, 1fr)); gap: 20px; margin-bottom: 30px; }
        .summary-card { background: white; padding: 20px; border-radius: 8px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); text-align: center; }
        .summary-card .number { font-size: 2.5rem; font-weight: bold; margin-bottom: 5px; }
        .summary-card .label { font-size: 0.85rem; text-transform: uppercase; color: #666; }
        .summary-card.critical .number { color: #dc3545; }
        .summary-card.high .number { color: #fd7e14; }
        .summary-card.medium .number { color: #ffc107; }
        .summary-card.low .number { color: #28a745; }
        .summary-card.info .number { color: #17a2b8; }
        .summary-card.total .number { color: #6f42c1; }
        table { width: 100%; border-collapse: collapse; background: white; border-radius: 8px; overflow: hidden; box-shadow: 0 2px 4px rgba(0,0,0,0.1); }
        th, td { padding: 12px 15px; text-align: left; border-bottom: 1px solid #eee; }
        th { background: #1a1a2e; color: white; font-weight: 600; }
        tr:last-child td { border-bottom: none; }
        tr:hover td { background: #f8f9fa; }
        .severity-badge { display: inline-block; padding: 3px 8px; border-radius: 4px; font-size: 0.75rem; font-weight: 600; text-transform: uppercase; }
        .severity-critical { background: #f8d7da; color: #721c24; }
        .severity-high { background: #ffeaa7; color: #856404; }
        .severity-medium { background: #fff3cd; color: #856404; }
        .severity-low { background: #d4edda; color: #155724; }
        .severity-info { background: #d1ecf1; color: #0c5460; }
        tr.severity-critical td:first-child { border-left: 4px solid #dc3545; }
        tr.severity-high td:first-child { border-left: 4px solid #fd7e14; }
        tr.severity-medium td:first-child { border-left: 4px solid #ffc107; }
        tr.severity-low td:first-child { border-left: 4px solid #28a745; }
        tr.severity-info td:first-child { border-left: 4px solid #17a2b8; }
        .no-findings { text-align: center; padding: 60px 20px; color: #666; }
        .no-findings h2 { color: #28a745; margin-bottom: 10px; }
        footer { margin-top: 30px; padding: 20px; text-align: center; color: #666; font-size: 0.85rem; }
        @media (max-width: 768px) {
            .container { padding: 10px; }
            table { font-size: 0.85rem; }
            th, td { padding: 8px 10px; }
        }
    </style>
</head>
<body>
    <div class="container">
        <header>
            <h1>🔍 awsProwl Security Scan Report</h1>
            <div class="meta">
                <span><strong>Scan ID:</strong> {{SCAN_ID}}</span>
                <span><strong>Generated:</strong> {{TIMESTAMP}}</span>
                <span><strong>Total Findings:</strong> {{TOTAL_FINDINGS}}</span>
            </div>
        </header>

        <div class="summary-cards">
            <div class="summary-card total">
                <div class="number">{{TOTAL_FINDINGS}}</div>
                <div class="label">Total Findings</div>
            </div>
            <div class="summary-card critical">
                <div class="number">{{CRITICAL_COUNT}}</div>
                <div class="label">Critical</div>
            </div>
            <div class="summary-card high">
                <div class="number">{{HIGH_COUNT}}</div>
                <div class="label">High</div>
            </div>
            <div class="summary-card medium">
                <div class="number">{{MEDIUM_COUNT}}</div>
                <div class="label">Medium</div>
            </div>
            <div class="summary-card low">
                <div class="number">{{LOW_COUNT}}</div>
                <div class="label">Low</div>
            </div>
            <div class="summary-card info">
                <div class="number">{{INFO_COUNT}}</div>
                <div class="label">Info</div>
            </div>
        </div>

        {% if findings %}
        <table>
            <thead>
                <tr>
                    <th>#</th>
                    <th>Severity</th>
                    <th>Title</th>
                    <th>Description</th>
                    <th>Resource Type</th>
                    <th>Resource ID</th>
                    <th>Region</th>
                    <th>Category</th>
                </tr>
            </thead>
            <tbody>
                {{FINDINGS_ROWS}}
            </tbody>
        </table>
        {% else %}
        <div class="no-findings">
            <h2>✅ No Security Findings</h2>
            <p>All checks passed. Your AWS environment appears to be secure!</p>
        </div>
        {% endif %}

        <footer>
            <p>Generated by <strong>awsProwl</strong> - AWS Security Assessment Tool</p>
            <p>Scan completed at {{TIMESTAMP}}</p>
        </footer>
    </div>
</body>
</html>"""


class MarkdownReportFormatter(ReportFormatter):
    """Generate Markdown report."""

    def generate(self) -> str:
        """Generate Markdown report."""
        lines = [
            "# awsProwl Security Scan Report",
            "",
            f"**Scan ID:** {self.findings.scan_id}",
            f"**Generated:** {datetime.now().isoformat()}",
            f"**Total Findings:** {len(self.findings.findings)}",
            "",
            "## Summary",
            "",
            "| Severity | Count |",
            "|----------|-------|",
            f"| Critical | {self.findings.severity_counts.get(Severity.CRITICAL, 0)} |",
            f"| High | {self.findings.severity_counts.get(Severity.HIGH, 0)} |",
            f"| Medium | {self.findings.severity_counts.get(Severity.MEDIUM, 0)} |",
            f"| Low | {self.findings.severity_counts.get(Severity.LOW, 0)} |",
            f"| Info | {self.findings.severity_counts.get(Severity.INFO, 0)} |",
            "",
            "## Findings",
            "",
        ]

        if not self.findings.findings:
            lines.append("*No security findings - all checks passed!*")
            return "\n".join(lines)

        for i, finding in enumerate(self.findings.findings, 1):
            lines.extend([
                f"### {i}. {finding.title}",
                "",
                f"**Severity:** {finding.severity.upper()}",
                f"**Category:** {finding.category}",
                f"**Resource:** {finding.resource_type} - {finding.resource_id}",
                f"**Region:** {finding.region}",
                f"**Rule ID:** {finding.rule_id}",
                "",
                "**Description:**",
                f"{finding.description}",
                "",
            ])

            if finding.evidence:
                lines.append("**Evidence:**")
                for ev in finding.evidence:
                    lines.append(f"- {ev.description}: {ev.data}")
                lines.append("")

            if finding.remediation:
                lines.append("**Remediation:**")
                lines.append(f"- **Summary:** {finding.remediation.summary}")
                if finding.remediation.steps:
                    lines.append("- **Steps:**")
                    for step in finding.remediation.steps:
                        lines.append(f"  - {step}")
                if finding.remediation.cli_commands:
                    lines.append("- **CLI Commands:**")
                    for cmd in finding.remediation.cli_commands:
                        lines.append("  ```bash")
                        lines.append(f"  {cmd}")
                        lines.append("  ```")
                lines.append("")

            lines.append("---")
            lines.append("")

        lines.append(f"*Report generated by awsProwl at {datetime.now().isoformat()}*")
        return "\n".join(lines)


class SARIFReportFormatter(ReportFormatter):
    """Generate SARIF (Static Analysis Results Interchange Format) report."""

    def generate(self) -> str:
        """Generate SARIF report."""
        sarif = {
            "version": "2.1.0",
            "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
            "runs": [
                {
                    "tool": {
                        "driver": {
                            "name": "awsProwl",
                            "version": "1.0.0",
                            "informationUri": "https://github.com/blackhat/awsprowl",
                            "rules": self._generate_rules(),
                        }
                    },
                    "results": self._generate_results(),
                    "invocations": [
                        {
                            "executionSuccessful": True,
                            "startTimeUtc": self.findings.created_at.isoformat() if self.findings.created_at else datetime.now().isoformat(),
                            "endTimeUtc": datetime.now().isoformat(),
                        }
                    ],
                }
            ],
        }
        return json.dumps(sarif, indent=2)

    def _generate_rules(self) -> list[dict[str, Any]]:
        """Generate SARIF rules from findings."""
        rules: dict[str, dict[str, Any]] = {}
        for finding in self.findings.findings:
            rule_id = finding.rule_id or f"awsprowl-{finding.category}"
            if rule_id not in rules:
                rules[rule_id] = {
                    "id": rule_id,
                    "name": rule_id,
                    "shortDescription": {"text": finding.title},
                    "fullDescription": {"text": finding.description},
                    "defaultConfiguration": {
                        "level": self._severity_to_sarif_level(finding.severity)
                    },
                    "help": {
                        "text": finding.description,
                        "markdown": finding.description,
                    },
                    "properties": {
                        "category": finding.category,
                        "resource_type": finding.resource_type,
                    }
                }
        return list(rules.values())

    def _generate_results(self) -> list[dict[str, Any]]:
        """Generate SARIF results from findings."""
        results: list[dict[str, Any]] = []
        for finding in self.findings.findings:
            rule_id = finding.rule_id or f"awsprowl-{finding.category}"
            result: dict[str, Any] = {
                "ruleId": rule_id,
                "level": self._severity_to_sarif_level(finding.severity),
                "message": {"text": finding.description},
                "locations": [
                    {
                        "physicalLocation": {
                            "artifactLocation": {
                                "uri": f"aws://{finding.region}/{finding.resource_type}/{finding.resource_id}",
                                "description": {"text": f"{finding.resource_type}: {finding.resource_id}"},
                            },
                            "region": {
                                "startLine": 1,
                            },
                        }
                    }
                ],
                "properties": {
                    "resource_type": finding.resource_type,
                    "resource_id": finding.resource_id,
                    "resource_name": finding.resource_name,
                    "region": finding.region,
                    "category": finding.category,
                    "tags": finding.tags,
                }
            }
            if finding.remediation:
                result["fixes"] = [
                    {
                        "description": {"text": finding.remediation.summary},
                    }
                ]
            results.append(result)
        return results

    def _severity_to_sarif_level(self, severity: str) -> str:
        """Map awsProwl severity to SARIF level."""
        mapping = {
            "critical": "error",
            "high": "error",
            "medium": "warning",
            "low": "note",
            "info": "none",
        }
        return mapping.get(severity.lower(), "warning")


def generate_report(findings: FindingCollection, format: str, output_dir: Path, scan_id: str) -> Path:
    """Generate a report in the specified format."""
    formatter: ReportFormatter
    if format == "html":
        formatter = HTMLReportFormatter(findings)
        filename = f"report-{scan_id}.html"
    elif format == "markdown":
        formatter = MarkdownReportFormatter(findings)
        filename = f"report-{scan_id}.md"
    elif format == "sarif":
        formatter = SARIFReportFormatter(findings)
        filename = f"report-{scan_id}.sarif"
    else:
        raise ValueError(f"Unknown report format: {format}")

    return formatter.save(output_dir, filename)

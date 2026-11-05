"""CloudWatch scanner for awsProwl."""

from __future__ import annotations

import botocore.exceptions
from awsprowl.aws.base import AWSServiceBase, ScanResult
from awsprowl.core.auth import AWSAuthManager
from awsprowl.core.logging import get_logger

log = get_logger(__name__)


class CloudWatchScanner(AWSServiceBase):
    """Scanner for CloudWatch resources."""

    SERVICE_NAME = "cloudwatch"
    REQUIRED_PERMISSIONS = [
        "logs:DescribeLogGroups",
        "logs:DescribeLogStreams",
        "cloudwatch:DescribeAlarms",
        "cloudwatch:ListDashboards",
        "cloudwatch:GetDashboard",
    ]

    def __init__(self, auth_manager: AWSAuthManager, region: str | None = None):
        super().__init__(auth_manager, region)

    async def scan(self, scan_id: str, findings: list) -> ScanResult:
        """Scan CloudWatch resources for security issues."""
        result = ScanResult(service=self.SERVICE_NAME, region=self.region)
        
        try:
            await self._scan_log_groups(scan_id, findings, result)
            await self._scan_metric_alarms(scan_id, findings, result)
            await self._scan_dashboards(scan_id, findings, result)
        except botocore.exceptions.ClientError as e:
            log.error(f"CloudWatch scan failed: {e}")
            result.errors.append(str(e))
        
        return result

    async def _scan_log_groups(self, scan_id: str, findings: list, result: ScanResult):
        """Scan log groups."""
        try:
            paginator = self.client.get_paginator("describe_log_groups")
            for page in paginator.paginate():
                for lg in page.get("logGroups", []):
                    lg_name = lg.get("logGroupName")
                    lg_arn = lg.get("arn", "Unknown")
                    
                    findings.append({
                        "title": f"CloudWatch Log Group: {lg_name}",
                        "description": f"ARN: {lg_arn}\nRetention: {lg.get('retentionInDays', 'Never expire')} days\nStored Bytes: {lg.get('storedBytes', 0)}",
                        "severity": "info",
                        "category": "enumeration",
                        "resource_type": "cloudwatch_log_group",
                        "resource_id": lg_arn,
                        "resource_name": lg_name,
                        "region": self.region,
                        "rule_id": "cloudwatch_enum_log_groups",
                    })
                    result.resources_scanned += 1
        except botocore.exceptions.ClientError as e:
            log.error(f"Failed to scan log groups: {e}")
            result.errors.append(str(e))

    async def _scan_metric_alarms(self, scan_id: str, findings: list, result: ScanResult):
        """Scan metric alarms."""
        try:
            paginator = self.client.get_paginator("describe_alarms")
            for page in paginator.paginate():
                for alarm in page.get("MetricAlarms", []):
                    alarm_name = alarm.get("AlarmName")
                    alarm_arn = alarm.get("AlarmArn", "Unknown")
                    
                    findings.append({
                        "title": f"CloudWatch Alarm: {alarm_name}",
                        "description": f"ARN: {alarm_arn}\nState: {alarm.get('StateValue', 'Unknown')}\nMetric: {alarm.get('MetricName', 'Unknown')}\nNamespace: {alarm.get('Namespace', 'Unknown')}\nComparison: {alarm.get('ComparisonOperator', 'Unknown')}",
                        "severity": "info",
                        "category": "enumeration",
                        "resource_type": "cloudwatch_alarm",
                        "resource_id": alarm_arn,
                        "resource_name": alarm_name,
                        "region": self.region,
                        "rule_id": "cloudwatch_enum_metric_alarms",
                    })
                    result.resources_scanned += 1
        except botocore.exceptions.ClientError as e:
            log.error(f"Failed to scan metric alarms: {e}")
            result.errors.append(str(e))

    async def _scan_dashboards(self, scan_id: str, findings: list, result: ScanResult):
        """Scan dashboards."""
        try:
            paginator = self.client.get_paginator("list_dashboards")
            for page in paginator.paginate():
                for dash in page.get("DashboardEntries", []):
                    dash_name = dash.get("DashboardName")
                    
                    detail = self.client.get_dashboard(DashboardName=dash_name)
                    dash_body = detail.get("DashboardBody", "{}")
                    
                    findings.append({
                        "title": f"CloudWatch Dashboard: {dash_name}",
                        "description": f"ARN: {dash.get('DashboardArn', 'Unknown')}\nLast Modified: {dash.get('LastModified', 'Unknown')}\nSize: {len(dash_body)} chars",
                        "severity": "info",
                        "category": "enumeration",
                        "resource_type": "cloudwatch_dashboard",
                        "resource_id": dash_name,
                        "resource_name": dash_name,
                        "region": self.region,
                        "rule_id": "cloudwatch_enum_dashboards",
                    })
                    result.resources_scanned += 1
        except botocore.exceptions.ClientError as e:
            log.error(f"Failed to scan dashboards: {e}")
            result.errors.append(str(e))

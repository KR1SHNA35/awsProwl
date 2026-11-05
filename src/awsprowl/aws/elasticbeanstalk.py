"""Elastic Beanstalk scanner for awsProwl."""

from __future__ import annotations

import botocore.exceptions
from awsprowl.aws.base import AWSServiceBase, ScanResult
from awsprowl.core.auth import AWSAuthManager
from awsprowl.core.logging import get_logger

log = get_logger(__name__)


class ElasticBeanstalkScanner(AWSServiceBase):
    """Scanner for Elastic Beanstalk resources."""

    SERVICE_NAME = "elasticbeanstalk"
    REQUIRED_PERMISSIONS = [
        "elasticbeanstalk:DescribeApplications",
        "elasticbeanstalk:DescribeEnvironments",
        "elasticbeanstalk:DescribeConfigurationSettings",
    ]

    def __init__(self, auth_manager: AWSAuthManager, region: str | None = None):
        super().__init__(auth_manager, region)

    async def scan(self, scan_id: str, findings: list) -> ScanResult:
        """Scan Elastic Beanstalk resources for security issues."""
        result = ScanResult(service=self.SERVICE_NAME, region=self.region)
        
        try:
            await self._scan_applications(scan_id, findings, result)
            await self._scan_environments(scan_id, findings, result)
        except botocore.exceptions.ClientError as e:
            log.error(f"Elastic Beanstalk scan failed: {e}")
            result.errors.append(str(e))
        
        return result

    async def _scan_applications(self, scan_id: str, findings: list, result: ScanResult):
        """Scan applications."""
        try:
            response = self.client.describe_applications()
            for app in response.get("Applications", []):
                name = app.get("ApplicationName")
                
                findings.append({
                    "title": f"Elastic Beanstalk Application: {name}",
                    "description": f"Description: {app.get('Description', 'None')}\nDate Created: {app.get('DateCreated', 'Unknown')}\nDate Updated: {app.get('DateUpdated', 'Unknown')}",
                    "severity": "info",
                    "category": "enumeration",
                    "resource_type": "elasticbeanstalk_application",
                    "resource_id": name,
                    "resource_name": name,
                    "region": self.region,
                    "rule_id": "elasticbeanstalk_enum_applications",
                })
                result.resources_scanned += 1
        except botocore.exceptions.ClientError as e:
            log.error(f"Failed to scan applications: {e}")
            result.errors.append(str(e))

    async def _scan_environments(self, scan_id: str, findings: list, result: ScanResult):
        """Scan environments."""
        try:
            paginator = self.client.get_paginator("describe_environments")
            for page in paginator.paginate():
                for env in page.get("Environments", []):
                    env_id = env.get("EnvironmentId")
                    name = env.get("EnvironmentName")
                    
                    findings.append({
                        "title": f"Elastic Beanstalk Environment: {name}",
                        "description": f"Environment ID: {env_id}\nApplication: {env.get('ApplicationName', 'Unknown')}\nStatus: {env.get('Status', 'Unknown')}\nHealth: {env.get('Health', 'Unknown')}\nPlatform: {env.get('PlatformArn', 'Unknown')}",
                        "severity": "info",
                        "category": "enumeration",
                        "resource_type": "elasticbeanstalk_environment",
                        "resource_id": env_id,
                        "resource_name": name,
                        "region": self.region,
                        "rule_id": "elasticbeanstalk_enum_resources",
                    })
                    result.resources_scanned += 1
        except botocore.exceptions.ClientError as e:
            log.error(f"Failed to scan environments: {e}")
            result.errors.append(str(e))

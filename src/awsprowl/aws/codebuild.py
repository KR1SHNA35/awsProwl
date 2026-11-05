"""CodeBuild scanner for awsProwl."""

from __future__ import annotations

import botocore.exceptions
from awsprowl.aws.base import AWSServiceBase, ScanResult
from awsprowl.core.auth import AWSAuthManager
from awsprowl.core.logging import get_logger

log = get_logger(__name__)


class CodeBuildScanner(AWSServiceBase):
    """Scanner for CodeBuild resources."""

    SERVICE_NAME = "codebuild"
    REQUIRED_PERMISSIONS = [
        "codebuild:ListProjects",
        "codebuild:BatchGetProjects",
        "codebuild:ListBuilds",
        "codebuild:BatchGetBuilds",
    ]

    def __init__(self, auth_manager: AWSAuthManager, region: str | None = None):
        super().__init__(auth_manager, region)

    async def scan(self, scan_id: str, findings: list) -> ScanResult:
        """Scan CodeBuild resources for security issues."""
        result = ScanResult(service=self.SERVICE_NAME, region=self.region)
        
        try:
            await self._scan_projects(scan_id, findings, result)
        except botocore.exceptions.ClientError as e:
            log.error(f"CodeBuild scan failed: {e}")
            result.errors.append(str(e))
        
        return result

    async def _scan_projects(self, scan_id: str, findings: list, result: ScanResult):
        """Scan CodeBuild projects."""
        try:
            paginator = self.client.get_paginator("list_projects")
            for page in paginator.paginate():
                for project_name in page.get("projects", []):
                    project_details = self.client.batch_get_projects(names=[project_name])
                    for project in project_details.get("projects", []):
                        name = project.get("name")
                        
                        findings.append({
                            "title": f"CodeBuild Project: {name}",
                            "description": f"Service Role: {project.get('serviceRole', 'Unknown')}\nEnvironment: {project.get('environment', {}).get('type', 'Unknown')}\nImage: {project.get('environment', {}).get('image', 'Unknown')}",
                            "severity": "info",
                            "category": "enumeration",
                            "resource_type": "codebuild_project",
                            "resource_id": name,
                            "resource_name": name,
                            "region": self.region,
                            "rule_id": "codebuild_enum_projects",
                        })
                        result.resources_scanned += 1
        except botocore.exceptions.ClientError as e:
            log.error(f"Failed to scan CodeBuild projects: {e}")
            result.errors.append(str(e))

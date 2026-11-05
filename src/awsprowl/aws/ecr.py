"""ECR scanner for awsProwl."""

from __future__ import annotations

import botocore.exceptions
from awsprowl.aws.base import AWSServiceBase, ScanResult
from awsprowl.core.auth import AWSAuthManager
from awsprowl.core.logging import get_logger

log = get_logger(__name__)


class ECRScanner(AWSServiceBase):
    """Scanner for ECR resources."""

    SERVICE_NAME = "ecr"
    REQUIRED_PERMISSIONS = [
        "ecr:DescribeRepositories",
        "ecr:DescribeImages",
        "ecr:DescribeImageScanFindings",
        "ecr:DescribePullThroughCacheRules",
    ]

    def __init__(self, auth_manager: AWSAuthManager, region: str | None = None):
        super().__init__(auth_manager, region)

    async def scan(self, scan_id: str, findings: list) -> ScanResult:
        """Scan ECR resources for security issues."""
        result = ScanResult(service=self.SERVICE_NAME, region=self.region)
        
        try:
            await self._scan_repositories(scan_id, findings, result)
            await self._scan_pull_through_cache(scan_id, findings, result)
        except botocore.exceptions.ClientError as e:
            log.error(f"ECR scan failed: {e}")
            result.errors.append(str(e))
        
        return result

    async def _scan_repositories(self, scan_id: str, findings: list, result: ScanResult):
        """Scan repositories."""
        try:
            paginator = self.client.get_paginator("describe_repositories")
            for page in paginator.paginate():
                for repo in page.get("repositories", []):
                    repo_name = repo.get("repositoryName")
                    repo_uri = repo.get("repositoryUri", "Unknown")
                    
                    findings.append({
                        "title": f"ECR Repository: {repo_name}",
                        "description": f"URI: {repo_uri}\nImage Tag Mutability: {repo.get('imageTagMutability', 'Unknown')}\nImage Scanning: {repo.get('imageScanningConfiguration', {}).get('scanOnPush', False)}",
                        "severity": "info",
                        "category": "enumeration",
                        "resource_type": "ecr_repository",
                        "resource_id": repo_name,
                        "resource_name": repo_name,
                        "region": self.region,
                        "rule_id": "ecr_enum_repositories",
                    })
                    result.resources_scanned += 1
        except botocore.exceptions.ClientError as e:
            log.error(f"Failed to scan repositories: {e}")
            result.errors.append(str(e))

    async def _scan_pull_through_cache(self, scan_id: str, findings: list, result: ScanResult):
        """Scan pull through cache rules."""
        try:
            paginator = self.client.get_paginator("describe_pull_through_cache_rules")
            for page in paginator.paginate():
                for rule in page.get("pullThroughCacheRules", []):
                    ecr_repo = rule.get("ecrRepositoryPrefix", "Unknown")
                    upstream = rule.get("upstreamRegistryUrl", "Unknown")
                    
                    findings.append({
                        "title": f"ECR Pull Through Cache: {ecr_repo}",
                        "description": f"Upstream: {upstream}\nCredential ARN: {rule.get('credentialArn', 'None')}\nCreated: {rule.get('createdAt', 'Unknown')}",
                        "severity": "info",
                        "category": "enumeration",
                        "resource_type": "ecr_pull_through_cache",
                        "resource_id": ecr_repo,
                        "resource_name": ecr_repo,
                        "region": self.region,
                        "rule_id": "ecr_enum_pull_through_cache",
                    })
                    result.resources_scanned += 1
        except botocore.exceptions.ClientError as e:
            log.error(f"Failed to scan pull through cache: {e}")
            result.errors.append(str(e))

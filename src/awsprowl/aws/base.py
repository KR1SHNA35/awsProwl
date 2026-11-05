"""Base AWS service module for awsProwl."""

from __future__ import annotations

import asyncio
from abc import ABC, abstractmethod
from dataclasses import dataclass

import botocore.config
import botocore.exceptions
from botocore.paginate import PageIterator

from awsprowl.core.auth import AWSAuthManager
from awsprowl.core.logging import get_logger

log = get_logger(__name__)


@dataclass
class ScanResult:
    """Result of a service scan."""

    service: str
    region: str
    resources_found: int = 0
    findings: list = None
    errors: list = None
    duration_ms: float = 0.0

    def __post_init__(self):
        if self.findings is None:
            self.findings = []
        if self.errors is None:
            self.errors = []


class AWSServiceBase(ABC):
    """Base class for AWS service scanners."""

    SERVICE_NAME: str = "unknown"
    REQUIRED_PERMISSIONS: list[str] = []

    def __init__(
        self,
        auth_manager: AWSAuthManager,
        region: str | None = None,
        config: botocore.config.Config | None = None,
    ):
        self.auth_manager = auth_manager
        self.region = region or auth_manager.region
        self.config = config or botocore.config.Config(
            retries={"max_attempts": 3, "mode": "adaptive"},
            connect_timeout=30,
            read_timeout=30,
        )
        self._client = None
        self._resource = None

    @property
    def client(self):
        """Get or create the boto3 client."""
        if self._client is None:
            self._client = self.auth_manager.get_client(
                self.SERVICE_NAME,
                region=self.region,
                config=self.config,
            )
        return self._client

    @property
    def resource(self):
        """Get or create the boto3 resource."""
        if self._resource is None:
            self._resource = self.auth_manager.get_resource(
                self.SERVICE_NAME,
                region=self.region,
                config=self.config,
            )
        return self._resource

    def paginate(
        self,
        operation: str,
        **kwargs,
    ) -> PageIterator:
        """Create a paginator for an operation."""
        paginator = self.client.get_paginator(operation)
        return paginator.paginate(**kwargs)

    def handle_client_error(self, error: botocore.exceptions.ClientError, operation: str, findings: list | None = None) -> dict | None:
        """Handle boto3 client errors and return a clean finding for permission issues.

        Like Prowler, returns clean "Access Denied" messages instead of verbose AWS errors.
        """
        error_code = error.response["Error"]["Code"]
        error_msg = error.response["Error"]["Message"]

        if error_code in ("AccessDenied", "UnauthorizedOperation", "AuthFailure"):
            finding = {
                "title": f"Access Denied: {self.SERVICE_NAME}:{operation}",
                "description": f"Not authorized to perform {self.SERVICE_NAME}:{operation}. Required permissions are missing.",
                "severity": "info",
                "category": "informational",
                "resource_type": "aws_permission",
                "resource_id": f"{self.SERVICE_NAME}:{operation}",
                "resource_name": f"{self.SERVICE_NAME}:{operation}",
                "region": self.region,
                "rule_id": f"access_denied_{self.SERVICE_NAME.lower()}_{operation.lower()}",
            }
            if findings is not None:
                findings.append(finding)
            return finding

        # For other errors, log and return None
        log.debug("Error in %s:%s: %s", self.SERVICE_NAME, operation, error_msg)
        return None

    @abstractmethod
    async def scan(self, scan_id: str, findings: list) -> ScanResult:
        """Scan the service and populate findings."""
        pass

    def create_finding(
        self,
        title: str,
        description: str,
        severity: str,
        category: str,
        resource_type: str,
        resource_id: str,
        resource_name: str = "",
        region: str | None = None,
        evidence: list | None = None,
        remediation: dict | None = None,
        rule_id: str = "",
        tags: list | None = None,
    ) -> dict:
        """Create a standardized finding dictionary."""

        finding = {
            "title": title,
            "description": description,
            "severity": severity,
            "category": category,
            "resource_type": resource_type,
            "resource_id": resource_id,
            "resource_name": resource_name,
            "region": region or self.region,
            "rule_id": rule_id or f"{self.SERVICE_NAME}_{title.lower().replace(' ', '_')}",
            "tags": tags or [],
            "evidence": evidence or [],
            "remediation": remediation,
        }
        return finding


class ParallelScanner:
    """Utility for running multiple service scanners in parallel."""

    def __init__(self, auth_manager: AWSAuthManager, max_workers: int = 10):
        self.auth_manager = auth_manager
        self.max_workers = max_workers
        self._semaphore = asyncio.Semaphore(max_workers)

    async def scan_services(
        self,
        services: list[str],
        regions: list[str],
        scan_id: str,
        findings: list,
    ) -> list[ScanResult]:
        """Scan multiple services across multiple regions in parallel."""

        tasks = []
        for region in regions:
            for service_name in services:
                task = self._scan_service_region(service_name, region, scan_id, findings)
                tasks.append(task)

        results = await asyncio.gather(*tasks, return_exceptions=True)

        # Process results
        scan_results = []
        for i, result in enumerate(results):
            if isinstance(result, Exception):
                log.error("Scan task failed: {}", result)
                # Create error result
                service_idx = i // len(regions)
                region_idx = i % len(regions)
                if service_idx < len(services) and region_idx < len(regions):
                    scan_results.append(ScanResult(
                        service=services[service_idx],
                        region=regions[region_idx],
                        errors=[str(result)],
                    ))
            else:
                scan_results.append(result)

        return scan_results

    async def _scan_service_region(
        self,
        service_name: str,
        region: str,
        scan_id: str,
        findings: list,
    ) -> ScanResult:
        """Scan a single service in a single region."""

        async with self._semaphore:
            # Import scanner class dynamically
            from awsprowl.aws import (
                BeanstalkScanner,
                CloudFrontScanner,
                CognitoScanner,
                DynamoDBScanner,
                EC2Scanner,
                ECSScanner,
                EKSScanner,
                IAMScanner,
                KMSScanner,
                LambdaScanner,
                OrganizationsScanner,
                RDSScanner,
                S3Scanner,
                SecretsScanner,
                SNSScanner,
                STSScanner,
            )

            scanner_map = {
                "iam": IAMScanner,
                "ec2": EC2Scanner,
                "s3": S3Scanner,
                "lambda": LambdaScanner,
                "ecs": ECSScanner,
                "secretsmanager": SecretsScanner,
                "sns": SNSScanner,
                "beanstalk": BeanstalkScanner,
                "cognito": CognitoScanner,
                "sts": STSScanner,
                "rds": RDSScanner,
                "dynamodb": DynamoDBScanner,
                "cloudfront": CloudFrontScanner,
                "kms": KMSScanner,
                "eks": EKSScanner,
                "organizations": OrganizationsScanner,
            }

            scanner_class = scanner_map.get(service_name)
            if not scanner_class:
                return ScanResult(
                    service=service_name,
                    region=region,
                    errors=[f"Unknown service: {service_name}"],
                )

            # Create region-specific auth manager if needed
            if region != self.auth_manager.region:
                region_auth = self.auth_manager
                # Note: In practice, we'd create a new auth manager with the region
                # For now, we'll use the existing one and override region in client creation
            else:
                region_auth = self.auth_manager

            scanner = scanner_class(region_auth, region=region)

            try:
                import time
                start = time.time()
                result = await scanner.scan(scan_id, findings)
                result.duration_ms = (time.time() - start) * 1000
                return result
            except Exception as e:
                log.error("Error scanning {} in {}: {}", service_name, region, e)
                return ScanResult(
                    service=service_name,
                    region=region,
                    errors=[str(e)],
                )

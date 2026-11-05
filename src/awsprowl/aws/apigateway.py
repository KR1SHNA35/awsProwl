"""API Gateway scanner for awsProwl."""

from __future__ import annotations

import botocore.exceptions
from awsprowl.aws.base import AWSServiceBase, ScanResult
from awsprowl.core.auth import AWSAuthManager
from awsprowl.core.logging import get_logger

log = get_logger(__name__)


class APIGatewayScanner(AWSServiceBase):
    """Scanner for API Gateway resources."""

    SERVICE_NAME = "apigateway"
    REQUIRED_PERMISSIONS = [
        "apigateway:GetRestApis",
        "apigateway:GetResources",
        "apigateway:GetMethods",
        "apigateway:GetMethod",
        "apigateway:GetIntegration",
        "apigateway:GetApiKeys",
        "apigateway:GetUsagePlans",
    ]

    def __init__(self, auth_manager: AWSAuthManager, region: str | None = None):
        super().__init__(auth_manager, region)

    async def scan(self, scan_id: str, findings: list) -> ScanResult:
        """Scan API Gateway resources for security issues."""
        result = ScanResult(service=self.SERVICE_NAME, region=self.region)
        
        try:
            await self._scan_rest_apis(scan_id, findings, result)
            await self._scan_api_keys(scan_id, findings, result)
            await self._scan_usage_plans(scan_id, findings, result)
        except botocore.exceptions.ClientError as e:
            log.error(f"API Gateway scan failed: {e}")
            result.errors.append(str(e))
        
        return result

    async def _scan_rest_apis(self, scan_id: str, findings: list, result: ScanResult):
        """Scan REST APIs."""
        try:
            paginator = self.client.get_paginator("get_rest_apis")
            for page in paginator.paginate():
                for api in page.get("items", []):
                    api_id = api.get("id")
                    name = api.get("name", "Unknown")
                    
                    findings.append({
                        "title": f"API Gateway REST API: {name}",
                        "description": f"API ID: {api_id}\nEndpoint: {api.get('endpointConfiguration', {}).get('types', ['EDGE'])[0]}\nCreated: {api.get('createdDate', 'Unknown')}",
                        "severity": "info",
                        "category": "enumeration",
                        "resource_type": "apigateway_rest_api",
                        "resource_id": api_id,
                        "resource_name": name,
                        "region": self.region,
                        "rule_id": "apigateway_enum_rest_apis",
                    })
                    result.resources_scanned += 1
        except botocore.exceptions.ClientError as e:
            log.error(f"Failed to scan REST APIs: {e}")
            result.errors.append(str(e))

    async def _scan_api_keys(self, scan_id: str, findings: list, result: ScanResult):
        """Scan API keys."""
        try:
            paginator = self.client.get_paginator("get_api_keys")
            for page in paginator.paginate():
                for key in page.get("items", []):
                    key_id = key.get("id")
                    name = key.get("name", "Unknown")
                    
                    findings.append({
                        "title": f"API Gateway API Key: {name}",
                        "description": f"Key ID: {key_id}\nEnabled: {key.get('enabled', False)}\nCreated: {key.get('createdDate', 'Unknown')}",
                        "severity": "info",
                        "category": "enumeration",
                        "resource_type": "apigateway_api_key",
                        "resource_id": key_id,
                        "resource_name": name,
                        "region": self.region,
                        "rule_id": "apigateway_enum_api_keys",
                    })
                    result.resources_scanned += 1
        except botocore.exceptions.ClientError as e:
            log.error(f"Failed to scan API keys: {e}")
            result.errors.append(str(e))

    async def _scan_usage_plans(self, scan_id: str, findings: list, result: ScanResult):
        """Scan usage plans."""
        try:
            paginator = self.client.get_paginator("get_usage_plans")
            for page in paginator.paginate():
                for plan in page.get("items", []):
                    plan_id = plan.get("id")
                    name = plan.get("name", "Unknown")
                    
                    findings.append({
                        "title": f"API Gateway Usage Plan: {name}",
                        "description": f"Plan ID: {plan_id}\nThrottle: {plan.get('throttle', {})}\nQuota: {plan.get('quota', {})}",
                        "severity": "info",
                        "category": "enumeration",
                        "resource_type": "apigateway_usage_plan",
                        "resource_id": plan_id,
                        "resource_name": name,
                        "region": self.region,
                        "rule_id": "apigateway_enum_api_keys",
                    })
                    result.resources_scanned += 1
        except botocore.exceptions.ClientError as e:
            log.error(f"Failed to scan usage plans: {e}")
            result.errors.append(str(e))

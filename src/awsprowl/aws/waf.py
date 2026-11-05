"""WAF scanner for awsProwl."""

from __future__ import annotations

import botocore.exceptions
from awsprowl.aws.base import AWSServiceBase, ScanResult
from awsprowl.core.auth import AWSAuthManager
from awsprowl.core.logging import get_logger

log = get_logger(__name__)


class WAFScanner(AWSServiceBase):
    """Scanner for WAF resources (WAFv2)."""

    SERVICE_NAME = "wafv2"
    REQUIRED_PERMISSIONS = [
        "wafv2:ListWebACLs",
        "wafv2:GetWebACL",
        "wafv2:ListRuleGroups",
        "wafv2:GetRuleGroup",
        "wafv2:ListIP Sets",
        "wafv2:GetIPSet",
        "wafv2:ListLoggingConfigurations",
    ]

    def __init__(self, auth_manager: AWSAuthManager, region: str | None = None):
        super().__init__(auth_manager, region)

    async def scan(self, scan_id: str, findings: list) -> ScanResult:
        """Scan WAF resources for security issues."""
        result = ScanResult(service=self.SERVICE_NAME, region=self.region)
        
        try:
            await self._scan_web_acls(scan_id, findings, result)
            await self._scan_rule_groups(scan_id, findings, result)
            await self._scan_ip_sets(scan_id, findings, result)
            await self._scan_logging(scan_id, findings, result)
        except botocore.exceptions.ClientError as e:
            log.error(f"WAF scan failed: {e}")
            result.errors.append(str(e))
        
        return result

    async def _scan_web_acls(self, scan_id: str, findings: list, result: ScanResult):
        """Scan Web ACLs."""
        try:
            for scope in ["REGIONAL", "CLOUDFRONT"]:
                paginator = self.client.get_paginator("list_web_acls")
                for page in paginator.paginate(Scope=scope):
                    for acl in page.get("WebACLs", []):
                        acl_name = acl.get("Name")
                        acl_id = acl.get("Id")
                        
                        findings.append({
                            "title": f"WAF Web ACL: {acl_name} ({scope})",
                            "description": f"ID: {acl_id}\nARN: {acl.get('ARN', 'Unknown')}\nScope: {scope}\nDefault Action: {acl.get('DefaultAction', {})}",
                            "severity": "info",
                            "category": "enumeration",
                            "resource_type": "waf_web_acl",
                            "resource_id": acl_id,
                            "resource_name": acl_name,
                            "region": self.region,
                            "rule_id": "waf_enum_web_acls",
                        })
                        result.resources_scanned += 1
        except botocore.exceptions.ClientError as e:
            log.error(f"Failed to scan Web ACLs: {e}")
            result.errors.append(str(e))

    async def _scan_rule_groups(self, scan_id: str, findings: list, result: ScanResult):
        """Scan Rule Groups."""
        try:
            for scope in ["REGIONAL", "CLOUDFRONT"]:
                paginator = self.client.get_paginator("list_rule_groups")
                for page in paginator.paginate(Scope=scope):
                    for rg in page.get("RuleGroups", []):
                        rg_name = rg.get("Name")
                        rg_id = rg.get("Id")
                        
                        findings.append({
                            "title": f"WAF Rule Group: {rg_name} ({scope})",
                            "description": f"ID: {rg_id}\nARN: {rg.get('ARN', 'Unknown')}\nScope: {scope}",
                            "severity": "info",
                            "category": "enumeration",
                            "resource_type": "waf_rule_group",
                            "resource_id": rg_id,
                            "resource_name": rg_name,
                            "region": self.region,
                            "rule_id": "waf_enum_rules",
                        })
                        result.resources_scanned += 1
        except botocore.exceptions.ClientError as e:
            log.error(f"Failed to scan Rule Groups: {e}")
            result.errors.append(str(e))

    async def _scan_ip_sets(self, scan_id: str, findings: list, result: ScanResult):
        """Scan IP Sets."""
        try:
            for scope in ["REGIONAL", "CLOUDFRONT"]:
                paginator = self.client.get_paginator("list_ip_sets")
                for page in paginator.paginate(Scope=scope):
                    for ip_set in page.get("IPSets", []):
                        ip_name = ip_set.get("Name")
                        ip_id = ip_set.get("Id")
                        
                        findings.append({
                            "title": f"WAF IP Set: {ip_name} ({scope})",
                            "description": f"ID: {ip_id}\nARN: {ip_set.get('ARN', 'Unknown')}\nScope: {scope}",
                            "severity": "info",
                            "category": "enumeration",
                            "resource_type": "waf_ip_set",
                            "resource_id": ip_id,
                            "resource_name": ip_name,
                            "region": self.region,
                            "rule_id": "waf_enum_rules",
                        })
                        result.resources_scanned += 1
        except botocore.exceptions.ClientError as e:
            log.error(f"Failed to scan IP Sets: {e}")
            result.errors.append(str(e))

    async def _scan_logging(self, scan_id: str, findings: list, result: ScanResult):
        """Scan logging configurations."""
        try:
            paginator = self.client.get_paginator("list_logging_configurations")
            for page in paginator.paginate():
                for log_config in page.get("LoggingConfigurations", []):
                    acl_arn = log_config.get("ResourceArn")
                    
                    findings.append({
                        "title": f"WAF Logging Configuration",
                        "description": f"Web ACL ARN: {acl_arn}\nLog Destination: {log_config.get('LogDestinationConfigs', [])}\nRedacted Fields: {log_config.get('RedactedFields', [])}",
                        "severity": "info",
                        "category": "enumeration",
                        "resource_type": "waf_logging",
                        "resource_id": acl_arn,
                        "resource_name": "logging_config",
                        "region": self.region,
                        "rule_id": "waf_enum_logging",
                    })
                    result.resources_scanned += 1
        except botocore.exceptions.ClientError as e:
            log.error(f"Failed to scan logging: {e}")
            result.errors.append(str(e))

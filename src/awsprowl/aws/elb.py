"""ELB scanner for awsProwl."""

from __future__ import annotations

import botocore.exceptions
from awsprowl.aws.base import AWSServiceBase, ScanResult
from awsprowl.core.auth import AWSAuthManager
from awsprowl.core.logging import get_logger

log = get_logger(__name__)


class ELBScanner(AWSServiceBase):
    """Scanner for ELB resources (Classic, Application, Network)."""

    SERVICE_NAME = "elb"
    REQUIRED_PERMISSIONS = [
        "elasticloadbalancing:DescribeLoadBalancers",
        "elasticloadbalancing:DescribeTargetGroups",
        "elasticloadbalancing:DescribeListeners",
        "elasticloadbalancing:DescribeLoadBalancerAttributes",
    ]

    def __init__(self, auth_manager: AWSAuthManager, region: str | None = None):
        super().__init__(auth_manager, region)

    async def scan(self, scan_id: str, findings: list) -> ScanResult:
        """Scan ELB resources for security issues."""
        result = ScanResult(service=self.SERVICE_NAME, region=self.region)
        
        try:
            await self._scan_load_balancers(scan_id, findings, result)
            await self._scan_target_groups(scan_id, findings, result)
        except botocore.exceptions.ClientError as e:
            log.error(f"ELB scan failed: {e}")
            result.errors.append(str(e))
        
        return result

    async def _scan_load_balancers(self, scan_id: str, findings: list, result: ScanResult):
        """Scan load balancers."""
        try:
            paginator = self.client.get_paginator("describe_load_balancers")
            for page in paginator.paginate():
                for lb in page.get("LoadBalancers", []):
                    lb_arn = lb.get("LoadBalancerArn")
                    name = lb.get("LoadBalancerName")
                    lb_type = lb.get("Type", "unknown")
                    
                    findings.append({
                        "title": f"ELB Load Balancer: {name} ({lb_type})",
                        "description": f"ARN: {lb_arn}\nScheme: {lb.get('Scheme', 'Unknown')}\nState: {lb.get('State', {}).get('Code', 'Unknown')}\nVPC: {lb.get('VpcId', 'Unknown')}",
                        "severity": "info",
                        "category": "enumeration",
                        "resource_type": "elb_load_balancer",
                        "resource_id": lb_arn,
                        "resource_name": name,
                        "region": self.region,
                        "rule_id": "elb_enum_load_balancers",
                    })
                    result.resources_scanned += 1
        except botocore.exceptions.ClientError as e:
            log.error(f"Failed to scan load balancers: {e}")
            result.errors.append(str(e))

    async def _scan_target_groups(self, scan_id: str, findings: list, result: ScanResult):
        """Scan target groups."""
        try:
            paginator = self.client.get_paginator("describe_target_groups")
            for page in paginator.paginate():
                for tg in page.get("TargetGroups", []):
                    tg_arn = tg.get("TargetGroupArn")
                    name = tg.get("TargetGroupName")
                    
                    findings.append({
                        "title": f"ELB Target Group: {name}",
                        "description": f"ARN: {tg_arn}\nProtocol: {tg.get('Protocol', 'Unknown')}\nPort: {tg.get('Port', 'Unknown')}\nVPC: {tg.get('VpcId', 'Unknown')}",
                        "severity": "info",
                        "category": "enumeration",
                        "resource_type": "elb_target_group",
                        "resource_id": tg_arn,
                        "resource_name": name,
                        "region": self.region,
                        "rule_id": "elb_enum_target_groups",
                    })
                    result.resources_scanned += 1
        except botocore.exceptions.ClientError as e:
            log.error(f"Failed to scan target groups: {e}")
            result.errors.append(str(e))

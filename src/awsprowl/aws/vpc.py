"""VPC scanner for awsProwl."""

from __future__ import annotations

import botocore.exceptions
from awsprowl.aws.base import AWSServiceBase, ScanResult
from awsprowl.core.auth import AWSAuthManager
from awsprowl.core.logging import get_logger

log = get_logger(__name__)


class VPCScanner(AWSServiceBase):
    """Scanner for VPC resources."""

    SERVICE_NAME = "vpc"
    REQUIRED_PERMISSIONS = [
        "ec2:DescribeVpcs",
        "ec2:DescribeSubnets",
        "ec2:DescribeRouteTables",
        "ec2:DescribeVpcEndpoints",
        "ec2:DescribeVpcPeeringConnections",
        "ec2:DescribeTransitGateways",
        "ec2:DescribeTransitGatewayAttachments",
        "ec2:DescribeFlowLogs",
    ]

    def __init__(self, auth_manager: AWSAuthManager, region: str | None = None):
        super().__init__(auth_manager, region)

    async def scan(self, scan_id: str, findings: list) -> ScanResult:
        """Scan VPC resources for security issues."""
        result = ScanResult(service=self.SERVICE_NAME, region=self.region)
        
        try:
            await self._scan_vpcs(scan_id, findings, result)
            await self._scan_endpoints(scan_id, findings, result)
            await self._scan_flow_logs(scan_id, findings, result)
            await self._scan_lateral_movement(scan_id, findings, result)
        except botocore.exceptions.ClientError as e:
            log.error(f"VPC scan failed: {e}")
            result.errors.append(str(e))
        
        return result

    async def _scan_vpcs(self, scan_id: str, findings: list, result: ScanResult):
        """Scan VPCs."""
        try:
            paginator = self.client.get_paginator("describe_vpcs")
            for page in paginator.paginate():
                for vpc in page.get("Vpcs", []):
                    vpc_id = vpc.get("VpcId")
                    cidr = vpc.get("CidrBlock", "Unknown")
                    
                    findings.append({
                        "title": f"VPC: {vpc_id}",
                        "description": f"CIDR: {cidr}\nState: {vpc.get('State', 'Unknown')}\nIs Default: {vpc.get('IsDefault', False)}",
                        "severity": "info",
                        "category": "enumeration",
                        "resource_type": "vpc",
                        "resource_id": vpc_id,
                        "resource_name": vpc_id,
                        "region": self.region,
                        "rule_id": "vpc_enum_endpoints",
                    })
                    result.resources_scanned += 1
        except botocore.exceptions.ClientError as e:
            log.error(f"Failed to scan VPCs: {e}")
            result.errors.append(str(e))

    async def _scan_endpoints(self, scan_id: str, findings: list, result: ScanResult):
        """Scan VPC endpoints."""
        try:
            paginator = self.client.get_paginator("describe_vpc_endpoints")
            for page in paginator.paginate():
                for ep in page.get("VpcEndpoints", []):
                    ep_id = ep.get("VpcEndpointId")
                    service_name = ep.get("ServiceName", "Unknown")
                    
                    findings.append({
                        "title": f"VPC Endpoint: {ep_id}",
                        "description": f"Service: {service_name}\nType: {ep.get('VpcEndpointType', 'Unknown')}\nState: {ep.get('State', 'Unknown')}\nVPC: {ep.get('VpcId', 'Unknown')}",
                        "severity": "info",
                        "category": "enumeration",
                        "resource_type": "vpc_endpoint",
                        "resource_id": ep_id,
                        "resource_name": ep_id,
                        "region": self.region,
                        "rule_id": "vpc_enum_endpoints",
                    })
                    result.resources_scanned += 1
        except botocore.exceptions.ClientError as e:
            log.error(f"Failed to scan endpoints: {e}")
            result.errors.append(str(e))

    async def _scan_flow_logs(self, scan_id: str, findings: list, result: ScanResult):
        """Scan flow logs."""
        try:
            response = self.client.describe_flow_logs()
            for fl in response.get("FlowLogs", []):
                fl_id = fl.get("FlowLogId")
                
                findings.append({
                    "title": f"VPC Flow Log: {fl_id}",
                    "description": f"Resource: {fl.get('ResourceId', 'Unknown')}\nTraffic Type: {fl.get('TrafficType', 'Unknown')}\nLog Destination: {fl.get('LogDestination', 'Unknown')}\nState: {fl.get('FlowLogStatus', 'Unknown')}",
                    "severity": "info",
                    "category": "enumeration",
                    "resource_type": "vpc_flow_log",
                    "resource_id": fl_id,
                    "resource_name": fl_id,
                    "region": self.region,
                    "rule_id": "vpc_enum_flow_logs",
                })
                result.resources_scanned += 1
        except botocore.exceptions.ClientError as e:
            log.error(f"Failed to scan flow logs: {e}")
            result.errors.append(str(e))

    async def _scan_lateral_movement(self, scan_id: str, findings: list, result: ScanResult):
        """Scan lateral movement paths."""
        try:
            # VPC peering
            paginator = self.client.get_paginator("describe_vpc_peering_connections")
            for page in paginator.paginate():
                for pcx in page.get("VpcPeeringConnections", []):
                    pcx_id = pcx.get("VpcPeeringConnectionId")
                    
                    findings.append({
                        "title": f"VPC Peering: {pcx_id}",
                        "description": f"Requester VPC: {pcx.get('RequesterVpcInfo', {}).get('VpcId', 'Unknown')}\nAccepter VPC: {pcx.get('AccepterVpcInfo', {}).get('VpcId', 'Unknown')}\nStatus: {pcx.get('Status', {}).get('Code', 'Unknown')}",
                        "severity": "info",
                        "category": "enumeration",
                        "resource_type": "vpc_peering",
                        "resource_id": pcx_id,
                        "resource_name": pcx_id,
                        "region": self.region,
                        "rule_id": "vpc_enum_lateral_movement",
                    })
                    result.resources_scanned += 1
            
            # Transit Gateways
            paginator = self.client.get_paginator("describe_transit_gateways")
            for page in paginator.paginate():
                for tgw in page.get("TransitGateways", []):
                    tgw_id = tgw.get("TransitGatewayId")
                    
                    findings.append({
                        "title": f"Transit Gateway: {tgw_id}",
                        "description": f"State: {tgw.get('State', 'Unknown')}\nDescription: {tgw.get('Description', 'None')}",
                        "severity": "info",
                        "category": "enumeration",
                        "resource_type": "transit_gateway",
                        "resource_id": tgw_id,
                        "resource_name": tgw_id,
                        "region": self.region,
                        "rule_id": "vpc_enum_lateral_movement",
                    })
                    result.resources_scanned += 1
        except botocore.exceptions.ClientError as e:
            log.error(f"Failed to scan lateral movement: {e}")
            result.errors.append(str(e))

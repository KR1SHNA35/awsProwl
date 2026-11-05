"""
VPC Service Modules - All VPC-related features including lateral movement

This module provides a unified interface for all VPC operations:
- enum: Enumeration (safe, read-only)
- privesc: Privilege escalation analysis
"""

from awsprowl.modules import ModuleCategory, ModuleMetadata, ModuleRisk, register_module

# ==================== ENUM MODULES ====================
register_module(ModuleMetadata(
    name="vpc_enum_lateral_movement",
    category=ModuleCategory.ENUM,
    risk=ModuleRisk.SAFE,
    description="Enumerate VPC lateral movement paths: VPC peering, Transit Gateway, VPN, Direct Connect, PrivateLink. PROWL: vpc__enum_lateral_movement.",
    required_permissions=[
        "ec2:DescribeVpcPeeringConnections", "ec2:DescribeTransitGateways",
        "ec2:DescribeTransitGatewayAttachments", "ec2:DescribeTransitGatewayRouteTables",
        "ec2:DescribeVpcEndpointServices", "ec2:DescribeVpcEndpoints",
        "ec2:DescribeVpnConnections", "ec2:DescribeCustomerGateways",
        "ec2:DescribeVpcs", "ec2:DescribeRouteTables"
    ],
    supported_services=["ec2"],
    mitre_techniques=["T1526", "T1021.004", "T1046"],
    tags=["vpc", "enum", "lateral-movement", "peering", "transit-gateway", "awsprowl"],
    requires_confirmation=False,
))

register_module(ModuleMetadata(
    name="vpc_enum_endpoints",
    category=ModuleCategory.ENUM,
    risk=ModuleRisk.SAFE,
    description="Enumerate VPC endpoints (Interface, Gateway) for PrivateLink access.",
    required_permissions=[
        "ec2:DescribeVpcEndpoints", "ec2:DescribeVpcEndpointServices",
        "ec2:DescribeVpcEndpointConnections"
    ],
    supported_services=["ec2"],
    mitre_techniques=["T1526", "T1046", "T1021.004"],
    tags=["vpc", "enum", "endpoints", "privatelink", "safe"],
    requires_confirmation=False,
))

register_module(ModuleMetadata(
    name="vpc_enum_flow_logs",
    category=ModuleCategory.ENUM,
    risk=ModuleRisk.SAFE,
    description="Enumerate VPC flow logs configuration.",
    required_permissions=[
        "ec2:DescribeFlowLogs", "ec2:DescribeVpcs"
    ],
    supported_services=["ec2"],
    mitre_techniques=["T1526", "T1530"],
    tags=["vpc", "enum", "flow-logs", "network-monitoring", "safe"],
    requires_confirmation=False,
))

# ==================== PRIVESC MODULES ====================
register_module(ModuleMetadata(
    name="vpc_privesc_analysis",
    category=ModuleCategory.PRIVESC,
    risk=ModuleRisk.SAFE,
    description="Analyze VPC configurations for privilege escalation: route table manipulation, security group abuse, endpoint policy bypass.",
    required_permissions=[
        "ec2:DescribeRouteTables", "ec2:DescribeSecurityGroups",
        "ec2:DescribeVpcEndpoints", "ec2:DescribeVpcEndpointServices",
        "ec2:DescribeVpcPeeringConnections", "ec2:DescribeTransitGatewayRouteTables"
    ],
    supported_services=["ec2"],
    mitre_techniques=["T1087.004", "T1046", "T1021.004"],
    tags=["vpc", "privesc", "network", "analysis", "safe"],
    requires_confirmation=False,
))

# List all VPC modules
VPC_MODULES = [
    # Enum
    "vpc_enum_lateral_movement", "vpc_enum_endpoints", "vpc_enum_flow_logs",
    # Privesc
    "vpc_privesc_analysis",
]

__all__ = ["VPC_MODULES"]
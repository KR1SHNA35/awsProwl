"""
ELB (Elastic Load Balancing) Service Modules - All ELB-related features

This module provides a unified interface for all ELB operations:
- enum: Enumeration (safe, read-only)
"""

from awsprowl.modules import ModuleCategory, ModuleMetadata, ModuleRisk, register_module

# ==================== ENUM MODULES ====================
register_module(ModuleMetadata(
    name="elb_enum_load_balancers",
    category=ModuleCategory.ENUM,
    risk=ModuleRisk.SAFE,
    description="Enumerate Classic, Application, and Network Load Balancers.",
    required_permissions=[
        "elb:DescribeLoadBalancers", "elb:DescribeTags",
        "elbv2:DescribeLoadBalancers", "elbv2:DescribeTags",
        "elbv2:DescribeListeners", "elbv2:DescribeRules",
        "elbv2:DescribeTargetGroups", "elbv2:DescribeTargetHealth"
    ],
    supported_services=["elb", "elbv2"],
    mitre_techniques=["T1526", "T1083"],
    tags=["elb", "enum", "load-balancers", "alb", "nlb", "safe"],
    requires_confirmation=False,
))

register_module(ModuleMetadata(
    name="elb_enum_logging",
    category=ModuleCategory.ENUM,
    risk=ModuleRisk.SAFE,
    description="Enumerate ELB access logging configuration. PROWL: elb__enum_logging.",
    required_permissions=[
        "elb:DescribeLoadBalancers", "elb:DescribeLoadBalancerAttributes",
        "elbv2:DescribeLoadBalancers", "elbv2:DescribeLoadBalancerAttributes",
        "s3:GetBucketLogging", "s3:GetBucketLocation"
    ],
    supported_services=["elb", "elbv2", "s3"],
    mitre_techniques=["T1526", "T1083", "T1530"],
    tags=["elb", "enum", "logging", "access-logs", "awsprowl"],
    requires_confirmation=False,
))

register_module(ModuleMetadata(
    name="elb_enum_target_groups",
    category=ModuleCategory.ENUM,
    risk=ModuleRisk.SAFE,
    description="Enumerate ALB/NLB target groups and their health.",
    required_permissions=[
        "elbv2:DescribeTargetGroups", "elbv2:DescribeTargetHealth",
        "elbv2:DescribeTags"
    ],
    supported_services=["elbv2"],
    mitre_techniques=["T1526", "T1083"],
    tags=["elb", "enum", "target-groups", "alb", "nlb", "safe"],
    requires_confirmation=False,
))

# ==================== EXPLOIT MODULES ====================
register_module(ModuleMetadata(
    name="elb_exploit_modify_attributes",
    category=ModuleCategory.EXPLOIT,
    risk=ModuleRisk.HIGH,
    description="Modify ELB attributes (access logs, deletion protection, idle timeout). DESTRUCTIVE.",
    required_permissions=[
        "elb:ModifyLoadBalancerAttributes", "elb:DescribeLoadBalancerAttributes",
        "elbv2:ModifyLoadBalancerAttributes", "elbv2:DescribeLoadBalancerAttributes"
    ],
    supported_services=["elb", "elbv2"],
    mitre_techniques=["T1098", "T1562.001"],
    tags=["elb", "exploit", "modify-attributes", "destructive"],
    requires_confirmation=True,
    destructive=True,
))

register_module(ModuleMetadata(
    name="elb_exploit_create_listener",
    category=ModuleCategory.EXPLOIT,
    risk=ModuleRisk.MEDIUM,
    description="Create malicious listener on ALB/NLB for traffic interception. DESTRUCTIVE.",
    required_permissions=["elbv2:CreateListener", "elbv2:DescribeListeners", "elbv2:DescribeLoadBalancers"],
    supported_services=["elbv2"],
    mitre_techniques=["T1098", "T1046"],
    tags=["elb", "exploit", "listener", "traffic-interception", "destructive"],
    requires_confirmation=True,
    destructive=True,
))

# List all ELB modules
ELB_MODULES = [
    # Enum
    "elb_enum_load_balancers", "elb_enum_logging", "elb_enum_target_groups",
    # Exploit
    "elb_exploit_modify_attributes", "elb_exploit_create_listener",
]

__all__ = ["ELB_MODULES"]
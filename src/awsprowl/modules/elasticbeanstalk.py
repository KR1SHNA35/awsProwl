"""
Elastic Beanstalk Service Modules - All Elastic Beanstalk-related features

This module provides a unified interface for all Elastic Beanstalk operations:
- enum: Enumeration (safe, read-only)
- exploit: Active exploitation
"""

from awsprowl.modules import ModuleCategory, ModuleMetadata, ModuleRisk, register_module

# ==================== ENUM MODULES ====================
register_module(ModuleMetadata(
    name="elasticbeanstalk_enum_applications",
    category=ModuleCategory.ENUM,
    risk=ModuleRisk.SAFE,
    description="Enumerate Elastic Beanstalk applications, environments, and versions. PROWL: elasticbeanstalk__enum.",
    required_permissions=[
        "elasticbeanstalk:DescribeApplications", "elasticbeanstalk:DescribeEnvironments",
        "elasticbeanstalk:DescribeApplicationVersions", "elasticbeanstalk:DescribeConfigurationOptions",
        "elasticbeanstalk:DescribeConfigurationSettings", "elasticbeanstalk:ListPlatformVersions"
    ],
    supported_services=["elasticbeanstalk"],
    mitre_techniques=["T1526", "T1083"],
    tags=["elasticbeanstalk", "enum", "applications", "environments", "awsprowl"],
    requires_confirmation=False,
))

register_module(ModuleMetadata(
    name="elasticbeanstalk_enum_resources",
    category=ModuleCategory.ENUM,
    risk=ModuleRisk.SAFE,
    description="Enumerate Elastic Beanstalk environment resources (EC2, RDS, etc.).",
    required_permissions=[
        "elasticbeanstalk:DescribeEnvironmentResources", "elasticbeanstalk:DescribeEnvironments"
    ],
    supported_services=["elasticbeanstalk", "ec2", "rds"],
    mitre_techniques=["T1526", "T1083"],
    tags=["elasticbeanstalk", "enum", "resources", "ec2", "rds"],
    requires_confirmation=False,
))

# ==================== EXPLOIT MODULES ====================
register_module(ModuleMetadata(
    name="elasticbeanstalk_exploit_create_environment",
    category=ModuleCategory.EXPLOIT,
    risk=ModuleRisk.HIGH,
    description="Create Elastic Beanstalk environment with custom configuration for code execution. DESTRUCTIVE.",
    required_permissions=["elasticbeanstalk:CreateEnvironment", "elasticbeanstalk:DescribeEnvironments", "iam:PassRole"],
    supported_services=["elasticbeanstalk", "iam"],
    mitre_techniques=["T1611", "T1059.004"],
    tags=["elasticbeanstalk", "exploit", "create-environment", "destructive"],
    requires_confirmation=True,
    destructive=True,
))

register_module(ModuleMetadata(
    name="elasticbeanstalk_exploit_update_environment",
    category=ModuleCategory.EXPLOIT,
    risk=ModuleRisk.HIGH,
    description="Update Elastic Beanstalk environment configuration. DESTRUCTIVE.",
    required_permissions=["elasticbeanstalk:UpdateEnvironment", "elasticbeanstalk:DescribeEnvironments", "iam:PassRole"],
    supported_services=["elasticbeanstalk", "iam"],
    mitre_techniques=["T1098", "T1556.002"],
    tags=["elasticbeanstalk", "exploit", "update-environment", "destructive"],
    requires_confirmation=True,
    destructive=True,
))

register_module(ModuleMetadata(
    name="elasticbeanstalk_exploit_deploy_version",
    category=ModuleCategory.EXPLOIT,
    risk=ModuleRisk.HIGH,
    description="Deploy application version to environment (can contain malicious code). DESTRUCTIVE.",
    required_permissions=["elasticbeanstalk:CreateApplicationVersion", "elasticbeanstalk:UpdateEnvironment", "s3:PutObject", "iam:PassRole"],
    supported_services=["elasticbeanstalk", "s3", "iam"],
    mitre_techniques=["T1059.004", "T1190"],
    tags=["elasticbeanstalk", "exploit", "deploy-version", "code-deployment", "destructive"],
    requires_confirmation=True,
    destructive=True,
))

# List all Elastic Beanstalk modules
ELASTICBEANSTALK_MODULES = [
    # Enum
    "elasticbeanstalk_enum_applications", "elasticbeanstalk_enum_resources",
    # Exploit
    "elasticbeanstalk_exploit_create_environment", "elasticbeanstalk_exploit_update_environment", "elasticbeanstalk_exploit_deploy_version",
]

__all__ = ["ELASTICBEANSTALK_MODULES"]
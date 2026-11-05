"""
Directory Service (DS) Service Modules - All DS-related features

This module provides a unified interface for all Directory Service operations:
- enum: Enumeration (safe, read-only)
"""

from awsprowl.modules import ModuleCategory, ModuleMetadata, ModuleRisk, register_module

# ==================== ENUM MODULES ====================
register_module(ModuleMetadata(
    name="ds_enum_directories",
    category=ModuleCategory.ENUM,
    risk=ModuleRisk.SAFE,
    description="Enumerate AWS Managed Microsoft AD, Simple AD, and AD Connector directories. PROWL: ds__enum.",
    required_permissions=[
        "ds:DescribeDirectories", "ds:DescribeDomainControllers",
        "ds:DescribeTrusts", "ds:DescribeSnapshots",
        "ds:ListIpRoutes", "ds:ListTagsForResource"
    ],
    supported_services=["ds"],
    mitre_techniques=["T1526", "T1083", "T1069.003"],
    tags=["ds", "enum", "directories", "active-directory", "awsprowl"],
    requires_confirmation=False,
))

register_module(ModuleMetadata(
    name="ds_enum_trusts",
    category=ModuleCategory.ENUM,
    risk=ModuleRisk.SAFE,
    description="Enumerate directory trusts (cross-forest, external).",
    required_permissions=[
        "ds:DescribeTrusts", "ds:DescribeDirectories"
    ],
    supported_services=["ds"],
    mitre_techniques=["T1526", "T1021.004"],
    tags=["ds", "enum", "trusts", "cross-forest", "safe"],
    requires_confirmation=False,
))

register_module(ModuleMetadata(
    name="ds_enum_snapshots",
    category=ModuleCategory.ENUM,
    risk=ModuleRisk.SAFE,
    description="Enumerate directory snapshots for backup/recovery.",
    required_permissions=[
        "ds:DescribeSnapshots", "ds:DescribeDirectories"
    ],
    supported_services=["ds"],
    mitre_techniques=["T1526", "T1083"],
    tags=["ds", "enum", "snapshots", "backup", "safe"],
    requires_confirmation=False,
))

# List all DS modules
DS_MODULES = [
    # Enum
    "ds_enum_directories", "ds_enum_trusts", "ds_enum_snapshots",
]

__all__ = ["DS_MODULES"]
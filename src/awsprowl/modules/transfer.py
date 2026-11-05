"""
AWS Transfer Family Service Modules - All Transfer Family-related features

This module provides a unified interface for all Transfer Family operations:
- enum: Enumeration (safe, read-only)
"""

from awsprowl.modules import ModuleCategory, ModuleMetadata, ModuleRisk, register_module

# ==================== ENUM MODULES ====================
register_module(ModuleMetadata(
    name="transfer_enum_servers",
    category=ModuleCategory.ENUM,
    risk=ModuleRisk.SAFE,
    description="Enumerate Transfer Family servers (SFTP, FTPS, FTP). PROWL: transfer_family__enum.",
    required_permissions=[
        "transfer:ListServers", "transfer:DescribeServer",
        "transfer:ListUsers", "transfer:DescribeUser",
        "transfer:ListAccesses", "transfer:DescribeAccess"
    ],
    supported_services=["transfer"],
    mitre_techniques=["T1526", "T1083"],
    tags=["transfer", "enum", "servers", "sftp", "ftps", "ftp", "awsprowl"],
    requires_confirmation=False,
))

register_module(ModuleMetadata(
    name="transfer_enum_certificates",
    category=ModuleCategory.ENUM,
    risk=ModuleRisk.SAFE,
    description="Enumerate Transfer Family certificates for FTPS.",
    required_permissions=[
        "transfer:ListCertificates", "transfer:DescribeCertificate"
    ],
    supported_services=["transfer"],
    mitre_techniques=["T1526", "T1083"],
    tags=["transfer", "enum", "certificates", "ftps", "safe"],
    requires_confirmation=False,
))

register_module(ModuleMetadata(
    name="transfer_enum_connectors",
    category=ModuleCategory.ENUM,
    risk=ModuleRisk.SAFE,
    description="Enumerate Transfer Family connectors (AS2).",
    required_permissions=[
        "transfer:ListConnectors", "transfer:DescribeConnector",
        "transfer:ListProfiles", "transfer:DescribeProfile"
    ],
    supported_services=["transfer"],
    mitre_techniques=["T1526", "T1083"],
    tags=["transfer", "enum", "connectors", "as2", "safe"],
    requires_confirmation=False,
))

# List all Transfer Family modules
TRANSFER_MODULES = [
    # Enum
    "transfer_enum_servers", "transfer_enum_certificates", "transfer_enum_connectors",
]

__all__ = ["TRANSFER_MODULES"]
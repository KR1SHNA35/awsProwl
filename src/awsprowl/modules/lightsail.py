"""
Lightsail Service Modules - All Lightsail-related features

This module provides a unified interface for all Lightsail operations:
- enum: Enumeration (safe, read-only)
- exploit: Active exploitation
- exfil: Data exfiltration
"""

from awsprowl.modules import ModuleCategory, ModuleMetadata, ModuleRisk, register_module

# ==================== ENUM MODULES ====================
register_module(ModuleMetadata(
    name="lightsail_enum_instances",
    category=ModuleCategory.ENUM,
    risk=ModuleRisk.SAFE,
    description="Enumerate Lightsail instances, disks, snapshots, and static IPs. PROWL: lightsail__enum.",
    required_permissions=[
        "lightsail:GetInstances", "lightsail:GetInstance",
        "lightsail:GetDisks", "lightsail:GetDisk",
        "lightsail:GetInstanceSnapshots", "lightsail:GetInstanceSnapshot",
        "lightsail:GetStaticIps", "lightsail:GetStaticIp"
    ],
    supported_services=["lightsail"],
    mitre_techniques=["T1526", "T1083"],
    tags=["lightsail", "enum", "instances", "disks", "snapshots", "awsprowl"],
    requires_confirmation=False,
))

register_module(ModuleMetadata(
    name="lightsail_enum_blueprints",
    category=ModuleCategory.ENUM,
    risk=ModuleRisk.SAFE,
    description="Enumerate Lightsail blueprints (images) and bundles (instance plans).",
    required_permissions=[
        "lightsail:GetBlueprints", "lightsail:GetBundles"
    ],
    supported_services=["lightsail"],
    mitre_techniques=["T1526", "T1083"],
    tags=["lightsail", "enum", "blueprints", "bundles", "safe"],
    requires_confirmation=False,
))

register_module(ModuleMetadata(
    name="lightsail_enum_databases",
    category=ModuleCategory.ENUM,
    risk=ModuleRisk.SAFE,
    description="Enumerate Lightsail managed databases.",
    required_permissions=[
        "lightsail:GetRelationalDatabases", "lightsail:GetRelationalDatabase",
        "lightsail:GetRelationalDatabaseSnapshots", "lightsail:GetRelationalDatabaseSnapshot"
    ],
    supported_services=["lightsail"],
    mitre_techniques=["T1526", "T1083"],
    tags=["lightsail", "enum", "databases", "rds", "safe"],
    requires_confirmation=False,
))

# ==================== EXPLOIT MODULES ====================
register_module(ModuleMetadata(
    name="lightsail_exploit_create_instance",
    category=ModuleCategory.EXPLOIT,
    risk=ModuleRisk.HIGH,
    description="Create Lightsail instance with user data for code execution. DESTRUCTIVE.",
    required_permissions=["lightsail:CreateInstances", "lightsail:GetInstances", "lightsail:GetBlueprints", "lightsail:GetBundles"],
    supported_services=["lightsail"],
    mitre_techniques=["T1059.004", "T1611"],
    tags=["lightsail", "exploit", "create-instance", "code-execution", "destructive"],
    requires_confirmation=True,
    destructive=True,
))

register_module(ModuleMetadata(
    name="lightsail_exploit_generate_ssh_keys",
    category=ModuleCategory.EXPLOIT,
    risk=ModuleRisk.HIGH,
    description="Generate SSH key pair for Lightsail instance access. PROWL: lightsail__generate_ssh_keys. DESTRUCTIVE.",
    required_permissions=["lightsail:CreateKeyPair", "lightsail:GetKeyPair"],
    supported_services=["lightsail"],
    mitre_techniques=["T1078.004", "T1556.002"],
    tags=["lightsail", "exploit", "ssh-keys", "awsprowl", "destructive"],
    requires_confirmation=True,
    destructive=True,
))

register_module(ModuleMetadata(
    name="lightsail_exploit_generate_temp_access",
    category=ModuleCategory.EXPLOIT,
    risk=ModuleRisk.HIGH,
    description="Generate temporary SSH/RDP access to Lightsail instance. PROWL: lightsail__generate_temp_access. DESTRUCTIVE.",
    required_permissions=["lightsail:GetInstanceAccessDetails", "lightsail:GetInstances"],
    supported_services=["lightsail"],
    mitre_techniques=["T1021.004", "T1078.004"],
    tags=["lightsail", "exploit", "temp-access", "ssh", "rdp", "awsprowl", "destructive"],
    requires_confirmation=True,
    destructive=True,
))

# ==================== EXFIL MODULES ====================
register_module(ModuleMetadata(
    name="lightsail_exfil_download_ssh_keys",
    category=ModuleCategory.EXFIL,
    risk=ModuleRisk.HIGH,
    description="Download SSH private keys from Lightsail key pairs. PROWL: lightsail__download_ssh_keys. DESTRUCTIVE - credential theft.",
    required_permissions=["lightsail:DownloadDefaultKeyPair", "lightsail:GetKeyPair"],
    supported_services=["lightsail"],
    mitre_techniques=["T1555.005", "T1530", "T1041"],
    tags=["lightsail", "exfil", "ssh-keys", "private-keys", "awsprowl", "destructive"],
    requires_confirmation=True,
    destructive=True,
))

register_module(ModuleMetadata(
    name="lightsail_exfil_snapshots",
    category=ModuleCategory.EXFIL,
    risk=ModuleRisk.HIGH,
    description="Export Lightsail instance/disk snapshots for data exfiltration. DESTRUCTIVE.",
    required_permissions=["lightsail:ExportSnapshot", "lightsail:GetInstanceSnapshots", "lightsail:GetDiskSnapshots", "ec2:DescribeSnapshots"],
    supported_services=["lightsail", "ec2"],
    mitre_techniques=["T1530", "T1020", "T1041"],
    tags=["lightsail", "exfil", "snapshots", "export", "destructive"],
    requires_confirmation=True,
    destructive=True,
))

# List all Lightsail modules
LIGHTSAIL_MODULES = [
    # Enum
    "lightsail_enum_instances", "lightsail_enum_blueprints", "lightsail_enum_databases",
    # Exploit
    "lightsail_exploit_create_instance", "lightsail_exploit_generate_ssh_keys", "lightsail_exploit_generate_temp_access",
    # Exfil
    "lightsail_exfil_download_ssh_keys", "lightsail_exfil_snapshots",
]

__all__ = ["LIGHTSAIL_MODULES"]
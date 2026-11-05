"""
DynamoDB Service Modules - All DynamoDB-related features across categories

This module provides a unified interface for all DynamoDB operations:
- enum: Enumeration (safe, read-only)
- privesc: Privilege escalation analysis
- exploit: Active exploitation
- exfil: Data exfiltration
"""

from awsprowl.modules import ModuleCategory, ModuleMetadata, ModuleRisk, register_module

# ==================== ENUM MODULES ====================
register_module(ModuleMetadata(
    name="dynamodb_enum_tables",
    category=ModuleCategory.ENUM,
    risk=ModuleRisk.SAFE,
    description="Enumerate DynamoDB tables, backups, and global tables.",
    required_permissions=[
        "dynamodb:ListTables", "dynamodb:DescribeTable", "dynamodb:ListBackups",
        "dynamodb:DescribeBackup", "dynamodb:ListGlobalTables"
    ],
    supported_services=["dynamodb"],
    mitre_techniques=["T1083", "T1526"],
    tags=["dynamodb", "enum", "tables", "database", "safe"],
    requires_confirmation=False,
))

# ==================== PRIVESC MODULES ====================
# DynamoDB doesn't have a dedicated privesc module in the category

# ==================== EXPLOIT MODULES ====================
register_module(ModuleMetadata(
    name="dynamodb_exploit_put_item",
    category=ModuleCategory.EXPLOIT,
    risk=ModuleRisk.MEDIUM,
    description="Put item into DynamoDB table (data injection, web shell storage). DESTRUCTIVE.",
    required_permissions=["dynamodb:PutItem", "dynamodb:DescribeTable"],
    supported_services=["dynamodb"],
    mitre_techniques=["T1505.003", "T1059.004"],
    tags=["dynamodb", "exploit", "put-item", "data-injection", "destructive"],
    requires_confirmation=True,
    destructive=True,
))

register_module(ModuleMetadata(
    name="dynamodb_exploit_update_table",
    category=ModuleCategory.EXPLOIT,
    risk=ModuleRisk.HIGH,
    description="Modify table settings: encryption, PITR, TTL, streams, GSI. DESTRUCTIVE.",
    required_permissions=["dynamodb:UpdateTable", "dynamodb:DescribeTable", "dynamodb:UpdateTimeToLive", "dynamodb:UpdateContinuousBackups"],
    supported_services=["dynamodb"],
    mitre_techniques=["T1098", "T1485"],
    tags=["dynamodb", "exploit", "update-table", "destructive"],
    requires_confirmation=True,
    destructive=True,
))

register_module(ModuleMetadata(
    name="dynamodb_exploit_create_table",
    category=ModuleCategory.EXPLOIT,
    risk=ModuleRisk.MEDIUM,
    description="Create new DynamoDB table for data storage/exfiltration. DESTRUCTIVE.",
    required_permissions=["dynamodb:CreateTable", "dynamodb:DescribeTable"],
    supported_services=["dynamodb"],
    mitre_techniques=["T1611", "T1505.003"],
    tags=["dynamodb", "exploit", "create-table", "destructive"],
    requires_confirmation=True,
    destructive=True,
))

register_module(ModuleMetadata(
    name="dynamodb_exploit_enable_streams",
    category=ModuleCategory.EXPLOIT,
    risk=ModuleRisk.MEDIUM,
    description="Enable DynamoDB Streams for real-time data capture. DESTRUCTIVE.",
    required_permissions=["dynamodb:UpdateTable", "dynamodb:DescribeTable", "dynamodb:DescribeStream"],
    supported_services=["dynamodb"],
    mitre_techniques=["T1530", "T1041"],
    tags=["dynamodb", "exploit", "streams", "destructive"],
    requires_confirmation=True,
    destructive=True,
))

register_module(ModuleMetadata(
    name="dynamodb_exploit_create_backup",
    category=ModuleCategory.EXPLOIT,
    risk=ModuleRisk.MEDIUM,
    description="Create on-demand backup for data staging. DESTRUCTIVE.",
    required_permissions=["dynamodb:CreateBackup", "dynamodb:DescribeBackup", "dynamodb:ListBackups"],
    supported_services=["dynamodb"],
    mitre_techniques=["T1530", "T1020"],
    tags=["dynamodb", "exploit", "backup", "destructive"],
    requires_confirmation=True,
    destructive=True,
))

# ==================== EXFIL MODULES ====================
register_module(ModuleMetadata(
    name="dynamodb_exfil_scan_table",
    category=ModuleCategory.EXFIL,
    risk=ModuleRisk.HIGH,
    description="Scan/query DynamoDB tables for complete data extraction. DESTRUCTIVE - reads all table data.",
    required_permissions=["dynamodb:Scan", "dynamodb:Query", "dynamodb:DescribeTable", "dynamodb:ListTables"],
    supported_services=["dynamodb"],
    mitre_techniques=["T1530", "T1020", "T1041"],
    tags=["dynamodb", "exfil", "scan", "data-theft", "destructive"],
    requires_confirmation=True,
    destructive=True,
))

register_module(ModuleMetadata(
    name="dynamodb_exfil_export_table",
    category=ModuleCategory.EXFIL,
    risk=ModuleRisk.HIGH,
    description="Export DynamoDB table to S3 for bulk exfiltration. DESTRUCTIVE.",
    required_permissions=["dynamodb:ExportTableToPointInTime", "dynamodb:DescribeExport", "dynamodb:ListExports", "s3:PutObject"],
    supported_services=["dynamodb", "s3"],
    mitre_techniques=["T1530", "T1020", "T1041"],
    tags=["dynamodb", "exfil", "export", "s3", "bulk", "destructive"],
    requires_confirmation=True,
    destructive=True,
))

register_module(ModuleMetadata(
    name="dynamodb_exfil_streams",
    category=ModuleCategory.EXFIL,
    risk=ModuleRisk.HIGH,
    description="Enable DynamoDB Streams and read stream records for real-time data exfiltration. DESTRUCTIVE.",
    required_permissions=["dynamodb:DescribeStream", "dynamodb:GetRecords", "dynamodb:GetShardIterator", "dynamodb:ListStreams"],
    supported_services=["dynamodb"],
    mitre_techniques=["T1530", "T1020", "T1041"],
    tags=["dynamodb", "exfil", "streams", "real-time", "destructive"],
    requires_confirmation=True,
    destructive=True,
))

register_module(ModuleMetadata(
    name="dynamodb_exfil_backup",
    category=ModuleCategory.EXFIL,
    risk=ModuleRisk.HIGH,
    description="Create and copy backup to attacker account for exfiltration. DESTRUCTIVE.",
    required_permissions=["dynamodb:CreateBackup", "dynamodb:DescribeBackup", "dynamodb:CopyBackup", "dynamodb:ListBackups"],
    supported_services=["dynamodb"],
    mitre_techniques=["T1530", "T1020", "T1041"],
    tags=["dynamodb", "exfil", "backup", "cross-account", "destructive"],
    requires_confirmation=True,
    destructive=True,
))

register_module(ModuleMetadata(
    name="dynamodb_exfil_tti",
    category=ModuleCategory.EXFIL,
    risk=ModuleRisk.MEDIUM,
    description="Use Time Travel (PITR) to query historical table data for exfiltration.",
    required_permissions=["dynamodb:Query", "dynamodb:DescribeTable", "dynamodb:DescribeContinuousBackups"],
    supported_services=["dynamodb"],
    mitre_techniques=["T1530", "T1020"],
    tags=["dynamodb", "exfil", "pitr", "time-travel", "historical"],
    requires_confirmation=True,
))

# List all DynamoDB modules
DYNAMODB_MODULES = [
    # Enum
    "dynamodb_enum_tables",
    # Privesc - none dedicated
    # Exploit
    "dynamodb_exploit_put_item", "dynamodb_exploit_update_table", "dynamodb_exploit_create_table",
    "dynamodb_exploit_enable_streams", "dynamodb_exploit_create_backup",
    # Exfil
    "dynamodb_exfil_scan_table", "dynamodb_exfil_export_table", "dynamodb_exfil_streams",
    "dynamodb_exfil_backup", "dynamodb_exfil_tti",
]

__all__ = ["DYNAMODB_MODULES"]

"""
RDS Service Modules - All RDS-related features across categories

This module provides a unified interface for all RDS operations:
- enum: Enumeration (safe, read-only)
- privesc: Privilege escalation analysis
- exploit: Active exploitation
- exfil: Data exfiltration
"""

from awsprowl.modules import ModuleCategory, ModuleMetadata, ModuleRisk, register_module

# ==================== ENUM MODULES ====================
register_module(ModuleMetadata(
    name="rds_enum_instances",
    category=ModuleCategory.ENUM,
    risk=ModuleRisk.SAFE,
    description="Enumerate RDS instances, clusters, snapshots, parameter groups, and security groups.",
    required_permissions=[
        "rds:DescribeDBInstances", "rds:DescribeDBClusters", "rds:DescribeDBSnapshots",
        "rds:DescribeDBClusterSnapshots", "rds:DescribeDBParameterGroups",
        "rds:DescribeDBClusterParameterGroups", "rds:DescribeDBSecurityGroups"
    ],
    supported_services=["rds"],
    mitre_techniques=["T1083", "T1526"],
    tags=["rds", "enum", "instances", "database", "safe"],
    requires_confirmation=False,
))

# ==================== PRIVESC MODULES ====================
# RDS doesn't have a dedicated privesc module, but instance profile abuse is covered by ec2_privesc_analysis

# ==================== EXPLOIT MODULES ====================
register_module(ModuleMetadata(
    name="rds_exploit_modify_instance",
    category=ModuleCategory.EXPLOIT,
    risk=ModuleRisk.HIGH,
    description="Modify RDS instance settings (public access, security groups, parameter groups). DESTRUCTIVE.",
    required_permissions=["rds:ModifyDBInstance", "rds:DescribeDBInstances", "ec2:DescribeSecurityGroups"],
    supported_services=["rds", "ec2"],
    mitre_techniques=["T1098", "T1046"],
    tags=["rds", "exploit", "modify-instance", "destructive"],
    requires_confirmation=True,
    destructive=True,
))

register_module(ModuleMetadata(
    name="rds_exploit_create_instance",
    category=ModuleCategory.EXPLOIT,
    risk=ModuleRisk.HIGH,
    description="Create new RDS instance with custom configuration. DESTRUCTIVE.",
    required_permissions=["rds:CreateDBInstance", "rds:DescribeDBInstances", "ec2:DescribeSubnets", "ec2:DescribeSecurityGroups", "iam:PassRole"],
    supported_services=["rds", "ec2", "iam"],
    mitre_techniques=["T1611", "T1098"],
    tags=["rds", "exploit", "create-instance", "destructive"],
    requires_confirmation=True,
    destructive=True,
))

register_module(ModuleMetadata(
    name="rds_exploit_create_snapshot",
    category=ModuleCategory.EXPLOIT,
    risk=ModuleRisk.MEDIUM,
    description="Create RDS snapshot for backup or exfiltration staging. DESTRUCTIVE.",
    required_permissions=["rds:CreateDBSnapshot", "rds:DescribeDBSnapshots", "rds:DescribeDBInstances"],
    supported_services=["rds"],
    mitre_techniques=["T1530", "T1020"],
    tags=["rds", "exploit", "snapshot", "destructive"],
    requires_confirmation=True,
    destructive=True,
))

register_module(ModuleMetadata(
    name="rds_exploit_modify_cluster",
    category=ModuleCategory.EXPLOIT,
    risk=ModuleRisk.HIGH,
    description="Modify Aurora cluster settings. DESTRUCTIVE.",
    required_permissions=["rds:ModifyDBCluster", "rds:DescribeDBClusters"],
    supported_services=["rds"],
    mitre_techniques=["T1098", "T1046"],
    tags=["rds", "exploit", "modify-cluster", "destructive"],
    requires_confirmation=True,
    destructive=True,
))

register_module(ModuleMetadata(
    name="rds_exploit_data_api_execute",
    category=ModuleCategory.EXPLOIT,
    risk=ModuleRisk.HIGH,
    description="Execute SQL via RDS Data API for code execution. DESTRUCTIVE.",
    required_permissions=["rds-data:ExecuteStatement", "rds-data:BatchExecuteStatement", "rds:DescribeDBInstances", "secretsmanager:GetSecretValue"],
    supported_services=["rds-data", "secretsmanager"],
    mitre_techniques=["T1059.004", "T1210"],
    tags=["rds", "exploit", "data-api", "sql-execution", "destructive"],
    requires_confirmation=True,
    destructive=True,
))

# ==================== EXFIL MODULES ====================
register_module(ModuleMetadata(
    name="rds_exfil_snapshot",
    category=ModuleCategory.EXFIL,
    risk=ModuleRisk.CRITICAL,
    description="Create and share RDS snapshot to attacker account for database exfiltration. CRITICAL - full DB copy.",
    required_permissions=["rds:CreateDBSnapshot", "rds:DescribeDBSnapshots", "rds:ModifyDBSnapshotAttribute", "rds:DescribeDBInstances"],
    supported_services=["rds"],
    mitre_techniques=["T1530", "T1020", "T1041"],
    tags=["rds", "exfil", "snapshot", "database", "cross-account", "destructive"],
    requires_confirmation=True,
    destructive=True,
))

register_module(ModuleMetadata(
    name="rds_exfil_clone",
    category=ModuleCategory.EXFIL,
    risk=ModuleRisk.CRITICAL,
    description="Clone RDS instance to attacker-controlled instance for data access. CRITICAL.",
    required_permissions=["rds:RestoreDBInstanceFromDBSnapshot", "rds:CreateDBSnapshot", "rds:DescribeDBInstances", "ec2:DescribeSubnets"],
    supported_services=["rds", "ec2"],
    mitre_techniques=["T1530", "T1020", "T1611"],
    tags=["rds", "exfil", "clone", "database", "destructive"],
    requires_confirmation=True,
    destructive=True,
))

register_module(ModuleMetadata(
    name="rds_exfil_data_api",
    category=ModuleCategory.EXFIL,
    risk=ModuleRisk.HIGH,
    description="Use RDS Data API to execute SQL queries for targeted data extraction.",
    required_permissions=["rds-data:ExecuteStatement", "rds-data:BatchExecuteStatement", "rds:DescribeDBInstances", "secretsmanager:GetSecretValue"],
    supported_services=["rds-data", "secretsmanager"],
    mitre_techniques=["T1530", "T1020", "T1041"],
    tags=["rds", "exfil", "data-api", "sql", "targeted"],
    requires_confirmation=True,
))

register_module(ModuleMetadata(
    name="rds_exfil_export_snapshot",
    category=ModuleCategory.EXFIL,
    risk=ModuleRisk.HIGH,
    description="Export RDS snapshot to S3 for data exfiltration. DESTRUCTIVE.",
    required_permissions=["rds:StartExportTask", "rds:DescribeExportTasks", "rds:DescribeDBInstances", "s3:PutObject"],
    supported_services=["rds", "s3"],
    mitre_techniques=["T1530", "T1020", "T1041"],
    tags=["rds", "exfil", "export", "s3", "destructive"],
    requires_confirmation=True,
    destructive=True,
))

register_module(ModuleMetadata(
    name="rds_exfil_logs",
    category=ModuleCategory.EXFIL,
    risk=ModuleRisk.MEDIUM,
    description="Download RDS logs (error, slow query, audit) for reconnaissance.",
    required_permissions=["rds:DescribeDBLogFiles", "rds:DownloadDBLogFilePortion", "rds:DescribeDBInstances"],
    supported_services=["rds"],
    mitre_techniques=["T1530", "T1020"],
    tags=["rds", "exfil", "logs", "reconnaissance"],
    requires_confirmation=True,
))

# ==================== EXFIL MODULES (PROWL parity) ====================
register_module(ModuleMetadata(
    name="rds_exfil_explore_snapshots",
    category=ModuleCategory.EXFIL,
    risk=ModuleRisk.CRITICAL,
    description="Explore RDS snapshots by restoring to temporary instance for data extraction. PROWL: rds__explore_snapshots. CRITICAL.",
    required_permissions=["rds:RestoreDBInstanceFromDBSnapshot", "rds:CreateDBSnapshot", "rds:DescribeDBSnapshots", "rds:DescribeDBInstances", "ec2:DescribeSubnets", "ec2:DescribeSecurityGroups"],
    supported_services=["rds", "ec2"],
    mitre_techniques=["T1530", "T1020", "T1611"],
    tags=["rds", "exfil", "snapshot", "explore", "restore", "awsprowl", "destructive"],
    requires_confirmation=True,
    destructive=True,
))

register_module(ModuleMetadata(
    name="rds_enum_snapshots",
    category=ModuleCategory.ENUM,
    risk=ModuleRisk.SAFE,
    description="Enumerate RDS snapshots (manual and automated). PROWL: rds__enum_snapshots.",
    required_permissions=["rds:DescribeDBSnapshots", "rds:DescribeDBClusterSnapshots"],
    supported_services=["rds"],
    mitre_techniques=["T1083", "T1526"],
    tags=["rds", "enum", "snapshots", "awsprowl"],
    requires_confirmation=False,
))

# List all RDS modules
RDS_MODULES = [
    # Enum
    "rds_enum_instances",
    "rds_enum_snapshots",
    # Privesc - covered by ec2_privesc_analysis
    # Exploit
    "rds_exploit_modify_instance", "rds_exploit_create_instance", "rds_exploit_create_snapshot",
    "rds_exploit_modify_cluster", "rds_exploit_data_api_execute",
    # Exfil
    "rds_exfil_snapshot", "rds_exfil_clone", "rds_exfil_data_api",
    "rds_exfil_export_snapshot", "rds_exfil_logs",
    "rds_exfil_explore_snapshots",
]

__all__ = ["RDS_MODULES"]

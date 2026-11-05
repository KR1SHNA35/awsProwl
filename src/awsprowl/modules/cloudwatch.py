"""
CloudWatch Service Modules - All CloudWatch-related features across categories

This module provides a unified interface for all CloudWatch operations:
- enum: Enumeration (safe, read-only)
- exfil: Data exfiltration (log download)
"""

from awsprowl.modules import ModuleCategory, ModuleMetadata, ModuleRisk, register_module

# ==================== ENUM MODULES ====================
register_module(ModuleMetadata(
    name="cloudwatch_enum_log_groups",
    category=ModuleCategory.ENUM,
    risk=ModuleRisk.SAFE,
    description="Enumerate CloudWatch log groups and log streams.",
    required_permissions=[
        "logs:DescribeLogGroups", "logs:DescribeLogStreams"
    ],
    supported_services=["cloudwatch", "logs"],
    mitre_techniques=["T1530", "T1526"],
    tags=["cloudwatch", "enum", "logs", "log-groups", "safe"],
    requires_confirmation=False,
))

register_module(ModuleMetadata(
    name="cloudwatch_enum_metric_alarms",
    category=ModuleCategory.ENUM,
    risk=ModuleRisk.SAFE,
    description="Enumerate CloudWatch metric alarms.",
    required_permissions=[
        "cloudwatch:DescribeAlarms", "cloudwatch:DescribeAlarmHistory"
    ],
    supported_services=["cloudwatch"],
    mitre_techniques=["T1526"],
    tags=["cloudwatch", "enum", "alarms", "metrics", "safe"],
    requires_confirmation=False,
))

register_module(ModuleMetadata(
    name="cloudwatch_enum_dashboards",
    category=ModuleCategory.ENUM,
    risk=ModuleRisk.SAFE,
    description="Enumerate CloudWatch dashboards.",
    required_permissions=[
        "cloudwatch:ListDashboards", "cloudwatch:GetDashboard"
    ],
    supported_services=["cloudwatch"],
    mitre_techniques=["T1526"],
    tags=["cloudwatch", "enum", "dashboards", "safe"],
    requires_confirmation=False,
))

# ==================== EXFIL MODULES ====================
register_module(ModuleMetadata(
    name="cloudwatch_exfil_logs",
    category=ModuleCategory.EXFIL,
    risk=ModuleRisk.HIGH,
    description="Download CloudWatch Logs from log groups for reconnaissance. PROWL: cloudwatch__download_logs. DESTRUCTIVE.",
    required_permissions=[
        "logs:DescribeLogGroups", "logs:DescribeLogStreams", "logs:GetLogEvents", "logs:FilterLogEvents"
    ],
    supported_services=["cloudwatch", "logs"],
    mitre_techniques=["T1530", "T1020", "T1041"],
    tags=["cloudwatch", "exfil", "logs", "download", "awsprowl", "destructive"],
    requires_confirmation=True,
    destructive=True,
))

register_module(ModuleMetadata(
    name="cloudwatch_exfil_metric_data",
    category=ModuleCategory.EXFIL,
    risk=ModuleRisk.MEDIUM,
    description="Extract CloudWatch metric data for monitoring analysis.",
    required_permissions=[
        "cloudwatch:GetMetricData", "cloudwatch:GetMetricStatistics", "cloudwatch:ListMetrics"
    ],
    supported_services=["cloudwatch"],
    mitre_techniques=["T1530", "T1020"],
    tags=["cloudwatch", "exfil", "metrics", "data"],
    requires_confirmation=True,
))

# List all CloudWatch modules
CLOUDWATCH_MODULES = [
    # Enum
    "cloudwatch_enum_log_groups",
    "cloudwatch_enum_metric_alarms",
    "cloudwatch_enum_dashboards",
    # Exfil
    "cloudwatch_exfil_logs",
    "cloudwatch_exfil_metric_data",
]

__all__ = ["CLOUDWATCH_MODULES"]
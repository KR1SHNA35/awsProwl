"""
CloudTrail Service Modules - All CloudTrail-related features across categories

This module provides a unified interface for all CloudTrail operations:
- enum: Enumeration (safe, read-only)
- persist: Persistence mechanisms
- exfil: Data exfiltration
"""

from awsprowl.modules import ModuleCategory, ModuleMetadata, ModuleRisk, register_module

# ==================== ENUM MODULES ====================
register_module(ModuleMetadata(
    name="cloudtrail_enum_trails",
    category=ModuleCategory.ENUM,
    risk=ModuleRisk.SAFE,
    description="Enumerate CloudTrail trails, event selectors, and insights.",
    required_permissions=[
        "cloudtrail:DescribeTrails", "cloudtrail:GetTrailStatus", "cloudtrail:ListTrails",
        "cloudtrail:LookupEvents", "cloudtrail:GetInsightSelectors"
    ],
    supported_services=["cloudtrail"],
    mitre_techniques=["T1530"],
    tags=["cloudtrail", "enum", "trails", "logging", "safe"],
    requires_confirmation=False,
))

register_module(ModuleMetadata(
    name="cloudtrail_enum_event_data_stores",
    category=ModuleCategory.ENUM,
    risk=ModuleRisk.SAFE,
    description="Enumerate CloudTrail Lake event data stores.",
    required_permissions=[
        "cloudtrail:ListEventDataStores", "cloudtrail:DescribeEventDataStore",
        "cloudtrail:GetEventDataStore"
    ],
    supported_services=["cloudtrail"],
    mitre_techniques=["T1530", "T1526"],
    tags=["cloudtrail", "enum", "event-data-stores", "lake", "safe"],
    requires_confirmation=False,
))

register_module(ModuleMetadata(
    name="cloudtrail_enum_channels",
    category=ModuleCategory.ENUM,
    risk=ModuleRisk.SAFE,
    description="Enumerate CloudTrail channels for event ingestion.",
    required_permissions=[
        "cloudtrail:ListChannels", "cloudtrail:GetChannel"
    ],
    supported_services=["cloudtrail"],
    mitre_techniques=["T1530", "T1526"],
    tags=["cloudtrail", "enum", "channels", "ingestion", "safe"],
    requires_confirmation=False,
))

# ==================== PERSIST MODULES ====================
register_module(ModuleMetadata(
    name="cloudtrail_persist_stop_logging",
    category=ModuleCategory.PERSIST,
    risk=ModuleRisk.HIGH,
    description="Stop CloudTrail logging to hide persistence activities. DESTRUCTIVE - impairs detection.",
    required_permissions=["cloudtrail:StopLogging", "cloudtrail:DescribeTrails", "cloudtrail:GetTrailStatus"],
    supported_services=["cloudtrail"],
    mitre_techniques=["T1562.008", "T1562.001"],
    tags=["cloudtrail", "persist", "defense-evasion", "logging", "destructive"],
    requires_confirmation=True,
    destructive=True,
))

register_module(ModuleMetadata(
    name="cloudtrail_persist_delete_trail",
    category=ModuleCategory.PERSIST,
    risk=ModuleRisk.CRITICAL,
    description="Delete CloudTrail trail to permanently remove logging. CRITICAL - destroys audit trail.",
    required_permissions=["cloudtrail:DeleteTrail", "cloudtrail:DescribeTrails"],
    supported_services=["cloudtrail"],
    mitre_techniques=["T1562.008", "T1562.001", "T1070.001"],
    tags=["cloudtrail", "persist", "defense-evasion", "destructive"],
    requires_confirmation=True,
    destructive=True,
))

register_module(ModuleMetadata(
    name="cloudtrail_persist_update_trail",
    category=ModuleCategory.PERSIST,
    risk=ModuleRisk.HIGH,
    description="Update trail to exclude sensitive events or change log destination. DESTRUCTIVE.",
    required_permissions=["cloudtrail:UpdateTrail", "cloudtrail:DescribeTrails", "cloudtrail:GetTrailStatus", "s3:PutBucketPolicy"],
    supported_services=["cloudtrail", "s3"],
    mitre_techniques=["T1562.008", "T1562.001"],
    tags=["cloudtrail", "persist", "update-trail", "defense-evasion", "destructive"],
    requires_confirmation=True,
    destructive=True,
))

register_module(ModuleMetadata(
    name="cloudtrail_persist_disable_insights",
    category=ModuleCategory.PERSIST,
    risk=ModuleRisk.MEDIUM,
    description="Disable CloudTrail Insights to reduce anomaly detection.",
    required_permissions=["cloudtrail:PutInsightSelectors", "cloudtrail:GetInsightSelectors", "cloudtrail:DescribeTrails"],
    supported_services=["cloudtrail"],
    mitre_techniques=["T1562.001"],
    tags=["cloudtrail", "persist", "insights", "defense-evasion"],
    requires_confirmation=True,
))

register_module(ModuleMetadata(
    name="cloudtrail_persist_create_trail",
    category=ModuleCategory.PERSIST,
    risk=ModuleRisk.LOW,
    description="Create new trail for attacker-controlled logging (cover tracks).",
    required_permissions=["cloudtrail:CreateTrail", "cloudtrail:DescribeTrails", "s3:CreateBucket", "s3:PutBucketPolicy"],
    supported_services=["cloudtrail", "s3"],
    mitre_techniques=["T1562.001", "T1505.003"],
    tags=["cloudtrail", "persist", "create-trail", "covert"],
    requires_confirmation=True,
))

# ==================== EXFIL MODULES ====================
register_module(ModuleMetadata(
    name="cloudtrail_exfil_logs",
    category=ModuleCategory.EXFIL,
    risk=ModuleRisk.HIGH,
    description="Extract CloudTrail logs from S3 bucket for reconnaissance. DESTRUCTIVE.",
    required_permissions=["s3:GetObject", "s3:ListObjectsV2", "cloudtrail:DescribeTrails", "cloudtrail:LookupEvents"],
    supported_services=["cloudtrail", "s3"],
    mitre_techniques=["T1530", "T1020", "T1041"],
    tags=["cloudtrail", "exfil", "logs", "reconnaissance", "destructive"],
    requires_confirmation=True,
    destructive=True,
))

register_module(ModuleMetadata(
    name="cloudtrail_exfil_lookup_events",
    category=ModuleCategory.EXFIL,
    risk=ModuleRisk.MEDIUM,
    description="Lookup CloudTrail events via API for targeted event extraction.",
    required_permissions=["cloudtrail:LookupEvents", "cloudtrail:DescribeTrails"],
    supported_services=["cloudtrail"],
    mitre_techniques=["T1530", "T1020"],
    tags=["cloudtrail", "exfil", "lookup-events", "targeted"],
    requires_confirmation=True,
))

register_module(ModuleMetadata(
    name="cloudtrail_exfil_lake_query",
    category=ModuleCategory.EXFIL,
    risk=ModuleRisk.HIGH,
    description="Query CloudTrail Lake event data stores for structured event extraction. DESTRUCTIVE.",
    required_permissions=["cloudtrail:StartQuery", "cloudtrail:GetQueryResults", "cloudtrail:DescribeQuery", "cloudtrail:ListEventDataStores"],
    supported_services=["cloudtrail"],
    mitre_techniques=["T1530", "T1020", "T1041"],
    tags=["cloudtrail", "exfil", "lake", "query", "destructive"],
    requires_confirmation=True,
    destructive=True,
))

register_module(ModuleMetadata(
    name="cloudtrail_exfil_insights",
    category=ModuleCategory.EXFIL,
    risk=ModuleRisk.MEDIUM,
    description="Extract CloudTrail Insights for anomaly analysis.",
    required_permissions=["cloudtrail:GetInsightSelectors", "cloudtrail:DescribeTrails", "cloudtrail:LookupEvents"],
    supported_services=["cloudtrail"],
    mitre_techniques=["T1530", "T1020"],
    tags=["cloudtrail", "exfil", "insights", "anomaly"],
    requires_confirmation=True,
))

# ==================== EXFIL MODULES (PROWL parity) ====================
register_module(ModuleMetadata(
    name="cloudtrail_exfil_download_event_history",
    category=ModuleCategory.EXFIL,
    risk=ModuleRisk.HIGH,
    description="Download CloudTrail event history (last 90 days) for full API activity reconstruction. PROWL: cloudtrail__download_event_history. DESTRUCTIVE.",
    required_permissions=[
        "cloudtrail:LookupEvents", "cloudtrail:DescribeTrails", "cloudtrail:GetTrailStatus",
        "s3:GetObject", "s3:ListObjectsV2"
    ],
    supported_services=["cloudtrail", "s3"],
    mitre_techniques=["T1530", "T1020", "T1041"],
    tags=["cloudtrail", "exfil", "event-history", "download", "awsprowl", "destructive"],
    requires_confirmation=True,
    destructive=True,
))

register_module(ModuleMetadata(
    name="cloudtrail_exfil_csv_injection",
    category=ModuleCategory.EXFIL,
    risk=ModuleRisk.HIGH,
    description="Inject malicious CSV data into CloudTrail logs via API calls for SIEM disruption. PROWL: cloudtrail__csv_injection. DESTRUCTIVE.",
    required_permissions=[
        "cloudtrail:PutEventSelectors", "cloudtrail:LookupEvents", "cloudtrail:DescribeTrails"
    ],
    supported_services=["cloudtrail"],
    mitre_techniques=["T1565.001", "T1562.001", "T1036.005"],
    tags=["cloudtrail", "exfil", "csv-injection", "siem-disruption", "awsprowl", "destructive"],
    requires_confirmation=True,
    destructive=True,
))

# List all CloudTrail modules
CLOUDTRAIL_MODULES = [
    # Enum
    "cloudtrail_enum_trails", "cloudtrail_enum_event_data_stores", "cloudtrail_enum_channels",
    # Persist
    "cloudtrail_persist_stop_logging", "cloudtrail_persist_delete_trail",
    "cloudtrail_persist_update_trail", "cloudtrail_persist_disable_insights",
    "cloudtrail_persist_create_trail",
    # Exfil
    "cloudtrail_exfil_logs", "cloudtrail_exfil_lookup_events",
    "cloudtrail_exfil_lake_query", "cloudtrail_exfil_insights",
    "cloudtrail_exfil_download_event_history",
    "cloudtrail_exfil_csv_injection",
]

__all__ = ["CLOUDTRAIL_MODULES"]

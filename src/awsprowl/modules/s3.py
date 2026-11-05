"""
S3 Service Modules - All S3-related features across categories

This module provides a unified interface for all S3 operations:
- enum: Enumeration (safe, read-only)
- privesc: Privilege escalation analysis
- exploit: Active exploitation
- persist: Persistence mechanisms
- backdoor: Covert access
- exfil: Data exfiltration
"""

from awsprowl.modules import ModuleCategory, ModuleMetadata, ModuleRisk, register_module

# ==================== ENUM MODULES ====================
register_module(ModuleMetadata(
    name="s3_enum_buckets",
    category=ModuleCategory.ENUM,
    risk=ModuleRisk.SAFE,
    description="Enumerate S3 buckets with full security analysis: public access blocks, ACLs, policies, encryption, versioning, logging, lifecycle, replication, CORS, website config, requester pays, transfer acceleration, Object Lock, analytics, intelligent tiering, and access points.",
    required_permissions=[
        "s3:ListAllMyBuckets", "s3:GetBucketLocation", "s3:GetBucketAcl", "s3:GetBucketPolicy",
        "s3:GetBucketPublicAccessBlock", "s3:GetBucketEncryption", "s3:GetBucketVersioning",
        "s3:GetBucketLogging", "s3:GetBucketWebsite", "s3:GetBucketCors",
        "s3:GetBucketLifecycleConfiguration", "s3:GetBucketReplication", "s3:GetBucketTagging",
        "s3:GetBucketRequestPayment", "s3:GetBucketAccelerateConfiguration",
        "s3:GetObjectAcl", "s3:GetObjectLegalHold", "s3:GetObjectRetention",
        "s3:GetObjectLockConfiguration", "s3:ListObjectsV2",
        "s3:ListBucketAnalyticsConfigurations", "s3:ListBucketIntelligentTieringConfigurations",
        "s3:ListAccessPoints", "s3:GetAccessPoint", "s3:ListAccessPointsForObjectLambda",
        "s3:GetAccessPointForObjectLambda"
    ],
    supported_services=["s3"],
    mitre_techniques=["T1083", "T1530", "T1602"],
    tags=["s3", "enum", "buckets", "safe"],
    requires_confirmation=False,
))

# ==================== PRIVESC MODULES ====================
register_module(ModuleMetadata(
    name="s3_privesc_analysis",
    category=ModuleCategory.PRIVESC,
    risk=ModuleRisk.SAFE,
    description="Analyze S3 buckets for privilege escalation: bucket policy modification, ACL abuse, replication configuration abuse, lifecycle policy injection, and access point policy abuse.",
    required_permissions=[
        "s3:ListAllMyBuckets", "s3:GetBucketLocation", "s3:GetBucketAcl", "s3:GetBucketPolicy",
        "s3:GetBucketPublicAccessBlock", "s3:GetBucketEncryption", "s3:GetBucketVersioning",
        "s3:GetBucketLogging", "s3:GetBucketWebsite", "s3:GetBucketCors",
        "s3:GetBucketLifecycleConfiguration", "s3:GetBucketReplication", "s3:GetBucketTagging",
        "s3:GetBucketRequestPayment", "s3:GetBucketAccelerateConfiguration",
        "s3:GetObjectAcl", "s3:GetObjectLegalHold", "s3:GetObjectRetention",
        "s3:GetObjectLockConfiguration", "s3:ListObjectsV2",
        "s3:ListBucketAnalyticsConfigurations", "s3:ListBucketIntelligentTieringConfigurations",
        "s3:ListAccessPoints", "s3:GetAccessPoint", "s3:ListAccessPointsForObjectLambda",
        "s3:GetAccessPointForObjectLambda"
    ],
    supported_services=["s3"],
    mitre_techniques=["T1083", "T1530", "T1602", "T1078.004"],
    tags=["s3", "privesc", "analysis", "safe"],
    requires_confirmation=False,
))

# ==================== EXPLOIT MODULES ====================
register_module(ModuleMetadata(
    name="s3_exploit_put_bucket_policy",
    category=ModuleCategory.EXPLOIT,
    risk=ModuleRisk.HIGH,
    description="Put bucket policy to grant public or cross-account access. DESTRUCTIVE - modifies access controls.",
    required_permissions=["s3:PutBucketPolicy", "s3:GetBucketPolicy", "s3:GetBucketLocation"],
    supported_services=["s3"],
    mitre_techniques=["T1098", "T1530"],
    tags=["s3", "exploit", "bucket-policy", "destructive"],
    requires_confirmation=True,
    destructive=True,
))

register_module(ModuleMetadata(
    name="s3_exploit_put_bucket_acl",
    category=ModuleCategory.EXPLOIT,
    risk=ModuleRisk.HIGH,
    description="Put bucket ACL to grant public read/write access. DESTRUCTIVE - modifies access controls.",
    required_permissions=["s3:PutBucketAcl", "s3:GetBucketAcl", "s3:GetBucketLocation"],
    supported_services=["s3"],
    mitre_techniques=["T1098", "T1530"],
    tags=["s3", "exploit", "acl", "destructive"],
    requires_confirmation=True,
    destructive=True,
))

register_module(ModuleMetadata(
    name="s3_exploit_put_object",
    category=ModuleCategory.EXPLOIT,
    risk=ModuleRisk.MEDIUM,
    description="Upload objects to S3 bucket (web shell, malware, etc.). DESTRUCTIVE - writes data.",
    required_permissions=["s3:PutObject", "s3:GetBucketLocation"],
    supported_services=["s3"],
    mitre_techniques=["T1505.003", "T1059.004"],
    tags=["s3", "exploit", "put-object", "destructive"],
    requires_confirmation=True,
    destructive=True,
))

register_module(ModuleMetadata(
    name="s3_exploit_put_object_acl",
    category=ModuleCategory.EXPLOIT,
    risk=ModuleRisk.MEDIUM,
    description="Put object ACL for public read access. DESTRUCTIVE - modifies object permissions.",
    required_permissions=["s3:PutObjectAcl", "s3:GetObjectAcl"],
    supported_services=["s3"],
    mitre_techniques=["T1098", "T1530"],
    tags=["s3", "exploit", "object-acl", "destructive"],
    requires_confirmation=True,
    destructive=True,
))

register_module(ModuleMetadata(
    name="s3_exploit_put_bucket_replication",
    category=ModuleCategory.EXPLOIT,
    risk=ModuleRisk.HIGH,
    description="Configure cross-region replication for data exfiltration. DESTRUCTIVE - creates replication.",
    required_permissions=["s3:PutBucketReplication", "s3:GetBucketReplication", "iam:PassRole"],
    supported_services=["s3", "iam"],
    mitre_techniques=["T1530", "T1020"],
    tags=["s3", "exploit", "replication", "exfiltration", "destructive"],
    requires_confirmation=True,
    destructive=True,
))

register_module(ModuleMetadata(
    name="s3_exploit_put_bucket_lifecycle",
    category=ModuleCategory.EXPLOIT,
    risk=ModuleRisk.MEDIUM,
    description="Put lifecycle configuration to transition/expire objects. DESTRUCTIVE - can cause data loss.",
    required_permissions=["s3:PutBucketLifecycleConfiguration", "s3:GetBucketLifecycleConfiguration"],
    supported_services=["s3"],
    mitre_techniques=["T1485", "T1565"],
    tags=["s3", "exploit", "lifecycle", "data-destruction", "destructive"],
    requires_confirmation=True,
    destructive=True,
))

# ==================== PERSIST MODULES ====================
register_module(ModuleMetadata(
    name="s3_persist_bucket_policy",
    category=ModuleCategory.PERSIST,
    risk=ModuleRisk.HIGH,
    description="Put bucket policy for persistent cross-account or public access. DESTRUCTIVE.",
    required_permissions=["s3:PutBucketPolicy", "s3:GetBucketPolicy", "s3:GetBucketLocation"],
    supported_services=["s3"],
    mitre_techniques=["T1098", "T1530"],
    tags=["s3", "persist", "bucket-policy", "data-access", "destructive"],
    requires_confirmation=True,
    destructive=True,
))

register_module(ModuleMetadata(
    name="s3_persist_bucket_acl",
    category=ModuleCategory.PERSIST,
    risk=ModuleRisk.HIGH,
    description="Put bucket ACL for persistent public read/write access. DESTRUCTIVE.",
    required_permissions=["s3:PutBucketAcl", "s3:GetBucketAcl", "s3:GetBucketLocation"],
    supported_services=["s3"],
    mitre_techniques=["T1098", "T1530"],
    tags=["s3", "persist", "acl", "data-access", "destructive"],
    requires_confirmation=True,
    destructive=True,
))

register_module(ModuleMetadata(
    name="s3_persist_replication",
    category=ModuleCategory.PERSIST,
    risk=ModuleRisk.HIGH,
    description="Configure cross-region replication for persistent data exfiltration. DESTRUCTIVE.",
    required_permissions=["s3:PutBucketReplication", "s3:GetBucketReplication", "iam:PassRole"],
    supported_services=["s3", "iam"],
    mitre_techniques=["T1020", "T1530"],
    tags=["s3", "persist", "replication", "exfiltration", "destructive"],
    requires_confirmation=True,
    destructive=True,
))

register_module(ModuleMetadata(
    name="s3_persist_object_versioning",
    category=ModuleCategory.PERSIST,
    risk=ModuleRisk.MEDIUM,
    description="Enable versioning and MFA delete for persistent object retention.",
    required_permissions=["s3:PutBucketVersioning", "s3:GetBucketVersioning", "s3:PutBucketLifecycleConfiguration"],
    supported_services=["s3"],
    mitre_techniques=["T1485", "T1565"],
    tags=["s3", "persist", "versioning", "data-retention"],
    requires_confirmation=True,
))

register_module(ModuleMetadata(
    name="s3_persist_lifecycle",
    category=ModuleCategory.PERSIST,
    risk=ModuleRisk.MEDIUM,
    description="Configure lifecycle to prevent object deletion for persistence.",
    required_permissions=["s3:PutBucketLifecycleConfiguration", "s3:GetBucketLifecycleConfiguration"],
    supported_services=["s3"],
    mitre_techniques=["T1485", "T1565"],
    tags=["s3", "persist", "lifecycle", "data-retention"],
    requires_confirmation=True,
))

# ==================== BACKDOOR MODULES ====================
register_module(ModuleMetadata(
    name="s3_backdoor_static_website",
    category=ModuleCategory.BACKDOOR,
    risk=ModuleRisk.MEDIUM,
    description="Configure S3 static website hosting with hidden backdoor page/C2 endpoint. DESTRUCTIVE.",
    required_permissions=["s3:PutBucketWebsite", "s3:GetBucketWebsite", "s3:PutBucketPolicy", "s3:PutObject", "s3:PutObjectAcl"],
    supported_services=["s3"],
    mitre_techniques=["T1505.003", "T1102", "T1583.001"],
    tags=["s3", "backdoor", "static-website", "c2", "covert", "destructive"],
    requires_confirmation=True,
    destructive=True,
))

register_module(ModuleMetadata(
    name="s3_backdoor_object_metadata",
    category=ModuleCategory.BACKDOOR,
    risk=ModuleRisk.LOW,
    description="Store C2 commands/payloads in S3 object metadata for covert retrieval.",
    required_permissions=["s3:PutObject", "s3:GetObject", "s3:HeadObject", "s3:ListObjectsV2"],
    supported_services=["s3"],
    mitre_techniques=["T1505.003", "T1102", "T1027"],
    tags=["s3", "backdoor", "metadata", "c2", "covert"],
    requires_confirmation=True,
))

register_module(ModuleMetadata(
    name="s3_backdoor_access_point",
    category=ModuleCategory.BACKDOOR,
    risk=ModuleRisk.HIGH,
    description="Create S3 Access Point with custom policy for restricted backdoor access. DESTRUCTIVE.",
    required_permissions=["s3:CreateAccessPoint", "s3:GetAccessPoint", "s3:PutAccessPointPolicy", "s3:ListAccessPoints"],
    supported_services=["s3"],
    mitre_techniques=["T1505.003", "T1098", "T1530"],
    tags=["s3", "backdoor", "access-point", "restricted", "covert", "destructive"],
    requires_confirmation=True,
    destructive=True,
))

register_module(ModuleMetadata(
    name="s3_backdoor_replication_exfil",
    category=ModuleCategory.BACKDOOR,
    risk=ModuleRisk.HIGH,
    description="Configure cross-region replication to attacker-controlled bucket for automated exfiltration. DESTRUCTIVE.",
    required_permissions=["s3:PutBucketReplication", "s3:GetBucketReplication", "iam:PassRole"],
    supported_services=["s3", "iam"],
    mitre_techniques=["T1020", "T1041", "T1530"],
    tags=["s3", "backdoor", "replication", "exfiltration", "automated", "destructive"],
    requires_confirmation=True,
    destructive=True,
))

# ==================== EXFIL MODULES ====================
register_module(ModuleMetadata(
    name="s3_exfil_download_objects",
    category=ModuleCategory.EXFIL,
    risk=ModuleRisk.HIGH,
    description="Download objects from S3 buckets (including versioned objects). DESTRUCTIVE - reads sensitive data.",
    required_permissions=["s3:GetObject", "s3:GetObjectVersion", "s3:ListObjectsV2", "s3:ListObjectVersions", "s3:GetBucketLocation"],
    supported_services=["s3"],
    mitre_techniques=["T1530", "T1020", "T1041"],
    tags=["s3", "exfil", "download", "objects", "destructive"],
    requires_confirmation=True,
    destructive=True,
))

register_module(ModuleMetadata(
    name="s3_exfil_bucket_sync",
    category=ModuleCategory.EXFIL,
    risk=ModuleRisk.HIGH,
    description="Sync entire S3 bucket to local/attacker-controlled destination. DESTRUCTIVE - mass data extraction.",
    required_permissions=["s3:ListObjectsV2", "s3:GetObject", "s3:GetBucketLocation", "s3:GetBucketVersioning"],
    supported_services=["s3"],
    mitre_techniques=["T1530", "T1020", "T1041"],
    tags=["s3", "exfil", "sync", "mass-extraction", "destructive"],
    requires_confirmation=True,
    destructive=True,
))

register_module(ModuleMetadata(
    name="s3_exfil_replication",
    category=ModuleCategory.EXFIL,
    risk=ModuleRisk.HIGH,
    description="Configure cross-region/account replication to attacker-controlled bucket for automated exfiltration. DESTRUCTIVE.",
    required_permissions=["s3:PutBucketReplication", "s3:GetBucketReplication", "iam:PassRole", "s3:GetBucketLocation"],
    supported_services=["s3", "iam"],
    mitre_techniques=["T1020", "T1041", "T1530"],
    tags=["s3", "exfil", "replication", "automated", "destructive"],
    requires_confirmation=True,
    destructive=True,
))

register_module(ModuleMetadata(
    name="s3_exfil_presigned_urls",
    category=ModuleCategory.EXFIL,
    risk=ModuleRisk.MEDIUM,
    description="Generate presigned URLs for time-limited object access without leaving CloudTrail GetObject events.",
    required_permissions=["s3:GetObject", "s3:ListObjectsV2"],
    supported_services=["s3"],
    mitre_techniques=["T1530", "T1020", "T1114.001"],
    tags=["s3", "exfil", "presigned-url", "stealth"],
    requires_confirmation=True,
))

register_module(ModuleMetadata(
    name="s3_exfil_access_points",
    category=ModuleCategory.EXFIL,
    risk=ModuleRisk.HIGH,
    description="Use S3 Access Points with custom policies for restricted data access. DESTRUCTIVE.",
    required_permissions=["s3:CreateAccessPoint", "s3:GetAccessPoint", "s3:GetObject", "s3:ListAccessPoints"],
    supported_services=["s3"],
    mitre_techniques=["T1530", "T1020"],
    tags=["s3", "exfil", "access-point", "restricted", "destructive"],
    requires_confirmation=True,
    destructive=True,
))

register_module(ModuleMetadata(
    name="s3_exfil_select_query",
    category=ModuleCategory.EXFIL,
    risk=ModuleRisk.MEDIUM,
    description="Use S3 Select to query and extract specific data from objects (CSV/JSON/Parquet) without full download.",
    required_permissions=["s3:SelectObjectContent", "s3:GetObject", "s3:ListObjectsV2"],
    supported_services=["s3"],
    mitre_techniques=["T1530", "T1020", "T1041"],
    tags=["s3", "exfil", "select", "query", "targeted"],
    requires_confirmation=True,
))

# List all S3 modules
S3_MODULES = [
    # Enum
    "s3_enum_buckets",
    # Privesc
    "s3_privesc_analysis",
    # Exploit
    "s3_exploit_put_bucket_policy", "s3_exploit_put_bucket_acl", "s3_exploit_put_object",
    "s3_exploit_put_object_acl", "s3_exploit_put_bucket_replication", "s3_exploit_put_bucket_lifecycle",
    # Persist
    "s3_persist_bucket_policy", "s3_persist_bucket_acl", "s3_persist_replication",
    "s3_persist_object_versioning", "s3_persist_lifecycle",
    # Backdoor
    "s3_backdoor_static_website", "s3_backdoor_object_metadata", "s3_backdoor_access_point",
    "s3_backdoor_replication_exfil",
    # Exfil
    "s3_exfil_download_objects", "s3_exfil_bucket_sync", "s3_exfil_replication",
    "s3_exfil_presigned_urls", "s3_exfil_access_points", "s3_exfil_select_query",
]

__all__ = ["S3_MODULES"]

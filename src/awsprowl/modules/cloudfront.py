"""
CloudFront Service Modules - All CloudFront-related features across categories

This module provides a unified interface for all CloudFront operations:
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
    name="cloudfront_enum_distributions",
    category=ModuleCategory.ENUM,
    risk=ModuleRisk.SAFE,
    description="Enumerate CloudFront distributions: origins, cache behaviors, viewer certificates, WAF associations, logging, geo restrictions, price class, HTTP version, IPv6.",
    required_permissions=[
        "cloudfront:ListDistributions", "cloudfront:GetDistribution",
        "cloudfront:GetDistributionConfig", "cloudfront:ListTagsForResource"
    ],
    supported_services=["cloudfront"],
    mitre_techniques=["T1526", "T1087.004"],
    tags=["cloudfront", "enum", "distributions", "cdn", "safe"],
    requires_confirmation=False,
))

register_module(ModuleMetadata(
    name="cloudfront_enum_origin_access_controls",
    category=ModuleCategory.ENUM,
    risk=ModuleRisk.SAFE,
    description="Enumerate CloudFront Origin Access Controls (OAC): signing behavior, signing protocol, origin type.",
    required_permissions=[
        "cloudfront:ListOriginAccessControls", "cloudfront:GetOriginAccessControl",
        "cloudfront:ListTagsForResource"
    ],
    supported_services=["cloudfront"],
    mitre_techniques=["T1526", "T1087.004"],
    tags=["cloudfront", "enum", "oac", "origin-access-control", "safe"],
    requires_confirmation=False,
))

register_module(ModuleMetadata(
    name="cloudfront_enum_origin_access_identities",
    category=ModuleCategory.ENUM,
    risk=ModuleRisk.SAFE,
    description="Enumerate CloudFront Origin Access Identities (OAI) - legacy: S3 canonical user IDs, comments.",
    required_permissions=[
        "cloudfront:ListCloudFrontOriginAccessIdentities",
        "cloudfront:GetCloudFrontOriginAccessIdentity",
        "cloudfront:ListTagsForResource"
    ],
    supported_services=["cloudfront"],
    mitre_techniques=["T1526", "T1087.004"],
    tags=["cloudfront", "enum", "oai", "origin-access-identity", "legacy", "safe"],
    requires_confirmation=False,
))

register_module(ModuleMetadata(
    name="cloudfront_enum_functions",
    category=ModuleCategory.ENUM,
    risk=ModuleRisk.SAFE,
    description="Enumerate CloudFront Functions (edge functions): code, runtime, metadata, associated distributions.",
    required_permissions=[
        "cloudfront:ListFunctions", "cloudfront:DescribeFunction",
        "cloudfront:ListTagsForResource"
    ],
    supported_services=["cloudfront"],
    mitre_techniques=["T1526", "T1087.004", "T1611"],
    tags=["cloudfront", "enum", "functions", "edge-functions", "code", "safe"],
    requires_confirmation=False,
))

register_module(ModuleMetadata(
    name="cloudfront_enum_key_groups",
    category=ModuleCategory.ENUM,
    risk=ModuleRisk.SAFE,
    description="Enumerate CloudFront Key Groups for signed URLs/cookies: public keys, key IDs.",
    required_permissions=[
        "cloudfront:ListKeyGroups", "cloudfront:GetKeyGroup",
        "cloudfront:GetPublicKey", "cloudfront:ListPublicKeys",
        "cloudfront:ListTagsForResource"
    ],
    supported_services=["cloudfront"],
    mitre_techniques=["T1526", "T1087.004", "T1555.005"],
    tags=["cloudfront", "enum", "key-groups", "signed-urls", "signed-cookies", "safe"],
    requires_confirmation=False,
))

register_module(ModuleMetadata(
    name="cloudfront_enum_realtime_log_configs",
    category=ModuleCategory.ENUM,
    risk=ModuleRisk.SAFE,
    description="Enumerate CloudFront real-time log configurations: sampling rate, fields, endpoints (Kinesis Data Streams).",
    required_permissions=[
        "cloudfront:ListRealtimeLogConfigs", "cloudfront:GetRealtimeLogConfig",
        "cloudfront:ListTagsForResource"
    ],
    supported_services=["cloudfront"],
    mitre_techniques=["T1526", "T1087.004"],
    tags=["cloudfront", "enum", "realtime-logs", "kinesis", "logging", "safe"],
    requires_confirmation=False,
))

register_module(ModuleMetadata(
    name="cloudfront_enum_response_headers_policies",
    category=ModuleCategory.ENUM,
    risk=ModuleRisk.SAFE,
    description="Enumerate CloudFront Response Headers Policies: security headers, CORS, custom headers, server timing.",
    required_permissions=[
        "cloudfront:ListResponseHeadersPolicies", "cloudfront:GetResponseHeadersPolicy",
        "cloudfront:ListTagsForResource"
    ],
    supported_services=["cloudfront"],
    mitre_techniques=["T1526", "T1087.004"],
    tags=["cloudfront", "enum", "response-headers-policies", "security-headers", "cors", "safe"],
    requires_confirmation=False,
))

register_module(ModuleMetadata(
    name="cloudfront_enum_cache_policies",
    category=ModuleCategory.ENUM,
    risk=ModuleRisk.SAFE,
    description="Enumerate CloudFront Cache Policies: TTL settings, headers/cookies/query strings in cache key, compression.",
    required_permissions=[
        "cloudfront:ListCachePolicies", "cloudfront:GetCachePolicy",
        "cloudfront:ListTagsForResource"
    ],
    supported_services=["cloudfront"],
    mitre_techniques=["T1526", "T1087.004"],
    tags=["cloudfront", "enum", "cache-policies", "caching", "safe"],
    requires_confirmation=False,
))

register_module(ModuleMetadata(
    name="cloudfront_enum_origin_request_policies",
    category=ModuleCategory.ENUM,
    risk=ModuleRisk.SAFE,
    description="Enumerate CloudFront Origin Request Policies: headers/cookies/query strings forwarded to origin.",
    required_permissions=[
        "cloudfront:ListOriginRequestPolicies", "cloudfront:GetOriginRequestPolicy",
        "cloudfront:ListTagsForResource"
    ],
    supported_services=["cloudfront"],
    mitre_techniques=["T1526", "T1087.004"],
    tags=["cloudfront", "enum", "origin-request-policies", "origin-forwarding", "safe"],
    requires_confirmation=False,
))

# ==================== PRIVESC MODULES ====================
register_module(ModuleMetadata(
    name="cloudfront_privesc_analysis",
    category=ModuleCategory.PRIVESC,
    risk=ModuleRisk.SAFE,
    description="Analyze CloudFront configuration for privilege escalation: origin access, function code execution, key group permissions, WAF bypass, cache poisoning.",
    required_permissions=[
        "cloudfront:ListDistributions", "cloudfront:GetDistribution",
        "cloudfront:GetDistributionConfig", "cloudfront:ListOriginAccessControls",
        "cloudfront:GetOriginAccessControl", "cloudfront:ListFunctions",
        "cloudfront:DescribeFunction", "cloudfront:ListKeyGroups",
        "cloudfront:GetKeyGroup", "cloudfront:GetPublicKey",
        "cloudfront:ListResponseHeadersPolicies", "cloudfront:GetResponseHeadersPolicy",
        "cloudfront:ListCachePolicies", "cloudfront:GetCachePolicy",
        "iam:GetRole", "iam:GetRolePolicy", "iam:ListAttachedRolePolicies",
        "iam:ListRolePolicies", "iam:GetPolicy", "iam:GetPolicyVersion",
        "s3:GetBucketPolicy", "s3:GetBucketAcl", "s3:GetBucketLocation"
    ],
    supported_services=["cloudfront", "iam", "s3", "lambda"],
    mitre_techniques=["T1526", "T1087.004", "T1046", "T1611"],
    tags=["cloudfront", "privesc", "analysis", "cdn", "safe"],
    requires_confirmation=False,
))

register_module(ModuleMetadata(
    name="cloudfront_privesc_origin_access",
    category=ModuleCategory.PRIVESC,
    risk=ModuleRisk.SAFE,
    description="Analyze CloudFront Origin Access Controls/Identities for privilege escalation: OAC/OAI permissions on S3 buckets, cross-account origin access.",
    required_permissions=[
        "cloudfront:ListOriginAccessControls", "cloudfront:GetOriginAccessControl",
        "cloudfront:ListCloudFrontOriginAccessIdentities",
        "cloudfront:GetCloudFrontOriginAccessIdentity",
        "cloudfront:ListDistributions", "cloudfront:GetDistributionConfig",
        "s3:GetBucketPolicy", "s3:GetBucketAcl", "s3:GetBucketLocation",
        "iam:GetRole", "iam:GetRolePolicy", "iam:ListAttachedRolePolicies"
    ],
    supported_services=["cloudfront", "s3", "iam"],
    mitre_techniques=["T1526", "T1087.004", "T1046", "T1078.004"],
    tags=["cloudfront", "privesc", "origin-access", "oac", "oai", "s3", "safe"],
    requires_confirmation=False,
))

register_module(ModuleMetadata(
    name="cloudfront_privesc_edge_functions",
    category=ModuleCategory.PRIVESC,
    risk=ModuleRisk.SAFE,
    description="Analyze CloudFront Functions for privilege escalation: function code execution, associated distributions, IAM role permissions, external requests.",
    required_permissions=[
        "cloudfront:ListFunctions", "cloudfront:DescribeFunction",
        "cloudfront:ListDistributions", "cloudfront:GetDistributionConfig",
        "iam:GetRole", "iam:GetRolePolicy", "iam:ListAttachedRolePolicies"
    ],
    supported_services=["cloudfront", "iam"],
    mitre_techniques=["T1526", "T1087.004", "T1611", "T1059.004"],
    tags=["cloudfront", "privesc", "edge-functions", "code-execution", "safe"],
    requires_confirmation=False,
))

# ==================== EXPLOIT MODULES ====================
register_module(ModuleMetadata(
    name="cloudfront_exploit_create_distribution",
    category=ModuleCategory.EXPLOIT,
    risk=ModuleRisk.HIGH,
    description="Create a CloudFront distribution with malicious configuration (open origins, no WAF, HTTP allowed, wildcard cache). DESTRUCTIVE - creates CDN resources.",
    required_permissions=[
        "cloudfront:CreateDistribution", "cloudfront:GetDistribution",
        "cloudfront:GetDistributionConfig", "cloudfront:DeleteDistribution",
        "cloudfront:CreateOriginAccessControl", "cloudfront:CreateFunction",
        "iam:CreateRole", "iam:AttachRolePolicy", "iam:PassRole"
    ],
    supported_services=["cloudfront", "iam", "s3"],
    mitre_techniques=["T1611", "T1098", "T1505.003", "T1046"],
    tags=["cloudfront", "exploit", "create-distribution", "cdn", "destructive"],
    requires_confirmation=True,
    destructive=True,
))

register_module(ModuleMetadata(
    name="cloudfront_exploit_update_distribution",
    category=ModuleCategory.EXPLOIT,
    risk=ModuleRisk.HIGH,
    description="Update an existing CloudFront distribution to weaken security (disable HTTPS enforcement, remove WAF, add malicious origins, modify cache behavior). DESTRUCTIVE.",
    required_permissions=[
        "cloudfront:UpdateDistribution", "cloudfront:GetDistribution",
        "cloudfront:GetDistributionConfig", "cloudfront:DeleteDistribution",
        "cloudfront:CreateOriginAccessControl", "cloudfront:UpdateOriginAccessControl",
        "iam:PassRole"
    ],
    supported_services=["cloudfront", "iam", "s3"],
    mitre_techniques=["T1098", "T1556.002", "T1505.003", "T1046"],
    tags=["cloudfront", "exploit", "update-distribution", "cdn", "destructive"],
    requires_confirmation=True,
    destructive=True,
))

register_module(ModuleMetadata(
    name="cloudfront_exploit_create_function",
    category=ModuleCategory.EXPLOIT,
    risk=ModuleRisk.HIGH,
    description="Create a CloudFront Function with malicious code for request/response manipulation, header injection, or redirect. DESTRUCTIVE - deploys edge code.",
    required_permissions=[
        "cloudfront:CreateFunction", "cloudfront:UpdateFunction",
        "cloudfront:DescribeFunction", "cloudfront:PublishFunction",
        "cloudfront:DeleteFunction", "cloudfront:AssociateFunction",
        "iam:PassRole"
    ],
    supported_services=["cloudfront", "iam"],
    mitre_techniques=["T1611", "T1059.004", "T1098", "T1505.003"],
    tags=["cloudfront", "exploit", "create-function", "edge-code", "code-injection", "destructive"],
    requires_confirmation=True,
    destructive=True,
))

register_module(ModuleMetadata(
    name="cloudfront_exploit_update_function",
    category=ModuleCategory.EXPLOIT,
    risk=ModuleRisk.HIGH,
    description="Update an existing CloudFront Function with malicious code. DESTRUCTIVE - modifies edge code.",
    required_permissions=[
        "cloudfront:UpdateFunction", "cloudfront:DescribeFunction",
        "cloudfront:PublishFunction", "cloudfront:AssociateFunction"
    ],
    supported_services=["cloudfront"],
    mitre_techniques=["T1059.004", "T1098", "T1505.003", "T1611"],
    tags=["cloudfront", "exploit", "update-function", "edge-code", "code-injection", "destructive"],
    requires_confirmation=True,
    destructive=True,
))

register_module(ModuleMetadata(
    name="cloudfront_exploit_create_key_group",
    category=ModuleCategory.EXPLOIT,
    risk=ModuleRisk.HIGH,
    description="Create a CloudFront Key Group with attacker-controlled public key for generating signed URLs/cookies. DESTRUCTIVE.",
    required_permissions=[
        "cloudfront:CreateKeyGroup", "cloudfront:GetKeyGroup",
        "cloudfront:CreatePublicKey", "cloudfront:GetPublicKey",
        "cloudfront:DeleteKeyGroup", "cloudfront:DeletePublicKey"
    ],
    supported_services=["cloudfront"],
    mitre_techniques=["T1555.005", "T1098", "T1611"],
    tags=["cloudfront", "exploit", "key-group", "signed-urls", "signed-cookies", "destructive"],
    requires_confirmation=True,
    destructive=True,
))

register_module(ModuleMetadata(
    name="cloudfront_exploit_disable_https_enforcement",
    category=ModuleCategory.EXPLOIT,
    risk=ModuleRisk.HIGH,
    description="Disable HTTPS enforcement on CloudFront distribution (allow HTTP). DESTRUCTIVE - weakens transport security.",
    required_permissions=[
        "cloudfront:UpdateDistribution", "cloudfront:GetDistribution",
        "cloudfront:GetDistributionConfig"
    ],
    supported_services=["cloudfront"],
    mitre_techniques=["T1556.002", "T1562.001", "T1562.004"],
    tags=["cloudfront", "exploit", "https", "tls", "defense-evasion", "destructive"],
    requires_confirmation=True,
    destructive=True,
))

register_module(ModuleMetadata(
    name="cloudfront_exploit_remove_waf",
    category=ModuleCategory.EXPLOIT,
    risk=ModuleRisk.HIGH,
    description="Remove WAF Web ACL association from CloudFront distribution. DESTRUCTIVE - removes protection layer.",
    required_permissions=[
        "cloudfront:UpdateDistribution", "cloudfront:GetDistribution",
        "cloudfront:GetDistributionConfig", "wafv2:DisassociateWebACL"
    ],
    supported_services=["cloudfront", "wafv2"],
    mitre_techniques=["T1562.001", "T1562.007", "T1098"],
    tags=["cloudfront", "exploit", "waf", "remove-protection", "destructive"],
    requires_confirmation=True,
    destructive=True,
))

# ==================== PERSIST MODULES ====================
register_module(ModuleMetadata(
    name="cloudfront_persist_distribution",
    category=ModuleCategory.PERSIST,
    risk=ModuleRisk.HIGH,
    description="Create a persistent CloudFront distribution with attacker-controlled origin for ongoing traffic interception/redirection. DESTRUCTIVE.",
    required_permissions=[
        "cloudfront:CreateDistribution", "cloudfront:GetDistribution",
        "cloudfront:GetDistributionConfig", "cloudfront:DeleteDistribution",
        "cloudfront:CreateOriginAccessControl", "iam:CreateRole",
        "iam:AttachRolePolicy", "iam:PassRole"
    ],
    supported_services=["cloudfront", "iam", "s3"],
    mitre_techniques=["T1611", "T1098", "T1505.003", "T1046", "T1020"],
    tags=["cloudfront", "persist", "distribution", "cdn", "traffic-interception", "destructive"],
    requires_confirmation=True,
    destructive=True,
))

register_module(ModuleMetadata(
    name="cloudfront_persist_function",
    category=ModuleCategory.PERSIST,
    risk=ModuleRisk.HIGH,
    description="Create a persistent CloudFront Function for ongoing request/response manipulation at the edge. DESTRUCTIVE.",
    required_permissions=[
        "cloudfront:CreateFunction", "cloudfront:UpdateFunction",
        "cloudfront:DescribeFunction", "cloudfront:PublishFunction",
        "cloudfront:AssociateFunction", "iam:PassRole"
    ],
    supported_services=["cloudfront", "iam"],
    mitre_techniques=["T1611", "T1059.004", "T1098", "T1505.003", "T1505.001"],
    tags=["cloudfront", "persist", "function", "edge-code", "code-execution", "destructive"],
    requires_confirmation=True,
    destructive=True,
))

register_module(ModuleMetadata(
    name="cloudfront_persist_key_group",
    category=ModuleCategory.PERSIST,
    risk=ModuleRisk.HIGH,
    description="Create a persistent Key Group for generating signed URLs/cookies with long expiration for ongoing unauthorized access. DESTRUCTIVE.",
    required_permissions=[
        "cloudfront:CreateKeyGroup", "cloudfront:GetKeyGroup",
        "cloudfront:CreatePublicKey", "cloudfront:GetPublicKey",
        "cloudfront:DeleteKeyGroup", "cloudfront:DeletePublicKey"
    ],
    supported_services=["cloudfront"],
    mitre_techniques=["T1555.005", "T1098", "T1505.003", "T1611"],
    tags=["cloudfront", "persist", "key-group", "signed-urls", "signed-cookies", "destructive"],
    requires_confirmation=True,
    destructive=True,
))

register_module(ModuleMetadata(
    name="cloudfront_persist_origin_access",
    category=ModuleCategory.PERSIST,
    risk=ModuleRisk.HIGH,
    description="Create/modify Origin Access Control or Identity for persistent access to S3 origins. DESTRUCTIVE.",
    required_permissions=[
        "cloudfront:CreateOriginAccessControl", "cloudfront:UpdateOriginAccessControl",
        "cloudfront:GetOriginAccessControl", "cloudfront:DeleteOriginAccessControl",
        "cloudfront:CreateCloudFrontOriginAccessIdentity",
        "cloudfront:UpdateCloudFrontOriginAccessIdentity",
        "cloudfront:GetCloudFrontOriginAccessIdentity",
        "s3:PutBucketPolicy", "s3:GetBucketPolicy", "iam:PassRole"
    ],
    supported_services=["cloudfront", "s3", "iam"],
    mitre_techniques=["T1098", "T1505.003", "T1046", "T1078.004"],
    tags=["cloudfront", "persist", "origin-access", "oac", "oai", "s3", "destructive"],
    requires_confirmation=True,
    destructive=True,
))

# ==================== BACKDOOR MODULES ====================
register_module(ModuleMetadata(
    name="cloudfront_backdoor_function",
    category=ModuleCategory.BACKDOOR,
    risk=ModuleRisk.HIGH,
    description="Create a covert CloudFront Function for stealthy traffic manipulation, header exfiltration, or covert C2 at the edge. DESTRUCTIVE.",
    required_permissions=[
        "cloudfront:CreateFunction", "cloudfront:UpdateFunction",
        "cloudfront:DescribeFunction", "cloudfront:PublishFunction",
        "cloudfront:AssociateFunction", "iam:PassRole"
    ],
    supported_services=["cloudfront", "iam"],
    mitre_techniques=["T1611", "T1059.004", "T1098", "T1505.003", "T1020", "T1041", "T1572"],
    tags=["cloudfront", "backdoor", "function", "edge-code", "covert", "c2", "exfiltration", "destructive"],
    requires_confirmation=True,
    destructive=True,
))

register_module(ModuleMetadata(
    name="cloudfront_backdoor_signed_urls",
    category=ModuleCategory.BACKDOOR,
    risk=ModuleRisk.HIGH,
    description="Create a Key Group and generate signed URLs/cookies for covert access to private content. DESTRUCTIVE.",
    required_permissions=[
        "cloudfront:CreateKeyGroup", "cloudfront:GetKeyGroup",
        "cloudfront:CreatePublicKey", "cloudfront:GetPublicKey",
        "cloudfront:DeleteKeyGroup", "cloudfront:DeletePublicKey"
    ],
    supported_services=["cloudfront"],
    mitre_techniques=["T1555.005", "T1098", "T1505.003", "T1020", "T1572"],
    tags=["cloudfront", "backdoor", "signed-urls", "signed-cookies", "covert", "private-content", "destructive"],
    requires_confirmation=True,
    destructive=True,
))

register_module(ModuleMetadata(
    name="cloudfront_backdoor_realtime_logs",
    category=ModuleCategory.BACKDOOR,
    risk=ModuleRisk.HIGH,
    description="Create a real-time log config sending traffic data to attacker-controlled Kinesis stream. DESTRUCTIVE.",
    required_permissions=[
        "cloudfront:CreateRealtimeLogConfig", "cloudfront:GetRealtimeLogConfig",
        "cloudfront:DeleteRealtimeLogConfig", "cloudfront:UpdateRealtimeLogConfig",
        "kinesis:CreateStream", "kinesis:PutRecord", "kinesis:PutRecords",
        "iam:CreateRole", "iam:AttachRolePolicy", "iam:PassRole"
    ],
    supported_services=["cloudfront", "kinesis", "iam"],
    mitre_techniques=["T1526", "T1020", "T1041", "T1537", "T1098"],
    tags=["cloudfront", "backdoor", "realtime-logs", "kinesis", "traffic-analysis", "covert", "destructive"],
    requires_confirmation=True,
    destructive=True,
))

# ==================== EXFIL MODULES ====================
register_module(ModuleMetadata(
    name="cloudfront_exfil_distribution_config",
    category=ModuleCategory.EXFIL,
    risk=ModuleRisk.MEDIUM,
    description="Exfiltrate CloudFront distribution configurations: origins, cache behaviors, certificates, WAF, logging, geo restrictions, policies.",
    required_permissions=[
        "cloudfront:ListDistributions", "cloudfront:GetDistribution",
        "cloudfront:GetDistributionConfig", "cloudfront:ListTagsForResource"
    ],
    supported_services=["cloudfront"],
    mitre_techniques=["T1526", "T1530", "T1087.004"],
    tags=["cloudfront", "exfil", "config", "distributions", "cdn", "reconnaissance"],
    requires_confirmation=True,
))

register_module(ModuleMetadata(
    name="cloudfront_exfil_function_code",
    category=ModuleCategory.EXFIL,
    risk=ModuleRisk.MEDIUM,
    description="Exfiltrate CloudFront Function source code (may contain business logic, secrets, routing rules).",
    required_permissions=[
        "cloudfront:ListFunctions", "cloudfront:DescribeFunction",
        "cloudfront:GetFunction"
    ],
    supported_services=["cloudfront"],
    mitre_techniques=["T1526", "T1530", "T1005", "T1213", "T1611"],
    tags=["cloudfront", "exfil", "function-code", "edge-code", "source-code", "reconnaissance"],
    requires_confirmation=True,
))

register_module(ModuleMetadata(
    name="cloudfront_exfil_key_groups",
    category=ModuleCategory.EXFIL,
    risk=ModuleRisk.HIGH,
    description="Exfiltrate CloudFront Key Groups and public keys for signed URL/cookie generation. DESTRUCTIVE - exposes signing keys.",
    required_permissions=[
        "cloudfront:ListKeyGroups", "cloudfront:GetKeyGroup",
        "cloudfront:GetPublicKey", "cloudfront:ListPublicKeys"
    ],
    supported_services=["cloudfront"],
    mitre_techniques=["T1555.005", "T1530", "T1528"],
    tags=["cloudfront", "exfil", "key-groups", "public-keys", "signed-urls", "credentials", "destructive"],
    requires_confirmation=True,
    destructive=True,
))

register_module(ModuleMetadata(
    name="cloudfront_exfil_realtime_logs",
    category=ModuleCategory.EXFIL,
    risk=ModuleRisk.HIGH,
    description="Exfiltrate real-time log configuration and sample log data (contains viewer IPs, URLs, headers, cookies). DESTRUCTIVE - sensitive access data.",
    required_permissions=[
        "cloudfront:ListRealtimeLogConfigs", "cloudfront:GetRealtimeLogConfig",
        "kinesis:GetRecords", "kinesis:GetShardIterator", "kinesis:DescribeStream"
    ],
    supported_services=["cloudfront", "kinesis"],
    mitre_techniques=["T1526", "T1530", "T1005", "T1041", "T1213"],
    tags=["cloudfront", "exfil", "realtime-logs", "access-logs", "pii", "traffic-data", "destructive"],
    requires_confirmation=True,
    destructive=True,
))

register_module(ModuleMetadata(
    name="cloudfront_exfil_response_headers_policies",
    category=ModuleCategory.EXFIL,
    risk=ModuleRisk.MEDIUM,
    description="Exfiltrate Response Headers Policies: security headers, CORS config, custom headers, server timing settings.",
    required_permissions=[
        "cloudfront:ListResponseHeadersPolicies", "cloudfront:GetResponseHeadersPolicy",
        "cloudfront:ListTagsForResource"
    ],
    supported_services=["cloudfront"],
    mitre_techniques=["T1526", "T1530", "T1087.004"],
    tags=["cloudfront", "exfil", "response-headers-policies", "security-headers", "cors", "reconnaissance"],
    requires_confirmation=True,
))

register_module(ModuleMetadata(
    name="cloudfront_exfil_cache_policies",
    category=ModuleCategory.EXFIL,
    risk=ModuleRisk.MEDIUM,
    description="Exfiltrate Cache Policies: TTL settings, cache key composition (headers/cookies/query strings), compression settings.",
    required_permissions=[
        "cloudfront:ListCachePolicies", "cloudfront:GetCachePolicy",
        "cloudfront:ListTagsForResource"
    ],
    supported_services=["cloudfront"],
    mitre_techniques=["T1526", "T1530", "T1087.004"],
    tags=["cloudfront", "exfil", "cache-policies", "caching", "reconnaissance"],
    requires_confirmation=True,
))

# List all CloudFront modules
CLOUDFRONT_MODULES = [
    # Enum
    "cloudfront_enum_distributions", "cloudfront_enum_origin_access_controls",
    "cloudfront_enum_origin_access_identities", "cloudfront_enum_functions",
    "cloudfront_enum_key_groups", "cloudfront_enum_realtime_log_configs",
    "cloudfront_enum_response_headers_policies", "cloudfront_enum_cache_policies",
    "cloudfront_enum_origin_request_policies",
    # Privesc
    "cloudfront_privesc_analysis", "cloudfront_privesc_origin_access", "cloudfront_privesc_edge_functions",
    # Exploit
    "cloudfront_exploit_create_distribution", "cloudfront_exploit_update_distribution",
    "cloudfront_exploit_create_function", "cloudfront_exploit_update_function",
    "cloudfront_exploit_create_key_group", "cloudfront_exploit_disable_https_enforcement",
    "cloudfront_exploit_remove_waf",
    # Persist
    "cloudfront_persist_distribution", "cloudfront_persist_function",
    "cloudfront_persist_key_group", "cloudfront_persist_origin_access",
    # Backdoor
    "cloudfront_backdoor_function", "cloudfront_backdoor_signed_urls", "cloudfront_backdoor_realtime_logs",
    # Exfil
    "cloudfront_exfil_distribution_config", "cloudfront_exfil_function_code",
    "cloudfront_exfil_key_groups", "cloudfront_exfil_realtime_logs",
    "cloudfront_exfil_response_headers_policies", "cloudfront_exfil_cache_policies",
]

__all__ = ["CLOUDFRONT_MODULES"]
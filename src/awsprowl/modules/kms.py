"""
KMS Service Modules - All KMS-related features across categories

This module provides a unified interface for all KMS operations:
- enum: Enumeration (safe, read-only)
- privesc: Privilege escalation analysis
- exploit: Active exploitation
"""

from awsprowl.modules import ModuleCategory, ModuleMetadata, ModuleRisk, register_module

# ==================== ENUM MODULES ====================
register_module(ModuleMetadata(
    name="kms_enum_keys",
    category=ModuleCategory.ENUM,
    risk=ModuleRisk.SAFE,
    description="Enumerate KMS keys, aliases, and key policies.",
    required_permissions=[
        "kms:ListKeys", "kms:DescribeKey", "kms:GetKeyPolicy", "kms:ListAliases",
        "kms:ListGrants"
    ],
    supported_services=["kms"],
    mitre_techniques=["T1555.005"],
    tags=["kms", "enum", "keys", "crypto", "safe"],
    requires_confirmation=False,
))

register_module(ModuleMetadata(
    name="kms_enum_aliases",
    category=ModuleCategory.ENUM,
    risk=ModuleRisk.SAFE,
    description="Enumerate KMS aliases and their target keys.",
    required_permissions=["kms:ListAliases"],
    supported_services=["kms"],
    mitre_techniques=["T1555.005", "T1526"],
    tags=["kms", "enum", "aliases", "safe"],
    requires_confirmation=False,
))

register_module(ModuleMetadata(
    name="kms_enum_grants",
    category=ModuleCategory.ENUM,
    risk=ModuleRisk.SAFE,
    description="Enumerate KMS grants for cross-account access analysis.",
    required_permissions=["kms:ListGrants", "kms:ListKeys", "kms:GetKeyPolicy"],
    supported_services=["kms"],
    mitre_techniques=["T1555.005", "T1069.003"],
    tags=["kms", "enum", "grants", "cross-account", "safe"],
    requires_confirmation=False,
))

# ==================== PRIVESC MODULES ====================
register_module(ModuleMetadata(
    name="kms_privesc_analysis",
    category=ModuleCategory.PRIVESC,
    risk=ModuleRisk.SAFE,
    description="Analyze KMS key policies and grants for privilege escalation: key policy modification, grant creation, and cross-account key access.",
    required_permissions=[
        "kms:ListKeys", "kms:DescribeKey", "kms:GetKeyPolicy", "kms:ListAliases",
        "kms:ListGrants", "kms:ListRetirableGrants", "iam:GetRole", "iam:GetRolePolicy"
    ],
    supported_services=["kms", "iam"],
    mitre_techniques=["T1555.005", "T1069.003", "T1078.004"],
    tags=["kms", "privesc", "key-policy", "grants", "analysis", "safe"],
    requires_confirmation=False,
))

register_module(ModuleMetadata(
    name="kms_privesc_key_policy",
    category=ModuleCategory.PRIVESC,
    risk=ModuleRisk.SAFE,
    description="Analyze specific KMS key policy for over-permissive statements allowing key usage by unauthorized principals.",
    required_permissions=["kms:GetKeyPolicy", "kms:DescribeKey", "kms:ListKeyPolicies"],
    supported_services=["kms"],
    mitre_techniques=["T1069.003", "T1078.004"],
    tags=["kms", "privesc", "key-policy", "safe"],
    requires_confirmation=False,
))

register_module(ModuleMetadata(
    name="kms_privesc_grant_analysis",
    category=ModuleCategory.PRIVESC,
    risk=ModuleRisk.SAFE,
    description="Analyze KMS grants for privilege escalation: CreateGrant, RetireGrant, and cross-account grant abuse.",
    required_permissions=["kms:ListGrants", "kms:ListRetirableGrants", "kms:GetKeyPolicy", "kms:DescribeKey"],
    supported_services=["kms"],
    mitre_techniques=["T1069.003", "T1078.004"],
    tags=["kms", "privesc", "grants", "safe"],
    requires_confirmation=False,
))

# ==================== EXPLOIT MODULES ====================
register_module(ModuleMetadata(
    name="kms_exploit_create_key",
    category=ModuleCategory.EXPLOIT,
    risk=ModuleRisk.MEDIUM,
    description="Create KMS key for attacker-controlled encryption. DESTRUCTIVE.",
    required_permissions=["kms:CreateKey", "kms:DescribeKey", "kms:PutKeyPolicy", "kms:CreateAlias"],
    supported_services=["kms"],
    mitre_techniques=["T1611", "T1555.005"],
    tags=["kms", "exploit", "create-key", "destructive"],
    requires_confirmation=True,
    destructive=True,
))

register_module(ModuleMetadata(
    name="kms_exploit_put_key_policy",
    category=ModuleCategory.EXPLOIT,
    risk=ModuleRisk.HIGH,
    description="Put key policy to grant attacker access to key. DESTRUCTIVE - modifies key access.",
    required_permissions=["kms:PutKeyPolicy", "kms:GetKeyPolicy", "kms:DescribeKey"],
    supported_services=["kms"],
    mitre_techniques=["T1098", "T1555.005"],
    tags=["kms", "exploit", "key-policy", "destructive"],
    requires_confirmation=True,
    destructive=True,
))

register_module(ModuleMetadata(
    name="kms_exploit_create_grant",
    category=ModuleCategory.EXPLOIT,
    risk=ModuleRisk.HIGH,
    description="Create KMS grant for cross-account or cross-role key access. DESTRUCTIVE.",
    required_permissions=["kms:CreateGrant", "kms:ListGrants", "kms:DescribeKey"],
    supported_services=["kms"],
    mitre_techniques=["T1098", "T1555.005", "T1526"],
    tags=["kms", "exploit", "create-grant", "cross-account", "destructive"],
    requires_confirmation=True,
    destructive=True,
))

register_module(ModuleMetadata(
    name="kms_exploit_encrypt_decrypt",
    category=ModuleCategory.EXPLOIT,
    risk=ModuleRisk.MEDIUM,
    description="Use KMS key to encrypt/decrypt data for exfiltration or ransomware.",
    required_permissions=["kms:Encrypt", "kms:Decrypt", "kms:ReEncrypt*", "kms:GenerateDataKey*", "kms:DescribeKey"],
    supported_services=["kms"],
    mitre_techniques=["T1486", "T1530"],
    tags=["kms", "exploit", "crypto", "encryption", "destructive"],
    requires_confirmation=True,
    destructive=True,
))

register_module(ModuleMetadata(
    name="kms_exploit_schedule_key_deletion",
    category=ModuleCategory.EXPLOIT,
    risk=ModuleRisk.CRITICAL,
    description="Schedule KMS key deletion to destroy encryption keys (ransomware/DoS). CRITICAL.",
    required_permissions=["kms:ScheduleKeyDeletion", "kms:CancelKeyDeletion", "kms:DescribeKey"],
    supported_services=["kms"],
    mitre_techniques=["T1485", "T1486", "T1565"],
    tags=["kms", "exploit", "key-deletion", "ransomware", "destructive"],
    requires_confirmation=True,
    destructive=True,
))

register_module(ModuleMetadata(
    name="kms_exploit_disable_key",
    category=ModuleCategory.EXPLOIT,
    risk=ModuleRisk.HIGH,
    description="Disable KMS key to deny access to encrypted resources. DESTRUCTIVE.",
    required_permissions=["kms:DisableKey", "kms:EnableKey", "kms:DescribeKey"],
    supported_services=["kms"],
    mitre_techniques=["T1485", "T1562.001"],
    tags=["kms", "exploit", "disable-key", "denial-of-service", "destructive"],
    requires_confirmation=True,
    destructive=True,
))

register_module(ModuleMetadata(
    name="kms_exploit_revoke_grant",
    category=ModuleCategory.EXPLOIT,
    risk=ModuleRisk.HIGH,
    description="Revoke KMS grants to cut off legitimate access. DESTRUCTIVE.",
    required_permissions=["kms:RevokeGrant", "kms:ListGrants", "kms:DescribeKey"],
    supported_services=["kms"],
    mitre_techniques=["T1485", "T1562.001"],
    tags=["kms", "exploit", "revoke-grant", "destructive"],
    requires_confirmation=True,
    destructive=True,
))

# List all KMS modules
KMS_MODULES = [
    # Enum
    "kms_enum_keys", "kms_enum_aliases", "kms_enum_grants",
    # Privesc
    "kms_privesc_analysis", "kms_privesc_key_policy", "kms_privesc_grant_analysis",
    # Exploit
    "kms_exploit_create_key", "kms_exploit_put_key_policy", "kms_exploit_create_grant",
    "kms_exploit_encrypt_decrypt", "kms_exploit_schedule_key_deletion",
    "kms_exploit_disable_key", "kms_exploit_revoke_grant",
]

__all__ = ["KMS_MODULES"]

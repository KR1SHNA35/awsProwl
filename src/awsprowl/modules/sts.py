"""
STS Service Modules - All STS-related features across categories

This module provides a unified interface for all STS operations:
- enum: Enumeration (safe, read-only)
- privesc: Privilege escalation analysis
- exploit: Active exploitation
"""

from awsprowl.modules import ModuleCategory, ModuleMetadata, ModuleRisk, register_module

# ==================== ENUM MODULES ====================
register_module(ModuleMetadata(
    name="sts_enum_identity",
    category=ModuleCategory.ENUM,
    risk=ModuleRisk.SAFE,
    description="Enumerate STS/Account settings: account aliases, password policy, MFA devices, SAML/OIDC providers, cross-account roles, federation capabilities, and credential reports.",
    required_permissions=[
        "sts:GetCallerIdentity", "sts:GetSessionToken", "sts:GetAccessKeyInfo",
        "sts:GetFederationToken", "iam:ListAccountAliases", "iam:GetAccountSummary",
        "iam:ListVirtualMFADevices", "iam:ListSAMLProviders", "iam:ListOpenIDConnectProviders",
        "iam:ListRoles"
    ],
    supported_services=["sts", "iam"],
    mitre_techniques=["T1087.004", "T1069.003"],
    tags=["sts", "enum", "identity", "federation", "safe"],
    requires_confirmation=False,
))

# ==================== PRIVESC MODULES ====================
# STS doesn't have a dedicated privesc module in the category, but we can analyze STS-related privesc
# The iam__privesc covers STS-related escalation paths

# ==================== EXPLOIT MODULES ====================
register_module(ModuleMetadata(
    name="sts_exploit_assume_role",
    category=ModuleCategory.EXPLOIT,
    risk=ModuleRisk.MEDIUM,
    description="Assume an IAM role to gain its permissions. Requires valid trust policy.",
    required_permissions=["sts:AssumeRole"],
    supported_services=["sts", "iam"],
    mitre_techniques=["T1078.004", "T1526"],
    tags=["sts", "exploit", "assume-role", "credential-access"],
    requires_confirmation=True,
))

register_module(ModuleMetadata(
    name="sts_exploit_get_federation_token",
    category=ModuleCategory.EXPLOIT,
    risk=ModuleRisk.MEDIUM,
    description="Get federated token with custom policy for temporary elevated access.",
    required_permissions=["sts:GetFederationToken"],
    supported_services=["sts"],
    mitre_techniques=["T1078.004"],
    tags=["sts", "exploit", "federation-token", "credential-access"],
    requires_confirmation=True,
))

register_module(ModuleMetadata(
    name="sts_exploit_get_session_token",
    category=ModuleCategory.EXPLOIT,
    risk=ModuleRisk.LOW,
    description="Get session token with MFA for temporary credentials.",
    required_permissions=["sts:GetSessionToken"],
    supported_services=["sts"],
    mitre_techniques=["T1078.004"],
    tags=["sts", "exploit", "session-token", "credential-access"],
    requires_confirmation=True,
))

register_module(ModuleMetadata(
    name="sts_exploit_assume_role_with_saml",
    category=ModuleCategory.EXPLOIT,
    risk=ModuleRisk.HIGH,
    description="Assume role with SAML assertion for federated access. DESTRUCTIVE.",
    required_permissions=["sts:AssumeRoleWithSAML"],
    supported_services=["sts"],
    mitre_techniques=["T1078.004", "T1526"],
    tags=["sts", "exploit", "saml", "federation", "destructive"],
    requires_confirmation=True,
    destructive=True,
))

register_module(ModuleMetadata(
    name="sts_exploit_assume_role_with_web_identity",
    category=ModuleCategory.EXPLOIT,
    risk=ModuleRisk.HIGH,
    description="Assume role with web identity (OIDC) token for federated access. DESTRUCTIVE.",
    required_permissions=["sts:AssumeRoleWithWebIdentity"],
    supported_services=["sts"],
    mitre_techniques=["T1078.004", "T1526"],
    tags=["sts", "exploit", "oidc", "web-identity", "federation", "destructive"],
    requires_confirmation=True,
    destructive=True,
))

register_module(ModuleMetadata(
    name="sts_exploit_decode_authorization_message",
    category=ModuleCategory.EXPLOIT,
    risk=ModuleRisk.LOW,
    description="Decode authorization message to understand permission denial details.",
    required_permissions=["sts:DecodeAuthorizationMessage"],
    supported_services=["sts"],
    mitre_techniques=["T1087.004"],
    tags=["sts", "exploit", "decode-auth", "recon"],
    requires_confirmation=True,
))

register_module(ModuleMetadata(
    name="sts_exploit_get_access_key_info",
    category=ModuleCategory.EXPLOIT,
    risk=ModuleRisk.LOW,
    description="Get access key info to identify account ID from key ID.",
    required_permissions=["sts:GetAccessKeyInfo"],
    supported_services=["sts"],
    mitre_techniques=["T1087.004"],
    tags=["sts", "exploit", "access-key-info", "recon"],
    requires_confirmation=True,
))

# List all STS modules
STS_MODULES = [
    # Enum
    "sts_enum_identity",
    # Privesc - covered by iam__privesc
    # Exploit
    "sts_exploit_assume_role", "sts_exploit_get_federation_token", "sts_exploit_get_session_token",
    "sts_exploit_assume_role_with_saml", "sts_exploit_assume_role_with_web_identity",
    "sts_exploit_decode_authorization_message", "sts_exploit_get_access_key_info",
]

__all__ = ["STS_MODULES"]

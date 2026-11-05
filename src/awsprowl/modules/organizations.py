"""
Organizations Service Modules - All Organizations-related features across categories

This module provides a unified interface for all Organizations operations:
- enum: Enumeration (safe, read-only)
- privesc: Privilege escalation analysis
- persist: Persistence mechanisms
"""

from awsprowl.modules import ModuleCategory, ModuleMetadata, ModuleRisk, register_module

# ==================== ENUM MODULES ====================
register_module(ModuleMetadata(
    name="organizations_enum_accounts",
    category=ModuleCategory.ENUM,
    risk=ModuleRisk.SAFE,
    description="Enumerate AWS Organization accounts, roots, OUs, and policies.",
    required_permissions=[
        "organizations:ListAccounts", "organizations:ListRoots",
        "organizations:ListOrganizationalUnitsForParent", "organizations:ListPolicies",
        "organizations:ListPoliciesForTarget", "organizations:DescribeHandshake"
    ],
    supported_services=["organizations"],
    mitre_techniques=["T1087.004"],
    tags=["organizations", "enum", "accounts", "management", "safe"],
    requires_confirmation=False,
))

register_module(ModuleMetadata(
    name="organizations_enum_roots_ous",
    category=ModuleCategory.ENUM,
    risk=ModuleRisk.SAFE,
    description="Enumerate Organization roots and Organizational Units hierarchy.",
    required_permissions=[
        "organizations:ListRoots", "organizations:ListOrganizationalUnitsForParent",
        "organizations:ListParents", "organizations:DescribeOrganizationalUnit"
    ],
    supported_services=["organizations"],
    mitre_techniques=["T1087.004", "T1526"],
    tags=["organizations", "enum", "roots", "ous", "hierarchy", "safe"],
    requires_confirmation=False,
))

register_module(ModuleMetadata(
    name="organizations_enum_policies",
    category=ModuleCategory.ENUM,
    risk=ModuleRisk.SAFE,
    description="Enumerate SCPs, tag policies, backup policies, and AI services opt-out policies.",
    required_permissions=[
        "organizations:ListPolicies", "organizations:DescribePolicy",
        "organizations:ListPoliciesForTarget", "organizations:ListTargetsForPolicy"
    ],
    supported_services=["organizations"],
    mitre_techniques=["T1087.004", "T1526"],
    tags=["organizations", "enum", "policies", "scp", "safe"],
    requires_confirmation=False,
))

register_module(ModuleMetadata(
    name="organizations_enum_delegated_admins",
    category=ModuleCategory.ENUM,
    risk=ModuleRisk.SAFE,
    description="Enumerate delegated administrators for AWS services.",
    required_permissions=[
        "organizations:ListDelegatedAdministrators", "organizations:ListDelegatedServicesForAccount"
    ],
    supported_services=["organizations"],
    mitre_techniques=["T1087.004", "T1069.003"],
    tags=["organizations", "enum", "delegated-admins", "safe"],
    requires_confirmation=False,
))

register_module(ModuleMetadata(
    name="organizations_enum_handshakes",
    category=ModuleCategory.ENUM,
    risk=ModuleRisk.SAFE,
    description="Enumerate handshakes (invitations, enable-all-features requests).",
    required_permissions=[
        "organizations:ListHandshakesForAccount", "organizations:ListHandshakesForOrganization",
        "organizations:DescribeHandshake"
    ],
    supported_services=["organizations"],
    mitre_techniques=["T1087.004", "T1526"],
    tags=["organizations", "enum", "handshakes", "invitations", "safe"],
    requires_confirmation=False,
))

# ==================== PRIVESC MODULES ====================
register_module(ModuleMetadata(
    name="organizations_privesc_analysis",
    category=ModuleCategory.PRIVESC,
    risk=ModuleRisk.SAFE,
    description="Analyze AWS Organizations for privilege escalation: account takeover via member account access, SCP bypass, and delegated administrator abuse.",
    required_permissions=[
        "organizations:ListAccounts", "organizations:ListRoots",
        "organizations:ListOrganizationalUnitsForParent", "organizations:ListPolicies",
        "organizations:ListPoliciesForTarget", "organizations:DescribeAccount",
        "organizations:ListDelegatedAdministrators", "organizations:ListDelegatedServicesForAccount",
        "sts:AssumeRole"
    ],
    supported_services=["organizations", "sts"],
    mitre_techniques=["T1087.004", "T1078.004", "T1526"],
    tags=["organizations", "privesc", "management", "analysis", "safe"],
    requires_confirmation=False,
))

register_module(ModuleMetadata(
    name="organizations_privesc_scp_bypass",
    category=ModuleCategory.PRIVESC,
    risk=ModuleRisk.SAFE,
    description="Analyze SCPs for privilege escalation: missing deny statements, condition bypass, resource-based policy conflicts.",
    required_permissions=[
        "organizations:ListPolicies", "organizations:DescribePolicy",
        "organizations:ListPoliciesForTarget", "organizations:ListRoots",
        "organizations:ListOrganizationalUnitsForParent"
    ],
    supported_services=["organizations"],
    mitre_techniques=["T1562.001", "T1078.004"],
    tags=["organizations", "privesc", "scp", "bypass", "safe"],
    requires_confirmation=False,
))

register_module(ModuleMetadata(
    name="organizations_privesc_delegated_admin",
    category=ModuleCategory.PRIVESC,
    risk=ModuleRisk.SAFE,
    description="Analyze delegated administrator permissions for privilege escalation paths.",
    required_permissions=[
        "organizations:ListDelegatedAdministrators", "organizations:ListDelegatedServicesForAccount",
        "iam:ListAttachedRolePolicies", "iam:GetRole", "iam:GetRolePolicy"
    ],
    supported_services=["organizations", "iam"],
    mitre_techniques=["T1069.003", "T1078.004", "T1526"],
    tags=["organizations", "privesc", "delegated-admin", "safe"],
    requires_confirmation=False,
))

register_module(ModuleMetadata(
    name="organizations_privesc_org_takeover",
    category=ModuleCategory.PRIVESC,
    risk=ModuleRisk.SAFE,
    description="Check for organization account takeover paths via member account compromise.",
    required_permissions=[
        "organizations:ListAccounts", "organizations:ListDelegatedAdministrators",
        "sts:AssumeRole", "iam:ListRoles", "iam:GetRole"
    ],
    supported_services=["organizations", "sts", "iam"],
    mitre_techniques=["T1087.004", "T1078.004", "T1526"],
    tags=["organizations", "privesc", "takeover", "account-compromise", "safe"],
    requires_confirmation=False,
))

# ==================== PERSIST MODULES ====================
register_module(ModuleMetadata(
    name="organizations_persist_scp",
    category=ModuleCategory.PERSIST,
    risk=ModuleRisk.CRITICAL,
    description="Attach/modify SCP to allow persistent attacker access across accounts. CRITICAL.",
    required_permissions=[
        "organizations:AttachPolicy", "organizations:DetachPolicy",
        "organizations:UpdatePolicy", "organizations:DescribePolicy",
        "organizations:ListPoliciesForTarget"
    ],
    supported_services=["organizations"],
    mitre_techniques=["T1098", "T1526", "T1562.001"],
    tags=["organizations", "persist", "scp", "cross-account", "destructive"],
    requires_confirmation=True,
    destructive=True,
))

register_module(ModuleMetadata(
    name="organizations_persist_delegated_admin",
    category=ModuleCategory.PERSIST,
    risk=ModuleRisk.CRITICAL,
    description="Register attacker account as delegated administrator for service persistence. CRITICAL.",
    required_permissions=[
        "organizations:RegisterDelegatedAdministrator", "organizations:DeregisterDelegatedAdministrator",
        "organizations:ListDelegatedAdministrators", "organizations:ListDelegatedServicesForAccount"
    ],
    supported_services=["organizations"],
    mitre_techniques=["T1098", "T1078.004", "T1526"],
    tags=["organizations", "persist", "delegated-admin", "cross-account", "destructive"],
    requires_confirmation=True,
    destructive=True,
))

register_module(ModuleMetadata(
    name="organizations_persist_account_creation",
    category=ModuleCategory.PERSIST,
    risk=ModuleRisk.HIGH,
    description="Create new member account for persistent resource deployment. DESTRUCTIVE.",
    required_permissions=[
        "organizations:CreateAccount", "organizations:DescribeCreateAccountStatus",
        "organizations:ListAccounts", "organizations:CloseAccount"
    ],
    supported_services=["organizations"],
    mitre_techniques=["T1136.003", "T1526", "T1611"],
    tags=["organizations", "persist", "account-creation", "destructive"],
    requires_confirmation=True,
    destructive=True,
))

register_module(ModuleMetadata(
    name="organizations_persist_trusted_access",
    category=ModuleCategory.PERSIST,
    risk=ModuleRisk.HIGH,
    description="Enable trusted access for service to maintain cross-account permissions. DESTRUCTIVE.",
    required_permissions=[
        "organizations:EnableAWSServiceAccess", "organizations:DisableAWSServiceAccess",
        "organizations:ListAWSServiceAccessForOrganization"
    ],
    supported_services=["organizations"],
    mitre_techniques=["T1098", "T1526"],
    tags=["organizations", "persist", "trusted-access", "cross-account", "destructive"],
    requires_confirmation=True,
    destructive=True,
))

# ==================== EXPLOIT MODULES (PROWL parity) ====================
register_module(ModuleMetadata(
    name="organizations_exploit_assume_role",
    category=ModuleCategory.EXPLOIT,
    risk=ModuleRisk.HIGH,
    description="Assume role in member account via OrganizationAccountAccessRole for cross-account access. PROWL: organizations__assume_role. DESTRUCTIVE.",
    required_permissions=[
        "sts:AssumeRole", "organizations:ListAccounts",
        "organizations:DescribeAccount"
    ],
    supported_services=["organizations", "sts"],
    mitre_techniques=["T1078.004", "T1526", "T1550.003"],
    tags=["organizations", "exploit", "assume-role", "cross-account", "awsprowl", "destructive"],
    requires_confirmation=True,
    destructive=True,
))

# List all Organizations modules
ORGANIZATIONS_MODULES = [
    # Enum
    "organizations_enum_accounts", "organizations_enum_roots_ous", "organizations_enum_policies",
    "organizations_enum_delegated_admins", "organizations_enum_handshakes",
    # Privesc
    "organizations_privesc_analysis", "organizations_privesc_scp_bypass",
    "organizations_privesc_delegated_admin", "organizations_privesc_org_takeover",
    # Persist
    "organizations_persist_scp", "organizations_persist_delegated_admin",
    "organizations_persist_account_creation", "organizations_persist_trusted_access",
    # Exploit
    "organizations_exploit_assume_role",
]

__all__ = ["ORGANIZATIONS_MODULES"]

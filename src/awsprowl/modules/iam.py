"""
IAM Service Modules - All IAM-related features across categories

This module provides a unified interface for all IAM operations:
- enum: Enumeration (safe, read-only)
- privesc: Privilege escalation analysis
- exploit: Active exploitation
- persist: Persistence mechanisms
- backdoor: Covert access
- exfil: Data exfiltration (limited for IAM)
"""

from awsprowl.modules import ModuleCategory, ModuleMetadata, ModuleRisk, register_module

# ==================== ENUM MODULES ====================
register_module(ModuleMetadata(
    name="iam_enum_users",
    category=ModuleCategory.ENUM,
    risk=ModuleRisk.SAFE,
    description="Enumerate IAM users with details: policies, groups, access keys, MFA, login profiles, SSH keys, signing certs, service-specific credentials.",
    required_permissions=["iam:ListUsers", "iam:GetUser", "iam:ListAttachedUserPolicies", "iam:ListUserPolicies", "iam:ListGroupsForUser", "iam:ListAccessKeys", "iam:ListMFADevices", "iam:GetLoginProfile", "iam:ListSSHPublicKeys", "iam:ListSigningCertificates", "iam:ListServiceSpecificCredentials"],
    supported_services=["iam"],
    mitre_techniques=["T1087.004", "T1069.003"],
    tags=["iam", "enum", "users", "safe"],
    requires_confirmation=False,
))

register_module(ModuleMetadata(
    name="iam_enum_action_query",
    category=ModuleCategory.ENUM,
    risk=ModuleRisk.SAFE,
    description="Query IAM actions/permissions for specific services. PROWL: iam__enum_action_query.",
    required_permissions=["iam:GetAccountAuthorizationDetails"],
    supported_services=["iam"],
    mitre_techniques=["T1087.004", "T1526"],
    tags=["iam", "enum", "action-query", "permissions", "awsprowl"],
    requires_confirmation=False,
))

register_module(ModuleMetadata(
    name="iam_enum_permissions",
    category=ModuleCategory.ENUM,
    risk=ModuleRisk.SAFE,
    description="Enumerate effective permissions for IAM entities using policy simulation. PROWL: iam__enum_permissions.",
    required_permissions=["iam:SimulatePrincipalPolicy", "iam:ListUsers", "iam:ListRoles"],
    supported_services=["iam"],
    mitre_techniques=["T1087.004", "T1526"],
    tags=["iam", "enum", "permissions", "simulation", "awsprowl"],
    requires_confirmation=False,
))

register_module(ModuleMetadata(
    name="iam_enum_users_roles_policies_groups",
    category=ModuleCategory.ENUM,
    risk=ModuleRisk.SAFE,
    description="Comprehensive enumeration of users, roles, policies, and groups in one call. PROWL: iam__enum_users_roles_policies_groups.",
    required_permissions=["iam:GetAccountAuthorizationDetails"],
    supported_services=["iam"],
    mitre_techniques=["T1087.004", "T1069.003", "T1526"],
    tags=["iam", "enum", "comprehensive", "awsprowl"],
    requires_confirmation=False,
))

register_module(ModuleMetadata(
    name="iam_enum_credential_report",
    category=ModuleCategory.ENUM,
    risk=ModuleRisk.SAFE,
    description="Get IAM credential report for account-wide credential inventory. PROWL: iam__get_credential_report.",
    required_permissions=["iam:GetCredentialReport"],
    supported_services=["iam"],
    mitre_techniques=["T1087.004", "T1526"],
    tags=["iam", "enum", "credential-report", "awsprowl"],
    requires_confirmation=False,
))

register_module(ModuleMetadata(
    name="iam_enum_honeytokens",
    category=ModuleCategory.ENUM,
    risk=ModuleRisk.SAFE,
    description="Detect potential honeytokens (canary credentials) in IAM access keys. PROWL: iam__detect_honeytokens.",
    required_permissions=["iam:ListAccessKeys", "iam:ListUsers", "iam:GetAccessKeyLastUsed"],
    supported_services=["iam"],
    mitre_techniques=["T1069.003", "T1526"],
    tags=["iam", "enum", "honeytokens", "detection", "awsprowl"],
    requires_confirmation=False,
))

register_module(ModuleMetadata(
    name="iam_enum_roles",
    category=ModuleCategory.ENUM,
    risk=ModuleRisk.SAFE,
    description="Enumerate IAM roles: trust policies, attached/inline policies, instance profiles, tags, last used.",
    required_permissions=["iam:ListRoles", "iam:GetRole", "iam:ListAttachedRolePolicies", "iam:ListRolePolicies", "iam:ListInstanceProfilesForRole", "iam:GetRolePolicy"],
    supported_services=["iam"],
    mitre_techniques=["T1087.004", "T1069.003"],
    tags=["iam", "enum", "roles", "safe"],
    requires_confirmation=False,
))

register_module(ModuleMetadata(
    name="iam_enum_policies",
    category=ModuleCategory.ENUM,
    risk=ModuleRisk.SAFE,
    description="Enumerate managed and inline policies: versions, default version, entities attached, policy documents.",
    required_permissions=["iam:ListPolicies", "iam:GetPolicy", "iam:GetPolicyVersion", "iam:ListPolicyVersions", "iam:ListEntitiesForPolicy"],
    supported_services=["iam"],
    mitre_techniques=["T1087.004", "T1069.003"],
    tags=["iam", "enum", "policies", "safe"],
    requires_confirmation=False,
))

register_module(ModuleMetadata(
    name="iam_enum_groups",
    category=ModuleCategory.ENUM,
    risk=ModuleRisk.SAFE,
    description="Enumerate IAM groups: members, attached/inline policies.",
    required_permissions=["iam:ListGroups", "iam:GetGroup", "iam:ListAttachedGroupPolicies", "iam:ListGroupPolicies"],
    supported_services=["iam"],
    mitre_techniques=["T1087.004", "T1069.003"],
    tags=["iam", "enum", "groups", "safe"],
    requires_confirmation=False,
))

register_module(ModuleMetadata(
    name="iam_enum_account_authorization",
    category=ModuleCategory.ENUM,
    risk=ModuleRisk.SAFE,
    description="GetAccountAuthorizationDetails - comprehensive snapshot of all IAM entities.",
    required_permissions=["iam:GetAccountAuthorizationDetails"],
    supported_services=["iam"],
    mitre_techniques=["T1087.004", "T1069.003", "T1526"],
    tags=["iam", "enum", "account-authorization", "safe"],
    requires_confirmation=False,
))

register_module(ModuleMetadata(
    name="iam_enum_password_policy",
    category=ModuleCategory.ENUM,
    risk=ModuleRisk.SAFE,
    description="Get account password policy and account summary.",
    required_permissions=["iam:GetAccountPasswordPolicy", "iam:GetAccountSummary"],
    supported_services=["iam"],
    mitre_techniques=["T1087.004"],
    tags=["iam", "enum", "password-policy", "safe"],
    requires_confirmation=False,
))

register_module(ModuleMetadata(
    name="iam_enum_account_aliases",
    category=ModuleCategory.ENUM,
    risk=ModuleRisk.SAFE,
    description="List account aliases.",
    required_permissions=["iam:ListAccountAliases"],
    supported_services=["iam"],
    mitre_techniques=["T1087.004"],
    tags=["iam", "enum", "account-aliases", "safe"],
    requires_confirmation=False,
))

register_module(ModuleMetadata(
    name="iam_enum_service_linked_roles",
    category=ModuleCategory.ENUM,
    risk=ModuleRisk.SAFE,
    description="List service-linked roles and their deletion status.",
    required_permissions=["iam:ListServiceLinkedRoles", "iam:GetServiceLinkedRoleDeletionStatus"],
    supported_services=["iam"],
    mitre_techniques=["T1087.004"],
    tags=["iam", "enum", "service-linked-roles", "safe"],
    requires_confirmation=False,
))

register_module(ModuleMetadata(
    name="iam_enum_org_accounts",
    category=ModuleCategory.ENUM,
    risk=ModuleRisk.SAFE,
    description="List AWS Organization accounts, roots, OUs, and policies.",
    required_permissions=["organizations:ListAccounts", "organizations:ListRoots", "organizations:ListOrganizationalUnitsForParent", "organizations:ListPolicies", "organizations:ListPoliciesForTarget"],
    supported_services=["organizations"],
    mitre_techniques=["T1087.004", "T1526"],
    tags=["iam", "enum", "organizations", "safe"],
    requires_confirmation=False,
))

register_module(ModuleMetadata(
    name="iam_enum_cross_account_trusts",
    category=ModuleCategory.ENUM,
    risk=ModuleRisk.SAFE,
    description="Analyze cross-account trust relationships in role trust policies.",
    required_permissions=["iam:ListRoles", "iam:GetRole"],
    supported_services=["iam"],
    mitre_techniques=["T1087.004", "T1526"],
    tags=["iam", "enum", "cross-account", "trust", "safe"],
    requires_confirmation=False,
))

# ==================== PRIVESC MODULES ====================
register_module(ModuleMetadata(
    name="iam_privesc_full_scan",
    category=ModuleCategory.PRIVESC,
    risk=ModuleRisk.SAFE,
    description="Full privilege escalation scan using 50+ techniques: CreateAccessKey, CreateLoginProfile, UpdateLoginProfile, AttachUserPolicy, PutUserPolicy, AttachRolePolicy, PutRolePolicy, AttachGroupPolicy, PutGroupPolicy, CreatePolicyVersion, SetDefaultPolicyVersion, CreateRole, UpdateAssumeRolePolicy, PassRole, AddUserToGroup, and cross-account trust abuse.",
    required_permissions=["iam:GetAccountAuthorizationDetails", "iam:SimulatePrincipalPolicy", "iam:ListUsers", "iam:ListRoles", "iam:ListPolicies", "iam:ListGroups", "iam:GetUser", "iam:GetRole", "iam:GetPolicy", "iam:GetPolicyVersion", "iam:ListAttachedUserPolicies", "iam:ListUserPolicies", "iam:ListAttachedRolePolicies", "iam:ListRolePolicies", "iam:ListAttachedGroupPolicies", "iam:ListGroupPolicies", "iam:ListGroupsForUser", "iam:GetLoginProfile", "iam:GetAccountPasswordPolicy", "organizations:ListAccounts"],
    supported_services=["iam", "organizations"],
    mitre_techniques=["T1069.003", "T1087.004", "T1078.004", "T1526"],
    tags=["iam", "privesc", "full-scan", "safe"],
    requires_confirmation=False,
))

register_module(ModuleMetadata(
    name="iam_privesc_create_access_key",
    category=ModuleCategory.PRIVESC,
    risk=ModuleRisk.SAFE,
    description="Check if current principal can create access keys for other users.",
    required_permissions=["iam:SimulatePrincipalPolicy", "iam:ListUsers"],
    supported_services=["iam"],
    mitre_techniques=["T1078.004", "T1555.005"],
    tags=["iam", "privesc", "create-access-key", "safe"],
    requires_confirmation=False,
))

register_module(ModuleMetadata(
    name="iam_privesc_create_login_profile",
    category=ModuleCategory.PRIVESC,
    risk=ModuleRisk.SAFE,
    description="Check if current principal can create console login profiles for users.",
    required_permissions=["iam:SimulatePrincipalPolicy", "iam:ListUsers"],
    supported_services=["iam"],
    mitre_techniques=["T1078.004", "T1136.003"],
    tags=["iam", "privesc", "create-login-profile", "safe"],
    requires_confirmation=False,
))

register_module(ModuleMetadata(
    name="iam_privesc_attach_user_policy",
    category=ModuleCategory.PRIVESC,
    risk=ModuleRisk.SAFE,
    description="Check if current principal can attach managed policies to users.",
    required_permissions=["iam:SimulatePrincipalPolicy", "iam:ListUsers", "iam:ListPolicies"],
    supported_services=["iam"],
    mitre_techniques=["T1098", "T1078.004"],
    tags=["iam", "privesc", "attach-user-policy", "safe"],
    requires_confirmation=False,
))

register_module(ModuleMetadata(
    name="iam_privesc_put_user_policy",
    category=ModuleCategory.PRIVESC,
    risk=ModuleRisk.SAFE,
    description="Check if current principal can put inline policies on users.",
    required_permissions=["iam:SimulatePrincipalPolicy", "iam:ListUsers"],
    supported_services=["iam"],
    mitre_techniques=["T1098", "T1078.004"],
    tags=["iam", "privesc", "put-user-policy", "safe"],
    requires_confirmation=False,
))

register_module(ModuleMetadata(
    name="iam_privesc_attach_role_policy",
    category=ModuleCategory.PRIVESC,
    risk=ModuleRisk.SAFE,
    description="Check if current principal can attach managed policies to roles.",
    required_permissions=["iam:SimulatePrincipalPolicy", "iam:ListRoles", "iam:ListPolicies"],
    supported_services=["iam"],
    mitre_techniques=["T1098", "T1078.004"],
    tags=["iam", "privesc", "attach-role-policy", "safe"],
    requires_confirmation=False,
))

register_module(ModuleMetadata(
    name="iam_privesc_put_role_policy",
    category=ModuleCategory.PRIVESC,
    risk=ModuleRisk.SAFE,
    description="Check if current principal can put inline policies on roles.",
    required_permissions=["iam:SimulatePrincipalPolicy", "iam:ListRoles"],
    supported_services=["iam"],
    mitre_techniques=["T1098", "T1078.004"],
    tags=["iam", "privesc", "put-role-policy", "safe"],
    requires_confirmation=False,
))

register_module(ModuleMetadata(
    name="iam_privesc_create_policy_version",
    category=ModuleCategory.PRIVESC,
    risk=ModuleRisk.SAFE,
    description="Check if current principal can create new policy versions and set as default.",
    required_permissions=["iam:SimulatePrincipalPolicy", "iam:ListPolicies", "iam:GetPolicy"],
    supported_services=["iam"],
    mitre_techniques=["T1098", "T1078.004"],
    tags=["iam", "privesc", "create-policy-version", "safe"],
    requires_confirmation=False,
))

register_module(ModuleMetadata(
    name="iam_privesc_create_role",
    category=ModuleCategory.PRIVESC,
    risk=ModuleRisk.SAFE,
    description="Check if current principal can create roles with assumed role permissions.",
    required_permissions=["iam:SimulatePrincipalPolicy"],
    supported_services=["iam"],
    mitre_techniques=["T1098", "T1078.004"],
    tags=["iam", "privesc", "create-role", "safe"],
    requires_confirmation=False,
))

register_module(ModuleMetadata(
    name="iam_privesc_update_assume_role_policy",
    category=ModuleCategory.PRIVESC,
    risk=ModuleRisk.SAFE,
    description="Check if current principal can modify role trust policies.",
    required_permissions=["iam:SimulatePrincipalPolicy", "iam:ListRoles", "iam:GetRole"],
    supported_services=["iam"],
    mitre_techniques=["T1098", "T1078.004"],
    tags=["iam", "privesc", "update-assume-role-policy", "safe"],
    requires_confirmation=False,
))

register_module(ModuleMetadata(
    name="iam_privesc_pass_role",
    category=ModuleCategory.PRIVESC,
    risk=ModuleRisk.SAFE,
    description="Check if current principal can pass roles to services (EC2, Lambda, etc.).",
    required_permissions=["iam:SimulatePrincipalPolicy", "iam:ListRoles"],
    supported_services=["iam"],
    mitre_techniques=["T1078.004"],
    tags=["iam", "privesc", "pass-role", "safe"],
    requires_confirmation=False,
))

register_module(ModuleMetadata(
    name="iam_privesc_add_user_to_group",
    category=ModuleCategory.PRIVESC,
    risk=ModuleRisk.SAFE,
    description="Check if current principal can add users to privileged groups.",
    required_permissions=["iam:SimulatePrincipalPolicy", "iam:ListGroups", "iam:ListUsers"],
    supported_services=["iam"],
    mitre_techniques=["T1098", "T1078.004"],
    tags=["iam", "privesc", "add-user-to-group", "safe"],
    requires_confirmation=False,
))

register_module(ModuleMetadata(
    name="iam_privesc_service_linked_roles",
    category=ModuleCategory.PRIVESC,
    risk=ModuleRisk.SAFE,
    description="Check for privilege escalation via service-linked roles.",
    required_permissions=["iam:ListServiceLinkedRoles", "iam:GetRole", "iam:SimulatePrincipalPolicy"],
    supported_services=["iam"],
    mitre_techniques=["T1087.004", "T1078.004"],
    tags=["iam", "privesc", "service-linked-roles", "safe"],
    requires_confirmation=False,
))

register_module(ModuleMetadata(
    name="iam_privesc_org_takeover",
    category=ModuleCategory.PRIVESC,
    risk=ModuleRisk.SAFE,
    description="Check for organization account takeover paths.",
    required_permissions=["organizations:ListAccounts", "organizations:ListDelegatedAdministrators", "sts:AssumeRole"],
    supported_services=["organizations", "sts"],
    mitre_techniques=["T1087.004", "T1078.004", "T1526"],
    tags=["iam", "privesc", "organizations", "takeover", "safe"],
    requires_confirmation=False,
))

# ==================== EXPLOIT MODULES ====================
register_module(ModuleMetadata(
    name="iam_exploit_bruteforce_permissions",
    category=ModuleCategory.EXPLOIT,
    risk=ModuleRisk.HIGH,
    description="Brute-force IAM permissions by simulating policy actions. PROWL: iam__bruteforce_permissions. DESTRUCTIVE - may trigger detection.",
    required_permissions=["iam:SimulatePrincipalPolicy", "iam:ListUsers", "iam:ListRoles", "iam:ListPolicies"],
    supported_services=["iam"],
    mitre_techniques=["T1069.003", "T1555.005", "T1087.004"],
    tags=["iam", "exploit", "bruteforce", "permissions", "awsprowl", "destructive"],
    requires_confirmation=True,
    destructive=True,
))

register_module(ModuleMetadata(
    name="iam_exploit_decode_access_key_id",
    category=ModuleCategory.EXPLOIT,
    risk=ModuleRisk.MEDIUM,
    description="Decode AWS Access Key ID to extract account ID and key metadata. PROWL: iam__decode_accesskey_id.",
    required_permissions=[],
    supported_services=["iam"],
    mitre_techniques=["T1555.005", "T1526"],
    tags=["iam", "exploit", "decode", "access-key-id", "awsprowl"],
    requires_confirmation=True,
))

register_module(ModuleMetadata(
    name="iam_exploit_create_user",
    category=ModuleCategory.EXPLOIT,
    risk=ModuleRisk.HIGH,
    description="Create new IAM user with specified permissions. DESTRUCTIVE.",
    required_permissions=["iam:CreateUser", "iam:AttachUserPolicy", "iam:PutUserPolicy", "iam:CreateAccessKey", "iam:CreateLoginProfile"],
    supported_services=["iam"],
    mitre_techniques=["T1136.003", "T1078.004"],
    tags=["iam", "exploit", "create-user", "destructive"],
    requires_confirmation=True,
    destructive=True,
))

register_module(ModuleMetadata(
    name="iam_exploit_create_access_key",
    category=ModuleCategory.EXPLOIT,
    risk=ModuleRisk.HIGH,
    description="Create access keys for existing users. DESTRUCTIVE.",
    required_permissions=["iam:CreateAccessKey", "iam:GetUser"],
    supported_services=["iam"],
    mitre_techniques=["T1078.004", "T1555.005"],
    tags=["iam", "exploit", "create-access-key", "destructive"],
    requires_confirmation=True,
    destructive=True,
))

register_module(ModuleMetadata(
    name="iam_exploit_attach_policy",
    category=ModuleCategory.EXPLOIT,
    risk=ModuleRisk.HIGH,
    description="Attach managed/inline policies to users/roles/groups. DESTRUCTIVE.",
    required_permissions=["iam:AttachUserPolicy", "iam:PutUserPolicy", "iam:AttachRolePolicy", "iam:PutRolePolicy", "iam:AttachGroupPolicy", "iam:PutGroupPolicy"],
    supported_services=["iam"],
    mitre_techniques=["T1098", "T1078.004"],
    tags=["iam", "exploit", "attach-policy", "destructive"],
    requires_confirmation=True,
    destructive=True,
))

register_module(ModuleMetadata(
    name="iam_exploit_create_role",
    category=ModuleCategory.EXPLOIT,
    risk=ModuleRisk.HIGH,
    description="Create new IAM role with custom trust policy. DESTRUCTIVE.",
    required_permissions=["iam:CreateRole", "iam:AttachRolePolicy", "iam:PutRolePolicy"],
    supported_services=["iam"],
    mitre_techniques=["T1098", "T1078.004"],
    tags=["iam", "exploit", "create-role", "destructive"],
    requires_confirmation=True,
    destructive=True,
))

register_module(ModuleMetadata(
    name="iam_exploit_update_assume_role_policy",
    category=ModuleCategory.EXPLOIT,
    risk=ModuleRisk.CRITICAL,
    description="Modify role trust policy for cross-account assumption. CRITICAL.",
    required_permissions=["iam:UpdateAssumeRolePolicy", "iam:GetRole"],
    supported_services=["iam"],
    mitre_techniques=["T1098", "T1078.004"],
    tags=["iam", "exploit", "update-assume-role-policy", "cross-account", "destructive"],
    requires_confirmation=True,
    destructive=True,
))

register_module(ModuleMetadata(
    name="iam_exploit_create_policy_version",
    category=ModuleCategory.EXPLOIT,
    risk=ModuleRisk.HIGH,
    description="Create new policy version with escalated permissions. DESTRUCTIVE.",
    required_permissions=["iam:CreatePolicyVersion", "iam:SetDefaultPolicyVersion", "iam:GetPolicy"],
    supported_services=["iam"],
    mitre_techniques=["T1098", "T1078.004"],
    tags=["iam", "exploit", "create-policy-version", "destructive"],
    requires_confirmation=True,
    destructive=True,
))

# ==================== PERSIST MODULES ====================
register_module(ModuleMetadata(
    name="iam_persist_create_user",
    category=ModuleCategory.PERSIST,
    risk=ModuleRisk.HIGH,
    description="Create IAM user with programmatic access for persistence. DESTRUCTIVE.",
    required_permissions=["iam:CreateUser", "iam:CreateAccessKey", "iam:AttachUserPolicy", "iam:PutUserPolicy"],
    supported_services=["iam"],
    mitre_techniques=["T1136.003", "T1078.004", "T1556.003"],
    tags=["iam", "persist", "create-user", "destructive"],
    requires_confirmation=True,
    destructive=True,
))

register_module(ModuleMetadata(
    name="iam_persist_create_role",
    category=ModuleCategory.PERSIST,
    risk=ModuleRisk.HIGH,
    description="Create IAM role with trust policy for cross-account/service assumption. DESTRUCTIVE.",
    required_permissions=["iam:CreateRole", "iam:AttachRolePolicy", "iam:PutRolePolicy", "iam:UpdateAssumeRolePolicy"],
    supported_services=["iam"],
    mitre_techniques=["T1098", "T1078.004", "T1556.003"],
    tags=["iam", "persist", "create-role", "destructive"],
    requires_confirmation=True,
    destructive=True,
))

register_module(ModuleMetadata(
    name="iam_persist_create_access_key",
    category=ModuleCategory.PERSIST,
    risk=ModuleRisk.HIGH,
    description="Create access keys for existing users/roles. DESTRUCTIVE.",
    required_permissions=["iam:CreateAccessKey", "iam:ListAccessKeys"],
    supported_services=["iam"],
    mitre_techniques=["T1555.005", "T1078.004"],
    tags=["iam", "persist", "create-access-key", "destructive"],
    requires_confirmation=True,
    destructive=True,
))

register_module(ModuleMetadata(
    name="iam_persist_create_login_profile",
    category=ModuleCategory.PERSIST,
    risk=ModuleRisk.HIGH,
    description="Create console login profile for IAM user. DESTRUCTIVE.",
    required_permissions=["iam:CreateLoginProfile", "iam:UpdateLoginProfile", "iam:GetLoginProfile"],
    supported_services=["iam"],
    mitre_techniques=["T1136.003", "T1078.004"],
    tags=["iam", "persist", "create-login-profile", "destructive"],
    requires_confirmation=True,
    destructive=True,
))

register_module(ModuleMetadata(
    name="iam_persist_attach_admin_policy",
    category=ModuleCategory.PERSIST,
    risk=ModuleRisk.CRITICAL,
    description="Attach AdministratorAccess or equivalent policy. CRITICAL.",
    required_permissions=["iam:AttachUserPolicy", "iam:AttachRolePolicy", "iam:AttachGroupPolicy", "iam:PutUserPolicy", "iam:PutRolePolicy", "iam:PutGroupPolicy"],
    supported_services=["iam"],
    mitre_techniques=["T1098", "T1078.004"],
    tags=["iam", "persist", "admin-policy", "destructive"],
    requires_confirmation=True,
    destructive=True,
))

register_module(ModuleMetadata(
    name="iam_persist_update_assume_role_policy",
    category=ModuleCategory.PERSIST,
    risk=ModuleRisk.CRITICAL,
    description="Modify role trust policy for persistent external assumption. CRITICAL.",
    required_permissions=["iam:UpdateAssumeRolePolicy", "iam:GetRole"],
    supported_services=["iam"],
    mitre_techniques=["T1098", "T1078.004", "T1556.003"],
    tags=["iam", "persist", "update-assume-role-policy", "destructive"],
    requires_confirmation=True,
    destructive=True,
))

register_module(ModuleMetadata(
    name="iam_persist_create_policy_version",
    category=ModuleCategory.PERSIST,
    risk=ModuleRisk.HIGH,
    description="Create new policy version with elevated permissions. DESTRUCTIVE.",
    required_permissions=["iam:CreatePolicyVersion", "iam:SetDefaultPolicyVersion", "iam:GetPolicy", "iam:ListPolicyVersions"],
    supported_services=["iam"],
    mitre_techniques=["T1098", "T1078.004"],
    tags=["iam", "persist", "create-policy-version", "destructive"],
    requires_confirmation=True,
    destructive=True,
))

register_module(ModuleMetadata(
    name="iam_persist_add_user_to_group",
    category=ModuleCategory.PERSIST,
    risk=ModuleRisk.MEDIUM,
    description="Add user to group with elevated permissions.",
    required_permissions=["iam:AddUserToGroup", "iam:GetGroup", "iam:ListGroupsForUser"],
    supported_services=["iam"],
    mitre_techniques=["T1098", "T1078.004"],
    tags=["iam", "persist", "add-user-to-group"],
    requires_confirmation=True,
))

register_module(ModuleMetadata(
    name="iam_persist_create_service_linked_role",
    category=ModuleCategory.PERSIST,
    risk=ModuleRisk.MEDIUM,
    description="Create service-linked role for service-specific persistence. DESTRUCTIVE.",
    required_permissions=["iam:CreateServiceLinkedRole", "iam:GetServiceLinkedRoleDeletionStatus"],
    supported_services=["iam"],
    mitre_techniques=["T1098", "T1078.004"],
    tags=["iam", "persist", "service-linked-role", "destructive"],
    requires_confirmation=True,
    destructive=True,
))

# ==================== BACKDOOR MODULES ====================
register_module(ModuleMetadata(
    name="iam_backdoor_assume_role",
    category=ModuleCategory.BACKDOOR,
    risk=ModuleRisk.HIGH,
    description="Create role with trust policy allowing attacker account assumption. PROWL: iam__backdoor_assume_role. DESTRUCTIVE.",
    required_permissions=["iam:CreateRole", "iam:UpdateAssumeRolePolicy", "iam:AttachRolePolicy", "iam:PutRolePolicy"],
    supported_services=["iam"],
    mitre_techniques=["T1098", "T1078.004", "T1556.003"],
    tags=["iam", "backdoor", "assume-role", "cross-account", "awsprowl", "destructive"],
    requires_confirmation=True,
    destructive=True,
))

register_module(ModuleMetadata(
    name="iam_backdoor_users_keys",
    category=ModuleCategory.BACKDOOR,
    risk=ModuleRisk.HIGH,
    description="Create access keys for existing users for persistent backdoor access. PROWL: iam__backdoor_users_keys. DESTRUCTIVE.",
    required_permissions=["iam:CreateAccessKey", "iam:ListUsers", "iam:ListAccessKeys"],
    supported_services=["iam"],
    mitre_techniques=["T1098", "T1078.004", "T1555.005"],
    tags=["iam", "backdoor", "users-keys", "credentials", "awsprowl", "destructive"],
    requires_confirmation=True,
    destructive=True,
))

register_module(ModuleMetadata(
    name="iam_backdoor_users_password",
    category=ModuleCategory.BACKDOOR,
    risk=ModuleRisk.HIGH,
    description="Create/update console login profiles for users for backdoor access. PROWL: iam__backdoor_users_password. DESTRUCTIVE.",
    required_permissions=["iam:CreateLoginProfile", "iam:UpdateLoginProfile", "iam:GetLoginProfile", "iam:ListUsers"],
    supported_services=["iam"],
    mitre_techniques=["T1098", "T1078.004", "T1136.003"],
    tags=["iam", "backdoor", "users-password", "console", "awsprowl", "destructive"],
    requires_confirmation=True,
    destructive=True,
))

register_module(ModuleMetadata(
    name="iam_backdoor_service_role",
    category=ModuleCategory.BACKDOOR,
    risk=ModuleRisk.HIGH,
    description="Create service-linked/service role with permissive trust policy. DESTRUCTIVE.",
    required_permissions=["iam:CreateServiceLinkedRole", "iam:CreateRole", "iam:UpdateAssumeRolePolicy", "iam:AttachRolePolicy", "iam:PutRolePolicy"],
    supported_services=["iam"],
    mitre_techniques=["T1098", "T1078.004", "T1556.003"],
    tags=["iam", "backdoor", "service-role", "destructive"],
    requires_confirmation=True,
    destructive=True,
))

register_module(ModuleMetadata(
    name="iam_backdoor_oidc_provider",
    category=ModuleCategory.BACKDOOR,
    risk=ModuleRisk.HIGH,
    description="Create OIDC identity provider with attacker-controlled issuer. DESTRUCTIVE.",
    required_permissions=["iam:CreateOpenIDConnectProvider", "iam:AddClientIDToOpenIDConnectProvider", "iam:UpdateOpenIDConnectProviderThumbprint", "iam:ListOpenIDConnectProviders"],
    supported_services=["iam"],
    mitre_techniques=["T1078.004", "T1556.003", "T1098"],
    tags=["iam", "backdoor", "oidc", "federation", "destructive"],
    requires_confirmation=True,
    destructive=True,
))

register_module(ModuleMetadata(
    name="iam_backdoor_saml_provider",
    category=ModuleCategory.BACKDOOR,
    risk=ModuleRisk.HIGH,
    description="Create SAML identity provider with attacker-controlled metadata. DESTRUCTIVE.",
    required_permissions=["iam:CreateSAMLProvider", "iam:UpdateSAMLProvider", "iam:ListSAMLProviders"],
    supported_services=["iam"],
    mitre_techniques=["T1078.004", "T1556.003", "T1098"],
    tags=["iam", "backdoor", "saml", "federation", "destructive"],
    requires_confirmation=True,
    destructive=True,
))

# ==================== EXFIL MODULES ====================
register_module(ModuleMetadata(
    name="iam_exfil_credential_report",
    category=ModuleCategory.EXFIL,
    risk=ModuleRisk.MEDIUM,
    description="Generate and download IAM credential report for credential inventory.",
    required_permissions=["iam:GenerateCredentialReport", "iam:GetCredentialReport"],
    supported_services=["iam"],
    mitre_techniques=["T1530", "T1020"],
    tags=["iam", "exfil", "credential-report"],
    requires_confirmation=True,
))

register_module(ModuleMetadata(
    name="iam_exfil_access_keys",
    category=ModuleCategory.EXFIL,
    risk=ModuleRisk.HIGH,
    description="List access keys for all users (metadata only, not secret keys). DESTRUCTIVE.",
    required_permissions=["iam:ListAccessKeys", "iam:ListUsers"],
    supported_services=["iam"],
    mitre_techniques=["T1555.005", "T1530"],
    tags=["iam", "exfil", "access-keys", "destructive"],
    requires_confirmation=True,
    destructive=True,
))

# List all IAM modules
IAM_MODULES = [
    # Enum
    "iam_enum_users", "iam_enum_roles", "iam_enum_policies", "iam_enum_groups",
    "iam_enum_account_authorization", "iam_enum_password_policy", "iam_enum_account_aliases",
    "iam_enum_service_linked_roles", "iam_enum_org_accounts", "iam_enum_cross_account_trusts",
    "iam_enum_action_query", "iam_enum_permissions", "iam_enum_users_roles_policies_groups",
    "iam_enum_credential_report", "iam_enum_honeytokens",
    # Privesc
    "iam_privesc_full_scan", "iam_privesc_create_access_key", "iam_privesc_create_login_profile",
    "iam_privesc_attach_user_policy", "iam_privesc_put_user_policy", "iam_privesc_attach_role_policy",
    "iam_privesc_put_role_policy", "iam_privesc_create_policy_version", "iam_privesc_create_role",
    "iam_privesc_update_assume_role_policy", "iam_privesc_pass_role", "iam_privesc_add_user_to_group",
    "iam_privesc_service_linked_roles", "iam_privesc_org_takeover",
    # Exploit
    "iam_exploit_bruteforce_permissions", "iam_exploit_decode_access_key_id",
    "iam_exploit_create_user", "iam_exploit_create_access_key", "iam_exploit_attach_policy",
    "iam_exploit_create_role", "iam_exploit_update_assume_role_policy", "iam_exploit_create_policy_version",
    # Persist
    "iam_persist_create_user", "iam_persist_create_role", "iam_persist_create_access_key",
    "iam_persist_create_login_profile", "iam_persist_attach_admin_policy", "iam_persist_update_assume_role_policy",
    "iam_persist_create_policy_version", "iam_persist_add_user_to_group", "iam_persist_create_service_linked_role",
    # Backdoor
    "iam_backdoor_assume_role", "iam_backdoor_users_keys", "iam_backdoor_users_password",
    "iam_backdoor_service_role", "iam_backdoor_oidc_provider", "iam_backdoor_saml_provider",
    # Exfil
    "iam_exfil_credential_report", "iam_exfil_access_keys",
]

__all__ = ["IAM_MODULES"]

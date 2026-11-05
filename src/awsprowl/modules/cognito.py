"""
Cognito Service Modules - All Cognito-related features across categories

This module provides a unified interface for all Cognito operations:
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
    name="cognito_enum_user_pools",
    category=ModuleCategory.ENUM,
    risk=ModuleRisk.SAFE,
    description="Enumerate Cognito User Pools with details: MFA, password policies, app clients, advanced security, Lambda triggers.",
    required_permissions=[
        "cognito-idp:ListUserPools", "cognito-idp:DescribeUserPool",
        "cognito-idp:ListUserPoolClients", "cognito-idp:DescribeUserPoolClient",
        "cognito-idp:ListTagsForResource"
    ],
    supported_services=["cognito-idp"],
    mitre_techniques=["T1526", "T1087.004"],
    tags=["cognito", "enum", "user-pools", "safe"],
    requires_confirmation=False,
))

register_module(ModuleMetadata(
    name="cognito_enum_identity_pools",
    category=ModuleCategory.ENUM,
    risk=ModuleRisk.SAFE,
    description="Enumerate Cognito Identity Pools (federated identities): roles, login providers, unauthenticated access.",
    required_permissions=[
        "cognito-identity:ListIdentityPools", "cognito-identity:DescribeIdentityPool",
        "cognito-identity:GetIdentityPoolRoles", "cognito-identity:ListTagsForResource"
    ],
    supported_services=["cognito-identity"],
    mitre_techniques=["T1526", "T1087.004"],
    tags=["cognito", "enum", "identity-pools", "federated-identities", "safe"],
    requires_confirmation=False,
))

register_module(ModuleMetadata(
    name="cognito_enum_user_pool_clients",
    category=ModuleCategory.ENUM,
    risk=ModuleRisk.SAFE,
    description="Enumerate app clients for a specific User Pool: auth flows, OAuth config, callback URLs, token settings.",
    required_permissions=[
        "cognito-idp:ListUserPoolClients", "cognito-idp:DescribeUserPoolClient"
    ],
    supported_services=["cognito-idp"],
    mitre_techniques=["T1526", "T1087.004"],
    tags=["cognito", "enum", "app-clients", "oauth", "safe"],
    requires_confirmation=False,
))

register_module(ModuleMetadata(
    name="cognito_enum_users",
    category=ModuleCategory.ENUM,
    risk=ModuleRisk.SAFE,
    description="Enumerate users in a User Pool: attributes, MFA status, groups, creation date, last modified.",
    required_permissions=[
        "cognito-idp:ListUsers", "cognito-idp:AdminGetUser",
        "cognito-idp:ListGroups", "cognito-idp:ListUsersInGroup"
    ],
    supported_services=["cognito-idp"],
    mitre_techniques=["T1087.004", "T1069.003"],
    tags=["cognito", "enum", "users", "safe"],
    requires_confirmation=False,
))

register_module(ModuleMetadata(
    name="cognito_enum_groups",
    category=ModuleCategory.ENUM,
    risk=ModuleRisk.SAFE,
    description="Enumerate groups in a User Pool: members, roles, precedence, IAM policies.",
    required_permissions=[
        "cognito-idp:ListGroups", "cognito-idp:GetGroup",
        "cognito-idp:ListUsersInGroup"
    ],
    supported_services=["cognito-idp"],
    mitre_techniques=["T1087.004", "T1069.003"],
    tags=["cognito", "enum", "groups", "rbac", "safe"],
    requires_confirmation=False,
))

register_module(ModuleMetadata(
    name="cognito_enum_lambda_triggers",
    category=ModuleCategory.ENUM,
    risk=ModuleRisk.SAFE,
    description="Enumerate Lambda triggers configured on User Pools: pre-auth, post-auth, pre-token, custom message, etc.",
    required_permissions=[
        "cognito-idp:DescribeUserPool", "lambda:GetFunction",
        "lambda:GetPolicy"
    ],
    supported_services=["cognito-idp", "lambda"],
    mitre_techniques=["T1526", "T1087.004"],
    tags=["cognito", "enum", "lambda-triggers", "safe"],
    requires_confirmation=False,
))

register_module(ModuleMetadata(
    name="cognito_enum_resource_servers",
    category=ModuleCategory.ENUM,
    risk=ModuleRisk.SAFE,
    description="Enumerate resource servers (API authorization) for User Pools: scopes, identifiers.",
    required_permissions=[
        "cognito-idp:ListResourceServers", "cognito-idp:DescribeResourceServer"
    ],
    supported_services=["cognito-idp"],
    mitre_techniques=["T1526", "T1087.004"],
    tags=["cognito", "enum", "resource-servers", "oauth", "safe"],
    requires_confirmation=False,
))

register_module(ModuleMetadata(
    name="cognito_enum_domains",
    category=ModuleCategory.ENUM,
    risk=ModuleRisk.SAFE,
    description="Enumerate custom domains and hosted UI configuration for User Pools.",
    required_permissions=[
        "cognito-idp:DescribeUserPoolDomain", "cognito-idp:DescribeUserPool"
    ],
    supported_services=["cognito-idp"],
    mitre_techniques=["T1526", "T1087.004"],
    tags=["cognito", "enum", "domains", "hosted-ui", "safe"],
    requires_confirmation=False,
))

# ==================== PRIVESC MODULES ====================
register_module(ModuleMetadata(
    name="cognito_privesc_analysis",
    category=ModuleCategory.PRIVESC,
    risk=ModuleRisk.SAFE,
    description="Analyze Cognito configuration for privilege escalation: weak MFA, password policies, implicit flows, unauthenticated identities, overly permissive identity pool roles.",
    required_permissions=[
        "cognito-idp:ListUserPools", "cognito-idp:DescribeUserPool",
        "cognito-idp:ListUserPoolClients", "cognito-idp:DescribeUserPoolClient",
        "cognito-identity:ListIdentityPools", "cognito-identity:DescribeIdentityPool",
        "cognito-identity:GetIdentityPoolRoles",
        "iam:GetRole", "iam:GetRolePolicy", "iam:ListAttachedRolePolicies",
        "iam:ListRolePolicies", "iam:GetPolicy", "iam:GetPolicyVersion"
    ],
    supported_services=["cognito-idp", "cognito-identity", "iam"],
    mitre_techniques=["T1087.004", "T1526", "T1078.004"],
    tags=["cognito", "privesc", "analysis", "safe"],
    requires_confirmation=False,
))

register_module(ModuleMetadata(
    name="cognito_privesc_identity_pool_roles",
    category=ModuleCategory.PRIVESC,
    risk=ModuleRisk.SAFE,
    description="Analyze Cognito Identity Pool roles for privilege escalation: authenticated/unauthenticated role permissions, trust policies, cross-account access.",
    required_permissions=[
        "cognito-identity:ListIdentityPools", "cognito-identity:DescribeIdentityPool",
        "cognito-identity:GetIdentityPoolRoles",
        "iam:GetRole", "iam:GetRolePolicy", "iam:ListAttachedRolePolicies",
        "iam:ListRolePolicies", "iam:GetPolicy", "iam:GetPolicyVersion",
        "iam:SimulatePrincipalPolicy"
    ],
    supported_services=["cognito-identity", "iam"],
    mitre_techniques=["T1087.004", "T1078.004", "T1526"],
    tags=["cognito", "privesc", "identity-pool-roles", "safe"],
    requires_confirmation=False,
))

register_module(ModuleMetadata(
    name="cognito_privesc_user_pool_client",
    category=ModuleCategory.PRIVESC,
    risk=ModuleRisk.SAFE,
    description="Analyze User Pool app clients for privilege escalation: insecure auth flows, missing client secrets, wildcard callback URLs, token revocation.",
    required_permissions=[
        "cognito-idp:ListUserPools", "cognito-idp:DescribeUserPool",
        "cognito-idp:ListUserPoolClients", "cognito-idp:DescribeUserPoolClient"
    ],
    supported_services=["cognito-idp"],
    mitre_techniques=["T1087.004", "T1526", "T1078.004"],
    tags=["cognito", "privesc", "app-client", "oauth", "safe"],
    requires_confirmation=False,
))

# ==================== EXPLOIT MODULES ====================
register_module(ModuleMetadata(
    name="cognito_exploit_create_user_pool_client",
    category=ModuleCategory.EXPLOIT,
    risk=ModuleRisk.HIGH,
    description="Create a new app client in a User Pool with insecure configuration (implicit flow, no secret, wildcard callbacks). DESTRUCTIVE.",
    required_permissions=[
        "cognito-idp:CreateUserPoolClient", "cognito-idp:DescribeUserPoolClient",
        "cognito-idp:UpdateUserPoolClient", "cognito-idp:DeleteUserPoolClient"
    ],
    supported_services=["cognito-idp"],
    mitre_techniques=["T1556.002", "T1098", "T1611"],
    tags=["cognito", "exploit", "create-client", "oauth", "destructive"],
    requires_confirmation=True,
    destructive=True,
))

register_module(ModuleMetadata(
    name="cognito_exploit_update_user_pool_client",
    category=ModuleCategory.EXPLOIT,
    risk=ModuleRisk.HIGH,
    description="Update an existing app client to enable insecure auth flows, disable token revocation, add wildcard callbacks. DESTRUCTIVE.",
    required_permissions=[
        "cognito-idp:UpdateUserPoolClient", "cognito-idp:DescribeUserPoolClient",
        "cognito-idp:DeleteUserPoolClient"
    ],
    supported_services=["cognito-idp"],
    mitre_techniques=["T1556.002", "T1098", "T1526"],
    tags=["cognito", "exploit", "update-client", "oauth", "destructive"],
    requires_confirmation=True,
    destructive=True,
))

register_module(ModuleMetadata(
    name="cognito_exploit_create_identity_pool",
    category=ModuleCategory.EXPLOIT,
    risk=ModuleRisk.HIGH,
    description="Create a Cognito Identity Pool with unauthenticated access and overly permissive roles. DESTRUCTIVE.",
    required_permissions=[
        "cognito-identity:CreateIdentityPool", "cognito-identity:DescribeIdentityPool",
        "cognito-identity:SetIdentityPoolRoles", "cognito-identity:DeleteIdentityPool",
        "iam:CreateRole", "iam:AttachRolePolicy", "iam:PutRolePolicy",
        "iam:PassRole"
    ],
    supported_services=["cognito-identity", "iam"],
    mitre_techniques=["T1556.002", "T1098", "T1611"],
    tags=["cognito", "exploit", "create-identity-pool", "federated-identities", "destructive"],
    requires_confirmation=True,
    destructive=True,
))

register_module(ModuleMetadata(
    name="cognito_exploit_update_identity_pool_roles",
    category=ModuleCategory.EXPLOIT,
    risk=ModuleRisk.HIGH,
    description="Update Identity Pool roles to grant excessive permissions to authenticated/unauthenticated identities. DESTRUCTIVE.",
    required_permissions=[
        "cognito-identity:SetIdentityPoolRoles", "cognito-identity:GetIdentityPoolRoles",
        "cognito-identity:DescribeIdentityPool",
        "iam:CreateRole", "iam:AttachRolePolicy", "iam:PutRolePolicy",
        "iam:PassRole"
    ],
    supported_services=["cognito-identity", "iam"],
    mitre_techniques=["T1098", "T1078.004", "T1611"],
    tags=["cognito", "exploit", "update-roles", "identity-pool", "destructive"],
    requires_confirmation=True,
    destructive=True,
))

register_module(ModuleMetadata(
    name="cognito_exploit_create_user",
    category=ModuleCategory.EXPLOIT,
    risk=ModuleRisk.HIGH,
    description="Create a user in a User Pool with admin privileges or add to privileged groups. DESTRUCTIVE.",
    required_permissions=[
        "cognito-idp:AdminCreateUser", "cognito-idp:AdminAddUserToGroup",
        "cognito-idp:AdminSetUserPassword", "cognito-idp:AdminUpdateUserAttributes",
        "cognito-idp:ListGroups", "cognito-idp:GetGroup"
    ],
    supported_services=["cognito-idp"],
    mitre_techniques=["T1136.003", "T1098", "T1556.002"],
    tags=["cognito", "exploit", "create-user", "user-management", "destructive"],
    requires_confirmation=True,
    destructive=True,
))

register_module(ModuleMetadata(
    name="cognito_exploit_disable_mfa",
    category=ModuleCategory.EXPLOIT,
    risk=ModuleRisk.HIGH,
    description="Disable MFA on a User Pool or for specific users. DESTRUCTIVE - weakens security posture.",
    required_permissions=[
        "cognito-idp:SetUserPoolMfaConfig", "cognito-idp:AdminSetUserMFAPreference",
        "cognito-idp:DescribeUserPool", "cognito-idp:AdminGetUser"
    ],
    supported_services=["cognito-idp"],
    mitre_techniques=["T1556.002", "T1562.001", "T1562.004"],
    tags=["cognito", "exploit", "disable-mfa", "defense-evasion", "destructive"],
    requires_confirmation=True,
    destructive=True,
))

register_module(ModuleMetadata(
    name="cognito_exploit_weak_password_policy",
    category=ModuleCategory.EXPLOIT,
    risk=ModuleRisk.MEDIUM,
    description="Weaken User Pool password policy (reduce length, disable complexity). DESTRUCTIVE.",
    required_permissions=[
        "cognito-idp:UpdateUserPool", "cognito-idp:DescribeUserPool"
    ],
    supported_services=["cognito-idp"],
    mitre_techniques=["T1556.002", "T1562.001"],
    tags=["cognito", "exploit", "password-policy", "destructive"],
    requires_confirmation=True,
    destructive=True,
))

# ==================== PERSIST MODULES ====================
register_module(ModuleMetadata(
    name="cognito_persist_user_pool_client",
    category=ModuleCategory.PERSIST,
    risk=ModuleRisk.HIGH,
    description="Create a persistent app client with long-lived refresh tokens and implicit flow for ongoing access. DESTRUCTIVE.",
    required_permissions=[
        "cognito-idp:CreateUserPoolClient", "cognito-idp:UpdateUserPoolClient",
        "cognito-idp:DescribeUserPoolClient", "cognito-idp:DeleteUserPoolClient"
    ],
    supported_services=["cognito-idp"],
    mitre_techniques=["T1556.002", "T1098", "T1505.003"],
    tags=["cognito", "persist", "app-client", "refresh-tokens", "destructive"],
    requires_confirmation=True,
    destructive=True,
))

register_module(ModuleMetadata(
    name="cognito_persist_identity_pool",
    category=ModuleCategory.PERSIST,
    risk=ModuleRisk.HIGH,
    description="Create a persistent Identity Pool with unauthenticated access and permissive roles for ongoing federated access. DESTRUCTIVE.",
    required_permissions=[
        "cognito-identity:CreateIdentityPool", "cognito-identity:SetIdentityPoolRoles",
        "cognito-identity:DescribeIdentityPool", "cognito-identity:DeleteIdentityPool",
        "iam:CreateRole", "iam:AttachRolePolicy", "iam:PutRolePolicy", "iam:PassRole"
    ],
    supported_services=["cognito-identity", "iam"],
    mitre_techniques=["T1556.002", "T1098", "T1505.003", "T1078.004"],
    tags=["cognito", "persist", "identity-pool", "federated-identities", "destructive"],
    requires_confirmation=True,
    destructive=True,
))

register_module(ModuleMetadata(
    name="cognito_persist_user_account",
    category=ModuleCategory.PERSIST,
    risk=ModuleRisk.HIGH,
    description="Create a persistent user account with permanent password and admin group membership. DESTRUCTIVE.",
    required_permissions=[
        "cognito-idp:AdminCreateUser", "cognito-idp:AdminSetUserPassword",
        "cognito-idp:AdminAddUserToGroup", "cognito-idp:AdminUpdateUserAttributes",
        "cognito-idp:ListGroups", "cognito-idp:GetGroup"
    ],
    supported_services=["cognito-idp"],
    mitre_techniques=["T1136.003", "T1098", "T1505.003", "T1556.002"],
    tags=["cognito", "persist", "user-account", "admin-access", "destructive"],
    requires_confirmation=True,
    destructive=True,
))

register_module(ModuleMetadata(
    name="cognito_persist_lambda_trigger",
    category=ModuleCategory.PERSIST,
    risk=ModuleRisk.HIGH,
    description="Add/modify Lambda trigger on User Pool for persistent code execution on auth events. DESTRUCTIVE.",
    required_permissions=[
        "cognito-idp:UpdateUserPool", "cognito-idp:DescribeUserPool",
        "lambda:CreateFunction", "lambda:UpdateFunctionCode",
        "lambda:AddPermission", "lambda:GetFunction", "iam:PassRole"
    ],
    supported_services=["cognito-idp", "lambda", "iam"],
    mitre_techniques=["T1059.004", "T1505.003", "T1098", "T1556.002"],
    tags=["cognito", "persist", "lambda-trigger", "code-execution", "destructive"],
    requires_confirmation=True,
    destructive=True,
))

# ==================== BACKDOOR MODULES ====================
register_module(ModuleMetadata(
    name="cognito_backdoor_oauth_client",
    category=ModuleCategory.BACKDOOR,
    risk=ModuleRisk.HIGH,
    description="Create a covert OAuth client with implicit flow, no secret, and wildcard redirects for stealthy token theft. DESTRUCTIVE.",
    required_permissions=[
        "cognito-idp:CreateUserPoolClient", "cognito-idp:UpdateUserPoolClient",
        "cognito-idp:DescribeUserPoolClient", "cognito-idp:DeleteUserPoolClient"
    ],
    supported_services=["cognito-idp"],
    mitre_techniques=["T1556.002", "T1098", "T1505.003", "T1528"],
    tags=["cognito", "backdoor", "oauth", "implicit-flow", "covert", "destructive"],
    requires_confirmation=True,
    destructive=True,
))

register_module(ModuleMetadata(
    name="cognito_backdoor_identity_pool",
    category=ModuleCategory.BACKDOOR,
    risk=ModuleRisk.HIGH,
    description="Create a covert Identity Pool with unauthenticated access and minimal role for stealthy federated identity access. DESTRUCTIVE.",
    required_permissions=[
        "cognito-identity:CreateIdentityPool", "cognito-identity:SetIdentityPoolRoles",
        "cognito-identity:DescribeIdentityPool", "cognito-identity:DeleteIdentityPool",
        "iam:CreateRole", "iam:AttachRolePolicy", "iam:PutRolePolicy", "iam:PassRole"
    ],
    supported_services=["cognito-identity", "iam"],
    mitre_techniques=["T1556.002", "T1098", "T1505.003", "T1078.004", "T1528"],
    tags=["cognito", "backdoor", "identity-pool", "federated-identities", "covert", "destructive"],
    requires_confirmation=True,
    destructive=True,
))

register_module(ModuleMetadata(
    name="cognito_backdoor_user_migration_lambda",
    category=ModuleCategory.BACKDOOR,
    risk=ModuleRisk.HIGH,
    description="Install a User Migration Lambda trigger to harvest credentials during user sign-in. DESTRUCTIVE.",
    required_permissions=[
        "cognito-idp:UpdateUserPool", "cognito-idp:DescribeUserPool",
        "lambda:CreateFunction", "lambda:UpdateFunctionCode",
        "lambda:AddPermission", "lambda:GetFunction", "iam:PassRole"
    ],
    supported_services=["cognito-idp", "lambda", "iam"],
    mitre_techniques=["T1056.001", "T1556.002", "T1059.004", "T1505.003"],
    tags=["cognito", "backdoor", "user-migration", "credential-harvesting", "covert", "destructive"],
    requires_confirmation=True,
    destructive=True,
))

# ==================== EXFIL MODULES ====================
register_module(ModuleMetadata(
    name="cognito_exfil_user_pool_config",
    category=ModuleCategory.EXFIL,
    risk=ModuleRisk.MEDIUM,
    description="Exfiltrate User Pool configuration: password policy, MFA settings, Lambda triggers, app clients, OAuth config.",
    required_permissions=[
        "cognito-idp:ListUserPools", "cognito-idp:DescribeUserPool",
        "cognito-idp:ListUserPoolClients", "cognito-idp:DescribeUserPoolClient",
        "cognito-idp:ListResourceServers", "cognito-idp:DescribeUserPoolDomain",
        "cognito-idp:ListTagsForResource"
    ],
    supported_services=["cognito-idp"],
    mitre_techniques=["T1526", "T1530", "T1087.004"],
    tags=["cognito", "exfil", "config", "user-pool", "reconnaissance"],
    requires_confirmation=True,
))

register_module(ModuleMetadata(
    name="cognito_exfil_identity_pool_config",
    category=ModuleCategory.EXFIL,
    risk=ModuleRisk.MEDIUM,
    description="Exfiltrate Identity Pool configuration: roles, login providers, unauthenticated access settings.",
    required_permissions=[
        "cognito-identity:ListIdentityPools", "cognito-identity:DescribeIdentityPool",
        "cognito-identity:GetIdentityPoolRoles", "cognito-identity:ListTagsForResource",
        "iam:GetRole", "iam:GetRolePolicy", "iam:ListAttachedRolePolicies",
        "iam:ListRolePolicies"
    ],
    supported_services=["cognito-identity", "iam"],
    mitre_techniques=["T1526", "T1530", "T1087.004"],
    tags=["cognito", "exfil", "config", "identity-pool", "federated-identities", "reconnaissance"],
    requires_confirmation=True,
))

register_module(ModuleMetadata(
    name="cognito_exfil_users",
    category=ModuleCategory.EXFIL,
    risk=ModuleRisk.HIGH,
    description="Exfiltrate user data from User Pools: usernames, emails, phone numbers, attributes, MFA status, group membership. DESTRUCTIVE - sensitive data.",
    required_permissions=[
        "cognito-idp:ListUsers", "cognito-idp:AdminGetUser",
        "cognito-idp:ListGroups", "cognito-idp:ListUsersInGroup",
        "cognito-idp:GetGroup"
    ],
    supported_services=["cognito-idp"],
    mitre_techniques=["T1087.004", "T1530", "T1005", "T1213"],
    tags=["cognito", "exfil", "users", "pii", "sensitive-data", "destructive"],
    requires_confirmation=True,
    destructive=True,
))

register_module(ModuleMetadata(
    name="cognito_exfil_app_client_secrets",
    category=ModuleCategory.EXFIL,
    risk=ModuleRisk.HIGH,
    description="Exfiltrate app client secrets from User Pools. DESTRUCTIVE - exposes OAuth client credentials.",
    required_permissions=[
        "cognito-idp:ListUserPoolClients", "cognito-idp:DescribeUserPoolClient"
    ],
    supported_services=["cognito-idp"],
    mitre_techniques=["T1555.005", "T1528", "T1530"],
    tags=["cognito", "exfil", "client-secrets", "oauth", "credentials", "destructive"],
    requires_confirmation=True,
    destructive=True,
))

register_module(ModuleMetadata(
    name="cognito_exfil_lambda_trigger_code",
    category=ModuleCategory.EXFIL,
    risk=ModuleRisk.HIGH,
    description="Exfiltrate Lambda trigger function code attached to User Pools. May contain secrets or business logic. DESTRUCTIVE.",
    required_permissions=[
        "cognito-idp:DescribeUserPool", "lambda:GetFunction",
        "lambda:GetFunctionCodeSigningConfig", "lambda:GetLayerVersion"
    ],
    supported_services=["cognito-idp", "lambda"],
    mitre_techniques=["T1526", "T1530", "T1005", "T1213"],
    tags=["cognito", "exfil", "lambda-code", "source-code", "destructive"],
    requires_confirmation=True,
    destructive=True,
))

# List all Cognito modules
COGNITO_MODULES = [
    # Enum
    "cognito_enum_user_pools", "cognito_enum_identity_pools", "cognito_enum_user_pool_clients",
    "cognito_enum_users", "cognito_enum_groups", "cognito_enum_lambda_triggers",
    "cognito_enum_resource_servers", "cognito_enum_domains",
    # Privesc
    "cognito_privesc_analysis", "cognito_privesc_identity_pool_roles", "cognito_privesc_user_pool_client",
    # Exploit
    "cognito_exploit_create_user_pool_client", "cognito_exploit_update_user_pool_client",
    "cognito_exploit_create_identity_pool", "cognito_exploit_update_identity_pool_roles",
    "cognito_exploit_create_user", "cognito_exploit_disable_mfa", "cognito_exploit_weak_password_policy",
    # Persist
    "cognito_persist_user_pool_client", "cognito_persist_identity_pool", "cognito_persist_user_account",
    "cognito_persist_lambda_trigger",
    # Backdoor
    "cognito_backdoor_oauth_client", "cognito_backdoor_identity_pool", "cognito_backdoor_user_migration_lambda",
    # Exfil
    "cognito_exfil_user_pool_config", "cognito_exfil_identity_pool_config",
    "cognito_exfil_users", "cognito_exfil_app_client_secrets", "cognito_exfil_lambda_trigger_code",
]

__all__ = ["COGNITO_MODULES"]
"""
EKS Service Modules - All EKS-related features across categories

This module provides a unified interface for all EKS operations:
- enum: Enumeration (safe, read-only)
- privesc: Privilege escalation analysis
- exploit: Active exploitation
"""

from awsprowl.modules import ModuleCategory, ModuleMetadata, ModuleRisk, register_module

# ==================== ENUM MODULES ====================
register_module(ModuleMetadata(
    name="eks_enum_clusters",
    category=ModuleCategory.ENUM,
    risk=ModuleRisk.SAFE,
    description="Enumerate EKS clusters, node groups, and Fargate profiles.",
    required_permissions=[
        "eks:ListClusters", "eks:DescribeCluster", "eks:ListNodegroups", "eks:DescribeNodegroup",
        "eks:ListFargateProfiles", "eks:DescribeFargateProfile"
    ],
    supported_services=["eks"],
    mitre_techniques=["T1087.004", "T1648.001"],
    tags=["eks", "enum", "clusters", "kubernetes", "safe"],
    requires_confirmation=False,
))

register_module(ModuleMetadata(
    name="eks_enum_addons",
    category=ModuleCategory.ENUM,
    risk=ModuleRisk.SAFE,
    description="Enumerate EKS add-ons (VPC CNI, CoreDNS, kube-proxy, CSI drivers, etc.).",
    required_permissions=[
        "eks:ListAddons", "eks:DescribeAddon", "eks:ListClusters"
    ],
    supported_services=["eks"],
    mitre_techniques=["T1087.004", "T1526"],
    tags=["eks", "enum", "addons", "kubernetes", "safe"],
    requires_confirmation=False,
))

register_module(ModuleMetadata(
    name="eks_enum_identity_providers",
    category=ModuleCategory.ENUM,
    risk=ModuleRisk.SAFE,
    description="Enumerate EKS identity provider configurations (OIDC).",
    required_permissions=[
        "eks:ListIdentityProviderConfigs", "eks:DescribeIdentityProviderConfig", "eks:ListClusters"
    ],
    supported_services=["eks"],
    mitre_techniques=["T1087.004", "T1069.003"],
    tags=["eks", "enum", "identity-providers", "oidc", "safe"],
    requires_confirmation=False,
))

# ==================== PRIVESC MODULES ====================
register_module(ModuleMetadata(
    name="eks_privesc_analysis",
    category=ModuleCategory.PRIVESC,
    risk=ModuleRisk.SAFE,
    description="Analyze EKS for privilege escalation: node group role assumption, Fargate profile role abuse, and auth configmap modification.",
    required_permissions=[
        "eks:ListClusters", "eks:DescribeCluster", "eks:ListNodegroups",
        "eks:DescribeNodegroup", "eks:ListFargateProfiles", "eks:DescribeFargateProfile",
        "iam:GetRole", "iam:GetRolePolicy", "iam:ListAttachedRolePolicies"
    ],
    supported_services=["eks", "iam"],
    mitre_techniques=["T1087.004", "T1648.001", "T1078.004"],
    tags=["eks", "privesc", "kubernetes", "analysis", "safe"],
    requires_confirmation=False,
))

register_module(ModuleMetadata(
    name="eks_privesc_auth_configmap",
    category=ModuleCategory.PRIVESC,
    risk=ModuleRisk.SAFE,
    description="Analyze aws-auth ConfigMap for privilege escalation paths (mapRoles, mapUsers, mapAccounts).",
    required_permissions=[
        "eks:DescribeCluster", "eks:ListClusters"
    ],
    supported_services=["eks"],
    mitre_techniques=["T1069.003", "T1078.004"],
    tags=["eks", "privesc", "auth-configmap", "rbac", "safe"],
    requires_confirmation=False,
))

register_module(ModuleMetadata(
    name="eks_privesc_irsa_analysis",
    category=ModuleCategory.PRIVESC,
    risk=ModuleRisk.SAFE,
    description="Analyze IAM Roles for Service Accounts (IRSA) for privilege escalation via pod identity.",
    required_permissions=[
        "eks:ListClusters", "eks:DescribeCluster", "iam:ListRoles", "iam:GetRole",
        "iam:ListAttachedRolePolicies", "iam:GetRolePolicy"
    ],
    supported_services=["eks", "iam"],
    mitre_techniques=["T1069.003", "T1078.004", "T1526"],
    tags=["eks", "privesc", "irsa", "service-accounts", "safe"],
    requires_confirmation=False,
))

# ==================== EXPLOIT MODULES ====================
register_module(ModuleMetadata(
    name="eks_exploit_create_access_entry",
    category=ModuleCategory.EXPLOIT,
    risk=ModuleRisk.HIGH,
    description="Create EKS access entry for cluster access. DESTRUCTIVE - modifies cluster access.",
    required_permissions=["eks:CreateAccessEntry", "eks:DescribeAccessEntry", "eks:ListAccessEntries"],
    supported_services=["eks"],
    mitre_techniques=["T1078.004", "T1648.001"],
    tags=["eks", "exploit", "access-entry", "access", "destructive"],
    requires_confirmation=True,
    destructive=True,
))

register_module(ModuleMetadata(
    name="eks_exploit_update_cluster_config",
    category=ModuleCategory.EXPLOIT,
    risk=ModuleRisk.HIGH,
    description="Update EKS cluster config (endpoint access, logging, authentication mode). DESTRUCTIVE.",
    required_permissions=["eks:UpdateClusterConfig", "eks:DescribeCluster"],
    supported_services=["eks"],
    mitre_techniques=["T1098", "T1562.001"],
    tags=["eks", "exploit", "cluster-config", "destructive"],
    requires_confirmation=True,
    destructive=True,
))

register_module(ModuleMetadata(
    name="eks_exploit_create_nodegroup",
    category=ModuleCategory.EXPLOIT,
    risk=ModuleRisk.HIGH,
    description="Create managed node group with custom launch template for code execution. DESTRUCTIVE.",
    required_permissions=["eks:CreateNodegroup", "eks:DescribeNodegroup", "eks:ListNodegroups", "ec2:RunInstances", "iam:PassRole"],
    supported_services=["eks", "ec2", "iam"],
    mitre_techniques=["T1611", "T1059.004", "T1648.001"],
    tags=["eks", "exploit", "nodegroup", "compute", "destructive"],
    requires_confirmation=True,
    destructive=True,
))

register_module(ModuleMetadata(
    name="eks_exploit_create_fargate_profile",
    category=ModuleCategory.EXPLOIT,
    risk=ModuleRisk.HIGH,
    description="Create Fargate profile for serverless pod execution with custom role. DESTRUCTIVE.",
    required_permissions=["eks:CreateFargateProfile", "eks:DescribeFargateProfile", "eks:ListFargateProfiles", "iam:PassRole"],
    supported_services=["eks", "iam"],
    mitre_techniques=["T1611", "T1059.004", "T1648.001"],
    tags=["eks", "exploit", "fargate-profile", "serverless", "destructive"],
    requires_confirmation=True,
    destructive=True,
))

register_module(ModuleMetadata(
    name="eks_exploit_create_addon",
    category=ModuleCategory.EXPLOIT,
    risk=ModuleRisk.MEDIUM,
    description="Install EKS add-on (potentially malicious custom addon). DESTRUCTIVE.",
    required_permissions=["eks:CreateAddon", "eks:DescribeAddon", "eks:ListAddons"],
    supported_services=["eks"],
    mitre_techniques=["T1611", "T1505.003"],
    tags=["eks", "exploit", "addon", "destructive"],
    requires_confirmation=True,
    destructive=True,
))

register_module(ModuleMetadata(
    name="eks_exploit_associate_identity_provider",
    category=ModuleCategory.EXPLOIT,
    risk=ModuleRisk.HIGH,
    description="Associate OIDC identity provider for federated cluster access. DESTRUCTIVE.",
    required_permissions=["eks:AssociateIdentityProviderConfig", "eks:DescribeIdentityProviderConfig", "eks:ListIdentityProviderConfigs"],
    supported_services=["eks"],
    mitre_techniques=["T1078.004", "T1556.003", "T1648.001"],
    tags=["eks", "exploit", "oidc", "identity-provider", "federation", "destructive"],
    requires_confirmation=True,
    destructive=True,
))

register_module(ModuleMetadata(
    name="eks_exploit_update_access_entry",
    category=ModuleCategory.EXPLOIT,
    risk=ModuleRisk.HIGH,
    description="Update EKS access entry to grant elevated permissions. DESTRUCTIVE.",
    required_permissions=["eks:UpdateAccessEntry", "eks:DescribeAccessEntry", "eks:ListAccessEntries"],
    supported_services=["eks"],
    mitre_techniques=["T1098", "T1078.004", "T1648.001"],
    tags=["eks", "exploit", "access-entry", "rbac", "destructive"],
    requires_confirmation=True,
    destructive=True,
))

# ==================== EXFIL MODULES (PROWL parity) ====================
register_module(ModuleMetadata(
    name="eks_exfil_collect_tokens",
    category=ModuleCategory.EXFIL,
    risk=ModuleRisk.HIGH,
    description="Collect EKS service account tokens and kubeconfig for cluster access. PROWL: eks__collect_tokens. DESTRUCTIVE.",
    required_permissions=[
        "eks:DescribeCluster", "eks:ListClusters", "eks:ListNodegroups",
        "eks:DescribeNodegroup", "eks:ListFargateProfiles"
    ],
    supported_services=["eks"],
    mitre_techniques=["T1555.005", "T1530", "T1041", "T1648.001"],
    tags=["eks", "exfil", "tokens", "service-accounts", "kubeconfig", "awsprowl", "destructive"],
    requires_confirmation=True,
    destructive=True,
))

# List all EKS modules
EKS_MODULES = [
    # Enum
    "eks_enum_clusters", "eks_enum_addons", "eks_enum_identity_providers",
    # Privesc
    "eks_privesc_analysis", "eks_privesc_auth_configmap", "eks_privesc_irsa_analysis",
    # Exploit
    "eks_exploit_create_access_entry", "eks_exploit_update_cluster_config",
    "eks_exploit_create_nodegroup", "eks_exploit_create_fargate_profile",
    "eks_exploit_create_addon", "eks_exploit_associate_identity_provider",
    "eks_exploit_update_access_entry",
    # Exfil
    "eks_exfil_collect_tokens",
]

__all__ = ["EKS_MODULES"]

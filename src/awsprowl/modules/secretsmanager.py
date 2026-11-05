"""
Secrets Manager Service Modules - All Secrets Manager-related features across categories

This module provides a unified interface for all Secrets Manager operations:
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
    name="secretsmanager_enum_secrets",
    category=ModuleCategory.ENUM,
    risk=ModuleRisk.SAFE,
    description="Enumerate Secrets Manager secrets and rotation configurations.",
    required_permissions=[
        "secretsmanager:ListSecrets", "secretsmanager:DescribeSecret",
        "secretsmanager:GetResourcePolicy", "secretsmanager:ListSecretVersionIds"
    ],
    supported_services=["secretsmanager"],
    mitre_techniques=["T1555.005"],
    tags=["secretsmanager", "enum", "secrets", "safe"],
    requires_confirmation=False,
))

# ==================== PRIVESC MODULES ====================
# Secrets Manager privesc is typically covered by IAM privesc (policy attachment)

# ==================== EXPLOIT MODULES ====================
register_module(ModuleMetadata(
    name="secretsmanager_exploit_create_secret",
    category=ModuleCategory.EXPLOIT,
    risk=ModuleRisk.MEDIUM,
    description="Create secret for storing attacker-controlled credentials/payloads. DESTRUCTIVE.",
    required_permissions=["secretsmanager:CreateSecret", "secretsmanager:PutSecretValue", "secretsmanager:TagResource"],
    supported_services=["secretsmanager"],
    mitre_techniques=["T1555.005", "T1505.003"],
    tags=["secretsmanager", "exploit", "create-secret", "destructive"],
    requires_confirmation=True,
    destructive=True,
))

register_module(ModuleMetadata(
    name="secretsmanager_exploit_put_secret_value",
    category=ModuleCategory.EXPLOIT,
    risk=ModuleRisk.MEDIUM,
    description="Put new secret version with malicious payload. DESTRUCTIVE.",
    required_permissions=["secretsmanager:PutSecretValue", "secretsmanager:DescribeSecret"],
    supported_services=["secretsmanager"],
    mitre_techniques=["T1555.005", "T1505.003"],
    tags=["secretsmanager", "exploit", "put-secret-value", "destructive"],
    requires_confirmation=True,
    destructive=True,
))

register_module(ModuleMetadata(
    name="secretsmanager_exploit_update_secret",
    category=ModuleCategory.EXPLOIT,
    risk=ModuleRisk.MEDIUM,
    description="Update secret metadata (description, KMS key, rotation config). DESTRUCTIVE.",
    required_permissions=["secretsmanager:UpdateSecret", "secretsmanager:DescribeSecret", "secretsmanager:GetResourcePolicy"],
    supported_services=["secretsmanager"],
    mitre_techniques=["T1098", "T1555.005"],
    tags=["secretsmanager", "exploit", "update-secret", "destructive"],
    requires_confirmation=True,
    destructive=True,
))

register_module(ModuleMetadata(
    name="secretsmanager_exploit_rotate_secret",
    category=ModuleCategory.EXPLOIT,
    risk=ModuleRisk.HIGH,
    description="Trigger secret rotation with malicious Lambda function. DESTRUCTIVE.",
    required_permissions=["secretsmanager:RotateSecret", "secretsmanager:DescribeSecret", "lambda:InvokeFunction"],
    supported_services=["secretsmanager", "lambda"],
    mitre_techniques=["T1555.005", "T1059.004"],
    tags=["secretsmanager", "exploit", "rotate-secret", "lambda", "destructive"],
    requires_confirmation=True,
    destructive=True,
))

register_module(ModuleMetadata(
    name="secretsmanager_exploit_delete_secret",
    category=ModuleCategory.EXPLOIT,
    risk=ModuleRisk.HIGH,
    description="Delete secret to cause denial of service or remove evidence. DESTRUCTIVE.",
    required_permissions=["secretsmanager:DeleteSecret", "secretsmanager:DescribeSecret"],
    supported_services=["secretsmanager"],
    mitre_techniques=["T1485", "T1070.001"],
    tags=["secretsmanager", "exploit", "delete-secret", "destructive"],
    requires_confirmation=True,
    destructive=True,
))

# ==================== PERSIST MODULES ====================
register_module(ModuleMetadata(
    name="secretsmanager_persist_secret",
    category=ModuleCategory.PERSIST,
    risk=ModuleRisk.MEDIUM,
    description="Store credentials/tokens in Secrets Manager for persistent access.",
    required_permissions=["secretsmanager:CreateSecret", "secretsmanager:PutSecretValue", "secretsmanager:GetSecretValue", "secretsmanager:DescribeSecret"],
    supported_services=["secretsmanager"],
    mitre_techniques=["T1555.005", "T1505.003"],
    tags=["secretsmanager", "persist", "credentials", "storage"],
    requires_confirmation=True,
))

register_module(ModuleMetadata(
    name="secretsmanager_persist_rotation",
    category=ModuleCategory.PERSIST,
    risk=ModuleRisk.HIGH,
    description="Configure secret rotation with attacker-controlled Lambda for persistent credential access. DESTRUCTIVE.",
    required_permissions=["secretsmanager:RotateSecret", "secretsmanager:DescribeSecret", "lambda:CreateFunction", "lambda:AddPermission", "iam:PassRole"],
    supported_services=["secretsmanager", "lambda", "iam"],
    mitre_techniques=["T1555.005", "T1059.004", "T1505.003"],
    tags=["secretsmanager", "persist", "rotation", "lambda", "destructive"],
    requires_confirmation=True,
    destructive=True,
))

register_module(ModuleMetadata(
    name="secretsmanager_persist_resource_policy",
    category=ModuleCategory.PERSIST,
    risk=ModuleRisk.HIGH,
    description="Attach resource policy to secret for cross-account persistent access. DESTRUCTIVE.",
    required_permissions=["secretsmanager:PutResourcePolicy", "secretsmanager:GetResourcePolicy", "secretsmanager:DescribeSecret"],
    supported_services=["secretsmanager"],
    mitre_techniques=["T1098", "T1555.005"],
    tags=["secretsmanager", "persist", "resource-policy", "cross-account", "destructive"],
    requires_confirmation=True,
    destructive=True,
))

# ==================== BACKDOOR MODULES ====================
register_module(ModuleMetadata(
    name="secretsmanager_backdoor_rotation_lambda",
    category=ModuleCategory.BACKDOOR,
    risk=ModuleRisk.HIGH,
    description="Configure secret rotation with malicious Lambda for credential theft/backdoor. DESTRUCTIVE.",
    required_permissions=["secretsmanager:RotateSecret", "secretsmanager:DescribeSecret", "lambda:CreateFunction", "lambda:AddPermission", "iam:PassRole"],
    supported_services=["secretsmanager", "lambda", "iam"],
    mitre_techniques=["T1555.005", "T1059.004", "T1505.003"],
    tags=["secretsmanager", "backdoor", "rotation", "credential-theft", "covert", "destructive"],
    requires_confirmation=True,
    destructive=True,
))

register_module(ModuleMetadata(
    name="secretsmanager_backdoor_replication",
    category=ModuleCategory.BACKDOOR,
    risk=ModuleRisk.HIGH,
    description="Enable cross-region replication to attacker-controlled region for secret sync. DESTRUCTIVE.",
    required_permissions=["secretsmanager:ReplicateSecretToRegions", "secretsmanager:DescribeSecret", "secretsmanager:ListSecrets"],
    supported_services=["secretsmanager"],
    mitre_techniques=["T1020", "T1555.005", "T1505.003"],
    tags=["secretsmanager", "backdoor", "replication", "cross-region", "covert", "destructive"],
    requires_confirmation=True,
    destructive=True,
))

register_module(ModuleMetadata(
    name="secretsmanager_backdoor_version_staging",
    category=ModuleCategory.BACKDOOR,
    risk=ModuleRisk.MEDIUM,
    description="Use secret version staging labels (AWSCURRENT, AWSPREVIOUS) for covert payload storage.",
    required_permissions=["secretsmanager:PutSecretValue", "secretsmanager:GetSecretValue", "secretsmanager:DescribeSecret", "secretsmanager:ListSecretVersionIds"],
    supported_services=["secretsmanager"],
    mitre_techniques=["T1555.005", "T1027", "T1505.003"],
    tags=["secretsmanager", "backdoor", "version-staging", "covert"],
    requires_confirmation=True,
))

# ==================== EXFIL MODULES ====================
register_module(ModuleMetadata(
    name="secretsmanager_exfil_secrets",
    category=ModuleCategory.EXFIL,
    risk=ModuleRisk.CRITICAL,
    description="Extract secret values from Secrets Manager. CRITICAL - credential theft.",
    required_permissions=["secretsmanager:GetSecretValue", "secretsmanager:DescribeSecret", "secretsmanager:ListSecrets", "secretsmanager:ListSecretVersionIds"],
    supported_services=["secretsmanager"],
    mitre_techniques=["T1555.005", "T1530", "T1041"],
    tags=["secretsmanager", "exfil", "secrets", "credentials", "destructive"],
    requires_confirmation=True,
    destructive=True,
))

register_module(ModuleMetadata(
    name="secretsmanager_exfil_metadata",
    category=ModuleCategory.EXFIL,
    risk=ModuleRisk.MEDIUM,
    description="Extract secret metadata (names, tags, rotation config, policies) for reconnaissance.",
    required_permissions=["secretsmanager:ListSecrets", "secretsmanager:DescribeSecret", "secretsmanager:GetResourcePolicy", "secretsmanager:ListSecretVersionIds"],
    supported_services=["secretsmanager"],
    mitre_techniques=["T1530", "T1020", "T1526"],
    tags=["secretsmanager", "exfil", "metadata", "reconnaissance"],
    requires_confirmation=True,
))

register_module(ModuleMetadata(
    name="secretsmanager_exfil_policy",
    category=ModuleCategory.EXFIL,
    risk=ModuleRisk.MEDIUM,
    description="Extract resource policies from secrets for cross-account access analysis.",
    required_permissions=["secretsmanager:GetResourcePolicy", "secretsmanager:ListSecrets", "secretsmanager:DescribeSecret"],
    supported_services=["secretsmanager"],
    mitre_techniques=["T1530", "T1526", "T1020"],
    tags=["secretsmanager", "exfil", "policy", "cross-account"],
    requires_confirmation=True,
))

# List all Secrets Manager modules
SECRETSMANAGER_MODULES = [
    # Enum
    "secretsmanager_enum_secrets",
    # Privesc - covered by iam_privesc
    # Exploit
    "secretsmanager_exploit_create_secret", "secretsmanager_exploit_put_secret_value",
    "secretsmanager_exploit_update_secret", "secretsmanager_exploit_rotate_secret",
    "secretsmanager_exploit_delete_secret",
    # Persist
    "secretsmanager_persist_secret", "secretsmanager_persist_rotation",
    "secretsmanager_persist_resource_policy",
    # Backdoor
    "secretsmanager_backdoor_rotation_lambda", "secretsmanager_backdoor_replication",
    "secretsmanager_backdoor_version_staging",
    # Exfil
    "secretsmanager_exfil_secrets", "secretsmanager_exfil_metadata",
    "secretsmanager_exfil_policy",
]

__all__ = ["SECRETSMANAGER_MODULES"]

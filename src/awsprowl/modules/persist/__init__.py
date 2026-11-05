"""
Persistence Modules - Long-term Access Maintenance

These modules create or modify AWS resources to maintain persistent access.
They require explicit authorization and confirmation before running.
"""

from awsprowl.modules import ModuleCategory, ModuleMetadata, ModuleRisk, register_module

# Register persist modules
register_module(ModuleMetadata(
    name="iam__persist_create_user",
    category=ModuleCategory.PERSIST,
    risk=ModuleRisk.HIGH,
    description="Create IAM user with programmatic access for long-term persistence. DESTRUCTIVE - creates permanent user.",
    required_permissions=["iam:CreateUser", "iam:CreateAccessKey", "iam:AttachUserPolicy", "iam:PutUserPolicy"],
    supported_services=["iam"],
    mitre_techniques=["T1136.003", "T1078.004", "T1556.003"],
    tags=["persist", "iam", "user", "credential-access", "destructive"],
    requires_confirmation=True,
    destructive=True,
))

register_module(ModuleMetadata(
    name="iam__persist_create_role",
    category=ModuleCategory.PERSIST,
    risk=ModuleRisk.HIGH,
    description="Create IAM role with trust policy for cross-account or service assumption. DESTRUCTIVE.",
    required_permissions=["iam:CreateRole", "iam:AttachRolePolicy", "iam:PutRolePolicy", "iam:UpdateAssumeRolePolicy"],
    supported_services=["iam"],
    mitre_techniques=["T1098", "T1078.004", "T1556.003"],
    tags=["persist", "iam", "role", "cross-account", "destructive"],
    requires_confirmation=True,
    destructive=True,
))

register_module(ModuleMetadata(
    name="iam__persist_create_access_key",
    category=ModuleCategory.PERSIST,
    risk=ModuleRisk.HIGH,
    description="Create access keys for existing users/roles for credential persistence. DESTRUCTIVE.",
    required_permissions=["iam:CreateAccessKey", "iam:ListAccessKeys"],
    supported_services=["iam"],
    mitre_techniques=["T1555.005", "T1078.004"],
    tags=["persist", "iam", "credentials", "destructive"],
    requires_confirmation=True,
    destructive=True,
))

register_module(ModuleMetadata(
    name="iam__persist_create_login_profile",
    category=ModuleCategory.PERSIST,
    risk=ModuleRisk.HIGH,
    description="Create console login profile for IAM user. DESTRUCTIVE.",
    required_permissions=["iam:CreateLoginProfile", "iam:UpdateLoginProfile", "iam:GetLoginProfile"],
    supported_services=["iam"],
    mitre_techniques=["T1136.003", "T1078.004"],
    tags=["persist", "iam", "console", "destructive"],
    requires_confirmation=True,
    destructive=True,
))

register_module(ModuleMetadata(
    name="iam__persist_attach_admin_policy",
    category=ModuleCategory.PERSIST,
    risk=ModuleRisk.CRITICAL,
    description="Attach AdministratorAccess or equivalent policy to user/role. CRITICAL - full admin access.",
    required_permissions=["iam:AttachUserPolicy", "iam:AttachRolePolicy", "iam:AttachGroupPolicy", "iam:PutUserPolicy", "iam:PutRolePolicy", "iam:PutGroupPolicy"],
    supported_services=["iam"],
    mitre_techniques=["T1098", "T1078.004"],
    tags=["persist", "iam", "admin", "privilege-escalation", "destructive"],
    requires_confirmation=True,
    destructive=True,
))

register_module(ModuleMetadata(
    name="iam__persist_update_assume_role_policy",
    category=ModuleCategory.PERSIST,
    risk=ModuleRisk.CRITICAL,
    description="Modify role trust policy to allow persistent external assumption. CRITICAL.",
    required_permissions=["iam:UpdateAssumeRolePolicy", "iam:GetRole"],
    supported_services=["iam"],
    mitre_techniques=["T1098", "T1078.004", "T1556.003"],
    tags=["persist", "iam", "trust-policy", "cross-account", "destructive"],
    requires_confirmation=True,
    destructive=True,
))

register_module(ModuleMetadata(
    name="iam__persist_create_policy_version",
    category=ModuleCategory.PERSIST,
    risk=ModuleRisk.HIGH,
    description="Create new policy version with elevated permissions and set as default. DESTRUCTIVE.",
    required_permissions=["iam:CreatePolicyVersion", "iam:SetDefaultPolicyVersion", "iam:GetPolicy", "iam:ListPolicyVersions"],
    supported_services=["iam"],
    mitre_techniques=["T1098", "T1078.004"],
    tags=["persist", "iam", "policy", "privilege-escalation", "destructive"],
    requires_confirmation=True,
    destructive=True,
))

register_module(ModuleMetadata(
    name="iam__persist_add_user_to_group",
    category=ModuleCategory.PERSIST,
    risk=ModuleRisk.MEDIUM,
    description="Add user to group with elevated permissions for persistence.",
    required_permissions=["iam:AddUserToGroup", "iam:GetGroup", "iam:ListGroupsForUser"],
    supported_services=["iam"],
    mitre_techniques=["T1098", "T1078.004"],
    tags=["persist", "iam", "group"],
    requires_confirmation=True,
))

register_module(ModuleMetadata(
    name="iam__persist_create_service_linked_role",
    category=ModuleCategory.PERSIST,
    risk=ModuleRisk.MEDIUM,
    description="Create service-linked role for service-specific persistence. DESTRUCTIVE.",
    required_permissions=["iam:CreateServiceLinkedRole", "iam:GetServiceLinkedRoleDeletionStatus"],
    supported_services=["iam"],
    mitre_techniques=["T1098", "T1078.004"],
    tags=["persist", "iam", "service-linked-role", "destructive"],
    requires_confirmation=True,
    destructive=True,
))

register_module(ModuleMetadata(
    name="lambda__persist_backdoor_function",
    category=ModuleCategory.PERSIST,
    risk=ModuleRisk.CRITICAL,
    description="Create or modify Lambda function as persistent backdoor with function URL. CRITICAL - persistent code execution.",
    required_permissions=["lambda:CreateFunction", "lambda:UpdateFunctionCode", "lambda:CreateFunctionUrlConfig", "lambda:AddPermission", "iam:PassRole"],
    supported_services=["lambda", "iam"],
    mitre_techniques=["T1059.004", "T1505.003", "T1648.002", "T1190"],
    tags=["persist", "lambda", "backdoor", "function-url", "code-execution", "destructive"],
    requires_confirmation=True,
    destructive=True,
))

register_module(ModuleMetadata(
    name="lambda__persist_alias",
    category=ModuleCategory.PERSIST,
    risk=ModuleRisk.MEDIUM,
    description="Create Lambda alias pointing to malicious version for persistent invocation.",
    required_permissions=["lambda:CreateAlias", "lambda:UpdateAlias", "lambda:ListAliases", "lambda:GetFunction"],
    supported_services=["lambda"],
    mitre_techniques=["T1059.004", "T1505.003"],
    tags=["persist", "lambda", "alias"],
    requires_confirmation=True,
))

register_module(ModuleMetadata(
    name="lambda__persist_layer",
    category=ModuleCategory.PERSIST,
    risk=ModuleRisk.HIGH,
    description="Publish Lambda layer with malicious code for supply chain persistence. DESTRUCTIVE.",
    required_permissions=["lambda:PublishLayerVersion", "lambda:AddLayerVersionPermission", "lambda:ListLayerVersions"],
    supported_services=["lambda"],
    mitre_techniques=["T1059.004", "T1505.003", "T1195.002"],
    tags=["persist", "lambda", "layer", "supply-chain", "destructive"],
    requires_confirmation=True,
    destructive=True,
))

register_module(ModuleMetadata(
    name="ec2__persist_user_data",
    category=ModuleCategory.PERSIST,
    risk=ModuleRisk.HIGH,
    description="Modify instance user data for persistent code execution on reboot. DESTRUCTIVE.",
    required_permissions=["ec2:ModifyInstanceAttribute", "ec2:DescribeInstances", "ec2:StopInstances", "ec2:StartInstances"],
    supported_services=["ec2"],
    mitre_techniques=["T1059.004", "T1505.003", "T1556.002"],
    tags=["persist", "ec2", "user-data", "reboot-persistence", "destructive"],
    requires_confirmation=True,
    destructive=True,
))

register_module(ModuleMetadata(
    name="ec2__persist_launch_template",
    category=ModuleCategory.PERSIST,
    risk=ModuleRisk.HIGH,
    description="Create launch template with user data for persistent instance deployment. DESTRUCTIVE.",
    required_permissions=["ec2:CreateLaunchTemplate", "ec2:CreateLaunchTemplateVersion", "ec2:DescribeLaunchTemplates", "iam:PassRole"],
    supported_services=["ec2", "iam"],
    mitre_techniques=["T1059.004", "T1505.003", "T1611"],
    tags=["persist", "ec2", "launch-template", "destructive"],
    requires_confirmation=True,
    destructive=True,
))

register_module(ModuleMetadata(
    name="ec2__persist_ami",
    category=ModuleCategory.PERSIST,
    risk=ModuleRisk.HIGH,
    description="Create custom AMI with backdoored software for persistent deployment. DESTRUCTIVE.",
    required_permissions=["ec2:CreateImage", "ec2:DescribeImages", "ec2:RegisterImage", "ec2:DescribeInstances"],
    supported_services=["ec2"],
    mitre_techniques=["T1059.004", "T1505.003", "T1611"],
    tags=["persist", "ec2", "ami", "golden-image", "destructive"],
    requires_confirmation=True,
    destructive=True,
))

register_module(ModuleMetadata(
    name="ec2__persist_security_group",
    category=ModuleCategory.PERSIST,
    risk=ModuleRisk.MEDIUM,
    description="Create/modify security group for persistent network access. DESTRUCTIVE.",
    required_permissions=["ec2:CreateSecurityGroup", "ec2:AuthorizeSecurityGroupIngress", "ec2:AuthorizeSecurityGroupEgress", "ec2:DescribeSecurityGroups", "ec2:DescribeVpcs"],
    supported_services=["ec2"],
    mitre_techniques=["T1046", "T1562.007"],
    tags=["persist", "ec2", "security-group", "network", "destructive"],
    requires_confirmation=True,
    destructive=True,
))

register_module(ModuleMetadata(
    name="ec2__persist_key_pair",
    category=ModuleCategory.PERSIST,
    risk=ModuleRisk.HIGH,
    description="Create/import key pair for persistent SSH access. DESTRUCTIVE.",
    required_permissions=["ec2:CreateKeyPair", "ec2:ImportKeyPair", "ec2:DescribeKeyPairs"],
    supported_services=["ec2"],
    mitre_techniques=["T1078.004", "T1556.002"],
    tags=["persist", "ec2", "key-pair", "ssh", "destructive"],
    requires_confirmation=True,
    destructive=True,
))

register_module(ModuleMetadata(
    name="ec2__persist_instance_profile",
    category=ModuleCategory.PERSIST,
    risk=ModuleRisk.HIGH,
    description="Associate IAM instance profile with instance for persistent role assumption. DESTRUCTIVE.",
    required_permissions=["ec2:AssociateIamInstanceProfile", "ec2:DescribeIamInstanceProfileAssociations", "ec2:DescribeInstances", "iam:PassRole"],
    supported_services=["ec2", "iam"],
    mitre_techniques=["T1078.004", "T1556.002"],
    tags=["persist", "ec2", "instance-profile", "destructive"],
    requires_confirmation=True,
    destructive=True,
))

register_module(ModuleMetadata(
    name="s3__persist_bucket_policy",
    category=ModuleCategory.PERSIST,
    risk=ModuleRisk.HIGH,
    description="Put bucket policy for persistent cross-account or public access. DESTRUCTIVE.",
    required_permissions=["s3:PutBucketPolicy", "s3:GetBucketPolicy", "s3:GetBucketLocation"],
    supported_services=["s3"],
    mitre_techniques=["T1098", "T1530"],
    tags=["persist", "s3", "bucket-policy", "data-access", "destructive"],
    requires_confirmation=True,
    destructive=True,
))

register_module(ModuleMetadata(
    name="s3__persist_bucket_acl",
    category=ModuleCategory.PERSIST,
    risk=ModuleRisk.HIGH,
    description="Put bucket ACL for persistent public read/write access. DESTRUCTIVE.",
    required_permissions=["s3:PutBucketAcl", "s3:GetBucketAcl", "s3:GetBucketLocation"],
    supported_services=["s3"],
    mitre_techniques=["T1098", "T1530"],
    tags=["persist", "s3", "acl", "data-access", "destructive"],
    requires_confirmation=True,
    destructive=True,
))

register_module(ModuleMetadata(
    name="s3__persist_replication",
    category=ModuleCategory.PERSIST,
    risk=ModuleRisk.HIGH,
    description="Configure cross-region replication for persistent data exfiltration. DESTRUCTIVE.",
    required_permissions=["s3:PutBucketReplication", "s3:GetBucketReplication", "iam:PassRole"],
    supported_services=["s3", "iam"],
    mitre_techniques=["T1020", "T1530"],
    tags=["persist", "s3", "replication", "exfiltration", "destructive"],
    requires_confirmation=True,
    destructive=True,
))

register_module(ModuleMetadata(
    name="s3__persist_object_versioning",
    category=ModuleCategory.PERSIST,
    risk=ModuleRisk.MEDIUM,
    description="Enable versioning and MFA delete for persistent object retention.",
    required_permissions=["s3:PutBucketVersioning", "s3:GetBucketVersioning", "s3:PutBucketLifecycleConfiguration"],
    supported_services=["s3"],
    mitre_techniques=["T1485", "T1565"],
    tags=["persist", "s3", "versioning", "data-retention"],
    requires_confirmation=True,
))

register_module(ModuleMetadata(
    name="s3__persist_lifecycle",
    category=ModuleCategory.PERSIST,
    risk=ModuleRisk.MEDIUM,
    description="Configure lifecycle to prevent object deletion for persistence.",
    required_permissions=["s3:PutBucketLifecycleConfiguration", "s3:GetBucketLifecycleConfiguration"],
    supported_services=["s3"],
    mitre_techniques=["T1485", "T1565"],
    tags=["persist", "s3", "lifecycle", "data-retention"],
    requires_confirmation=True,
))

register_module(ModuleMetadata(
    name="cloudformation__persist_stack",
    category=ModuleCategory.PERSIST,
    risk=ModuleRisk.CRITICAL,
    description="Deploy CloudFormation stack with persistent resources (IAM, Lambda, EC2). CRITICAL.",
    required_permissions=["cloudformation:CreateStack", "cloudformation:UpdateStack", "cloudformation:DescribeStacks", "iam:PassRole"],
    supported_services=["cloudformation", "iam"],
    mitre_techniques=["T1611", "T1059.004", "T1505.003"],
    tags=["persist", "cloudformation", "stack", "infrastructure", "destructive"],
    requires_confirmation=True,
    destructive=True,
))

register_module(ModuleMetadata(
    name="cloudformation__persist_stack_set",
    category=ModuleCategory.PERSIST,
    risk=ModuleRisk.CRITICAL,
    description="Deploy StackSet for cross-account/region persistent infrastructure. CRITICAL.",
    required_permissions=["cloudformation:CreateStackSet", "cloudformation:CreateStackInstances", "cloudformation:DescribeStackSet", "iam:PassRole"],
    supported_services=["cloudformation", "iam"],
    mitre_techniques=["T1611", "T1059.004", "T1505.003"],
    tags=["persist", "cloudformation", "stackset", "cross-account", "destructive"],
    requires_confirmation=True,
    destructive=True,
))

register_module(ModuleMetadata(
    name="cloudtrail__persist_stop_logging",
    category=ModuleCategory.PERSIST,
    risk=ModuleRisk.HIGH,
    description="Stop CloudTrail logging to hide persistence activities. DESTRUCTIVE - impairs detection.",
    required_permissions=["cloudtrail:StopLogging", "cloudtrail:DescribeTrails", "cloudtrail:GetTrailStatus"],
    supported_services=["cloudtrail"],
    mitre_techniques=["T1562.008", "T1562.001"],
    tags=["persist", "cloudtrail", "defense-evasion", "logging", "destructive"],
    requires_confirmation=True,
    destructive=True,
))

register_module(ModuleMetadata(
    name="cloudtrail__persist_delete_trail",
    category=ModuleCategory.PERSIST,
    risk=ModuleRisk.CRITICAL,
    description="Delete CloudTrail trail to permanently remove logging. CRITICAL - destroys audit trail.",
    required_permissions=["cloudtrail:DeleteTrail", "cloudtrail:DescribeTrails"],
    supported_services=["cloudtrail"],
    mitre_techniques=["T1562.008", "T1562.001", "T1070.001"],
    tags=["persist", "cloudtrail", "defense-evasion", "destructive"],
    requires_confirmation=True,
    destructive=True,
))

register_module(ModuleMetadata(
    name="config__persist_stop_recorder",
    category=ModuleCategory.PERSIST,
    risk=ModuleRisk.HIGH,
    description="Stop AWS Config recorder to hide resource changes. DESTRUCTIVE.",
    required_permissions=["config:StopConfigurationRecorder", "config:DescribeConfigurationRecorders", "config:DescribeConfigurationRecorderStatus"],
    supported_services=["config"],
    mitre_techniques=["T1562.008", "T1562.001"],
    tags=["persist", "config", "defense-evasion", "destructive"],
    requires_confirmation=True,
    destructive=True,
))

register_module(ModuleMetadata(
    name="guardduty__persist_delete_detector",
    category=ModuleCategory.PERSIST,
    risk=ModuleRisk.CRITICAL,
    description="Delete GuardDuty detector to disable threat detection. CRITICAL - destroys security monitoring.",
    required_permissions=["guardduty:DeleteDetector", "guardduty:ListDetectors", "guardduty:GetDetector"],
    supported_services=["guardduty"],
    mitre_techniques=["T1562.001", "T1562.008"],
    tags=["persist", "guardduty", "defense-evasion", "threat-detection", "destructive"],
    requires_confirmation=True,
    destructive=True,
))

register_module(ModuleMetadata(
    name="securityhub__persist_disable",
    category=ModuleCategory.PERSIST,
    risk=ModuleRisk.HIGH,
    description="Disable Security Hub to reduce security visibility. DESTRUCTIVE.",
    required_permissions=["securityhub:DisableSecurityHub", "securityhub:DescribeHub"],
    supported_services=["securityhub"],
    mitre_techniques=["T1562.001", "T1562.008"],
    tags=["persist", "securityhub", "defense-evasion", "destructive"],
    requires_confirmation=True,
    destructive=True,
))

register_module(ModuleMetadata(
    name="ssm__persist_parameter",
    category=ModuleCategory.PERSIST,
    risk=ModuleRisk.MEDIUM,
    description="Store persistent payload/commands in SSM Parameter Store (SecureString).",
    required_permissions=["ssm:PutParameter", "ssm:GetParameter", "ssm:DeleteParameter", "ssm:DescribeParameters"],
    supported_services=["ssm"],
    mitre_techniques=["T1505.003", "T1555.003"],
    tags=["persist", "ssm", "parameter-store", "credential-storage"],
    requires_confirmation=True,
))

register_module(ModuleMetadata(
    name="ssm__persist_document",
    category=ModuleCategory.PERSIST,
    risk=ModuleRisk.HIGH,
    description="Create SSM Document with malicious commands for persistent automation. DESTRUCTIVE.",
    required_permissions=["ssm:CreateDocument", "ssm:UpdateDocument", "ssm:GetDocument", "ssm:ListDocuments"],
    supported_services=["ssm"],
    mitre_techniques=["T1059.004", "T1505.003", "T1611"],
    tags=["persist", "ssm", "document", "automation", "destructive"],
    requires_confirmation=True,
    destructive=True,
))

register_module(ModuleMetadata(
    name="events__persist_rule",
    category=ModuleCategory.PERSIST,
    risk=ModuleRisk.HIGH,
    description="Create EventBridge rule to trigger Lambda/SSM on schedule for persistence. DESTRUCTIVE.",
    required_permissions=["events:PutRule", "events:PutTargets", "events:DescribeRule", "events:ListRules", "lambda:AddPermission", "ssm:StartAutomationExecution"],
    supported_services=["events", "lambda", "ssm"],
    mitre_techniques=["T1059.004", "T1505.003", "T1611"],
    tags=["persist", "events", "eventbridge", "scheduled", "destructive"],
    requires_confirmation=True,
    destructive=True,
))

register_module(ModuleMetadata(
    name="secretsmanager__persist_secret",
    category=ModuleCategory.PERSIST,
    risk=ModuleRisk.MEDIUM,
    description="Store credentials/tokens in Secrets Manager for persistent access.",
    required_permissions=["secretsmanager:CreateSecret", "secretsmanager:PutSecretValue", "secretsmanager:GetSecretValue", "secretsmanager:DescribeSecret"],
    supported_services=["secretsmanager"],
    mitre_techniques=["T1555.005", "T1505.003"],
    tags=["persist", "secretsmanager", "credentials", "storage"],
    requires_confirmation=True,
))

# List all persist modules
PERSIST_MODULES = [
    "iam__persist_create_user", "iam__persist_create_role", "iam__persist_create_access_key",
    "iam__persist_create_login_profile", "iam__persist_attach_admin_policy", "iam__persist_update_assume_role_policy",
    "iam__persist_create_policy_version", "iam__persist_add_user_to_group", "iam__persist_create_service_linked_role",
    "lambda__persist_backdoor_function", "lambda__persist_alias", "lambda__persist_layer",
    "ec2__persist_user_data", "ec2__persist_launch_template", "ec2__persist_ami",
    "ec2__persist_security_group", "ec2__persist_key_pair", "ec2__persist_instance_profile",
    "s3__persist_bucket_policy", "s3__persist_bucket_acl", "s3__persist_replication",
    "s3__persist_object_versioning", "s3__persist_lifecycle",
    "cloudformation__persist_stack", "cloudformation__persist_stack_set",
    "cloudtrail__persist_stop_logging", "cloudtrail__persist_delete_trail",
    "config__persist_stop_recorder",
    "guardduty__persist_delete_detector",
    "securityhub__persist_disable",
    "ssm__persist_parameter", "ssm__persist_document",
    "events__persist_rule",
    "secretsmanager__persist_secret",
]

__all__ = ["PERSIST_MODULES"]

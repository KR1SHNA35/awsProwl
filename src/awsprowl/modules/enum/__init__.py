"""
Enumeration Modules - Read-only scanning (SAFE)

These modules perform only read operations and never modify AWS resources.
They can be run safely without special authorization beyond read permissions.
"""

from awsprowl.modules import ModuleCategory, ModuleMetadata, ModuleRisk, register_module

# Register all enumeration modules
register_module(ModuleMetadata(
    name="iam__enum",
    category=ModuleCategory.ENUM,
    risk=ModuleRisk.SAFE,
    description="Enumerate IAM users, roles, policies, groups, and permissions boundaries. Includes account authorization details, service-specific credentials, SSH keys, signing certificates, login profiles, and organization accounts.",
    required_permissions=[
        "iam:ListUsers", "iam:ListRoles", "iam:ListPolicies", "iam:ListGroups",
        "iam:GetUser", "iam:GetRole", "iam:GetPolicy", "iam:GetPolicyVersion",
        "iam:ListAttachedUserPolicies", "iam:ListUserPolicies", "iam:ListAttachedRolePolicies",
        "iam:ListRolePolicies", "iam:ListGroupsForUser", "iam:ListAttachedGroupPolicies",
        "iam:ListGroupPolicies", "iam:SimulatePrincipalPolicy",
        "iam:GetAccountAuthorizationDetails", "iam:ListServiceSpecificCredentials",
        "iam:ListSSHPublicKeys", "iam:ListSigningCertificates", "iam:GetLoginProfile",
        "iam:GetAccountPasswordPolicy", "iam:GetAccountSummary", "iam:ListAccountAliases",
        "organizations:ListAccounts", "organizations:ListRoots", "organizations:ListOrganizationalUnitsForParent"
    ],
    supported_services=["iam", "organizations"],
    mitre_techniques=["T1069.003", "T1087.004", "T1526"],
    tags=["enumeration", "iam", "identity", "safe"],
))

register_module(ModuleMetadata(
    name="s3__enum",
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
    tags=["enumeration", "s3", "storage", "safe"],
))

register_module(ModuleMetadata(
    name="lambda__enum",
    category=ModuleCategory.ENUM,
    risk=ModuleRisk.SAFE,
    description="Enumerate Lambda functions, layers, function URLs, aliases, versions, event source mappings, code signing configs, and account concurrency. Detects deprecated runtimes, public function URLs, secrets in env vars, VPC config, and excessive permissions.",
    required_permissions=[
        "lambda:ListFunctions", "lambda:GetFunction", "lambda:GetFunctionConfiguration",
        "lambda:GetPolicy", "lambda:GetFunctionUrlConfig", "lambda:ListFunctionUrlConfigs",
        "lambda:ListAliases", "lambda:ListVersionsByFunction", "lambda:ListEventSourceMappings",
        "lambda:GetEventSourceMapping", "lambda:ListLayers", "lambda:ListLayerVersions",
        "lambda:GetLayerVersion", "lambda:GetLayerVersionPolicy",
        "lambda:ListCodeSigningConfigs", "lambda:GetCodeSigningConfig",
        "lambda:GetFunctionConcurrency", "lambda:GetAccountConcurrency",
        "iam:GetRole", "iam:GetRolePolicy", "iam:ListAttachedRolePolicies"
    ],
    supported_services=["lambda", "iam"],
    mitre_techniques=["T1087.004", "T1648.002"],
    tags=["enumeration", "lambda", "serverless", "safe"],
))

register_module(ModuleMetadata(
    name="ec2__enum",
    category=ModuleCategory.ENUM,
    risk=ModuleRisk.SAFE,
    description="Enumerate EC2 resources: instances, security groups, VPCs, subnets, volumes, snapshots, AMIs, key pairs, EIPs, NACLs, NAT gateways, route tables, internet gateways, VPC endpoints, launch templates, instance connect endpoints, placement groups, dedicated hosts, capacity reservations, network interfaces, transit gateways, VPC peering, VPN connections, and customer gateways.",
    required_permissions=[
        "ec2:DescribeInstances", "ec2:DescribeSecurityGroups", "ec2:DescribeVpcs",
        "ec2:DescribeSubnets", "ec2:DescribeVolumes", "ec2:DescribeSnapshots",
        "ec2:DescribeImages", "ec2:DescribeKeyPairs", "ec2:DescribeNetworkInterfaces",
        "ec2:DescribeAddresses", "ec2:DescribeInstanceAttribute", "ec2:DescribeNetworkAcls",
        "ec2:DescribeRouteTables", "ec2:DescribeInternetGateways", "ec2:DescribeNatGateways",
        "ec2:DescribeVpcEndpoints", "ec2:DescribeVpcEndpointServices",
        "ec2:DescribeLaunchTemplates", "ec2:DescribeLaunchTemplateVersions",
        "ec2:DescribeInstanceConnectEndpoints", "ec2:DescribePlacementGroups",
        "ec2:DescribeHosts", "ec2:DescribeCapacityReservations",
        "ec2:DescribeTransitGateways", "ec2:DescribeTransitGatewayAttachments",
        "ec2:DescribeTransitGatewayRouteTables", "ec2:DescribeVpcPeeringConnections",
        "ec2:DescribeVpnConnections", "ec2:DescribeCustomerGateways", "ec2:DescribeFlowLogs",
        "iam:GetInstanceProfile", "iam:GetRole", "iam:GetRolePolicy",
        "iam:ListRolePolicies", "iam:ListAttachedRolePolicies", "iam:GetPolicy", "iam:GetPolicyVersion"
    ],
    supported_services=["ec2", "iam"],
    mitre_techniques=["T1087.004", "T1046", "T1526"],
    tags=["enumeration", "ec2", "compute", "network", "safe"],
))

register_module(ModuleMetadata(
    name="sts__enum",
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
    tags=["enumeration", "sts", "identity", "federation", "safe"],
))

register_module(ModuleMetadata(
    name="rds__enum",
    category=ModuleCategory.ENUM,
    risk=ModuleRisk.SAFE,
    description="Enumerate RDS instances, clusters, snapshots, parameter groups, and security groups.",
    required_permissions=[
        "rds:DescribeDBInstances", "rds:DescribeDBClusters", "rds:DescribeDBSnapshots",
        "rds:DescribeDBClusterSnapshots", "rds:DescribeDBParameterGroups",
        "rds:DescribeDBClusterParameterGroups", "rds:DescribeDBSecurityGroups"
    ],
    supported_services=["rds"],
    mitre_techniques=["T1083", "T1526"],
    tags=["enumeration", "rds", "database", "safe"],
))

register_module(ModuleMetadata(
    name="dynamodb__enum",
    category=ModuleCategory.ENUM,
    risk=ModuleRisk.SAFE,
    description="Enumerate DynamoDB tables, backups, and global tables.",
    required_permissions=[
        "dynamodb:ListTables", "dynamodb:DescribeTable", "dynamodb:ListBackups",
        "dynamodb:DescribeBackup", "dynamodb:ListGlobalTables"
    ],
    supported_services=["dynamodb"],
    mitre_techniques=["T1083", "T1526"],
    tags=["enumeration", "dynamodb", "database", "safe"],
))

register_module(ModuleMetadata(
    name="ecs__enum",
    category=ModuleCategory.ENUM,
    risk=ModuleRisk.SAFE,
    description="Enumerate ECS clusters, services, task definitions, and container instances.",
    required_permissions=[
        "ecs:ListClusters", "ecs:DescribeClusters", "ecs:ListServices", "ecs:DescribeServices",
        "ecs:ListTaskDefinitions", "ecs:DescribeTaskDefinition", "ecs:ListContainerInstances",
        "ecs:DescribeContainerInstances"
    ],
    supported_services=["ecs"],
    mitre_techniques=["T1087.004", "T1648.001"],
    tags=["enumeration", "ecs", "containers", "safe"],
))

register_module(ModuleMetadata(
    name="eks__enum",
    category=ModuleCategory.ENUM,
    risk=ModuleRisk.SAFE,
    description="Enumerate EKS clusters, node groups, and Fargate profiles.",
    required_permissions=[
        "eks:ListClusters", "eks:DescribeCluster", "eks:ListNodegroups", "eks:DescribeNodegroup",
        "eks:ListFargateProfiles", "eks:DescribeFargateProfile"
    ],
    supported_services=["eks"],
    mitre_techniques=["T1087.004", "T1648.001"],
    tags=["enumeration", "eks", "kubernetes", "safe"],
))

register_module(ModuleMetadata(
    name="secretsmanager__enum",
    category=ModuleCategory.ENUM,
    risk=ModuleRisk.SAFE,
    description="Enumerate Secrets Manager secrets and rotation configurations.",
    required_permissions=[
        "secretsmanager:ListSecrets", "secretsmanager:DescribeSecret",
        "secretsmanager:GetResourcePolicy", "secretsmanager:ListSecretVersionIds"
    ],
    supported_services=["secretsmanager"],
    mitre_techniques=["T1555.005"],
    tags=["enumeration", "secrets", "safe"],
))

register_module(ModuleMetadata(
    name="sns__enum",
    category=ModuleCategory.ENUM,
    risk=ModuleRisk.SAFE,
    description="Enumerate SNS topics, subscriptions, and platform applications.",
    required_permissions=[
        "sns:ListTopics", "sns:GetTopicAttributes", "sns:ListSubscriptions",
        "sns:ListSubscriptionsByTopic", "sns:ListPlatformApplications"
    ],
    supported_services=["sns"],
    mitre_techniques=["T1083"],
    tags=["enumeration", "sns", "messaging", "safe"],
))

register_module(ModuleMetadata(
    name="cloudfront__enum",
    category=ModuleCategory.ENUM,
    risk=ModuleRisk.SAFE,
    description="Enumerate CloudFront distributions, origin access identities, and key groups.",
    required_permissions=[
        "cloudfront:ListDistributions", "cloudfront:GetDistribution", "cloudfront:GetDistributionConfig",
        "cloudfront:ListOriginAccessControls", "cloudfront:GetOriginAccessControl"
    ],
    supported_services=["cloudfront"],
    mitre_techniques=["T1083"],
    tags=["enumeration", "cloudfront", "cdn", "safe"],
))

register_module(ModuleMetadata(
    name="kms__enum",
    category=ModuleCategory.ENUM,
    risk=ModuleRisk.SAFE,
    description="Enumerate KMS keys, aliases, and key policies.",
    required_permissions=[
        "kms:ListKeys", "kms:DescribeKey", "kms:GetKeyPolicy", "kms:ListAliases",
        "kms:ListGrants"
    ],
    supported_services=["kms"],
    mitre_techniques=["T1555.005"],
    tags=["enumeration", "kms", "crypto", "safe"],
))

register_module(ModuleMetadata(
    name="cognito__enum",
    category=ModuleCategory.ENUM,
    risk=ModuleRisk.SAFE,
    description="Enumerate Cognito user pools, identity pools, and app clients.",
    required_permissions=[
        "cognito-idp:ListUserPools", "cognito-idp:DescribeUserPool",
        "cognito-idp:ListUserPoolClients", "cognito-identity:ListIdentityPools",
        "cognito-identity:DescribeIdentityPool"
    ],
    supported_services=["cognito-idp", "cognito-identity"],
    mitre_techniques=["T1087.004"],
    tags=["enumeration", "cognito", "identity", "safe"],
))

register_module(ModuleMetadata(
    name="organizations__enum",
    category=ModuleCategory.ENUM,
    risk=ModuleRisk.SAFE,
    description="Enumerate AWS Organization accounts, OUs, policies, and handshakes.",
    required_permissions=[
        "organizations:ListAccounts", "organizations:ListRoots",
        "organizations:ListOrganizationalUnitsForParent", "organizations:ListPolicies",
        "organizations:ListPoliciesForTarget", "organizations:DescribeHandshake"
    ],
    supported_services=["organizations"],
    mitre_techniques=["T1087.004"],
    tags=["enumeration", "organizations", "management", "safe"],
))

register_module(ModuleMetadata(
    name="cloudtrail__enum",
    category=ModuleCategory.ENUM,
    risk=ModuleRisk.SAFE,
    description="Enumerate CloudTrail trails, event selectors, and insights.",
    required_permissions=[
        "cloudtrail:DescribeTrails", "cloudtrail:GetTrailStatus", "cloudtrail:ListTrails",
        "cloudtrail:LookupEvents", "cloudtrail:GetInsightSelectors"
    ],
    supported_services=["cloudtrail"],
    mitre_techniques=["T1530"],
    tags=["enumeration", "cloudtrail", "logging", "safe"],
))

register_module(ModuleMetadata(
    name="guardduty__enum",
    category=ModuleCategory.ENUM,
    risk=ModuleRisk.SAFE,
    description="Enumerate GuardDuty detectors, findings, and threat lists.",
    required_permissions=[
        "guardduty:ListDetectors", "guardduty:GetDetector", "guardduty:ListFindings",
        "guardduty:GetFindings", "guardduty:ListThreatIntelSets", "guardduty:GetThreatIntelSet"
    ],
    supported_services=["guardduty"],
    mitre_techniques=["T1530"],
    tags=["enumeration", "guardduty", "threat-detection", "safe"],
))

# List all enum modules
ENUM_MODULES = [
    "iam__enum", "s3__enum", "lambda__enum", "ec2__enum", "sts__enum",
    "rds__enum", "dynamodb__enum", "ecs__enum", "eks__enum",
    "secretsmanager__enum", "sns__enum", "cloudfront__enum",
    "kms__enum", "cognito__enum", "organizations__enum",
    "cloudtrail__enum", "guardduty__enum",
]

__all__ = ["ENUM_MODULES"]

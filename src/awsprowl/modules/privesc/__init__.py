"""
Privilege Escalation Modules - Analysis & Detection

These modules analyze the current IAM configuration to identify privilege escalation paths.
They are read-only and perform no modifications to AWS resources.
"""

from awsprowl.modules import ModuleCategory, ModuleMetadata, ModuleRisk, register_module

# Register privesc modules
register_module(ModuleMetadata(
    name="iam__privesc",
    category=ModuleCategory.PRIVESC,
    risk=ModuleRisk.SAFE,
    description="Analyze IAM configuration for privilege escalation paths using 50+ techniques. Checks for: CreateAccessKey, CreateLoginProfile, UpdateLoginProfile, AttachUserPolicy, PutUserPolicy, AttachRolePolicy, PutRolePolicy, AttachGroupPolicy, PutGroupPolicy, CreatePolicyVersion, SetDefaultPolicyVersion, CreateRole, UpdateAssumeRolePolicy, PassRole, AddUserToGroup, CreateUser, CreateGroup, UpdateAssumeRolePolicy, and cross-account trust abuse.",
    required_permissions=[
        "iam:GetAccountAuthorizationDetails", "iam:SimulatePrincipalPolicy",
        "iam:ListUsers", "iam:ListRoles", "iam:ListPolicies", "iam:ListGroups",
        "iam:GetUser", "iam:GetRole", "iam:GetPolicy", "iam:GetPolicyVersion",
        "iam:ListAttachedUserPolicies", "iam:ListUserPolicies",
        "iam:ListAttachedRolePolicies", "iam:ListRolePolicies",
        "iam:ListAttachedGroupPolicies", "iam:ListGroupPolicies",
        "iam:ListGroupsForUser", "iam:GetLoginProfile",
        "iam:GetAccountPasswordPolicy", "organizations:ListAccounts"
    ],
    supported_services=["iam", "organizations"],
    mitre_techniques=["T1069.003", "T1087.004", "T1078.004", "T1526"],
    tags=["privesc", "iam", "privilege-escalation", "analysis", "safe"],
    requires_confirmation=False,
))

register_module(ModuleMetadata(
    name="lambda__privesc",
    category=ModuleCategory.PRIVESC,
    risk=ModuleRisk.SAFE,
    description="Analyze Lambda functions for privilege escalation paths: function code modification, environment variable injection, layer version manipulation, function URL public access, and event source mapping abuse.",
    required_permissions=[
        "lambda:ListFunctions", "lambda:GetFunction", "lambda:GetFunctionConfiguration",
        "lambda:GetPolicy", "lambda:GetFunctionUrlConfig", "lambda:ListFunctionUrlConfigs",
        "lambda:ListAliases", "lambda:ListVersionsByFunction", "lambda:ListEventSourceMappings",
        "lambda:GetEventSourceMapping", "lambda:ListLayers", "lambda:ListLayerVersions",
        "lambda:GetLayerVersion", "lambda:GetLayerVersionPolicy",
        "lambda:ListCodeSigningConfigs", "lambda:GetCodeSigningConfig",
        "iam:GetRole", "iam:GetRolePolicy", "iam:ListAttachedRolePolicies"
    ],
    supported_services=["lambda", "iam"],
    mitre_techniques=["T1087.004", "T1648.002", "T1078.004"],
    tags=["privesc", "lambda", "serverless", "analysis", "safe"],
    requires_confirmation=False,
))

register_module(ModuleMetadata(
    name="ec2__privesc",
    category=ModuleCategory.PRIVESC,
    risk=ModuleRisk.SAFE,
    description="Analyze EC2 resources for privilege escalation: instance profile abuse, user data injection, security group modification, launch template abuse, ENI attachment, and Instance Connect endpoints.",
    required_permissions=[
        "ec2:DescribeInstances", "ec2:DescribeSecurityGroups", "ec2:DescribeVpcs",
        "ec2:DescribeSubnets", "ec2:DescribeNetworkInterfaces", "ec2:DescribeAddresses",
        "ec2:DescribeInstanceAttribute", "ec2:DescribeNetworkAcls",
        "ec2:DescribeRouteTables", "ec2:DescribeInternetGateways", "ec2:DescribeNatGateways",
        "ec2:DescribeVpcEndpoints", "ec2:DescribeLaunchTemplates",
        "ec2:DescribeLaunchTemplateVersions", "ec2:DescribeInstanceConnectEndpoints",
        "ec2:DescribePlacementGroups", "ec2:DescribeHosts", "ec2:DescribeCapacityReservations",
        "ec2:DescribeTransitGateways", "ec2:DescribeTransitGatewayAttachments",
        "ec2:DescribeTransitGatewayRouteTables", "ec2:DescribeVpcPeeringConnections",
        "ec2:DescribeVpnConnections", "ec2:DescribeCustomerGateways", "ec2:DescribeFlowLogs",
        "iam:GetInstanceProfile", "iam:GetRole", "iam:GetRolePolicy",
        "iam:ListRolePolicies", "iam:ListAttachedRolePolicies", "iam:GetPolicy", "iam:GetPolicyVersion"
    ],
    supported_services=["ec2", "iam"],
    mitre_techniques=["T1087.004", "T1046", "T1078.004", "T1526"],
    tags=["privesc", "ec2", "compute", "network", "analysis", "safe"],
    requires_confirmation=False,
))

register_module(ModuleMetadata(
    name="s3__privesc",
    category=ModuleCategory.PRIVESC,
    risk=ModuleRisk.SAFE,
    description="Analyze S3 buckets for privilege escalation: bucket policy modification, ACL abuse, replication configuration abuse, lifecycle policy injection, and access point policy abuse.",
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
    mitre_techniques=["T1083", "T1530", "T1602", "T1078.004"],
    tags=["privesc", "s3", "storage", "analysis", "safe"],
    requires_confirmation=False,
))

register_module(ModuleMetadata(
    name="glue__privesc",
    category=ModuleCategory.PRIVESC,
    risk=ModuleRisk.SAFE,
    description="Analyze AWS Glue for privilege escalation: dev endpoint abuse, job role assumption, and connection credential extraction.",
    required_permissions=[
        "glue:GetDevEndpoints", "glue:GetJobs", "glue:GetJobRuns",
        "glue:GetConnections", "glue:GetSecurityConfigurations",
        "iam:GetRole", "iam:GetRolePolicy", "iam:ListAttachedRolePolicies"
    ],
    supported_services=["glue", "iam"],
    mitre_techniques=["T1087.004", "T1078.004"],
    tags=["privesc", "glue", "etl", "analysis", "safe"],
    requires_confirmation=False,
))

register_module(ModuleMetadata(
    name="cloudformation__privesc",
    category=ModuleCategory.PRIVESC,
    risk=ModuleRisk.SAFE,
    description="Analyze CloudFormation for privilege escalation: stack role assumption, custom resource abuse, and drift detection bypass.",
    required_permissions=[
        "cloudformation:ListStacks", "cloudformation:DescribeStacks",
        "cloudformation:DescribeStackResources", "cloudformation:ListStackSetOperations",
        "iam:GetRole", "iam:GetRolePolicy", "iam:ListAttachedRolePolicies"
    ],
    supported_services=["cloudformation", "iam"],
    mitre_techniques=["T1087.004", "T1078.004"],
    tags=["privesc", "cloudformation", "iac", "analysis", "safe"],
    requires_confirmation=False,
))

register_module(ModuleMetadata(
    name="datapipeline__privesc",
    category=ModuleCategory.PRIVESC,
    risk=ModuleRisk.SAFE,
    description="Analyze Data Pipeline for privilege escalation: pipeline role assumption and EC2 resource abuse.",
    required_permissions=[
        "datapipeline:ListPipelines", "datapipeline:DescribePipelines",
        "datapipeline:GetPipelineDefinition", "iam:GetRole",
        "iam:GetRolePolicy", "iam:ListAttachedRolePolicies"
    ],
    supported_services=["datapipeline", "iam"],
    mitre_techniques=["T1087.004", "T1078.004"],
    tags=["privesc", "datapipeline", "analysis", "safe"],
    requires_confirmation=False,
))

register_module(ModuleMetadata(
    name="ssm__privesc",
    category=ModuleCategory.PRIVESC,
    risk=ModuleRisk.SAFE,
    description="Analyze SSM for privilege escalation: document abuse, parameter store secrets, automation execution, and session manager access.",
    required_permissions=[
        "ssm:ListDocuments", "ssm:DescribeDocument", "ssm:GetParameters",
        "ssm:GetParametersByPath", "ssm:ListAssociations", "ssm:DescribeAutomationExecutions",
        "ssm:DescribeInstanceInformation", "iam:GetRole", "iam:GetRolePolicy",
        "iam:ListAttachedRolePolicies"
    ],
    supported_services=["ssm", "iam"],
    mitre_techniques=["T1087.004", "T1078.004", "T1555.003"],
    tags=["privesc", "ssm", "systems-manager", "analysis", "safe"],
    requires_confirmation=False,
))

register_module(ModuleMetadata(
    name="codebuild__privesc",
    category=ModuleCategory.PRIVESC,
    risk=ModuleRisk.SAFE,
    description="Analyze CodeBuild for privilege escalation: build project role assumption, buildspec injection, and artifact access.",
    required_permissions=[
        "codebuild:ListProjects", "codebuild:BatchGetProjects",
        "codebuild:ListBuildsForProject", "codebuild:BatchGetBuilds",
        "iam:GetRole", "iam:GetRolePolicy", "iam:ListAttachedRolePolicies"
    ],
    supported_services=["codebuild", "iam"],
    mitre_techniques=["T1087.004", "T1078.004", "T1648"],
    tags=["privesc", "codebuild", "ci-cd", "analysis", "safe"],
    requires_confirmation=False,
))

register_module(ModuleMetadata(
    name="ecs__privesc",
    category=ModuleCategory.PRIVESC,
    risk=ModuleRisk.SAFE,
    description="Analyze ECS for privilege escalation: task role assumption, task definition injection, service role abuse, and exec command access.",
    required_permissions=[
        "ecs:ListClusters", "ecs:DescribeClusters", "ecs:ListServices", "ecs:DescribeServices",
        "ecs:ListTaskDefinitions", "ecs:DescribeTaskDefinition",
        "ecs:ListContainerInstances", "ecs:DescribeContainerInstances",
        "iam:GetRole", "iam:GetRolePolicy", "iam:ListAttachedRolePolicies"
    ],
    supported_services=["ecs", "iam"],
    mitre_techniques=["T1087.004", "T1648.001", "T1078.004"],
    tags=["privesc", "ecs", "containers", "analysis", "safe"],
    requires_confirmation=False,
))

register_module(ModuleMetadata(
    name="eks__privesc",
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
    tags=["privesc", "eks", "kubernetes", "analysis", "safe"],
    requires_confirmation=False,
))

register_module(ModuleMetadata(
    name="batch__privesc",
    category=ModuleCategory.PRIVESC,
    risk=ModuleRisk.SAFE,
    description="Analyze AWS Batch for privilege escalation: job definition role assumption, compute environment abuse, and job queue manipulation.",
    required_permissions=[
        "batch:DescribeJobDefinitions", "batch:DescribeComputeEnvironments",
        "batch:DescribeJobQueues", "batch:ListJobs", "iam:GetRole",
        "iam:GetRolePolicy", "iam:ListAttachedRolePolicies"
    ],
    supported_services=["batch", "iam"],
    mitre_techniques=["T1087.004", "T1078.004"],
    tags=["privesc", "batch", "compute", "analysis", "safe"],
    requires_confirmation=False,
))

register_module(ModuleMetadata(
    name="sagemaker__privesc",
    category=ModuleCategory.PRIVESC,
    risk=ModuleRisk.SAFE,
    description="Analyze SageMaker for privilege escalation: notebook instance role assumption, model deployment role abuse, and pipeline execution role.",
    required_permissions=[
        "sagemaker:ListNotebookInstances", "sagemaker:DescribeNotebookInstance",
        "sagemaker:ListModels", "sagemaker:DescribeModel",
        "sagemaker:ListPipelines", "sagemaker:DescribePipeline",
        "iam:GetRole", "iam:GetRolePolicy", "iam:ListAttachedRolePolicies"
    ],
    supported_services=["sagemaker", "iam"],
    mitre_techniques=["T1087.004", "T1078.004"],
    tags=["privesc", "sagemaker", "ml", "analysis", "safe"],
    requires_confirmation=False,
))

register_module(ModuleMetadata(
    name="cloud9__privesc",
    category=ModuleCategory.PRIVESC,
    risk=ModuleRisk.SAFE,
    description="Analyze Cloud9 for privilege escalation: environment EC2 role assumption, SSH access abuse, and user settings injection.",
    required_permissions=[
        "cloud9:ListEnvironments", "cloud9:DescribeEnvironments",
        "ec2:DescribeInstances", "iam:GetInstanceProfile", "iam:GetRole",
        "iam:GetRolePolicy", "iam:ListAttachedRolePolicies"
    ],
    supported_services=["cloud9", "ec2", "iam"],
    mitre_techniques=["T1087.004", "T1078.004"],
    tags=["privesc", "cloud9", "ide", "analysis", "safe"],
    requires_confirmation=False,
))

register_module(ModuleMetadata(
    name="servicecatalog__privesc",
    category=ModuleCategory.PRIVESC,
    risk=ModuleRisk.SAFE,
    description="Analyze Service Catalog for privilege escalation: provisioned product role assumption, portfolio share abuse, and constraint bypass.",
    required_permissions=[
        "servicecatalog:ListProvisionedProducts", "servicecatalog:DescribeProvisionedProduct",
        "servicecatalog:ListPortfolios", "servicecatalog:DescribePortfolio",
        "iam:GetRole", "iam:GetRolePolicy", "iam:ListAttachedRolePolicies"
    ],
    supported_services=["servicecatalog", "iam"],
    mitre_techniques=["T1087.004", "T1078.004"],
    tags=["privesc", "servicecatalog", "analysis", "safe"],
    requires_confirmation=False,
))

register_module(ModuleMetadata(
    name="organizations__privesc",
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
    tags=["privesc", "organizations", "management", "analysis", "safe"],
    requires_confirmation=False,
))

register_module(ModuleMetadata(
    name="iam_service_linked_roles__privesc",
    category=ModuleCategory.PRIVESC,
    risk=ModuleRisk.SAFE,
    description="Analyze IAM Service-Linked Roles for privilege escalation: SLR assumption via service actions, implicit permissions abuse.",
    required_permissions=[
        "iam:GetServiceLinkedRoleDeletionStatus", "iam:ListServiceLinkedRoles",
        "iam:GetRole", "iam:GetRolePolicy", "iam:ListAttachedRolePolicies",
        "iam:SimulatePrincipalPolicy"
    ],
    supported_services=["iam"],
    mitre_techniques=["T1087.004", "T1078.004"],
    tags=["privesc", "iam", "service-linked-roles", "analysis", "safe"],
    requires_confirmation=False,
))

# List all privesc modules
PRIVESC_MODULES = [
    "iam__privesc", "lambda__privesc", "ec2__privesc", "s3__privesc",
    "glue__privesc", "cloudformation__privesc", "datapipeline__privesc",
    "ssm__privesc", "codebuild__privesc", "ecs__privesc", "eks__privesc",
    "batch__privesc", "sagemaker__privesc", "cloud9__privesc",
    "servicecatalog__privesc", "organizations__privesc", "iam_service_linked_roles__privesc",
]

__all__ = ["PRIVESC_MODULES"]

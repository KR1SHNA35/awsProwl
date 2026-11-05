"""
Backdoor Modules - Covert Access Mechanisms

These modules create hidden/covert access mechanisms that blend in with normal AWS operations.
They require explicit authorization and confirmation before running.
"""

from awsprowl.modules import ModuleCategory, ModuleMetadata, ModuleRisk, register_module

# Register backdoor modules
register_module(ModuleMetadata(
    name="lambda__backdoor_function_url",
    category=ModuleCategory.BACKDOOR,
    risk=ModuleRisk.CRITICAL,
    description="Create Lambda function with public Function URL (no auth) as covert backdoor. Blends with legitimate serverless functions. CRITICAL - public code execution endpoint.",
    required_permissions=["lambda:CreateFunction", "lambda:CreateFunctionUrlConfig", "lambda:AddPermission", "lambda:UpdateFunctionCode", "iam:PassRole"],
    supported_services=["lambda", "iam"],
    mitre_techniques=["T1059.004", "T1505.003", "T1190", "T1648.002"],
    tags=["backdoor", "lambda", "function-url", "public", "covert", "code-execution", "destructive"],
    requires_confirmation=True,
    destructive=True,
))

register_module(ModuleMetadata(
    name="lambda__backdoor_layer",
    category=ModuleCategory.BACKDOOR,
    risk=ModuleRisk.HIGH,
    description="Publish malicious Lambda layer that gets auto-imported by functions. Supply chain backdoor. DESTRUCTIVE.",
    required_permissions=["lambda:PublishLayerVersion", "lambda:AddLayerVersionPermission", "lambda:ListLayerVersions", "lambda:GetLayerVersion"],
    supported_services=["lambda"],
    mitre_techniques=["T1059.004", "T1195.002", "T1505.003"],
    tags=["backdoor", "lambda", "layer", "supply-chain", "covert", "destructive"],
    requires_confirmation=True,
    destructive=True,
))

register_module(ModuleMetadata(
    name="lambda__backdoor_alias_routing",
    category=ModuleCategory.BACKDOOR,
    risk=ModuleRisk.HIGH,
    description="Create Lambda alias with weighted routing to malicious version. Traffic shifting backdoor.",
    required_permissions=["lambda:CreateAlias", "lambda:UpdateAlias", "lambda:GetAlias", "lambda:ListAliases", "lambda:GetFunction"],
    supported_services=["lambda"],
    mitre_techniques=["T1059.004", "T1505.003", "T1556.002"],
    tags=["backdoor", "lambda", "alias", "traffic-shifting", "covert"],
    requires_confirmation=True,
))

register_module(ModuleMetadata(
    name="lambda__backdoor_event_source",
    category=ModuleCategory.BACKDOOR,
    risk=ModuleRisk.HIGH,
    description="Create event source mapping (SQS/Kinesis/DynamoDB) to trigger backdoor function on data events. DESTRUCTIVE.",
    required_permissions=["lambda:CreateEventSourceMapping", "lambda:ListEventSourceMappings", "lambda:GetEventSourceMapping", "iam:PassRole"],
    supported_services=["lambda", "iam", "sqs", "kinesis", "dynamodb"],
    mitre_techniques=["T1059.004", "T1505.003", "T1648.002"],
    tags=["backdoor", "lambda", "event-source", "trigger", "covert", "destructive"],
    requires_confirmation=True,
    destructive=True,
))

register_module(ModuleMetadata(
    name="lambda__backdoor_code_signing_bypass",
    category=ModuleCategory.BACKDOOR,
    risk=ModuleRisk.HIGH,
    description="Bypass Lambda code signing by updating unsigned $LATEST version or using untrusted layer. DESTRUCTIVE.",
    required_permissions=["lambda:UpdateFunctionCode", "lambda:PutFunctionCodeSigningConfig", "lambda:GetFunction", "lambda:GetCodeSigningConfig"],
    supported_services=["lambda"],
    mitre_techniques=["T1059.004", "T1553.004", "T1505.003"],
    tags=["backdoor", "lambda", "code-signing", "bypass", "destructive"],
    requires_confirmation=True,
    destructive=True,
))

register_module(ModuleMetadata(
    name="lambda__backdoor_container_image",
    category=ModuleCategory.BACKDOOR,
    risk=ModuleRisk.HIGH,
    description="Deploy Lambda container image with hidden backdoor. Image-based persistence.",
    required_permissions=["lambda:CreateFunction", "lambda:UpdateFunctionCode", "ecr:BatchGetImage", "ecr:GetDownloadUrlForLayer", "iam:PassRole"],
    supported_services=["lambda", "ecr", "iam"],
    mitre_techniques=["T1059.004", "T1505.003", "T1610"],
    tags=["backdoor", "lambda", "container", "image", "covert", "destructive"],
    requires_confirmation=True,
    destructive=True,
))

register_module(ModuleMetadata(
    name="lambda__backdoor_vpc_endpoint",
    category=ModuleCategory.BACKDOOR,
    risk=ModuleRisk.MEDIUM,
    description="Create Lambda in VPC with VPC endpoint for private backdoor access.",
    required_permissions=["lambda:CreateFunction", "lambda:UpdateFunctionConfiguration", "ec2:CreateVpcEndpoint", "ec2:DescribeVpcEndpoints", "iam:PassRole"],
    supported_services=["lambda", "ec2", "iam"],
    mitre_techniques=["T1059.004", "T1505.003", "T1021.004"],
    tags=["backdoor", "lambda", "vpc", "private", "covert"],
    requires_confirmation=True,
))

register_module(ModuleMetadata(
    name="ec2__backdoor_instance_connect",
    category=ModuleCategory.BACKDOOR,
    risk=ModuleRisk.HIGH,
    description="Create EC2 Instance Connect Endpoint for covert SSH/RDP access. DESTRUCTIVE.",
    required_permissions=["ec2:CreateInstanceConnectEndpoint", "ec2:DescribeInstanceConnectEndpoints", "ec2:DeleteInstanceConnectEndpoint", "ec2:DescribeVpcs", "ec2:DescribeSubnets"],
    supported_services=["ec2"],
    mitre_techniques=["T1021.004", "T1505.003", "T1133"],
    tags=["backdoor", "ec2", "instance-connect", "ssh", "rdp", "covert", "destructive"],
    requires_confirmation=True,
    destructive=True,
))

register_module(ModuleMetadata(
    name="ec2__backdoor_ssm_agent",
    category=ModuleCategory.BACKDOOR,
    risk=ModuleRisk.HIGH,
    description="Install/configure SSM Agent on instances for agent-based backdoor access. DESTRUCTIVE.",
    required_permissions=["ssm:CreateAssociation", "ssm:SendCommand", "ec2:DescribeInstances", "iam:PassRole"],
    supported_services=["ssm", "ec2", "iam"],
    mitre_techniques=["T1505.003", "T1569.002", "T1021.004"],
    tags=["backdoor", "ec2", "ssm", "agent", "covert", "destructive"],
    requires_confirmation=True,
    destructive=True,
))

register_module(ModuleMetadata(
    name="ec2__backdoor_user_data_script",
    category=ModuleCategory.BACKDOOR,
    risk=ModuleRisk.HIGH,
    description="Embed reverse shell/backdoor in instance user data for persistent access on boot. DESTRUCTIVE.",
    required_permissions=["ec2:RunInstances", "ec2:ModifyInstanceAttribute", "ec2:DescribeInstances", "ec2:DescribeImages"],
    supported_services=["ec2"],
    mitre_techniques=["T1059.004", "T1505.003", "T1556.002", "T1611"],
    tags=["backdoor", "ec2", "user-data", "reverse-shell", "covert", "destructive"],
    requires_confirmation=True,
    destructive=True,
))

register_module(ModuleMetadata(
    name="ec2__backdoor_ami_implant",
    category=ModuleCategory.BACKDOOR,
    risk=ModuleRisk.HIGH,
    description="Create custom AMI with pre-installed backdoor (SSH keys, agents, cron jobs). DESTRUCTIVE.",
    required_permissions=["ec2:CreateImage", "ec2:RegisterImage", "ec2:DescribeImages", "ec2:DescribeInstances", "ec2:RunInstances"],
    supported_services=["ec2"],
    mitre_techniques=["T1059.004", "T1505.003", "T1611", "T1556.002"],
    tags=["backdoor", "ec2", "ami", "golden-image", "implant", "covert", "destructive"],
    requires_confirmation=True,
    destructive=True,
))

register_module(ModuleMetadata(
    name="ec2__backdoor_security_group_hidden",
    category=ModuleCategory.BACKDOOR,
    risk=ModuleRisk.MEDIUM,
    description="Create security group with non-standard ports/protocols for covert C2. DESTRUCTIVE.",
    required_permissions=["ec2:CreateSecurityGroup", "ec2:AuthorizeSecurityGroupIngress", "ec2:AuthorizeSecurityGroupEgress", "ec2:DescribeVpcs"],
    supported_services=["ec2"],
    mitre_techniques=["T1046", "T1571", "T1572"],
    tags=["backdoor", "ec2", "security-group", "c2", "covert", "destructive"],
    requires_confirmation=True,
    destructive=True,
))

register_module(ModuleMetadata(
    name="ec2__backdoor_eip_association",
    category=ModuleCategory.BACKDOOR,
    risk=ModuleRisk.MEDIUM,
    description="Allocate and associate Elastic IP for persistent public backdoor endpoint.",
    required_permissions=["ec2:AllocateAddress", "ec2:AssociateAddress", "ec2:DescribeAddresses", "ec2:DescribeInstances"],
    supported_services=["ec2"],
    mitre_techniques=["T1021.004", "T1505.003"],
    tags=["backdoor", "ec2", "eip", "persistent-ip"],
    requires_confirmation=True,
))

register_module(ModuleMetadata(
    name="s3__backdoor_static_website",
    category=ModuleCategory.BACKDOOR,
    risk=ModuleRisk.MEDIUM,
    description="Configure S3 static website hosting with hidden backdoor page/C2 endpoint. DESTRUCTIVE.",
    required_permissions=["s3:PutBucketWebsite", "s3:GetBucketWebsite", "s3:PutBucketPolicy", "s3:PutObject", "s3:PutObjectAcl"],
    supported_services=["s3"],
    mitre_techniques=["T1505.003", "T1102", "T1583.001"],
    tags=["backdoor", "s3", "static-website", "c2", "covert", "destructive"],
    requires_confirmation=True,
    destructive=True,
))

register_module(ModuleMetadata(
    name="s3__backdoor_object_metadata",
    category=ModuleCategory.BACKDOOR,
    risk=ModuleRisk.LOW,
    description="Store C2 commands/payloads in S3 object metadata for covert retrieval.",
    required_permissions=["s3:PutObject", "s3:GetObject", "s3:HeadObject", "s3:ListObjectsV2"],
    supported_services=["s3"],
    mitre_techniques=["T1505.003", "T1102", "T1027"],
    tags=["backdoor", "s3", "metadata", "c2", "covert"],
    requires_confirmation=True,
))

register_module(ModuleMetadata(
    name="s3__backdoor_access_point",
    category=ModuleCategory.BACKDOOR,
    risk=ModuleRisk.HIGH,
    description="Create S3 Access Point with custom policy for restricted backdoor access. DESTRUCTIVE.",
    required_permissions=["s3:CreateAccessPoint", "s3:GetAccessPoint", "s3:PutAccessPointPolicy", "s3:ListAccessPoints"],
    supported_services=["s3"],
    mitre_techniques=["T1505.003", "T1098", "T1530"],
    tags=["backdoor", "s3", "access-point", "restricted", "covert", "destructive"],
    requires_confirmation=True,
    destructive=True,
))

register_module(ModuleMetadata(
    name="s3__backdoor_replication_exfil",
    category=ModuleCategory.BACKDOOR,
    risk=ModuleRisk.HIGH,
    description="Configure cross-region replication to attacker-controlled bucket for automated exfiltration. DESTRUCTIVE.",
    required_permissions=["s3:PutBucketReplication", "s3:GetBucketReplication", "iam:PassRole"],
    supported_services=["s3", "iam"],
    mitre_techniques=["T1020", "T1041", "T1530"],
    tags=["backdoor", "s3", "replication", "exfiltration", "automated", "destructive"],
    requires_confirmation=True,
    destructive=True,
))

register_module(ModuleMetadata(
    name="iam__backdoor_service_role",
    category=ModuleCategory.BACKDOOR,
    risk=ModuleRisk.HIGH,
    description="Create service-linked role or service role with overly permissive trust policy for service abuse. DESTRUCTIVE.",
    required_permissions=["iam:CreateServiceLinkedRole", "iam:CreateRole", "iam:UpdateAssumeRolePolicy", "iam:AttachRolePolicy", "iam:PutRolePolicy"],
    supported_services=["iam"],
    mitre_techniques=["T1098", "T1078.004", "T1556.003"],
    tags=["backdoor", "iam", "service-role", "trust-policy", "covert", "destructive"],
    requires_confirmation=True,
    destructive=True,
))

register_module(ModuleMetadata(
    name="iam__backdoor_oidc_provider",
    category=ModuleCategory.BACKDOOR,
    risk=ModuleRisk.HIGH,
    description="Create OIDC identity provider with attacker-controlled issuer for federation backdoor. DESTRUCTIVE.",
    required_permissions=["iam:CreateOpenIDConnectProvider", "iam:AddClientIDToOpenIDConnectProvider", "iam:UpdateOpenIDConnectProviderThumbprint", "iam:ListOpenIDConnectProviders"],
    supported_services=["iam"],
    mitre_techniques=["T1078.004", "T1556.003", "T1098"],
    tags=["backdoor", "iam", "oidc", "federation", "covert", "destructive"],
    requires_confirmation=True,
    destructive=True,
))

register_module(ModuleMetadata(
    name="iam__backdoor_saml_provider",
    category=ModuleCategory.BACKDOOR,
    risk=ModuleRisk.HIGH,
    description="Create SAML identity provider with attacker-controlled metadata for federation backdoor. DESTRUCTIVE.",
    required_permissions=["iam:CreateSAMLProvider", "iam:UpdateSAMLProvider", "iam:ListSAMLProviders"],
    supported_services=["iam"],
    mitre_techniques=["T1078.004", "T1556.003", "T1098"],
    tags=["backdoor", "iam", "saml", "federation", "covert", "destructive"],
    requires_confirmation=True,
    destructive=True,
))

register_module(ModuleMetadata(
    name="cloudformation__backdoor_macro",
    category=ModuleCategory.BACKDOOR,
    risk=ModuleRisk.HIGH,
    description="Create CloudFormation macro that executes arbitrary code during stack deployment. DESTRUCTIVE.",
    required_permissions=["cloudformation:CreateStack", "cloudformation:DescribeStacks", "lambda:CreateFunction", "lambda:AddPermission", "iam:PassRole"],
    supported_services=["cloudformation", "lambda", "iam"],
    mitre_techniques=["T1059.004", "T1611", "T1505.003"],
    tags=["backdoor", "cloudformation", "macro", "code-execution", "covert", "destructive"],
    requires_confirmation=True,
    destructive=True,
))

register_module(ModuleMetadata(
    name="cloudformation__backdoor_custom_resource",
    category=ModuleCategory.BACKDOOR,
    risk=ModuleRisk.HIGH,
    description="Deploy custom resource provider (Lambda) that executes on stack create/update/delete. DESTRUCTIVE.",
    required_permissions=["cloudformation:CreateStack", "cloudformation:DescribeStacks", "lambda:CreateFunction", "lambda:AddPermission", "iam:PassRole"],
    supported_services=["cloudformation", "lambda", "iam"],
    mitre_techniques=["T1059.004", "T1611", "T1505.003"],
    tags=["backdoor", "cloudformation", "custom-resource", "code-execution", "covert", "destructive"],
    requires_confirmation=True,
    destructive=True,
))

register_module(ModuleMetadata(
    name="events__backdoor_scheduled_rule",
    category=ModuleCategory.BACKDOOR,
    risk=ModuleRisk.HIGH,
    description="Create EventBridge scheduled rule triggering backdoor Lambda/SSM for persistent callback. DESTRUCTIVE.",
    required_permissions=["events:PutRule", "events:PutTargets", "events:DescribeRule", "lambda:AddPermission", "ssm:StartAutomationExecution", "iam:PassRole"],
    supported_services=["events", "lambda", "ssm", "iam"],
    mitre_techniques=["T1059.004", "T1505.003", "T1611", "T1053.005"],
    tags=["backdoor", "events", "eventbridge", "scheduled", "callback", "covert", "destructive"],
    requires_confirmation=True,
    destructive=True,
))

register_module(ModuleMetadata(
    name="events__backdoor_event_pattern",
    category=ModuleCategory.BACKDOOR,
    risk=ModuleRisk.HIGH,
    description="Create EventBridge rule with event pattern to trigger backdoor on specific AWS API calls. DESTRUCTIVE.",
    required_permissions=["events:PutRule", "events:PutTargets", "events:DescribeRule", "lambda:AddPermission", "iam:PassRole"],
    supported_services=["events", "lambda", "iam"],
    mitre_techniques=["T1059.004", "T1505.003", "T1611"],
    tags=["backdoor", "events", "eventbridge", "event-pattern", "api-monitoring", "covert", "destructive"],
    requires_confirmation=True,
    destructive=True,
))

register_module(ModuleMetadata(
    name="stepfunctions__backdoor_state_machine",
    category=ModuleCategory.BACKDOOR,
    risk=ModuleRisk.HIGH,
    description="Create Step Functions state machine with malicious Lambda steps for orchestrated backdoor. DESTRUCTIVE.",
    required_permissions=["states:CreateStateMachine", "states:StartExecution", "states:DescribeStateMachine", "lambda:InvokeFunction", "iam:PassRole"],
    supported_services=["states", "lambda", "iam"],
    mitre_techniques=["T1059.004", "T1505.003", "T1611"],
    tags=["backdoor", "stepfunctions", "state-machine", "orchestration", "covert", "destructive"],
    requires_confirmation=True,
    destructive=True,
))

register_module(ModuleMetadata(
    name="ssm__backdoor_maintenance_window",
    category=ModuleCategory.BACKDOOR,
    risk=ModuleRisk.HIGH,
    description="Create SSM Maintenance Window with malicious task for scheduled backdoor execution. DESTRUCTIVE.",
    required_permissions=["ssm:CreateMaintenanceWindow", "ssm:RegisterTaskWithMaintenanceWindow", "ssm:DescribeMaintenanceWindows", "lambda:InvokeFunction", "iam:PassRole"],
    supported_services=["ssm", "lambda", "iam"],
    mitre_techniques=["T1059.004", "T1505.003", "T1053.005", "T1611"],
    tags=["backdoor", "ssm", "maintenance-window", "scheduled", "covert", "destructive"],
    requires_confirmation=True,
    destructive=True,
))

register_module(ModuleMetadata(
    name="secretsmanager__backdoor_rotation_lambda",
    category=ModuleCategory.BACKDOOR,
    risk=ModuleRisk.HIGH,
    description="Configure secret rotation with malicious Lambda for credential theft/backdoor. DESTRUCTIVE.",
    required_permissions=["secretsmanager:RotateSecret", "secretsmanager:DescribeSecret", "lambda:CreateFunction", "lambda:AddPermission", "iam:PassRole"],
    supported_services=["secretsmanager", "lambda", "iam"],
    mitre_techniques=["T1555.005", "T1059.004", "T1505.003"],
    tags=["backdoor", "secretsmanager", "rotation", "credential-theft", "covert", "destructive"],
    requires_confirmation=True,
    destructive=True,
))

register_module(ModuleMetadata(
    name="cognito__backdoor_identity_pool",
    category=ModuleCategory.BACKDOOR,
    risk=ModuleRisk.HIGH,
    description="Create Cognito Identity Pool with unauthenticated role allowing backdoor access. DESTRUCTIVE.",
    required_permissions=["cognito-identity:CreateIdentityPool", "cognito-identity:UpdateIdentityPool", "cognito-identity:SetIdentityPoolRoles", "iam:CreateRole", "iam:UpdateAssumeRolePolicy", "iam:AttachRolePolicy"],
    supported_services=["cognito-identity", "iam"],
    mitre_techniques=["T1078.004", "T1098", "T1556.003"],
    tags=["backdoor", "cognito", "identity-pool", "unauthenticated", "covert", "destructive"],
    requires_confirmation=True,
    destructive=True,
))

register_module(ModuleMetadata(
    name="apigateway__backdoor_stage_variables",
    category=ModuleCategory.BACKDOOR,
    risk=ModuleRisk.MEDIUM,
    description="Use API Gateway stage variables to route traffic to backdoor Lambda alias. DESTRUCTIVE.",
    required_permissions=["apigateway:CreateRestApi", "apigateway:CreateStage", "apigateway:UpdateStage", "apigateway:PutIntegration", "lambda:AddPermission"],
    supported_services=["apigateway", "lambda"],
    mitre_techniques=["T1059.004", "T1505.003", "T1190"],
    tags=["backdoor", "apigateway", "stage-variables", "traffic-routing", "covert", "destructive"],
    requires_confirmation=True,
    destructive=True,
))

register_module(ModuleMetadata(
    name="appsync__backdoor_resolver",
    category=ModuleCategory.BACKDOOR,
    risk=ModuleRisk.HIGH,
    description="Create AppSync resolver with malicious Lambda data source for GraphQL backdoor. DESTRUCTIVE.",
    required_permissions=["appsync:CreateGraphqlApi", "appsync:CreateResolver", "appsync:CreateDataSource", "lambda:AddPermission", "iam:PassRole"],
    supported_services=["appsync", "lambda", "iam"],
    mitre_techniques=["T1059.004", "T1505.003", "T1611"],
    tags=["backdoor", "appsync", "graphql", "resolver", "covert", "destructive"],
    requires_confirmation=True,
    destructive=True,
))

# List all backdoor modules
BACKDOOR_MODULES = [
    "lambda__backdoor_function_url", "lambda__backdoor_layer", "lambda__backdoor_alias_routing",
    "lambda__backdoor_event_source", "lambda__backdoor_code_signing_bypass", "lambda__backdoor_container_image",
    "lambda__backdoor_vpc_endpoint",
    "ec2__backdoor_instance_connect", "ec2__backdoor_ssm_agent", "ec2__backdoor_user_data_script",
    "ec2__backdoor_ami_implant", "ec2__backdoor_security_group_hidden", "ec2__backdoor_eip_association",
    "s3__backdoor_static_website", "s3__backdoor_object_metadata", "s3__backdoor_access_point",
    "s3__backdoor_replication_exfil",
    "iam__backdoor_service_role", "iam__backdoor_oidc_provider", "iam__backdoor_saml_provider",
    "cloudformation__backdoor_macro", "cloudformation__backdoor_custom_resource",
    "events__backdoor_scheduled_rule", "events__backdoor_event_pattern",
    "stepfunctions__backdoor_state_machine",
    "ssm__backdoor_maintenance_window",
    "secretsmanager__backdoor_rotation_lambda",
    "cognito__backdoor_identity_pool",
    "apigateway__backdoor_stage_variables",
    "appsync__backdoor_resolver",
]

__all__ = ["BACKDOOR_MODULES"]

"""
Lambda Service Modules - All Lambda-related features across categories

This module provides a unified interface for all Lambda operations:
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
    name="lambda_enum_functions",
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
    tags=["lambda", "enum", "functions", "safe"],
    requires_confirmation=False,
))

# ==================== PRIVESC MODULES ====================
register_module(ModuleMetadata(
    name="lambda_privesc_analysis",
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
    tags=["lambda", "privesc", "analysis", "safe"],
    requires_confirmation=False,
))

# ==================== EXPLOIT MODULES ====================
register_module(ModuleMetadata(
    name="lambda_exploit_update_function_code",
    category=ModuleCategory.EXPLOIT,
    risk=ModuleRisk.HIGH,
    description="Update Lambda function code to execute arbitrary code. DESTRUCTIVE - modifies function behavior.",
    required_permissions=["lambda:UpdateFunctionCode", "lambda:GetFunction", "iam:PassRole"],
    supported_services=["lambda", "iam"],
    mitre_techniques=["T1059.004", "T1648.002"],
    tags=["lambda", "exploit", "code-execution", "destructive"],
    requires_confirmation=True,
    destructive=True,
))

register_module(ModuleMetadata(
    name="lambda_exploit_update_function_configuration",
    category=ModuleCategory.EXPLOIT,
    risk=ModuleRisk.HIGH,
    description="Modify Lambda configuration: environment variables, VPC, layers, timeout. DESTRUCTIVE.",
    required_permissions=["lambda:UpdateFunctionConfiguration", "lambda:GetFunctionConfiguration", "iam:PassRole"],
    supported_services=["lambda", "iam"],
    mitre_techniques=["T1059.004", "T1648.002"],
    tags=["lambda", "exploit", "configuration", "destructive"],
    requires_confirmation=True,
    destructive=True,
))

register_module(ModuleMetadata(
    name="lambda_exploit_invoke_function",
    category=ModuleCategory.EXPLOIT,
    risk=ModuleRisk.MEDIUM,
    description="Invoke Lambda function with custom payload for code execution.",
    required_permissions=["lambda:InvokeFunction", "lambda:GetFunction"],
    supported_services=["lambda"],
    mitre_techniques=["T1059.004", "T1648.002"],
    tags=["lambda", "exploit", "code-execution"],
    requires_confirmation=True,
))

register_module(ModuleMetadata(
    name="lambda_exploit_create_function_url",
    category=ModuleCategory.EXPLOIT,
    risk=ModuleRisk.HIGH,
    description="Create public function URL for Lambda (no auth). DESTRUCTIVE - exposes function publicly.",
    required_permissions=["lambda:CreateFunctionUrlConfig", "lambda:AddPermission", "lambda:GetFunctionUrlConfig"],
    supported_services=["lambda"],
    mitre_techniques=["T1059.004", "T1648.002", "T1190"],
    tags=["lambda", "exploit", "public-exposure", "destructive"],
    requires_confirmation=True,
    destructive=True,
))

register_module(ModuleMetadata(
    name="lambda_exploit_add_layer_version_permission",
    category=ModuleCategory.EXPLOIT,
    risk=ModuleRisk.MEDIUM,
    description="Add permission to Lambda layer version for cross-account access.",
    required_permissions=["lambda:AddLayerVersionPermission", "lambda:GetLayerVersion"],
    supported_services=["lambda"],
    mitre_techniques=["T1078.004"],
    tags=["lambda", "exploit", "layer"],
    requires_confirmation=True,
))

# ==================== PERSIST MODULES ====================
register_module(ModuleMetadata(
    name="lambda_persist_backdoor_function",
    category=ModuleCategory.PERSIST,
    risk=ModuleRisk.CRITICAL,
    description="Create or modify Lambda function as persistent backdoor with function URL. CRITICAL - persistent code execution.",
    required_permissions=["lambda:CreateFunction", "lambda:UpdateFunctionCode", "lambda:CreateFunctionUrlConfig", "lambda:AddPermission", "iam:PassRole"],
    supported_services=["lambda", "iam"],
    mitre_techniques=["T1059.004", "T1505.003", "T1648.002", "T1190"],
    tags=["lambda", "persist", "backdoor", "function-url", "code-execution", "destructive"],
    requires_confirmation=True,
    destructive=True,
))

register_module(ModuleMetadata(
    name="lambda_persist_alias",
    category=ModuleCategory.PERSIST,
    risk=ModuleRisk.MEDIUM,
    description="Create Lambda alias pointing to malicious version for persistent invocation.",
    required_permissions=["lambda:CreateAlias", "lambda:UpdateAlias", "lambda:ListAliases", "lambda:GetFunction"],
    supported_services=["lambda"],
    mitre_techniques=["T1059.004", "T1505.003"],
    tags=["lambda", "persist", "alias"],
    requires_confirmation=True,
))

register_module(ModuleMetadata(
    name="lambda_persist_layer",
    category=ModuleCategory.PERSIST,
    risk=ModuleRisk.HIGH,
    description="Publish Lambda layer with malicious code for supply chain persistence. DESTRUCTIVE.",
    required_permissions=["lambda:PublishLayerVersion", "lambda:AddLayerVersionPermission", "lambda:ListLayerVersions"],
    supported_services=["lambda"],
    mitre_techniques=["T1059.004", "T1505.003", "T1195.002"],
    tags=["lambda", "persist", "layer", "supply-chain", "destructive"],
    requires_confirmation=True,
    destructive=True,
))

# ==================== BACKDOOR MODULES ====================
register_module(ModuleMetadata(
    name="lambda_backdoor_function_url",
    category=ModuleCategory.BACKDOOR,
    risk=ModuleRisk.CRITICAL,
    description="Create Lambda function with public Function URL (no auth) as covert backdoor. Blends with legitimate serverless functions. CRITICAL - public code execution endpoint.",
    required_permissions=["lambda:CreateFunction", "lambda:CreateFunctionUrlConfig", "lambda:AddPermission", "lambda:UpdateFunctionCode", "iam:PassRole"],
    supported_services=["lambda", "iam"],
    mitre_techniques=["T1059.004", "T1505.003", "T1190", "T1648.002"],
    tags=["lambda", "backdoor", "function-url", "public", "covert", "code-execution", "destructive"],
    requires_confirmation=True,
    destructive=True,
))

register_module(ModuleMetadata(
    name="lambda_backdoor_layer",
    category=ModuleCategory.BACKDOOR,
    risk=ModuleRisk.HIGH,
    description="Publish malicious Lambda layer that gets auto-imported by functions. Supply chain backdoor. DESTRUCTIVE.",
    required_permissions=["lambda:PublishLayerVersion", "lambda:AddLayerVersionPermission", "lambda:ListLayerVersions", "lambda:GetLayerVersion"],
    supported_services=["lambda"],
    mitre_techniques=["T1059.004", "T1195.002", "T1505.003"],
    tags=["lambda", "backdoor", "layer", "supply-chain", "covert", "destructive"],
    requires_confirmation=True,
    destructive=True,
))

register_module(ModuleMetadata(
    name="lambda_backdoor_alias_routing",
    category=ModuleCategory.BACKDOOR,
    risk=ModuleRisk.HIGH,
    description="Create Lambda alias with weighted routing to malicious version. Traffic shifting backdoor.",
    required_permissions=["lambda:CreateAlias", "lambda:UpdateAlias", "lambda:GetAlias", "lambda:ListAliases", "lambda:GetFunction"],
    supported_services=["lambda"],
    mitre_techniques=["T1059.004", "T1505.003", "T1556.002"],
    tags=["lambda", "backdoor", "alias", "traffic-shifting", "covert"],
    requires_confirmation=True,
))

register_module(ModuleMetadata(
    name="lambda_backdoor_event_source",
    category=ModuleCategory.BACKDOOR,
    risk=ModuleRisk.HIGH,
    description="Create event source mapping (SQS/Kinesis/DynamoDB) to trigger backdoor function on data events. DESTRUCTIVE.",
    required_permissions=["lambda:CreateEventSourceMapping", "lambda:ListEventSourceMappings", "lambda:GetEventSourceMapping", "iam:PassRole"],
    supported_services=["lambda", "iam", "sqs", "kinesis", "dynamodb"],
    mitre_techniques=["T1059.004", "T1505.003", "T1648.002"],
    tags=["lambda", "backdoor", "event-source", "trigger", "covert", "destructive"],
    requires_confirmation=True,
    destructive=True,
))

register_module(ModuleMetadata(
    name="lambda_backdoor_code_signing_bypass",
    category=ModuleCategory.BACKDOOR,
    risk=ModuleRisk.HIGH,
    description="Bypass Lambda code signing by updating unsigned $LATEST version or using untrusted layer. DESTRUCTIVE.",
    required_permissions=["lambda:UpdateFunctionCode", "lambda:PutFunctionCodeSigningConfig", "lambda:GetFunction", "lambda:GetCodeSigningConfig"],
    supported_services=["lambda"],
    mitre_techniques=["T1059.004", "T1553.004", "T1505.003"],
    tags=["lambda", "backdoor", "code-signing", "bypass", "destructive"],
    requires_confirmation=True,
    destructive=True,
))

register_module(ModuleMetadata(
    name="lambda_backdoor_container_image",
    category=ModuleCategory.BACKDOOR,
    risk=ModuleRisk.HIGH,
    description="Deploy Lambda container image with hidden backdoor. Image-based persistence.",
    required_permissions=["lambda:CreateFunction", "lambda:UpdateFunctionCode", "ecr:BatchGetImage", "ecr:GetDownloadUrlForLayer", "iam:PassRole"],
    supported_services=["lambda", "ecr", "iam"],
    mitre_techniques=["T1059.004", "T1505.003", "T1610"],
    tags=["lambda", "backdoor", "container", "image", "covert", "destructive"],
    requires_confirmation=True,
    destructive=True,
))

register_module(ModuleMetadata(
    name="lambda_backdoor_vpc_endpoint",
    category=ModuleCategory.BACKDOOR,
    risk=ModuleRisk.MEDIUM,
    description="Create Lambda in VPC with VPC endpoint for private backdoor access.",
    required_permissions=["lambda:CreateFunction", "lambda:UpdateFunctionConfiguration", "ec2:CreateVpcEndpoint", "ec2:DescribeVpcEndpoints", "iam:PassRole"],
    supported_services=["lambda", "ec2", "iam"],
    mitre_techniques=["T1059.004", "T1505.003", "T1021.004"],
    tags=["lambda", "backdoor", "vpc", "private", "covert"],
    requires_confirmation=True,
))

# ==================== EXFIL MODULES ====================
register_module(ModuleMetadata(
    name="lambda_exfil_env_vars",
    category=ModuleCategory.EXFIL,
    risk=ModuleRisk.HIGH,
    description="Extract environment variables from Lambda functions (secrets, API keys, DB credentials). DESTRUCTIVE.",
    required_permissions=["lambda:GetFunctionConfiguration", "lambda:ListFunctions", "lambda:GetFunction"],
    supported_services=["lambda"],
    mitre_techniques=["T1555.005", "T1530", "T1041"],
    tags=["lambda", "exfil", "env-vars", "secrets", "credentials", "destructive"],
    requires_confirmation=True,
    destructive=True,
))

register_module(ModuleMetadata(
    name="lambda_exfil_function_code",
    category=ModuleCategory.EXFIL,
    risk=ModuleRisk.HIGH,
    description="Download Lambda function code packages for source code analysis/extraction. DESTRUCTIVE.",
    required_permissions=["lambda:GetFunction", "lambda:ListFunctions", "lambda:GetFunctionCodeSigningConfig"],
    supported_services=["lambda"],
    mitre_techniques=["T1530", "T1020", "T1041"],
    tags=["lambda", "exfil", "code", "source-code", "destructive"],
    requires_confirmation=True,
    destructive=True,
))

register_module(ModuleMetadata(
    name="lambda_exfil_layer_code",
    category=ModuleCategory.EXFIL,
    risk=ModuleRisk.MEDIUM,
    description="Download Lambda layer code for analysis/extraction.",
    required_permissions=["lambda:GetLayerVersion", "lambda:ListLayerVersions", "lambda:ListLayers"],
    supported_services=["lambda"],
    mitre_techniques=["T1530", "T1020"],
    tags=["lambda", "exfil", "layer", "code"],
    requires_confirmation=True,
))

# List all Lambda modules
LAMBDA_MODULES = [
    # Enum
    "lambda_enum_functions",
    # Privesc
    "lambda_privesc_analysis",
    # Exploit
    "lambda_exploit_update_function_code", "lambda_exploit_update_function_configuration",
    "lambda_exploit_invoke_function", "lambda_exploit_create_function_url", "lambda_exploit_add_layer_version_permission",
    # Persist
    "lambda_persist_backdoor_function", "lambda_persist_alias", "lambda_persist_layer",
    # Backdoor
    "lambda_backdoor_function_url", "lambda_backdoor_layer", "lambda_backdoor_alias_routing",
    "lambda_backdoor_event_source", "lambda_backdoor_code_signing_bypass", "lambda_backdoor_container_image",
    "lambda_backdoor_vpc_endpoint",
    # Exfil
    "lambda_exfil_env_vars", "lambda_exfil_function_code", "lambda_exfil_layer_code",
]

__all__ = ["LAMBDA_MODULES"]

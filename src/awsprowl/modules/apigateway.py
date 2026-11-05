"""
API Gateway Service Modules - All API Gateway-related features across categories

This module provides a unified interface for all API Gateway operations:
- enum: Enumeration (safe, read-only)
- exploit: Active exploitation
"""

from awsprowl.modules import ModuleCategory, ModuleMetadata, ModuleRisk, register_module

# ==================== ENUM MODULES ====================
register_module(ModuleMetadata(
    name="apigateway_enum_rest_apis",
    category=ModuleCategory.ENUM,
    risk=ModuleRisk.SAFE,
    description="Enumerate API Gateway REST APIs, resources, methods, and integrations.",
    required_permissions=[
        "apigateway:GetRestApis", "apigateway:GetResources", "apigateway:GetMethod",
        "apigateway:GetIntegration", "apigateway:GetStages", "apigateway:GetStage"
    ],
    supported_services=["apigateway"],
    mitre_techniques=["T1526", "T1083"],
    tags=["apigateway", "enum", "rest-api", "safe"],
    requires_confirmation=False,
))

register_module(ModuleMetadata(
    name="apigateway_enum_http_apis",
    category=ModuleCategory.ENUM,
    risk=ModuleRisk.SAFE,
    description="Enumerate API Gateway HTTP APIs (v2).",
    required_permissions=[
        "apigateway:GetApis", "apigateway:GetRoutes", "apigateway:GetIntegrations",
        "apigateway:GetStages", "apigateway:GetAuthorizers"
    ],
    supported_services=["apigateway"],
    mitre_techniques=["T1526", "T1083"],
    tags=["apigateway", "enum", "http-api", "v2", "safe"],
    requires_confirmation=False,
))

register_module(ModuleMetadata(
    name="apigateway_enum_api_keys",
    category=ModuleCategory.ENUM,
    risk=ModuleRisk.SAFE,
    description="Enumerate API Gateway API keys and usage plans. PROWL: api_gateway__create_api_keys (enum portion).",
    required_permissions=[
        "apigateway:GetApiKeys", "apigateway:GetUsagePlans", "apigateway:GetUsagePlanKeys"
    ],
    supported_services=["apigateway"],
    mitre_techniques=["T1087.004", "T1526"],
    tags=["apigateway", "enum", "api-keys", "usage-plans", "awsprowl"],
    requires_confirmation=False,
))

# ==================== EXPLOIT MODULES ====================
register_module(ModuleMetadata(
    name="apigateway_exploit_create_api_key",
    category=ModuleCategory.EXPLOIT,
    risk=ModuleRisk.HIGH,
    description="Create API Gateway API key for unauthorized access. PROWL: api_gateway__create_api_keys. DESTRUCTIVE.",
    required_permissions=[
        "apigateway:CreateApiKey", "apigateway:CreateUsagePlanKey", "apigateway:GetUsagePlans"
    ],
    supported_services=["apigateway"],
    mitre_techniques=["T1078.004", "T1190"],
    tags=["apigateway", "exploit", "api-key", "awsprowl", "destructive"],
    requires_confirmation=True,
    destructive=True,
))

register_module(ModuleMetadata(
    name="apigateway_exploit_create_deployment",
    category=ModuleCategory.EXPLOIT,
    risk=ModuleRisk.HIGH,
    description="Create API Gateway deployment with malicious configuration. DESTRUCTIVE.",
    required_permissions=["apigateway:CreateDeployment", "apigateway:GetRestApis", "apigateway:GetStages"],
    supported_services=["apigateway"],
    mitre_techniques=["T1190", "T1505.003"],
    tags=["apigateway", "exploit", "deployment", "destructive"],
    requires_confirmation=True,
    destructive=True,
))

register_module(ModuleMetadata(
    name="apigateway_exploit_update_stage",
    category=ModuleCategory.EXPLOIT,
    risk=ModuleRisk.HIGH,
    description="Update API Gateway stage configuration (logging, throttling, variables). DESTRUCTIVE.",
    required_permissions=["apigateway:UpdateStage", "apigateway:GetStage", "apigateway:GetRestApis"],
    supported_services=["apigateway"],
    mitre_techniques=["T1098", "T1562.001"],
    tags=["apigateway", "exploit", "stage", "destructive"],
    requires_confirmation=True,
    destructive=True,
))

# ==================== BACKDOOR MODULES ====================
register_module(ModuleMetadata(
    name="apigateway_backdoor_stage_variables",
    category=ModuleCategory.BACKDOOR,
    risk=ModuleRisk.MEDIUM,
    description="Use API Gateway stage variables to route traffic to backdoor Lambda alias. DESTRUCTIVE.",
    required_permissions=["apigateway:CreateRestApi", "apigateway:CreateStage", "apigateway:UpdateStage", "apigateway:PutIntegration", "lambda:AddPermission"],
    supported_services=["apigateway", "lambda"],
    mitre_techniques=["T1059.004", "T1505.003", "T1190"],
    tags=["apigateway", "backdoor", "stage-variables", "traffic-routing", "covert", "destructive"],
    requires_confirmation=True,
    destructive=True,
))

# List all API Gateway modules
APIGATEWAY_MODULES = [
    # Enum
    "apigateway_enum_rest_apis", "apigateway_enum_http_apis", "apigateway_enum_api_keys",
    # Exploit
    "apigateway_exploit_create_api_key", "apigateway_exploit_create_deployment", "apigateway_exploit_update_stage",
    # Backdoor
    "apigateway_backdoor_stage_variables",
]

__all__ = ["APIGATEWAY_MODULES"]
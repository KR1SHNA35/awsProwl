"""
CloudFormation Service Modules - All CloudFormation-related features across categories

This module provides a unified interface for all CloudFormation operations:
- privesc: Privilege escalation analysis
- exploit: Active exploitation
- persist: Persistence mechanisms
- backdoor: Covert access
"""

from awsprowl.modules import ModuleCategory, ModuleMetadata, ModuleRisk, register_module

# ==================== PRIVESC MODULES ====================
register_module(ModuleMetadata(
    name="cloudformation_privesc_analysis",
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
    tags=["cloudformation", "privesc", "iac", "analysis", "safe"],
    requires_confirmation=False,
))

# ==================== EXPLOIT MODULES ====================
register_module(ModuleMetadata(
    name="cloudformation_exploit_create_stack",
    category=ModuleCategory.EXPLOIT,
    risk=ModuleRisk.CRITICAL,
    description="Create CloudFormation stack with malicious template for resource deployment. CRITICAL - full infrastructure deployment.",
    required_permissions=["cloudformation:CreateStack", "cloudformation:DescribeStacks", "iam:PassRole"],
    supported_services=["cloudformation", "iam"],
    mitre_techniques=["T1611", "T1059.004"],
    tags=["cloudformation", "exploit", "create-stack", "infrastructure", "destructive"],
    requires_confirmation=True,
    destructive=True,
))

register_module(ModuleMetadata(
    name="cloudformation_exploit_update_stack",
    category=ModuleCategory.EXPLOIT,
    risk=ModuleRisk.CRITICAL,
    description="Update existing CloudFormation stack with malicious template. CRITICAL - modifies infrastructure.",
    required_permissions=["cloudformation:UpdateStack", "cloudformation:DescribeStacks", "iam:PassRole"],
    supported_services=["cloudformation", "iam"],
    mitre_techniques=["T1611", "T1059.004"],
    tags=["cloudformation", "exploit", "update-stack", "infrastructure", "destructive"],
    requires_confirmation=True,
    destructive=True,
))

register_module(ModuleMetadata(
    name="cloudformation_exploit_create_stack_set",
    category=ModuleCategory.EXPLOIT,
    risk=ModuleRisk.CRITICAL,
    description="Create StackSet for cross-account/region malicious deployment. CRITICAL.",
    required_permissions=["cloudformation:CreateStackSet", "cloudformation:CreateStackInstances", "cloudformation:DescribeStackSet", "iam:PassRole"],
    supported_services=["cloudformation", "iam"],
    mitre_techniques=["T1611", "T1059.004", "T1526"],
    tags=["cloudformation", "exploit", "stackset", "cross-account", "destructive"],
    requires_confirmation=True,
    destructive=True,
))

register_module(ModuleMetadata(
    name="cloudformation_exploit_delete_stack",
    category=ModuleCategory.EXPLOIT,
    risk=ModuleRisk.HIGH,
    description="Delete CloudFormation stack to destroy infrastructure. DESTRUCTIVE.",
    required_permissions=["cloudformation:DeleteStack", "cloudformation:DescribeStacks"],
    supported_services=["cloudformation"],
    mitre_techniques=["T1485", "T1070.001"],
    tags=["cloudformation", "exploit", "delete-stack", "destructive"],
    requires_confirmation=True,
    destructive=True,
))

register_module(ModuleMetadata(
    name="cloudformation_exploit_detect_drift",
    category=ModuleCategory.EXPLOIT,
    risk=ModuleRisk.LOW,
    description="Detect drift on stack resources to identify manual changes.",
    required_permissions=["cloudformation:DetectStackDrift", "cloudformation:DescribeStackDriftDetectionStatus", "cloudformation:DescribeStacks"],
    supported_services=["cloudformation"],
    mitre_techniques=["T1526"],
    tags=["cloudformation", "exploit", "drift-detection", "recon"],
    requires_confirmation=True,
))

# ==================== PERSIST MODULES ====================
register_module(ModuleMetadata(
    name="cloudformation_persist_stack",
    category=ModuleCategory.PERSIST,
    risk=ModuleRisk.CRITICAL,
    description="Deploy CloudFormation stack with persistent resources (IAM, Lambda, EC2). CRITICAL.",
    required_permissions=["cloudformation:CreateStack", "cloudformation:UpdateStack", "cloudformation:DescribeStacks", "iam:PassRole"],
    supported_services=["cloudformation", "iam"],
    mitre_techniques=["T1611", "T1059.004", "T1505.003"],
    tags=["cloudformation", "persist", "stack", "infrastructure", "destructive"],
    requires_confirmation=True,
    destructive=True,
))

register_module(ModuleMetadata(
    name="cloudformation_persist_stack_set",
    category=ModuleCategory.PERSIST,
    risk=ModuleRisk.CRITICAL,
    description="Deploy StackSet for cross-account/region persistent infrastructure. CRITICAL.",
    required_permissions=["cloudformation:CreateStackSet", "cloudformation:CreateStackInstances", "cloudformation:DescribeStackSet", "iam:PassRole"],
    supported_services=["cloudformation", "iam"],
    mitre_techniques=["T1611", "T1059.004", "T1505.003"],
    tags=["cloudformation", "persist", "stackset", "cross-account", "destructive"],
    requires_confirmation=True,
    destructive=True,
))

register_module(ModuleMetadata(
    name="cloudformation_persist_change_set",
    category=ModuleCategory.PERSIST,
    risk=ModuleRisk.HIGH,
    description="Create change set for staged malicious deployment. DESTRUCTIVE.",
    required_permissions=["cloudformation:CreateChangeSet", "cloudformation:ExecuteChangeSet", "cloudformation:DescribeChangeSet", "cloudformation:DescribeStacks", "iam:PassRole"],
    supported_services=["cloudformation", "iam"],
    mitre_techniques=["T1611", "T1505.003"],
    tags=["cloudformation", "persist", "change-set", "staged", "destructive"],
    requires_confirmation=True,
    destructive=True,
))

# ==================== BACKDOOR MODULES ====================
register_module(ModuleMetadata(
    name="cloudformation_backdoor_macro",
    category=ModuleCategory.BACKDOOR,
    risk=ModuleRisk.HIGH,
    description="Create CloudFormation macro that executes arbitrary code during stack deployment. DESTRUCTIVE.",
    required_permissions=["cloudformation:CreateStack", "cloudformation:DescribeStacks", "lambda:CreateFunction", "lambda:AddPermission", "iam:PassRole"],
    supported_services=["cloudformation", "lambda", "iam"],
    mitre_techniques=["T1059.004", "T1611", "T1505.003"],
    tags=["cloudformation", "backdoor", "macro", "code-execution", "covert", "destructive"],
    requires_confirmation=True,
    destructive=True,
))

register_module(ModuleMetadata(
    name="cloudformation_backdoor_custom_resource",
    category=ModuleCategory.BACKDOOR,
    risk=ModuleRisk.HIGH,
    description="Deploy custom resource provider (Lambda) that executes on stack create/update/delete. DESTRUCTIVE.",
    required_permissions=["cloudformation:CreateStack", "cloudformation:DescribeStacks", "lambda:CreateFunction", "lambda:AddPermission", "iam:PassRole"],
    supported_services=["cloudformation", "lambda", "iam"],
    mitre_techniques=["T1059.004", "T1611", "T1505.003"],
    tags=["cloudformation", "backdoor", "custom-resource", "code-execution", "covert", "destructive"],
    requires_confirmation=True,
    destructive=True,
))

register_module(ModuleMetadata(
    name="cloudformation_backdoor_stack_policy",
    category=ModuleCategory.BACKDOOR,
    risk=ModuleRisk.MEDIUM,
    description="Set stack policy to protect malicious resources from updates. DESTRUCTIVE.",
    required_permissions=["cloudformation:SetStackPolicy", "cloudformation:GetStackPolicy", "cloudformation:DescribeStacks"],
    supported_services=["cloudformation"],
    mitre_techniques=["T1562.001", "T1505.003"],
    tags=["cloudformation", "backdoor", "stack-policy", "protection", "covert", "destructive"],
    requires_confirmation=True,
    destructive=True,
))

register_module(ModuleMetadata(
    name="cloudformation_backdoor_nested_stack",
    category=ModuleCategory.BACKDOOR,
    risk=ModuleRisk.HIGH,
    description="Deploy nested stack with hidden malicious resources. DESTRUCTIVE.",
    required_permissions=["cloudformation:CreateStack", "cloudformation:DescribeStacks", "iam:PassRole"],
    supported_services=["cloudformation", "iam"],
    mitre_techniques=["T1505.003", "T1611"],
    tags=["cloudformation", "backdoor", "nested-stack", "covert", "destructive"],
    requires_confirmation=True,
    destructive=True,
))

# ==================== EXPLOIT MODULES (PROWL parity) ====================
register_module(ModuleMetadata(
    name="cloudformation_exploit_resource_injection",
    category=ModuleCategory.EXPLOIT,
    risk=ModuleRisk.CRITICAL,
    description="Inject malicious resources into existing CloudFormation stacks via template manipulation. PROWL: cfn__resource_injection. CRITICAL - modifies existing infrastructure.",
    required_permissions=["cloudformation:UpdateStack", "cloudformation:DescribeStacks", "cloudformation:GetTemplate", "iam:PassRole"],
    supported_services=["cloudformation", "iam"],
    mitre_techniques=["T1611", "T1059.004", "T1505.003"],
    tags=["cloudformation", "exploit", "resource-injection", "awsprowl", "destructive"],
    requires_confirmation=True,
    destructive=True,
))

# ==================== EXFIL MODULES (PROWL parity) ====================
register_module(ModuleMetadata(
    name="cloudformation_exfil_download_data",
    category=ModuleCategory.EXFIL,
    risk=ModuleRisk.MEDIUM,
    description="Download CloudFormation stack templates, resources, and outputs. PROWL: cloudformation__download_data.",
    required_permissions=["cloudformation:DescribeStacks", "cloudformation:GetTemplate", "cloudformation:ListStackResources", "cloudformation:DescribeStackResource"],
    supported_services=["cloudformation"],
    mitre_techniques=["T1530", "T1020", "T1526"],
    tags=["cloudformation", "exfil", "download", "templates", "awsprowl"],
    requires_confirmation=True,
))

# List all CloudFormation modules
CLOUDFORMATION_MODULES = [
    # Privesc
    "cloudformation_privesc_analysis",
    # Exploit
    "cloudformation_exploit_create_stack", "cloudformation_exploit_update_stack",
    "cloudformation_exploit_create_stack_set", "cloudformation_exploit_delete_stack",
    "cloudformation_exploit_detect_drift",
    "cloudformation_exploit_resource_injection",
    # Persist
    "cloudformation_persist_stack", "cloudformation_persist_stack_set",
    "cloudformation_persist_change_set",
    # Backdoor
    "cloudformation_backdoor_macro", "cloudformation_backdoor_custom_resource",
    "cloudformation_backdoor_stack_policy", "cloudformation_backdoor_nested_stack",
    # Exfil
    "cloudformation_exfil_download_data",
]

__all__ = ["CLOUDFORMATION_MODULES"]

"""
SSM Service Modules - All SSM-related features across categories

This module provides a unified interface for all SSM operations:
- privesc: Privilege escalation analysis
- exploit: Active exploitation
- persist: Persistence mechanisms
- backdoor: Covert access
- exfil: Data exfiltration
"""

from awsprowl.modules import ModuleCategory, ModuleMetadata, ModuleRisk, register_module

# ==================== PRIVESC MODULES ====================
register_module(ModuleMetadata(
    name="ssm_privesc_analysis",
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
    tags=["ssm", "privesc", "systems-manager", "analysis", "safe"],
    requires_confirmation=False,
))

register_module(ModuleMetadata(
    name="ssm_privesc_document_analysis",
    category=ModuleCategory.PRIVESC,
    risk=ModuleRisk.SAFE,
    description="Analyze SSM documents for privilege escalation: owned documents with dangerous actions, shared documents.",
    required_permissions=["ssm:ListDocuments", "ssm:DescribeDocument", "ssm:GetDocument"],
    supported_services=["ssm"],
    mitre_techniques=["T1087.004", "T1078.004"],
    tags=["ssm", "privesc", "documents", "safe"],
    requires_confirmation=False,
))

register_module(ModuleMetadata(
    name="ssm_privesc_parameter_analysis",
    category=ModuleCategory.PRIVESC,
    risk=ModuleRisk.SAFE,
    description="Analyze Parameter Store for sensitive values that enable privilege escalation.",
    required_permissions=["ssm:GetParameters", "ssm:GetParametersByPath", "ssm:DescribeParameters", "kms:Decrypt"],
    supported_services=["ssm", "kms"],
    mitre_techniques=["T1555.003", "T1087.004"],
    tags=["ssm", "privesc", "parameters", "secrets", "safe"],
    requires_confirmation=False,
))

# ==================== EXPLOIT MODULES ====================
register_module(ModuleMetadata(
    name="ssm_exploit_send_command",
    category=ModuleCategory.EXPLOIT,
    risk=ModuleRisk.HIGH,
    description="Send SSM Run Command to EC2 instances for remote code execution. DESTRUCTIVE.",
    required_permissions=["ssm:SendCommand", "ssm:ListCommands", "ssm:GetCommandInvocation", "ec2:DescribeInstances"],
    supported_services=["ssm", "ec2"],
    mitre_techniques=["T1059.004", "T1569.002"],
    tags=["ssm", "exploit", "send-command", "remote-execution", "destructive"],
    requires_confirmation=True,
    destructive=True,
))

register_module(ModuleMetadata(
    name="ssm_exploit_start_automation_execution",
    category=ModuleCategory.EXPLOIT,
    risk=ModuleRisk.HIGH,
    description="Start SSM Automation execution with malicious document. DESTRUCTIVE.",
    required_permissions=["ssm:StartAutomationExecution", "ssm:DescribeAutomationExecutions", "iam:PassRole"],
    supported_services=["ssm", "iam"],
    mitre_techniques=["T1059.004", "T1611"],
    tags=["ssm", "exploit", "automation", "destructive"],
    requires_confirmation=True,
    destructive=True,
))

register_module(ModuleMetadata(
    name="ssm_exploit_create_document",
    category=ModuleCategory.EXPLOIT,
    risk=ModuleRisk.HIGH,
    description="Create SSM document with malicious commands. DESTRUCTIVE.",
    required_permissions=["ssm:CreateDocument", "ssm:DescribeDocument", "ssm:ListDocuments"],
    supported_services=["ssm"],
    mitre_techniques=["T1059.004", "T1611", "T1505.003"],
    tags=["ssm", "exploit", "create-document", "destructive"],
    requires_confirmation=True,
    destructive=True,
))

register_module(ModuleMetadata(
    name="ssm_exploit_put_parameter",
    category=ModuleCategory.EXPLOIT,
    risk=ModuleRisk.MEDIUM,
    description="Put parameter in Parameter Store (credential injection, config tampering). DESTRUCTIVE.",
    required_permissions=["ssm:PutParameter", "ssm:DescribeParameters", "kms:Encrypt"],
    supported_services=["ssm", "kms"],
    mitre_techniques=["T1555.003", "T1556.002"],
    tags=["ssm", "exploit", "put-parameter", "credential-injection", "destructive"],
    requires_confirmation=True,
    destructive=True,
))

register_module(ModuleMetadata(
    name="ssm_exploit_start_session",
    category=ModuleCategory.EXPLOIT,
    risk=ModuleRisk.HIGH,
    description="Start SSM Session Manager session for interactive shell access. DESTRUCTIVE.",
    required_permissions=["ssm:StartSession", "ssm:DescribeSessions", "ec2:DescribeInstances"],
    supported_services=["ssm", "ec2"],
    mitre_techniques=["T1021.004", "T1569.002"],
    tags=["ssm", "exploit", "session-manager", "interactive", "destructive"],
    requires_confirmation=True,
    destructive=True,
))

register_module(ModuleMetadata(
    name="ssm_exploit_create_association",
    category=ModuleCategory.EXPLOIT,
    risk=ModuleRisk.HIGH,
    description="Create State Manager association for persistent command execution. DESTRUCTIVE.",
    required_permissions=["ssm:CreateAssociation", "ssm:DescribeAssociation", "ssm:ListAssociations"],
    supported_services=["ssm"],
    mitre_techniques=["T1059.004", "T1505.003", "T1053.005"],
    tags=["ssm", "exploit", "association", "state-manager", "destructive"],
    requires_confirmation=True,
    destructive=True,
))

# ==================== PERSIST MODULES ====================
register_module(ModuleMetadata(
    name="ssm_persist_parameter",
    category=ModuleCategory.PERSIST,
    risk=ModuleRisk.MEDIUM,
    description="Store persistent payload/commands in SSM Parameter Store (SecureString).",
    required_permissions=["ssm:PutParameter", "ssm:GetParameter", "ssm:DeleteParameter", "ssm:DescribeParameters"],
    supported_services=["ssm"],
    mitre_techniques=["T1505.003", "T1555.003"],
    tags=["ssm", "persist", "parameter-store", "credential-storage"],
    requires_confirmation=True,
))

register_module(ModuleMetadata(
    name="ssm_persist_document",
    category=ModuleCategory.PERSIST,
    risk=ModuleRisk.HIGH,
    description="Create SSM Document with malicious commands for persistent automation. DESTRUCTIVE.",
    required_permissions=["ssm:CreateDocument", "ssm:UpdateDocument", "ssm:GetDocument", "ssm:ListDocuments"],
    supported_services=["ssm"],
    mitre_techniques=["T1059.004", "T1505.003", "T1611"],
    tags=["ssm", "persist", "document", "automation", "destructive"],
    requires_confirmation=True,
    destructive=True,
))

register_module(ModuleMetadata(
    name="ssm_persist_association",
    category=ModuleCategory.PERSIST,
    risk=ModuleRisk.HIGH,
    description="Create State Manager association for persistent scheduled execution. DESTRUCTIVE.",
    required_permissions=["ssm:CreateAssociation", "ssm:UpdateAssociation", "ssm:DescribeAssociation", "ssm:ListAssociations"],
    supported_services=["ssm"],
    mitre_techniques=["T1059.004", "T1505.003", "T1053.005"],
    tags=["ssm", "persist", "association", "scheduled", "destructive"],
    requires_confirmation=True,
    destructive=True,
))

register_module(ModuleMetadata(
    name="ssm_persist_automation",
    category=ModuleCategory.PERSIST,
    risk=ModuleRisk.HIGH,
    description="Create Automation document for persistent workflow execution. DESTRUCTIVE.",
    required_permissions=["ssm:CreateDocument", "ssm:StartAutomationExecution", "ssm:DescribeAutomationExecutions", "iam:PassRole"],
    supported_services=["ssm", "iam"],
    mitre_techniques=["T1059.004", "T1505.003", "T1611"],
    tags=["ssm", "persist", "automation", "workflow", "destructive"],
    requires_confirmation=True,
    destructive=True,
))

register_module(ModuleMetadata(
    name="ssm_persist_managed_instance",
    category=ModuleCategory.PERSIST,
    risk=ModuleRisk.MEDIUM,
    description="Register on-prem instance as managed instance for persistent hybrid access. DESTRUCTIVE.",
    required_permissions=["ssm:CreateActivation", "ssm:DescribeActivations", "ssm:RegisterManagedInstance", "ssm:DeregisterManagedInstance"],
    supported_services=["ssm"],
    mitre_techniques=["T1136.001", "T1505.003", "T1021.004"],
    tags=["ssm", "persist", "managed-instance", "hybrid", "destructive"],
    requires_confirmation=True,
    destructive=True,
))

# ==================== BACKDOOR MODULES ====================
register_module(ModuleMetadata(
    name="ssm_backdoor_maintenance_window",
    category=ModuleCategory.BACKDOOR,
    risk=ModuleRisk.HIGH,
    description="Create SSM Maintenance Window with malicious task for scheduled backdoor execution. DESTRUCTIVE.",
    required_permissions=["ssm:CreateMaintenanceWindow", "ssm:RegisterTaskWithMaintenanceWindow", "ssm:DescribeMaintenanceWindows", "lambda:InvokeFunction", "iam:PassRole"],
    supported_services=["ssm", "lambda", "iam"],
    mitre_techniques=["T1059.004", "T1505.003", "T1053.005", "T1611"],
    tags=["ssm", "backdoor", "maintenance-window", "scheduled", "covert", "destructive"],
    requires_confirmation=True,
    destructive=True,
))

register_module(ModuleMetadata(
    name="ssm_backdoor_session_manager",
    category=ModuleCategory.BACKDOOR,
    risk=ModuleRisk.HIGH,
    description="Configure Session Manager preferences for persistent shell access (port forwarding, RunAs). DESTRUCTIVE.",
    required_permissions=["ssm:UpdateDocument", "ssm:StartSession", "ssm:DescribeInstanceInformation", "ssm:GetConnectionStatus"],
    supported_services=["ssm"],
    mitre_techniques=["T1021.004", "T1505.003", "T1569.002", "T1571"],
    tags=["ssm", "backdoor", "session-manager", "port-forwarding", "covert", "destructive"],
    requires_confirmation=True,
    destructive=True,
))

register_module(ModuleMetadata(
    name="ssm_backdoor_distributor",
    category=ModuleCategory.BACKDOOR,
    risk=ModuleRisk.MEDIUM,
    description="Use Distributor to deploy malicious agent/package to managed instances. DESTRUCTIVE.",
    required_permissions=["ssm:CreateDocument", "ssm:SendCommand", "ssm:DescribeDocument", "ssm:ListDocuments"],
    supported_services=["ssm"],
    mitre_techniques=["T1059.004", "T1505.003", "T1195.002"],
    tags=["ssm", "backdoor", "distributor", "agent", "covert", "destructive"],
    requires_confirmation=True,
    destructive=True,
))

register_module(ModuleMetadata(
    name="ssm_backdoor_parameter_store_c2",
    category=ModuleCategory.BACKDOOR,
    risk=ModuleRisk.MEDIUM,
    description="Use Parameter Store as C2 channel (store commands in parameters, poll for updates).",
    required_permissions=["ssm:PutParameter", "ssm:GetParameter", "ssm:GetParametersByPath", "ssm:DescribeParameters"],
    supported_services=["ssm"],
    mitre_techniques=["T1102", "T1505.003", "T1027"],
    tags=["ssm", "backdoor", "parameter-store", "c2", "covert"],
    requires_confirmation=True,
))

# ==================== EXFIL MODULES ====================
# Parameter Store exfil is covered in exfil/__init__.py as parameter_store__exfil_parameters
# We'll reference that pattern here
register_module(ModuleMetadata(
    name="ssm_exfil_parameters",
    category=ModuleCategory.EXFIL,
    risk=ModuleRisk.HIGH,
    description="Extract SecureString parameters from SSM Parameter Store. DESTRUCTIVE.",
    required_permissions=["ssm:GetParameters", "ssm:GetParametersByPath", "ssm:DescribeParameters", "kms:Decrypt"],
    supported_services=["ssm", "kms"],
    mitre_techniques=["T1555.003", "T1530", "T1041"],
    tags=["ssm", "exfil", "parameters", "secrets", "credentials", "destructive"],
    requires_confirmation=True,
    destructive=True,
))

register_module(ModuleMetadata(
    name="ssm_exfil_documents",
    category=ModuleCategory.EXFIL,
    risk=ModuleRisk.MEDIUM,
    description="Extract SSM documents for automation/workflow analysis.",
    required_permissions=["ssm:GetDocument", "ssm:ListDocuments", "ssm:DescribeDocument"],
    supported_services=["ssm"],
    mitre_techniques=["T1530", "T1020", "T1526"],
    tags=["ssm", "exfil", "documents", "automation"],
    requires_confirmation=True,
))

register_module(ModuleMetadata(
    name="ssm_exfil_instance_info",
    category=ModuleCategory.EXFIL,
    risk=ModuleRisk.MEDIUM,
    description="Extract managed instance information (IP, platform, agent version, associations).",
    required_permissions=["ssm:DescribeInstanceInformation", "ssm:GetConnectionStatus", "ssm:ListComplianceItems"],
    supported_services=["ssm"],
    mitre_techniques=["T1530", "T1082", "T1526"],
    tags=["ssm", "exfil", "instance-info", "inventory"],
    requires_confirmation=True,
))

register_module(ModuleMetadata(
    name="ssm_exfil_inventory",
    category=ModuleCategory.EXFIL,
    risk=ModuleRisk.MEDIUM,
    description="Extract software inventory from managed instances.",
    required_permissions=["ssm:ListInventoryEntries", "ssm:GetInventory", "ssm:DescribeInstanceInformation"],
    supported_services=["ssm"],
    mitre_techniques=["T1530", "T1082", "T1526"],
    tags=["ssm", "exfil", "inventory", "software"],
    requires_confirmation=True,
))

register_module(ModuleMetadata(
    name="ssm_exfil_patch_baselines",
    category=ModuleCategory.EXFIL,
    risk=ModuleRisk.LOW,
    description="Extract patch baseline and compliance data for vulnerability analysis.",
    required_permissions=["ssm:DescribePatchBaselines", "ssm:GetPatchBaseline", "ssm:ListComplianceSummaries"],
    supported_services=["ssm"],
    mitre_techniques=["T1530", "T1020", "T1526"],
    tags=["ssm", "exfil", "patch-baselines", "vulnerability"],
    requires_confirmation=True,
))

# List all SSM modules
SSM_MODULES = [
    # Privesc
    "ssm_privesc_analysis", "ssm_privesc_document_analysis", "ssm_privesc_parameter_analysis",
    # Exploit
    "ssm_exploit_send_command", "ssm_exploit_start_automation_execution",
    "ssm_exploit_create_document", "ssm_exploit_put_parameter",
    "ssm_exploit_start_session", "ssm_exploit_create_association",
    # Persist
    "ssm_persist_parameter", "ssm_persist_document", "ssm_persist_association",
    "ssm_persist_automation", "ssm_persist_managed_instance",
    # Backdoor
    "ssm_backdoor_maintenance_window", "ssm_backdoor_session_manager",
    "ssm_backdoor_distributor", "ssm_backdoor_parameter_store_c2",
    # Exfil
    "ssm_exfil_parameters", "ssm_exfil_documents", "ssm_exfil_instance_info",
    "ssm_exfil_inventory", "ssm_exfil_patch_baselines",
]

__all__ = ["SSM_MODULES"]

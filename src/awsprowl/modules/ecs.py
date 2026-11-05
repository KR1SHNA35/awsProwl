"""
ECS Service Modules - All ECS-related features across categories

This module provides a unified interface for all ECS operations:
- enum: Enumeration (safe, read-only)
- privesc: Privilege escalation analysis
- exploit: Active exploitation
- persist: Persistence mechanisms
- backdoor: Covert access
"""

from awsprowl.modules import ModuleCategory, ModuleMetadata, ModuleRisk, register_module

# ==================== ENUM MODULES ====================
register_module(ModuleMetadata(
    name="ecs_enum_clusters",
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
    tags=["ecs", "enum", "clusters", "containers", "safe"],
    requires_confirmation=False,
))

# ==================== PRIVESC MODULES ====================
register_module(ModuleMetadata(
    name="ecs_privesc_analysis",
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
    tags=["ecs", "privesc", "containers", "analysis", "safe"],
    requires_confirmation=False,
))

# ==================== EXPLOIT MODULES ====================
register_module(ModuleMetadata(
    name="ecs_exploit_run_task",
    category=ModuleCategory.EXPLOIT,
    risk=ModuleRisk.HIGH,
    description="Run ECS task with custom task definition for container execution. DESTRUCTIVE.",
    required_permissions=["ecs:RunTask", "ecs:DescribeTasks", "ecs:RegisterTaskDefinition", "iam:PassRole"],
    supported_services=["ecs", "iam"],
    mitre_techniques=["T1059.004", "T1648.001"],
    tags=["ecs", "exploit", "run-task", "container", "code-execution", "destructive"],
    requires_confirmation=True,
    destructive=True,
))

register_module(ModuleMetadata(
    name="ecs_exploit_update_service",
    category=ModuleCategory.EXPLOIT,
    risk=ModuleRisk.HIGH,
    description="Update ECS service to deploy malicious task definition. DESTRUCTIVE.",
    required_permissions=["ecs:UpdateService", "ecs:DescribeServices", "ecs:RegisterTaskDefinition", "iam:PassRole"],
    supported_services=["ecs", "iam"],
    mitre_techniques=["T1059.004", "T1648.001", "T1556.002"],
    tags=["ecs", "exploit", "update-service", "destructive"],
    requires_confirmation=True,
    destructive=True,
))

register_module(ModuleMetadata(
    name="ecs_exploit_register_task_definition",
    category=ModuleCategory.EXPLOIT,
    risk=ModuleRisk.HIGH,
    description="Register malicious task definition with host networking/privileged mode. DESTRUCTIVE.",
    required_permissions=["ecs:RegisterTaskDefinition", "ecs:ListTaskDefinitions", "iam:PassRole"],
    supported_services=["ecs", "iam"],
    mitre_techniques=["T1059.004", "T1611", "T1648.001"],
    tags=["ecs", "exploit", "task-definition", "privileged", "destructive"],
    requires_confirmation=True,
    destructive=True,
))

register_module(ModuleMetadata(
    name="ecs_exploit_execute_command",
    category=ModuleCategory.EXPLOIT,
    risk=ModuleRisk.HIGH,
    description="Execute command in running ECS container (ECS Exec). DESTRUCTIVE.",
    required_permissions=["ecs:ExecuteCommand", "ecs:DescribeTasks", "ecs:ListTasks"],
    supported_services=["ecs"],
    mitre_techniques=["T1059.004", "T1648.001", "T1021.004"],
    tags=["ecs", "exploit", "exec-command", "container", "destructive"],
    requires_confirmation=True,
    destructive=True,
))

register_module(ModuleMetadata(
    name="ecs_exploit_create_cluster",
    category=ModuleCategory.EXPLOIT,
    risk=ModuleRisk.MEDIUM,
    description="Create ECS cluster for resource deployment. DESTRUCTIVE.",
    required_permissions=["ecs:CreateCluster", "ecs:DescribeClusters"],
    supported_services=["ecs"],
    mitre_techniques=["T1611"],
    tags=["ecs", "exploit", "create-cluster", "destructive"],
    requires_confirmation=True,
    destructive=True,
))

# ==================== PERSIST MODULES ====================
register_module(ModuleMetadata(
    name="ecs_persist_task_definition",
    category=ModuleCategory.PERSIST,
    risk=ModuleRisk.HIGH,
    description="Register task definition with backdoored container image for persistent deployment. DESTRUCTIVE.",
    required_permissions=["ecs:RegisterTaskDefinition", "ecs:ListTaskDefinitions", "ecs:DescribeTaskDefinition", "iam:PassRole"],
    supported_services=["ecs", "iam"],
    mitre_techniques=["T1059.004", "T1505.003", "T1611"],
    tags=["ecs", "persist", "task-definition", "container", "destructive"],
    requires_confirmation=True,
    destructive=True,
))

register_module(ModuleMetadata(
    name="ecs_persist_service",
    category=ModuleCategory.PERSIST,
    risk=ModuleRisk.HIGH,
    description="Create/update ECS service with malicious task definition for persistent execution. DESTRUCTIVE.",
    required_permissions=["ecs:CreateService", "ecs:UpdateService", "ecs:DescribeServices", "ecs:RegisterTaskDefinition", "iam:PassRole"],
    supported_services=["ecs", "iam"],
    mitre_techniques=["T1059.004", "T1505.003", "T1648.001"],
    tags=["ecs", "persist", "service", "container", "destructive"],
    requires_confirmation=True,
    destructive=True,
))

register_module(ModuleMetadata(
    name="ecs_persist_capacity_provider",
    category=ModuleCategory.PERSIST,
    risk=ModuleRisk.MEDIUM,
    description="Create capacity provider for persistent compute resources. DESTRUCTIVE.",
    required_permissions=["ecs:CreateCapacityProvider", "ecs:DescribeCapacityProviders", "ecs:PutClusterCapacityProviders"],
    supported_services=["ecs"],
    mitre_techniques=["T1611", "T1505.003"],
    tags=["ecs", "persist", "capacity-provider", "destructive"],
    requires_confirmation=True,
    destructive=True,
))

# ==================== BACKDOOR MODULES ====================
register_module(ModuleMetadata(
    name="ecs_backdoor_task_definition",
    category=ModuleCategory.BACKDOOR,
    risk=ModuleRisk.HIGH,
    description="Create task definition with hidden backdoor container (reverse shell, C2 agent). DESTRUCTIVE.",
    required_permissions=["ecs:RegisterTaskDefinition", "ecs:ListTaskDefinitions", "iam:PassRole"],
    supported_services=["ecs", "iam"],
    mitre_techniques=["T1059.004", "T1505.003", "T1648.001"],
    tags=["ecs", "backdoor", "task-definition", "container", "covert", "destructive"],
    requires_confirmation=True,
    destructive=True,
))

register_module(ModuleMetadata(
    name="ecs_backdoor_service_discovery",
    category=ModuleCategory.BACKDOOR,
    risk=ModuleRisk.MEDIUM,
    description="Use Cloud Map service discovery for covert C2 endpoint registration.",
    required_permissions=["servicediscovery:CreateService", "servicediscovery:RegisterInstance", "servicediscovery:ListServices", "ecs:CreateService"],
    supported_services=["ecs", "servicediscovery"],
    mitre_techniques=["T1505.003", "T1102"],
    tags=["ecs", "backdoor", "service-discovery", "c2", "covert"],
    requires_confirmation=True,
))

register_module(ModuleMetadata(
    name="ecs_backdoor_fargate_profile",
    category=ModuleCategory.BACKDOOR,
    risk=ModuleRisk.HIGH,
    description="Deploy Fargate task with hidden backdoor - serverless, no EC2 management. DESTRUCTIVE.",
    required_permissions=["ecs:RunTask", "ecs:RegisterTaskDefinition", "ecs:DescribeTasks", "iam:PassRole", "ec2:DescribeSubnets"],
    supported_services=["ecs", "iam", "ec2"],
    mitre_techniques=["T1059.004", "T1505.003", "T1648.001"],
    tags=["ecs", "backdoor", "fargate", "serverless", "covert", "destructive"],
    requires_confirmation=True,
    destructive=True,
))

# List all ECS modules
ECS_MODULES = [
    # Enum
    "ecs_enum_clusters",
    # Privesc
    "ecs_privesc_analysis",
    # Exploit
    "ecs_exploit_run_task", "ecs_exploit_update_service", "ecs_exploit_register_task_definition",
    "ecs_exploit_execute_command", "ecs_exploit_create_cluster",
    # Persist
    "ecs_persist_task_definition", "ecs_persist_service", "ecs_persist_capacity_provider",
    # Backdoor
    "ecs_backdoor_task_definition", "ecs_backdoor_service_discovery", "ecs_backdoor_fargate_profile",
]

__all__ = ["ECS_MODULES"]

"""
CodeBuild Service Modules - All CodeBuild-related features across categories

This module provides a unified interface for all CodeBuild operations:
- enum: Enumeration (safe, read-only)
- privesc: Privilege escalation analysis
- exploit: Active exploitation
"""

from awsprowl.modules import ModuleCategory, ModuleMetadata, ModuleRisk, register_module

# ==================== ENUM MODULES ====================
register_module(ModuleMetadata(
    name="codebuild_enum_projects",
    category=ModuleCategory.ENUM,
    risk=ModuleRisk.SAFE,
    description="Enumerate CodeBuild projects, builds, and configurations. PROWL: codebuild__enum.",
    required_permissions=[
        "codebuild:ListProjects", "codebuild:BatchGetProjects",
        "codebuild:ListBuilds", "codebuild:BatchGetBuilds",
        "codebuild:ListBuildsForProject", "codebuild:ListReportGroups"
    ],
    supported_services=["codebuild"],
    mitre_techniques=["T1526", "T1083"],
    tags=["codebuild", "enum", "projects", "ci-cd", "awsprowl"],
    requires_confirmation=False,
))

register_module(ModuleMetadata(
    name="codebuild_enum_build_details",
    category=ModuleCategory.ENUM,
    risk=ModuleRisk.SAFE,
    description="Enumerate detailed build information including environment variables, artifacts, and logs.",
    required_permissions=[
        "codebuild:BatchGetBuilds", "codebuild:ListBuildsForProject",
        "codebuild:ListReportsForReportGroup", "codebuild:BatchGetReports"
    ],
    supported_services=["codebuild"],
    mitre_techniques=["T1526", "T1083", "T1555.005"],
    tags=["codebuild", "enum", "builds", "details", "env-vars"],
    requires_confirmation=False,
))

# ==================== PRIVESC MODULES ====================
register_module(ModuleMetadata(
    name="codebuild_privesc_analysis",
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
    tags=["codebuild", "privesc", "ci-cd", "analysis", "safe"],
    requires_confirmation=False,
))

# ==================== EXPLOIT MODULES ====================
register_module(ModuleMetadata(
    name="codebuild_exploit_start_build",
    category=ModuleCategory.EXPLOIT,
    risk=ModuleRisk.HIGH,
    description="Start CodeBuild build with custom buildspec for code execution. DESTRUCTIVE.",
    required_permissions=["codebuild:StartBuild", "codebuild:BatchGetBuilds", "iam:PassRole"],
    supported_services=["codebuild", "iam"],
    mitre_techniques=["T1059.004", "T1648"],
    tags=["codebuild", "exploit", "start-build", "code-execution", "destructive"],
    requires_confirmation=True,
    destructive=True,
))

register_module(ModuleMetadata(
    name="codebuild_exploit_update_project",
    category=ModuleCategory.EXPLOIT,
    risk=ModuleRisk.HIGH,
    description="Update CodeBuild project with malicious buildspec/environment. DESTRUCTIVE.",
    required_permissions=["codebuild:UpdateProject", "codebuild:BatchGetProjects", "iam:PassRole"],
    supported_services=["codebuild", "iam"],
    mitre_techniques=["T1059.004", "T1648", "T1556.002"],
    tags=["codebuild", "exploit", "update-project", "destructive"],
    requires_confirmation=True,
    destructive=True,
))

register_module(ModuleMetadata(
    name="codebuild_exploit_create_webhook",
    category=ModuleCategory.EXPLOIT,
    risk=ModuleRisk.MEDIUM,
    description="Create webhook for CodeBuild project to trigger builds on repo events. DESTRUCTIVE.",
    required_permissions=["codebuild:CreateWebhook", "codebuild:BatchGetProjects"],
    supported_services=["codebuild"],
    mitre_techniques=["T1190", "T1648"],
    tags=["codebuild", "exploit", "webhook", "destructive"],
    requires_confirmation=True,
    destructive=True,
))

# List all CodeBuild modules
CODEBUILD_MODULES = [
    # Enum
    "codebuild_enum_projects", "codebuild_enum_build_details",
    # Privesc
    "codebuild_privesc_analysis",
    # Exploit
    "codebuild_exploit_start_build", "codebuild_exploit_update_project", "codebuild_exploit_create_webhook",
]

__all__ = ["CODEBUILD_MODULES"]
"""
ECR (Elastic Container Registry) Service Modules - All ECR-related features

This module provides a unified interface for all ECR operations:
- enum: Enumeration (safe, read-only)
- exfil: Data exfiltration
"""

from awsprowl.modules import ModuleCategory, ModuleMetadata, ModuleRisk, register_module

# ==================== ENUM MODULES ====================
register_module(ModuleMetadata(
    name="ecr_enum_repositories",
    category=ModuleCategory.ENUM,
    risk=ModuleRisk.SAFE,
    description="Enumerate ECR repositories, images, and scan findings. PROWL: ecr__enum.",
    required_permissions=[
        "ecr:DescribeRepositories", "ecr:ListImages",
        "ecr:DescribeImages", "ecr:DescribeImageScanFindings",
        "ecr:GetLifecyclePolicy", "ecr:GetRepositoryPolicy"
    ],
    supported_services=["ecr"],
    mitre_techniques=["T1526", "T1083"],
    tags=["ecr", "enum", "repositories", "images", "scan-findings", "awsprowl"],
    requires_confirmation=False,
))

register_module(ModuleMetadata(
    name="ecr_enum_pull_through_cache",
    category=ModuleCategory.ENUM,
    risk=ModuleRisk.SAFE,
    description="Enumerate ECR pull-through cache rules.",
    required_permissions=[
        "ecr:DescribePullThroughCacheRules"
    ],
    supported_services=["ecr"],
    mitre_techniques=["T1526", "T1083"],
    tags=["ecr", "enum", "pull-through-cache", "safe"],
    requires_confirmation=False,
))

# ==================== EXFIL MODULES ====================
register_module(ModuleMetadata(
    name="ecr_exfil_pull_images",
    category=ModuleCategory.EXFIL,
    risk=ModuleRisk.HIGH,
    description="Pull ECR container images for analysis/extraction. PROWL: ecr__exfil_images (partial). DESTRUCTIVE.",
    required_permissions=["ecr:BatchGetImage", "ecr:GetDownloadUrlForLayer", "ecr:ListImages", "ecr:DescribeRepositories", "ecr:BatchCheckLayerAvailability"],
    supported_services=["ecr"],
    mitre_techniques=["T1530", "T1020", "T1610"],
    tags=["ecr", "exfil", "images", "container", "awsprowl", "destructive"],
    requires_confirmation=True,
    destructive=True,
))

# List all ECR modules
ECR_MODULES = [
    # Enum
    "ecr_enum_repositories", "ecr_enum_pull_through_cache",
    # Exfil
    "ecr_exfil_pull_images",
]

__all__ = ["ECR_MODULES"]
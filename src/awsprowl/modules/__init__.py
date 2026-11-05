"""
awsProwl Modules - Organized by Category (Prowler-inspired)

Module Categories:
- enum: Enumeration/Scanning (read-only, safe)
- privesc: Privilege Escalation Detection & Analysis
- exploit: Active Exploitation (requires authorization)
- persist: Persistence Mechanisms
- backdoor: Backdoor Creation
- exfil: Data Exfiltration
"""

from dataclasses import dataclass, field
from enum import Enum
from typing import Any


class ModuleCategory(Enum):
    """Module category - determines safety level and required authorization."""
    ENUM = "enum"           # Read-only enumeration, safe
    PRIVESC = "privesc"     # Privilege escalation detection
    EXPLOIT = "exploit"     # Active exploitation
    PERSIST = "persist"     # Persistence mechanisms
    BACKDOOR = "backdoor"   # Backdoor creation
    EXFIL = "exfil"         # Data exfiltration


class ModuleRisk(Enum):
    """Module risk level."""
    SAFE = "safe"           # Read-only, no state changes
    LOW = "low"             # Minor state changes, easily reversible
    MEDIUM = "medium"       # Moderate impact, requires cleanup
    HIGH = "high"           # Significant impact, hard to reverse
    CRITICAL = "critical"   # Severe impact, may require incident response


@dataclass
class ModuleMetadata:
    """Metadata for a module."""
    name: str
    category: ModuleCategory
    risk: ModuleRisk
    description: str
    required_permissions: list[str] = field(default_factory=list)
    supported_services: list[str] = field(default_factory=list)
    mitre_techniques: list[str] = field(default_factory=list)
    requires_confirmation: bool = True
    destructive: bool = False
    tags: list[str] = field(default_factory=list)


# Module registry
MODULE_REGISTRY: dict[str, ModuleMetadata] = {}

def register_module(metadata: ModuleMetadata) -> None:
    """Register a module in the registry."""
    MODULE_REGISTRY[metadata.name] = metadata

def get_module(name: str) -> ModuleMetadata | None:
    """Get module metadata by name."""
    return MODULE_REGISTRY.get(name)

def list_modules(category: ModuleCategory | None = None) -> list[ModuleMetadata]:
    """List all modules, optionally filtered by category."""
    if category:
        return [m for m in MODULE_REGISTRY.values() if m.category == category]
    return list(MODULE_REGISTRY.values())

def list_categories() -> list[ModuleCategory]:
    """List all available categories."""
    return list(ModuleCategory)

def get_modules_by_service(service: str) -> list[ModuleMetadata]:
    """Get all modules for a specific service (e.g., 'iam', 'ec2')."""
    return [m for m in MODULE_REGISTRY.values() if service in m.supported_services]

def get_modules_by_service_and_category(service: str, category: ModuleCategory) -> list[ModuleMetadata]:
    """Get all modules for a specific service and category."""
    return [m for m in MODULE_REGISTRY.values()
            if service in m.supported_services and m.category == category]

def search_modules(query: str, category: ModuleCategory | None = None, service: str | None = None) -> list[ModuleMetadata]:
    """Search modules by name, description, or tags."""
    query_lower = query.lower()
    results = []
    for module in MODULE_REGISTRY.values():
        if category and module.category != category:
            continue
        if service and service not in module.supported_services:
            continue
        if (query_lower in module.name.lower() or
            query_lower in module.description.lower() or
            any(query_lower in tag.lower() for tag in module.tags)):
            results.append(module)
    return results


# Import all service modules to register their modules
# This must be at the end to avoid circular imports
from awsprowl.modules import (
    iam,
    ec2,
    s3,
    lambda_,
    sts,
    rds,
    dynamodb,
    ecs,
    eks,
    secretsmanager,
    cloudformation,
    cloudtrail,
    kms,
    ssm,
    organizations,
    apigateway,
    codebuild,
    elasticbeanstalk,
    elb,
    transfer,
    vpc,
    waf,
    ds,
    lightsail,
    sns,
    acm,
    ecr,
    cloudwatch,
    detection,
    ssm_extended,
    cognito,
    cloudfront,
)

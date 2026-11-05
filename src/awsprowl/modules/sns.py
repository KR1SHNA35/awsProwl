"""
SNS Service Modules - All SNS-related features

This module provides a unified interface for all SNS operations:
- enum: Enumeration (safe, read-only)
- exploit: Active exploitation
"""

from awsprowl.modules import ModuleCategory, ModuleMetadata, ModuleRisk, register_module

# ==================== ENUM MODULES ====================
register_module(ModuleMetadata(
    name="sns_enum_topics",
    category=ModuleCategory.ENUM,
    risk=ModuleRisk.SAFE,
    description="Enumerate SNS topics, subscriptions, and platform applications.",
    required_permissions=[
        "sns:ListTopics", "sns:GetTopicAttributes",
        "sns:ListSubscriptions", "sns:ListSubscriptionsByTopic",
        "sns:ListPlatformApplications", "sns:GetPlatformApplicationAttributes"
    ],
    supported_services=["sns"],
    mitre_techniques=["T1083", "T1526"],
    tags=["sns", "enum", "topics", "subscriptions", "safe"],
    requires_confirmation=False,
))

# ==================== EXPLOIT MODULES ====================
register_module(ModuleMetadata(
    name="sns_exploit_subscribe",
    category=ModuleCategory.EXPLOIT,
    risk=ModuleRisk.HIGH,
    description="Subscribe attacker endpoint to SNS topic for message interception. PROWL: sns__subscribe. DESTRUCTIVE.",
    required_permissions=["sns:Subscribe", "sns:ListSubscriptions", "sns:GetTopicAttributes"],
    supported_services=["sns"],
    mitre_techniques=["T1114.001", "T1098"],
    tags=["sns", "exploit", "subscribe", "message-interception", "awsprowl", "destructive"],
    requires_confirmation=True,
    destructive=True,
))

register_module(ModuleMetadata(
    name="sns_exploit_publish",
    category=ModuleCategory.EXPLOIT,
    risk=ModuleRisk.MEDIUM,
    description="Publish message to SNS topic for notification spam or command injection. DESTRUCTIVE.",
    required_permissions=["sns:Publish", "sns:GetTopicAttributes"],
    supported_services=["sns"],
    mitre_techniques=["T1499", "T1190"],
    tags=["sns", "exploit", "publish", "notification-spam", "destructive"],
    requires_confirmation=True,
    destructive=True,
))

register_module(ModuleMetadata(
    name="sns_exploit_create_topic",
    category=ModuleCategory.EXPLOIT,
    risk=ModuleRisk.MEDIUM,
    description="Create SNS topic for malicious notification routing. DESTRUCTIVE.",
    required_permissions=["sns:CreateTopic", "sns:SetTopicAttributes", "sns:Subscribe"],
    supported_services=["sns"],
    mitre_techniques=["T1505.003", "T1114.001"],
    tags=["sns", "exploit", "create-topic", "destructive"],
    requires_confirmation=True,
    destructive=True,
))

# List all SNS modules
SNS_MODULES = [
    # Enum
    "sns_enum_topics",
    # Exploit
    "sns_exploit_subscribe", "sns_exploit_publish", "sns_exploit_create_topic",
]

__all__ = ["SNS_MODULES"]
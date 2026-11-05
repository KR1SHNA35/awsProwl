"""
WAF (Web Application Firewall) Service Modules - All WAF-related features

This module provides a unified interface for all WAF operations:
- enum: Enumeration (safe, read-only)
"""

from awsprowl.modules import ModuleCategory, ModuleMetadata, ModuleRisk, register_module

# ==================== ENUM MODULES ====================
register_module(ModuleMetadata(
    name="waf_enum_web_acls",
    category=ModuleCategory.ENUM,
    risk=ModuleRisk.SAFE,
    description="Enumerate WAF Web ACLs (Classic and v2). PROWL: waf__enum.",
    required_permissions=[
        "waf:ListWebACLs", "waf:GetWebACL",
        "wafv2:ListWebACLs", "wafv2:GetWebACL",
        "wafv2:ListResourcesForWebACL"
    ],
    supported_services=["waf", "wafv2"],
    mitre_techniques=["T1526", "T1083"],
    tags=["waf", "enum", "web-acls", "wafv2", "awsprowl"],
    requires_confirmation=False,
))

register_module(ModuleMetadata(
    name="waf_enum_rules",
    category=ModuleCategory.ENUM,
    risk=ModuleRisk.SAFE,
    description="Enumerate WAF rules, rule groups, and IP sets.",
    required_permissions=[
        "waf:ListRules", "waf:GetRule", "waf:ListRuleGroups", "waf:GetRuleGroup",
        "wafv2:ListRuleGroups", "wafv2:GetRuleGroup", "wafv2:ListIPSets", "wafv2:GetIPSet"
    ],
    supported_services=["waf", "wafv2"],
    mitre_techniques=["T1526", "T1083"],
    tags=["waf", "enum", "rules", "rule-groups", "ip-sets", "safe"],
    requires_confirmation=False,
))

register_module(ModuleMetadata(
    name="waf_enum_logging",
    category=ModuleCategory.ENUM,
    risk=ModuleRisk.SAFE,
    description="Enumerate WAF logging configuration.",
    required_permissions=[
        "wafv2:GetLoggingConfiguration", "wafv2:ListWebACLs"
    ],
    supported_services=["wafv2"],
    mitre_techniques=["T1526", "T1530"],
    tags=["waf", "enum", "logging", "safe"],
    requires_confirmation=False,
))

# ==================== EXPLOIT MODULES ====================
register_module(ModuleMetadata(
    name="waf_exploit_update_ip_set",
    category=ModuleCategory.EXPLOIT,
    risk=ModuleRisk.MEDIUM,
    description="Update WAF IP set to allow attacker IPs. DESTRUCTIVE.",
    required_permissions=["wafv2:UpdateIPSet", "wafv2:GetIPSet", "wafv2:ListIPSets"],
    supported_services=["wafv2"],
    mitre_techniques=["T1562.007", "T1098"],
    tags=["waf", "exploit", "ip-set", "destructive"],
    requires_confirmation=True,
    destructive=True,
))

register_module(ModuleMetadata(
    name="waf_exploit_update_rule_group",
    category=ModuleCategory.EXPLOIT,
    risk=ModuleRisk.HIGH,
    description="Update WAF rule group to disable/modify protective rules. DESTRUCTIVE.",
    required_permissions=["wafv2:UpdateRuleGroup", "wafv2:GetRuleGroup", "wafv2:ListRuleGroups"],
    supported_services=["wafv2"],
    mitre_techniques=["T1562.001", "T1098"],
    tags=["waf", "exploit", "rule-group", "destructive"],
    requires_confirmation=True,
    destructive=True,
))

# List all WAF modules
WAF_MODULES = [
    # Enum
    "waf_enum_web_acls", "waf_enum_rules", "waf_enum_logging",
    # Exploit
    "waf_exploit_update_ip_set", "waf_exploit_update_rule_group",
]

__all__ = ["WAF_MODULES"]
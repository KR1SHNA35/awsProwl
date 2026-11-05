"""
Detection Service Modules - Detection evasion/disruption (GuardDuty, CloudTrail, Config, Security Hub)

This module provides detection evasion capabilities:
- persist: Persistence via detection disruption
- exfil: Data exfiltration via detection services
- exploit: Active exploitation of detection services
"""

from awsprowl.modules import ModuleCategory, ModuleMetadata, ModuleRisk, register_module

# ==================== ENUM MODULES ====================
register_module(ModuleMetadata(
    name="detection_enum_services",
    category=ModuleCategory.ENUM,
    risk=ModuleRisk.SAFE,
    description="Enumerate AWS detection services: GuardDuty, Security Hub, Inspector, Macie, Detective. PROWL: detection__enum_services.",
    required_permissions=[
        "guardduty:ListDetectors", "guardduty:GetDetector",
        "securityhub:DescribeHub", "securityhub:ListEnabledProductsForImport",
        "inspector:ListAssessmentTemplates", "inspector:ListAssessmentTargets",
        "macie2:GetMacieSession", "macie2:ListClassificationJobs",
        "detective:ListGraphs", "detective:ListMembers"
    ],
    supported_services=["guardduty", "securityhub", "inspector", "macie", "detective"],
    mitre_techniques=["T1526", "T1082"],
    tags=["detection", "enum", "guardduty", "securityhub", "inspector", "macie", "awsprowl"],
    requires_confirmation=False,
))

# ==================== PERSIST MODULES (Detection Disruption) ====================
register_module(ModuleMetadata(
    name="detection_persist_disrupt_guardduty",
    category=ModuleCategory.PERSIST,
    risk=ModuleRisk.CRITICAL,
    description="Disrupt GuardDuty by deleting detector, disabling findings, or whitelisting IPs. PROWL: detection__disruption (GuardDuty). CRITICAL - destroys threat detection.",
    required_permissions=[
        "guardduty:DeleteDetector", "guardduty:UpdateDetector", "guardduty:ListDetectors",
        "guardduty:CreateThreatIntelSet", "guardduty:DeleteThreatIntelSet",
        "guardduty:UpdateThreatIntelSet", "guardduty:ListThreatIntelSets"
    ],
    supported_services=["guardduty"],
    mitre_techniques=["T1562.001", "T1562.008", "T1036.005"],
    tags=["detection", "persist", "guardduty", "disruption", "defense-evasion", "awsprowl", "destructive"],
    requires_confirmation=True,
    destructive=True,
))

register_module(ModuleMetadata(
    name="detection_persist_disrupt_cloudtrail",
    category=ModuleCategory.PERSIST,
    risk=ModuleRisk.CRITICAL,
    description="Disrupt CloudTrail by stopping logging, deleting trails, or modifying event selectors. PROWL: detection__disruption (CloudTrail). CRITICAL.",
    required_permissions=[
        "cloudtrail:StopLogging", "cloudtrail:DeleteTrail", "cloudtrail:UpdateTrail",
        "cloudtrail:PutEventSelectors", "cloudtrail:DescribeTrails"
    ],
    supported_services=["cloudtrail"],
    mitre_techniques=["T1562.008", "T1562.001", "T1070.001"],
    tags=["detection", "persist", "cloudtrail", "disruption", "defense-evasion", "awsprowl", "destructive"],
    requires_confirmation=True,
    destructive=True,
))

register_module(ModuleMetadata(
    name="detection_persist_disrupt_config",
    category=ModuleCategory.PERSIST,
    risk=ModuleRisk.HIGH,
    description="Disrupt AWS Config by stopping recorder, deleting delivery channel, or modifying rules. PROWL: detection__disruption (Config). DESTRUCTIVE.",
    required_permissions=[
        "config:StopConfigurationRecorder", "config:DeleteConfigurationRecorder",
        "config:DeleteDeliveryChannel", "config:PutConfigRule", "config:DeleteConfigRule",
        "config:DescribeConfigurationRecorders"
    ],
    supported_services=["config"],
    mitre_techniques=["T1562.008", "T1562.001"],
    tags=["detection", "persist", "config", "disruption", "defense-evasion", "awsprowl", "destructive"],
    requires_confirmation=True,
    destructive=True,
))

register_module(ModuleMetadata(
    name="detection_persist_disrupt_securityhub",
    category=ModuleCategory.PERSIST,
    risk=ModuleRisk.HIGH,
    description="Disable Security Hub to reduce security visibility. PROWL: detection__disruption (Security Hub). DESTRUCTIVE.",
    required_permissions=[
        "securityhub:DisableSecurityHub", "securityhub:DescribeHub",
        "securityhub:BatchDisableStandards", "securityhub:BatchEnableStandards"
    ],
    supported_services=["securityhub"],
    mitre_techniques=["T1562.001", "T1562.008"],
    tags=["detection", "persist", "securityhub", "disruption", "defense-evasion", "awsprowl", "destructive"],
    requires_confirmation=True,
    destructive=True,
))

register_module(ModuleMetadata(
    name="detection_persist_guardduty_whitelist_ip",
    category=ModuleCategory.PERSIST,
    risk=ModuleRisk.HIGH,
    description="Add IP to GuardDuty threat intel set whitelist to suppress findings. PROWL: guardduty__whitelist_ip. DESTRUCTIVE.",
    required_permissions=[
        "guardduty:CreateThreatIntelSet", "guardduty:UpdateThreatIntelSet",
        "guardduty:ListThreatIntelSets", "guardduty:GetThreatIntelSet"
    ],
    supported_services=["guardduty"],
    mitre_techniques=["T1562.001", "T1562.008"],
    tags=["detection", "persist", "guardduty", "whitelist", "threat-intel", "awsprowl", "destructive"],
    requires_confirmation=True,
    destructive=True,
))

# ==================== EXFIL MODULES ====================
register_module(ModuleMetadata(
    name="detection_exfil_guardduty_findings",
    category=ModuleCategory.EXFIL,
    risk=ModuleRisk.HIGH,
    description="Extract GuardDuty findings for reconnaissance. PROWL: guardduty__list_findings. DESTRUCTIVE.",
    required_permissions=[
        "guardduty:ListFindings", "guardduty:GetFindings", "guardduty:ListDetectors"
    ],
    supported_services=["guardduty"],
    mitre_techniques=["T1530", "T1020", "T1041"],
    tags=["detection", "exfil", "guardduty", "findings", "awsprowl", "destructive"],
    requires_confirmation=True,
    destructive=True,
))

register_module(ModuleMetadata(
    name="detection_exfil_inspector_reports",
    category=ModuleCategory.EXFIL,
    risk=ModuleRisk.MEDIUM,
    description="Download Inspector assessment reports. PROWL: inspector__get_reports.",
    required_permissions=[
        "inspector:GetAssessmentReport", "inspector:ListAssessmentRuns",
        "inspector:ListAssessmentTemplates"
    ],
    supported_services=["inspector"],
    mitre_techniques=["T1530", "T1020"],
    tags=["detection", "exfil", "inspector", "reports", "awsprowl"],
    requires_confirmation=True,
))

register_module(ModuleMetadata(
    name="detection_exfil_guardduty_accounts",
    category=ModuleCategory.EXFIL,
    risk=ModuleRisk.MEDIUM,
    description="List GuardDuty member accounts in organization. PROWL: guardduty__list_accounts.",
    required_permissions=[
        "guardduty:ListMembers", "guardduty:ListDetectors"
    ],
    supported_services=["guardduty"],
    mitre_techniques=["T1530", "T1020", "T1526"],
    tags=["detection", "exfil", "guardduty", "accounts", "awsprowl"],
    requires_confirmation=True,
))

# List all Detection modules
DETECTION_MODULES = [
    # Enum
    "detection_enum_services",
    # Persist (Disruption)
    "detection_persist_disrupt_guardduty",
    "detection_persist_disrupt_cloudtrail",
    "detection_persist_disrupt_config",
    "detection_persist_disrupt_securityhub",
    "detection_persist_guardduty_whitelist_ip",
    # Exfil
    "detection_exfil_guardduty_findings",
    "detection_exfil_inspector_reports",
    "detection_exfil_guardduty_accounts",
]

__all__ = ["DETECTION_MODULES"]
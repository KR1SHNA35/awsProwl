"""Analysis modules for awsProwl."""

from awsprowl.analysis.analytics_scanner import AnalyticsScanner, RiskScore, SecurityMetric
from awsprowl.analysis.attack_path import (
    AttackEdge,
    AttackNode,
    AttackPath,
    AttackPathBuilder,
    create_attack_path_builder,
)
from awsprowl.analysis.cicd_scanner import CICDScanner, GitHubActionsScanner
from awsprowl.analysis.compliance import ComplianceAnalyzer, ComplianceControl, ComplianceResult
from awsprowl.analysis.findings import (
    Evidence,
    Finding,
    FindingCategory,
    FindingCollection,
    Remediation,
    ResourceType,
    Severity,
)
from awsprowl.analysis.network_analyzer import NetworkAnalyzer, NetworkExposure, NetworkPath
from awsprowl.analysis.privesc import PrivescAnalyzer, PrivescPath, create_privesc_analyzer
from awsprowl.analysis.secret_hunter import SecretHunter

__all__ = [
    # Findings
    "Severity",
    "FindingCategory",
    "ResourceType",
    "Evidence",
    "Remediation",
    "Finding",
    "FindingCollection",
    # Privilege Escalation
    "PrivescAnalyzer",
    "PrivescPath",
    "create_privesc_analyzer",
    # Attack Path
    "AttackNode",
    "AttackEdge",
    "AttackPath",
    "AttackPathBuilder",
    "create_attack_path_builder",
    # Compliance
    "ComplianceAnalyzer",
    "ComplianceControl",
    "ComplianceResult",
    # Network Analysis
    "NetworkAnalyzer",
    "NetworkExposure",
    "NetworkPath",
    # Secret Hunter
    "SecretHunter",
    # CI/CD Scanner
    "CICDScanner",
    "GitHubActionsScanner",
    # Analytics
    "AnalyticsScanner",
    "SecurityMetric",
    "RiskScore",
]

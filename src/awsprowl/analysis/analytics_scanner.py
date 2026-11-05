"""Analytics scanner module for awsProwl."""

from __future__ import annotations

import asyncio
from collections import defaultdict
from dataclasses import dataclass
from datetime import datetime, timedelta

import botocore.exceptions

from awsprowl.aws.base import AWSServiceBase, ScanResult
from awsprowl.core.auth import AWSAuthManager
from awsprowl.core.logging import get_logger

log = get_logger(__name__)


@dataclass
class SecurityMetric:
    """Represents a security metric."""
    name: str
    value: float
    unit: str
    trend: str  # improving, degrading, stable
    description: str
    severity: str


@dataclass
class RiskScore:
    """Risk score for an account/resource."""
    resource_id: str
    resource_type: str
    score: float  # 0-100
    factors: dict[str, float]
    level: str  # critical, high, medium, low


class AnalyticsScanner(AWSServiceBase):
    """Scanner for security analytics and risk scoring."""

    SERVICE_NAME = "analytics"
    REQUIRED_PERMISSIONS = [
        "cloudwatch:GetMetricStatistics",
        "cloudwatch:ListMetrics",
        "cloudtrail:LookupEvents",
        "config:ListDiscoveredResources",
        "config:GetComplianceDetailsByConfigRule",
        "securityhub:GetFindings",
        "securityhub:GetInsights",
        "guardduty:ListDetectors",
        "guardduty:GetFindings",
        "guardduty:GetFindingsStatistics",
        "accessanalyzer:ListAnalyzers",
        "accessanalyzer:GetAnalyzedResource",
        "accessanalyzer:ListFindings",
        "inspector2:ListFindings",
        "inspector2:GetFindingsStatistics",
    ]

    def __init__(self, auth_manager: AWSAuthManager, region: str | None = None):
        super().__init__(auth_manager, region)

    async def scan(self, scan_id: str, findings: list, scan_data: dict = None) -> ScanResult:
        """Scan for security analytics and compute risk scores."""
        result = ScanResult(service=self.SERVICE_NAME, region=self.region)

        try:
            self.scan_data = scan_data or {}
            await asyncio.gather(
                self._compute_risk_scores(scan_id, findings, result),
                self._analyze_guardduty(scan_id, findings, result),
                self._analyze_security_hub(scan_id, findings, result),
                self._analyze_access_analyzer(scan_id, findings, result),
                self._analyze_inspector(scan_id, findings, result),
                self._analyze_config_compliance(scan_id, findings, result),
                self._generate_security_metrics(scan_id, findings, result),
                return_exceptions=True,
            )

        except Exception as e:
            log.error("Error in analytics scan: {}", e)
            result.errors.append(str(e))

        return result

    async def _compute_risk_scores(self, scan_id: str, findings: list, result: ScanResult) -> None:
        """Compute risk scores for resources based on findings."""
        # Group findings by resource
        resource_findings = defaultdict(list)
        for f in findings:
            resource_id = f.get("resource_id", "")
            resource_type = f.get("resource_type", "")
            if resource_id:
                resource_findings[(resource_type, resource_id)].append(f)

        # Calculate risk score for each resource
        for (resource_type, resource_id), res_findings in resource_findings.items():
            score = self._calculate_risk_score(res_findings)
            level = self._get_risk_level(score)

            factors = self._get_risk_factors(res_findings)

            # Add risk score as a finding
            findings.append(self.create_finding(
                title=f"Risk score for {resource_type} {resource_id}: {score:.1f}/100 ({level})",
                description=f"Computed risk score based on {len(res_findings)} findings",
                severity=level,
                category="risk_score",
                resource_type=resource_type,
                resource_id=resource_id,
                resource_name=resource_id,
                region=self.region,
                evidence=[{
                    "type": "risk_score",
                    "description": "Risk score computation",
                    "data": {
                        "score": score,
                        "level": level,
                        "finding_count": len(res_findings),
                        "factors": factors,
                    }
                }],
                rule_id=f"analytics_risk_score_{resource_type}",
            ))

            result.resources_found += 1

    def _calculate_risk_score(self, findings: list) -> float:
        """Calculate risk score from findings (0-100)."""
        if not findings:
            return 0.0

        severity_weights = {
            "critical": 25,
            "high": 15,
            "medium": 8,
            "low": 3,
            "info": 1,
        }

        category_weights = {
            "credential_exposure": 2.0,
            "data_exposure": 1.8,
            "network_exposure": 1.5,
            "excessive_permissions": 1.5,
            "encryption_missing": 1.3,
            "weak_configuration": 1.0,
            "logging_missing": 0.8,
            "data_loss_risk": 1.2,
            "cost_optimization": 0.3,
            "informational": 0.1,
        }

        total_score = 0.0
        for f in findings:
            severity = f.get("severity", "low")
            category = f.get("category", "weak_configuration")

            base = severity_weights.get(severity, 3)
            multiplier = category_weights.get(category, 1.0)

            total_score += base * multiplier

        # Cap at 100
        return min(total_score, 100.0)

    def _get_risk_level(self, score: float) -> str:
        """Get risk level from score."""
        if score >= 70:
            return "critical"
        if score >= 40:
            return "high"
        if score >= 20:
            return "medium"
        return "low"

    def _get_risk_factors(self, findings: list) -> dict[str, float]:
        """Get risk factors breakdown."""
        factors = defaultdict(float)
        for f in findings:
            severity = f.get("severity", "low")
            category = f.get("category", "weak_configuration")
            factors[f"{category}:{severity}"] += 1
        return dict(factors)

    async def _analyze_guardduty(self, scan_id: str, findings: list, result: ScanResult) -> None:
        """Analyze GuardDuty findings."""
        try:
            detectors = self.client.list_detectors().get("DetectorIds", [])
            for detector_id in detectors:
                result.resources_found += 1

                # Get finding statistics
                stats = self.client.get_findings_statistics(
                    DetectorId=detector_id,
                    FindingStatisticTypes=["COUNT_BY_SEVERITY"]
                )

                severity_counts = stats.get("FindingStatistics", {}).get("CountBySeverity", {})
                total_findings = sum(severity_counts.values())

                if total_findings > 0:
                    findings.append(self.create_finding(
                        title=f"GuardDuty detector {detector_id} has {total_findings} active findings",
                        description=f"Severity breakdown: {severity_counts}",
                        severity="high" if severity_counts.get("3.0", 0) > 0 else "medium",
                        category="threat_detection",
                        resource_type="guardduty_detector",
                        resource_id=detector_id,
                        resource_name=detector_id,
                        region=self.region,
                        evidence=[{"type": "guardduty_stats", "description": "GuardDuty finding statistics", "data": severity_counts}],
                        rule_id="analytics_guardduty_findings",
                    ))

                # Get recent high severity findings
                recent_findings = self.client.get_findings(
                    DetectorId=detector_id,
                    FindingCriteria={
                        "Criterion": {
                            "severity": {"Gte": 7},
                            "updatedAt": {"Gte": int((datetime.now() - timedelta(days=7)).timestamp())}
                        }
                    },
                    MaxResults=10
                )

                for gd_finding in recent_findings.get("Findings", []):
                    findings.append(self.create_finding(
                        title=f"GuardDuty: {gd_finding.get('Title', 'Unknown')}",
                        description=gd_finding.get("Description", ""),
                        severity=self._map_guardduty_severity(gd_finding.get("Severity", 0)),
                        category="threat_detection",
                        resource_type="guardduty_finding",
                        resource_id=gd_finding.get("Id", ""),
                        resource_name=gd_finding.get("Title", ""),
                        region=self.region,
                        evidence=[{"type": "guardduty_finding", "description": "GuardDuty finding details", "data": gd_finding}],
                        rule_id="analytics_guardduty_finding",
                    ))

        except botocore.exceptions.ClientError as e:
            if e.response["Error"]["Code"] != "AccessDenied":
                self.handle_client_error(e, "GuardDuty")

    async def _analyze_security_hub(self, scan_id: str, findings: list, result: ScanResult) -> None:
        """Analyze Security Hub findings."""
        try:
            # Get Security Hub insights
            insights = self.client.get_insights().get("Insights", [])
            for insight in insights[:5]:  # Top 5 insights
                result.resources_found += 1
                findings.append(self.create_finding(
                    title=f"Security Hub Insight: {insight.get('Name', '')}",
                    description=insight.get("Filters", {}),
                    severity="info",
                    category="security_posture",
                    resource_type="securityhub_insight",
                    resource_id=insight.get("InsightArn", ""),
                    resource_name=insight.get("Name", ""),
                    region=self.region,
                    rule_id="analytics_securityhub_insight",
                ))

            # Get recent findings
            recent = self.client.get_findings(
                Filters={
                    "RecordState": [{"Value": "ACTIVE", "Comparison": "EQUALS"}],
                    "SeverityLabel": [{"Value": "CRITICAL", "Comparison": "EQUALS"},
                                      {"Value": "HIGH", "Comparison": "EQUALS"}],
                    "UpdatedAt": [{"Start": (datetime.now() - timedelta(days=7)).isoformat()}]
                },
                MaxResults=20
            )

            for sh_finding in recent.get("Findings", []):
                findings.append(self.create_finding(
                    title=f"Security Hub: {sh_finding.get('Title', 'Unknown')}",
                    description=sh_finding.get("Description", ""),
                    severity=sh_finding.get("Severity", {}).get("Label", "MEDIUM").lower(),
                    category="security_posture",
                    resource_type="securityhub_finding",
                    resource_id=sh_finding.get("Id", ""),
                    resource_name=sh_finding.get("Title", ""),
                    region=self.region,
                    evidence=[{"type": "securityhub_finding", "description": "Security Hub finding", "data": sh_finding}],
                    rule_id="analytics_securityhub_finding",
                ))

        except botocore.exceptions.ClientError as e:
            if e.response["Error"]["Code"] != "AccessDenied":
                self.handle_client_error(e, "SecurityHub")

    async def _analyze_access_analyzer(self, scan_id: str, findings: list, result: ScanResult) -> None:
        """Analyze IAM Access Analyzer findings."""
        try:
            analyzers = self.client.list_analyzers(type="ACCOUNT").get("analyzers", [])
            for analyzer in analyzers:
                analyzer_name = analyzer["name"]
                analyzer_arn = analyzer["arn"]
                result.resources_found += 1

                # Get findings
                aa_findings = self.client.list_findings(analyzerArn=analyzer_arn, maxResults=50)
                for aa_finding in aa_findings.get("findings", []):
                    if aa_finding.get("status") == "ACTIVE":
                        findings.append(self.create_finding(
                            title=f"Access Analyzer: {aa_finding.get('findingType', 'Unknown')} - {aa_finding.get('resource', '')}",
                            description=f"Resource {aa_finding.get('resource')} shared with {aa_finding.get('principal', {})}",
                            severity=self._map_access_analyzer_severity(aa_finding),
                            category="excessive_permissions",
                            resource_type="accessanalyzer_finding",
                            resource_id=aa_finding.get("id", ""),
                            resource_name=aa_finding.get("resource", ""),
                            region=self.region,
                            evidence=[{"type": "accessanalyzer_finding", "description": "IAM Access Analyzer finding", "data": aa_finding}],
                            rule_id="analytics_accessanalyzer_finding",
                        ))

        except botocore.exceptions.ClientError as e:
            if e.response["Error"]["Code"] != "AccessDenied":
                self.handle_client_error(e, "AccessAnalyzer")

    async def _analyze_inspector(self, scan_id: str, findings: list, result: ScanResult) -> None:
        """Analyze Inspector findings."""
        try:
            stats = self.client.get_findings_statistics(
                filterCriteria={
                    "severity": [{"comparison": "EQUALS", "value": "CRITICAL"}],
                    "findingStatus": [{"comparison": "EQUALS", "value": "ACTIVE"}]
                }
            )

            critical_count = stats.get("findingStatistics", {}).get("countBySeverity", {}).get("CRITICAL", 0)
            high_count = stats.get("findingStatistics", {}).get("countBySeverity", {}).get("HIGH", 0)

            if critical_count > 0 or high_count > 0:
                findings.append(self.create_finding(
                    title=f"Inspector has {critical_count} critical and {high_count} high severity findings",
                    description="Amazon Inspector detected vulnerabilities in your environment",
                    severity="critical" if critical_count > 0 else "high",
                    category="vulnerability",
                    resource_type="inspector",
                    resource_id="inspector",
                    resource_name="Amazon Inspector",
                    region=self.region,
                    evidence=[{"type": "inspector_stats", "description": "Inspector finding statistics", "data": stats}],
                    rule_id="analytics_inspector_findings",
                ))

        except botocore.exceptions.ClientError as e:
            if e.response["Error"]["Code"] != "AccessDenied":
                self.handle_client_error(e, "Inspector")

    async def _analyze_config_compliance(self, scan_id: str, findings: list, result: ScanResult) -> None:
        """Analyze Config compliance."""
        try:
            # Get compliance summary
            compliance = self.client.get_compliance_summary()
            non_compliant = compliance.get("ComplianceSummary", {}).get("NonCompliantResourceCount", {}).get("CappedCount", 0)

            if non_compliant > 0:
                findings.append(self.create_finding(
                    title=f"AWS Config reports {non_compliant} non-compliant resources",
                    description="Resources not compliant with Config rules",
                    severity="high",
                    category="compliance",
                    resource_type="config",
                    resource_id="config",
                    resource_name="AWS Config",
                    region=self.region,
                    evidence=[{"type": "config_compliance", "description": "Config compliance summary", "data": compliance}],
                    rule_id="analytics_config_noncompliant",
                ))

        except botocore.exceptions.ClientError as e:
            if e.response["Error"]["Code"] != "AccessDenied":
                self.handle_client_error(e, "Config")

    async def _generate_security_metrics(self, scan_id: str, findings: list, result: ScanResult) -> None:
        """Generate security metrics from findings."""
        metrics = []

        # Count findings by severity
        severity_counts = defaultdict(int)
        category_counts = defaultdict(int)
        service_counts = defaultdict(int)

        for f in findings:
            severity_counts[f.get("severity", "unknown")] += 1
            category_counts[f.get("category", "unknown")] += 1
            service_counts[f.get("resource_type", "unknown").split("_")[0]] += 1

        total_findings = sum(severity_counts.values())

        # Overall security posture metric
        critical_high = severity_counts.get("critical", 0) + severity_counts.get("high", 0)
        posture_score = max(0, 100 - (critical_high * 5) - (severity_counts.get("medium", 0) * 2) - (severity_counts.get("low", 0) * 0.5))

        metrics.append(SecurityMetric(
            name="Overall Security Posture",
            value=posture_score,
            unit="score",
            trend="stable",
            description=f"Security posture score based on {total_findings} findings",
            severity="critical" if posture_score < 30 else "high" if posture_score < 60 else "medium" if posture_score < 80 else "low",
        ))

        metrics.append(SecurityMetric(
            name="Critical Findings",
            value=severity_counts.get("critical", 0),
            unit="count",
            trend="stable",
            description="Number of critical severity findings",
            severity="critical" if severity_counts.get("critical", 0) > 0 else "low",
        ))

        metrics.append(SecurityMetric(
            name="High Findings",
            value=severity_counts.get("high", 0),
            unit="count",
            trend="stable",
            description="Number of high severity findings",
            severity="high" if severity_counts.get("high", 0) > 5 else "medium" if severity_counts.get("high", 0) > 0 else "low",
        ))

        metrics.append(SecurityMetric(
            name="Exposed Resources",
            value=category_counts.get("data_exposure", 0) + category_counts.get("network_exposure", 0),
            unit="count",
            trend="stable",
            description="Resources with data or network exposure",
            severity="high" if metrics[-1].value > 0 else "low",
        ))

        metrics.append(SecurityMetric(
            name="Credential Exposure",
            value=category_counts.get("credential_exposure", 0),
            unit="count",
            trend="stable",
            description="Potential credential exposure findings",
            severity="critical" if metrics[-1].value > 0 else "low",
        ))

        metrics.append(SecurityMetric(
            name="Unencrypted Resources",
            value=category_counts.get("encryption_missing", 0),
            unit="count",
            trend="stable",
            description="Resources missing encryption",
            severity="high" if metrics[-1].value > 10 else "medium" if metrics[-1].value > 0 else "low",
        ))

        # Store metrics in scan data for reporting
        self.scan_data["security_metrics"] = [self._metric_to_dict(m) for m in metrics]
        self.scan_data["finding_summary"] = {
            "by_severity": dict(severity_counts),
            "by_category": dict(category_counts),
            "by_service": dict(service_counts),
            "total": total_findings,
        }

    def _metric_to_dict(self, metric: SecurityMetric) -> dict:
        """Convert metric to dict."""
        return {
            "name": metric.name,
            "value": metric.value,
            "unit": metric.unit,
            "trend": metric.trend,
            "description": metric.description,
            "severity": metric.severity,
        }

    def _map_guardduty_severity(self, severity: float) -> str:
        """Map GuardDuty severity to our severity levels."""
        if severity >= 7:
            return "critical"
        if severity >= 4:
            return "high"
        if severity >= 1:
            return "medium"
        return "low"

    def _map_access_analyzer_severity(self, finding: dict) -> str:
        """Map Access Analyzer finding to severity."""
        finding_type = finding.get("findingType", "")
        if "ExternalPrincipal" in finding_type:
            return "high"
        if "UnusedPermission" in finding_type:
            return "medium"
        return "low"

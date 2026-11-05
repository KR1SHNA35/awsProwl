"""Compliance analysis module for awsProwl."""

from __future__ import annotations

from dataclasses import dataclass, field

from awsprowl.core.logging import get_logger

log = get_logger(__name__)


@dataclass
class ComplianceControl:
    """Represents a compliance control."""
    control_id: str
    title: str
    description: str
    framework: str
    severity: str
    category: str
    check_function: str  # Name of the function to run


@dataclass
class ComplianceResult:
    """Result of a compliance check."""
    control_id: str
    passed: bool
    severity: str
    evidence: list[dict] = field(default_factory=list)
    remediation: dict | None = None


class ComplianceAnalyzer:
    """Analyzes findings against compliance frameworks."""

    # CIS AWS Foundations Benchmark v1.5.0 controls
    CIS_CONTROLS = [
        ComplianceControl(
            control_id="CIS-1.1",
            title="Ensure no root account access key exists",
            description="Root account should not have access keys",
            framework="CIS",
            severity="critical",
            category="iam",
            check_function="check_root_access_keys",
        ),
        ComplianceControl(
            control_id="CIS-1.2",
            title="Ensure MFA is enabled for root account",
            description="Root account should have MFA enabled",
            framework="CIS",
            severity="critical",
            category="iam",
            check_function="check_root_mfa",
        ),
        ComplianceControl(
            control_id="CIS-1.3",
            title="Ensure MFA is enabled for all IAM users with console password",
            description="All IAM users with console access should have MFA",
            framework="CIS",
            severity="high",
            category="iam",
            check_function="check_iam_user_mfa",
        ),
        ComplianceControl(
            control_id="CIS-1.4",
            title="Ensure no IAM users have inline policies",
            description="IAM users should use managed policies instead of inline policies",
            framework="CIS",
            severity="medium",
            category="iam",
            check_function="check_iam_inline_policies",
        ),
        ComplianceControl(
            control_id="CIS-1.5",
            title="Ensure IAM password policy requires minimum length of 14",
            description="Password policy should require at least 14 characters",
            framework="CIS",
            severity="medium",
            category="iam",
            check_function="check_password_policy",
        ),
        ComplianceControl(
            control_id="CIS-1.6",
            title="Ensure IAM password policy requires rotation within 90 days",
            description="Passwords should expire within 90 days",
            framework="CIS",
            severity="medium",
            category="iam",
            check_function="check_password_rotation",
        ),
        ComplianceControl(
            control_id="CIS-1.7",
            title="Ensure IAM password policy prevents password reuse",
            description="Password policy should prevent reuse of last 24 passwords",
            framework="CIS",
            severity="medium",
            category="iam",
            check_function="check_password_reuse",
        ),
        ComplianceControl(
            control_id="CIS-1.8",
            title="Ensure MFA is enabled for all IAM users",
            description="All IAM users should have MFA enabled",
            framework="CIS",
            severity="high",
            category="iam",
            check_function="check_all_iam_user_mfa",
        ),
        ComplianceControl(
            control_id="CIS-2.1",
            title="Ensure CloudTrail is enabled in all regions",
            description="CloudTrail should be enabled and logging in all regions",
            framework="CIS",
            severity="high",
            category="logging",
            check_function="check_cloudtrail_enabled",
        ),
        ComplianceControl(
            control_id="CIS-2.2",
            title="Ensure CloudTrail log file validation is enabled",
            description="CloudTrail should have log file integrity validation enabled",
            framework="CIS",
            severity="medium",
            category="logging",
            check_function="check_cloudtrail_validation",
        ),
        ComplianceControl(
            control_id="CIS-2.3",
            title="Ensure CloudTrail logs are encrypted at rest using KMS",
            description="CloudTrail logs should be encrypted with KMS",
            framework="CIS",
            severity="high",
            category="encryption",
            check_function="check_cloudtrail_encryption",
        ),
        ComplianceControl(
            control_id="CIS-2.4",
            title="Ensure CloudTrail trails are integrated with CloudWatch Logs",
            description="CloudTrail should send logs to CloudWatch Logs",
            framework="CIS",
            severity="medium",
            category="logging",
            check_function="check_cloudtrail_cloudwatch",
        ),
        ComplianceControl(
            control_id="CIS-3.1",
            title="Ensure S3 bucket access logging is enabled",
            description="S3 buckets should have access logging enabled",
            framework="CIS",
            severity="medium",
            category="logging",
            check_function="check_s3_access_logging",
        ),
        ComplianceControl(
            control_id="CIS-3.2",
            title="Ensure S3 buckets have versioning enabled",
            description="S3 buckets should have versioning enabled",
            framework="CIS",
            severity="medium",
            category="data_protection",
            check_function="check_s3_versioning",
        ),
        ComplianceControl(
            control_id="CIS-3.3",
            title="Ensure S3 buckets have server-side encryption enabled",
            description="S3 buckets should have default encryption enabled",
            framework="CIS",
            severity="high",
            category="encryption",
            check_function="check_s3_encryption",
        ),
        ComplianceControl(
            control_id="CIS-3.4",
            title="Ensure S3 buckets are not publicly accessible",
            description="S3 buckets should block public access",
            framework="CIS",
            severity="critical",
            category="data_exposure",
            check_function="check_s3_public_access",
        ),
        ComplianceControl(
            control_id="CIS-4.1",
            title="Ensure VPC flow logging is enabled",
            description="VPC flow logs should be enabled for all VPCs",
            framework="CIS",
            severity="medium",
            category="logging",
            check_function="check_vpc_flow_logs",
        ),
        ComplianceControl(
            control_id="CIS-4.2",
            title="Ensure default security group restricts all traffic",
            description="Default security groups should deny all inbound/outbound",
            framework="CIS",
            severity="medium",
            category="network",
            check_function="check_default_sg",
        ),
        ComplianceControl(
            control_id="CIS-4.3",
            title="Ensure security groups don't allow unrestricted SSH access",
            description="Security groups should not allow 0.0.0.0/0 on port 22",
            framework="CIS",
            severity="high",
            category="network",
            check_function="check_sg_ssh",
        ),
        ComplianceControl(
            control_id="CIS-4.4",
            title="Ensure security groups don't allow unrestricted RDP access",
            description="Security groups should not allow 0.0.0.0/0 on port 3389",
            framework="CIS",
            severity="high",
            category="network",
            check_function="check_sg_rdp",
        ),
        ComplianceControl(
            control_id="CIS-5.1",
            title="Ensure RDS instances are not publicly accessible",
            description="RDS instances should not have public access enabled",
            framework="CIS",
            severity="critical",
            category="network",
            check_function="check_rds_public",
        ),
        ComplianceControl(
            control_id="CIS-5.2",
            title="Ensure RDS instances have encryption at rest enabled",
            description="RDS instances should have storage encryption enabled",
            framework="CIS",
            severity="high",
            category="encryption",
            check_function="check_rds_encryption",
        ),
        ComplianceControl(
            control_id="CIS-5.3",
            title="Ensure RDS instances have backup retention >= 7 days",
            description="RDS backup retention should be at least 7 days",
            framework="CIS",
            severity="medium",
            category="data_protection",
            check_function="check_rds_backup_retention",
        ),
        ComplianceControl(
            control_id="CIS-6.1",
            title="Ensure EBS volumes are encrypted",
            description="EBS volumes should be encrypted at rest",
            framework="CIS",
            severity="high",
            category="encryption",
            check_function="check_ebs_encryption",
        ),
        ComplianceControl(
            control_id="CIS-6.2",
            title="Ensure EBS snapshots are not public",
            description="EBS snapshots should not be publicly accessible",
            framework="CIS",
            severity="critical",
            category="data_exposure",
            check_function="check_ebs_snapshot_public",
        ),
    ]

    # AWS Foundational Security Best Practices
    FSBP_CONTROLS = [
        ComplianceControl(
            control_id="FSBP-IAM-1",
            title="IAM root user should not have access keys",
            description="Root user access keys pose a significant security risk",
            framework="FSBP",
            severity="critical",
            category="iam",
            check_function="check_root_access_keys",
        ),
        ComplianceControl(
            control_id="FSBP-IAM-2",
            title="MFA should be enabled for root user",
            description="Root user should have MFA enabled for additional security",
            framework="FSBP",
            severity="critical",
            category="iam",
            check_function="check_root_mfa",
        ),
        ComplianceControl(
            control_id="FSBP-S3-1",
            title="S3 buckets should block public access",
            description="S3 buckets should have public access blocked to prevent data exposure",
            framework="FSBP",
            severity="high",
            category="data_exposure",
            check_function="check_s3_public_access",
        ),
        ComplianceControl(
            control_id="FSBP-S3-2",
            title="S3 buckets should have default encryption",
            description="S3 buckets should have default encryption enabled",
            framework="FSBP",
            severity="high",
            category="encryption",
            check_function="check_s3_encryption",
        ),
        ComplianceControl(
            control_id="FSBP-EC2-1",
            title="EBS volumes should be encrypted",
            description="EBS volumes should be encrypted at rest",
            framework="FSBP",
            severity="high",
            category="encryption",
            check_function="check_ebs_encryption",
        ),
        ComplianceControl(
            control_id="FSBP-RDS-1",
            title="RDS instances should be encrypted",
            description="RDS instances should have encryption at rest enabled",
            framework="FSBP",
            severity="high",
            category="encryption",
            check_function="check_rds_encryption",
        ),
        ComplianceControl(
            control_id="FSBP-RDS-2",
            title="RDS instances should not be publicly accessible",
            description="RDS instances should not be publicly accessible from the internet",
            framework="FSBP",
            severity="critical",
            category="network",
            check_function="check_rds_public",
        ),
    ]

    def __init__(self, findings: list):
        self.findings = findings
        self.results: list[ComplianceResult] = []

    def run_compliance_check(self, framework: str = "CIS") -> list[ComplianceResult]:
        """Run compliance checks for a framework."""
        controls = self.CIS_CONTROLS if framework == "CIS" else self.FSBP_CONTROLS
        self.results = []

        for control in controls:
            check_func = getattr(self, control.check_function, None)
            if check_func:
                try:
                    passed, evidence = check_func()
                    self.results.append(ComplianceResult(
                        control_id=control.control_id,
                        passed=passed,
                        severity=control.severity,
                        evidence=evidence,
                    ))
                except Exception as e:
                    log.error("Error running compliance check {}: {}", control.control_id, e)
                    self.results.append(ComplianceResult(
                        control_id=control.control_id,
                        passed=False,
                        severity=control.severity,
                        evidence=[{"error": str(e)}],
                    ))

        return self.results

    def get_summary(self) -> dict:
        """Get compliance summary."""
        total = len(self.results)
        passed = sum(1 for r in self.results if r.passed)
        failed = total - passed

        by_severity = {}
        for r in self.results:
            if not r.passed:
                by_severity[r.severity] = by_severity.get(r.severity, 0) + 1

        return {
            "total_controls": total,
            "passed": passed,
            "failed": failed,
            "compliance_score": round((passed / total * 100) if total > 0 else 0, 1),
            "by_severity": by_severity,
        }

    # Check functions - these look at findings to determine compliance

    def check_root_access_keys(self) -> tuple[bool, list]:
        """Check if root account has access keys."""
        for f in self.findings:
            if f.get("rule_id") == "iam_root_access_keys":
                return False, [{"finding": f.get("title"), "resource": f.get("resource_id")}]
        return True, []

    def check_root_mfa(self) -> tuple[bool, list]:
        """Check if root account has MFA."""
        for f in self.findings:
            if f.get("rule_id") == "iam_root_no_mfa":
                return False, [{"finding": f.get("title")}]
        return True, []

    def check_iam_user_mfa(self) -> tuple[bool, list]:
        """Check if IAM users with console have MFA."""
        evidence = []
        for f in self.findings:
            if f.get("rule_id") == "iam_user_no_mfa":
                evidence.append({"finding": f.get("title"), "resource": f.get("resource_id")})
        return len(evidence) == 0, evidence

    def check_all_iam_user_mfa(self) -> tuple[bool, list]:
        """Check if all IAM users have MFA."""
        evidence = []
        for f in self.findings:
            if f.get("rule_id") in ("iam_user_no_mfa", "iam_user_mfa_not_enabled"):
                evidence.append({"finding": f.get("title"), "resource": f.get("resource_id")})
        return len(evidence) == 0, evidence

    def check_iam_inline_policies(self) -> tuple[bool, list]:
        """Check for inline policies on users."""
        evidence = []
        for f in self.findings:
            if f.get("rule_id") == "iam_user_inline_policy":
                evidence.append({"finding": f.get("title"), "resource": f.get("resource_id")})
        return len(evidence) == 0, evidence

    def check_password_policy(self) -> tuple[bool, list]:
        """Check password policy minimum length."""
        for f in self.findings:
            if f.get("rule_id") == "iam_password_policy_length":
                return False, [{"finding": f.get("title")}]
        return True, []

    def check_password_rotation(self) -> tuple[bool, list]:
        """Check password rotation policy."""
        for f in self.findings:
            if f.get("rule_id") == "iam_password_policy_rotation":
                return False, [{"finding": f.get("title")}]
        return True, []

    def check_password_reuse(self) -> tuple[bool, list]:
        """Check password reuse prevention."""
        for f in self.findings:
            if f.get("rule_id") == "iam_password_policy_reuse":
                return False, [{"finding": f.get("title")}]
        return True, []

    def check_cloudtrail_enabled(self) -> tuple[bool, list]:
        """Check CloudTrail enabled in all regions."""
        evidence = []
        for f in self.findings:
            if f.get("rule_id") in ("cloudtrail_not_enabled", "cloudtrail_not_multi_region"):
                evidence.append({"finding": f.get("title"), "region": f.get("region")})
        return len(evidence) == 0, evidence

    def check_cloudtrail_validation(self) -> tuple[bool, list]:
        """Check CloudTrail log validation."""
        for f in self.findings:
            if f.get("rule_id") == "cloudtrail_log_validation_disabled":
                return False, [{"finding": f.get("title")}]
        return True, []

    def check_cloudtrail_encryption(self) -> tuple[bool, list]:
        """Check CloudTrail encryption."""
        for f in self.findings:
            if f.get("rule_id") == "cloudtrail_not_encrypted":
                return False, [{"finding": f.get("title")}]
        return True, []

    def check_cloudtrail_cloudwatch(self) -> tuple[bool, list]:
        """Check CloudTrail CloudWatch integration."""
        for f in self.findings:
            if f.get("rule_id") == "cloudtrail_no_cloudwatch":
                return False, [{"finding": f.get("title")}]
        return True, []

    def check_s3_access_logging(self) -> tuple[bool, list]:
        """Check S3 access logging."""
        evidence = []
        for f in self.findings:
            if f.get("rule_id") == "s3_logging_disabled":
                evidence.append({"finding": f.get("title"), "resource": f.get("resource_id")})
        return len(evidence) == 0, evidence

    def check_s3_versioning(self) -> tuple[bool, list]:
        """Check S3 versioning."""
        evidence = []
        for f in self.findings:
            if f.get("rule_id") == "s3_versioning_disabled":
                evidence.append({"finding": f.get("title"), "resource": f.get("resource_id")})
        return len(evidence) == 0, evidence

    def check_s3_encryption(self) -> tuple[bool, list]:
        """Check S3 encryption."""
        evidence = []
        for f in self.findings:
            if f.get("rule_id") in ("s3_encryption_missing", "s3_encryption_no_rules"):
                evidence.append({"finding": f.get("title"), "resource": f.get("resource_id")})
        return len(evidence) == 0, evidence

    def check_s3_public_access(self) -> tuple[bool, list]:
        """Check S3 public access."""
        evidence = []
        for f in self.findings:
            if f.get("rule_id") in ("s3_public_access_block_missing", "s3_public_access_block_incomplete",
                                    "s3_bucket_acl_public_read", "s3_bucket_acl_public_write",
                                    "s3_bucket_acl_public_full_control", "s3_bucket_policy_public"):
                evidence.append({"finding": f.get("title"), "resource": f.get("resource_id")})
        return len(evidence) == 0, evidence

    def check_vpc_flow_logs(self) -> tuple[bool, list]:
        """Check VPC flow logs."""
        evidence = []
        for f in self.findings:
            if f.get("rule_id") == "vpc_flow_logs_disabled":
                evidence.append({"finding": f.get("title"), "resource": f.get("resource_id")})
        return len(evidence) == 0, evidence

    def check_default_sg(self) -> tuple[bool, list]:
        """Check default security groups."""
        evidence = []
        for f in self.findings:
            if f.get("rule_id") == "ec2_default_sg_allows_traffic":
                evidence.append({"finding": f.get("title"), "resource": f.get("resource_id")})
        return len(evidence) == 0, evidence

    def check_sg_ssh(self) -> tuple[bool, list]:
        """Check security groups for unrestricted SSH."""
        evidence = []
        for f in self.findings:
            if f.get("rule_id") in ("ec2_sg_ssh_open", "ec2_sg_ssh_open_ipv6"):
                evidence.append({"finding": f.get("title"), "resource": f.get("resource_id")})
        return len(evidence) == 0, evidence

    def check_sg_rdp(self) -> tuple[bool, list]:
        """Check security groups for unrestricted RDP."""
        evidence = []
        for f in self.findings:
            if f.get("rule_id") in ("ec2_sg_rdp_open", "ec2_sg_rdp_open_ipv6"):
                evidence.append({"finding": f.get("title"), "resource": f.get("resource_id")})
        return len(evidence) == 0, evidence

    def check_rds_public(self) -> tuple[bool, list]:
        """Check RDS public access."""
        evidence = []
        for f in self.findings:
            if f.get("rule_id") == "rds_public_access":
                evidence.append({"finding": f.get("title"), "resource": f.get("resource_id")})
        return len(evidence) == 0, evidence

    def check_rds_encryption(self) -> tuple[bool, list]:
        """Check RDS encryption."""
        evidence = []
        for f in self.findings:
            if f.get("rule_id") in ("rds_unencrypted", "rds_cluster_unencrypted"):
                evidence.append({"finding": f.get("title"), "resource": f.get("resource_id")})
        return len(evidence) == 0, evidence

    def check_rds_backup_retention(self) -> tuple[bool, list]:
        """Check RDS backup retention."""
        evidence = []
        for f in self.findings:
            if f.get("rule_id") in ("rds_short_backup_retention", "rds_cluster_short_backup_retention"):
                evidence.append({"finding": f.get("title"), "resource": f.get("resource_id")})
        return len(evidence) == 0, evidence

    def check_ebs_encryption(self) -> tuple[bool, list]:
        """Check EBS encryption."""
        evidence = []
        for f in self.findings:
            if f.get("rule_id") == "ec2_ebs_unencrypted":
                evidence.append({"finding": f.get("title"), "resource": f.get("resource_id")})
        return len(evidence) == 0, evidence

    def check_ebs_snapshot_public(self) -> tuple[bool, list]:
        """Check EBS snapshot public access."""
        evidence = []
        for f in self.findings:
            if f.get("rule_id") == "ec2_snapshot_public":
                evidence.append({"finding": f.get("title"), "resource": f.get("resource_id")})
        return len(evidence) == 0, evidence

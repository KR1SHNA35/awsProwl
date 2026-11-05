"""Finding models and severity handling for awsProwl."""

from __future__ import annotations

import uuid
from datetime import datetime, timezone
from enum import Enum
from typing import Any

from pydantic import BaseModel, Field, field_validator


class Severity(str, Enum):
    """Finding severity levels."""

    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"
    UNKNOWN = "unknown"

    @property
    def color(self) -> str:
        """Rich color for terminal output."""
        colors = {
            Severity.CRITICAL: "bold red",
            Severity.HIGH: "red",
            Severity.MEDIUM: "yellow",
            Severity.LOW: "blue",
            Severity.INFO: "cyan",
            Severity.UNKNOWN: "white",
        }
        return colors.get(self, "white")

    @property
    def icon(self) -> str:
        """Icon for display."""
        icons = {
            Severity.CRITICAL: "🔴",
            Severity.HIGH: "🟠",
            Severity.MEDIUM: "🟡",
            Severity.LOW: "🔵",
            Severity.INFO: "🟢",
            Severity.UNKNOWN: "⚪",
        }
        return icons.get(self, "⚪")

    @property
    def score(self) -> int:
        """Numeric score for sorting (higher = more severe)."""
        scores = {
            Severity.CRITICAL: 5,
            Severity.HIGH: 4,
            Severity.MEDIUM: 3,
            Severity.LOW: 2,
            Severity.INFO: 1,
            Severity.UNKNOWN: 0,
        }
        return scores.get(self, 0)

    @classmethod
    def from_cvss(cls, cvss_score: float) -> Severity:
        """Convert CVSS score to severity."""
        if cvss_score >= 9.0:
            return cls.CRITICAL
        if cvss_score >= 7.0:
            return cls.HIGH
        if cvss_score >= 4.0:
            return cls.MEDIUM
        if cvss_score > 0.0:
            return cls.LOW
        return cls.INFO


class FindingCategory(str, Enum):
    """Finding categories."""

    PRIVILEGE_ESCALATION = "privilege_escalation"
    DATA_EXPOSURE = "data_exposure"
    NETWORK_EXPOSURE = "network_exposure"
    WEAK_CONFIGURATION = "weak_configuration"
    EXCESSIVE_PERMISSIONS = "excessive_permissions"
    MISSING_ENCRYPTION = "missing_encryption"
    PUBLIC_ACCESS = "public_access"
    CROSS_ACCOUNT_ACCESS = "cross_account_access"
    UNUSED_RESOURCES = "unused_resources"
    COMPLIANCE = "compliance"
    INFORMATIONAL = "informational"
    ENUMERATION = "enumeration"
    DATA_LOSS_RISK = "data_loss_risk"
    LOGGING_MISSING = "logging_missing"
    POLICY_SIMULATION = "policy_simulation"
    DATA_EXFILTRATION = "data_exfiltration"
    MISCONFIGURATION = "misconfiguration"
    ENCRYPTION_MISSING = "encryption_missing"
    SECRETS_EXPOSURE = "secrets_exposure"
    DOS_RISK = "dos_risk"
    VULNERABLE_CONFIGURATION = "vulnerable_configuration"
    BEST_PRACTICE = "best_practice"
    NETWORK_CONFIGURATION = "network_configuration"
    INFORMATION_DISCLOSURE = "information_disclosure"
    AVAILABILITY = "availability"
    UNUSED_CREDENTIALS = "unused_credentials"
    COST_OPTIMIZATION = "cost_optimization"


class ResourceType(str, Enum):
    """AWS resource types."""

    IAM_USER = "iam_user"
    IAM_ROLE = "iam_role"
    IAM_POLICY = "iam_policy"
    IAM_GROUP = "iam_group"
    IAM_ACCESS_KEY = "iam_access_key"
    EC2_INSTANCE = "ec2_instance"
    EC2_SECURITY_GROUP = "ec2_security_group"
    EC2_KEY_PAIR = "ec2_key_pair"
    EC2_VOLUME = "ec2_volume"
    S3_BUCKET = "s3_bucket"
    S3_OBJECT = "s3_object"
    LAMBDA_FUNCTION = "lambda_function"
    LAMBDA_FUNCTION_URL = "lambda_function_url"
    LAMBDA_LAYER = "lambda_layer"
    LAMBDA_EVENT_SOURCE_MAPPING = "lambda_event_source_mapping"
    ECS_CLUSTER = "ecs_cluster"
    ECS_SERVICE = "ecs_service"
    ECS_TASK_DEFINITION = "ecs_task_definition"
    SECRETS_MANAGER_SECRET = "secrets_manager_secret"
    SNS_TOPIC = "sns_topic"
    BEANSTALK_APPLICATION = "beanstalk_application"
    BEANSTALK_ENVIRONMENT = "beanstalk_environment"
    COGNITO_USER_POOL = "cognito_user_pool"
    COGNITO_IDENTITY_POOL = "cognito_identity_pool"
    RDS_INSTANCE = "rds_instance"
    DYNAMODB_TABLE = "dynamodb_table"
    CLOUDFRONT_DISTRIBUTION = "cloudfront_distribution"
    API_GATEWAY = "api_gateway"
    KMS_KEY = "kms_key"
    CLOUDFORMATION_STACK = "cloudformation_stack"
    CLOUDFORMATION_STACK_SET = "cloudformation_stack_set"
    CLOUDFORMATION_STACK_INSTANCE = "cloudformation_stack_instance"
    ORGANIZATIONS_ACCOUNT = "organizations_account"
    STS_SESSION = "sts:session"
    STS_ASSUMED_ROLE = "sts:assumed_role"
    STS_DECODED_MESSAGE = "sts:decoded_message"
    SSM_COMMAND = "ssm_command"
    SSM_ASSOCIATION = "ssm_association"
    GLUE_JOB = "glue_job"
    GLUE_DEV_ENDPOINT = "glue_dev_endpoint"
    CODEBUILD_PROJECT = "codebuild_project"
    ECS_TASK = "ecs_task"
    EKS_CLUSTER = "eks_cluster"
    BATCH_JOB_QUEUE = "batch_job_queue"
    BATCH_COMPUTE_ENV = "batch_compute_env"
    SAGEMAKER_NOTEBOOK = "sagemaker_notebook"
    SAGEMAKER_ENDPOINT = "sagemaker_endpoint"
    CLOUD9_ENVIRONMENT = "cloud9_environment"
    OTHER = "other"


class Evidence(BaseModel):
    """Evidence supporting a finding."""

    type: str = Field(description="Type of evidence (api_response, config, log, etc.)")
    description: str = Field(description="Human-readable description")
    data: dict[str, Any] = Field(default_factory=dict, description="Raw evidence data")
    source: str = Field(default="", description="Source of evidence (service, API call)")
    timestamp: datetime = Field(default_factory=datetime.utcnow)


class Remediation(BaseModel):
    """Remediation guidance for a finding."""

    summary: str = Field(description="Brief remediation summary")
    steps: list[str] = Field(default_factory=list, description="Detailed remediation steps")
    references: list[str] = Field(default_factory=list, description="Reference URLs")
    effort: str = Field(default="medium", description="Estimated effort (low, medium, high)")
    automatable: bool = Field(default=False, description="Whether remediation can be automated")
    cli_commands: list[str] = Field(default_factory=list, description="AWS CLI commands for remediation")
    terraform_example: str | None = Field(default=None, description="Terraform example for fix")


class Finding(BaseModel):
    """Security finding model."""

    id: str = Field(default_factory=lambda: f"finding-{uuid.uuid4().hex[:12]}")
    title: str = Field(description="Short finding title")
    description: str = Field(description="Detailed finding description")
    severity: Severity = Field(default=Severity.INFO)
    category: FindingCategory = Field(default=FindingCategory.INFORMATIONAL)

    # Resource information
    resource_type: ResourceType = Field(default=ResourceType.OTHER)
    resource_id: str = Field(default="", description="AWS resource ID/ARN")
    resource_name: str = Field(default="", description="Human-readable resource name")
    region: str = Field(default="", description="AWS region")
    account_id: str = Field(default="", description="AWS account ID")

    # Evidence and remediation
    evidence: list[Evidence] = Field(default_factory=list)
    remediation: Remediation | None = None

    # Metadata
    scan_id: str = Field(default="", description="Scan that produced this finding")
    rule_id: str = Field(default="", description="Rule/check that triggered this finding")
    destructive: bool = Field(default=False, description="Whether this finding represents a destructive change")
    tags: list[str] = Field(default_factory=list)
    created_at: datetime = Field(default_factory=datetime.utcnow)
    updated_at: datetime = Field(default_factory=datetime.utcnow)

    # Status tracking
    status: str = Field(default="open", description="open, acknowledged, fixed, false_positive, risk_accepted")
    assignee: str | None = Field(default=None)
    due_date: datetime | None = Field(default=None)

    # CVSS
    cvss_score: float | None = Field(default=None, ge=0, le=10)
    cvss_vector: str | None = Field(default=None)

    @field_validator("severity", mode="before")
    @classmethod
    def validate_severity(cls, v: Any) -> Severity:
        if isinstance(v, str):
            return Severity(v.lower())
        if isinstance(v, Severity):
            return v
        return Severity.INFO

    @field_validator("category", mode="before")
    @classmethod
    def validate_category(cls, v: Any) -> FindingCategory:
        if isinstance(v, str):
            return FindingCategory(v.lower())
        if isinstance(v, FindingCategory):
            return v
        return FindingCategory.INFORMATIONAL

    @field_validator("resource_type", mode="before")
    @classmethod
    def validate_resource_type(cls, v: Any) -> ResourceType:
        if isinstance(v, str):
            try:
                return ResourceType(v.lower())
            except ValueError:
                return ResourceType.OTHER
        if isinstance(v, ResourceType):
            return v
        return ResourceType.OTHER

    def update_severity(self, severity: Severity) -> None:
        """Update severity and timestamp."""
        self.severity = severity
        self.updated_at = datetime.now(timezone.utc)

    def add_evidence(self, evidence: Evidence) -> None:
        """Add evidence to finding."""
        self.evidence.append(evidence)
        self.updated_at = datetime.now(timezone.utc)

    def set_remediation(self, remediation: Remediation) -> None:
        """Set remediation guidance."""
        self.remediation = remediation
        self.updated_at = datetime.now(timezone.utc)

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary for serialization."""
        return self.model_dump(mode="json")

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> Finding:
        """Create finding from dictionary."""
        return cls.model_validate(data)


class FindingCollection(BaseModel):
    """Collection of findings with metadata."""

    findings: list[Finding] = Field(default_factory=list)
    scan_id: str = Field(default="")
    total_count: int = 0
    severity_counts: dict[Severity, int] = Field(default_factory=dict)
    category_counts: dict[FindingCategory, int] = Field(default_factory=dict)
    created_at: datetime = Field(default_factory=datetime.utcnow)

    def add_finding(self, finding: Finding) -> None:
        """Add a finding to the collection."""
        self.findings.append(finding)
        self.total_count = len(self.findings)
        self._update_counts()

    def _update_counts(self) -> None:
        """Update severity and category counts."""
        self.severity_counts = {}
        self.category_counts = {}
        for finding in self.findings:
            self.severity_counts[finding.severity] = self.severity_counts.get(finding.severity, 0) + 1
            self.category_counts[finding.category] = self.category_counts.get(finding.category, 0) + 1

    def get_by_severity(self, severity: Severity) -> list[Finding]:
        """Get findings by severity."""
        return [f for f in self.findings if f.severity == severity]

    def get_by_category(self, category: FindingCategory) -> list[Finding]:
        """Get findings by category."""
        return [f for f in self.findings if f.category == category]

    def get_by_resource(self, resource_id: str) -> list[Finding]:
        """Get findings for a specific resource."""
        return [f for f in self.findings if f.resource_id == resource_id]

    def sort_by_severity(self, descending: bool = True) -> None:
        """Sort findings by severity."""
        self.findings.sort(key=lambda f: f.severity.score, reverse=descending)

    def filter(self, **kwargs: Any) -> FindingCollection:
        """Create filtered collection."""
        filtered = FindingCollection(scan_id=self.scan_id)
        for finding in self.findings:
            match = True
            for key, value in kwargs.items():
                if hasattr(finding, key):
                    if getattr(finding, key) != value:
                        match = False
                        break
                else:
                    match = False
                    break
            if match:
                filtered.add_finding(finding)
        return filtered

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary."""
        return self.model_dump(mode="json")


# Pre-built remediation templates
REMEDIATION_TEMPLATES = {
    "public_s3_bucket": Remediation(
        summary="Restrict S3 bucket public access",
        steps=[
            "Block public access at bucket level",
            "Remove public bucket policies",
            "Review and remove public ACLs",
            "Enable bucket access logging",
        ],
        references=[
            "https://docs.aws.amazon.com/AmazonS3/latest/userguide/access-control-block-public-access.html",
        ],
        effort="low",
        automatable=True,
        cli_commands=[
            "aws s3api put-public-access-block --bucket <bucket> --public-access-block-configuration BlockPublicAcls=true,IgnorePublicAcls=true,BlockPublicPolicy=true,RestrictPublicBuckets=true",
        ],
    ),
    "unencrypted_ebs": Remediation(
        summary="Enable encryption for EBS volume",
        steps=[
            "Create encrypted snapshot of the volume",
            "Create new encrypted volume from snapshot",
            "Replace volume on instance",
            "Delete unencrypted volume and snapshot",
        ],
        references=[
            "https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/EBSEncryption.html",
        ],
        effort="medium",
        automatable=False,
        cli_commands=[
            "aws ec2 create-snapshot --volume-id <volume-id>",
            "aws ec2 create-volume --snapshot-id <snapshot-id> --encrypted --region <region>",
        ],
    ),
    "iam_wildcard_policy": Remediation(
        summary="Remove wildcard permissions from IAM policy",
        steps=[
            "Identify specific permissions needed",
            "Create new policy with least privilege",
            "Attach new policy and detach wildcard policy",
            "Test application functionality",
        ],
        references=[
            "https://docs.aws.amazon.com/IAM/latest/UserGuide/best-practices.html",
        ],
        effort="medium",
        automatable=False,
        cli_commands=[
            "aws iam create-policy --policy-name <name> --policy-document file://policy.json",
            "aws iam attach-user-policy --user-name <user> --policy-arn <arn>",
        ],
    ),
    "public_snapshot": Remediation(
        summary="Make RDS/EBS snapshot private",
        steps=[
            "Modify snapshot attribute to remove public access",
            "Share snapshot with specific accounts if needed",
        ],
        references=[
            "https://docs.aws.amazon.com/AmazonRDS/latest/UserGuide/USER_ShareSnapshot.html",
        ],
        effort="low",
        automatable=True,
        cli_commands=[
            "aws rds modify-db-snapshot-attribute --db-snapshot-identifier <id> --attribute-name restore --values-to-remove all",
        ],
    ),
}

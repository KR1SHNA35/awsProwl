"""Tests for awsProwl core modules."""


import pytest

from awsprowl.analysis.findings import (
    Evidence,
    Finding,
    FindingCategory,
    FindingCollection,
    Remediation,
    ResourceType,
    Severity,
)
from awsprowl.core.config import (
    AWSConfig,
    Config,
    ScanConfig,
)
from awsprowl.core.exceptions import (
    AuthenticationError,
    AuthorizationError,
    AwsProwlError,
    ConfigurationError,
    ResourceNotFoundError,
    ScanError,
    ValidationError,
)


class TestConfig:
    """Test configuration models."""

    def test_default_config(self):
        """Test default configuration values."""
        config = Config()
        assert config.aws.profile is None  # Default is None
        assert config.aws.region == "us-east-1"
        assert config.scan.regions == ["us-east-1"]
        assert config.scan.parallel_regions is True  # Default is bool True
        assert config.output.format == "table"  # Default is table
        assert config.web.host == "127.0.0.1"
        assert config.web.port == 8080

    def test_aws_config(self):
        """Test AWS configuration."""
        aws_config = AWSConfig(
            profile="test-profile",
            region="us-west-2",
            access_key_id="AKIATEST",
            secret_access_key="secret",
        )
        assert aws_config.profile == "test-profile"
        assert aws_config.region == "us-west-2"

    def test_scan_config(self):
        """Test scan configuration."""
        scan_config = ScanConfig(
            regions=["us-east-1", "us-west-2"],
            services=["iam", "ec2", "s3"],
            parallel_regions=False,  # It's a bool
            max_workers=3,
        )
        assert scan_config.regions == ["us-east-1", "us-west-2"]
        assert scan_config.services == ["iam", "ec2", "s3"]
        assert scan_config.parallel_regions is False
        assert scan_config.max_workers == 3

    def test_config_yaml_roundtrip(self, tmp_path):
        """Test config YAML serialization."""
        config = Config(
            aws=AWSConfig(profile="test", region="eu-west-1"),
            scan=ScanConfig(regions=["eu-west-1"]),
        )
        yaml_file = tmp_path / "config.yaml"
        config.save_to_file(yaml_file)
        loaded = Config.load_from_file(yaml_file)
        assert loaded.aws.profile == "test"
        assert loaded.aws.region == "eu-west-1"
        assert loaded.scan.regions == ["eu-west-1"]


class TestExceptions:
    """Test exception hierarchy."""

    def test_base_exception(self):
        """Test base exception."""
        exc = AwsProwlError("Test error", remediation="Fix it")
        assert str(exc) == "Test error"
        assert exc.remediation == "Fix it"
        assert exc.code == "AWSPROWLERROR"

    def test_authentication_error(self):
        """Test authentication error."""
        exc = AuthenticationError("Auth failed")
        assert exc.code == "AUTH_ERROR"

    def test_authorization_error(self):
        """Test authorization error."""
        exc = AuthorizationError("Access denied", action="iam:ListUsers")
        assert exc.code == "AUTHZ_ERROR"
        assert exc.details["action"] == "iam:ListUsers"

    def test_configuration_error(self):
        """Test configuration error."""
        exc = ConfigurationError("Bad config", config_key="aws.region")
        assert exc.code == "CONFIG_ERROR"
        assert exc.details["config_key"] == "aws.region"

    def test_resource_not_found_error(self):
        """Test resource not found error."""
        exc = ResourceNotFoundError("Not found", resource_type="s3_bucket", resource_id="my-bucket")
        assert exc.code == "RESOURCE_NOT_FOUND"
        assert exc.details["resource_type"] == "s3_bucket"
        assert exc.details["resource_id"] == "my-bucket"

    def test_scan_error(self):
        """Test scan error."""
        exc = ScanError("Scan failed", service="ec2", region="us-east-1")
        assert exc.code == "SCAN_ERROR"
        assert exc.details["service"] == "ec2"
        assert exc.details["region"] == "us-east-1"

    def test_validation_error(self):
        """Test validation error."""
        exc = ValidationError("Invalid input", field="region", value="invalid")
        assert exc.code == "VALIDATION_ERROR"
        assert exc.details["field"] == "region"
        assert exc.details["value"] == "invalid"


class TestFindings:
    """Test finding models."""

    def test_severity_enum(self):
        """Test severity enum."""
        assert Severity.CRITICAL.value == "critical"
        assert Severity.HIGH.value == "high"
        assert Severity.MEDIUM.value == "medium"
        assert Severity.LOW.value == "low"
        assert Severity.INFO.value == "info"

    def test_category_enum(self):
        """Test finding category enum."""
        assert FindingCategory.PRIVILEGE_ESCALATION.value == "privilege_escalation"
        assert FindingCategory.EXCESSIVE_PERMISSIONS.value == "excessive_permissions"
        assert FindingCategory.DATA_EXPOSURE.value == "data_exposure"
        assert FindingCategory.NETWORK_EXPOSURE.value == "network_exposure"
        assert FindingCategory.WEAK_CONFIGURATION.value == "weak_configuration"

    def test_resource_type_enum(self):
        """Test resource type enum."""
        assert ResourceType.IAM_USER.value == "iam_user"
        assert ResourceType.IAM_ROLE.value == "iam_role"
        assert ResourceType.S3_BUCKET.value == "s3_bucket"
        assert ResourceType.EC2_INSTANCE.value == "ec2_instance"
        assert ResourceType.LAMBDA_FUNCTION.value == "lambda_function"

    def test_evidence_creation(self):
        """Test evidence creation."""
        evidence = Evidence(
            type="api_response",
            description="Test evidence",
            data={"key": "value"},
        )
        assert evidence.type == "api_response"
        assert evidence.data["key"] == "value"

    def test_remediation_creation(self):
        """Test remediation creation."""
        remediation = Remediation(
            summary="Fix it",
            steps=["Step 1", "Step 2"],
            effort="low",
            automatable=True,
        )
        assert remediation.summary == "Fix it"
        assert len(remediation.steps) == 2
        assert remediation.effort == "low"
        assert remediation.automatable is True

    def test_finding_creation(self):
        """Test finding creation."""
        finding = Finding(
            title="Test Finding",
            description="Test description",
            severity=Severity.HIGH,
            category=FindingCategory.WEAK_CONFIGURATION,
            resource_type=ResourceType.IAM_USER,
            resource_id="test-user",
            region="us-east-1",
        )
        assert finding.title == "Test Finding"
        assert finding.severity == Severity.HIGH
        assert finding.resource_id == "test-user"

    def test_finding_to_dict(self):
        """Test finding serialization."""
        finding = Finding(
            title="Test Finding",
            description="Test description",
            severity=Severity.HIGH,
            category=FindingCategory.WEAK_CONFIGURATION,
            resource_type=ResourceType.IAM_USER,
            resource_id="test-user",
            region="us-east-1",
        )
        finding_dict = finding.to_dict()
        assert finding_dict["title"] == "Test Finding"
        assert finding_dict["severity"] == "high"
        assert finding_dict["resource_type"] == "iam_user"

    def test_finding_collection(self):
        """Test finding collection."""
        findings = [
            Finding(
                title="Finding 1",
                description="Desc 1",
                severity=Severity.CRITICAL,
                category=FindingCategory.DATA_EXPOSURE,
                resource_type=ResourceType.S3_BUCKET,
                resource_id="bucket-1",
            ),
            Finding(
                title="Finding 2",
                description="Desc 2",
                severity=Severity.HIGH,
                category=FindingCategory.NETWORK_EXPOSURE,
                resource_type=ResourceType.EC2_INSTANCE,
                resource_id="i-12345",
            ),
            Finding(
                title="Finding 3",
                description="Desc 3",
                severity=Severity.MEDIUM,
                category=FindingCategory.WEAK_CONFIGURATION,
                resource_type=ResourceType.IAM_USER,
                resource_id="user-1",
            ),
        ]

        collection = FindingCollection()
        for finding in findings:
            collection.add_finding(finding)

        # Test filtering by severity
        critical = collection.get_by_severity(Severity.CRITICAL)
        assert len(critical) == 1
        assert critical[0].title == "Finding 1"

        # Test sorting
        collection.sort_by_severity()
        assert collection.findings[0].severity == Severity.CRITICAL
        assert collection.findings[1].severity == Severity.HIGH
        assert collection.findings[2].severity == Severity.MEDIUM

        # Test summary - check severity_counts
        assert collection.total_count == 3
        assert collection.severity_counts[Severity.CRITICAL] == 1
        assert collection.severity_counts[Severity.HIGH] == 1
        assert collection.severity_counts[Severity.MEDIUM] == 1


if __name__ == "__main__":
    pytest.main([__file__, "-v"])

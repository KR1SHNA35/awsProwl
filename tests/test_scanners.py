"""Tests for awsProwl AWS scanners using moto."""

import boto3
import pytest
from moto import mock_aws

from awsprowl.aws import (
    EC2Scanner,
    IAMScanner,
    LambdaScanner,
    S3Scanner,
    ScanOrchestrator,
)
from awsprowl.core.config import ScanConfig


class MockAuthManager:
    """Mock auth manager for testing."""

    def __init__(self, region="us-east-1"):
        self.region = region
        self._session = boto3.Session(region_name=region)

    def get_client(self, service, region=None, config=None):
        return self._session.client(service, region_name=region or self.region, config=config)

    def get_resource(self, service, region=None, config=None):
        return self._session.resource(service, region_name=region or self.region, config=config)

    def get_caller_identity(self):
        return {"Account": "123456789012", "Arn": "arn:aws:iam::123456789012:user/test"}


@mock_aws
class TestIAMScanner:
    """Test IAM scanner."""

    @pytest.fixture
    def auth_manager(self):
        return MockAuthManager()

    @pytest.fixture
    def scanner(self, auth_manager):
        return IAMScanner(auth_manager)

    def test_scan_users(self, scanner):
        """Test scanning IAM users."""
        iam = boto3.client("iam", region_name="us-east-1")
        iam.create_user(UserName="test-user")
        iam.create_user(UserName="admin-user")

        findings = []
        import asyncio
        result = asyncio.run(scanner.scan("test-scan", findings))

        assert result.service == "iam"
        assert result.resources_found >= 2
        assert len(findings) > 0  # Should find MFA not enabled

    def test_scan_roles(self, scanner):
        """Test scanning IAM roles."""
        iam = boto3.client("iam", region_name="us-east-1")
        iam.create_role(
            RoleName="test-role",
            AssumeRolePolicyDocument='{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"Service":"ec2.amazonaws.com"},"Action":"sts:AssumeRole"}]}'
        )

        findings = []
        import asyncio
        result = asyncio.run(scanner.scan("test-scan", findings))

        assert result.resources_found >= 1

    def test_scan_policies(self, scanner):
        """Test scanning IAM policies."""
        iam = boto3.client("iam", region_name="us-east-1")
        iam.create_policy(
            PolicyName="TestPolicy",
            PolicyDocument='{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"*","Resource":"*"}]}'
        )

        findings = []
        import asyncio
        result = asyncio.run(scanner.scan("test-scan", findings))

        assert result.resources_found >= 1
        # Should find wildcard policy
        wildcard_findings = [f for f in findings if f.get("rule_id") == "iam_wildcard_policy"]
        assert len(wildcard_findings) > 0


@mock_aws
class TestEC2Scanner:
    """Test EC2 scanner."""

    @pytest.fixture
    def auth_manager(self):
        return MockAuthManager()

    @pytest.fixture
    def scanner(self, auth_manager):
        return EC2Scanner(auth_manager)

    def test_scan_instances(self, scanner):
        """Test scanning EC2 instances."""
        ec2 = boto3.client("ec2", region_name="us-east-1")
        ec2.run_instances(ImageId="ami-12345", MinCount=1, MaxCount=1)

        findings = []
        import asyncio
        result = asyncio.run(scanner.scan("test-scan", findings))

        assert result.service == "ec2"
        assert result.resources_found >= 1

    def test_scan_security_groups(self, scanner):
        """Test scanning security groups."""
        ec2 = boto3.client("ec2", region_name="us-east-1")
        vpc = ec2.create_vpc(CidrBlock="10.0.0.0/16")
        vpc_id = vpc["Vpc"]["VpcId"]

        ec2.create_security_group(
            GroupName="test-sg",
            Description="Test SG",
            VpcId=vpc_id
        )

        findings = []
        import asyncio
        result = asyncio.run(scanner.scan("test-scan", findings))

        assert result.resources_found >= 1


@mock_aws
class TestS3Scanner:
    """Test S3 scanner."""

    @pytest.fixture
    def auth_manager(self):
        return MockAuthManager()

    @pytest.fixture
    def scanner(self, auth_manager):
        return S3Scanner(auth_manager)

    def test_scan_buckets(self, scanner):
        """Test scanning S3 buckets."""
        s3 = boto3.client("s3", region_name="us-east-1")
        s3.create_bucket(Bucket="test-bucket")
        s3.create_bucket(Bucket="another-bucket")

        findings = []
        import asyncio
        result = asyncio.run(scanner.scan("test-scan", findings))

        assert result.service == "s3"
        assert result.resources_found >= 2

    def test_bucket_encryption(self, scanner):
        """Test bucket encryption detection."""
        s3 = boto3.client("s3", region_name="us-east-1")
        s3.create_bucket(Bucket="unencrypted-bucket")

        findings = []
        import asyncio
        result = asyncio.run(scanner.scan("test-scan", findings))

        encryption_findings = [f for f in findings if f.get("rule_id") == "s3_encryption_missing"]
        assert len(encryption_findings) > 0


@mock_aws
class TestLambdaScanner:
    """Test Lambda scanner."""

    @pytest.fixture
    def auth_manager(self):
        return MockAuthManager()

    @pytest.fixture
    def scanner(self, auth_manager):
        return LambdaScanner(auth_manager)

    def test_scan_functions(self, scanner):
        """Test scanning Lambda functions."""
        # Need IAM role for Lambda
        iam = boto3.client("iam", region_name="us-east-1")
        role = iam.create_role(
            RoleName="lambda-role",
            AssumeRolePolicyDocument='{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"Service":"lambda.amazonaws.com"},"Action":"sts:AssumeRole"}]}'
        )
        role_arn = role["Role"]["Arn"]

        lambda_client = boto3.client("lambda", region_name="us-east-1")
        lambda_client.create_function(
            FunctionName="test-function",
            Runtime="python3.9",
            Role=role_arn,
            Handler="index.handler",
            Code={"ZipFile": b"def handler(event, context): return 'hello'"},
        )

        findings = []
        import asyncio
        result = asyncio.run(scanner.scan("test-scan", findings))

        assert result.service == "lambda"
        assert result.resources_found >= 1


@mock_aws
class TestScanOrchestrator:
    """Test scan orchestrator."""

    @pytest.fixture
    def auth_manager(self):
        return MockAuthManager()

    @pytest.fixture
    def orchestrator(self, auth_manager):
        config = ScanConfig(regions=["us-east-1"], services=["iam", "ec2", "s3"])
        return ScanOrchestrator(auth_manager, config)

    def test_get_services_for_profile(self, orchestrator):
        """Test getting services for scan profile."""
        assert "iam" in orchestrator.get_services_for_profile("quick")
        assert "ec2" in orchestrator.get_services_for_profile("quick")
        assert "s3" in orchestrator.get_services_for_profile("quick")

        assert len(orchestrator.get_services_for_profile("standard")) > 3
        assert len(orchestrator.get_services_for_profile("deep")) > 7

    def test_get_regions_for_scan(self, orchestrator):
        """Test getting regions for scan."""
        regions = orchestrator.get_regions_for_scan(["us-east-1", "us-west-2"])
        assert regions == ["us-east-1", "us-west-2"]

        all_regions = orchestrator.get_regions_for_scan(["all"])
        assert len(all_regions) > 1

    def test_run_quick_scan(self, orchestrator):
        """Test running a quick scan."""
        import asyncio

        # Create some test resources
        iam = boto3.client("iam", region_name="us-east-1")
        iam.create_user(UserName="test-user")

        ec2 = boto3.client("ec2", region_name="us-east-1")
        ec2.create_vpc(CidrBlock="10.0.0.0/16")

        s3 = boto3.client("s3", region_name="us-east-1")
        s3.create_bucket(Bucket="test-bucket")

        session = asyncio.run(orchestrator.run_scan(
            profile="default",
            regions=["us-east-1"],
            scan_profile="quick",
        ))

        assert session.status == "completed"
        assert len(session.results) >= 3  # iam, ec2, s3
        assert session.findings is not None


if __name__ == "__main__":
    pytest.main([__file__, "-v"])

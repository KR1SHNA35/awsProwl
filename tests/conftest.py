"""Pytest configuration and fixtures for awsProwl tests."""

from __future__ import annotations

import asyncio

import boto3
import pytest
from moto import mock_aws

from awsprowl.core.config import (
    AWSConfig,
    Config,
    LoggingConfig,
    OutputConfig,
    ScanConfig,
    UIConfig,
    WebConfig,
)
from awsprowl.core.safety import (
    DryRunGuard,
    RollbackManager,
)
from awsprowl.modules import ModuleCategory, ModuleMetadata, ModuleRisk

# ============================================================================
# Configuration Fixtures
# ============================================================================

@pytest.fixture(scope="session")
def event_loop():
    """Create event loop for async tests."""
    loop = asyncio.get_event_loop_policy().new_event_loop()
    yield loop
    loop.close()


@pytest.fixture
def test_config():
    """Test configuration."""
    return Config(
        aws=AWSConfig(
            default_region="us-east-1",
            max_retries=3,
            connect_timeout=5,
            read_timeout=30,
        ),
        scan=ScanConfig(
            max_concurrent_scans=5,
            timeout=300,
        ),
        output=OutputConfig(
            output_dir="./test_output",
            format="json",
        ),
        web=WebConfig(),
        logging=LoggingConfig(level="DEBUG"),
        ui=UIConfig(),
    )


@pytest.fixture(autouse=True)
def reset_safety_state():
    """Reset safety state before each test."""
    DryRunGuard.disable()
    RollbackManager.get_instance().clear()
    yield
    DryRunGuard.disable()
    RollbackManager.get_instance().clear()


# ============================================================================
# Auth Fixtures
# ============================================================================

class MockAuthManager:
    """Mock AWSAuthManager for testing without real AWS credentials."""

    def __init__(self, region: str = "us-east-1", profile: str | None = None):
        self.region = region
        self.profile = profile
        self._session = None
        self._clients = {}

    def get_session(self):
        if self._session is None:
            self._session = boto3.Session(region_name=self.region)
        return self._session

    def get_client(self, service: str, region: str | None = None):
        region = region or self.region
        key = (service, region)
        if key not in self._clients:
            self._clients[key] = self.get_session().client(service, region_name=region)
        return self._clients[key]

    def get_caller_identity(self):
        return {"Account": "123456789012", "Arn": "arn:aws:iam::123456789012:user/test", "UserId": "AIDATEST"}

    def invalidate_cache(self):
        self._clients.clear()


@pytest.fixture
def mock_auth_manager():
    """Mock auth manager for unit tests."""
    return MockAuthManager()


@pytest.fixture
def moto_auth_manager():
    """Auth manager with moto mock for integration tests."""
    with mock_aws():
        yield MockAuthManager()


# ============================================================================
# Module Metadata Fixtures
# ============================================================================

@pytest.fixture
def iam_create_user_metadata():
    """IAM Create User module metadata."""
    return ModuleMetadata(
        name="iam__exploit_create_user",
        category=ModuleCategory.EXPLOIT,
        risk=ModuleRisk.HIGH,
        description="Create a new IAM user with optional policy attachment and access key creation",
        required_permissions=["iam:CreateUser", "iam:AttachUserPolicy", "iam:CreateAccessKey"],
        supported_services=["iam"],
        mitre_techniques=["T1136.003"],
        requires_confirmation=True,
        destructive=True,
        tags=["persistence", "credential_access", "user_creation"]
    )


@pytest.fixture
def sts_get_session_token_metadata():
    """STS Get Session Token module metadata."""
    return ModuleMetadata(
        name="sts__exploit_get_session_token",
        category=ModuleCategory.EXPLOIT,
        risk=ModuleRisk.HIGH,
        description="Obtain temporary session credentials via STS GetSessionToken",
        required_permissions=["sts:GetSessionToken"],
        supported_services=["sts"],
        mitre_techniques=["T1552.001"],
        requires_confirmation=True,
        destructive=True,
        tags=["credential_access", "session_token"]
    )


@pytest.fixture
def lambda_create_function_metadata():
    """Lambda Create Function module metadata."""
    return ModuleMetadata(
        name="lambda__exploit_create_function",
        category=ModuleCategory.EXPLOIT,
        risk=ModuleRisk.HIGH,
        description="Create a new Lambda function with custom code",
        required_permissions=["lambda:CreateFunction", "iam:PassRole"],
        supported_services=["lambda"],
        mitre_techniques=["T1059.004", "T1136.001"],
        requires_confirmation=True,
        destructive=True,
        tags=["persistence", "code_execution", "function_creation"]
    )


# ============================================================================
# Handler Fixtures
# ============================================================================

@pytest.fixture
def iam_create_user_handler(mock_auth_manager, iam_create_user_metadata):
    """IAM Create User handler instance."""
    from awsprowl.cli.ui.handlers.exploit.iam import CreateUserHandler
    return CreateUserHandler(mock_auth_manager, iam_create_user_metadata)


@pytest.fixture
def sts_get_session_token_handler(mock_auth_manager, sts_get_session_token_metadata):
    """STS Get Session Token handler instance."""
    from awsprowl.cli.ui.handlers.exploit.sts import GetSessionTokenHandler
    return GetSessionTokenHandler(mock_auth_manager, sts_get_session_token_metadata)


@pytest.fixture
def lambda_create_function_handler(mock_auth_manager, lambda_create_function_metadata):
    """Lambda Create Function handler instance."""
    from awsprowl.cli.ui.handlers.exploit.lambda_ import CreateFunctionHandler
    return CreateFunctionHandler(mock_auth_manager, lambda_create_function_metadata)


# ============================================================================
# Test Data Fixtures
# ============================================================================

@pytest.fixture
def sample_iam_user():
    """Sample IAM user data."""
    return {
        "UserName": "test-user",
        "UserId": "AIDATESTUSER",
        "Arn": "arn:aws:iam::123456789012:user/test-user",
        "CreateDate": "2024-01-01T00:00:00Z",
    }


@pytest.fixture
def sample_lambda_function():
    """Sample Lambda function data."""
    return {
        "FunctionName": "test-function",
        "FunctionArn": "arn:aws:lambda:us-east-1:123456789012:function:test-function",
        "Runtime": "python3.9",
        "Role": "arn:aws:iam::123456789012:role/lambda-role",
        "Handler": "lambda_function.lambda_handler",
        "CodeSize": 1024,
        "Description": "Test function",
        "Timeout": 30,
        "MemorySize": 128,
        "LastModified": "2024-01-01T00:00:00.000+0000",
    }


@pytest.fixture
def sample_ec2_instance():
    """Sample EC2 instance data."""
    return {
        "InstanceId": "i-1234567890abcdef0",
        "InstanceType": "t3.micro",
        "State": {"Name": "running"},
        "LaunchTime": "2024-01-01T00:00:00.000Z",
        "PrivateIpAddress": "10.0.1.100",
        "PublicIpAddress": "54.123.45.67",
        "VpcId": "vpc-12345678",
        "SubnetId": "subnet-12345678",
        "Placement": {"AvailabilityZone": "us-east-1a"},
        "SecurityGroups": [
            {"GroupId": "sg-12345678", "GroupName": "default"}
        ],
    }


# ============================================================================
# Utility Fixtures
# ============================================================================

@pytest.fixture
def temp_output_dir(tmp_path):
    """Temporary output directory."""
    output_dir = tmp_path / "output"
    output_dir.mkdir()
    return output_dir


@pytest.fixture
def mock_console():
    """Mock rich console for testing output."""
    from io import StringIO

    from rich.console import Console
    return Console(file=StringIO(), force_terminal=True)


# ============================================================================
# Pytest Configuration
# ============================================================================

def pytest_configure(config):
    """Configure pytest."""
    config.addinivalue_line("markers", "unit: Unit tests")
    config.addinivalue_line("markers", "integration: Integration tests with moto")
    config.addinivalue_line("markers", "slow: Slow tests")


def pytest_collection_modifyitems(config, items):
    """Auto-mark tests based on location."""
    for item in items:
        if "integration" in str(item.fspath):
            item.add_marker(pytest.mark.integration)
        elif "unit" in str(item.fspath):
            item.add_marker(pytest.mark.unit)

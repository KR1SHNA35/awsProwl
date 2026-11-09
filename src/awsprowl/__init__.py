"""awsProwl - AWS Security Research Tool."""

__version__ = "2.0.0"
__author__ = "awsProwl Team"
__description__ = "AWS Security Research Tool for CTF and Security Assessments"

# Main exports
from awsprowl.analysis import (
    AttackPathBuilder,
    Finding,
    FindingCategory,
    FindingCollection,
    PrivescAnalyzer,
    ResourceType,
    Severity,
)
from awsprowl.aws import (
    AWSServiceBase,
    BeanstalkScanner,
    CognitoScanner,
    EC2Scanner,
    ECSScanner,
    IAMScanner,
    LambdaScanner,
    ParallelScanner,
    S3Scanner,
    ScanOrchestrator,
    ScanResult,
    ScanSession,
    SecretsScanner,
    SNSScanner,
    STSScanner,
)
from awsprowl.core.auth import AWSAuthManager
from awsprowl.core.config import Config, get_config
from awsprowl.core.exceptions import AwsProwlError
from awsprowl.core.lib import (
    confirm,
    downloads_dir,
    format_table,
    module_data_dir,
    print_error,
    print_output,
    prompt,
    save,
    session_dir,
)
from awsprowl.core.logging import get_logger, setup_logging
from awsprowl.core.models import migrations
from awsprowl.core.session import (
    AWSKey,
    ProwlSession,
    activate_session,
    add_aws_key,
    create_session,
    get_active_session,
    get_session,
    list_sessions,
)

__all__ = [
    # Version info
    "__version__",
    "__author__",
    "__description__",
    # Core
    "Config",
    "get_config",
    "AWSAuthManager",
    "AwsProwlError",
    "get_logger",
    "setup_logging",
    # Session Management
    "create_session",
    "get_session",
    "get_active_session",
    "list_sessions",
    "activate_session",
    "add_aws_key",
    "ProwlSession",
    "AWSKey",
    "migrations",
    # Lib Utilities
    "session_dir",
    "downloads_dir",
    "module_data_dir",
    "save",
    "print_output",
    "print_error",
    "confirm",
    "prompt",
    "format_table",
    # AWS Scanners
    "AWSServiceBase",
    "ScanResult",
    "ParallelScanner",
    "IAMScanner",
    "EC2Scanner",
    "S3Scanner",
    "LambdaScanner",
    "ECSScanner",
    "SecretsScanner",
    "SNSScanner",
    "BeanstalkScanner",
    "CognitoScanner",
    "STSScanner",
    "ScanOrchestrator",
    "ScanSession",
    # Analysis
    "Severity",
    "FindingCategory",
    "ResourceType",
    "Finding",
    "FindingCollection",
    "PrivescAnalyzer",
    "AttackPathBuilder",
]

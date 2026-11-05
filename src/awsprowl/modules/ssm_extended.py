"""
Systems Manager Extended Modules - Additional SSM features for PROWL parity

This module provides additional SSM operations beyond the core ssm.py:
- exfil: Data exfiltration
- exploit: Active exploitation
"""

from awsprowl.modules import ModuleCategory, ModuleMetadata, ModuleRisk, register_module

# ==================== EXFIL MODULES (PROWL parity) ====================
register_module(ModuleMetadata(
    name="ssm_exfil_download_parameters",
    category=ModuleCategory.EXFIL,
    risk=ModuleRisk.HIGH,
    description="Download all SSM Parameter Store parameters (including SecureString) for credential extraction. PROWL: systemsmanager__download_parameters. DESTRUCTIVE.",
    required_permissions=["ssm:GetParametersByPath", "ssm:DescribeParameters", "kms:Decrypt"],
    supported_services=["ssm", "kms"],
    mitre_techniques=["T1555.003", "T1530", "T1041"],
    tags=["ssm", "exfil", "parameters", "parameter-store", "secrets", "awsprowl", "destructive"],
    requires_confirmation=True,
    destructive=True,
))

# ==================== EXPLOIT MODULES (PROWL parity) ====================
register_module(ModuleMetadata(
    name="ssm_exploit_rce_ec2",
    category=ModuleCategory.EXPLOIT,
    risk=ModuleRisk.CRITICAL,
    description="Execute commands on EC2 instances via SSM SendCommand/RunCommand for remote code execution. PROWL: systemsmanager__rce_ec2. CRITICAL.",
    required_permissions=["ssm:SendCommand", "ssm:ListCommands", "ssm:GetCommandInvocation", "ec2:DescribeInstances", "iam:PassRole"],
    supported_services=["ssm", "ec2", "iam"],
    mitre_techniques=["T1059.004", "T1569.002", "T1611"],
    tags=["ssm", "exploit", "rce", "ec2", "send-command", "awsprowl", "destructive"],
    requires_confirmation=True,
    destructive=True,
))

register_module(ModuleMetadata(
    name="ssm_exploit_session_manager",
    category=ModuleCategory.EXPLOIT,
    risk=ModuleRisk.HIGH,
    description="Start SSM Session Manager session for interactive shell on EC2 instance. DESTRUCTIVE.",
    required_permissions=["ssm:StartSession", "ssm:DescribeSessions", "ssm:TerminateSession", "ec2:DescribeInstances"],
    supported_services=["ssm", "ec2"],
    mitre_techniques=["T1059.004", "T1569.002", "T1021.004"],
    tags=["ssm", "exploit", "session-manager", "interactive-shell", "destructive"],
    requires_confirmation=True,
    destructive=True,
))

# List all SSM Extended modules
SSM_EXTENDED_MODULES = [
    # Exfil
    "ssm_exfil_download_parameters",
    # Exploit
    "ssm_exploit_rce_ec2", "ssm_exploit_session_manager",
]

__all__ = ["SSM_EXTENDED_MODULES"]
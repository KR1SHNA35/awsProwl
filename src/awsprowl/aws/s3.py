"""S3 scanner for awsProwl."""

from __future__ import annotations

import hashlib

import botocore.exceptions

from awsprowl.aws.base import AWSServiceBase, ScanResult
from awsprowl.core.auth import AWSAuthManager
from awsprowl.core.logging import get_logger

log = get_logger(__name__)


class S3Scanner(AWSServiceBase):
    """Scanner for S3 resources."""

    SERVICE_NAME = "s3"
    REQUIRED_PERMISSIONS = [
        "s3:ListAllMyBuckets",
        "s3:GetBucketLocation",
        "s3:GetBucketAcl",
        "s3:GetBucketPolicy",
        "s3:GetBucketPublicAccessBlock",
        "s3:GetBucketEncryption",
        "s3:GetBucketVersioning",
        "s3:GetBucketLogging",
        "s3:GetBucketWebsite",
        "s3:GetBucketCors",
        "s3:GetBucketLifecycle",
        "s3:GetBucketLifecycleConfiguration",
        "s3:GetBucketReplication",
        "s3:GetBucketTagging",
        "s3:GetBucketRequestPayment",
        "s3:GetBucketAccelerateConfiguration",
        "s3:GetObjectAcl",
        "s3:GetObjectLegalHold",
        "s3:GetObjectRetention",
        "s3:GetObjectLockConfiguration",
        "s3:ListObjectsV2",
        "s3:ListBucketAnalyticsConfigurations",
        "s3:ListBucketIntelligentTieringConfigurations",
        "s3:ListAccessPoints",
        "s3:GetAccessPoint",
        "s3:ListAccessPointsForObjectLambda",
        "s3:GetAccessPointForObjectLambda",
    ]

    def __init__(self, auth_manager: AWSAuthManager, region: str | None = None):
        super().__init__(auth_manager, region or "us-east-1")

    async def scan(self, scan_id: str, findings: list) -> ScanResult:
        """Scan S3 resources for security issues."""
        result = ScanResult(service=self.SERVICE_NAME, region=self.region)

        try:
            # Get all buckets
            response = self.client.list_buckets()
            buckets = response.get("Buckets", [])

            # Process each bucket
            for bucket in buckets:
                result.resources_found += 1
                try:
                    await self._analyze_bucket(bucket["Name"], scan_id, findings, result)
                except Exception as e:
                    log.error("Error analyzing bucket {}: {}", bucket["Name"], e)
                    result.errors.append(f"Bucket {bucket['Name']}: {str(e)}")

        except botocore.exceptions.ClientError as e:
            self.handle_client_error(e, "ListBuckets", findings)
            result.errors.append(str(e))
        except Exception as e:
            log.error("Error in S3 scan: {}", e)
            result.errors.append(str(e))

        return result

    async def _analyze_bucket(self, bucket_name: str, scan_id: str, findings: list, result: ScanResult) -> None:
        """Analyze a single S3 bucket for security issues."""
        # Get bucket region
        try:
            location = self.client.get_bucket_location(Bucket=bucket_name)
            bucket_region = location.get("LocationConstraint") or "us-east-1"
        except botocore.exceptions.ClientError:
            bucket_region = self.region

        # Get bucket details for enumeration
        try:
            bucket_info = {}
            # Get tags
            try:
                tags_resp = self.client.get_bucket_tagging(Bucket=bucket_name)
                bucket_info["tags"] = {t["Key"]: t["Value"] for t in tags_resp.get("TagSet", [])}
            except botocore.exceptions.ClientError:
                bucket_info["tags"] = {}

            # Get versioning status
            try:
                ver_resp = self.client.get_bucket_versioning(Bucket=bucket_name)
                bucket_info["versioning"] = ver_resp.get("Status", "Disabled")
            except botocore.exceptions.ClientError:
                bucket_info["versioning"] = "Unknown"

            # Get encryption status
            try:
                enc_resp = self.client.get_bucket_encryption(Bucket=bucket_name)
                bucket_info["encryption"] = "Enabled"
            except botocore.exceptions.ClientError:
                bucket_info["encryption"] = "Disabled"

            # Add bucket enumeration finding
            await self._add_enumeration_finding("s3_bucket", bucket_name, bucket_name, {
                "region": bucket_region,
                "tags": bucket_info.get("tags", {}),
                "versioning": bucket_info.get("versioning", "Unknown"),
                "encryption": bucket_info.get("encryption", "Unknown"),
            }, findings, scan_id)

        except botocore.exceptions.ClientError:
            pass

        # Check if bucket is in our scan region (for multi-region scans)
        # For now, scan all buckets

        # Check public access block
        await self._check_public_access_block(bucket_name, bucket_region, scan_id, findings)

        # Check bucket ACL
        await self._check_bucket_acl(bucket_name, bucket_region, scan_id, findings)

        # Check bucket policy
        await self._check_bucket_policy(bucket_name, bucket_region, scan_id, findings)

        # Check encryption
        await self._check_encryption(bucket_name, bucket_region, scan_id, findings)

        # Check versioning
        await self._check_versioning(bucket_name, bucket_region, scan_id, findings)

        # Check logging
        await self._check_logging(bucket_name, bucket_region, scan_id, findings)

        # Check lifecycle
        await self._check_lifecycle(bucket_name, bucket_region, scan_id, findings)

        # Check replication
        await self._check_replication(bucket_name, bucket_region, scan_id, findings)

        # Check CORS
        await self._check_cors(bucket_name, bucket_region, scan_id, findings)

        # Check website configuration
        await self._check_website(bucket_name, bucket_region, scan_id, findings)

        # Check requester pays
        await self._check_requester_pays(bucket_name, bucket_region, scan_id, findings)

        # Check transfer acceleration
        await self._check_transfer_acceleration(bucket_name, bucket_region, scan_id, findings)

        # Check Object Lock
        await self._check_object_lock(bucket_name, bucket_region, scan_id, findings)

        # Check analytics configurations
        await self._check_analytics(bucket_name, bucket_region, scan_id, findings)

        # Check intelligent tiering
        await self._check_intelligent_tiering(bucket_name, bucket_region, scan_id, findings)

        # Check access points
        await self._check_access_points(bucket_name, bucket_region, scan_id, findings)

        # Check for public objects
        await self._check_public_objects(bucket_name, bucket_region, scan_id, findings)

        # Enumerate objects (sample)
        await self._enumerate_objects_sample(bucket_name, bucket_region, scan_id, findings)

    async def _check_public_access_block(self, bucket_name: str, bucket_region: str, scan_id: str, findings: list) -> None:
        """Check S3 Public Access Block configuration."""
        try:
            response = self.client.get_public_access_block(Bucket=bucket_name)
            config = response.get("PublicAccessBlockConfiguration", {})

            issues = []
            if not config.get("BlockPublicAcls", False):
                issues.append("BlockPublicAcls disabled")
            if not config.get("IgnorePublicAcls", False):
                issues.append("IgnorePublicAcls disabled")
            if not config.get("BlockPublicPolicy", False):
                issues.append("BlockPublicPolicy disabled")
            if not config.get("RestrictPublicBuckets", False):
                issues.append("RestrictPublicBuckets disabled")

            if issues:
                self._add_finding_deduped(findings, self.create_finding(
                    title=f"S3 bucket {bucket_name} has incomplete Public Access Block",
                    description=f"Public Access Block not fully configured: {', '.join(issues)}",
                    severity="high",
                    category="weak_configuration",
                    resource_type="s3_bucket",
                    resource_id=bucket_name,
                    resource_name=bucket_name,
                    region=bucket_region,
                    evidence=[{"type": "public_access_block", "description": "Public Access Block configuration", "data": config}],
                    remediation={
                        "summary": "Enable all Public Access Block settings",
                        "steps": [
                            "Enable BlockPublicAcls",
                            "Enable IgnorePublicAcls",
                            "Enable BlockPublicPolicy",
                            "Enable RestrictPublicBuckets",
                        ],
                        "effort": "low",
                        "automatable": True,
                        "cli_commands": [
                            f"aws s3api put-public-access-block --bucket {bucket_name} --public-access-block-configuration BlockPublicAcls=true,IgnorePublicAcls=true,BlockPublicPolicy=true,RestrictPublicBuckets=true",
                        ],
                    },
                    rule_id="s3_public_access_block_incomplete",
                ))

        except botocore.exceptions.ClientError as e:
            if e.response["Error"]["Code"] == "NoSuchPublicAccessBlockConfiguration":
                self._add_finding_deduped(findings, self.create_finding(
                    title=f"S3 bucket {bucket_name} has no Public Access Block",
                    description="Public Access Block is not configured, allowing potential public access",
                    severity="high",
                    category="weak_configuration",
                    resource_type="s3_bucket",
                    resource_id=bucket_name,
                    resource_name=bucket_name,
                    region=bucket_region,
                    remediation={
                        "summary": "Enable Public Access Block",
                        "steps": [
                            "Enable all four Public Access Block settings",
                        ],
                        "effort": "low",
                        "automatable": True,
                        "cli_commands": [
                            f"aws s3api put-public-access-block --bucket {bucket_name} --public-access-block-configuration BlockPublicAcls=true,IgnorePublicAcls=true,BlockPublicPolicy=true,RestrictPublicBuckets=true",
                        ],
                    },
                    rule_id="s3_public_access_block_missing",
                ))

    async def _check_bucket_acl(self, bucket_name: str, bucket_region: str, scan_id: str, findings: list) -> None:
        """Check bucket ACL for public access."""
        try:
            acl = self.client.get_bucket_acl(Bucket=bucket_name)
            for grant in acl.get("Grants", []):
                grantee = grant.get("Grantee", {})
                if grantee.get("Type") == "Group":
                    uri = grantee.get("URI", "")
                    if uri == "http://acs.amazonaws.com/groups/global/AllUsers":
                        permission = grant.get("Permission", "")
                        severity = "critical" if permission in ("FULL_CONTROL", "WRITE", "WRITE_ACP") else "high"
                        self._add_finding_deduped(findings, self.create_finding(
                            title=f"S3 bucket {bucket_name} ACL allows public {permission.lower()} access",
                            description=f"Bucket ACL grants {permission} to AllUsers (everyone on the internet)",
                            severity=severity,
                            category="data_exposure",
                            resource_type="s3_bucket",
                            resource_id=bucket_name,
                            resource_name=bucket_name,
                            region=bucket_region,
                            evidence=[{"type": "bucket_acl", "description": f"Public {permission} grant", "data": grant}],
                            remediation={
                                "summary": "Remove public ACL grants",
                                "steps": [
                                    "Remove AllUsers grants from bucket ACL",
                                    "Use bucket policies for controlled access instead",
                                ],
                                "effort": "low",
                                "automatable": True,
                                "cli_commands": [
                                    f"aws s3api put-bucket-acl --bucket {bucket_name} --acl private",
                                ],
                            },
                            rule_id=f"s3_bucket_acl_public_{permission.lower()}",
                        ))
                    elif uri == "http://acs.amazonaws.com/groups/global/AuthenticatedUsers":
                        permission = grant.get("Permission", "")
                        self._add_finding_deduped(findings, self.create_finding(
                            title=f"S3 bucket {bucket_name} ACL allows authenticated AWS users {permission.lower()} access",
                            description=f"Bucket ACL grants {permission} to AuthenticatedUsers (any AWS account)",
                            severity="medium",
                            category="data_exposure",
                            resource_type="s3_bucket",
                            resource_id=bucket_name,
                            resource_name=bucket_name,
                            region=bucket_region,
                            evidence=[{"type": "bucket_acl", "description": f"AuthenticatedUsers {permission} grant", "data": grant}],
                            remediation={
                                "summary": "Remove AuthenticatedUsers ACL grants",
                                "steps": [
                                    "Remove AuthenticatedUsers grants from bucket ACL",
                                    "Use bucket policies for controlled access instead",
                                ],
                                "effort": "low",
                                "automatable": True,
                            },
                            rule_id=f"s3_bucket_acl_authenticated_{permission.lower()}",
                        ))

        except botocore.exceptions.ClientError:
            pass

    async def _check_bucket_policy(self, bucket_name: str, bucket_region: str, scan_id: str, findings: list) -> None:
        """Check bucket policy for security issues."""
        try:
            policy = self.client.get_bucket_policy(Bucket=bucket_name)
            import json
            policy_doc = json.loads(policy["Policy"])

            statements = policy_doc.get("Statement", [])
            if not isinstance(statements, list):
                statements = [statements]

            for stmt in statements:
                if stmt.get("Effect") != "Allow":
                    continue

                principal = stmt.get("Principal", {})
                if not principal:
                    continue

                # Check for wildcard principal
                if principal == "*" or principal.get("AWS") == "*":
                    actions = stmt.get("Action", [])
                    if isinstance(actions, str):
                        actions = [actions]

                    severity = "critical" if any("*" in a or "Put" in a or "Delete" in a for a in actions) else "high"
                    self._add_finding_deduped(findings, self.create_finding(
                        title=f"S3 bucket {bucket_name} policy allows public access",
                        description=f"Bucket policy allows {'all actions' if '*' in actions else ', '.join(actions)} from any principal",
                        severity=severity,
                        category="data_exposure",
                        resource_type="s3_bucket",
                        resource_id=bucket_name,
                        resource_name=bucket_name,
                        region=bucket_region,
                        evidence=[{"type": "bucket_policy", "description": "Public bucket policy", "data": policy_doc}],
                        remediation={
                            "summary": "Restrict bucket policy to specific principals",
                            "steps": [
                                "Identify required principals",
                                "Update policy with specific ARNs or conditions",
                                "Add condition keys (aws:SourceArn, aws:SourceVpc, etc.)",
                            ],
                            "effort": "medium",
                            "automatable": False,
                        },
                        rule_id="s3_bucket_policy_public",
                    ))

                # Check for overly broad actions
                actions = stmt.get("Action", [])
                if isinstance(actions, str):
                    actions = [actions]

                resources = stmt.get("Resource", [])
                if isinstance(resources, str):
                    resources = [resources]

                has_wildcard_action = "*" in actions or any(a.endswith("*") for a in actions)
                has_wildcard_resource = "*" in resources or any("*" in r for r in resources)

                if has_wildcard_action and has_wildcard_resource:
                    self._add_finding_deduped(findings, self.create_finding(
                        title=f"S3 bucket {bucket_name} policy is overly permissive",
                        description="Bucket policy allows wildcard actions on wildcard resources",
                        severity="high",
                        category="excessive_permissions",
                        resource_type="s3_bucket",
                        resource_id=bucket_name,
                        resource_name=bucket_name,
                        region=bucket_region,
                        evidence=[{"type": "bucket_policy", "description": "Overly permissive policy", "data": policy_doc}],
                        remediation={
                            "summary": "Apply least privilege to bucket policy",
                            "steps": [
                                "Identify minimum required actions and resources",
                                "Update policy with specific actions and resource ARNs",
                            ],
                            "effort": "medium",
                            "automatable": False,
                        },
                        rule_id="s3_bucket_policy_overly_permissive",
                    ))

        except botocore.exceptions.ClientError as e:
            if e.response["Error"]["Code"] != "NoSuchBucketPolicy":
                pass

    async def _check_encryption(self, bucket_name: str, bucket_region: str, scan_id: str, findings: list) -> None:
        """Check bucket encryption."""
        try:
            response = self.client.get_bucket_encryption(Bucket=bucket_name)
            rules = response.get("ServerSideEncryptionConfiguration", {}).get("Rules", [])

            if not rules:
                self._add_finding_deduped(findings, self.create_finding(
                    title=f"S3 bucket {bucket_name} has encryption configured but no rules",
                    description="Bucket encryption is enabled but no encryption rules are defined",
                    severity="medium",
                    category="encryption_missing",
                    resource_type="s3_bucket",
                    resource_id=bucket_name,
                    resource_name=bucket_name,
                    region=bucket_region,
                    rule_id="s3_encryption_no_rules",
                ))
            else:
                for rule in rules:
                    sse = rule.get("ApplyServerSideEncryptionByDefault", {})
                    algo = sse.get("SSEAlgorithm", "")
                    if algo != "AES256" and algo != "aws:kms":
                        self._add_finding_deduped(findings, self.create_finding(
                            title=f"S3 bucket {bucket_name} uses weak encryption: {algo}",
                            description=f"Bucket uses {algo} encryption instead of AES256 or aws:kms",
                            severity="medium",
                            category="weak_configuration",
                            resource_type="s3_bucket",
                            resource_id=bucket_name,
                            resource_name=bucket_name,
                            region=bucket_region,
                            rule_id="s3_encryption_weak_algorithm",
                        ))

        except botocore.exceptions.ClientError as e:
            if e.response["Error"]["Code"] == "ServerSideEncryptionConfigurationNotFoundError":
                self._add_finding_deduped(findings, self.create_finding(
                    title=f"S3 bucket {bucket_name} has no default encryption",
                    description="Bucket does not have default server-side encryption enabled",
                    severity="high",
                    category="encryption_missing",
                    resource_type="s3_bucket",
                    resource_id=bucket_name,
                    resource_name=bucket_name,
                    region=bucket_region,
                    remediation={
                        "summary": "Enable default bucket encryption",
                        "steps": [
                            "Enable SSE-S3 (AES256) or SSE-KMS encryption",
                            "For KMS, specify a customer managed key",
                        ],
                        "effort": "low",
                        "automatable": True,
                        "cli_commands": [
                            f"aws s3api put-bucket-encryption --bucket {bucket_name} --server-side-encryption-configuration 'Rules=[{{ApplyServerSideEncryptionByDefault:{{SSEAlgorithm:AES256}}}}]'",
                        ],
                    },
                    rule_id="s3_encryption_missing",
                ))

    async def _check_versioning(self, bucket_name: str, bucket_region: str, scan_id: str, findings: list) -> None:
        """Check bucket versioning."""
        try:
            response = self.client.get_bucket_versioning(Bucket=bucket_name)
            status = response.get("Status", "")
            mfa_delete = response.get("MFADelete", "")

            if status != "Enabled":
                self._add_finding_deduped(findings, self.create_finding(
                    title=f"S3 bucket {bucket_name} has versioning disabled",
                    description="Bucket versioning is not enabled, preventing recovery from accidental deletion or corruption",
                    severity="medium",
                    category="data_loss_risk",
                    resource_type="s3_bucket",
                    resource_id=bucket_name,
                    resource_name=bucket_name,
                    region=bucket_region,
                    remediation={
                        "summary": "Enable bucket versioning",
                        "steps": [
                            "Enable versioning on the bucket",
                            "Consider enabling MFA Delete for extra protection",
                        ],
                        "effort": "low",
                        "automatable": True,
                        "cli_commands": [
                            f"aws s3api put-bucket-versioning --bucket {bucket_name} --versioning-configuration Status=Enabled",
                        ],
                    },
                    rule_id="s3_versioning_disabled",
                ))

            if mfa_delete != "Enabled":
                self._add_finding_deduped(findings, self.create_finding(
                    title=f"S3 bucket {bucket_name} does not have MFA Delete enabled",
                    description="MFA Delete is not enabled, allowing permanent deletion without MFA",
                    severity="low",
                    category="weak_configuration",
                    resource_type="s3_bucket",
                    resource_id=bucket_name,
                    resource_name=bucket_name,
                    region=bucket_region,
                    remediation={
                        "summary": "Enable MFA Delete",
                        "steps": [
                            "Enable MFA Delete on the bucket (requires root account or MFA)",
                        ],
                        "effort": "medium",
                        "automatable": False,
                    },
                    rule_id="s3_mfa_delete_disabled",
                ))

        except botocore.exceptions.ClientError:
            pass

    async def _check_logging(self, bucket_name: str, bucket_region: str, scan_id: str, findings: list) -> None:
        """Check bucket logging."""
        try:
            response = self.client.get_bucket_logging(Bucket=bucket_name)
            logging_enabled = response.get("LoggingEnabled")

            if not logging_enabled:
                self._add_finding_deduped(findings, self.create_finding(
                    title=f"S3 bucket {bucket_name} has no access logging",
                    description="Bucket access logging is not configured, limiting audit trail",
                    severity="medium",
                    category="logging_missing",
                    resource_type="s3_bucket",
                    resource_id=bucket_name,
                    resource_name=bucket_name,
                    region=bucket_region,
                    remediation={
                        "summary": "Enable bucket access logging",
                        "steps": [
                            "Create a target bucket for logs",
                            "Enable logging on source bucket pointing to target bucket",
                        ],
                        "effort": "low",
                        "automatable": True,
                    },
                    rule_id="s3_logging_disabled",
                ))

        except botocore.exceptions.ClientError:
            pass

    async def _check_public_objects(self, bucket_name: str, bucket_region: str, scan_id: str, findings: list) -> None:
        """Check for public objects in bucket (sample check)."""
        try:
            # Sample first 1000 objects
            paginator = self.client.get_paginator("list_objects_v2")
            page_iterator = paginator.paginate(Bucket=bucket_name, MaxKeys=1000)

            public_objects = 0
            for page in page_iterator:
                for obj in page.get("Contents", []):
                    # Check object ACL
                    try:
                        obj_acl = self.client.get_object_acl(Bucket=bucket_name, Key=obj["Key"])
                        for grant in obj_acl.get("Grants", []):
                            grantee = grant.get("Grantee", {})
                            if grantee.get("Type") == "Group":
                                uri = grantee.get("URI", "")
                                if uri in ("http://acs.amazonaws.com/groups/global/AllUsers", "http://acs.amazonaws.com/groups/global/AuthenticatedUsers"):
                                    public_objects += 1
                                    break
                    except botocore.exceptions.ClientError:
                        pass

            if public_objects > 0:
                self._add_finding_deduped(findings, self.create_finding(
                    title=f"S3 bucket {bucket_name} has {public_objects} publicly accessible objects",
                    description=f"Found {public_objects} objects with public ACL grants in sample of 1000 objects",
                    severity="high",
                    category="data_exposure",
                    resource_type="s3_bucket",
                    resource_id=bucket_name,
                    resource_name=bucket_name,
                    region=bucket_region,
                    remediation={
                        "summary": "Remove public ACLs from objects",
                        "steps": [
                            "Run bulk ACL removal for public objects",
                            "Set bucket policy to prevent future public objects",
                        ],
                        "effort": "medium",
                        "automatable": True,
                    },
                    rule_id="s3_public_objects",
                ))

        except botocore.exceptions.ClientError:
            pass

    def _get_finding_key(self, finding: dict) -> str:
        """Generate a unique key for a finding to enable deduplication."""
        key_parts = [
            finding.get("rule_id", ""),
            finding.get("resource_id", ""),
            finding.get("region", ""),
        ]
        key_str = "|".join(key_parts)
        return hashlib.sha256(key_str.encode()).hexdigest()[:16]

    def _add_finding_deduped(self, findings: list, new_finding: dict, seen_keys: set | None = None) -> None:
        """Add a finding to the list with deduplication."""
        if seen_keys is None:
            seen_keys = set()
            for f in findings:
                seen_keys.add(self._get_finding_key(f))

        finding_key = self._get_finding_key(new_finding)
        if finding_key not in seen_keys:
            findings.append(new_finding)
            seen_keys.add(finding_key)

    async def _add_enumeration_finding(self, resource_type: str, resource_id: str, resource_name: str,
                                        details: dict, findings: list, scan_id: str) -> None:
        """Add an informational enumeration finding for a discovered resource."""
        finding = self.create_finding(
            title=f"Discovered {resource_type}: {resource_name}",
            description=f"Enumerated {resource_type} in {self.region}: {resource_name}",
            severity="info",
            category="enumeration",
            resource_type=resource_type,
            resource_id=resource_id,
            resource_name=resource_name,
            region=self.region,
            evidence=[{"type": "enumeration", "description": f"{resource_type} details", "data": details}],
            remediation={
                "summary": "Review discovered resource",
                "steps": [
                    "Verify this resource is expected and properly configured",
                    "Check for security misconfigurations",
                ],
                "effort": "low",
                "automatable": False,
            },
            rule_id=f"s3_enum_{resource_type}",
        )
        self._add_finding_deduped(findings, finding)

    async def _enumerate_objects_sample(self, bucket_name: str, bucket_region: str, scan_id: str, findings: list) -> None:
        """Enumerate objects in bucket (sample) and add enumeration findings."""
        try:
            paginator = self.client.get_paginator("list_objects_v2")
            page_iterator = paginator.paginate(Bucket=bucket_name, MaxKeys=1000)

            object_count = 0
            total_size = 0
            for page in page_iterator:
                for obj in page.get("Contents", []):
                    object_count += 1
                    total_size += obj.get("Size", 0)

                    # Add enumeration finding for each object (limited to first 100)
                    if object_count <= 100:
                        await self._add_enumeration_finding("s3_object", f"{bucket_name}/{obj['Key']}", obj["Key"], {
                            "bucket": bucket_name,
                            "key": obj["Key"],
                            "size": obj.get("Size", 0),
                            "last_modified": obj.get("LastModified", "").isoformat() if obj.get("LastModified") else "",
                            "storage_class": obj.get("StorageClass", "STANDARD"),
                            "etag": obj.get("ETag", ""),
                        }, findings, scan_id)

            # Add summary finding for bucket contents
            if object_count > 0:
                self._add_finding_deduped(findings, self.create_finding(
                    title=f"S3 bucket {bucket_name} contains {object_count} objects ({total_size} bytes)",
                    description=f"Bucket contains {object_count} objects with total size {total_size} bytes (sampled first 1000)",
                    severity="info",
                    category="enumeration",
                    resource_type="s3_bucket",
                    resource_id=bucket_name,
                    resource_name=bucket_name,
                    region=bucket_region,
                    evidence=[{"type": "enumeration", "description": "Bucket object summary", "data": {"object_count": object_count, "total_size_bytes": total_size}}],
                    rule_id="s3_bucket_object_summary",
                ))

        except botocore.exceptions.ClientError as e:
            if e.response["Error"]["Code"] != "AccessDenied":
                pass

    async def _check_lifecycle(self, bucket_name: str, bucket_region: str, scan_id: str, findings: list) -> None:
        """Check bucket lifecycle configuration."""
        try:
            response = self.client.get_bucket_lifecycle_configuration(Bucket=bucket_name)
            rules = response.get("Rules", [])
            if not rules:
                self._add_finding_deduped(findings, self.create_finding(
                    title=f"S3 bucket {bucket_name} has no lifecycle rules",
                    description="Bucket has no lifecycle configuration for object expiration/transition",
                    severity="low",
                    category="weak_configuration",
                    resource_type="s3_bucket",
                    resource_id=bucket_name,
                    resource_name=bucket_name,
                    region=bucket_region,
                    remediation={
                        "summary": "Configure lifecycle rules",
                        "steps": [
                            "Define object expiration rules",
                            "Configure transitions to cheaper storage classes",
                            "Set up incomplete multipart upload cleanup",
                        ],
                        "effort": "medium",
                        "automatable": True,
                    },
                    rule_id="s3_lifecycle_missing",
                ))
            else:
                for rule in rules:
                    await self._add_enumeration_finding("s3_lifecycle_rule", f"{bucket_name}/{rule.get('ID', 'unknown')}", rule.get("ID", "unknown"), {
                        "bucket": bucket_name,
                        "status": rule.get("Status", ""),
                        "filter": rule.get("Filter", {}),
                        "expiration": rule.get("Expiration", {}),
                        "transitions": rule.get("Transitions", []),
                        "noncurrent_expiration": rule.get("NoncurrentVersionExpiration", {}),
                        "noncurrent_transitions": rule.get("NoncurrentVersionTransitions", []),
                    }, findings, scan_id)

        except botocore.exceptions.ClientError as e:
            if e.response["Error"]["Code"] == "NoSuchLifecycleConfiguration":
                self._add_finding_deduped(findings, self.create_finding(
                    title=f"S3 bucket {bucket_name} has no lifecycle configuration",
                    description="Bucket has no lifecycle rules configured",
                    severity="low",
                    category="weak_configuration",
                    resource_type="s3_bucket",
                    resource_id=bucket_name,
                    resource_name=bucket_name,
                    region=bucket_region,
                    rule_id="s3_lifecycle_missing",
                ))

    async def _check_replication(self, bucket_name: str, bucket_region: str, scan_id: str, findings: list) -> None:
        """Check bucket replication configuration."""
        try:
            response = self.client.get_bucket_replication(Bucket=bucket_name)
            config = response.get("ReplicationConfiguration", {})
            rules = config.get("Rules", [])
            if not rules:
                self._add_finding_deduped(findings, self.create_finding(
                    title=f"S3 bucket {bucket_name} has no replication rules",
                    description="Bucket has no cross-region replication configured",
                    severity="info",
                    category="enumeration",
                    resource_type="s3_bucket",
                    resource_id=bucket_name,
                    resource_name=bucket_name,
                    region=bucket_region,
                    rule_id="s3_replication_missing",
                ))
            else:
                for rule in rules:
                    await self._add_enumeration_finding("s3_replication_rule", f"{bucket_name}/{rule.get('ID', 'unknown')}", rule.get("ID", "unknown"), {
                        "bucket": bucket_name,
                        "status": rule.get("Status", ""),
                        "priority": rule.get("Priority", 0),
                        "destination": rule.get("Destination", {}),
                        "filter": rule.get("Filter", {}),
                    }, findings, scan_id)
        except botocore.exceptions.ClientError as e:
            if e.response["Error"]["Code"] == "ReplicationConfigurationNotFoundError":
                pass

    async def _check_cors(self, bucket_name: str, bucket_region: str, scan_id: str, findings: list) -> None:
        """Check bucket CORS configuration."""
        try:
            response = self.client.get_bucket_cors(Bucket=bucket_name)
            rules = response.get("CORSRules", [])
            for rule in rules:
                allowed_origins = rule.get("AllowedOrigins", [])
                if "*" in allowed_origins:
                    self._add_finding_deduped(findings, self.create_finding(
                        title=f"S3 bucket {bucket_name} has overly permissive CORS",
                        description="CORS configuration allows any origin (*)",
                        severity="medium",
                        category="weak_configuration",
                        resource_type="s3_bucket",
                        resource_id=bucket_name,
                        resource_name=bucket_name,
                        region=bucket_region,
                        evidence=[{"type": "cors_rule", "description": "Permissive CORS rule", "data": rule}],
                        remediation={
                            "summary": "Restrict CORS to specific origins",
                            "steps": [
                                "Identify required origins",
                                "Update CORS configuration with specific domains",
                            ],
                            "effort": "low",
                            "automatable": True,
                        },
                        rule_id="s3_cors_wildcard_origin",
                    ))
        except botocore.exceptions.ClientError as e:
            if e.response["Error"]["Code"] == "NoSuchCORSConfiguration":
                pass

    async def _check_website(self, bucket_name: str, bucket_region: str, scan_id: str, findings: list) -> None:
        """Check bucket website configuration."""
        try:
            response = self.client.get_bucket_website(Bucket=bucket_name)
            await self._add_enumeration_finding("s3_website", bucket_name, bucket_name, {
                "index_document": response.get("IndexDocument", {}),
                "error_document": response.get("ErrorDocument", {}),
                "redirect_all_requests": response.get("RedirectAllRequestsTo", {}),
                "routing_rules": response.get("RoutingRules", []),
            }, findings, scan_id)

            # Check if website is public (no bucket policy restriction)
            self._add_finding_deduped(findings, self.create_finding(
                title=f"S3 bucket {bucket_name} configured as static website",
                description="Bucket is configured for static website hosting - verify access is intended",
                severity="info",
                category="enumeration",
                resource_type="s3_bucket",
                resource_id=bucket_name,
                resource_name=bucket_name,
                region=bucket_region,
                rule_id="s3_website_enabled",
            ))
        except botocore.exceptions.ClientError as e:
            if e.response["Error"]["Code"] == "NoSuchWebsiteConfiguration":
                pass

    async def _check_requester_pays(self, bucket_name: str, bucket_region: str, scan_id: str, findings: list) -> None:
        """Check bucket requester pays configuration."""
        try:
            response = self.client.get_bucket_request_payment(Bucket=bucket_name)
            payer = response.get("Payer", "BucketOwner")
            if payer == "Requester":
                self._add_finding_deduped(findings, self.create_finding(
                    title=f"S3 bucket {bucket_name} has Requester Pays enabled",
                    description="Requester pays for data access costs",
                    severity="info",
                    category="cost_optimization",
                    resource_type="s3_bucket",
                    resource_id=bucket_name,
                    resource_name=bucket_name,
                    region=bucket_region,
                    rule_id="s3_requester_pays_enabled",
                ))
        except botocore.exceptions.ClientError:
            pass

    async def _check_transfer_acceleration(self, bucket_name: str, bucket_region: str, scan_id: str, findings: list) -> None:
        """Check bucket transfer acceleration configuration."""
        try:
            response = self.client.get_bucket_accelerate_configuration(Bucket=bucket_name)
            status = response.get("Status", "Suspended")
            if status == "Enabled":
                self._add_finding_deduped(findings, self.create_finding(
                    title=f"S3 bucket {bucket_name} has Transfer Acceleration enabled",
                    description="Transfer Acceleration is enabled (incurs additional data transfer costs)",
                    severity="info",
                    category="cost_optimization",
                    resource_type="s3_bucket",
                    resource_id=bucket_name,
                    resource_name=bucket_name,
                    region=bucket_region,
                    rule_id="s3_transfer_acceleration_enabled",
                ))
        except botocore.exceptions.ClientError:
            pass

    async def _check_object_lock(self, bucket_name: str, bucket_region: str, scan_id: str, findings: list) -> None:
        """Check bucket Object Lock configuration."""
        try:
            response = self.client.get_object_lock_configuration(Bucket=bucket_name)
            config = response.get("ObjectLockConfiguration", {})
            enabled = config.get("ObjectLockEnabled", "Disabled")
            if enabled == "Enabled":
                rule = config.get("Rule", {})
                retention = rule.get("DefaultRetention", {})
                await self._add_enumeration_finding("s3_object_lock", bucket_name, bucket_name, {
                    "object_lock_enabled": True,
                    "default_retention_mode": retention.get("Mode", ""),
                    "default_retention_days": retention.get("Days", 0),
                    "default_retention_years": retention.get("Years", 0),
                }, findings, scan_id)
            else:
                self._add_finding_deduped(findings, self.create_finding(
                    title=f"S3 bucket {bucket_name} has Object Lock disabled",
                    description="Object Lock is not enabled - objects can be deleted/overwritten",
                    severity="medium",
                    category="data_loss_risk",
                    resource_type="s3_bucket",
                    resource_id=bucket_name,
                    resource_name=bucket_name,
                    region=bucket_region,
                    remediation={
                        "summary": "Enable Object Lock for compliance",
                        "steps": [
                            "Enable Object Lock on bucket (requires versioning)",
                            "Configure default retention period",
                            "Set retention mode (GOVERNANCE or COMPLIANCE)",
                        ],
                        "effort": "medium",
                        "automatable": True,
                    },
                    rule_id="s3_object_lock_disabled",
                ))
        except botocore.exceptions.ClientError as e:
            if e.response["Error"]["Code"] == "ObjectLockConfigurationNotFoundError":
                self._add_finding_deduped(findings, self.create_finding(
                    title=f"S3 bucket {bucket_name} has no Object Lock configuration",
                    description="Object Lock is not configured on bucket",
                    severity="medium",
                    category="data_loss_risk",
                    resource_type="s3_bucket",
                    resource_id=bucket_name,
                    resource_name=bucket_name,
                    region=bucket_region,
                    rule_id="s3_object_lock_missing",
                ))

    async def _check_analytics(self, bucket_name: str, bucket_region: str, scan_id: str, findings: list) -> None:
        """Check bucket analytics configurations."""
        try:
            response = self.client.list_bucket_analytics_configurations(Bucket=bucket_name)
            configs = response.get("AnalyticsConfigurationList", [])
            for config in configs:
                await self._add_enumeration_finding("s3_analytics", f"{bucket_name}/{config.get('Id', 'unknown')}", config.get("Id", "unknown"), {
                    "bucket": bucket_name,
                    "filter": config.get("Filter", {}),
                    "storage_class_analysis": config.get("StorageClassAnalysis", {}),
                }, findings, scan_id)
        except botocore.exceptions.ClientError:
            pass

    async def _check_intelligent_tiering(self, bucket_name: str, bucket_region: str, scan_id: str, findings: list) -> None:
        """Check bucket intelligent tiering configurations."""
        try:
            response = self.client.list_bucket_intelligent_tiering_configurations(Bucket=bucket_name)
            configs = response.get("IntelligentTieringConfigurationList", [])
            for config in configs:
                await self._add_enumeration_finding("s3_intelligent_tiering", f"{bucket_name}/{config.get('Id', 'unknown')}", config.get("Id", "unknown"), {
                    "bucket": bucket_name,
                    "status": config.get("Status", ""),
                    "filter": config.get("Filter", {}),
                    "tierings": config.get("Tierings", []),
                }, findings, scan_id)
        except botocore.exceptions.ClientError:
            pass

    async def _check_access_points(self, bucket_name: str, bucket_region: str, scan_id: str, findings: list) -> None:
        """Check S3 Access Points for bucket."""
        try:
            # S3 Access Points are managed via S3Control API, not S3 API
            # Get S3Control client
            s3control_client = self.auth_manager.get_client("s3control", region=bucket_region)
            
            # List all access points for the account
            # Note: list_access_points doesn't support Bucket parameter directly in all versions
            # So we list all and filter by bucket
            result = s3control_client.list_access_points(AccountId=self.auth_manager.get_caller_identity().get("Account", ""))
            
            for ap in result.get("AccessPointList", []):
                # Filter by bucket name in the ARN
                ap_arn = ap.get("AccessPointArn", "")
                if f":accesspoint/{bucket_name}" in ap_arn or bucket_name in ap_arn:
                    ap_name = ap["Name"]
                    
                    # Get access point details
                    ap_result = s3control_client.get_access_point(Name=ap_name, AccountId=self.auth_manager.get_caller_identity().get("Account", ""))
                    policy = ap_result.get("Policy", "")

                    await self._add_enumeration_finding("s3_access_point", ap_name, ap_name, {
                        "bucket": bucket_name,
                        "arn": ap_arn,
                        "network_origin": ap_result.get("NetworkOrigin", ""),
                        "vpc_configuration": ap_result.get("VpcConfiguration", {}),
                        "public_access_block": ap_result.get("PublicAccessBlockConfiguration", {}),
                        "has_policy": bool(policy),
                    }, findings, scan_id)

                    # Check access point policy for public access
                    if policy:
                        import json
                        policy_doc = json.loads(policy)
                        statements = policy_doc.get("Statement", [])
                        if not isinstance(statements, list):
                            statements = [statements]
                        for stmt in statements:
                            if stmt.get("Effect") == "Allow":
                                principal = stmt.get("Principal", {})
                                if principal == "*" or principal.get("AWS") == "*":
                                    self._add_finding_deduped(findings, self.create_finding(
                                        title=f"S3 Access Point {ap_name} has public policy",
                                        description="Access Point policy allows access from any principal",
                                        severity="critical",
                                        category="data_exposure",
                                        resource_type="s3_access_point",
                                        resource_id=ap_name,
                                        resource_name=ap_name,
                                        region=bucket_region,
                                        evidence=[{"type": "access_point_policy", "description": "Public access point policy", "data": policy_doc}],
                                        rule_id="s3_access_point_public_policy",
                                    ))

        except botocore.exceptions.ClientError as e:
            if e.response["Error"]["Code"] not in ("AccessDenied", "NoSuchAccessPoint"):
                log.warning("Error checking access points for bucket {}: {}", bucket_name, e)

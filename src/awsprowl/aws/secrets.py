"""Secrets Manager scanner for awsProwl."""

from __future__ import annotations

import hashlib

import botocore.exceptions

from awsprowl.aws.base import AWSServiceBase, ScanResult
from awsprowl.core.auth import AWSAuthManager
from awsprowl.core.logging import get_logger

log = get_logger(__name__)


class SecretsScanner(AWSServiceBase):
    """Scanner for AWS Secrets Manager resources."""

    SERVICE_NAME = "secretsmanager"
    REQUIRED_PERMISSIONS = [
        "secretsmanager:ListSecrets",
        "secretsmanager:DescribeSecret",
        "secretsmanager:GetSecretValue",
        "secretsmanager:GetResourcePolicy",
        "secretsmanager:ListSecretVersionIds",
        "kms:DescribeKey",
    ]

    def __init__(self, auth_manager: AWSAuthManager, region: str | None = None):
        super().__init__(auth_manager, region)

    async def scan(self, scan_id: str, findings: list) -> ScanResult:
        """Scan Secrets Manager resources for security issues."""
        result = ScanResult(service=self.SERVICE_NAME, region=self.region)

        try:
            await self._scan_secrets(scan_id, findings, result)

        except Exception as e:
            log.error("Error in Secrets Manager scan: {}", e)
            result.errors.append(str(e))

        return result

    async def _scan_secrets(self, scan_id: str, findings: list, result: ScanResult) -> None:
        """Scan secrets."""
        try:
            paginator = self.client.get_paginator("list_secrets")
            for page in paginator.paginate():
                for secret in page.get("SecretList", []):
                    result.resources_found += 1
                    await self._analyze_secret(secret, scan_id, findings)

        except botocore.exceptions.ClientError as e:
            self.handle_client_error(e, "ListSecrets", findings)

    async def _analyze_secret(self, secret: dict, scan_id: str, findings: list) -> None:
        """Analyze a single secret for security issues."""
        secret_name = secret["Name"]
        secret_arn = secret["ARN"]

        # Add enumeration finding
        await self._add_enumeration_finding("secret", secret_name, secret_name, {
            "arn": secret_arn,
            "rotation_enabled": secret.get("RotationEnabled", False),
            "last_rotated": str(secret.get("LastRotatedDate", "")) if secret.get("LastRotatedDate") else "Never",
            "kms_key_id": secret.get("KmsKeyId", "AWS managed"),
            "description": secret.get("Description", ""),
        }, findings, scan_id)

        # Check rotation
        rotation_enabled = secret.get("RotationEnabled", False)
        if not rotation_enabled:
            self._add_finding_deduped(findings, self.create_finding(
                title=f"Secret {secret_name} does not have rotation enabled",
                description="Secret rotation is not configured, increasing risk of long-lived credentials",
                severity="medium",
                category="weak_configuration",
                resource_type="secret",
                resource_id=secret_name,
                resource_name=secret_name,
                region=self.region,
                evidence=[{"type": "secret_metadata", "description": "Rotation configuration", "data": {"RotationEnabled": rotation_enabled}}],
                remediation={
                    "summary": "Enable automatic rotation",
                    "steps": [
                        "Create Lambda rotation function",
                        "Configure secret rotation schedule",
                        "Test rotation",
                    ],
                    "effort": "medium",
                    "automatable": True,
                },
                rule_id="secrets_rotation_disabled",
            ))

        # Check last rotation date
        last_rotated = secret.get("LastRotatedDate")
        if last_rotated:
            from datetime import datetime, timezone
            age_days = (datetime.now(timezone.utc) - last_rotated).days
            if age_days > 90:
                self._add_finding_deduped(findings, self.create_finding(
                    title=f"Secret {secret_name} not rotated in {age_days} days",
                    description=f"Secret was last rotated {age_days} days ago (recommended: rotate every 90 days)",
                    severity="medium",
                    category="weak_configuration",
                    resource_type="secret",
                    resource_id=secret_name,
                    resource_name=secret_name,
                    region=self.region,
                    evidence=[{"type": "secret_metadata", "description": "Last rotation date", "data": {"LastRotatedDate": str(last_rotated), "age_days": age_days}}],
                    remediation={
                        "summary": "Rotate secret",
                        "steps": [
                            "Trigger manual rotation or wait for scheduled rotation",
                            "Verify applications work with new secret",
                        ],
                        "effort": "low",
                        "automatable": True,
                    },
                    rule_id="secrets_old_rotation",
                ))

        # Check for KMS encryption
        kms_key_id = secret.get("KmsKeyId")
        if not kms_key_id:
            self._add_finding_deduped(findings, self.create_finding(
                title=f"Secret {secret_name} uses default AWS managed KMS key",
                description="Secret is encrypted with AWS managed key instead of customer managed key",
                severity="low",
                category="encryption_missing",
                resource_type="secret",
                resource_id=secret_name,
                resource_name=secret_name,
                region=self.region,
                remediation={
                    "summary": "Use customer managed KMS key",
                    "steps": [
                        "Create customer managed KMS key",
                        "Re-encrypt secret with new key",
                        "Update key policy for least privilege",
                    ],
                    "effort": "medium",
                    "automatable": False,
                },
                rule_id="secrets_aws_managed_key",
            ))

        # Check resource policy
        await self._check_resource_policy(secret_name, secret_arn, scan_id, findings)

        # Check secret versioning
        await self._check_secret_versions(secret_name, secret_arn, scan_id, findings)

    async def _check_resource_policy(self, secret_name: str, secret_arn: str, scan_id: str, findings: list) -> None:
        """Check secret resource policy for overly permissive access."""
        try:
            policy = self.client.get_resource_policy(SecretId=secret_name)
            import json
            policy_doc = json.loads(policy["ResourcePolicy"])

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
                    self._add_finding_deduped(findings, self.create_finding(
                        title=f"Secret {secret_name} has public resource policy",
                        description="Secret resource policy allows access from any principal",
                        severity="critical",
                        category="data_exposure",
                        resource_type="secret",
                        resource_id=secret_name,
                        resource_name=secret_name,
                        region=self.region,
                        evidence=[{"type": "resource_policy", "description": "Public secret policy", "data": policy_doc}],
                        remediation={
                            "summary": "Restrict secret policy to specific principals",
                            "steps": [
                                "Identify required principals (roles, users, accounts)",
                                "Update policy with specific ARNs",
                                "Add conditions (aws:SourceArn, etc.)",
                            ],
                            "effort": "medium",
                            "automatable": False,
                        },
                        rule_id="secrets_public_policy",
                    ))

                # Check for cross-account access without conditions
                if principal.get("AWS"):
                    aws_principals = principal["AWS"]
                    if isinstance(aws_principals, str):
                        aws_principals = [aws_principals]

                    for p in aws_principals:
                        if p.startswith("arn:aws:iam::") and ":root" in p:
                            condition = stmt.get("Condition", {})
                            if not condition:
                                self._add_finding_deduped(findings, self.create_finding(
                                    title=f"Secret {secret_name} allows cross-account root access without conditions",
                                    description=f"Secret policy allows {p} to access without source restrictions",
                                    severity="high",
                                    category="cross_account_access",
                                    resource_type="secret",
                                    resource_id=secret_name,
                                    resource_name=secret_name,
                                    region=self.region,
                                    remediation={
                                        "summary": "Add condition keys to cross-account access",
                                        "steps": [
                                            "Add aws:SourceArn condition",
                                            "Add aws:SourceAccount condition",
                                        ],
                                        "effort": "low",
                                        "automatable": True,
                                    },
                                    rule_id="secrets_cross_account_no_condition",
                                ))

        except botocore.exceptions.ClientError as e:
            if e.response["Error"]["Code"] != "ResourceNotFoundException":
                pass

    async def _check_secret_versions(self, secret_name: str, secret_arn: str, scan_id: str, findings: list) -> None:
        """Check secret versions for staging labels."""
        try:
            versions = self.client.list_secret_version_ids(SecretId=secret_name)
            version_ids = versions.get("Versions", [])

            # Check for versions without staging labels (orphaned)
            for version in version_ids:
                staging_labels = version.get("VersionStages", [])
                if not staging_labels:
                    self._add_finding_deduped(findings, self.create_finding(
                        title=f"Secret {secret_name} has orphaned version: {version['VersionId'][:8]}...",
                        description="Secret version has no staging label (AWSCURRENT, AWSPREVIOUS, etc.)",
                        severity="low",
                        category="weak_configuration",
                        resource_type="secret",
                        resource_id=secret_name,
                        resource_name=secret_name,
                        region=self.region,
                        evidence=[{"type": "secret_version", "description": "Orphaned version", "data": version}],
                        remediation={
                            "summary": "Clean up orphaned secret versions",
                            "steps": [
                                "Verify version is not needed",
                                "Delete orphaned version",
                            ],
                            "effort": "low",
                            "automatable": True,
                        },
                        rule_id="secrets_orphaned_version",
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
            rule_id=f"secrets_enum_{resource_type}",
        )
        self._add_finding_deduped(findings, finding)

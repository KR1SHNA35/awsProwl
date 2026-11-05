"""KMS scanner for awsProwl."""

from __future__ import annotations

import asyncio
import hashlib

import botocore.exceptions

from awsprowl.aws.base import AWSServiceBase, ScanResult
from awsprowl.core.auth import AWSAuthManager
from awsprowl.core.logging import get_logger

log = get_logger(__name__)


class KMSScanner(AWSServiceBase):
    """Scanner for KMS resources."""

    SERVICE_NAME = "kms"
    REQUIRED_PERMISSIONS = [
        "kms:ListKeys",
        "kms:DescribeKey",
        "kms:GetKeyPolicy",
        "kms:GetKeyRotationStatus",
        "kms:ListAliases",
        "kms:ListKeyPolicies",
        "kms:ListGrants",
    ]

    def __init__(self, auth_manager: AWSAuthManager, region: str | None = None):
        super().__init__(auth_manager, region)

    async def scan(self, scan_id: str, findings: list) -> ScanResult:
        """Scan KMS resources for security issues."""
        result = ScanResult(service=self.SERVICE_NAME, region=self.region)

        try:
            await asyncio.gather(
                self._scan_keys(scan_id, findings, result),
                self._scan_aliases(scan_id, findings, result),
                return_exceptions=True,
            )

        except Exception as e:
            log.error("Error in KMS scan: {}", e)
            result.errors.append(str(e))

        return result

    async def _scan_keys(self, scan_id: str, findings: list, result: ScanResult) -> None:
        """Scan KMS keys."""
        try:
            paginator = self.client.get_paginator("list_keys")
            for page in paginator.paginate():
                for key_summary in page.get("Keys", []):
                    result.resources_found += 1
                    key_id = key_summary["KeyId"]
                    await self._analyze_key(key_id, scan_id, findings)

        except botocore.exceptions.ClientError as e:
            self.handle_client_error(e, "ListKeys", findings)

    async def _analyze_key(self, key_id: str, scan_id: str, findings: list) -> None:
        """Analyze a single KMS key."""
        try:
            response = self.client.describe_key(KeyId=key_id)
            key_metadata = response.get("KeyMetadata", {})

            key_state = key_metadata.get("KeyState", "")
            key_manager = key_metadata.get("KeyManager", "")
            origin = key_metadata.get("Origin", "")
            key_usage = key_metadata.get("KeyUsage", "")
            description = key_metadata.get("Description", "")
            key_spec = key_metadata.get("KeySpec", "")
            multi_region = key_metadata.get("MultiRegion", False)
            deletion_date = key_metadata.get("DeletionDate")
            creation_date = key_metadata.get("CreationDate")
            enabled = key_metadata.get("Enabled", False)
            key_rotation = key_metadata.get("KeyRotationEnabled", False)

            # Add enumeration finding
            await self._add_enumeration_finding("kms_key", key_id, description or key_id, {
                "arn": key_metadata.get("Arn", ""),
                "state": key_state,
                "key_manager": key_manager,
                "origin": origin,
                "key_usage": key_usage,
                "key_spec": key_spec,
                "multi_region": multi_region,
                "enabled": enabled,
                "creation_date": creation_date.isoformat() if creation_date else "",
                "deletion_date": deletion_date.isoformat() if deletion_date else "",
                "rotation_enabled": key_rotation,
            }, findings, scan_id)

            # Check if key is disabled
            if not enabled:
                self._add_finding_deduped(findings, self.create_finding(
                    title=f"KMS key {key_id} is disabled",
                    description=f"Key {key_id} ({description}) is disabled and cannot be used",
                    severity="medium",
                    category="weak_configuration",
                    resource_type="kms_key",
                    resource_id=key_id,
                    resource_name=description or key_id,
                    region=self.region,
                    remediation={
                        "summary": "Enable key if needed, or schedule deletion",
                        "steps": [
                            "Determine if key is still needed",
                            "Enable key if required",
                            "Schedule deletion if no longer needed",
                        ],
                        "effort": "low",
                        "automatable": True,
                    },
                    rule_id="kms_key_disabled",
                ))

            # Check if key is pending deletion
            if key_state == "PendingDeletion":
                self._add_finding_deduped(findings, self.create_finding(
                    title=f"KMS key {key_id} is pending deletion",
                    description=f"Key {key_id} is scheduled for deletion on {deletion_date}",
                    severity="medium",
                    category="data_loss_risk",
                    resource_type="kms_key",
                    resource_id=key_id,
                    resource_name=description or key_id,
                    region=self.region,
                    remediation={
                        "summary": "Cancel deletion if key is still needed",
                        "steps": [
                            "Verify if key is still in use",
                            "Cancel key deletion if needed",
                        ],
                        "effort": "low",
                        "automatable": True,
                    },
                    rule_id="kms_key_pending_deletion",
                ))

            # Check key rotation for customer managed keys
            if key_manager == "CUSTOMER" and origin == "AWS_KMS":
                rotation_status = False
                try:
                    rot_response = self.client.get_key_rotation_status(KeyId=key_id)
                    rotation_status = rot_response.get("KeyRotationEnabled", False)
                except botocore.exceptions.ClientError:
                    pass

                if not rotation_status:
                    self._add_finding_deduped(findings, self.create_finding(
                        title=f"KMS key {key_id} has automatic key rotation disabled",
                        description="Customer managed key does not have automatic annual rotation enabled",
                        severity="medium",
                        category="weak_configuration",
                        resource_type="kms_key",
                        resource_id=key_id,
                        resource_name=description or key_id,
                        region=self.region,
                        remediation={
                            "summary": "Enable automatic key rotation",
                            "steps": [
                                "Enable automatic key rotation for the key",
                            ],
                            "effort": "low",
                            "automatable": True,
                            "cli_commands": [
                                f"aws kms enable-key-rotation --key-id {key_id}",
                            ],
                        },
                        rule_id="kms_key_rotation_disabled",
                    ))

            # Check key policy for overly permissive access
            await self._check_key_policy(key_id, description, scan_id, findings)

            # Check for external accounts in key policy (cross-account access)
            await self._check_cross_account_access(key_id, description, scan_id, findings)

            # Check grants for excessive permissions
            await self._check_grants(key_id, description, scan_id, findings)

            # Check key spec strength
            if key_spec in ("RSA_2048", "RSA_3072", "RSA_4096", "ECC_NIST_P256", "ECC_NIST_P384", "ECC_NIST_P521", "ECC_SECG_P256K1"):
                # These are fine
                pass
            elif key_spec and "RSA" in key_spec:
                # Check for weak RSA
                if "1024" in key_spec:
                    self._add_finding_deduped(findings, self.create_finding(
                        title=f"KMS key {key_id} uses weak RSA key size: {key_spec}",
                        description="RSA 1024-bit keys are considered weak",
                        severity="high",
                        category="weak_configuration",
                        resource_type="kms_key",
                        resource_id=key_id,
                        resource_name=description or key_id,
                        region=self.region,
                        rule_id="kms_weak_rsa_key",
                    ))

            # Check for imported key material (EXTERNAL origin)
            if origin == "EXTERNAL":
                self._add_finding_deduped(findings, self.create_finding(
                    title=f"KMS key {key_id} uses imported key material",
                    description="Key was created with imported key material (EXTERNAL origin)",
                    severity="info",
                    category="informational",
                    resource_type="kms_key",
                    resource_id=key_id,
                    resource_name=description or key_id,
                    region=self.region,
                    evidence=[{"type": "key_metadata", "description": "External key origin", "data": {"origin": origin, "key_manager": key_manager}}],
                    rule_id="kms_external_key",
                ))

            # Check for multi-region keys
            if multi_region:
                self._add_finding_deduped(findings, self.create_finding(
                    title=f"KMS key {key_id} is a multi-region key",
                    description="Multi-region keys replicate across regions automatically",
                    severity="info",
                    category="informational",
                    resource_type="kms_key",
                    resource_id=key_id,
                    resource_name=description or key_id,
                    region=self.region,
                    rule_id="kms_multi_region_key",
                ))

            # Check for asymmetric keys used for encryption (should be for signing)
            if key_usage == "SIGN_VERIFY":
                self._add_finding_deduped(findings, self.create_finding(
                    title=f"KMS key {key_id} is asymmetric signing key",
                    description=f"Key {key_id} is configured for signing only (key usage: {key_usage})",
                    severity="info",
                    category="informational",
                    resource_type="kms_key",
                    resource_id=key_id,
                    resource_name=description or key_id,
                    region=self.region,
                    rule_id="kms_signing_key",
                ))

        except botocore.exceptions.ClientError as e:
            self.handle_client_error(e, "DescribeKey", findings)

    async def _check_key_policy(self, key_id: str, description: str, scan_id: str, findings: list) -> None:
        """Check KMS key policy for security issues."""
        try:
            policy_response = self.client.get_key_policy(KeyId=key_id, PolicyName="default")
            import json
            policy = json.loads(policy_response.get("Policy", "{}"))

            statements = policy.get("Statement", [])
            if not isinstance(statements, list):
                statements = [statements]

            for stmt in statements:
                effect = stmt.get("Effect", "")
                if effect != "Allow":
                    continue

                principal = stmt.get("Principal", {})
                actions = stmt.get("Action", [])
                if isinstance(actions, str):
                    actions = [actions]

                resources = stmt.get("Resource", [])
                if isinstance(resources, str):
                    resources = [resources]

                # Check for wildcard principal (any AWS account)
                if principal == "*" or (isinstance(principal, dict) and principal.get("AWS") == "*"):
                    if "*" in actions or any("kms:*" in a for a in actions):
                        self._add_finding_deduped(findings, self.create_finding(
                            title=f"KMS key {key_id} policy allows public access",
                            description="Key policy allows any principal to perform all KMS actions",
                            severity="critical",
                            category="excessive_permissions",
                            resource_type="kms_key",
                            resource_id=key_id,
                            resource_name=description or key_id,
                            region=self.region,
                            evidence=[{"type": "key_policy", "description": "Overly permissive policy statement", "data": stmt}],
                            remediation={
                                "summary": "Restrict key policy to specific principals",
                                "steps": [
                                    "Identify required principals (roles, users, accounts)",
                                    "Update key policy with specific ARNs",
                                    "Remove wildcard principals",
                                ],
                                "effort": "medium",
                                "automatable": False,
                            },
                            rule_id="kms_key_policy_public",
                        ))

                # Check for root account access (allowing entire account)
                if isinstance(principal, dict) and "AWS" in principal:
                    aws_principals = principal["AWS"]
                    if isinstance(aws_principals, str):
                        aws_principals = [aws_principals]

                    for p in aws_principals:
                        if p.endswith(":root") or (":root" in p and p.count(":") == 5):
                            # Root account access - check if it's the same account
                            account_id = self.auth_manager.get_caller_identity().get("Account", "")
                            if account_id and account_id not in p:
                                self._add_finding_deduped(findings, self.create_finding(
                                    title=f"KMS key {key_id} policy allows cross-account root access",
                                    description=f"Key policy grants access to root of external account: {p}",
                                    severity="high",
                                    category="excessive_permissions",
                                    resource_type="kms_key",
                                    resource_id=key_id,
                                    resource_name=description or key_id,
                                    region=self.region,
                                    evidence=[{"type": "key_policy", "description": "Cross-account root access", "data": {"principal": p, "actions": actions}}],
                                    remediation={
                                        "summary": "Restrict cross-account access to specific roles",
                                        "steps": [
                                            "Replace root account ARN with specific role ARNs",
                                            "Add condition keys for additional restrictions",
                                        ],
                                        "effort": "medium",
                                        "automatable": False,
                                    },
                                    rule_id="kms_key_policy_cross_account_root",
                                ))

                # Check for missing conditions on sensitive actions
                sensitive_actions = ["kms:Decrypt", "kms:ReEncrypt*", "kms:GenerateDataKey*", "kms:DescribeKey"]
                has_sensitive = any(any(sa in a for sa in sensitive_actions) for a in actions)
                conditions = stmt.get("Condition", {})

                if has_sensitive and not conditions:
                    self._add_finding_deduped(findings, self.create_finding(
                        title=f"KMS key {key_id} policy grants sensitive permissions without conditions",
                        description="Key policy allows decrypt/re-encrypt/data key generation without conditions",
                        severity="medium",
                        category="weak_configuration",
                        resource_type="kms_key",
                        resource_id=key_id,
                        resource_name=description or key_id,
                        region=self.region,
                        evidence=[{"type": "key_policy", "description": "Sensitive actions without conditions", "data": {"actions": actions, "conditions": conditions}}],
                        remediation={
                            "summary": "Add conditions to restrict sensitive operations",
                            "steps": [
                                "Add kms:EncryptionContext condition for decrypt operations",
                                "Add kms:ViaService condition to restrict service usage",
                                "Add aws:SourceArn/aws:SourceAccount for service-linked access",
                            ],
                            "effort": "medium",
                            "automatable": True,
                        },
                        rule_id="kms_key_policy_no_conditions",
                    ))

        except botocore.exceptions.ClientError as e:
            if e.response["Error"]["Code"] != "AccessDenied":
                self.handle_client_error(e, "GetKeyPolicy", findings)

    async def _check_cross_account_access(self, key_id: str, description: str, scan_id: str, findings: list) -> None:
        """Check for cross-account access in key policy."""
        # This is covered in _check_key_policy but we can add more detailed checks here
        pass

    async def _check_grants(self, key_id: str, description: str, scan_id: str, findings: list) -> None:
        """Check KMS grants for excessive permissions."""
        try:
            paginator = self.client.get_paginator("list_grants")
            grant_count = 0
            for page in paginator.paginate(KeyId=key_id):
                for grant in page.get("Grants", []):
                    grant_count += 1
                    grantee = grant.get("GranteePrincipal", "")
                    operations = grant.get("Operations", [])
                    retiring_principal = grant.get("RetiringPrincipal", "")

                    # Check for excessive operations
                    sensitive_ops = ["Decrypt", "ReEncryptFrom", "ReEncryptTo", "GenerateDataKey", "GenerateDataKeyWithoutPlaintext"]
                    has_sensitive = any(op in sensitive_ops for op in operations)

                    # Check if grant is to external account
                    account_id = self.auth_manager.get_caller_identity().get("Account", "")
                    if account_id and account_id not in grantee:
                        self._add_finding_deduped(findings, self.create_finding(
                            title=f"KMS key {key_id} has cross-account grant",
                            description=f"Grant to {grantee} allows operations: {', '.join(operations)}",
                            severity="medium" if has_sensitive else "low",
                            category="excessive_permissions",
                            resource_type="kms_key",
                            resource_id=key_id,
                            resource_name=description or key_id,
                            region=self.region,
                            evidence=[{"type": "grant", "description": "Cross-account grant", "data": {"grantee": grantee, "operations": operations, "retiring_principal": retiring_principal}}],
                            rule_id="kms_cross_account_grant",
                        ))

            if grant_count > 10:
                self._add_finding_deduped(findings, self.create_finding(
                    title=f"KMS key {key_id} has many grants ({grant_count})",
                    description="Large number of grants may indicate overly complex access control",
                    severity="low",
                    category="weak_configuration",
                    resource_type="kms_key",
                    resource_id=key_id,
                    resource_name=description or key_id,
                    region=self.region,
                    rule_id="kms_many_grants",
                ))

        except botocore.exceptions.ClientError as e:
            if e.response["Error"]["Code"] != "AccessDenied":
                self.handle_client_error(e, "ListGrants", findings)

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
            rule_id=f"kms_enum_{resource_type}",
        )
        self._add_finding_deduped(findings, finding)

    async def _scan_aliases(self, scan_id: str, findings: list, result: ScanResult) -> None:
        """Scan KMS aliases."""
        try:
            paginator = self.client.get_paginator("list_aliases")
            for page in paginator.paginate():
                for alias in page.get("Aliases", []):
                    alias_name = alias.get("AliasName", "")
                    alias_arn = alias.get("AliasArn", "")
                    target_key_id = alias.get("TargetKeyId", "")

                    if not alias_name or not alias_name.startswith("alias/"):
                        continue

                    result.resources_found += 1

                    # Add enumeration finding
                    await self._add_enumeration_finding("kms_alias", alias_name, alias_name, {
                        "arn": alias_arn,
                        "target_key_id": target_key_id,
                    }, findings, scan_id)

                    # Check for cross-account aliases (alias points to key in another account)
                    if target_key_id and alias_arn:
                        # Parse account ID from alias ARN
                        # Format: arn:aws:kms:region:account-id:alias/alias-name
                        alias_parts = alias_arn.split(":")
                        if len(alias_parts) >= 5:
                            alias_account = alias_parts[4]
                            account_id = self.auth_manager.get_caller_identity().get("Account", "")
                            if account_id and account_id != alias_account:
                                self._add_finding_deduped(findings, self.create_finding(
                                    title=f"KMS alias {alias_name} points to key in different account",
                                    description=f"Alias {alias_name} in account {alias_account} targets key {target_key_id}",
                                    severity="medium",
                                    category="cross_account_access",
                                    resource_type="kms_alias",
                                    resource_id=alias_name,
                                    resource_name=alias_name,
                                    region=self.region,
                                    evidence=[{"type": "alias", "description": "Cross-account alias", "data": {"alias_arn": alias_arn, "target_key_id": target_key_id, "alias_account": alias_account}}],
                                    remediation={
                                        "summary": "Review cross-account alias usage",
                                        "steps": [
                                            "Verify if cross-account key access is intentional",
                                            "Consider using local keys with grants instead",
                                        ],
                                        "effort": "medium",
                                        "automatable": False,
                                    },
                                    rule_id="kms_alias_cross_account",
                                ))

                    # Check for aliases without target keys (orphaned aliases)
                    if not target_key_id:
                        self._add_finding_deduped(findings, self.create_finding(
                            title=f"KMS alias {alias_name} has no target key",
                            description=f"Alias {alias_name} exists but does not point to any key",
                            severity="low",
                            category="misconfiguration",
                            resource_type="kms_alias",
                            resource_id=alias_name,
                            resource_name=alias_name,
                            region=self.region,
                            evidence=[{"type": "alias", "description": "Orphaned alias", "data": {"alias_arn": alias_arn}}],
                            remediation={
                                "summary": "Remove or update orphaned alias",
                                "steps": [
                                    "Delete the alias if not needed",
                                    "Or update it to point to a valid key",
                                ],
                                "effort": "low",
                                "automatable": True,
                                "cli_commands": [
                                    f"aws kms delete-alias --alias-name {alias_name}",
                                ],
                            },
                            rule_id="kms_alias_orphaned",
                        ))

                    # Check for AWS managed aliases (aws/*) that might be unused
                    if alias_name.startswith("alias/aws/"):
                        # Check if the target key is AWS managed
                        if target_key_id:
                            try:
                                key_desc = self.client.describe_key(KeyId=target_key_id)
                                key_metadata = key_desc.get("KeyMetadata", {})
                                if key_metadata.get("KeyManager") == "AWS":
                                    self._add_finding_deduped(findings, self.create_finding(
                                        title=f"AWS managed alias {alias_name} for AWS managed key",
                                        description=f"Alias {alias_name} points to AWS managed key {target_key_id}",
                                        severity="info",
                                        category="informational",
                                        resource_type="kms_alias",
                                        resource_id=alias_name,
                                        resource_name=alias_name,
                                        region=self.region,
                                        evidence=[{"type": "alias", "description": "AWS managed alias", "data": {"alias_name": alias_name, "target_key_id": target_key_id}}],
                                        rule_id="kms_alias_aws_managed",
                                    ))
                            except botocore.exceptions.ClientError:
                                pass

        except botocore.exceptions.ClientError as e:
            self.handle_client_error(e, "ListAliases", findings)

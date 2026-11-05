"""STS scanner for awsProwl."""

from __future__ import annotations

import asyncio

import botocore.exceptions

from awsprowl.aws.base import AWSServiceBase, ScanResult
from awsprowl.core.auth import AWSAuthManager
from awsprowl.core.logging import get_logger

log = get_logger(__name__)


class STSScanner(AWSServiceBase):
    """Scanner for STS (Security Token Service) resources."""

    SERVICE_NAME = "sts"
    REQUIRED_PERMISSIONS = [
        "sts:GetCallerIdentity",
        "sts:GetSessionToken",
        "sts:GetAccessKeyInfo",
        "sts:GetFederationToken",
        "iam:ListAccountAliases",
        "iam:GetAccountSummary",
        "iam:ListVirtualMFADevices",
        "iam:ListSAMLProviders",
        "iam:ListOpenIDConnectProviders",
        "iam:ListRoles",
    ]

    def __init__(self, auth_manager: AWSAuthManager, region: str | None = None):
        super().__init__(auth_manager, region or "us-east-1")  # STS is global

    async def scan(self, scan_id: str, findings: list) -> ScanResult:
        """Scan STS/Account resources for security issues."""
        result = ScanResult(service=self.SERVICE_NAME, region="global")

        try:
            await asyncio.gather(
                self._scan_account_settings(scan_id, findings, result),
                self._scan_credential_report(scan_id, findings, result),
                self._scan_mfa_devices(scan_id, findings, result),
                self._scan_saml_providers(scan_id, findings, result),
                self._scan_oidc_providers(scan_id, findings, result),
                self._scan_cross_account_roles(scan_id, findings, result),
                self._scan_federation(scan_id, findings, result),
                return_exceptions=True,
            )

        except Exception as e:
            log.error("Error in STS/Account scan: {}", e)
            result.errors.append(str(e))

        return result

    async def _scan_account_settings(self, scan_id: str, findings: list, result: ScanResult) -> None:
        """Scan account-level settings."""
        try:
            # Get caller identity
            identity = self.client.get_caller_identity()
            account_id = identity.get("Account", "")
            user_arn = identity.get("Arn", "")

            result.resources_found += 1

            # Get account aliases
            aliases = self.client.list_account_aliases()
            alias = aliases.get("AccountAliases", [""])[0] if aliases.get("AccountAliases") else ""

            # Get account summary
            summary = self.client.get_account_summary()
            summary_map = summary.get("SummaryMap", {})

            # Check for root access keys
            root_access_keys = summary_map.get("AccountAccessKeysPresent", 0)
            if root_access_keys > 0:
                findings.append(self.create_finding(
                    title="Root account has access keys",
                    description="Root user has active access keys (should never be used)",
                    severity="critical",
                    category="weak_configuration",
                    resource_type="aws_account",
                    resource_id=account_id,
                    resource_name=alias or account_id,
                    region="global",
                    evidence=[{"type": "account_summary", "description": "Root access keys present", "data": {"AccountAccessKeysPresent": root_access_keys}}],
                    remediation={
                        "summary": "Delete root access keys",
                        "steps": [
                            "Create IAM users/roles for programmatic access",
                            "Delete root access keys",
                            "Enable MFA on root account",
                        ],
                        "effort": "low",
                        "automatable": True,
                        "cli_commands": [
                            "aws iam delete-access-key --user-name root --access-key-id <key-id>",
                        ],
                    },
                    rule_id="sts_root_access_keys",
                ))

            # Check for MFA on root
            root_mfa = summary_map.get("AccountMFAEnabled", 0)
            if root_mfa == 0:
                findings.append(self.create_finding(
                    title="Root account does not have MFA enabled",
                    description="Root user does not have MFA enabled",
                    severity="critical",
                    category="weak_configuration",
                    resource_type="aws_account",
                    resource_id=account_id,
                    resource_name=alias or account_id,
                    region="global",
                    remediation={
                        "summary": "Enable MFA on root account",
                        "steps": [
                            "Log in as root user",
                            "Enable virtual or hardware MFA",
                        ],
                        "effort": "low",
                        "automatable": False,
                    },
                    rule_id="sts_root_no_mfa",
                ))

            # Check password policy
            password_policy = summary_map.get("PasswordPolicy", {})
            if not password_policy:
                findings.append(self.create_finding(
                    title="Account has no password policy",
                    description="No IAM password policy is configured",
                    severity="high",
                    category="weak_configuration",
                    resource_type="aws_account",
                    resource_id=account_id,
                    resource_name=alias or account_id,
                    region="global",
                    remediation={
                        "summary": "Set account password policy",
                        "steps": [
                            "Configure minimum password length (8+)",
                            "Require uppercase, lowercase, numbers, symbols",
                            "Set password expiration and reuse prevention",
                        ],
                        "effort": "low",
                        "automatable": True,
                        "cli_commands": [
                            "aws iam update-account-password-policy --minimum-password-length 12 --require-uppercase --require-lowercase --require-numbers --require-symbols --max-password-age 90 --password-reuse-prevention 24",
                        ],
                    },
                    rule_id="sts_no_password_policy",
                ))

        except botocore.exceptions.ClientError as e:
            self.handle_client_error(e, "GetCallerIdentity/GetAccountSummary", findings)

    async def _scan_credential_report(self, scan_id: str, findings: list, result: ScanResult) -> None:
        """Generate and analyze IAM credential report."""
        try:
            # Generate credential report
            self.client.generate_credential_report()

            # Get credential report
            import time
            for _ in range(10):
                time.sleep(1)
                try:
                    report = self.client.get_credential_report()
                    break
                except botocore.exceptions.ClientError as e:
                    if e.response["Error"]["Code"] == "ReportNotPresent":
                        continue
                    raise
            else:
                return

            content = report.get("Content", b"").decode("utf-8")
            lines = content.strip().split("\n")
            if len(lines) < 2:
                return

            headers = lines[0].split(",")
            for line in lines[1:]:
                values = line.split(",")
                if len(values) != len(headers):
                    continue

                user_data = dict(zip(headers, values))
                user_name = user_data.get("user", "")

                if not user_name or user_name == "<root>":
                    continue

                result.resources_found += 1

                # Check for active access keys
                for key_num in [1, 2]:
                    key_active = user_data.get(f"access_key_{key_num}_active", "false")
                    if key_active.lower() == "true":
                        key_last_rotated = user_data.get(f"access_key_{key_num}_last_rotated", "")
                        if key_last_rotated:
                            from datetime import datetime, timezone
                            try:
                                last_rotated = datetime.fromisoformat(key_last_rotated.replace("Z", "+00:00"))
                                age_days = (datetime.now(timezone.utc) - last_rotated).days
                                if age_days > 90:
                                    findings.append(self.create_finding(
                                        title=f"IAM user {user_name} has access key {key_num} not rotated in {age_days} days",
                                        description=f"Access key {key_num} for user {user_name} is {age_days} days old",
                                        severity="medium",
                                        category="weak_configuration",
                                        resource_type="iam_user",
                                        resource_id=user_name,
                                        resource_name=user_name,
                                        region="global",
                                        evidence=[{"type": "credential_report", "description": f"Access key {key_num} age", "data": {"user": user_name, "key_number": key_num, "age_days": age_days}}],
                                        remediation={
                                            "summary": "Rotate access key",
                                            "steps": [
                                                "Create new access key",
                                                "Update applications",
                                                "Deactivate old key",
                                            ],
                                            "effort": "low",
                                            "automatable": True,
                                        },
                                        rule_id=f"sts_old_access_key_{key_num}",
                                    ))
                            except Exception:
                                pass

                # Check for MFA
                mfa_active = user_data.get("mfa_active", "false")
                if mfa_active.lower() != "true":
                    findings.append(self.create_finding(
                        title=f"IAM user {user_name} does not have MFA enabled",
                        description="User does not have MFA device configured",
                        severity="high",
                        category="weak_configuration",
                        resource_type="iam_user",
                        resource_id=user_name,
                        resource_name=user_name,
                        region="global",
                        remediation={
                            "summary": "Enable MFA for user",
                            "steps": [
                                "Create virtual MFA device",
                                "Enable MFA for user",
                            ],
                            "effort": "low",
                            "automatable": True,
                        },
                        rule_id="sts_user_no_mfa",
                    ))

                # Check for console access without MFA
                console_access = user_data.get("password_enabled", "false")
                if console_access.lower() == "true" and mfa_active.lower() != "true":
                    findings.append(self.create_finding(
                        title=f"IAM user {user_name} has console access without MFA",
                        description="User can log into AWS Console without MFA",
                        severity="high",
                        category="weak_configuration",
                        resource_type="iam_user",
                        resource_id=user_name,
                        resource_name=user_name,
                        region="global",
                        rule_id="sts_console_no_mfa",
                    ))

                # Check for unused credentials
                password_last_used = user_data.get("password_last_used", "N/A")
                if password_last_used not in ("N/A", "no_information"):
                    try:
                        last_used = datetime.fromisoformat(password_last_used.replace("Z", "+00:00"))
                        days_unused = (datetime.now(timezone.utc) - last_used).days
                        if days_unused > 90:
                            findings.append(self.create_finding(
                                title=f"IAM user {user_name} has not logged in for {days_unused} days",
                                description=f"Console password last used {days_unused} days ago",
                                severity="low",
                                category="unused_credentials",
                                resource_type="iam_user",
                                resource_id=user_name,
                                resource_name=user_name,
                                region="global",
                                remediation={
                                    "summary": "Review and remove unused credentials",
                                    "steps": [
                                        "Verify if user still needs access",
                                        "Disable console password if not needed",
                                    ],
                                    "effort": "low",
                                    "automatable": True,
                                },
                                rule_id="sts_unused_console",
                            ))
                    except Exception:
                        pass

                # Check access key last used
                for key_num in [1, 2]:
                    key_last_used = user_data.get(f"access_key_{key_num}_last_used_date", "N/A")
                    if key_last_used not in ("N/A", "no_information"):
                        try:
                            last_used = datetime.fromisoformat(key_last_used.replace("Z", "+00:00"))
                            days_unused = (datetime.now(timezone.utc) - last_used).days
                            if days_unused > 90:
                                findings.append(self.create_finding(
                                    title=f"IAM user {user_name} access key {key_num} not used for {days_unused} days",
                                    description=f"Access key {key_num} last used {days_unused} days ago",
                                    severity="low",
                                    category="unused_credentials",
                                    resource_type="iam_user",
                                    resource_id=user_name,
                                    resource_name=user_name,
                                    region="global",
                                    remediation={
                                        "summary": "Review and remove unused access keys",
                                        "steps": [
                                            "Verify if access key is still needed",
                                            "Deactivate and delete if not needed",
                                        ],
                                        "effort": "low",
                                        "automatable": True,
                                    },
                                    rule_id=f"sts_unused_access_key_{key_num}",
                                ))
                        except Exception:
                            pass

        except botocore.exceptions.ClientError:
            pass

    async def _scan_mfa_devices(self, scan_id: str, findings: list, result: ScanResult) -> None:
        """Scan for virtual MFA devices."""
        try:
            mfa_devices = self.client.list_virtual_mfa_devices()
            for device in mfa_devices.get("VirtualMFADevices", []):
                result.resources_found += 1
                serial = device.get("SerialNumber", "")
                user = device.get("User", {})
                user_name = user.get("UserName", "") if user else ""

                # Check for unassigned MFA devices
                if not user_name:
                    findings.append(self.create_finding(
                        title=f"Unassigned virtual MFA device: {serial}",
                        description="Virtual MFA device is not assigned to any user",
                        severity="low",
                        category="unused_credentials",
                        resource_type="mfa_device",
                        resource_id=serial,
                        resource_name=serial,
                        region="global",
                        remediation={
                            "summary": "Assign or delete unassigned MFA device",
                            "steps": [
                                "Assign to a user or delete the device",
                            ],
                            "effort": "low",
                            "automatable": True,
                        },
                        rule_id="sts_unassigned_mfa",
                    ))

        except botocore.exceptions.ClientError:
            pass

    async def _scan_saml_providers(self, scan_id: str, findings: list, result: ScanResult) -> None:
        """Scan SAML identity providers."""
        try:
            providers = self.client.list_saml_providers()
            for provider in providers.get("SAMLProviderList", []):
                result.resources_found += 1
                provider_arn = provider.get("Arn", "")
                provider_name = provider_arn.split("/")[-1] if provider_arn else "Unknown"
                create_date = provider.get("CreateDate", "")
                valid_until = provider.get("ValidUntil", "")

                # Check if SAML provider is expiring soon
                if valid_until:
                    from datetime import datetime, timezone
                    try:
                        expiry = datetime.fromisoformat(valid_until.replace("Z", "+00:00"))
                        days_until_expiry = (expiry - datetime.now(timezone.utc)).days
                        if days_until_expiry < 30:
                            findings.append(self.create_finding(
                                title=f"SAML provider {provider_name} expires in {days_until_expiry} days",
                                description=f"SAML identity provider certificate expires on {valid_until}",
                                severity="high" if days_until_expiry < 7 else "medium",
                                category="weak_configuration",
                                resource_type="saml_provider",
                                resource_id=provider_name,
                                resource_name=provider_name,
                                region="global",
                                evidence=[{"type": "saml_provider", "description": "SAML provider expiry", "data": {"provider_arn": provider_arn, "create_date": str(create_date), "valid_until": str(valid_until), "days_until_expiry": days_until_expiry}}],
                                remediation={
                                    "summary": "Renew SAML provider certificate",
                                    "steps": [
                                        "Obtain new metadata from identity provider",
                                        "Update SAML provider with new certificate",
                                    ],
                                    "effort": "medium",
                                    "automatable": False,
                                },
                                rule_id="sts_saml_expiring",
                            ))
                    except Exception:
                        pass

                # Check for SAML provider without valid metadata
                findings.append(self.create_finding(
                    title=f"SAML Identity Provider: {provider_name}",
                    description=f"SAML provider ARN: {provider_arn}, Created: {create_date}, Valid until: {valid_until}",
                    severity="info",
                    category="informational",
                    resource_type="saml_provider",
                    resource_id=provider_name,
                    resource_name=provider_name,
                    region="global",
                    rule_id="sts_list_saml_provider",
                ))

        except botocore.exceptions.ClientError as e:
            self.handle_client_error(e, "ListSAMLProviders", findings)

    async def _scan_oidc_providers(self, scan_id: str, findings: list, result: ScanResult) -> None:
        """Scan OIDC (OpenID Connect) identity providers."""
        try:
            providers = self.client.list_open_id_connect_providers()
            for provider in providers.get("OpenIDConnectProviderList", []):
                result.resources_found += 1
                provider_arn = provider.get("Arn", "")
                provider_name = provider_arn.split("/")[-1] if provider_arn else "Unknown"

                # Get provider details
                try:
                    details = self.client.get_open_id_connect_provider(OpenIDConnectProviderArn=provider_arn)
                    url = details.get("Url", "")
                    client_ids = details.get("ClientIDList", [])
                    thumbprints = details.get("ThumbprintList", [])
                    create_date = details.get("CreateDate", "")
                    tags = details.get("Tags", [])

                    # Check for multiple client IDs (could indicate shared provider)
                    if len(client_ids) > 1:
                        findings.append(self.create_finding(
                            title=f"OIDC provider {provider_name} has multiple client IDs",
                            description=f"Provider has {len(client_ids)} client IDs configured: {', '.join(client_ids)}",
                            severity="medium",
                            category="weak_configuration",
                            resource_type="oidc_provider",
                            resource_id=provider_name,
                            resource_name=provider_name,
                            region="global",
                            evidence=[{"type": "oidc_provider", "description": "Multiple client IDs", "data": {"provider_arn": provider_arn, "client_ids": client_ids, "url": url}}],
                            remediation={
                                "summary": "Review OIDC provider client IDs",
                                "steps": [
                                    "Verify each client ID is necessary",
                                    "Remove unused client IDs",
                                ],
                                "effort": "low",
                                "automatable": True,
                            },
                            rule_id="sts_oidc_multiple_clients",
                        ))

                    # Check for missing thumbprints
                    if not thumbprints:
                        findings.append(self.create_finding(
                            title=f"OIDC provider {provider_name} has no thumbprints configured",
                            description="OIDC provider should have at least one certificate thumbprint for validation",
                            severity="high",
                            category="weak_configuration",
                            resource_type="oidc_provider",
                            resource_id=provider_name,
                            resource_name=provider_name,
                            region="global",
                            evidence=[{"type": "oidc_provider", "description": "Missing thumbprints", "data": {"provider_arn": provider_arn, "url": url}}],
                            remediation={
                                "summary": "Add certificate thumbprints to OIDC provider",
                                "steps": [
                                    "Get certificate thumbprint from identity provider",
                                    "Update OIDC provider with thumbprint",
                                ],
                                "effort": "low",
                                "automatable": False,
                            },
                            rule_id="sts_oidc_no_thumbprint",
                        ))

                    findings.append(self.create_finding(
                        title=f"OIDC Identity Provider: {provider_name}",
                        description=f"OIDC provider ARN: {provider_arn}, URL: {url}, Client IDs: {len(client_ids)}, Thumbprints: {len(thumbprints)}, Created: {create_date}",
                        severity="info",
                        category="informational",
                        resource_type="oidc_provider",
                        resource_id=provider_name,
                        resource_name=provider_name,
                        region="global",
                        rule_id="sts_list_oidc_provider",
                    ))

                except botocore.exceptions.ClientError:
                    findings.append(self.create_finding(
                        title=f"OIDC Identity Provider: {provider_name}",
                        description=f"OIDC provider ARN: {provider_arn} (details unavailable)",
                        severity="info",
                        category="informational",
                        resource_type="oidc_provider",
                        resource_id=provider_name,
                        resource_name=provider_name,
                        region="global",
                        rule_id="sts_list_oidc_provider",
                    ))

        except botocore.exceptions.ClientError as e:
            self.handle_client_error(e, "ListOpenIDConnectProviders", findings)

    async def _scan_cross_account_roles(self, scan_id: str, findings: list, result: ScanResult) -> None:
        """Scan for IAM roles with cross-account trust policies."""
        try:
            paginator = self.client.get_paginator("list_roles")
            for page in paginator.paginate():
                for role in page.get("Roles", []):
                    # Skip AWS service-linked roles
                    if role.get("Path", "").startswith("/aws-service-role/"):
                        continue

                    role_name = role["RoleName"]
                    role_arn = role["Arn"]
                    assume_role_policy = role.get("AssumeRolePolicyDocument", {})

                    result.resources_found += 1

                    # Parse trust policy for cross-account access
                    statements = assume_role_policy.get("Statement", [])
                    if not isinstance(statements, list):
                        statements = [statements]

                    for stmt in statements:
                        if stmt.get("Effect") != "Allow":
                            continue

                        principal = stmt.get("Principal", {})
                        if not principal:
                            continue

                        # Check for AWS principals (cross-account)
                        if "AWS" in principal:
                            aws_principals = principal["AWS"]
                            if isinstance(aws_principals, str):
                                aws_principals = [aws_principals]

                            for p in aws_principals:
                                if p.startswith("arn:aws:iam::") and ":root" in p:
                                    # Extract account ID
                                    parts = p.split(":")
                                    if len(parts) >= 5:
                                        trusted_account = parts[4]
                                        # Get current account ID
                                        identity = self.client.get_caller_identity()
                                        current_account = identity.get("Account", "")

                                        if trusted_account != current_account:
                                            # Check for conditions
                                            condition = stmt.get("Condition", {})
                                            if not condition:
                                                findings.append(self.create_finding(
                                                    title=f"Role {role_name} allows cross-account assume from {trusted_account} without conditions",
                                                    description=f"Role trust policy allows account {trusted_account} root to assume role without source restrictions",
                                                    severity="high",
                                                    category="cross_account_access",
                                                    resource_type="iam_role",
                                                    resource_id=role_name,
                                                    resource_name=role_name,
                                                    region="global",
                                                    evidence=[{"type": "trust_policy", "description": "Cross-account trust without conditions", "data": {"role_arn": role_arn, "trusted_account": trusted_account, "statement": stmt}}],
                                                    remediation={
                                                        "summary": "Add condition keys to cross-account trust",
                                                        "steps": [
                                                            "Add aws:SourceArn condition to restrict to specific resources",
                                                            "Add aws:SourceAccount condition",
                                                            "Consider using external ID",
                                                        ],
                                                        "effort": "low",
                                                        "automatable": True,
                                                    },
                                                    rule_id="sts_cross_account_no_condition",
                                                ))
                                            else:
                                                findings.append(self.create_finding(
                                                    title=f"Role {role_name} allows cross-account assume from {trusted_account}",
                                                    description=f"Role trust policy allows account {trusted_account} root to assume role with conditions: {list(condition.keys())}",
                                                    severity="medium",
                                                    category="cross_account_access",
                                                    resource_type="iam_role",
                                                    resource_id=role_name,
                                                    resource_name=role_name,
                                                    region="global",
                                                    evidence=[{"type": "trust_policy", "description": "Cross-account trust with conditions", "data": {"role_arn": role_arn, "trusted_account": trusted_account, "conditions": list(condition.keys())}}],
                                                    rule_id="sts_cross_account_with_condition",
                                                ))

                        # Check for federated principals (SAML/OIDC)
                        if "Federated" in principal:
                            federated = principal["Federated"]
                            if isinstance(federated, str):
                                federated = [federated]

                            for fed in federated:
                                if "saml-provider" in fed or "oidc-provider" in fed:
                                    findings.append(self.create_finding(
                                        title=f"Role {role_name} allows federated assume via {fed}",
                                        description=f"Role trust policy allows federation through {fed}",
                                        severity="info",
                                        category="cross_account_access",
                                        resource_type="iam_role",
                                        resource_id=role_name,
                                        resource_name=role_name,
                                        region="global",
                                        evidence=[{"type": "trust_policy", "description": "Federated trust", "data": {"role_arn": role_arn, "federated_provider": fed}}],
                                        rule_id="sts_federated_trust",
                                    ))

                        # Check for wildcard principal
                        if principal == "*" or principal.get("AWS") == "*":
                            findings.append(self.create_finding(
                                title=f"Role {role_name} has public trust policy (allows anyone to assume)",
                                description="Role trust policy allows any principal to assume this role",
                                severity="critical",
                                category="data_exposure",
                                resource_type="iam_role",
                                resource_id=role_name,
                                resource_name=role_name,
                                region="global",
                                evidence=[{"type": "trust_policy", "description": "Public trust policy", "data": {"role_arn": role_arn, "statement": stmt}}],
                                remediation={
                                    "summary": "Restrict trust policy to specific principals",
                                    "steps": [
                                        "Identify required principals (roles, users, accounts)",
                                        "Update trust policy with specific ARNs",
                                        "Add conditions (aws:SourceArn, etc.)",
                                    ],
                                    "effort": "medium",
                                    "automatable": False,
                                },
                                rule_id="sts_public_trust_policy",
                            ))

        except botocore.exceptions.ClientError as e:
            self.handle_client_error(e, "ListRoles/GetRole", findings)

    async def _scan_federation(self, scan_id: str, findings: list, result: ScanResult) -> None:
        """Scan federation-related STS capabilities."""
        try:
            # Get caller identity to verify STS access
            identity = self.client.get_caller_identity()
            account_id = identity.get("Account", "")

            result.resources_found += 1

            # Check GetAccessKeyInfo capability
            try:
                # This would require an access key ID to test, so we just note the capability
                findings.append(self.create_finding(
                    title="STS GetAccessKeyInfo capability available",
                    description="STS GetAccessKeyInfo can be used to identify which account an access key belongs to",
                    severity="info",
                    category="informational",
                    resource_type="sts_capability",
                    resource_id="GetAccessKeyInfo",
                    resource_name="STS GetAccessKeyInfo",
                    region="global",
                    rule_id="sts_get_access_key_info",
                ))
            except Exception:
                pass

            # Check GetFederationToken capability
            try:
                findings.append(self.create_finding(
                    title="STS GetFederationToken capability available",
                    description="STS GetFederationToken can create federated user sessions with custom policies",
                    severity="info",
                    category="informational",
                    resource_type="sts_capability",
                    resource_id="GetFederationToken",
                    resource_name="STS GetFederationToken",
                    region="global",
                    rule_id="sts_get_federation_token",
                ))
            except Exception:
                pass

            # Check GetSessionToken capability
            try:
                findings.append(self.create_finding(
                    title="STS GetSessionToken capability available",
                    description="STS GetSessionToken can create temporary credentials for IAM users",
                    severity="info",
                    category="informational",
                    resource_type="sts_capability",
                    resource_id="GetSessionToken",
                    resource_name="STS GetSessionToken",
                    region="global",
                    rule_id="sts_get_session_token",
                ))
            except Exception:
                pass

            # Check AssumeRole capability
            try:
                findings.append(self.create_finding(
                    title="STS AssumeRole capability available",
                    description="STS AssumeRole can be used to assume IAM roles (cross-account or same-account)",
                    severity="info",
                    category="informational",
                    resource_type="sts_capability",
                    resource_id="AssumeRole",
                    resource_name="STS AssumeRole",
                    region="global",
                    rule_id="sts_assume_role",
                ))
            except Exception:
                pass

        except botocore.exceptions.ClientError as e:
            self.handle_client_error(e, "GetCallerIdentity", findings)

    def _get_finding_key(self, finding: dict) -> str:
        """Generate a unique key for a finding to enable deduplication."""
        key_parts = [
            finding.get("rule_id", ""),
            finding.get("resource_id", ""),
            finding.get("region", ""),
        ]
        key_str = "|".join(key_parts)
        import hashlib
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
            description=f"Enumerated {resource_type} in account: {resource_name}",
            severity="info",
            category="enumeration",
            resource_type=resource_type,
            resource_id=resource_id,
            resource_name=resource_name,
            region="global",
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
            rule_id=f"sts_enum_{resource_type}",
        )
        self._add_finding_deduped(findings, finding)

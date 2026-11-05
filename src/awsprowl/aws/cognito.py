"""Cognito scanner for awsProwl."""

from __future__ import annotations

import asyncio
import hashlib

import botocore.exceptions

from awsprowl.aws.base import AWSServiceBase, ScanResult
from awsprowl.core.auth import AWSAuthManager
from awsprowl.core.logging import get_logger

log = get_logger(__name__)


class CognitoScanner(AWSServiceBase):
    """Scanner for Cognito resources."""

    SERVICE_NAME = "cognito-idp"
    REQUIRED_PERMISSIONS = [
        "cognito-idp:ListUserPools",
        "cognito-idp:DescribeUserPool",
        "cognito-idp:DescribeUserPoolClient",
        "cognito-idp:ListUserPoolClients",
        "cognito-idp:ListIdentityPools",
        "cognito-idp:DescribeIdentityPool",
    ]

    def __init__(self, auth_manager: AWSAuthManager, region: str | None = None):
        super().__init__(auth_manager, region)

    async def scan(self, scan_id: str, findings: list) -> ScanResult:
        """Scan Cognito resources for security issues."""
        result = ScanResult(service=self.SERVICE_NAME, region=self.region)

        try:
            await asyncio.gather(
                self._scan_user_pools(scan_id, findings, result),
                self._scan_identity_pools(scan_id, findings, result),
                return_exceptions=True,
            )

        except Exception as e:
            log.error("Error in Cognito scan: {}", e)
            result.errors.append(str(e))

        return result

    async def _scan_user_pools(self, scan_id: str, findings: list, result: ScanResult) -> None:
        """Scan Cognito User Pools."""
        try:
            paginator = self.client.get_paginator("list_user_pools")
            for page in paginator.paginate(MaxResults=60):
                for pool in page.get("UserPools", []):
                    result.resources_found += 1
                    pool_id = pool["Id"]
                    pool_details = self.client.describe_user_pool(UserPoolId=pool_id)
                    await self._analyze_user_pool(pool_details["UserPool"], scan_id, findings)

        except botocore.exceptions.ClientError as e:
            self.handle_client_error(e, "ListUserPools/DescribeUserPool", findings)

    async def _analyze_user_pool(self, pool: dict, scan_id: str, findings: list) -> None:
        """Analyze a Cognito User Pool."""
        pool_id = pool["Id"]
        pool_name = pool["Name"]

        # Add enumeration finding
        await self._add_enumeration_finding("cognito_user_pool", pool_id, pool_name, {
            "id": pool_id,
            "name": pool_name,
            "status": pool.get("Status", ""),
            "mfa_configuration": pool.get("MfaConfiguration", "OFF"),
            "advanced_security_mode": pool.get("UserPoolAddOns", {}).get("AdvancedSecurityMode", "OFF"),
            "auto_verified_attributes": pool.get("AutoVerifiedAttributes", []),
            "admin_create_user_config": pool.get("AdminCreateUserConfig", {}),
        }, findings, scan_id)

        # Check for MFA configuration
        mfa_config = pool.get("MfaConfiguration", "OFF")
        if mfa_config == "OFF":
            self._add_finding_deduped(findings, self.create_finding(
                title=f"Cognito User Pool {pool_name} has MFA disabled",
                description="Multi-factor authentication is not enabled for the user pool",
                severity="high",
                category="weak_configuration",
                resource_type="cognito_user_pool",
                resource_id=pool_id,
                resource_name=pool_name,
                region=self.region,
                remediation={
                    "summary": "Enable MFA",
                    "steps": [
                        "Set MfaConfiguration to ON or OPTIONAL",
                        "Configure SMS or TOTP MFA",
                        "Test MFA enrollment",
                    ],
                    "effort": "low",
                    "automatable": True,
                    "cli_commands": [
                        f"aws cognito-idp set-user-pool-mfa-config --user-pool-id {pool_id} --mfa-configuration ON",
                    ],
                },
                rule_id="cognito_mfa_disabled",
            ))

        # Check password policy
        password_policy = pool.get("Policies", {}).get("PasswordPolicy", {})
        min_length = password_policy.get("MinimumLength", 0)
        require_uppercase = password_policy.get("RequireUppercase", False)
        require_lowercase = password_policy.get("RequireLowercase", False)
        require_numbers = password_policy.get("RequireNumbers", False)
        require_symbols = password_policy.get("RequireSymbols", False)

        if min_length < 8:
            self._add_finding_deduped(findings, self.create_finding(
                title=f"Cognito User Pool {pool_name} has weak password policy: min length {min_length}",
                description=f"Password policy requires only {min_length} characters (recommended: 8+)",
                severity="medium",
                category="weak_configuration",
                resource_type="cognito_user_pool",
                resource_id=pool_id,
                resource_name=pool_name,
                region=self.region,
                evidence=[{"type": "password_policy", "description": "Password policy", "data": password_policy}],
                remediation={
                    "summary": "Strengthen password policy",
                    "steps": [
                        "Set MinimumLength to at least 8",
                        "Enable RequireUppercase, RequireLowercase, RequireNumbers, RequireSymbols",
                    ],
                    "effort": "low",
                    "automatable": True,
                },
                rule_id="cognito_weak_password_policy",
            ))

        if not (require_uppercase and require_lowercase and require_numbers and require_symbols):
            self._add_finding_deduped(findings, self.create_finding(
                title=f"Cognito User Pool {pool_name} has incomplete password complexity requirements",
                description="Password policy does not require all character types",
                severity="medium",
                category="weak_configuration",
                resource_type="cognito_user_pool",
                resource_id=pool_id,
                resource_name=pool_name,
                region=self.region,
                evidence=[{"type": "password_policy", "description": "Password policy", "data": password_policy}],
                remediation={
                    "summary": "Enable all password complexity requirements",
                    "steps": [
                        "Enable RequireUppercase, RequireLowercase, RequireNumbers, RequireSymbols",
                    ],
                    "effort": "low",
                    "automatable": True,
                },
                rule_id="cognito_incomplete_password_complexity",
            ))

        # Check for advanced security
        advanced_security = pool.get("UserPoolAddOns", {}).get("AdvancedSecurityMode", "OFF")
        if advanced_security == "OFF":
            self._add_finding_deduped(findings, self.create_finding(
                title=f"Cognito User Pool {pool_name} does not have advanced security enabled",
                description="Advanced security features (adaptive authentication, threat protection) are disabled",
                severity="medium",
                category="vulnerable_configuration",
                resource_type="cognito_user_pool",
                resource_id=pool_id,
                resource_name=pool_name,
                region=self.region,
                remediation={
                    "summary": "Enable advanced security",
                    "steps": [
                        "Enable AdvancedSecurityMode (AUDIT or ENFORCED)",
                        "Configure adaptive authentication",
                    ],
                    "effort": "low",
                    "automatable": True,
                    "cli_commands": [
                        f"aws cognito-idp update-user-pool --user-pool-id {pool_id} --user-pool-add-ons AdvancedSecurityMode=ENFORCED",
                    ],
                },
                rule_id="cognito_advanced_security_off",
            ))

        # Check for unverified email/phone
        auto_verified = pool.get("AutoVerifiedAttributes", [])
        if "email" not in auto_verified:
            self._add_finding_deduped(findings, self.create_finding(
                title=f"Cognito User Pool {pool_name} does not auto-verify email",
                description="Email addresses are not automatically verified on registration",
                severity="low",
                category="weak_configuration",
                resource_type="cognito_user_pool",
                resource_id=pool_id,
                resource_name=pool_name,
                region=self.region,
                rule_id="cognito_email_not_verified",
            ))

        # Check for admin create user config (allow admin to create users without temp password)
        admin_create = pool.get("AdminCreateUserConfig", {})
        allow_admin_create = admin_create.get("AllowAdminCreateUserOnly", False)
        if not allow_admin_create:
            self._add_finding_deduped(findings, self.create_finding(
                title=f"Cognito User Pool {pool_name} allows self-signup without restrictions",
                description="Users can sign up without admin approval (may be intentional)",
                severity="info",
                category="weak_configuration",
                resource_type="cognito_user_pool",
                resource_id=pool_id,
                resource_name=pool_name,
                region=self.region,
                rule_id="cognito_self_signup_allowed",
            ))

        # Scan app clients
        try:
            clients = self.client.list_user_pool_clients(UserPoolId=pool_id, MaxResults=60)
            for client in clients.get("UserPoolClients", []):
                client_id = client["ClientId"]
                client_details = self.client.describe_user_pool_client(UserPoolId=pool_id, ClientId=client_id)
                await self._analyze_user_pool_client(client_details["UserPoolClient"], pool_id, pool_name, scan_id, findings)
        except botocore.exceptions.ClientError:
            pass

    async def _analyze_user_pool_client(self, client: dict, pool_id: str, pool_name: str, scan_id: str, findings: list) -> None:
        """Analyze a Cognito User Pool Client."""
        client_id = client["ClientId"]
        client_name = client["ClientName"]

        # Add enumeration finding
        await self._add_enumeration_finding("cognito_user_pool_client", client_id, client_name, {
            "client_id": client_id,
            "client_name": client_name,
            "user_pool_id": pool_id,
            "user_pool_name": pool_name,
            "has_client_secret": bool(client.get("ClientSecret", "")),
            "explicit_auth_flows": client.get("ExplicitAuthFlows", []),
            "allowed_oauth_flows": client.get("AllowedOAuthFlows", []),
            "callback_urls": client.get("CallbackURLs", []),
        }, findings, scan_id)

        # Check for secret
        client_secret = client.get("ClientSecret", "")
        if not client_secret:
            self._add_finding_deduped(findings, self.create_finding(
                title=f"Cognito User Pool Client {client_name} has no client secret",
                description="Public client (no secret) - ensure this is intentional for SPA/mobile apps",
                severity="info",
                category="weak_configuration",
                resource_type="cognito_user_pool_client",
                resource_id=client_id,
                resource_name=client_name,
                region=self.region,
                rule_id="cognito_client_no_secret",
            ))

        # Check for implicit/auth flows
        explicit_auth_flows = client.get("ExplicitAuthFlows", [])
        if "ALLOW_USER_SRP_AUTH" not in explicit_auth_flows:
            self._add_finding_deduped(findings, self.create_finding(
                title=f"Cognito User Pool Client {client_name} does not use SRP auth",
                description="Client does not use Secure Remote Password (SRP) authentication flow",
                severity="medium",
                category="weak_configuration",
                resource_type="cognito_user_pool_client",
                resource_id=client_id,
                resource_name=client_name,
                region=self.region,
                evidence=[{"type": "auth_flows", "description": "Explicit auth flows", "data": explicit_auth_flows}],
                remediation={
                    "summary": "Enable SRP auth flow",
                    "steps": [
                        "Add ALLOW_USER_SRP_AUTH to ExplicitAuthFlows",
                        "Remove insecure flows like ALLOW_USER_PASSWORD_AUTH",
                    ],
                    "effort": "low",
                    "automatable": True,
                },
                rule_id="cognito_client_no_srp",
            ))

        # Check for insecure auth flows
        insecure_flows = ["ALLOW_USER_PASSWORD_AUTH", "ALLOW_ADMIN_USER_PASSWORD_AUTH"]
        for flow in insecure_flows:
            if flow in explicit_auth_flows:
                self._add_finding_deduped(findings, self.create_finding(
                    title=f"Cognito User Pool Client {client_name} allows insecure auth flow: {flow}",
                    description=f"Client allows {flow} which sends passwords directly",
                    severity="high",
                    category="weak_configuration",
                    resource_type="cognito_user_pool_client",
                    resource_id=client_id,
                    resource_name=client_name,
                    region=self.region,
                    remediation={
                        "summary": "Remove insecure auth flows",
                        "steps": [
                            f"Remove {flow} from ExplicitAuthFlows",
                            "Use SRP or OIDC flows instead",
                        ],
                        "effort": "low",
                        "automatable": True,
                    },
                    rule_id=f"cognito_client_insecure_{flow.lower()}",
                ))

        # Check callback URLs
        callback_urls = client.get("CallbackURLs", [])
        for url in callback_urls:
            if url.startswith("http://") and "localhost" not in url:
                self._add_finding_deduped(findings, self.create_finding(
                    title=f"Cognito User Pool Client {client_name} uses HTTP callback URL: {url}",
                    description="OAuth callback URL uses HTTP instead of HTTPS",
                    severity="high",
                    category="weak_configuration",
                    resource_type="cognito_user_pool_client",
                    resource_id=client_id,
                    resource_name=client_name,
                    region=self.region,
                    evidence=[{"type": "callback_url", "description": "HTTP callback URL", "data": {"url": url}}],
                    remediation={
                        "summary": "Use HTTPS for callback URLs",
                        "steps": [
                            "Update callback URLs to use HTTPS",
                            "Ensure valid TLS certificate",
                        ],
                        "effort": "low",
                        "automatable": True,
                    },
                    rule_id="cognito_client_http_callback",
                ))

        # Check logout URLs
        logout_urls = client.get("LogoutURLs", [])
        for url in logout_urls:
            if url.startswith("http://") and "localhost" not in url:
                self._add_finding_deduped(findings, self.create_finding(
                    title=f"Cognito User Pool Client {client_name} uses HTTP logout URL: {url}",
                    description="OAuth logout URL uses HTTP instead of HTTPS",
                    severity="medium",
                    category="weak_configuration",
                    resource_type="cognito_user_pool_client",
                    resource_id=client_id,
                    resource_name=client_name,
                    region=self.region,
                    rule_id="cognito_client_http_logout",
                ))

        # Check allowed OAuth flows
        allowed_oauth_flows = client.get("AllowedOAuthFlows", [])
        if "implicit" in allowed_oauth_flows:
            self._add_finding_deduped(findings, self.create_finding(
                title=f"Cognito User Pool Client {client_name} allows implicit OAuth flow",
                description="Implicit flow returns tokens in URL fragment, less secure than authorization code flow",
                severity="medium",
                category="weak_configuration",
                resource_type="cognito_user_pool_client",
                resource_id=client_id,
                resource_name=client_name,
                region=self.region,
                remediation={
                    "summary": "Use authorization code flow with PKCE",
                    "steps": [
                        "Remove 'implicit' from AllowedOAuthFlows",
                        "Add 'code' flow",
                        "Enable PKCE",
                    ],
                    "effort": "low",
                    "automatable": True,
                },
                rule_id="cognito_client_implicit_flow",
            ))

        # Check for token revocation
        prevent_user_existence = client.get("PreventUserExistenceErrors", "LEGACY")
        if prevent_user_existence == "LEGACY":
            self._add_finding_deduped(findings, self.create_finding(
                title=f"Cognito User Pool Client {client_name} uses legacy user existence errors",
                description="Legacy mode reveals whether a user exists during auth (user enumeration)",
                severity="medium",
                category="information_disclosure",
                resource_type="cognito_user_pool_client",
                resource_id=client_id,
                resource_name=client_name,
                region=self.region,
                remediation={
                    "summary": "Enable PreventUserExistenceErrors",
                    "steps": [
                        "Set PreventUserExistenceErrors to ENABLED",
                    ],
                    "effort": "low",
                    "automatable": True,
                    "cli_commands": [
                        f"aws cognito-idp update-user-pool-client --user-pool-id {pool_id} --client-id {client_id} --prevent-user-existence-errors ENABLED",
                    ],
                },
                rule_id="cognito_client_legacy_user_existence",
            ))

    async def _scan_identity_pools(self, scan_id: str, findings: list, result: ScanResult) -> None:
        """Scan Cognito Identity Pools."""
        try:
            paginator = self.client.get_paginator("list_identity_pools")
            for page in paginator.paginate(MaxResults=60):
                for pool in page.get("IdentityPools", []):
                    result.resources_found += 1
                    pool_id = pool["IdentityPoolId"]
                    pool_details = self.client.describe_identity_pool(IdentityPoolId=pool_id)
                    await self._analyze_identity_pool(pool_details, scan_id, findings)

        except botocore.exceptions.ClientError as e:
            self.handle_client_error(e, "ListIdentityPools/DescribeIdentityPool", findings)

    async def _analyze_identity_pool(self, pool: dict, scan_id: str, findings: list) -> None:
        """Analyze a Cognito Identity Pool."""
        pool_id = pool["IdentityPoolId"]
        pool_name = pool["IdentityPoolName"]

        # Add enumeration finding
        await self._add_enumeration_finding("cognito_identity_pool", pool_id, pool_name, {
            "id": pool_id,
            "name": pool_name,
            "allow_unauthenticated_identities": pool.get("AllowUnauthenticatedIdentities", False),
            "authenticated_role": pool.get("IdentityPoolRoles", {}).get("authenticated", ""),
            "unauthenticated_role": pool.get("IdentityPoolRoles", {}).get("unauthenticated", ""),
            "supported_login_providers": list(pool.get("SupportedLoginProviders", {}).keys()),
        }, findings, scan_id)

        # Check for unauthenticated identities
        allow_unauth = pool.get("AllowUnauthenticatedIdentities", False)
        if allow_unauth:
            self._add_finding_deduped(findings, self.create_finding(
                title=f"Cognito Identity Pool {pool_name} allows unauthenticated identities",
                description="Identity pool allows unauthenticated (guest) access - may be intentional for public apps",
                severity="medium",
                category="weak_configuration",
                resource_type="cognito_identity_pool",
                resource_id=pool_id,
                resource_name=pool_name,
                region=self.region,
                evidence=[{"type": "identity_pool_config", "description": "Unauthenticated access", "data": {"AllowUnauthenticatedIdentities": True}}],
                remediation={
                    "summary": "Review unauthenticated access",
                    "steps": [
                        "Verify if unauthenticated access is required",
                        "If not needed, set AllowUnauthenticatedIdentities to false",
                        "If needed, ensure unauthenticated role has minimal permissions",
                    ],
                    "effort": "low",
                    "automatable": True,
                },
                rule_id="cognito_identity_pool_unauthenticated",
            ))

        # Check roles
        auth_role = pool.get("IdentityPoolRoles", {}).get("authenticated")
        unauth_role = pool.get("IdentityPoolRoles", {}).get("unauthenticated")

        if auth_role:
            await self._check_cognito_role(auth_role, "authenticated", pool_id, pool_name, scan_id, findings)

        if unauth_role:
            await self._check_cognito_role(unauth_role, "unauthenticated", pool_id, pool_name, scan_id, findings)

    async def _check_cognito_role(self, role_arn: str, role_type: str, pool_id: str, pool_name: str, scan_id: str, findings: list) -> None:
        """Check Cognito identity pool role for excessive permissions."""
        try:
            role_name = role_arn.split("/")[-1]

            # Get inline policies
            inline = self.client.list_role_policies(RoleName=role_name)
            for policy_name in inline.get("PolicyNames", []):
                policy = self.client.get_role_policy(RoleName=role_name, PolicyName=policy_name)
                await self._check_policy_document(policy["PolicyDocument"], f"cognito_{role_type}_role/{role_name}/inline/{policy_name}", pool_id, pool_name, scan_id, findings)

            # Get attached policies
            attached = self.client.list_attached_role_policies(RoleName=role_name)
            for policy in attached.get("AttachedPolicies", []):
                policy_detail = self.client.get_policy(PolicyArn=policy["PolicyArn"])
                version = self.client.get_policy_version(
                    PolicyArn=policy["PolicyArn"],
                    VersionId=policy_detail["Policy"]["DefaultVersionId"],
                )
                await self._check_policy_document(version["PolicyVersion"]["Document"], f"cognito_{role_type}_role/{role_name}/attached/{policy['PolicyName']}", pool_id, pool_name, scan_id, findings)

        except botocore.exceptions.ClientError:
            pass

    async def _check_policy_document(self, policy_doc: dict, policy_id: str, pool_id: str, pool_name: str, scan_id: str, findings: list) -> None:
        """Check a policy document for excessive permissions."""
        statements = policy_doc.get("Statement", [])
        if not isinstance(statements, list):
            statements = [statements]

        for stmt in statements:
            if stmt.get("Effect") != "Allow":
                continue

            actions = stmt.get("Action", [])
            if isinstance(actions, str):
                actions = [actions]

            resources = stmt.get("Resource", [])
            if isinstance(resources, str):
                resources = [resources]

            has_wildcard_action = "*" in actions or any(a.endswith("*") for a in actions)
            has_wildcard_resource = "*" in resources

            if has_wildcard_action and has_wildcard_resource:
                self._add_finding_deduped(findings, self.create_finding(
                    title=f"Cognito Identity Pool {pool_name} {policy_id} has overly permissive policy",
                    description=f"{role_type.capitalize()} role allows all actions on all resources",
                    severity="critical" if role_type == "unauthenticated" else "high",
                    category="excessive_permissions",
                    resource_type="cognito_identity_pool",
                    resource_id=pool_id,
                    resource_name=pool_name,
                    region=self.region,
                    evidence=[{"type": "role_policy", "description": f"Overly permissive {role_type} role policy {policy_id}", "data": policy_doc}],
                    remediation={
                        "summary": "Apply least privilege to identity pool roles",
                        "steps": [
                            "Identify minimum required permissions",
                            "Create new policy with specific actions and resources",
                            "Attach new policy and remove overly permissive one",
                        ],
                        "effort": "medium",
                        "automatable": False,
                    },
                    rule_id=f"cognito_{role_type}_role_wildcard_policy",
                ))

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
            rule_id=f"cognito_enum_{resource_type}",
        )
        self._add_finding_deduped(findings, finding)

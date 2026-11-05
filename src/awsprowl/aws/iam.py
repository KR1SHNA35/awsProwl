"""IAM scanner for awsProwl."""

from __future__ import annotations

import asyncio
import hashlib

import botocore.exceptions

from awsprowl.aws.base import AWSServiceBase, ScanResult
from awsprowl.core.auth import AWSAuthManager
from awsprowl.core.logging import get_logger

log = get_logger(__name__)


class IAMScanner(AWSServiceBase):
    """Scanner for IAM resources."""

    SERVICE_NAME = "iam"
    REQUIRED_PERMISSIONS = [
        "iam:ListUsers",
        "iam:ListRoles",
        "iam:ListPolicies",
        "iam:ListGroups",
        "iam:GetUser",
        "iam:GetRole",
        "iam:GetPolicy",
        "iam:GetPolicyVersion",
        "iam:ListAttachedUserPolicies",
        "iam:ListUserPolicies",
        "iam:ListAttachedRolePolicies",
        "iam:ListRolePolicies",
        "iam:ListGroupsForUser",
        "iam:ListAttachedGroupPolicies",
        "iam:ListGroupPolicies",
        "iam:SimulatePrincipalPolicy",
        "iam:GetAccountAuthorizationDetails",
        "iam:ListServiceSpecificCredentials",
        "iam:ListSSHPublicKeys",
        "iam:ListSigningCertificates",
        "iam:GetLoginProfile",
        "iam:GetAccountPasswordPolicy",
        "iam:GetAccountSummary",
        "iam:ListAccountAliases",
        "organizations:ListAccounts",
        "organizations:ListRoots",
        "organizations:ListOrganizationalUnitsForParent",
    ]

    def __init__(self, auth_manager: AWSAuthManager, region: str | None = None):
        super().__init__(auth_manager, region or "us-east-1")  # IAM is global

    async def scan(self, scan_id: str, findings: list) -> ScanResult:
        """Scan IAM resources for security issues."""
        result = ScanResult(service=self.SERVICE_NAME, region="global")

        try:
            # Run all scans in parallel
            await asyncio.gather(
                self._scan_users(scan_id, findings, result),
                self._scan_roles(scan_id, findings, result),
                self._scan_policies(scan_id, findings, result),
                self._scan_groups(scan_id, findings, result),
                self._scan_account_authorization(scan_id, findings, result),
                self._scan_service_credentials(scan_id, findings, result),
                self._scan_ssh_keys(scan_id, findings, result),
                self._scan_signing_certs(scan_id, findings, result),
                self._scan_login_profiles(scan_id, findings, result),
                self._scan_permissions_boundaries(scan_id, findings, result),
                self._scan_service_linked_roles(scan_id, findings, result),
                self._scan_organization_accounts(scan_id, findings, result),
                self._scan_with_simulation(scan_id, findings, result),
                return_exceptions=True,
            )

        except Exception as e:
            log.error("Error in IAM scan: {}", e)
            result.errors.append(str(e))

        return result

    async def _scan_users(self, scan_id: str, findings: list, result: ScanResult) -> None:
        """Scan IAM users."""
        try:
            paginator = self.client.get_paginator("list_users")
            for page in paginator.paginate():
                for user in page.get("Users", []):
                    result.resources_found += 1
                    await self._analyze_user(user, scan_id, findings)

        except botocore.exceptions.ClientError as e:
            self.handle_client_error(e, "ListUsers", findings)

    async def _analyze_user(self, user: dict, scan_id: str, findings: list) -> None:
        """Analyze a single IAM user for security issues."""
        user_name = user["UserName"]
        user_arn = user["Arn"]

        # Add enumeration finding
        await self._add_enumeration_finding("iam_user", user_name, user_name, {
            "arn": user_arn,
            "path": user.get("Path", "/"),
            "created": user.get("CreateDate", "").isoformat() if user.get("CreateDate") else "",
            "password_last_used": user.get("PasswordLastUsed", "").isoformat() if user.get("PasswordLastUsed") else "Never",
        }, findings, scan_id)

        # Get attached policies
        try:
            attached = self.client.list_attached_user_policies(UserName=user_name)
            for policy in attached.get("AttachedPolicies", []):
                await self._check_policy_permissions(policy["PolicyArn"], f"user/{user_name}", scan_id, findings)
        except botocore.exceptions.ClientError:
            pass

        # Get inline policies
        try:
            inline = self.client.list_user_policies(UserName=user_name)
            for policy_name in inline.get("PolicyNames", []):
                policy = self.client.get_user_policy(UserName=user_name, PolicyName=policy_name)
                await self._check_policy_document(policy["PolicyDocument"], f"user/{user_name}/inline/{policy_name}", scan_id, findings)
        except botocore.exceptions.ClientError:
            pass

        # Check for access keys
        try:
            keys = self.client.list_access_keys(UserName=user_name)
            for key in keys.get("AccessKeyMetadata", []):
                if key["Status"] == "Active":
                    # Check key age
                    from datetime import datetime, timezone
                    age_days = (datetime.now(timezone.utc) - key["CreateDate"]).days
                    if age_days > 90:
                        self._add_finding_deduped(findings, self.create_finding(
                            title=f"Old access key for user {user_name}",
                            description=f"Access key {key['AccessKeyId']} is {age_days} days old (recommended: rotate every 90 days)",
                            severity="medium",
                            category="weak_configuration",
                            resource_type="iam_user",
                            resource_id=user_name,
                            resource_name=user_name,
                            region="global",
                            evidence=[{"type": "api_response", "description": "Access key metadata", "data": key}],
                            remediation={
                                "summary": "Rotate access key",
                                "steps": [
                                    "Create new access key",
                                    "Update applications to use new key",
                                    "Deactivate old key",
                                    "Delete old key after confirmation",
                                ],
                                "effort": "low",
                                "automatable": True,
                                "cli_commands": [
                                    f"aws iam create-access-key --user-name {user_name}",
                                    f"aws iam update-access-key --user-name {user_name} --access-key-id {key['AccessKeyId']} --status Inactive",
                                    f"aws iam delete-access-key --user-name {user_name} --access-key-id {key['AccessKeyId']}",
                                ],
                            },
                            rule_id="iam_old_access_key",
                        ))
        except botocore.exceptions.ClientError:
            pass

        # Check for MFA
        try:
            mfa = self.client.list_mfa_devices(UserName=user_name)
            if not mfa.get("MFADevices"):
                self._add_finding_deduped(findings, self.create_finding(
                    title=f"MFA not enabled for user {user_name}",
                    description=f"IAM user {user_name} does not have MFA enabled",
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
                                    "Verify MFA works",
                                ],
                                "effort": "low",
                                "automatable": True,
                                "cli_commands": [
                                    f"aws iam create-virtual-mfa-device --virtual-mfa-device-name {user_name}-mfa",
                                    f"aws iam enable-mfa-device --user-name {user_name} --serial-number arn:aws:iam::123456789012:mfa/{user_name}-mfa --authentication-code-1 123456 --authentication-code-2 789012",
                                ],
                            },
                            rule_id="iam_mfa_not_enabled",
                ))
        except botocore.exceptions.ClientError:
            pass

    async def _scan_roles(self, scan_id: str, findings: list, result: ScanResult) -> None:
        """Scan IAM roles."""
        try:
            paginator = self.client.get_paginator("list_roles")
            for page in paginator.paginate():
                for role in page.get("Roles", []):
                    # Skip service-linked roles
                    if role.get("Path", "").startswith("/aws-service-role/"):
                        continue

                    result.resources_found += 1
                    await self._analyze_role(role, scan_id, findings)

        except botocore.exceptions.ClientError as e:
            self.handle_client_error(e, "ListRoles", findings)

    async def _analyze_role(self, role: dict, scan_id: str, findings: list) -> None:
        """Analyze a single IAM role for security issues."""
        role_name = role["RoleName"]
        role_arn = role["Arn"]

        # Add enumeration finding
        await self._add_enumeration_finding("iam_role", role_name, role_name, {
            "arn": role_arn,
            "path": role.get("Path", "/"),
            "created": role.get("CreateDate", "").isoformat() if role.get("CreateDate") else "",
            "description": role.get("Description", ""),
            "max_session_duration": role.get("MaxSessionDuration", 3600),
        }, findings, scan_id)

        # Check trust policy for overly permissive principals
        trust_policy = role.get("AssumeRolePolicyDocument", {})
        await self._check_trust_policy(trust_policy, f"role/{role_name}", scan_id, findings)

        # Get attached policies
        try:
            attached = self.client.list_attached_role_policies(RoleName=role_name)
            for policy in attached.get("AttachedPolicies", []):
                await self._check_policy_permissions(policy["PolicyArn"], f"role/{role_name}", scan_id, findings)
        except botocore.exceptions.ClientError:
            pass

        # Get inline policies
        try:
            inline = self.client.list_role_policies(RoleName=role_name)
            for policy_name in inline.get("PolicyNames", []):
                policy = self.client.get_role_policy(RoleName=role_name, PolicyName=policy_name)
                await self._check_policy_document(policy["PolicyDocument"], f"role/{role_name}/inline/{policy_name}", scan_id, findings)
        except botocore.exceptions.ClientError:
            pass

        # Check for cross-account trust
        await self._check_cross_account_trust(trust_policy, f"role/{role_name}", scan_id, findings)

    async def _check_trust_policy(self, trust_policy: dict, resource_id: str, scan_id: str, findings: list) -> None:
        """Check trust policy for security issues."""
        statements = trust_policy.get("Statement", [])
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
                    title=f"Role {resource_id} allows anyone to assume",
                    description="Trust policy allows any principal to assume this role",
                    severity="critical",
                    category="privilege_escalation",
                    resource_type="iam_role",
                    resource_id=resource_id,
                    region="global",
                    evidence=[{"type": "trust_policy", "description": "Trust policy with wildcard principal", "data": trust_policy}],
                    remediation={
                        "summary": "Restrict trust policy to specific principals",
                        "steps": [
                            "Identify required principals",
                            "Update trust policy with specific ARNs",
                            "Test role assumption",
                        ],
                        "effort": "low",
                        "automatable": True,
                        "cli_commands": [
                            f"aws iam update-assume-role-policy --role-name {resource_id.split('/')[-1]} --policy-document file://trust-policy.json",
                        ],
                    },
                    rule_id="iam_wildcard_trust",
                ))

    async def _check_cross_account_trust(self, trust_policy: dict, resource_id: str, scan_id: str, findings: list) -> None:
        """Check for cross-account trust relationships."""
        statements = trust_policy.get("Statement", [])
        if not isinstance(statements, list):
            statements = [statements]

        for stmt in statements:
            principal = stmt.get("Principal", {})
            if not principal:
                continue

            aws_principals = principal.get("AWS", [])
            if isinstance(aws_principals, str):
                aws_principals = [aws_principals]

            for principal_arn in aws_principals:
                if ":root" in principal_arn and not principal_arn.startswith("arn:aws:iam::" + self._get_account_id() + ":"):
                    self._add_finding_deduped(findings, self.create_finding(
                        title=f"Cross-account trust in role {resource_id}",
                        description=f"Role trusts external account root: {principal_arn}",
                        severity="high",
                        category="cross_account_access",
                        resource_type="iam_role",
                        resource_id=resource_id,
                        region="global",
                        evidence=[{"type": "trust_policy", "description": "Cross-account trust", "data": {"principal": principal_arn}}],
                        remediation={
                            "summary": "Review and restrict cross-account trust",
                            "steps": [
                                "Verify if cross-account access is intentional",
                                "Restrict to specific roles/users instead of root",
                                "Add conditions (ExternalId, MFA, etc.)",
                            ],
                            "effort": "medium",
                            "automatable": False,
                        },
                        rule_id="iam_cross_account_trust",
                    ))

    def _get_account_id(self) -> str:
        """Get current account ID."""
        try:
            return self.auth_manager.get_caller_identity().get("Account", "")
        except Exception:
            return ""

    async def _check_policy_permissions(self, policy_arn: str, resource_id: str, scan_id: str, findings: list) -> None:
        """Check a managed policy for dangerous permissions."""
        try:
            policy = self.client.get_policy(PolicyArn=policy_arn)
            version = self.client.get_policy_version(
                PolicyArn=policy_arn,
                VersionId=policy["Policy"]["DefaultVersionId"],
            )
            await self._check_policy_document(version["PolicyVersion"]["Document"], f"policy/{policy_arn}", scan_id, findings)
        except botocore.exceptions.ClientError:
            pass

    async def _check_policy_document(self, policy_doc: dict, resource_id: str, scan_id: str, findings: list) -> None:
        """Check a policy document for dangerous permissions."""
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

            # Check for wildcard action + wildcard resource
            has_wildcard_action = "*" in actions or any(a.endswith("*") for a in actions)
            has_wildcard_resource = "*" in resources

            if has_wildcard_action and has_wildcard_resource:
                self._add_finding_deduped(findings, self.create_finding(
                    title=f"Overly permissive policy on {resource_id}",
                    description="Policy allows all actions on all resources (full admin access)",
                    severity="critical",
                    category="excessive_permissions",
                    resource_type="iam_policy",
                    resource_id=resource_id,
                    region="global",
                    evidence=[{"type": "policy_document", "description": "Policy with wildcard action and resource", "data": policy_doc}],
                    remediation={
                        "summary": "Apply least privilege principle",
                        "steps": [
                            "Identify minimum required permissions",
                            "Create new policy with specific actions and resources",
                            "Test and replace",
                        ],
                        "effort": "medium",
                        "automatable": False,
                    },
                    rule_id="iam_wildcard_policy",
                ))

            # Check for dangerous specific permissions
            dangerous_actions = [
                "iam:*", "iam:AttachUserPolicy", "iam:AttachRolePolicy", "iam:PutUserPolicy", "iam:PutRolePolicy",
                "iam:CreateAccessKey", "iam:CreateLoginProfile", "iam:UpdateLoginProfile",
                "iam:AddUserToGroup", "iam:CreatePolicyVersion", "iam:SetDefaultPolicyVersion",
                "sts:AssumeRole", "ec2:RunInstances", "lambda:CreateFunction", "lambda:InvokeFunction",
            ]

            for action in actions:
                if action in dangerous_actions or any(action.startswith(d.replace("*", "")) for d in dangerous_actions if d.endswith("*")):
                    self._add_finding_deduped(findings, self.create_finding(
                        title=f"Dangerous permission {action} in {resource_id}",
                        description=f"Policy grants {action} which could enable privilege escalation",
                        severity="high" if "iam:" in action else "medium",
                        category="privilege_escalation" if "iam:" in action else "excessive_permissions",
                        resource_type="iam_policy",
                        resource_id=resource_id,
                        region="global",
                        evidence=[{"type": "policy_document", "description": f"Policy grants {action}", "data": {"action": action, "statement": stmt}}],
                        remediation={
                            "summary": f"Review necessity of {action} permission",
                            "steps": [
                                "Verify if this permission is required",
                                "If not needed, remove from policy",
                                "If needed, add resource constraints",
                            ],
                            "effort": "medium",
                            "automatable": False,
                        },
                        rule_id=f"iam_dangerous_{action.replace(':', '_').replace('*', 'wildcard')}",
                    ))

    async def _scan_policies(self, scan_id: str, findings: list, result: ScanResult) -> None:
        """Scan IAM managed policies."""
        try:
            paginator = self.client.get_paginator("list_policies")
            for page in paginator.paginate(Scope="Local"):  # Only customer managed
                for policy in page.get("Policies", []):
                    result.resources_found += 1
                    # Add enumeration finding
                    await self._add_enumeration_finding("iam_policy", policy["PolicyName"], policy["PolicyName"], {
                        "arn": policy["Arn"],
                        "path": policy.get("Path", "/"),
                        "created": policy.get("CreateDate", "").isoformat() if policy.get("CreateDate") else "",
                        "updated": policy.get("UpdateDate", "").isoformat() if policy.get("UpdateDate") else "",
                        "description": policy.get("Description", ""),
                        "default_version": policy.get("DefaultVersionId", ""),
                        "attachment_count": policy.get("AttachmentCount", 0),
                        "is_attachable": policy.get("IsAttachable", True),
                    }, findings, scan_id)
                    await self._check_policy_permissions(policy["Arn"], f"policy/{policy['PolicyName']}", scan_id, findings)
        except botocore.exceptions.ClientError as e:
            self.handle_client_error(e, "ListPolicies", findings)

    async def _scan_groups(self, scan_id: str, findings: list, result: ScanResult) -> None:
        """Scan IAM groups."""
        try:
            paginator = self.client.get_paginator("list_groups")
            for page in paginator.paginate():
                for group in page.get("Groups", []):
                    result.resources_found += 1
                    group_name = group["GroupName"]

                    # Add enumeration finding
                    await self._add_enumeration_finding("iam_group", group_name, group_name, {
                        "arn": group["Arn"],
                        "path": group.get("Path", "/"),
                        "created": group.get("CreateDate", "").isoformat() if group.get("CreateDate") else "",
                    }, findings, scan_id)

                    # Check attached policies
                    try:
                        attached = self.client.list_attached_group_policies(GroupName=group_name)
                        for policy in attached.get("AttachedPolicies", []):
                            await self._check_policy_permissions(policy["PolicyArn"], f"group/{group_name}", scan_id, findings)
                    except botocore.exceptions.ClientError:
                        pass

                    # Check inline policies
                    try:
                        inline = self.client.list_group_policies(GroupName=group_name)
                        for policy_name in inline.get("PolicyNames", []):
                            policy = self.client.get_group_policy(GroupName=group_name, PolicyName=policy_name)
                            await self._check_policy_document(policy["PolicyDocument"], f"group/{group_name}/inline/{policy_name}", scan_id, findings)
                    except botocore.exceptions.ClientError:
                        pass

        except botocore.exceptions.ClientError as e:
            self.handle_client_error(e, "ListGroups", findings)

    def _get_finding_key(self, finding: dict) -> str:
        """Generate a unique key for a finding to enable deduplication."""
        # Create a hash based on rule_id, resource_id, and region
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
            # Initialize seen_keys from existing findings
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
                    "Check for excessive permissions or misconfigurations",
                ],
                "effort": "low",
                "automatable": False,
            },
            rule_id=f"iam_enum_{resource_type}",
        )
        self._add_finding_deduped(findings, finding)

    async def _simulate_principal_policy(self, principal_arn: str, action_names: list,
                                         resource_arns: list | None = None, scan_id: str = "", findings: list | None = None) -> None:
        """Use IAM SimulatePrincipalPolicy to test what actions a principal can perform."""
        if findings is None:
            findings = []

        try:
            # Prepare simulation request
            kwargs = {
                "PolicySourceArn": principal_arn,
                "ActionNames": action_names,
            }
            if resource_arns:
                kwargs["ResourceArns"] = resource_arns

            result = self.client.simulate_principal_policy(**kwargs)

            for eval_result in result.get("EvaluationResults", []):
                action = eval_result.get("EvalActionName", "")
                decision = eval_result.get("EvalDecision", "")

                if decision == "allowed":
                    self._add_finding_deduped(findings, self.create_finding(
                        title=f"Principal {principal_arn} can perform {action}",
                        description=f"IAM policy simulation confirms {principal_arn} is allowed to perform {action}",
                        severity="info",
                        category="policy_simulation",
                        resource_type="iam_principal",
                        resource_id=principal_arn,
                        region="global",
                        evidence=[{"type": "simulation_result", "description": f"Allowed action: {action}", "data": eval_result}],
                        remediation={
                            "summary": "Review if this permission is necessary",
                            "steps": [
                                "Verify the action is required for the principal's function",
                                "Consider adding resource constraints or conditions",
                            ],
                            "effort": "low",
                            "automatable": False,
                        },
                        rule_id=f"iam_simulate_{action.replace(':', '_').replace('*', 'wildcard')}",
                    ))

        except botocore.exceptions.ClientError as e:
            if e.response["Error"]["Code"] != "InvalidInput":
                log.debug("SimulatePrincipalPolicy failed for {}: {}", principal_arn, e)

    async def _scan_with_simulation(self, scan_id: str, findings: list, result: ScanResult) -> None:
        """Run IAM policy simulation for critical actions."""
        try:
            # Get account ID for resource ARNs
            account_id = self._get_account_id()
            if not account_id:
                return

            # Critical actions to test
            critical_actions = [
                "iam:AttachUserPolicy",
                "iam:AttachRolePolicy",
                "iam:PutUserPolicy",
                "iam:PutRolePolicy",
                "iam:CreateAccessKey",
                "iam:CreateLoginProfile",
                "iam:UpdateLoginProfile",
                "iam:AddUserToGroup",
                "iam:CreatePolicyVersion",
                "iam:SetDefaultPolicyVersion",
                "sts:AssumeRole",
                "ec2:RunInstances",
                "lambda:CreateFunction",
                "lambda:InvokeFunction",
                "s3:GetObject",
                "s3:PutObject",
                "secretsmanager:GetSecretValue",
            ]

            # Test for users with admin-like policies
            paginator = self.client.get_paginator("list_users")
            for page in paginator.paginate():
                for user in page.get("Users", []):
                    user_arn = user["Arn"]
                    await self._simulate_principal_policy(user_arn, critical_actions, scan_id=scan_id, findings=findings)

            # Test for roles (non-service-linked)
            paginator = self.client.get_paginator("list_roles")
            for page in paginator.paginate():
                for role in page.get("Roles", []):
                    if role.get("Path", "").startswith("/aws-service-role/"):
                        continue
                    role_arn = role["Arn"]
                    await self._simulate_principal_policy(role_arn, critical_actions, scan_id=scan_id, findings=findings)

        except botocore.exceptions.ClientError as e:
            log.debug("Policy simulation scan error: {}", e)

    async def _scan_account_authorization(self, scan_id: str, findings: list, result: ScanResult) -> None:
        """Scan using GetAccountAuthorizationDetails for full IAM mapping."""
        try:
            paginator = self.client.get_paginator("get_account_authorization_details")
            for page in paginator.paginate():
                # Users
                for user in page.get("UserDetailList", []):
                    result.resources_found += 1
                    await self._analyze_user_detail(user, scan_id, findings)

                # Roles
                for role in page.get("RoleDetailList", []):
                    result.resources_found += 1
                    await self._analyze_role_detail(role, scan_id, findings)

                # Policies
                for policy in page.get("Policies", []):
                    result.resources_found += 1
                    await self._analyze_policy_detail(policy, scan_id, findings)

                # Groups
                for group in page.get("GroupDetailList", []):
                    result.resources_found += 1
                    await self._analyze_group_detail(group, scan_id, findings)

        except botocore.exceptions.ClientError as e:
            self.handle_client_error(e, "GetAccountAuthorizationDetails", findings)

    async def _analyze_user_detail(self, user: dict, scan_id: str, findings: list) -> None:
        """Analyze user from GetAccountAuthorizationDetails."""
        user_name = user["UserName"]
        user_arn = user["Arn"]

        # Permissions boundary
        permissions_boundary = user.get("PermissionsBoundary", {})
        if permissions_boundary:
            await self._add_enumeration_finding("iam_user_permissions_boundary", user_name, user_name, {
                "arn": user_arn,
                "permissions_boundary_type": permissions_boundary.get("PermissionsBoundaryType", ""),
                "permissions_boundary_arn": permissions_boundary.get("PermissionsBoundaryArn", ""),
            }, findings, scan_id)
        else:
            self._add_finding_deduped(findings, self.create_finding(
                title=f"IAM user {user_name} has no permissions boundary",
                description="User lacks a permissions boundary which could limit maximum permissions",
                severity="medium",
                category="weak_configuration",
                resource_type="iam_user",
                resource_id=user_name,
                resource_name=user_name,
                region="global",
                remediation={
                    "summary": "Set permissions boundary for user",
                    "steps": [
                        "Create a managed policy defining maximum permissions",
                        "Attach as permissions boundary to user",
                    ],
                    "effort": "medium",
                    "automatable": False,
                },
                rule_id="iam_user_no_permissions_boundary",
            ))

        # Tags
        tags = user.get("Tags", [])
        if not tags:
            self._add_finding_deduped(findings, self.create_finding(
                title=f"IAM user {user_name} has no tags",
                description="User lacks tags for resource management and cost allocation",
                severity="low",
                category="weak_configuration",
                resource_type="iam_user",
                resource_id=user_name,
                resource_name=user_name,
                region="global",
                rule_id="iam_user_no_tags",
            ))

    async def _analyze_role_detail(self, role: dict, scan_id: str, findings: list) -> None:
        """Analyze role from GetAccountAuthorizationDetails."""
        role_name = role["RoleName"]
        role_arn = role["Arn"]

        # Skip service-linked roles
        if role.get("Path", "").startswith("/aws-service-role/"):
            return

        # Permissions boundary
        permissions_boundary = role.get("PermissionsBoundary", {})
        if permissions_boundary:
            await self._add_enumeration_finding("iam_role_permissions_boundary", role_name, role_name, {
                "arn": role_arn,
                "permissions_boundary_type": permissions_boundary.get("PermissionsBoundaryType", ""),
                "permissions_boundary_arn": permissions_boundary.get("PermissionsBoundaryArn", ""),
            }, findings, scan_id)

        # Tags
        tags = role.get("Tags", [])
        if not tags:
            self._add_finding_deduped(findings, self.create_finding(
                title=f"IAM role {role_name} has no tags",
                description="Role lacks tags for resource management",
                severity="low",
                category="weak_configuration",
                resource_type="iam_role",
                resource_id=role_name,
                resource_name=role_name,
                region="global",
                rule_id="iam_role_no_tags",
            ))

        # Inline policies (already in detail)
        for policy in role.get("RolePolicyList", []):
            await self._check_policy_document(policy["PolicyDocument"], f"role/{role_name}/inline/{policy['PolicyName']}", scan_id, findings)

        # Attached managed policies
        for policy in role.get("AttachedManagedPolicies", []):
            await self._check_policy_permissions(policy["PolicyArn"], f"role/{role_name}", scan_id, findings)

    async def _analyze_policy_detail(self, policy: dict, scan_id: str, findings: list) -> None:
        """Analyze policy from GetAccountAuthorizationDetails."""
        policy_name = policy["PolicyName"]
        policy_arn = policy["Arn"]

        await self._add_enumeration_finding("iam_policy_detail", policy_name, policy_name, {
            "arn": policy_arn,
            "path": policy.get("Path", "/"),
            "created": policy.get("CreateDate", "").isoformat() if policy.get("CreateDate") else "",
            "updated": policy.get("UpdateDate", "").isoformat() if policy.get("UpdateDate") else "",
            "description": policy.get("Description", ""),
            "default_version": policy.get("DefaultVersionId", ""),
            "attachment_count": policy.get("AttachmentCount", 0),
            "is_attachable": policy.get("IsAttachable", True),
            "permissions_boundary_usage_count": policy.get("PermissionsBoundaryUsageCount", 0),
        }, findings, scan_id)

        # Check default version
        try:
            version = self.client.get_policy_version(
                PolicyArn=policy_arn,
                VersionId=policy["DefaultVersionId"],
            )
            await self._check_policy_document(version["PolicyVersion"]["Document"], f"policy/{policy_arn}", scan_id, findings)
        except botocore.exceptions.ClientError:
            pass

    async def _analyze_group_detail(self, group: dict, scan_id: str, findings: list) -> None:
        """Analyze group from GetAccountAuthorizationDetails."""
        group_name = group["GroupName"]

        # Inline policies
        for policy in group.get("GroupPolicyList", []):
            await self._check_policy_document(policy["PolicyDocument"], f"group/{group_name}/inline/{policy['PolicyName']}", scan_id, findings)

        # Attached managed policies
        for policy in group.get("AttachedManagedPolicies", []):
            await self._check_policy_permissions(policy["PolicyArn"], f"group/{group_name}", scan_id, findings)

    async def _scan_service_credentials(self, scan_id: str, findings: list, result: ScanResult) -> None:
        """Scan service-specific credentials (CodeCommit, Keys)."""
        try:
            paginator = self.client.get_paginator("list_users")
            for page in paginator.paginate():
                for user in page.get("Users", []):
                    user_name = user["UserName"]
                    try:
                        creds = self.client.list_service_specific_credentials(UserName=user_name)
                        for cred in creds.get("ServiceSpecificCredentials", []):
                            result.resources_found += 1
                            await self._add_enumeration_finding("service_specific_credential", f"{user_name}/{cred['ServiceSpecificCredentialId']}", cred["ServiceSpecificCredentialId"], {
                                "user_name": user_name,
                                "service_name": cred.get("ServiceName", ""),
                                "service_user_name": cred.get("ServiceUserName", ""),
                                "status": cred.get("Status", ""),
                                "create_date": cred.get("CreateDate", "").isoformat() if cred.get("CreateDate") else "",
                            }, findings, scan_id)

                            if cred.get("Status") == "Active":
                                self._add_finding_deduped(findings, self.create_finding(
                                    title=f"Active service-specific credential for {user_name}",
                                    description=f"User {user_name} has active service-specific credential for {cred.get('ServiceName')}",
                                    severity="medium",
                                    category="weak_configuration",
                                    resource_type="service_credential",
                                    resource_id=f"{user_name}/{cred['ServiceSpecificCredentialId']}",
                                    resource_name=cred["ServiceSpecificCredentialId"],
                                    region="global",
                                    remediation={
                                        "summary": "Review and rotate service credentials",
                                        "steps": [
                                            "Verify if credential is still needed",
                                            "Rotate credential if active",
                                            "Delete if unused",
                                        ],
                                        "effort": "low",
                                        "automatable": True,
                                    },
                                    rule_id="iam_service_credential_active",
                                ))
                    except botocore.exceptions.ClientError as e:
                        if e.response["Error"]["Code"] != "NoSuchEntity":
                            pass
        except botocore.exceptions.ClientError as e:
            self.handle_client_error(e, "ListUsers/ListServiceSpecificCredentials", findings)

    async def _scan_ssh_keys(self, scan_id: str, findings: list, result: ScanResult) -> None:
        """Scan SSH public keys for IAM users."""
        try:
            paginator = self.client.get_paginator("list_users")
            for page in paginator.paginate():
                for user in page.get("Users", []):
                    user_name = user["UserName"]
                    try:
                        keys = self.client.list_ssh_public_keys(UserName=user_name)
                        for key in keys.get("SSHPublicKeys", []):
                            result.resources_found += 1
                            key_id = key["SSHPublicKeyId"]
                            await self._add_enumeration_finding("ssh_public_key", f"{user_name}/{key_id}", key_id, {
                                "user_name": user_name,
                                "status": key.get("Status", ""),
                                "upload_date": key.get("UploadDate", "").isoformat() if key.get("UploadDate") else "",
                            }, findings, scan_id)

                            if key.get("Status") == "Active":
                                self._add_finding_deduped(findings, self.create_finding(
                                    title=f"Active SSH public key for user {user_name}",
                                    description=f"User {user_name} has active SSH public key {key_id} (for CodeCommit)",
                                    severity="info",
                                    category="enumeration",
                                    resource_type="ssh_public_key",
                                    resource_id=f"{user_name}/{key_id}",
                                    resource_name=key_id,
                                    region="global",
                                    rule_id="iam_ssh_key_active",
                                ))
                    except botocore.exceptions.ClientError:
                        pass
        except botocore.exceptions.ClientError as e:
            self.handle_client_error(e, "ListUsers/ListSSHPublicKeys", findings)

    async def _scan_signing_certs(self, scan_id: str, findings: list, result: ScanResult) -> None:
        """Scan signing certificates for IAM users."""
        try:
            paginator = self.client.get_paginator("list_users")
            for page in paginator.paginate():
                for user in page.get("Users", []):
                    user_name = user["UserName"]
                    try:
                        certs = self.client.list_signing_certificates(UserName=user_name)
                        for cert in certs.get("Certificates", []):
                            result.resources_found += 1
                            cert_id = cert["CertificateId"]
                            await self._add_enumeration_finding("signing_certificate", f"{user_name}/{cert_id}", cert_id, {
                                "user_name": user_name,
                                "status": cert.get("Status", ""),
                                "upload_date": cert.get("UploadDate", "").isoformat() if cert.get("UploadDate") else "",
                            }, findings, scan_id)

                            if cert.get("Status") == "Active":
                                self._add_finding_deduped(findings, self.create_finding(
                                    title=f"Active signing certificate for user {user_name}",
                                    description=f"User {user_name} has active signing certificate {cert_id}",
                                    severity="medium",
                                    category="weak_configuration",
                                    resource_type="signing_certificate",
                                    resource_id=f"{user_name}/{cert_id}",
                                    resource_name=cert_id,
                                    region="global",
                                    remediation={
                                        "summary": "Review and rotate signing certificates",
                                        "steps": [
                                            "Verify if certificate is still needed",
                                            "Rotate or delete if unused",
                                        ],
                                        "effort": "low",
                                        "automatable": True,
                                    },
                                    rule_id="iam_signing_cert_active",
                                ))
                    except botocore.exceptions.ClientError:
                        pass
        except botocore.exceptions.ClientError as e:
            self.handle_client_error(e, "ListUsers/ListSigningCertificates", findings)

    async def _scan_login_profiles(self, scan_id: str, findings: list, result: ScanResult) -> None:
        """Scan login profiles (console passwords) for IAM users."""
        try:
            # Get account password policy
            try:
                policy = self.client.get_account_password_policy()
                policy_map = policy.get("PasswordPolicy", {})
                await self._add_enumeration_finding("account_password_policy", "account", "account", {
                    "minimum_length": policy_map.get("MinimumPasswordLength", 0),
                    "require_symbols": policy_map.get("RequireSymbols", False),
                    "require_numbers": policy_map.get("RequireNumbers", False),
                    "require_uppercase": policy_map.get("RequireUppercase", False),
                    "require_lowercase": policy_map.get("RequireLowercase", False),
                    "allow_users_to_change": policy_map.get("AllowUsersToChangePassword", False),
                    "max_age": policy_map.get("MaxPasswordAge", 0),
                    "reuse_prevention": policy_map.get("PasswordReusePrevention", 0),
                    "hard_expiry": policy_map.get("HardExpiry", False),
                }, findings, scan_id)

                # Check for weak password policy
                issues = []
                if policy_map.get("MinimumPasswordLength", 0) < 8:
                    issues.append("length < 8")
                if not policy_map.get("RequireSymbols", False):
                    issues.append("no symbols required")
                if not policy_map.get("RequireNumbers", False):
                    issues.append("no numbers required")
                if not policy_map.get("RequireUppercase", False):
                    issues.append("no uppercase required")
                if not policy_map.get("RequireLowercase", False):
                    issues.append("no lowercase required")
                if policy_map.get("MaxPasswordAge", 0) == 0 or policy_map.get("MaxPasswordAge", 0) > 90:
                    issues.append("no rotation or > 90 days")
                if policy_map.get("PasswordReusePrevention", 0) < 5:
                    issues.append("reuse prevention < 5")

                if issues:
                    self._add_finding_deduped(findings, self.create_finding(
                        title="Weak account password policy",
                        description=f"Password policy issues: {', '.join(issues)}",
                        severity="high",
                        category="weak_configuration",
                        resource_type="aws_account",
                        resource_id=self._get_account_id(),
                        resource_name="account",
                        region="global",
                        evidence=[{"type": "password_policy", "description": "Account password policy", "data": policy_map}],
                        remediation={
                            "summary": "Strengthen password policy",
                            "steps": [
                                "Set minimum length to 12+",
                                "Require uppercase, lowercase, numbers, symbols",
                                "Set max age to 90 days",
                                "Set reuse prevention to 24+",
                            ],
                            "effort": "low",
                            "automatable": True,
                            "cli_commands": [
                                "aws iam update-account-password-policy --minimum-password-length 12 --require-uppercase --require-lowercase --require-numbers --require-symbols --max-password-age 90 --password-reuse-prevention 24",
                            ],
                        },
                        rule_id="iam_weak_password_policy",
                    ))
            except botocore.exceptions.ClientError as e:
                if e.response["Error"]["Code"] == "NoSuchEntity":
                    self._add_finding_deduped(findings, self.create_finding(
                        title="No account password policy configured",
                        description="No IAM password policy is set for the account",
                        severity="high",
                        category="weak_configuration",
                        resource_type="aws_account",
                        resource_id=self._get_account_id(),
                        resource_name="account",
                        region="global",
                        rule_id="iam_no_password_policy",
                    ))

            # Check each user's login profile
            paginator = self.client.get_paginator("list_users")
            for page in paginator.paginate():
                for user in page.get("Users", []):
                    user_name = user["UserName"]
                    try:
                        profile = self.client.get_login_profile(UserName=user_name)
                        result.resources_found += 1
                        await self._add_enumeration_finding("login_profile", user_name, user_name, {
                            "user_name": user_name,
                            "created": profile.get("LoginProfile", {}).get("CreateDate", "").isoformat() if profile.get("LoginProfile", {}).get("CreateDate") else "",
                            "password_reset_required": profile.get("LoginProfile", {}).get("PasswordResetRequired", False),
                        }, findings, scan_id)

                        if profile.get("LoginProfile", {}).get("PasswordResetRequired"):
                            self._add_finding_deduped(findings, self.create_finding(
                                title=f"User {user_name} requires password reset",
                                description="User must reset password on next login",
                                severity="info",
                                category="enumeration",
                                resource_type="login_profile",
                                resource_id=user_name,
                                resource_name=user_name,
                                region="global",
                                rule_id="iam_password_reset_required",
                            ))
                    except botocore.exceptions.ClientError as e:
                        if e.response["Error"]["Code"] == "NoSuchEntity":
                            # User has no console access
                            pass
                        else:
                            pass
        except botocore.exceptions.ClientError as e:
            self.handle_client_error(e, "GetAccountPasswordPolicy/GetLoginProfile", findings)

    async def _scan_permissions_boundaries(self, scan_id: str, findings: list, result: ScanResult) -> None:
        """Scan for permissions boundaries on users and roles."""
        try:
            # Already covered in _analyze_user_detail and _analyze_role_detail
            # This method provides additional analysis
            pass
        except botocore.exceptions.ClientError as e:
            self.handle_client_error(e, "Permissions boundary scan", findings)

    async def _scan_service_linked_roles(self, scan_id: str, findings: list, result: ScanResult) -> None:
        """Scan service-linked roles."""
        try:
            paginator = self.client.get_paginator("list_roles")
            for page in paginator.paginate():
                for role in page.get("Roles", []):
                    if role.get("Path", "").startswith("/aws-service-role/"):
                        result.resources_found += 1
                        role_name = role["RoleName"]
                        await self._add_enumeration_finding("service_linked_role", role_name, role_name, {
                            "arn": role["Arn"],
                            "path": role.get("Path", ""),
                            "created": role.get("CreateDate", "").isoformat() if role.get("CreateDate") else "",
                            "description": role.get("Description", ""),
                        }, findings, scan_id)
        except botocore.exceptions.ClientError as e:
            self.handle_client_error(e, "ListRoles (service-linked)", findings)

    async def _scan_organization_accounts(self, scan_id: str, findings: list, result: ScanResult) -> None:
        """Scan AWS Organization accounts if available."""
        try:
            org_client = self.session.client("organizations", region_name="us-east-1")
            paginator = org_client.get_paginator("list_accounts")
            for page in paginator.paginate():
                for account in page.get("Accounts", []):
                    result.resources_found += 1
                    await self._add_enumeration_finding("org_account", account["Id"], account["Name"] or account["Id"], {
                        "account_id": account["Id"],
                        "name": account.get("Name", ""),
                        "email": account.get("Email", ""),
                        "status": account.get("Status", ""),
                        "joined_method": account.get("JoinedMethod", ""),
                        "joined_timestamp": account.get("JoinedTimestamp", "").isoformat() if account.get("JoinedTimestamp") else "",
                    }, findings, scan_id)
        except botocore.exceptions.ClientError as e:
            if e.response["Error"]["Code"] not in ("AccessDenied", "AWSOrganizationsNotInUseException"):
                self.handle_client_error(e, "Organizations ListAccounts", findings)

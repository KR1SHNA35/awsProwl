"""AWS Organizations scanner for awsProwl."""

from __future__ import annotations

import asyncio
import hashlib

import botocore.exceptions

from awsprowl.aws.base import AWSServiceBase, ScanResult
from awsprowl.core.auth import AWSAuthManager
from awsprowl.core.logging import get_logger

log = get_logger(__name__)


class OrganizationsScanner(AWSServiceBase):
    """Scanner for AWS Organizations resources."""

    SERVICE_NAME = "organizations"
    REQUIRED_PERMISSIONS = [
        "organizations:ListAccounts",
        "organizations:ListOrganizationalUnitsForParent",
        "organizations:ListRoots",
        "organizations:ListPolicies",
        "organizations:ListPoliciesForTarget",
        "organizations:DescribePolicy",
        "organizations:ListDelegatedAdministrators",
        "organizations:ListDelegatedServicesForAccount",
        "organizations:ListAccountsForParent",
        "organizations:DescribeOrganization",
        "organizations:DescribeAccount",
    ]

    def __init__(self, auth_manager: AWSAuthManager, region: str | None = None):
        # Organizations is global, uses us-east-1 endpoint
        super().__init__(auth_manager, region or "us-east-1")

    async def scan(self, scan_id: str, findings: list) -> ScanResult:
        """Scan Organizations resources for security issues."""
        result = ScanResult(service=self.SERVICE_NAME, region="global")

        try:
            # Run all scans in parallel
            await asyncio.gather(
                self._scan_accounts(scan_id, findings, result),
                self._scan_organizational_units(scan_id, findings, result),
                self._scan_roots(scan_id, findings, result),
                self._scan_policies(scan_id, findings, result),
                self._scan_delegated_administrators(scan_id, findings, result),
                return_exceptions=True,
            )

        except Exception as e:
            log.error("Error in Organizations scan: {}", e)
            result.errors.append(str(e))

        return result

    async def _scan_accounts(self, scan_id: str, findings: list, result: ScanResult) -> None:
        """Scan AWS accounts in the organization."""
        try:
            paginator = self.client.get_paginator("list_accounts")
            for page in paginator.paginate():
                for account in page.get("Accounts", []):
                    result.resources_found += 1
                    await self._analyze_account(account, scan_id, findings)

        except botocore.exceptions.ClientError as e:
            self.handle_client_error(e, "ListAccounts", findings)

    async def _analyze_account(self, account: dict, scan_id: str, findings: list) -> None:
        """Analyze a single account for security issues."""
        account_id = account["Id"]
        account_name = account.get("Name", account_id)
        account_email = account.get("Email", "")
        account_status = account.get("Status", "UNKNOWN")

        # Add enumeration finding
        await self._add_enumeration_finding("organizations_account", account_id, account_name, {
            "id": account_id,
            "email": account_email,
            "status": account_status,
            "joined_method": account.get("JoinedMethod", ""),
            "joined_timestamp": str(account.get("JoinedTimestamp", "")) if account.get("JoinedTimestamp") else "",
        }, findings, scan_id)

        # Check for suspended accounts
        if account_status == "SUSPENDED":
            self._add_finding_deduped(findings, self.create_finding(
                title=f"Suspended account: {account_name}",
                description=f"Account {account_id} ({account_name}) is suspended and cannot be used",
                severity="high",
                category="weak_configuration",
                resource_type="organizations_account",
                resource_id=account_id,
                resource_name=account_name,
                region="global",
                evidence=[{"type": "api_response", "description": "Account status", "data": account}],
                remediation={
                    "summary": "Review suspended account status",
                    "steps": [
                        "Determine why account was suspended",
                        "Contact AWS Support if suspension was unexpected",
                        "Resolve billing or compliance issues",
                        "Close account if no longer needed",
                    ],
                    "effort": "medium",
                    "automatable": False,
                },
                rule_id="org_account_suspended",
            ))

        # Check if account has no SCPs attached (will be checked in _scan_policies)
        # This is a placeholder for cross-referencing

        # Check for accounts without MFA on root (requires IAM access per account)
        # This would require cross-account role assumption

    async def _scan_organizational_units(self, scan_id: str, findings: list, result: ScanResult) -> None:
        """Scan Organizational Units (OUs)."""
        try:
            # First get roots
            roots_response = self.client.list_roots()
            roots = roots_response.get("Roots", [])

            for root in roots:
                root_id = root["Id"]
                await self._scan_ou_tree(root_id, scan_id, findings, result)

        except botocore.exceptions.ClientError as e:
            self.handle_client_error(e, "ListOrganizationalUnitsForParent", findings)

    async def _scan_ou_tree(self, parent_id: str, scan_id: str, findings: list, result: ScanResult) -> None:
        """Recursively scan OU tree."""
        try:
            paginator = self.client.get_paginator("list_organizational_units_for_parent")
            for page in paginator.paginate(ParentId=parent_id):
                for ou in page.get("OrganizationalUnits", []):
                    result.resources_found += 1
                    ou_id = ou["Id"]
                    ou_name = ou.get("Name", ou_id)

                    # Add enumeration finding
                    await self._add_enumeration_finding("organizations_ou", ou_id, ou_name, {
                        "id": ou_id,
                        "name": ou_name,
                        "parent_id": parent_id,
                        "arn": ou.get("Arn", ""),
                    }, findings, scan_id)

                    # Check if OU has any SCPs attached
                    await self._check_ou_scps(ou_id, ou_name, scan_id, findings)

                    # Recursively scan child OUs
                    await self._scan_ou_tree(ou_id, scan_id, findings, result)

                    # Scan accounts directly in this OU
                    await self._scan_accounts_in_ou(ou_id, scan_id, findings, result)

        except botocore.exceptions.ClientError as e:
            self.handle_client_error(e, "ListOrganizationalUnitsForParent", findings)

    async def _check_ou_scps(self, ou_id: str, ou_name: str, scan_id: str, findings: list) -> None:
        """Check if an OU has SCPs attached."""
        try:
            response = self.client.list_policies_for_target(
                TargetId=ou_id,
                Filter="SERVICE_CONTROL_POLICY"
            )
            policies = response.get("Policies", [])

            if not policies:
                self._add_finding_deduped(findings, self.create_finding(
                    title=f"OU missing SCPs: {ou_name}",
                    description=f"Organizational Unit {ou_name} ({ou_id}) has no Service Control Policies attached",
                    severity="medium",
                    category="weak_configuration",
                    resource_type="organizations_account",
                    resource_id=ou_id,
                    resource_name=ou_name,
                    region="global",
                    evidence=[{"type": "api_response", "description": "No SCPs attached to OU", "data": {"ou_id": ou_id, "policies": []}}],
                    remediation={
                        "summary": "Attach appropriate SCPs to OU",
                        "steps": [
                            "Identify required guardrails for this OU",
                            "Create or select appropriate SCPs",
                            "Attach SCPs to the OU",
                            "Test that SCPs don't break required functionality",
                        ],
                        "effort": "medium",
                        "automatable": True,
                        "cli_commands": [
                            f"aws organizations attach-policy --policy-id <policy-id> --target-id {ou_id}",
                        ],
                    },
                    rule_id="org_ou_missing_scp",
                ))

        except botocore.exceptions.ClientError as e:
            if e.response["Error"]["Code"] != "AccessDenied":
                self.handle_client_error(e, "ListPoliciesForTarget", findings)

    async def _scan_accounts_in_ou(self, ou_id: str, scan_id: str, findings: list, result: ScanResult) -> None:
        """Scan accounts directly in an OU."""
        try:
            paginator = self.client.get_paginator("list_accounts_for_parent")
            for page in paginator.paginate(ParentId=ou_id):
                for account in page.get("Accounts", []):
                    result.resources_found += 1
                    await self._analyze_account(account, scan_id, findings)

        except botocore.exceptions.ClientError as e:
            self.handle_client_error(e, "ListAccountsForParent", findings)

    async def _scan_roots(self, scan_id: str, findings: list, result: ScanResult) -> None:
        """Scan organization roots."""
        try:
            response = self.client.list_roots()
            roots = response.get("Roots", [])

            for root in roots:
                result.resources_found += 1
                root_id = root["Id"]

                # Add enumeration finding
                await self._add_enumeration_finding("organizations_root", root_id, "Organization Root", {
                    "id": root_id,
                    "arn": root.get("Arn", ""),
                    "name": root.get("Name", "Root"),
                    "policy_types": root.get("PolicyTypes", []),
                }, findings, scan_id)

                # Check if root has SCPs attached
                await self._check_root_scps(root_id, scan_id, findings)

                # Check root policy types
                policy_types = root.get("PolicyTypes", [])
                scp_enabled = any(pt.get("Type") == "SERVICE_CONTROL_POLICY" and pt.get("Status") == "ENABLED" for pt in policy_types)

                if not scp_enabled:
                    self._add_finding_deduped(findings, self.create_finding(
                        title="SCPs not enabled at root level",
                        description="Service Control Policies are not enabled for the organization root",
                        severity="high",
                        category="weak_configuration",
                        resource_type="organizations_account",
                        resource_id=root_id,
                        resource_name="Organization Root",
                        region="global",
                        evidence=[{"type": "api_response", "description": "Root policy types", "data": {"policy_types": policy_types}}],
                        remediation={
                            "summary": "Enable SCPs at organization root",
                            "steps": [
                                "Enable SCP policy type at root",
                                "Create baseline SCPs",
                                "Attach SCPs to root or OUs",
                            ],
                            "effort": "low",
                            "automatable": True,
                            "cli_commands": [
                                f"aws organizations enable-policy-type --root-id {root_id} --policy-type SERVICE_CONTROL_POLICY",
                            ],
                        },
                        rule_id="org_root_scp_disabled",
                    ))

        except botocore.exceptions.ClientError as e:
            self.handle_client_error(e, "ListRoots", findings)

    async def _check_root_scps(self, root_id: str, scan_id: str, findings: list) -> None:
        """Check if root has SCPs attached."""
        try:
            response = self.client.list_policies_for_target(
                TargetId=root_id,
                Filter="SERVICE_CONTROL_POLICY"
            )
            policies = response.get("Policies", [])

            if not policies:
                self._add_finding_deduped(findings, self.create_finding(
                    title="Root missing SCPs",
                    description="Organization root has no Service Control Policies attached",
                    severity="medium",
                    category="weak_configuration",
                    resource_type="organizations_account",
                    resource_id=root_id,
                    resource_name="Organization Root",
                    region="global",
                    evidence=[{"type": "api_response", "description": "No SCPs attached to root", "data": {"root_id": root_id, "policies": []}}],
                    remediation={
                        "summary": "Attach baseline SCPs to organization root",
                        "steps": [
                            "Create baseline SCPs (e.g., deny regions, require encryption)",
                            "Attach SCPs to root",
                            "Test impact on member accounts",
                        ],
                        "effort": "medium",
                        "automatable": True,
                        "cli_commands": [
                            f"aws organizations attach-policy --policy-id <policy-id> --target-id {root_id}",
                        ],
                    },
                    rule_id="org_root_missing_scp",
                ))

        except botocore.exceptions.ClientError as e:
            if e.response["Error"]["Code"] != "AccessDenied":
                self.handle_client_error(e, "ListPoliciesForTarget", findings)

    async def _scan_policies(self, scan_id: str, findings: list, result: ScanResult) -> None:
        """Scan Service Control Policies (SCPs)."""
        try:
            paginator = self.client.get_paginator("list_policies")
            for page in paginator.paginate(Filter="SERVICE_CONTROL_POLICY"):
                for policy_summary in page.get("Policies", []):
                    result.resources_found += 1
                    policy_id = policy_summary["Id"]
                    policy_name = policy_summary.get("Name", policy_id)

                    await self._analyze_scp(policy_id, policy_name, scan_id, findings)

        except botocore.exceptions.ClientError as e:
            self.handle_client_error(e, "ListPolicies", findings)

    async def _analyze_scp(self, policy_id: str, policy_name: str, scan_id: str, findings: list) -> None:
        """Analyze a single SCP for security issues."""
        try:
            response = self.client.describe_policy(PolicyId=policy_id)
            policy = response.get("Policy", {})
            content = policy.get("Content", "{}")

            import json
            policy_doc = json.loads(content)

            # Add enumeration finding
            await self._add_enumeration_finding("organizations_scp", policy_id, policy_name, {
                "id": policy_id,
                "name": policy_name,
                "arn": policy.get("Arn", ""),
                "description": policy.get("Description", ""),
                "type": policy.get("Type", ""),
                "aws_managed": policy.get("AwsManaged", False),
            }, findings, scan_id)

            # Check for overly permissive SCPs (allowing too much)
            await self._check_scp_permissions(policy_doc, policy_id, policy_name, scan_id, findings)

            # Check if SCP is attached to anything
            await self._check_scp_attachment(policy_id, policy_name, scan_id, findings)

        except botocore.exceptions.ClientError as e:
            if e.response["Error"]["Code"] != "AccessDenied":
                self.handle_client_error(e, "DescribePolicy", findings)

    async def _check_scp_permissions(self, policy_doc: dict, policy_id: str, policy_name: str, scan_id: str, findings: list) -> None:
        """Check SCP for overly permissive or ineffective statements."""
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

            # Check for wildcard allow in SCP (defeats purpose of SCP)
            has_wildcard_action = "*" in actions or any(a.endswith("*") for a in actions)
            has_wildcard_resource = "*" in resources

            if has_wildcard_action and has_wildcard_resource:
                self._add_finding_deduped(findings, self.create_finding(
                    title=f"Overly permissive SCP: {policy_name}",
                    description=f"SCP {policy_name} ({policy_id}) allows all actions on all resources, defeating its purpose as a guardrail",
                    severity="high",
                    category="weak_configuration",
                    resource_type="organizations_account",
                    resource_id=policy_id,
                    resource_name=policy_name,
                    region="global",
                    evidence=[{"type": "policy_document", "description": "SCP with wildcard allow", "data": policy_doc}],
                    remediation={
                        "summary": "Restrict SCP to specific deny statements",
                        "steps": [
                            "Review SCP purpose - SCPs should primarily deny",
                            "Replace wildcard allows with specific deny statements",
                            "Test SCP impact on member accounts",
                        ],
                        "effort": "medium",
                        "automatable": False,
                    },
                    rule_id="org_scp_overly_permissive",
                ))

            # Check for missing condition keys that could strengthen SCP
            conditions = stmt.get("Condition", {})
            if not conditions and has_wildcard_action:
                self._add_finding_deduped(findings, self.create_finding(
                    title=f"SCP missing conditions: {policy_name}",
                    description=f"SCP {policy_name} has broad allow without condition keys",
                    severity="medium",
                    category="weak_configuration",
                    resource_type="organizations_account",
                    resource_id=policy_id,
                    resource_name=policy_name,
                    region="global",
                    evidence=[{"type": "policy_document", "description": "SCP without conditions", "data": {"statement": stmt}}],
                    remediation={
                        "summary": "Add conditions to strengthen SCP",
                        "steps": [
                            "Add aws:RequestedRegion condition to restrict regions",
                            "Add aws:PrincipalOrgID to restrict to organization",
                            "Add appropriate service-specific conditions",
                        ],
                        "effort": "low",
                        "automatable": True,
                    },
                    rule_id="org_scp_missing_conditions",
                ))

    async def _check_scp_attachment(self, policy_id: str, policy_name: str, scan_id: str, findings: list) -> None:
        """Check if SCP is attached to any targets."""
        # Note: There's no direct API to list targets for a policy
        # This would require checking all roots and OUs
        # For now, we'll note this as informational
        pass

    async def _scan_delegated_administrators(self, scan_id: str, findings: list, result: ScanResult) -> None:
        """Scan delegated administrators."""
        try:
            paginator = self.client.get_paginator("list_delegated_administrators")
            for page in paginator.paginate():
                for admin in page.get("DelegatedAdministrators", []):
                    result.resources_found += 1
                    account_id = admin["Id"]
                    account_name = admin.get("Name", account_id)
                    service_principal = admin.get("ServicePrincipal", "")

                    # Check for excessive delegated admin
                    await self._check_delegated_admin(account_id, account_name, service_principal, scan_id, findings)

                    # Get services delegated to this account
                    await self._scan_delegated_services(account_id, account_name, scan_id, findings)

        except botocore.exceptions.ClientError as e:
            if e.response["Error"]["Code"] != "AccessDenied":
                self.handle_client_error(e, "ListDelegatedAdministrators", findings)

    async def _check_delegated_admin(self, account_id: str, account_name: str, service_principal: str, scan_id: str, findings: list) -> None:
        """Check for excessive delegated administrator permissions."""
        # Add enumeration finding
        await self._add_enumeration_finding("organizations_delegated_admin", account_id, account_name, {
            "account_id": account_id,
            "account_name": account_name,
            "service_principal": service_principal,
        }, findings, scan_id)

        # High-risk service principals that should have limited delegation
        high_risk_services = {
            "cloudformation.amazonaws.com": "Can create/manage stacks across accounts",
            "stacksets.cloudformation.amazonaws.com": "Can deploy StackSets across accounts",
            "access-analyzer.amazonaws.com": "Can analyze cross-account access",
            "config.amazonaws.com": "Can view compliance across accounts",
            "guardduty.amazonaws.com": "Can view security findings across accounts",
            "securityhub.amazonaws.com": "Can view security posture across accounts",
            "iam.amazonaws.com": "Can manage IAM across accounts (if enabled)",
        }

        if service_principal in high_risk_services:
            self._add_finding_deduped(findings, self.create_finding(
                title=f"High-risk delegated admin: {account_name} for {service_principal}",
                description=f"Account {account_id} ({account_name}) is delegated administrator for {service_principal}: {high_risk_services[service_principal]}",
                severity="medium",
                category="excessive_permissions",
                resource_type="organizations_account",
                resource_id=account_id,
                resource_name=account_name,
                region="global",
                evidence=[{"type": "api_response", "description": "Delegated administrator", "data": admin}],
                remediation={
                    "summary": "Review delegated administrator necessity",
                    "steps": [
                        "Verify if this account needs delegated admin for this service",
                        "Consider using a dedicated security/audit account",
                        "Limit delegation to specific OUs if possible",
                        "Monitor delegated admin activity via CloudTrail",
                    ],
                    "effort": "medium",
                    "automatable": False,
                },
                rule_id="org_delegated_admin_high_risk",
            ))

    async def _scan_delegated_services(self, account_id: str, account_name: str, scan_id: str, findings: list) -> None:
        """Get services delegated to an account."""
        try:
            response = self.client.list_delegated_services_for_account(AccountId=account_id)
            services = response.get("DelegatedServices", [])

            # Add enumeration finding
            await self._add_enumeration_finding("organizations_delegated_services", account_id, account_name, {
                "account_id": account_id,
                "account_name": account_name,
                "delegated_service_count": len(services),
                "services": [s.get("ServicePrincipal", "") for s in services],
            }, findings, scan_id)

            if len(services) > 5:
                self._add_finding_deduped(findings, self.create_finding(
                    title=f"Excessive delegated services for account: {account_name}",
                    description=f"Account {account_id} ({account_name}) is delegated administrator for {len(services)} services",
                    severity="medium",
                    category="excessive_permissions",
                    resource_type="organizations_account",
                    resource_id=account_id,
                    resource_name=account_name,
                    region="global",
                    evidence=[{"type": "api_response", "description": "Delegated services", "data": {"services": services}}],
                    remediation={
                        "summary": "Review and reduce delegated services",
                        "steps": [
                            "Audit each delegated service for necessity",
                            "Remove delegation for unused services",
                            "Consolidate delegated admin to dedicated accounts",
                            "Document justification for each delegation",
                        ],
                        "effort": "medium",
                        "automatable": False,
                    },
                    rule_id="org_excessive_delegated_services",
                ))

        except botocore.exceptions.ClientError as e:
            if e.response["Error"]["Code"] != "AccessDenied":
                self.handle_client_error(e, "ListDelegatedServicesForAccount", findings)

    def _get_account_id(self) -> str:
        """Get current account ID."""
        try:
            return self.auth_manager.get_caller_identity().get("Account", "")
        except Exception:
            return ""

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
            rule_id=f"org_enum_{resource_type}",
        )
        self._add_finding_deduped(findings, finding)

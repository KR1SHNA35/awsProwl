"""SNS scanner for awsProwl."""

from __future__ import annotations

import asyncio
import hashlib
import json

import botocore.exceptions

from awsprowl.aws.base import AWSServiceBase, ScanResult
from awsprowl.core.auth import AWSAuthManager
from awsprowl.core.logging import get_logger

log = get_logger(__name__)


class SNSScanner(AWSServiceBase):
    """Scanner for SNS resources."""

    SERVICE_NAME = "sns"
    REQUIRED_PERMISSIONS = [
        "sns:ListTopics",
        "sns:GetTopicAttributes",
        "sns:ListSubscriptions",
        "sns:ListSubscriptionsByTopic",
        "sns:GetSubscriptionAttributes",
    ]

    def __init__(self, auth_manager: AWSAuthManager, region: str | None = None):
        super().__init__(auth_manager, region)

    async def scan(self, scan_id: str, findings: list) -> ScanResult:
        """Scan SNS resources for security issues."""
        result = ScanResult(service=self.SERVICE_NAME, region=self.region)

        try:
            await asyncio.gather(
                self._scan_topics(scan_id, findings, result),
                self._scan_subscriptions(scan_id, findings, result),
                return_exceptions=True,
            )

        except Exception as e:
            log.error("Error in SNS scan: {}", e)
            result.errors.append(str(e))

        return result

    async def _scan_topics(self, scan_id: str, findings: list, result: ScanResult) -> None:
        """Scan SNS topics."""
        try:
            paginator = self.client.get_paginator("list_topics")
            for page in paginator.paginate():
                for topic in page.get("Topics", []):
                    result.resources_found += 1
                    await self._analyze_topic(topic["TopicArn"], scan_id, findings)

        except botocore.exceptions.ClientError as e:
            self.handle_client_error(e, "ListTopics", findings)

    async def _analyze_topic(self, topic_arn: str, scan_id: str, findings: list) -> None:
        """Analyze a single SNS topic for security issues."""
        topic_name = topic_arn.split(":")[-1]

        try:
            attrs = self.client.get_topic_attributes(TopicArn=topic_arn)
            attributes = attrs.get("Attributes", {})

            # Add enumeration finding
            await self._add_enumeration_finding("sns_topic", topic_name, topic_name, {
                "arn": topic_arn,
                "display_name": attributes.get("DisplayName", ""),
                "subscriptions_confirmed": attributes.get("SubscriptionsConfirmed", "0"),
                "subscriptions_pending": attributes.get("SubscriptionsPending", "0"),
                "subscriptions_deleted": attributes.get("SubscriptionsDeleted", "0"),
                "policy_present": bool(attributes.get("Policy", "")),
                "delivery_policy_present": bool(attributes.get("DeliveryPolicy", "")),
                "kms_master_key_id": attributes.get("KmsMasterKeyId", ""),
            }, findings, scan_id)

            # Check access policy
            policy = attributes.get("Policy", "")
            if policy:
                await self._check_topic_policy(topic_arn, topic_name, policy, scan_id, findings)
            else:
                self._add_finding_deduped(findings, self.create_finding(
                    title=f"SNS topic {topic_name} has no access policy",
                    description="Topic has no access policy, defaulting to topic owner only (may be intentional)",
                    severity="info",
                    category="weak_configuration",
                    resource_type="sns_topic",
                    resource_id=topic_name,
                    resource_name=topic_name,
                    region=self.region,
                    rule_id="sns_topic_no_policy",
                ))

            # Check for display name (helps identify topic purpose)
            display_name = attributes.get("DisplayName", "")
            if not display_name:
                self._add_finding_deduped(findings, self.create_finding(
                    title=f"SNS topic {topic_name} has no display name",
                    description="Topic lacks a display name, making it harder to identify purpose",
                    severity="info",
                    category="best_practice",
                    resource_type="sns_topic",
                    resource_id=topic_name,
                    resource_name=topic_name,
                    region=self.region,
                    rule_id="sns_topic_no_display_name",
                ))

            # Check for delivery policy (retry logic)
            delivery_policy = attributes.get("DeliveryPolicy", "")
            if not delivery_policy:
                self._add_finding_deduped(findings, self.create_finding(
                    title=f"SNS topic {topic_name} has no delivery policy",
                    description="Topic has no delivery policy, using default retry behavior",
                    severity="low",
                    category="weak_configuration",
                    resource_type="sns_topic",
                    resource_id=topic_name,
                    resource_name=topic_name,
                    region=self.region,
                    rule_id="sns_topic_no_delivery_policy",
                ))

            # Check for encryption
            kms_key = attributes.get("KmsMasterKeyId", "")
            if not kms_key:
                self._add_finding_deduped(findings, self.create_finding(
                    title=f"SNS topic {topic_name} is not encrypted",
                    description="Topic messages are not encrypted at rest",
                    severity="medium",
                    category="encryption_missing",
                    resource_type="sns_topic",
                    resource_id=topic_name,
                    resource_name=topic_name,
                    region=self.region,
                    remediation={
                        "summary": "Enable server-side encryption",
                        "steps": [
                            "Create or use existing KMS key",
                            "Update topic with KMS key ID",
                        ],
                        "effort": "low",
                        "automatable": True,
                        "cli_commands": [
                            f"aws sns set-topic-attributes --topic-arn {topic_arn} --attribute-name KmsMasterKeyId --attribute-value <kms-key-id>",
                        ],
                    },
                    rule_id="sns_topic_unencrypted",
                ))

        except botocore.exceptions.ClientError as e:
            self.handle_client_error(e, "GetTopicAttributes", findings)

    async def _check_topic_policy(self, topic_arn: str, topic_name: str, policy: str, scan_id: str, findings: list) -> None:
        """Check SNS topic policy for security issues."""
        try:
            policy_doc = json.loads(policy)
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
                        title=f"SNS topic {topic_name} has public access policy",
                        description="Topic policy allows any principal to publish/subscribe",
                        severity="critical",
                        category="data_exposure",
                        resource_type="sns_topic",
                        resource_id=topic_name,
                        resource_name=topic_name,
                        region=self.region,
                        evidence=[{"type": "topic_policy", "description": "Public topic policy", "data": policy_doc}],
                        remediation={
                            "summary": "Restrict topic policy to specific principals",
                            "steps": [
                                "Identify required publishers/subscribers",
                                "Update policy with specific ARNs",
                                "Add conditions (aws:SourceArn, etc.)",
                            ],
                            "effort": "medium",
                            "automatable": False,
                        },
                        rule_id="sns_topic_public_policy",
                    ))

                # Check for cross-account access
                if principal.get("AWS"):
                    aws_principals = principal["AWS"]
                    if isinstance(aws_principals, str):
                        aws_principals = [aws_principals]

                    for p in aws_principals:
                        if p.startswith("arn:aws:iam::") and ":root" in p:
                            condition = stmt.get("Condition", {})
                            if not condition:
                                self._add_finding_deduped(findings, self.create_finding(
                                    title=f"SNS topic {topic_name} allows cross-account root access without conditions",
                                    description=f"Topic policy allows {p} to access without source restrictions",
                                    severity="high",
                                    category="cross_account_access",
                                    resource_type="sns_topic",
                                    resource_id=topic_name,
                                    resource_name=topic_name,
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
                                    rule_id="sns_topic_cross_account_no_condition",
                                ))

        except json.JSONDecodeError:
            pass

    async def _scan_subscriptions(self, scan_id: str, findings: list, result: ScanResult) -> None:
        """Scan SNS subscriptions."""
        try:
            paginator = self.client.get_paginator("list_subscriptions")
            for page in paginator.paginate():
                for sub in page.get("Subscriptions", []):
                    result.resources_found += 1
                    await self._analyze_subscription(sub, scan_id, findings)

        except botocore.exceptions.ClientError as e:
            self.handle_client_error(e, "ListSubscriptions", findings)

    async def _analyze_subscription(self, subscription: dict, scan_id: str, findings: list) -> None:
        """Analyze a single SNS subscription."""
        sub_arn = subscription.get("SubscriptionArn", "")
        topic_arn = subscription.get("TopicArn", "")
        protocol = subscription.get("Protocol", "")
        endpoint = subscription.get("Endpoint", "")
        topic_name = topic_arn.split(":")[-1] if topic_arn else "unknown"

        # Add enumeration finding
        await self._add_enumeration_finding("sns_subscription", sub_arn, f"{protocol}:{endpoint}", {
            "topic_arn": topic_arn,
            "topic_name": topic_name,
            "protocol": protocol,
            "endpoint": endpoint,
            "confirmed": sub_arn != "PendingConfirmation",
        }, findings, scan_id)

        if sub_arn == "PendingConfirmation":
            self._add_finding_deduped(findings, self.create_finding(
                title=f"SNS subscription to {topic_arn.split(':')[-1]} is pending confirmation",
                description=f"Subscription {sub_arn} for protocol {protocol} to {endpoint} is not confirmed",
                severity="low",
                category="weak_configuration",
                resource_type="sns_subscription",
                resource_id=sub_arn,
                resource_name=f"{protocol}:{endpoint}",
                region=self.region,
                evidence=[{"type": "subscription", "description": "Pending subscription", "data": subscription}],
                remediation={
                    "summary": "Confirm or delete pending subscription",
                    "steps": [
                        "Check endpoint for confirmation message",
                        "Confirm subscription or delete if not needed",
                    ],
                    "effort": "low",
                    "automatable": False,
                },
                rule_id="sns_subscription_pending",
            ))

        # Check for HTTP/HTTPS endpoints without authentication
        if protocol in ("http", "https"):
            self._add_finding_deduped(findings, self.create_finding(
                title=f"SNS subscription uses {protocol.upper()} endpoint: {endpoint}",
                description="HTTP/S endpoint subscriptions should implement message authentication",
                severity="medium",
                category="weak_configuration",
                resource_type="sns_subscription",
                resource_id=sub_arn,
                resource_name=f"{protocol}:{endpoint}",
                region=self.region,
                remediation={
                    "summary": "Implement message validation",
                    "steps": [
                        "Verify SignatureVersion in message",
                        "Validate SigningCertURL certificate",
                        "Verify signature matches message",
                    ],
                    "effort": "medium",
                    "automatable": False,
                },
                rule_id="sns_subscription_http_endpoint",
            ))

        # Check for email subscriptions (potential information disclosure)
        if protocol == "email":
            self._add_finding_deduped(findings, self.create_finding(
                title=f"SNS subscription sends to email: {endpoint}",
                description="Email subscriptions may expose sensitive data in notifications",
                severity="low",
                category="data_exposure",
                resource_type="sns_subscription",
                resource_id=sub_arn,
                resource_name=f"email:{endpoint}",
                region=self.region,
                rule_id="sns_subscription_email",
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
            rule_id=f"sns_enum_{resource_type}",
        )
        self._add_finding_deduped(findings, finding)

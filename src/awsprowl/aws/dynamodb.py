"""DynamoDB scanner for awsProwl."""

from __future__ import annotations

import asyncio
import hashlib

import botocore.exceptions

from awsprowl.aws.base import AWSServiceBase, ScanResult
from awsprowl.core.auth import AWSAuthManager
from awsprowl.core.logging import get_logger

log = get_logger(__name__)


class DynamoDBScanner(AWSServiceBase):
    """Scanner for DynamoDB resources."""

    SERVICE_NAME = "dynamodb"
    REQUIRED_PERMISSIONS = [
        "dynamodb:ListTables",
        "dynamodb:DescribeTable",
        "dynamodb:DescribeContinuousBackups",
        "dynamodb:DescribeContributorInsights",
        "dynamodb:ListTagsOfResource",
        "dynamodb:ListGlobalTables",
        "dynamodb:DescribeGlobalTable",
        "dynamodb:DescribeLimits",
        "dynamodb:ListBackups",
    ]

    def __init__(self, auth_manager: AWSAuthManager, region: str | None = None):
        super().__init__(auth_manager, region)

    async def scan(self, scan_id: str, findings: list) -> ScanResult:
        """Scan DynamoDB resources for security issues."""
        result = ScanResult(service=self.SERVICE_NAME, region=self.region)

        try:
            await asyncio.gather(
                self._scan_tables(scan_id, findings, result),
                self._scan_global_tables(scan_id, findings, result),
                self._check_public_access_scan(scan_id, findings, result),
                return_exceptions=True,
            )

        except Exception as e:
            log.error("Error in DynamoDB scan: {}", e)
            result.errors.append(str(e))

        return result

    async def _scan_tables(self, scan_id: str, findings: list, result: ScanResult) -> None:
        """Scan DynamoDB tables."""
        try:
            paginator = self.client.get_paginator("list_tables")
            for page in paginator.paginate():
                for table_name in page.get("TableNames", []):
                    result.resources_found += 1
                    await self._analyze_table(table_name, scan_id, findings)

        except botocore.exceptions.ClientError as e:
            self.handle_client_error(e, "ListTables", findings)

    async def _analyze_table(self, table_name: str, scan_id: str, findings: list) -> None:
        """Analyze a single DynamoDB table."""
        try:
            response = self.client.describe_table(TableName=table_name)
            table = response.get("Table", {})

            # Add enumeration finding
            await self._add_enumeration_finding("dynamodb_table", table_name, table_name, {
                "arn": table.get("TableArn", ""),
                "status": table.get("TableStatus", ""),
                "creation_date": table.get("CreationDateTime", "").isoformat() if table.get("CreationDateTime") else "",
                "item_count": table.get("ItemCount", 0),
                "size_bytes": table.get("TableSizeBytes", 0),
                "billing_mode": table.get("BillingModeSummary", {}).get("BillingMode", "PROVISIONED"),
                "encryption": table.get("SSEDescription", {}).get("Status", "DISABLED"),
                "pitr": table.get("PointInTimeRecoveryDescription", {}).get("PointInTimeRecoveryStatus", "DISABLED"),
                "ttl": table.get("TimeToLiveDescription", {}).get("TimeToLiveStatus", "DISABLED"),
                "contributor_insights": table.get("ContributorInsights", {}).get("ContributorInsightsStatus", "DISABLED"),
            }, findings, scan_id)

            sse = table.get("SSEDescription", {})
            encrypted = sse.get("Status") == "ENABLED"
            sse_type = sse.get("SSEType", "NONE")

            pitr = table.get("PointInTimeRecoveryDescription", {})
            pitr_enabled = pitr.get("PointInTimeRecoveryStatus") == "ENABLED"

            contributor_insights = table.get("ContributorInsights", {}).get("ContributorInsightsStatus", "DISABLED")
            ttl = table.get("TimeToLiveDescription", {}).get("TimeToLiveStatus", "DISABLED")

            billing_mode = table.get("BillingModeSummary", {}).get("BillingMode", "PROVISIONED")
            read_capacity = table.get("ProvisionedThroughput", {}).get("ReadCapacityUnits", 0)
            write_capacity = table.get("ProvisionedThroughput", {}).get("WriteCapacityUnits", 0)

            # Encryption at rest
            if not encrypted:
                self._add_finding_deduped(findings, self.create_finding(
                    title=f"DynamoDB table {table_name} is not encrypted",
                    description="Table does not have server-side encryption enabled",
                    severity="high",
                    category="encryption_missing",
                    resource_type="dynamodb_table",
                    resource_id=table_name,
                    resource_name=table_name,
                    region=self.region,
                    remediation={
                        "summary": "Enable encryption at rest",
                        "steps": [
                            "Enable SSE with AWS owned key or customer managed KMS key",
                            "Note: Encryption can only be enabled at table creation",
                            "Create new encrypted table and migrate data if needed",
                        ],
                        "effort": "high",
                        "automatable": False,
                    },
                    rule_id="dynamodb_unencrypted",
                ))
            elif sse_type == "KMS":
                # Check if using customer managed key
                kms_key = sse.get("KMSMasterKeyArn", "")
                if not kms_key or ":key/" not in kms_key:
                    self._add_finding_deduped(findings, self.create_finding(
                        title=f"DynamoDB table {table_name} uses AWS owned key for encryption",
                        description="Consider using a customer managed KMS key for more control",
                        severity="low",
                        category="weak_configuration",
                        resource_type="dynamodb_table",
                        resource_id=table_name,
                        resource_name=table_name,
                        region=self.region,
                        remediation={
                            "summary": "Use customer managed KMS key",
                            "steps": [
                                "Create customer managed KMS key",
                                "Create new table with custom KMS key",
                                "Migrate data to new table",
                            ],
                            "effort": "medium",
                            "automatable": False,
                        },
                        rule_id="dynamodb_aws_owned_key",
                    ))

            # Point-in-time recovery
            if not pitr_enabled:
                self._add_finding_deduped(findings, self.create_finding(
                    title=f"DynamoDB table {table_name} has PITR disabled",
                    description="Point-in-time recovery provides continuous backups for 35 days",
                    severity="medium",
                    category="data_loss_risk",
                    resource_type="dynamodb_table",
                    resource_id=table_name,
                    resource_name=table_name,
                    region=self.region,
                    remediation={
                        "summary": "Enable point-in-time recovery",
                        "steps": [
                            "Enable PITR on the table",
                        ],
                        "effort": "low",
                        "automatable": True,
                        "cli_commands": [
                            f"aws dynamodb update-continuous-backups --table-name {table_name} --point-in-time-recovery-specification PointInTimeRecoveryEnabled=true",
                        ],
                    },
                    rule_id="dynamodb_pitr_disabled",
                ))

            # Contributor Insights
            if contributor_insights == "DISABLED":
                self._add_finding_deduped(findings, self.create_finding(
                    title=f"DynamoDB table {table_name} has Contributor Insights disabled",
                    description="Contributor Insights helps identify frequently accessed items and hot partitions",
                    severity="low",
                    category="weak_configuration",
                    resource_type="dynamodb_table",
                    resource_id=table_name,
                    resource_name=table_name,
                    region=self.region,
                    remediation={
                        "summary": "Enable Contributor Insights",
                        "steps": [
                            "Enable Contributor Insights on the table",
                        ],
                        "effort": "low",
                        "automatable": True,
                        "cli_commands": [
                            f"aws dynamodb update-contributor-insights --table-name {table_name} --contributor-insights-action ENABLE",
                        ],
                    },
                    rule_id="dynamodb_contributor_insights_disabled",
                ))

            # TTL
            if ttl == "DISABLED":
                self._add_finding_deduped(findings, self.create_finding(
                    title=f"DynamoDB table {table_name} has TTL disabled",
                    description="Time to Live automatically deletes expired items to reduce storage costs",
                    severity="low",
                    category="cost_optimization",
                    resource_type="dynamodb_table",
                    resource_id=table_name,
                    resource_name=table_name,
                    region=self.region,
                    remediation={
                        "summary": "Enable TTL with appropriate attribute",
                        "steps": [
                            "Add TTL attribute to items",
                            "Enable TTL on the table specifying the attribute name",
                        ],
                        "effort": "low",
                        "automatable": False,
                    },
                    rule_id="dynamodb_ttl_disabled",
                ))

            # Auto scaling for provisioned tables
            if billing_mode == "PROVISIONED":
                # Check if auto scaling is configured (would need application-autoscaling API)
                self._add_finding_deduped(findings, self.create_finding(
                    title=f"DynamoDB table {table_name} uses provisioned capacity",
                    description="Consider enabling auto scaling or switching to on-demand mode for variable workloads",
                    severity="info",
                    category="cost_optimization",
                    resource_type="dynamodb_table",
                    resource_id=table_name,
                    resource_name=table_name,
                    region=self.region,
                    evidence=[{"type": "table_config", "description": "Provisioned capacity", "data": {"read_capacity": read_capacity, "write_capacity": write_capacity}}],
                    rule_id="dynamodb_provisioned_capacity",
                ))

        except botocore.exceptions.ClientError as e:
            self.handle_client_error(e, "DescribeTable", findings)

    async def _scan_global_tables(self, scan_id: str, findings: list, result: ScanResult) -> None:
        """Scan Global Tables."""
        try:
            paginator = self.client.get_paginator("list_global_tables")
            for page in paginator.paginate():
                for gt in page.get("GlobalTables", []):
                    result.resources_found += 1
                    table_name = gt.get("GlobalTableName", "")
                    replication_group = gt.get("ReplicationGroup", [])

                    # Add enumeration finding
                    await self._add_enumeration_finding("dynamodb_global_table", table_name, table_name, {
                        "replication_group": [
                            {"region": r.get("RegionName", ""), "status": r.get("ReplicaStatus", "")}
                            for r in replication_group
                        ],
                        "replica_count": len(replication_group),
                    }, findings, scan_id)

                    if len(replication_group) < 2:
                        self._add_finding_deduped(findings, self.create_finding(
                            title=f"Global Table {table_name} has only {len(replication_group)} replica region(s)",
                            description="Global Tables should replicate to multiple regions for disaster recovery",
                            severity="medium",
                            category="data_loss_risk",
                            resource_type="dynamodb_global_table",
                            resource_id=table_name,
                            resource_name=table_name,
                            region=self.region,
                            remediation={
                                "summary": "Add replica regions",
                                "steps": [
                                    "Add additional replica regions to global table",
                                    "Ensure replicas are in different geographic regions",
                                ],
                                "effort": "medium",
                                "automatable": True,
                            },
                            rule_id="dynamodb_global_table_single_region",
                        ))

        except botocore.exceptions.ClientError as e:
            self.handle_client_error(e, "ListGlobalTables", findings)

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
            rule_id=f"dynamodb_enum_{resource_type}",
        )
        self._add_finding_deduped(findings, finding)

    async def _check_table_public_access(self, table_name: str, scan_id: str, findings: list) -> None:
        """Check if a DynamoDB table has public access (via resource policy or overly permissive IAM)."""
        try:
            # Check if table has a resource policy (DynamoDB doesn't support resource policies directly,
            # but we can check for overly permissive access patterns)

            # Get table details including tags for context
            table_desc = self.client.describe_table(TableName=table_name)
            table = table_desc.get("Table", {})
            table_arn = table.get("TableArn", "")

            if not table_arn:
                return

            # Check for public access via VPC endpoint policies (if any)
            # This is informational since DynamoDB doesn't have direct resource policies

            # Check for table tags that might indicate public access
            tags = {}
            try:
                tags_response = self.client.list_tags_of_resource(ResourceArn=table_arn)
                tags = {tag["Key"]: tag["Value"] for tag in tags_response.get("Tags", [])}
            except botocore.exceptions.ClientError:
                pass

            # Check for tags indicating public access
            public_indicators = ["public", "public-access", "open", "internet-facing"]
            for tag_key, tag_value in tags.items():
                if any(indicator in tag_key.lower() or indicator in tag_value.lower() for indicator in public_indicators):
                    self._add_finding_deduped(findings, self.create_finding(
                        title=f"DynamoDB table {table_name} tagged as potentially public",
                        description=f"Table has tag '{tag_key}={tag_value}' which may indicate public access",
                        severity="medium",
                        category="network_exposure",
                        resource_type="dynamodb_table",
                        resource_id=table_name,
                        resource_name=table_name,
                        region=self.region,
                        evidence=[{"type": "tag", "description": "Public indicator tag", "data": {"tag_key": tag_key, "tag_value": tag_value}}],
                        remediation={
                            "summary": "Review table access controls",
                            "steps": [
                                "Verify if table should be publicly accessible",
                                "If not, ensure IAM policies restrict access",
                                "Remove misleading tags if not actually public",
                            ],
                            "effort": "low",
                            "automatable": False,
                        },
                        rule_id="dynamodb_tag_public_indicator",
                    ))

            # Check for overly permissive IAM access (this would be found by IAM scanner)
            # But we can note if the table has no encryption which makes public access more dangerous
            sse = table.get("SSEDescription", {})
            encrypted = sse.get("Status") == "ENABLED"

            if not encrypted:
                self._add_finding_deduped(findings, self.create_finding(
                    title=f"DynamoDB table {table_name} is unencrypted - higher risk if exposed",
                    description="Unencrypted table data could be exposed if access controls are misconfigured",
                    severity="medium",
                    category="encryption_missing",
                    resource_type="dynamodb_table",
                    resource_id=table_name,
                    resource_name=table_name,
                    region=self.region,
                    evidence=[{"type": "table_config", "description": "No encryption", "data": {"sse_status": sse.get("Status", "DISABLED")}}],
                    remediation={
                        "summary": "Enable encryption at rest",
                        "steps": [
                            "Enable SSE with customer managed KMS key",
                            "Recreate table with encryption if needed",
                        ],
                        "effort": "high",
                        "automatable": False,
                    },
                    rule_id="dynamodb_unencrypted_public_risk",
                ))

        except botocore.exceptions.ClientError as e:
            self.handle_client_error(e, "DescribeTable/ListTagsOfResource", findings)

    async def _check_public_access_scan(self, scan_id: str, findings: list, result: ScanResult) -> None:
        """Scan all tables for public access indicators."""
        try:
            paginator = self.client.get_paginator("list_tables")
            for page in paginator.paginate():
                for table_name in page.get("TableNames", []):
                    await self._check_table_public_access(table_name, scan_id, findings)
        except botocore.exceptions.ClientError as e:
            self.handle_client_error(e, "ListTables", findings)

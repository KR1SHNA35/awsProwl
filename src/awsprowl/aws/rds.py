"""RDS scanner for awsProwl."""

from __future__ import annotations

import asyncio
import hashlib

import botocore.exceptions

from awsprowl.aws.base import AWSServiceBase, ScanResult
from awsprowl.core.auth import AWSAuthManager
from awsprowl.core.logging import get_logger

log = get_logger(__name__)


class RDSScanner(AWSServiceBase):
    """Scanner for RDS resources."""

    SERVICE_NAME = "rds"
    REQUIRED_PERMISSIONS = [
        "rds:DescribeDBInstances",
        "rds:DescribeDBClusters",
        "rds:DescribeDBSnapshots",
        "rds:DescribeDBSubnetGroups",
        "rds:DescribeDBSecurityGroups",
        "rds:ListTagsForResource",
    ]

    def __init__(self, auth_manager: AWSAuthManager, region: str | None = None):
        super().__init__(auth_manager, region)

    async def scan(self, scan_id: str, findings: list) -> ScanResult:
        """Scan RDS resources for security issues."""
        result = ScanResult(service=self.SERVICE_NAME, region=self.region)

        try:
            await asyncio.gather(
                self._scan_instances(scan_id, findings, result),
                self._scan_clusters(scan_id, findings, result),
                self._scan_snapshots(scan_id, findings, result),
                self._scan_subnet_groups(scan_id, findings, result),
                return_exceptions=True,
            )

        except Exception as e:
            log.error("Error in RDS scan: {}", e)
            result.errors.append(str(e))

        return result

    async def _scan_instances(self, scan_id: str, findings: list, result: ScanResult) -> None:
        """Scan RDS instances."""
        try:
            paginator = self.client.get_paginator("describe_db_instances")
            for page in paginator.paginate():
                for instance in page.get("DBInstances", []):
                    result.resources_found += 1
                    await self._analyze_instance(instance, scan_id, findings)

        except botocore.exceptions.ClientError as e:
            self.handle_client_error(e, "DescribeDBInstances", findings)

    async def _analyze_instance(self, instance: dict, scan_id: str, findings: list) -> None:
        """Analyze a single RDS instance."""
        instance_id = instance["DBInstanceIdentifier"]
        engine = instance.get("Engine", "")
        public = instance.get("PubliclyAccessible", False)
        encrypted = instance.get("StorageEncrypted", False)
        iam_auth = instance.get("IAMDatabaseAuthenticationEnabled", False)
        deletion_protection = instance.get("DeletionProtection", False)
        backup_retention = instance.get("BackupRetentionPeriod", 0)
        enhanced_monitoring = instance.get("EnhancedMonitoringResourceArn", "")
        performance_insights = instance.get("PerformanceInsightsEnabled", False)
        minor_version_upgrade = instance.get("AutoMinorVersionUpgrade", False)

        # Add enumeration finding
        await self._add_enumeration_finding("rds_instance", instance_id, instance_id, {
            "engine": engine,
            "publicly_accessible": public,
            "encrypted": encrypted,
            "iam_auth": iam_auth,
            "deletion_protection": deletion_protection,
            "backup_retention": backup_retention,
            "enhanced_monitoring": bool(enhanced_monitoring),
            "performance_insights": performance_insights,
            "auto_minor_version_upgrade": minor_version_upgrade,
        }, findings, scan_id)

        # Public accessibility
        if public:
            self._add_finding_deduped(findings, self.create_finding(
                title=f"RDS instance {instance_id} is publicly accessible",
                description=f"RDS instance {instance_id} can be accessed from the internet",
                severity="critical",
                category="network_exposure",
                resource_type="rds_instance",
                resource_id=instance_id,
                resource_name=instance_id,
                region=self.region,
                evidence=[{"type": "instance_attribute", "description": "Publicly accessible", "data": {"publicly_accessible": True}}],
                remediation={
                    "summary": "Disable public access",
                    "steps": [
                        "Modify instance to disable public accessibility",
                        "Ensure VPC security groups restrict access",
                        "Use bastion host or VPN for admin access",
                    ],
                    "effort": "low",
                    "automatable": True,
                    "cli_commands": [
                        f"aws rds modify-db-instance --db-instance-identifier {instance_id} --no-publicly-accessible --apply-immediately",
                    ],
                },
                rule_id="rds_public_access",
            ))

        # Encryption at rest
        if not encrypted:
            self._add_finding_deduped(findings, self.create_finding(
                title=f"RDS instance {instance_id} is not encrypted",
                description="RDS instance storage is not encrypted at rest",
                severity="high",
                category="encryption_missing",
                resource_type="rds_instance",
                resource_id=instance_id,
                resource_name=instance_id,
                region=self.region,
                remediation={
                    "summary": "Enable encryption",
                    "steps": [
                        "Create snapshot of instance",
                        "Copy snapshot with encryption enabled",
                        "Restore instance from encrypted snapshot",
                        "Update applications to use new endpoint",
                    ],
                    "effort": "medium",
                    "automatable": True,
                },
                rule_id="rds_unencrypted",
            ))

        # IAM authentication
        if not iam_auth:
            self._add_finding_deduped(findings, self.create_finding(
                title=f"RDS instance {instance_id} has IAM authentication disabled",
                description="IAM database authentication provides centralized credential management",
                severity="medium",
                category="weak_configuration",
                resource_type="rds_instance",
                resource_id=instance_id,
                resource_name=instance_id,
                region=self.region,
                remediation={
                    "summary": "Enable IAM authentication",
                    "steps": [
                        "Modify instance to enable IAM authentication",
                        "Create IAM policies for database users",
                        "Update applications to use IAM auth tokens",
                    ],
                    "effort": "medium",
                    "automatable": True,
                    "cli_commands": [
                        f"aws rds modify-db-instance --db-instance-identifier {instance_id} --enable-iam-database-authentication --apply-immediately",
                    ],
                },
                rule_id="rds_iam_auth_disabled",
            ))

        # Deletion protection
        if not deletion_protection:
            self._add_finding_deduped(findings, self.create_finding(
                title=f"RDS instance {instance_id} has deletion protection disabled",
                description="Deletion protection prevents accidental instance deletion",
                severity="medium",
                category="data_loss_risk",
                resource_type="rds_instance",
                resource_id=instance_id,
                resource_name=instance_id,
                region=self.region,
                remediation={
                    "summary": "Enable deletion protection",
                    "steps": [
                        "Modify instance to enable deletion protection",
                    ],
                    "effort": "low",
                    "automatable": True,
                    "cli_commands": [
                        f"aws rds modify-db-instance --db-instance-identifier {instance_id} --deletion-protection --apply-immediately",
                    ],
                },
                rule_id="rds_deletion_protection_disabled",
            ))

        # Backup retention
        if backup_retention < 7:
            self._add_finding_deduped(findings, self.create_finding(
                title=f"RDS instance {instance_id} has short backup retention: {backup_retention} days",
                description="Backup retention should be at least 7 days for recovery",
                severity="medium" if backup_retention == 0 else "low",
                category="data_loss_risk",
                resource_type="rds_instance",
                resource_id=instance_id,
                resource_name=instance_id,
                region=self.region,
                remediation={
                    "summary": "Increase backup retention period",
                    "steps": [
                        "Modify instance to set backup retention to at least 7 days",
                    ],
                    "effort": "low",
                    "automatable": True,
                    "cli_commands": [
                        f"aws rds modify-db-instance --db-instance-identifier {instance_id} --backup-retention-period 7 --apply-immediately",
                    ],
                },
                rule_id="rds_short_backup_retention",
            ))

        # Enhanced monitoring
        if not enhanced_monitoring:
            self._add_finding_deduped(findings, self.create_finding(
                title=f"RDS instance {instance_id} has enhanced monitoring disabled",
                description="Enhanced monitoring provides OS-level metrics for performance analysis",
                severity="low",
                category="logging_missing",
                resource_type="rds_instance",
                resource_id=instance_id,
                resource_name=instance_id,
                region=self.region,
                remediation={
                    "summary": "Enable enhanced monitoring",
                    "steps": [
                        "Create IAM role for enhanced monitoring",
                        "Modify instance to enable enhanced monitoring",
                    ],
                    "effort": "low",
                    "automatable": True,
                },
                rule_id="rds_enhanced_monitoring_disabled",
            ))

        # Performance Insights
        if not performance_insights:
            self._add_finding_deduped(findings, self.create_finding(
                title=f"RDS instance {instance_id} has Performance Insights disabled",
                description="Performance Insights helps identify database performance bottlenecks",
                severity="low",
                category="weak_configuration",
                resource_type="rds_instance",
                resource_id=instance_id,
                resource_name=instance_id,
                region=self.region,
                remediation={
                    "summary": "Enable Performance Insights",
                    "steps": [
                        "Modify instance to enable Performance Insights",
                        "Optionally specify KMS key for encryption",
                    ],
                    "effort": "low",
                    "automatable": True,
                    "cli_commands": [
                        f"aws rds modify-db-instance --db-instance-identifier {instance_id} --enable-performance-insights --apply-immediately",
                    ],
                },
                rule_id="rds_performance_insights_disabled",
            ))

        # Auto minor version upgrade
        if not minor_version_upgrade:
            self._add_finding_deduped(findings, self.create_finding(
                title=f"RDS instance {instance_id} has auto minor version upgrade disabled",
                description="Automatic minor version upgrades keep the database patched",
                severity="low",
                category="weak_configuration",
                resource_type="rds_instance",
                resource_id=instance_id,
                resource_name=instance_id,
                region=self.region,
                remediation={
                    "summary": "Enable auto minor version upgrade",
                    "steps": [
                        "Modify instance to enable auto minor version upgrade",
                    ],
                    "effort": "low",
                    "automatable": True,
                    "cli_commands": [
                        f"aws rds modify-db-instance --db-instance-identifier {instance_id} --auto-minor-version-upgrade --apply-immediately",
                    ],
                },
                rule_id="rds_auto_minor_upgrade_disabled",
            ))

    async def _scan_clusters(self, scan_id: str, findings: list, result: ScanResult) -> None:
        """Scan Aurora clusters."""
        try:
            paginator = self.client.get_paginator("describe_db_clusters")
            for page in paginator.paginate():
                for cluster in page.get("DBClusters", []):
                    result.resources_found += 1
                    await self._analyze_cluster(cluster, scan_id, findings)

        except botocore.exceptions.ClientError as e:
            self.handle_client_error(e, "DescribeDBClusters", findings)

    async def _analyze_cluster(self, cluster: dict, scan_id: str, findings: list) -> None:
        """Analyze an Aurora cluster."""
        cluster_id = cluster["DBClusterIdentifier"]
        engine = cluster.get("Engine", "")
        encrypted = cluster.get("StorageEncrypted", False)
        iam_auth = cluster.get("IAMDatabaseAuthenticationEnabled", False)
        deletion_protection = cluster.get("DeletionProtection", False)
        backup_retention = cluster.get("BackupRetentionPeriod", 0)
        global_cluster = cluster.get("GlobalClusterIdentifier", "")
        serverless_v2 = cluster.get("ServerlessV2ScalingConfiguration", {})

        # Add enumeration finding
        await self._add_enumeration_finding("rds_cluster", cluster_id, cluster_id, {
            "engine": engine,
            "encrypted": encrypted,
            "iam_auth": iam_auth,
            "deletion_protection": deletion_protection,
            "backup_retention": backup_retention,
            "global_cluster": global_cluster,
            "serverless_v2": bool(serverless_v2),
        }, findings, scan_id)

        # Encryption
        if not encrypted:
            self._add_finding_deduped(findings, self.create_finding(
                title=f"Aurora cluster {cluster_id} is not encrypted",
                description="Cluster storage is not encrypted at rest",
                severity="high",
                category="encryption_missing",
                resource_type="rds_cluster",
                resource_id=cluster_id,
                resource_name=cluster_id,
                region=self.region,
                remediation={
                    "summary": "Enable encryption",
                    "steps": [
                        "Create snapshot of cluster",
                        "Copy snapshot with encryption",
                        "Restore cluster from encrypted snapshot",
                    ],
                    "effort": "medium",
                    "automatable": True,
                },
                rule_id="rds_cluster_unencrypted",
            ))

        # IAM auth
        if not iam_auth:
            self._add_finding_deduped(findings, self.create_finding(
                title=f"Aurora cluster {cluster_id} has IAM authentication disabled",
                severity="medium",
                category="weak_configuration",
                resource_type="rds_cluster",
                resource_id=cluster_id,
                resource_name=cluster_id,
                region=self.region,
                rule_id="rds_cluster_iam_auth_disabled",
            ))

        # Deletion protection
        if not deletion_protection:
            self._add_finding_deduped(findings, self.create_finding(
                title=f"Aurora cluster {cluster_id} has deletion protection disabled",
                severity="medium",
                category="data_loss_risk",
                resource_type="rds_cluster",
                resource_id=cluster_id,
                resource_name=cluster_id,
                region=self.region,
                rule_id="rds_cluster_deletion_protection_disabled",
            ))

        # Backup retention
        if backup_retention < 7:
            self._add_finding_deduped(findings, self.create_finding(
                title=f"Aurora cluster {cluster_id} has short backup retention: {backup_retention} days",
                severity="medium" if backup_retention == 0 else "low",
                category="data_loss_risk",
                resource_type="rds_cluster",
                resource_id=cluster_id,
                resource_name=cluster_id,
                region=self.region,
                rule_id="rds_cluster_short_backup_retention",
            ))

        # Global cluster check
        if global_cluster:
            self._add_finding_deduped(findings, self.create_finding(
                title=f"Aurora cluster {cluster_id} is part of global cluster {global_cluster}",
                description="Global cluster provides cross-region disaster recovery",
                severity="info",
                category="informational",
                resource_type="rds_cluster",
                resource_id=cluster_id,
                resource_name=cluster_id,
                region=self.region,
                rule_id="rds_global_cluster",
            ))

        # Serverless v2
        if serverless_v2:
            min_cap = serverless_v2.get("MinCapacity", 0)
            max_cap = serverless_v2.get("MaxCapacity", 0)
            if min_cap == 0 and max_cap == 0:
                self._add_finding_deduped(findings, self.create_finding(
                    title=f"Aurora cluster {cluster_id} has Serverless v2 with no capacity limits",
                    description="Serverless v2 scaling configuration has no min/max capacity set",
                    severity="low",
                    category="weak_configuration",
                    resource_type="rds_cluster",
                    resource_id=cluster_id,
                    resource_name=cluster_id,
                    region=self.region,
                    rule_id="rds_serverless_v2_no_limits",
                ))

    async def _scan_snapshots(self, scan_id: str, findings: list, result: ScanResult) -> None:
        """Scan RDS snapshots."""
        try:
            paginator = self.client.get_paginator("describe_db_snapshots")
            for page in paginator.paginate(SnapshotType="manual"):
                for snapshot in page.get("DBSnapshots", []):
                    result.resources_found += 1
                    await self._analyze_snapshot(snapshot, scan_id, findings)

        except botocore.exceptions.ClientError as e:
            self.handle_client_error(e, "DescribeDBSnapshots", findings)

    async def _analyze_snapshot(self, snapshot: dict, scan_id: str, findings: list) -> None:
        """Analyze an RDS snapshot."""
        snapshot_id = snapshot["DBSnapshotIdentifier"]
        encrypted = snapshot.get("Encrypted", False)

        # Add enumeration finding
        await self._add_enumeration_finding("rds_snapshot", snapshot_id, snapshot_id, {
            "encrypted": encrypted,
            "snapshot_type": snapshot.get("SnapshotType", ""),
            "engine": snapshot.get("Engine", ""),
            "allocated_storage": snapshot.get("AllocatedStorage", 0),
        }, findings, scan_id)

        if not encrypted:
            self._add_finding_deduped(findings, self.create_finding(
                title=f"RDS snapshot {snapshot_id} is not encrypted",
                description="Manual snapshot is not encrypted at rest",
                severity="high",
                category="encryption_missing",
                resource_type="rds_snapshot",
                resource_id=snapshot_id,
                resource_name=snapshot_id,
                region=self.region,
                remediation={
                    "summary": "Encrypt snapshot",
                    "steps": [
                        "Copy snapshot with encryption enabled",
                        "Delete unencrypted snapshot",
                    ],
                    "effort": "low",
                    "automatable": True,
                },
                rule_id="rds_snapshot_unencrypted",
            ))

        # Check for public snapshots
        try:
            attrs = self.client.describe_db_snapshot_attributes(DBSnapshotIdentifier=snapshot_id)
            for attr in attrs.get("DBSnapshotAttributesResult", {}).get("DBSnapshotAttributes", []):
                if attr.get("AttributeName") == "restore":
                    for value in attr.get("AttributeValues", []):
                        if value == "all":
                            self._add_finding_deduped(findings, self.create_finding(
                                title=f"RDS snapshot {snapshot_id} is public",
                                description="Snapshot is publicly accessible - anyone can restore it",
                                severity="critical",
                                category="data_exposure",
                                resource_type="rds_snapshot",
                                resource_id=snapshot_id,
                                resource_name=snapshot_id,
                                region=self.region,
                                remediation={
                                    "summary": "Make snapshot private",
                                    "steps": [
                                        "Remove 'all' from restore attribute",
                                        "Add specific account IDs if sharing needed",
                                    ],
                                    "effort": "low",
                                    "automatable": True,
                                    "cli_commands": [
                                        f"aws rds modify-db-snapshot-attribute --db-snapshot-identifier {snapshot_id} --attribute-name restore --values-to-remove all",
                                    ],
                                },
                                rule_id="rds_snapshot_public",
                            ))
        except botocore.exceptions.ClientError:
            pass

    async def _scan_subnet_groups(self, scan_id: str, findings: list, result: ScanResult) -> None:
        """Scan DB subnet groups."""
        try:
            paginator = self.client.get_paginator("describe_db_subnet_groups")
            for page in paginator.paginate():
                for sg in page.get("DBSubnetGroups", []):
                    result.resources_found += 1
                    sg_id = sg["DBSubnetGroupName"]
                    subnets = sg.get("Subnets", [])
                    public_subnets = sum(1 for s in subnets if s.get("SubnetAvailabilityZone", {}).get("Name", "").startswith("public"))
                    # This is a simplified check - in reality you'd check route tables
                    if len(subnets) == 1:
                        self._add_finding_deduped(findings, self.create_finding(
                            title=f"DB Subnet Group {sg_id} has only one subnet",
                            description="DB Subnet Group should have subnets in multiple AZs for high availability",
                            severity="medium",
                            category="weak_configuration",
                            resource_type="db_subnet_group",
                            resource_id=sg_id,
                            resource_name=sg_id,
                            region=self.region,
                            rule_id="rds_subnet_group_single_az",
                        ))

        except botocore.exceptions.ClientError as e:
            self.handle_client_error(e, "DescribeDBSubnetGroups", findings)

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
            rule_id=f"rds_enum_{resource_type}",
        )
        self._add_finding_deduped(findings, finding)

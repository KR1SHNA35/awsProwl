"""EKS scanner for awsProwl."""

from __future__ import annotations

import asyncio
import hashlib

import botocore.exceptions

from awsprowl.aws.base import AWSServiceBase, ScanResult
from awsprowl.core.auth import AWSAuthManager
from awsprowl.core.logging import get_logger

log = get_logger(__name__)


class EKSScanner(AWSServiceBase):
    """Scanner for EKS resources."""

    SERVICE_NAME = "eks"
    REQUIRED_PERMISSIONS = [
        "eks:ListClusters",
        "eks:DescribeCluster",
        "eks:ListNodegroups",
        "eks:DescribeNodegroup",
        "eks:ListFargateProfiles",
        "eks:DescribeFargateProfile",
        "eks:ListAddons",
        "eks:DescribeAddon",
        "eks:ListIdentityProviderConfigs",
        "eks:DescribeIdentityProviderConfig",
        "eks:ListTagsForResource",
    ]

    def __init__(self, auth_manager: AWSAuthManager, region: str | None = None):
        super().__init__(auth_manager, region)

    async def scan(self, scan_id: str, findings: list) -> ScanResult:
        """Scan EKS resources for security issues."""
        result = ScanResult(service=self.SERVICE_NAME, region=self.region)

        try:
            await asyncio.gather(
                self._scan_clusters(scan_id, findings, result),
                return_exceptions=True,
            )

        except Exception as e:
            log.error("Error in EKS scan: {}", e)
            result.errors.append(str(e))

        return result

    async def _scan_clusters(self, scan_id: str, findings: list, result: ScanResult) -> None:
        """Scan EKS clusters."""
        try:
            paginator = self.client.get_paginator("list_clusters")
            for page in paginator.paginate():
                for cluster_name in page.get("clusters", []):
                    result.resources_found += 1
                    await self._analyze_cluster(cluster_name, scan_id, findings)

        except botocore.exceptions.ClientError as e:
            self.handle_client_error(e, "ListClusters", findings)

    async def _analyze_cluster(self, cluster_name: str, scan_id: str, findings: list) -> None:
        """Analyze an EKS cluster."""
        try:
            response = self.client.describe_cluster(name=cluster_name)
            cluster = response.get("cluster", {})

            cluster_arn = cluster.get("arn", "")
            version = cluster.get("version", "")
            platform_version = cluster.get("platformVersion", "")
            endpoint = cluster.get("endpoint", "")
            endpoint_public_access = cluster.get("resourcesVpcConfig", {}).get("endpointPublicAccess", True)
            endpoint_private_access = cluster.get("resourcesVpcConfig", {}).get("endpointPrivateAccess", False)
            public_access_cidrs = cluster.get("resourcesVpcConfig", {}).get("publicAccessCidrs", [])
            vpc_id = cluster.get("resourcesVpcConfig", {}).get("vpcId", "")
            subnet_ids = cluster.get("resourcesVpcConfig", {}).get("subnetIds", [])
            security_group_ids = cluster.get("resourcesVpcConfig", {}).get("securityGroupIds", [])
            cluster_logging = cluster.get("logging", {}).get("clusterLogging", [])
            identity = cluster.get("identity", {})
            oidc_issuer = identity.get("oidc", {}).get("issuer", "")
            kubernetes_network_config = cluster.get("kubernetesNetworkConfig", {})
            service_ipv4_cidr = kubernetes_network_config.get("serviceIpv4Cidr", "")
            ip_family = kubernetes_network_config.get("ipFamily", "")

            # Add enumeration finding
            await self._add_enumeration_finding("eks_cluster", cluster_name, cluster_name, {
                "arn": cluster_arn,
                "version": version,
                "platform_version": platform_version,
                "endpoint": endpoint,
                "endpoint_public_access": endpoint_public_access,
                "endpoint_private_access": endpoint_private_access,
                "public_access_cidrs": public_access_cidrs,
                "vpc_id": vpc_id,
                "subnet_count": len(subnet_ids),
                "security_group_count": len(security_group_ids),
                "logging_enabled": any(log.get("enabled", False) for log in cluster_logging),
                "oidc_issuer": oidc_issuer,
                "service_ipv4_cidr": service_ipv4_cidr,
                "ip_family": ip_family,
                "encryption_config": bool(cluster.get("encryptionConfig", [])),
            }, findings, scan_id)

            # Check public endpoint access
            if endpoint_public_access:
                if not public_access_cidrs or "0.0.0.0/0" in public_access_cidrs:
                    self._add_finding_deduped(findings, self.create_finding(
                        title=f"EKS cluster {cluster_name} has public endpoint open to 0.0.0.0/0",
                        description="Cluster API endpoint is publicly accessible from anywhere on the internet",
                        severity="critical",
                        category="network_exposure",
                        resource_type="eks_cluster",
                        resource_id=cluster_name,
                        resource_name=cluster_name,
                        region=self.region,
                        evidence=[{"type": "cluster_config", "description": "Public endpoint access", "data": {"endpoint_public_access": True, "public_access_cidrs": public_access_cidrs}}],
                        remediation={
                            "summary": "Restrict public endpoint access",
                            "steps": [
                                "Enable private endpoint access",
                                "Restrict public access CIDRs to specific IP ranges",
                                "Ideally disable public endpoint entirely",
                            ],
                            "effort": "low",
                            "automatable": True,
                            "cli_commands": [
                                f"aws eks update-cluster-config --name {cluster_name} --resources-vpc-config endpointPublicAccess=false,endpointPrivateAccess=true",
                            ],
                        },
                        rule_id="eks_public_endpoint_open",
                    ))
                else:
                    self._add_finding_deduped(findings, self.create_finding(
                        title=f"EKS cluster {cluster_name} has public endpoint with restricted CIDRs",
                        description=f"Cluster API endpoint is publicly accessible but restricted to: {', '.join(public_access_cidrs)}",
                        severity="high",
                        category="network_exposure",
                        resource_type="eks_cluster",
                        resource_id=cluster_name,
                        resource_name=cluster_name,
                        region=self.region,
                        evidence=[{"type": "cluster_config", "description": "Public endpoint with restrictions", "data": {"public_access_cidrs": public_access_cidrs}}],
                        remediation={
                            "summary": "Prefer private endpoint only",
                            "steps": [
                                "Enable private endpoint access",
                                "Disable public endpoint access",
                                "Use bastion host or VPN for cluster access",
                            ],
                            "effort": "low",
                            "automatable": True,
                        },
                        rule_id="eks_public_endpoint_restricted",
                    ))

            if not endpoint_private_access:
                self._add_finding_deduped(findings, self.create_finding(
                    title=f"EKS cluster {cluster_name} has private endpoint disabled",
                    description="Private endpoint access is not enabled for the cluster",
                    severity="high",
                    category="network_exposure",
                    resource_type="eks_cluster",
                    resource_id=cluster_name,
                    resource_name=cluster_name,
                    region=self.region,
                    remediation={
                        "summary": "Enable private endpoint access",
                        "steps": [
                            "Enable private endpoint access on the cluster",
                            "Ensure subnets have proper NAT gateway for outbound traffic",
                        ],
                        "effort": "low",
                        "automatable": True,
                        "cli_commands": [
                            f"aws eks update-cluster-config --name {cluster_name} --resources-vpc-config endpointPrivateAccess=true",
                        ],
                    },
                    rule_id="eks_private_endpoint_disabled",
                ))

            # Check cluster logging
            logging_types = [log.get("types", []) for log in cluster_logging if log.get("enabled", False)]
            enabled_log_types = []
            for types in logging_types:
                enabled_log_types.extend(types)

            expected_logs = ["api", "audit", "authenticator", "controllerManager", "scheduler"]
            missing_logs = [log for log in expected_logs if log not in enabled_log_types]

            if missing_logs:
                self._add_finding_deduped(findings, self.create_finding(
                    title=f"EKS cluster {cluster_name} missing control plane logging: {', '.join(missing_logs)}",
                    description=f"Cluster control plane logging is not enabled for: {', '.join(missing_logs)}",
                    severity="medium",
                    category="logging_missing",
                    resource_type="eks_cluster",
                    resource_id=cluster_name,
                    resource_name=cluster_name,
                    region=self.region,
                    evidence=[{"type": "cluster_logging", "description": "Enabled log types", "data": {"enabled": enabled_log_types, "missing": missing_logs}}],
                    remediation={
                        "summary": "Enable all control plane logging",
                        "steps": [
                            "Enable api, audit, authenticator, controllerManager, scheduler logs",
                            "Configure CloudWatch Logs for log retention",
                        ],
                        "effort": "low",
                        "automatable": True,
                        "cli_commands": [
                            f"aws eks update-cluster-config --name {cluster_name} --logging '{{clusterLogging=[{{enabled=true,types=[api,audit,authenticator,controllerManager,scheduler]}}]}}'",
                        ],
                    },
                    rule_id="eks_control_plane_logging_incomplete",
                ))

            # Check Kubernetes version (check for outdated versions)
            # This would need version comparison logic
            # For now, just note the version
            self._add_finding_deduped(findings, self.create_finding(
                title=f"EKS cluster {cluster_name} running Kubernetes {version}",
                description=f"Cluster is running Kubernetes version {version} (platform version {platform_version})",
                severity="info",
                category="informational",
                resource_type="eks_cluster",
                resource_id=cluster_name,
                resource_name=cluster_name,
                region=self.region,
                evidence=[{"type": "cluster_version", "description": "Kubernetes version", "data": {"version": version, "platform_version": platform_version}}],
                rule_id="eks_cluster_version",
            ))

            # Check OIDC issuer
            if not oidc_issuer:
                self._add_finding_deduped(findings, self.create_finding(
                    title=f"EKS cluster {cluster_name} has no OIDC issuer",
                    description="OIDC issuer is not configured - required for IAM roles for service accounts (IRSA)",
                    severity="medium",
                    category="weak_configuration",
                    resource_type="eks_cluster",
                    resource_id=cluster_name,
                    resource_name=cluster_name,
                    region=self.region,
                    remediation={
                        "summary": "Associate OIDC issuer with cluster",
                        "steps": [
                            "Create OIDC provider for the cluster",
                            "Update cluster to associate OIDC issuer",
                        ],
                        "effort": "medium",
                        "automatable": True,
                    },
                    rule_id="eks_no_oidc_issuer",
                ))

            # Check secrets encryption
            encryption_config = cluster.get("encryptionConfig", [])
            if not encryption_config:
                self._add_finding_deduped(findings, self.create_finding(
                    title=f"EKS cluster {cluster_name} has no secrets encryption",
                    description="Cluster does not have envelope encryption for Kubernetes secrets",
                    severity="high",
                    category="encryption_missing",
                    resource_type="eks_cluster",
                    resource_id=cluster_name,
                    resource_name=cluster_name,
                    region=self.region,
                    remediation={
                        "summary": "Enable secrets encryption",
                        "steps": [
                            "Create KMS key for secrets encryption",
                            "Update cluster with encryption configuration",
                        ],
                        "effort": "medium",
                        "automatable": True,
                    },
                    rule_id="eks_secrets_encryption_disabled",
                ))
            else:
                for enc in encryption_config:
                    provider = enc.get("provider", {})
                    key_arn = provider.get("keyArn", "")
                    resources = enc.get("resources", [])
                    if "secrets" not in resources:
                        self._add_finding_deduped(findings, self.create_finding(
                            title=f"EKS cluster {cluster_name} encryption config missing secrets",
                            description="Secrets encryption is configured but 'secrets' resource type is not included",
                            severity="medium",
                            category="encryption_missing",
                            resource_type="eks_cluster",
                            resource_id=cluster_name,
                            resource_name=cluster_name,
                            region=self.region,
                            rule_id="eks_secrets_not_in_encryption",
                        ))

            # Scan node groups
            await self._scan_nodegroups(cluster_name, scan_id, findings)

            # Scan Fargate profiles
            await self._scan_fargate_profiles(cluster_name, scan_id, findings)

            # Scan addons
            await self._scan_addons(cluster_name, scan_id, findings)

            # Scan identity provider configs
            await self._scan_identity_providers(cluster_name, scan_id, findings)

        except botocore.exceptions.ClientError as e:
            self.handle_client_error(e, "DescribeCluster", findings)

    async def _scan_nodegroups(self, cluster_name: str, scan_id: str, findings: list) -> None:
        """Scan EKS node groups."""
        try:
            paginator = self.client.get_paginator("list_nodegroups")
            for page in paginator.paginate(clusterName=cluster_name):
                for ng_name in page.get("nodegroups", []):
                    ng_response = self.client.describe_nodegroup(clusterName=cluster_name, nodegroupName=ng_name)
                    ng = ng_response.get("nodegroup", {})

                    ng_arn = ng.get("nodegroupArn", "")
                    instance_types = ng.get("instanceTypes", [])
                    ami_type = ng.get("amiType", "")
                    capacity_type = ng.get("capacityType", "")
                    subnets = ng.get("subnets", [])
                    remote_access = ng.get("remoteAccess", {})
                    labels = ng.get("labels", {})
                    taints = ng.get("taints", [])
                    scaling_config = ng.get("scalingConfig", {})
                    min_size = scaling_config.get("minSize", 0)
                    max_size = scaling_config.get("maxSize", 0)
                    desired_size = scaling_config.get("desiredSize", 0)

                    # Add enumeration finding
                    await self._add_enumeration_finding("eks_nodegroup", ng_arn, ng_name, {
                        "cluster_name": cluster_name,
                        "arn": ng_arn,
                        "instance_types": instance_types,
                        "ami_type": ami_type,
                        "capacity_type": capacity_type,
                        "subnet_count": len(subnets),
                        "remote_access_enabled": bool(remote_access.get("ec2SshKey")),
                        "labels": labels,
                        "taint_count": len(taints),
                        "scaling_min": min_size,
                        "scaling_max": max_size,
                        "scaling_desired": desired_size,
                    }, findings, scan_id)

                    # Check for public subnets in node group
                    # This would require checking subnet route tables - simplified check
                    if len(subnets) < 2:
                        self._add_finding_deduped(findings, self.create_finding(
                            title=f"EKS node group {ng_name} in cluster {cluster_name} has < 2 subnets",
                            description="Node group should span multiple AZs for high availability",
                            severity="medium",
                            category="weak_configuration",
                            resource_type="eks_nodegroup",
                            resource_id=ng_arn,
                            resource_name=ng_name,
                            region=self.region,
                            rule_id="eks_nodegroup_single_az",
                        ))

                    # Check remote access (SSH)
                    if remote_access.get("ec2SshKey"):
                        self._add_finding_deduped(findings, self.create_finding(
                            title=f"EKS node group {ng_name} has SSH access enabled",
                            description=f"Node group allows SSH access via key: {remote_access.get('ec2SshKey')}",
                            severity="medium",
                            category="weak_configuration",
                            resource_type="eks_nodegroup",
                            resource_id=ng_arn,
                            resource_name=ng_name,
                            region=self.region,
                            remediation={
                                "summary": "Disable SSH access to nodes",
                                "steps": [
                                    "Remove SSH key from node group configuration",
                                    "Use SSM Session Manager for node access",
                                ],
                                "effort": "low",
                                "automatable": True,
                            },
                            rule_id="eks_nodegroup_ssh_enabled",
                        ))

                    # Check for spot instances without proper handling
                    if capacity_type == "SPOT" and not taints:
                        self._add_finding_deduped(findings, self.create_finding(
                            title=f"EKS node group {ng_name} uses SPOT instances without taints",
                            description="Spot instances should have taints to prevent critical workloads from scheduling",
                            severity="low",
                            category="weak_configuration",
                            resource_type="eks_nodegroup",
                            resource_id=ng_arn,
                            resource_name=ng_name,
                            region=self.region,
                            rule_id="eks_nodegroup_spot_no_taints",
                        ))

        except botocore.exceptions.ClientError as e:
            if e.response["Error"]["Code"] != "AccessDenied":
                self.handle_client_error(e, "ListNodegroups", findings)

    async def _scan_fargate_profiles(self, cluster_name: str, scan_id: str, findings: list) -> None:
        """Scan EKS Fargate profiles."""
        try:
            paginator = self.client.get_paginator("list_fargate_profiles")
            for page in paginator.paginate(clusterName=cluster_name):
                for fp_name in page.get("fargateProfileNames", []):
                    fp_response = self.client.describe_fargate_profile(clusterName=cluster_name, fargateProfileName=fp_name)
                    fp = fp_response.get("fargateProfile", {})

                    fp_arn = fp.get("fargateProfileArn", "")
                    selectors = fp.get("selectors", [])
                    subnets = fp.get("subnets", [])

                    # Add enumeration finding
                    await self._add_enumeration_finding("eks_fargate_profile", fp_arn, fp_name, {
                        "cluster_name": cluster_name,
                        "arn": fp_arn,
                        "selectors": selectors,
                        "subnet_count": len(subnets),
                        "status": fp.get("status", ""),
                        "pod_execution_role_arn": fp.get("podExecutionRoleArn", ""),
                    }, findings, scan_id)

                    # Check for namespace selectors without labels (too broad)
                    for selector in selectors:
                        namespace = selector.get("namespace", "")
                        labels = selector.get("labels", {})
                        if namespace and not labels:
                            self._add_finding_deduped(findings, self.create_finding(
                                title=f"EKS Fargate profile {fp_name} has broad namespace selector",
                                description=f"Selector for namespace '{namespace}' has no label restrictions",
                                severity="low",
                                category="weak_configuration",
                                resource_type="eks_fargate_profile",
                                resource_id=fp_arn,
                                resource_name=fp_name,
                                region=self.region,
                                rule_id="eks_fargate_broad_selector",
                            ))

                    if len(subnets) < 2:
                        self._add_finding_deduped(findings, self.create_finding(
                            title=f"EKS Fargate profile {fp_name} has < 2 subnets",
                            description="Fargate profile should span multiple AZs",
                            severity="medium",
                            category="weak_configuration",
                            resource_type="eks_fargate_profile",
                            resource_id=fp_arn,
                            resource_name=fp_name,
                            region=self.region,
                            rule_id="eks_fargate_single_az",
                        ))

        except botocore.exceptions.ClientError as e:
            if e.response["Error"]["Code"] != "AccessDenied":
                self.handle_client_error(e, "ListFargateProfiles", findings)

    async def _scan_addons(self, cluster_name: str, scan_id: str, findings: list) -> None:
        """Scan EKS addons."""
        try:
            paginator = self.client.get_paginator("list_addons")
            for page in paginator.paginate(clusterName=cluster_name):
                for addon_name in page.get("addons", []):
                    addon_response = self.client.describe_addon(clusterName=cluster_name, addonName=addon_name)
                    addon = addon_response.get("addon", {})

                    addon_arn = addon.get("addonArn", "")
                    addon_version = addon.get("addonVersion", "")
                    status = addon.get("status", "")
                    health = addon.get("health", {})

                    # Add enumeration finding
                    await self._add_enumeration_finding("eks_addon", addon_arn, addon_name, {
                        "cluster_name": cluster_name,
                        "arn": addon_arn,
                        "version": addon_version,
                        "status": status,
                        "health_issues": health.get("issues", []),
                        "service_account_role_arn": addon.get("serviceAccountRoleArn", ""),
                    }, findings, scan_id)

                    # Check for deprecated addons
                    deprecated_addons = ["kube-proxy", "coredns", "vpc-cni"]  # These are now managed differently
                    # Actually these are standard - check for outdated versions

                    if status == "DEGRADED":
                        issues = health.get("issues", [])
                        for issue in issues:
                            self._add_finding_deduped(findings, self.create_finding(
                                title=f"EKS addon {addon_name} in cluster {cluster_name} is degraded",
                                description=f"Addon status: {status}, issue: {issue.get('code', '')} - {issue.get('message', '')}",
                                severity="medium",
                                category="weak_configuration",
                                resource_type="eks_addon",
                                resource_id=addon_arn,
                                resource_name=addon_name,
                                region=self.region,
                                evidence=[{"type": "addon_health", "description": "Addon health issues", "data": health}],
                                rule_id="eks_addon_degraded",
                            ))

        except botocore.exceptions.ClientError as e:
            if e.response["Error"]["Code"] != "AccessDenied":
                self.handle_client_error(e, "ListAddons", findings)

    async def _scan_identity_providers(self, cluster_name: str, scan_id: str, findings: list) -> None:
        """Scan EKS identity provider configs (OIDC)."""
        try:
            paginator = self.client.get_paginator("list_identity_provider_configs")
            for page in paginator.paginate(clusterName=cluster_name):
                for idp in page.get("identityProviderConfigs", []):
                    idp_name = idp.get("name", "")
                    idp_type = idp.get("type", "")

                    idp_response = self.client.describe_identity_provider_config(
                        clusterName=cluster_name,
                        identityProviderConfig={"name": idp_name, "type": idp_type}
                    )
                    idp_detail = idp_response.get("identityProviderConfig", {})
                    oidc_config = idp_detail.get("oidc", {})

                    issuer_url = oidc_config.get("issuerUrl", "")
                    client_id = oidc_config.get("clientId", "")
                    username_claim = oidc_config.get("usernameClaim", "")
                    groups_claim = oidc_config.get("groupsClaim", "")

                    # Add enumeration finding
                    await self._add_enumeration_finding("eks_identity_provider", idp_name, idp_name, {
                        "cluster_name": cluster_name,
                        "type": idp_type,
                        "issuer_url": issuer_url,
                        "client_id": client_id,
                        "username_claim": username_claim,
                        "groups_claim": groups_claim,
                    }, findings, scan_id)

                    # Check for non-standard claims
                    if username_claim and username_claim != "email":
                        self._add_finding_deduped(findings, self.create_finding(
                            title=f"EKS cluster {cluster_name} OIDC uses non-standard username claim: {username_claim}",
                            description="Non-standard username claims may cause authentication issues",
                            severity="low",
                            category="weak_configuration",
                            resource_type="eks_identity_provider",
                            resource_id=idp_name,
                            resource_name=idp_name,
                            region=self.region,
                            rule_id="eks_oidc_nonstandard_username_claim",
                        ))

                    if not groups_claim:
                        self._add_finding_deduped(findings, self.create_finding(
                            title=f"EKS cluster {cluster_name} OIDC has no groups claim configured",
                            description="Groups claim is not configured - RBAC group mapping may not work",
                            severity="low",
                            category="weak_configuration",
                            resource_type="eks_identity_provider",
                            resource_id=idp_name,
                            resource_name=idp_name,
                            region=self.region,
                            rule_id="eks_oidc_no_groups_claim",
                        ))

        except botocore.exceptions.ClientError as e:
            if e.response["Error"]["Code"] != "AccessDenied":
                self.handle_client_error(e, "ListIdentityProviderConfigs", findings)

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
            rule_id=f"eks_enum_{resource_type}",
        )
        self._add_finding_deduped(findings, finding)

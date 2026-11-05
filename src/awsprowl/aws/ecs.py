"""ECS scanner for awsProwl."""

from __future__ import annotations

import asyncio
import hashlib

import botocore.exceptions

from awsprowl.aws.base import AWSServiceBase, ScanResult
from awsprowl.core.auth import AWSAuthManager
from awsprowl.core.logging import get_logger

log = get_logger(__name__)


class ECSScanner(AWSServiceBase):
    """Scanner for ECS resources."""

    SERVICE_NAME = "ecs"
    REQUIRED_PERMISSIONS = [
        "ecs:ListClusters",
        "ecs:DescribeClusters",
        "ecs:ListServices",
        "ecs:DescribeServices",
        "ecs:ListTaskDefinitions",
        "ecs:DescribeTaskDefinition",
        "ecs:ListTasks",
        "ecs:DescribeTasks",
        "ecs:ListContainerInstances",
        "ecs:DescribeContainerInstances",
    ]

    def __init__(self, auth_manager: AWSAuthManager, region: str | None = None):
        super().__init__(auth_manager, region)

    async def scan(self, scan_id: str, findings: list) -> ScanResult:
        """Scan ECS resources for security issues."""
        result = ScanResult(service=self.SERVICE_NAME, region=self.region)

        try:
            await asyncio.gather(
                self._scan_clusters(scan_id, findings, result),
                self._scan_task_definitions(scan_id, findings, result),
                return_exceptions=True,
            )

        except Exception as e:
            log.error("Error in ECS scan: {}", e)
            result.errors.append(str(e))

        return result

    async def _scan_clusters(self, scan_id: str, findings: list, result: ScanResult) -> None:
        """Scan ECS clusters."""
        try:
            paginator = self.client.get_paginator("list_clusters")
            for page in paginator.paginate():
                cluster_arns = page.get("clusterArns", [])
                if cluster_arns:
                    clusters = self.client.describe_clusters(clusters=cluster_arns)
                    for cluster in clusters.get("clusters", []):
                        result.resources_found += 1
                        await self._analyze_cluster(cluster, scan_id, findings)

        except botocore.exceptions.ClientError as e:
            self.handle_client_error(e, "ListClusters/DescribeClusters", findings)

    async def _analyze_cluster(self, cluster: dict, scan_id: str, findings: list) -> None:
        """Analyze an ECS cluster."""
        cluster_name = cluster["clusterName"]
        cluster_arn = cluster["clusterArn"]

        # Add enumeration finding
        await self._add_enumeration_finding("ecs_cluster", cluster_name, cluster_name, {
            "arn": cluster_arn,
            "status": cluster.get("status", ""),
            "running_tasks": cluster.get("runningTasksCount", 0),
            "pending_tasks": cluster.get("pendingTasksCount", 0),
            "active_services": cluster.get("activeServicesCount", 0),
            "capacity_providers": cluster.get("capacityProviders", []),
            "container_insights": any(s.get("name") == "containerInsights" and s.get("value") == "enabled" for s in cluster.get("settings", [])),
        }, findings, scan_id)

        # Check for container insights
        settings = cluster.get("settings", [])
        has_insights = any(s.get("name") == "containerInsights" and s.get("value") == "enabled" for s in settings)
        if not has_insights:
            self._add_finding_deduped(findings, self.create_finding(
                title=f"ECS cluster {cluster_name} does not have Container Insights enabled",
                description="Container Insights provides enhanced monitoring and is not enabled",
                severity="low",
                category="logging_missing",
                resource_type="ecs_cluster",
                resource_id=cluster_name,
                resource_name=cluster_name,
                region=self.region,
                remediation={
                    "summary": "Enable Container Insights",
                    "steps": [
                        "Enable Container Insights on cluster",
                        "Verify CloudWatch metrics appear",
                    ],
                    "effort": "low",
                    "automatable": True,
                    "cli_commands": [
                        f"aws ecs update-cluster-settings --cluster {cluster_name} --settings name=containerInsights,value=enabled",
                    ],
                },
                rule_id="ecs_cluster_insights_disabled",
            ))

        # Check cluster configuration for Fargate vs EC2
        capacity_providers = cluster.get("capacityProviders", [])
        if "FARGATE" not in capacity_providers and "FARGATE_SPOT" not in capacity_providers:
            self._add_finding_deduped(findings, self.create_finding(
                title=f"ECS cluster {cluster_name} does not have Fargate capacity providers",
                description="Cluster is not configured for Fargate, which provides better isolation",
                severity="info",
                category="best_practice",
                resource_type="ecs_cluster",
                resource_id=cluster_name,
                resource_name=cluster_name,
                region=self.region,
                remediation={
                    "summary": "Consider adding Fargate capacity providers",
                    "steps": [
                        "Add FARGATE and FARGATE_SPOT capacity providers",
                        "Update services to use Fargate launch type",
                    ],
                    "effort": "medium",
                    "automatable": True,
                },
                rule_id="ecs_cluster_no_fargate",
            ))

        # Scan services in this cluster
        try:
            services_paginator = self.client.get_paginator("list_services")
            for page in services_paginator.paginate(cluster=cluster_name):
                service_arns = page.get("serviceArns", [])
                if service_arns:
                    services = self.client.describe_services(cluster=cluster_name, services=service_arns)
                    for service in services.get("services", []):
                        await self._analyze_service(service, cluster_name, scan_id, findings)
        except botocore.exceptions.ClientError:
            pass

    async def _analyze_service(self, service: dict, cluster_name: str, scan_id: str, findings: list) -> None:
        """Analyze an ECS service."""
        service_name = service["serviceName"]
        service_arn = service["serviceArn"]
        launch_type = service.get("launchType", "EC2")
        network_config = service.get("networkConfiguration", {})

        # Add enumeration finding
        await self._add_enumeration_finding("ecs_service", service_name, service_name, {
            "arn": service_arn,
            "cluster": cluster_name,
            "launch_type": launch_type,
            "desired_count": service.get("desiredCount", 0),
            "running_count": service.get("runningCount", 0),
            "pending_count": service.get("pendingCount", 0),
            "load_balancers": len(service.get("loadBalancers", [])),
            "network_mode": network_config.get("awsvpcConfiguration", {}).get("assignPublicIp", "N/A") if launch_type == "FARGATE" else "N/A",
        }, findings, scan_id)

        # Check for public IP assignment (Fargate)
        if launch_type == "FARGATE":
            awsvpc_config = network_config.get("awsvpcConfiguration", {})
            assign_public_ip = awsvpc_config.get("assignPublicIp", "DISABLED")
            if assign_public_ip == "ENABLED":
                self._add_finding_deduped(findings, self.create_finding(
                    title=f"ECS service {service_name} assigns public IPs to tasks",
                    description="Fargate service tasks are assigned public IP addresses",
                    severity="medium",
                    category="network_exposure",
                    resource_type="ecs_service",
                    resource_id=service_name,
                    resource_name=service_name,
                    region=self.region,
                    evidence=[{"type": "service_config", "description": "Network configuration", "data": network_config}],
                    remediation={
                        "summary": "Disable public IP assignment",
                        "steps": [
                            "Update service network configuration",
                            "Use NAT Gateway for outbound internet access",
                        ],
                        "effort": "low",
                        "automatable": True,
                        "cli_commands": [
                            f"aws ecs update-service --cluster {cluster_name} --service {service_name} --network-configuration 'awsvpcConfiguration={{subnets=[subnet-1,subnet-2],assignPublicIp=DISABLED}}'",
                        ],
                    },
                    rule_id="ecs_service_public_ip",
                ))

        # Check for load balancer configuration
        load_balancers = service.get("loadBalancers", [])
        if not load_balancers and launch_type == "FARGATE":
            self._add_finding_deduped(findings, self.create_finding(
                title=f"ECS service {service_name} has no load balancer",
                description="Fargate service is not behind a load balancer, may not be accessible or properly load balanced",
                severity="low",
                category="weak_configuration",
                resource_type="ecs_service",
                resource_id=service_name,
                resource_name=service_name,
                region=self.region,
                rule_id="ecs_service_no_lb",
            ))

        # Check deployment configuration for rolling updates
        deployment_config = service.get("deploymentConfiguration", {})
        max_percent = deployment_config.get("maximumPercent", 200)
        min_healthy = deployment_config.get("minimumHealthyPercent", 100)
        if max_percent > 200 or min_healthy < 50:
            self._add_finding_deduped(findings, self.create_finding(
                title=f"ECS service {service_name} has aggressive deployment configuration",
                description=f"Deployment config: max={max_percent}%, min_healthy={min_healthy}% - may cause downtime",
                severity="low",
                category="availability",
                resource_type="ecs_service",
                resource_id=service_name,
                resource_name=service_name,
                region=self.region,
                rule_id="ecs_service_deployment_config",
            ))

    async def _scan_task_definitions(self, scan_id: str, findings: list, result: ScanResult) -> None:
        """Scan ECS task definitions."""
        try:
            paginator = self.client.get_paginator("list_task_definitions")
            for page in paginator.paginate(status="ACTIVE"):
                for td_arn in page.get("taskDefinitionArns", []):
                    result.resources_found += 1
                    td = self.client.describe_task_definition(taskDefinition=td_arn)
                    await self._analyze_task_definition(td["taskDefinition"], scan_id, findings)

        except botocore.exceptions.ClientError as e:
            self.handle_client_error(e, "ListTaskDefinitions/DescribeTaskDefinition", findings)

    async def _analyze_task_definition(self, td: dict, scan_id: str, findings: list) -> None:
        """Analyze a task definition for security issues."""
        family = td["family"]
        revision = td["revision"]
        td_arn = td["taskDefinitionArn"]
        network_mode = td.get("networkMode", "bridge")
        requires_compatibilities = td.get("requiresCompatibilities", [])
        execution_role_arn = td.get("executionRoleArn", "")
        task_role_arn = td.get("taskRoleArn", "")

        # Add enumeration finding
        await self._add_enumeration_finding("ecs_task_definition", f"{family}:{revision}", family, {
            "arn": td_arn,
            "revision": revision,
            "network_mode": network_mode,
            "requires_compatibilities": requires_compatibilities,
            "execution_role_arn": execution_role_arn,
            "task_role_arn": task_role_arn,
            "container_count": len(td.get("containerDefinitions", [])),
            "cpu": td.get("cpu", ""),
            "memory": td.get("memory", ""),
        }, findings, scan_id)

        # Check for privileged containers
        for container in td.get("containerDefinitions", []):
            container_name = container["name"]
            privileged = container.get("privileged", False)
            if privileged:
                self._add_finding_deduped(findings, self.create_finding(
                    title=f"Task definition {family}:{revision} has privileged container: {container_name}",
                    description="Container runs in privileged mode, giving it full access to host",
                    severity="critical",
                    category="privilege_escalation",
                    resource_type="ecs_task_definition",
                    resource_id=f"{family}:{revision}",
                    resource_name=family,
                    region=self.region,
                    evidence=[{"type": "container_definition", "description": f"Privileged container {container_name}", "data": {"name": container_name, "privileged": True}}],
                    remediation={
                        "summary": "Remove privileged mode from container",
                        "steps": [
                            "Identify why privileged mode is needed",
                            "Use specific Linux capabilities instead",
                            "Update task definition",
                        ],
                        "effort": "medium",
                        "automatable": False,
                    },
                    rule_id="ecs_task_privileged_container",
                ))

            # Check for host network mode
            if network_mode == "host":
                self._add_finding_deduped(findings, self.create_finding(
                    title=f"Task definition {family}:{revision} uses host network mode",
                    description="Host network mode shares host network namespace, reducing isolation",
                    severity="high",
                    category="network_exposure",
                    resource_type="ecs_task_definition",
                    resource_id=f"{family}:{revision}",
                    resource_name=family,
                    region=self.region,
                    remediation={
                        "summary": "Use awsvpc network mode instead",
                        "steps": [
                            "Change networkMode to awsvpc",
                            "Ensure VPC and subnets are configured",
                            "Update service to use awsvpc",
                        ],
                        "effort": "medium",
                        "automatable": True,
                    },
                    rule_id="ecs_task_host_network",
                ))

            # Check for environment variable secrets
            env_vars = container.get("environment", [])
            secret_keywords = ["password", "secret", "key", "token", "api_key", "access_key", "secret_key"]
            for env in env_vars:
                if any(kw in env.get("name", "").lower() for kw in secret_keywords):
                    self._add_finding_deduped(findings, self.create_finding(
                        title=f"Task definition {family}:{revision} has potential secret in env var: {env['name']}",
                        description=f"Container {container_name} environment variable {env['name']} may contain sensitive data",
                        severity="high",
                        category="secrets_exposure",
                        resource_type="ecs_task_definition",
                        resource_id=f"{family}:{revision}",
                        resource_name=family,
                        region=self.region,
                        evidence=[{"type": "container_env", "description": f"Env var {env['name']}", "data": env}],
                        remediation={
                            "summary": "Use AWS Secrets Manager or Parameter Store",
                            "steps": [
                                "Store secrets in Secrets Manager",
                                "Use secrets section in task definition",
                                "Remove from environment variables",
                            ],
                            "effort": "medium",
                            "automatable": False,
                        },
                        rule_id="ecs_task_env_secret",
                    ))

            # Check for secrets in container definition
            secrets = container.get("secrets", [])
            for secret in secrets:
                value_from = secret.get("valueFrom", "")
                if "ssm" in value_from.lower() or "secretsmanager" in value_from.lower():
                    # Good - using secrets manager
                    pass
                else:
                    self._add_finding_deduped(findings, self.create_finding(
                        title=f"Task definition {family}:{revision} secret {secret['name']} may not use Secrets Manager",
                        description=f"Secret {secret['name']} valueFrom: {value_from}",
                        severity="medium",
                        category="secrets_exposure",
                        resource_type="ecs_task_definition",
                        resource_id=f"{family}:{revision}",
                        resource_name=family,
                        region=self.region,
                        rule_id="ecs_task_secret_source",
                    ))

            # Check resource limits
            cpu = container.get("cpu", 0)
            memory = container.get("memory", 0)
            memory_reservation = container.get("memoryReservation", 0)
            if cpu == 0 and memory == 0 and memory_reservation == 0:
                self._add_finding_deduped(findings, self.create_finding(
                    title=f"Task definition {family}:{revision} container {container_name} has no resource limits",
                    description="Container has no CPU or memory limits, can consume all host resources",
                    severity="medium",
                    category="dos_risk",
                    resource_type="ecs_task_definition",
                    resource_id=f"{family}:{revision}",
                    resource_name=family,
                    region=self.region,
                    remediation={
                        "summary": "Set CPU and memory limits",
                        "steps": [
                            "Determine appropriate resource limits",
                            "Update container definition with limits",
                        ],
                        "effort": "low",
                        "automatable": True,
                    },
                    rule_id="ecs_task_no_resource_limits",
                ))

        # Check execution role
        if not execution_role_arn:
            self._add_finding_deduped(findings, self.create_finding(
                title=f"Task definition {family}:{revision} has no execution role",
                description="Task definition does not specify an execution role, required for Fargate and some features",
                severity="medium",
                category="weak_configuration",
                resource_type="ecs_task_definition",
                resource_id=f"{family}:{revision}",
                resource_name=family,
                region=self.region,
                rule_id="ecs_task_no_execution_role",
            ))

        # Check task role permissions
        if task_role_arn:
            await self._check_task_role(task_role_arn, f"{family}:{revision}", scan_id, findings)

    async def _check_task_role(self, role_arn: str, td_id: str, scan_id: str, findings: list) -> None:
        """Check ECS task role for excessive permissions."""
        try:
            role_name = role_arn.split("/")[-1]

            # Get inline policies
            inline = self.client.list_role_policies(RoleName=role_name)
            for policy_name in inline.get("PolicyNames", []):
                policy = self.client.get_role_policy(RoleName=role_name, PolicyName=policy_name)
                await self._check_policy_document(policy["PolicyDocument"], f"ecs_task_role/{role_name}/inline/{policy_name}", td_id, scan_id, findings)

            # Get attached policies
            attached = self.client.list_attached_role_policies(RoleName=role_name)
            for policy in attached.get("AttachedPolicies", []):
                policy_detail = self.client.get_policy(PolicyArn=policy["PolicyArn"])
                version = self.client.get_policy_version(
                    PolicyArn=policy["PolicyArn"],
                    VersionId=policy_detail["Policy"]["DefaultVersionId"],
                )
                await self._check_policy_document(version["PolicyVersion"]["Document"], f"ecs_task_role/{role_name}/attached/{policy['PolicyName']}", td_id, scan_id, findings)

        except botocore.exceptions.ClientError:
            pass

    async def _check_policy_document(self, policy_doc: dict, policy_id: str, td_id: str, scan_id: str, findings: list) -> None:
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
                    title=f"ECS task definition {td_id} role has overly permissive policy: {policy_id}",
                    description="Task role policy allows all actions on all resources",
                    severity="critical",
                    category="excessive_permissions",
                    resource_type="ecs_task_definition",
                    resource_id=td_id,
                    region=self.region,
                    evidence=[{"type": "role_policy", "description": f"Overly permissive policy {policy_id}", "data": policy_doc}],
                    remediation={
                        "summary": "Apply least privilege to task role",
                        "steps": [
                            "Identify minimum required permissions",
                            "Create new policy with specific actions and resources",
                            "Attach new policy and remove overly permissive one",
                        ],
                        "effort": "medium",
                        "automatable": False,
                    },
                    rule_id="ecs_task_role_wildcard_policy",
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
            rule_id=f"ecs_enum_{resource_type}",
        )
        self._add_finding_deduped(findings, finding)

"""Elastic Beanstalk scanner for awsProwl."""

from __future__ import annotations

import hashlib

import botocore.exceptions

from awsprowl.aws.base import AWSServiceBase, ScanResult
from awsprowl.core.auth import AWSAuthManager
from awsprowl.core.logging import get_logger

log = get_logger(__name__)


class BeanstalkScanner(AWSServiceBase):
    """Scanner for Elastic Beanstalk resources."""

    SERVICE_NAME = "elasticbeanstalk"
    REQUIRED_PERMISSIONS = [
        "elasticbeanstalk:DescribeApplications",
        "elasticbeanstalk:DescribeEnvironments",
        "elasticbeanstalk:DescribeConfigurationSettings",
        "elasticbeanstalk:ListPlatformVersions",
    ]

    def __init__(self, auth_manager: AWSAuthManager, region: str | None = None):
        super().__init__(auth_manager, region)

    async def scan(self, scan_id: str, findings: list) -> ScanResult:
        """Scan Elastic Beanstalk resources for security issues."""
        result = ScanResult(service=self.SERVICE_NAME, region=self.region)

        try:
            await self._scan_applications(scan_id, findings, result)

        except Exception as e:
            log.error("Error in Elastic Beanstalk scan: {}", e)
            result.errors.append(str(e))

        return result

    async def _scan_applications(self, scan_id: str, findings: list, result: ScanResult) -> None:
        """Scan Beanstalk applications and environments."""
        try:
            apps = self.client.describe_applications()
            for app in apps.get("Applications", []):
                app_name = app["ApplicationName"]
                result.resources_found += 1

                # Scan environments for this application
                envs = self.client.describe_environments(ApplicationName=app_name)
                for env in envs.get("Environments", []):
                    result.resources_found += 1
                    await self._analyze_environment(env, app_name, scan_id, findings)

        except botocore.exceptions.ClientError as e:
            self.handle_client_error(e, "DescribeApplications/DescribeEnvironments", findings)

    async def _analyze_environment(self, env: dict, app_name: str, scan_id: str, findings: list) -> None:
        """Analyze a Beanstalk environment."""
        env_name = env["EnvironmentName"]
        env_id = env["EnvironmentId"]
        status = env.get("Status", "")
        health = env.get("Health", "")
        platform_arn = env.get("PlatformArn", "")
        solution_stack = env.get("SolutionStackName", "")

        # Add enumeration finding
        await self._add_enumeration_finding("beanstalk_environment", env_id, env_name, {
            "application_name": app_name,
            "status": status,
            "health": health,
            "platform_arn": platform_arn,
            "solution_stack": solution_stack,
            "tier": env.get("Tier", {}).get("Type", ""),
            "endpoint_url": env.get("EndpointURL", ""),
        }, findings, scan_id)

        # Check for deprecated platforms
        deprecated_keywords = [
            "Python 3.6", "Python 3.7", "Node.js 10", "Node.js 12", "Node.js 14",
            "Java 8", "Java 11", "Ruby 2.5", "Ruby 2.6", "Go 1.11", "Go 1.12",
            "Docker 18", "Docker 19", "Docker 20",
        ]

        for deprecated in deprecated_keywords:
            if deprecated in solution_stack:
                self._add_finding_deduped(findings, self.create_finding(
                    title=f"Beanstalk environment {env_name} uses deprecated platform: {solution_stack}",
                    description=f"Environment runs on deprecated platform {solution_stack}",
                    severity="high",
                    category="vulnerable_configuration",
                    resource_type="beanstalk_environment",
                    resource_id=env_id,
                    resource_name=env_name,
                    region=self.region,
                    evidence=[{"type": "environment_config", "description": "Platform", "data": {"solution_stack": solution_stack}}],
                    remediation={
                        "summary": "Upgrade to supported platform version",
                        "steps": [
                            "Identify latest supported platform",
                            "Test application on new platform",
                            "Deploy platform update",
                        ],
                        "effort": "medium",
                        "automatable": False,
                    },
                    rule_id="beanstalk_deprecated_platform",
                ))
                break

        # Check environment health
        if health in ("Red", "Yellow"):
            severity = "high" if health == "Red" else "medium"
            self._add_finding_deduped(findings, self.create_finding(
                title=f"Beanstalk environment {env_name} health is {health}",
                description=f"Environment health status is {health}, indicating issues",
                severity=severity,
                category="availability",
                resource_type="beanstalk_environment",
                resource_id=env_id,
                resource_name=env_name,
                region=self.region,
                rule_id="beanstalk_unhealthy",
            ))

        # Check configuration settings
        try:
            config = self.client.describe_configuration_settings(
                ApplicationName=app_name,
                EnvironmentName=env_name,
            )
            for option_settings in config.get("ConfigurationSettings", []):
                await self._check_option_settings(option_settings, env_name, env_id, scan_id, findings)
        except botocore.exceptions.ClientError:
            pass

        # Check for public load balancer
        if env.get("EndpointURL", "").startswith("http://") or env.get("EndpointURL", "").startswith("https://"):
            tier = env.get("Tier", {})
            if tier.get("Type") == "Standard" and tier.get("Name") == "WebServer":
                self._add_finding_deduped(findings, self.create_finding(
                    title=f"Beanstalk environment {env_name} is a public web server environment",
                    description="Environment has a public endpoint, ensure proper security groups and WAF",
                    severity="info",
                    category="network_exposure",
                    resource_type="beanstalk_environment",
                    resource_id=env_id,
                    resource_name=env_name,
                    region=self.region,
                    rule_id="beanstalk_public_endpoint",
                ))

    async def _check_option_settings(self, config: dict, env_name: str, env_id: str, scan_id: str, findings: list) -> None:
        """Check Beanstalk configuration option settings."""
        option_settings = config.get("OptionSettings", [])

        for setting in option_settings:
            namespace = setting.get("Namespace", "")
            option_name = setting.get("OptionName", "")
            value = setting.get("Value", "")

            # Check for SSH access enabled
            if namespace == "aws:autoscaling:launchconfiguration" and option_name == "SSHSourceRestriction":
                if not value or value == "tcp,22,22,0.0.0.0/0":
                    self._add_finding_deduped(findings, self.create_finding(
                        title=f"Beanstalk environment {env_name} allows SSH from anywhere",
                        description="SSH access is open to the world (0.0.0.0/0)",
                        severity="high",
                        category="network_exposure",
                        resource_type="beanstalk_environment",
                        resource_id=env_id,
                        resource_name=env_name,
                        region=self.region,
                        remediation={
                            "summary": "Restrict SSH access to specific IPs",
                            "steps": [
                                "Update SSHSourceRestriction to specific CIDR",
                                "Or disable SSH access entirely",
                            ],
                            "effort": "low",
                            "automatable": True,
                        },
                        rule_id="beanstalk_ssh_open",
                    ))

            # Check for IAM instance profile
            if namespace == "aws:autoscaling:launchconfiguration" and option_name == "IamInstanceProfile":
                if not value:
                    self._add_finding_deduped(findings, self.create_finding(
                        title=f"Beanstalk environment {env_name} has no IAM instance profile",
                        description="Instances have no IAM role, cannot access AWS services securely",
                        severity="medium",
                        category="weak_configuration",
                        resource_type="beanstalk_environment",
                        resource_id=env_id,
                        resource_name=env_name,
                        region=self.region,
                        rule_id="beanstalk_no_instance_profile",
                    ))

            # Check for managed platform updates
            if namespace == "aws:elasticbeanstalk:managedactions" and option_name == "ManagedActionsEnabled":
                if value.lower() != "true":
                    self._add_finding_deduped(findings, self.create_finding(
                        title=f"Beanstalk environment {env_name} does not have managed platform updates enabled",
                        description="Automatic platform updates are disabled, requiring manual maintenance",
                        severity="medium",
                        category="vulnerable_configuration",
                        resource_type="beanstalk_environment",
                        resource_id=env_id,
                        resource_name=env_name,
                        region=self.region,
                        remediation={
                            "summary": "Enable managed platform updates",
                            "steps": [
                                "Enable ManagedActionsEnabled",
                                "Configure PreferredStartTime for maintenance window",
                            ],
                            "effort": "low",
                            "automatable": True,
                        },
                        rule_id="beanstalk_no_managed_updates",
                    ))

            # Check for application health check URL
            if namespace == "aws:elasticbeanstalk:application" and option_name == "Application Healthcheck URL":
                if not value:
                    self._add_finding_deduped(findings, self.create_finding(
                        title=f"Beanstalk environment {env_name} has no health check URL",
                        description="No custom health check URL configured, using default",
                        severity="low",
                        category="best_practice",
                        resource_type="beanstalk_environment",
                        resource_id=env_id,
                        resource_name=env_name,
                        region=self.region,
                        rule_id="beanstalk_no_health_check_url",
                    ))

            # Check for environment variables with secrets
            if namespace == "aws:elasticbeanstalk:application:environment":
                secret_keywords = ["password", "secret", "key", "token", "api_key", "access_key", "secret_key"]
                if any(kw in option_name.lower() for kw in secret_keywords):
                    self._add_finding_deduped(findings, self.create_finding(
                        title=f"Beanstalk environment {env_name} has potential secret in env var: {option_name}",
                        description=f"Environment variable {option_name} may contain sensitive data",
                        severity="high",
                        category="secrets_exposure",
                        resource_type="beanstalk_environment",
                        resource_id=env_id,
                        resource_name=env_name,
                        region=self.region,
                        evidence=[{"type": "environment_variable", "description": f"Env var {option_name}", "data": {"key": option_name, "value_preview": value[:20] + "..." if len(value) > 20 else value}}],
                        remediation={
                            "summary": "Move secrets to AWS Secrets Manager or Parameter Store",
                            "steps": [
                                "Store secrets in Secrets Manager",
                                "Update application to fetch secrets at runtime",
                                "Remove from environment configuration",
                            ],
                            "effort": "medium",
                            "automatable": False,
                        },
                        rule_id="beanstalk_env_secret",
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
            rule_id=f"beanstalk_enum_{resource_type}",
        )
        self._add_finding_deduped(findings, finding)

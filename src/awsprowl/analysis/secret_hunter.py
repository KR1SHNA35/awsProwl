"""Secret hunter module for awsProwl."""

from __future__ import annotations

import asyncio
import re

import botocore.exceptions

from awsprowl.aws.base import AWSServiceBase, ScanResult
from awsprowl.core.auth import AWSAuthManager
from awsprowl.core.logging import get_logger

log = get_logger(__name__)


class SecretHunter(AWSServiceBase):
    """Scans for secrets in various AWS resources."""

    SERVICE_NAME = "secret_hunter"
    REQUIRED_PERMISSIONS = [
        "ec2:DescribeInstances",
        "ec2:DescribeUserData",
        "lambda:GetFunction",
        "lambda:ListFunctions",
        "secretsmanager:ListSecrets",
        "secretsmanager:GetSecretValue",
        "ssm:GetParametersByPath",
        "ssm:GetParameters",
        "ssm:DescribeParameters",
        "codebuild:BatchGetBuilds",
        "codebuild:ListBuildsForProject",
        "codebuild:ListProjects",
        "ecs:ListClusters",
        "ecs:ListTasks",
        "ecs:DescribeTasks",
        "ecs:DescribeTaskDefinition",
    ]

    # Common secret patterns
    SECRET_PATTERNS = [
        (re.compile(r'(?i)(aws_access_key_id|aws_secret_access_key)\s*[:=]\s*["\']?([A-Z0-9]{20})["\']?'), "AWS Access Key"),
        (re.compile(r'(?i)(aws_secret_access_key)\s*[:=]\s*["\']?([A-Za-z0-9/+=]{40})["\']?'), "AWS Secret Key"),
        (re.compile(r'(?i)(api_key|apikey)\s*[:=]\s*["\']?([A-Za-z0-9_\-]{20,})["\']?'), "API Key"),
        (re.compile(r'(?i)(password|passwd|pwd)\s*[:=]\s*["\']?([^\s"\']{8,})["\']?'), "Password"),
        (re.compile(r'(?i)(secret|token)\s*[:=]\s*["\']?([A-Za-z0-9_\-]{20,})["\']?'), "Secret/Token"),
        (re.compile(r'(?i)(private_key|privatekey)\s*[:=]\s*["\']?(-----BEGIN (RSA |EC )?PRIVATE KEY-----)["\']?'), "Private Key"),
        (re.compile(r'(?i)(github_token|ghp_)\s*[:=]\s*["\']?([A-Za-z0-9]{36,})["\']?'), "GitHub Token"),
        (re.compile(r'(?i)(slack_token|xoxb-)\s*[:=]\s*["\']?([A-Za-z0-9\-]{30,})["\']?'), "Slack Token"),
        (re.compile(r'(?i)(database_url|db_url)\s*[:=]\s*["\']?([^\s"\']+)["\']?'), "Database URL"),
        (re.compile(r'(?i)(connection_string|conn_str)\s*[:=]\s*["\']?([^\s"\']+)["\']?'), "Connection String"),
        (re.compile(r'eyJ[A-Za-z0-9_\-]+\.eyJ[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+', re.DOTALL), "JWT Token"),
        (re.compile(r'(?i)(ssh-rsa|ssh-ed25519|ecdsa-sha2-nistp256)\s+[A-Za-z0-9+/=]+', re.DOTALL), "SSH Key"),
    ]

    def __init__(self, auth_manager: AWSAuthManager, region: str | None = None):
        super().__init__(auth_manager, region)

    async def scan(self, scan_id: str, findings: list) -> ScanResult:
        """Scan for secrets in AWS resources."""
        result = ScanResult(service=self.SERVICE_NAME, region=self.region)

        try:
            await asyncio.gather(
                self._scan_ec2_user_data(scan_id, findings, result),
                self._scan_lambda_env_vars(scan_id, findings, result),
                self._scan_secrets_manager(scan_id, findings, result),
                self._scan_ssm_parameters(scan_id, findings, result),
                self._scan_codebuild_projects(scan_id, findings, result),
                self._scan_ecs_task_definitions(scan_id, findings, result),
                return_exceptions=True,
            )

        except Exception as e:
            log.error("Error in secret hunter scan: {}", e)
            result.errors.append(str(e))

        return result

    async def _scan_ec2_user_data(self, scan_id: str, findings: list, result: ScanResult) -> None:
        """Scan EC2 instance user data for secrets."""
        try:
            paginator = self.client.get_paginator("describe_instances")
            for page in paginator.paginate():
                for reservation in page.get("Reservations", []):
                    for instance in reservation.get("Instances", []):
                        instance_id = instance["InstanceId"]
                        result.resources_found += 1

                        # Get user data
                        try:
                            ud_response = self.client.describe_instance_attribute(
                                InstanceId=instance_id,
                                Attribute="userData"
                            )
                            user_data = ud_response.get("UserData", {}).get("Value", "")
                            if user_data:
                                import base64
                                try:
                                    decoded = base64.b64decode(user_data).decode("utf-8")
                                    self._scan_content(decoded, f"EC2 user data for {instance_id}", findings, {
                                        "resource_type": "ec2_instance",
                                        "resource_id": instance_id,
                                    })
                                except Exception:
                                    pass
                        except botocore.exceptions.ClientError:
                            pass

        except botocore.exceptions.ClientError as e:
            self.handle_client_error(e, "DescribeInstances")

    async def _scan_lambda_env_vars(self, scan_id: str, findings: list, result: ScanResult) -> None:
        """Scan Lambda function environment variables for secrets."""
        try:
            paginator = self.client.get_paginator("list_functions")
            for page in paginator.paginate():
                for func in page.get("Functions", []):
                    result.resources_found += 1
                    func_name = func["FunctionName"]

                    env_vars = func.get("Environment", {}).get("Variables", {})
                    for key, value in env_vars.items():
                        self._scan_content(value, f"Lambda env var {key} for {func_name}", findings, {
                            "resource_type": "lambda_function",
                            "resource_id": func_name,
                            "variable_name": key,
                        })

        except botocore.exceptions.ClientError as e:
            self.handle_client_error(e, "ListFunctions")

    async def _scan_secrets_manager(self, scan_id: str, findings: list, result: ScanResult) -> None:
        """Scan Secrets Manager for rotation status and access."""
        try:
            paginator = self.client.get_paginator("list_secrets")
            for page in paginator.paginate():
                for secret in page.get("SecretList", []):
                    result.resources_found += 1
                    secret_name = secret["Name"]
                    secret_arn = secret["ARN"]

                    # Check rotation status
                    rotation_enabled = secret.get("RotationEnabled", False)
                    if not rotation_enabled:
                        findings.append(self.create_finding(
                            title=f"Secrets Manager secret {secret_name} has rotation disabled",
                            description="Secret rotation is not enabled",
                            severity="medium",
                            category="weak_configuration",
                            resource_type="secretsmanager_secret",
                            resource_id=secret_arn,
                            resource_name=secret_name,
                            region=self.region,
                            remediation={
                                "summary": "Enable automatic rotation",
                                "steps": [
                                    "Create Lambda rotation function",
                                    "Configure secret rotation schedule",
                                ],
                                "effort": "medium",
                                "automatable": True,
                            },
                            rule_id="secretsmanager_rotation_disabled",
                        ))

                    # Check for secrets with no KMS encryption
                    kms_key = secret.get("KmsKeyId")
                    if not kms_key:
                        findings.append(self.create_finding(
                            title=f"Secrets Manager secret {secret_name} uses default encryption",
                            description="Secret is encrypted with AWS managed key instead of customer managed key",
                            severity="low",
                            category="weak_configuration",
                            resource_type="secretsmanager_secret",
                            resource_id=secret_arn,
                            resource_name=secret_name,
                            region=self.region,
                            rule_id="secretsmanager_aws_managed_key",
                        ))

                    # Check last rotation date
                    last_rotated = secret.get("LastRotatedDate")
                    if last_rotated:
                        from datetime import datetime, timezone
                        days_since = (datetime.now(timezone.utc) - last_rotated.replace(tzinfo=timezone.utc)).days
                        if days_since > 90:
                            findings.append(self.create_finding(
                                title=f"Secrets Manager secret {secret_name} not rotated in {days_since} days",
                                description=f"Secret was last rotated {days_since} days ago",
                                severity="medium",
                                category="weak_configuration",
                                resource_type="secretsmanager_secret",
                                resource_id=secret_arn,
                                resource_name=secret_name,
                                region=self.region,
                                rule_id="secretsmanager_stale_rotation",
                            ))

        except botocore.exceptions.ClientError as e:
            self.handle_client_error(e, "ListSecrets")

    async def _scan_ssm_parameters(self, scan_id: str, findings: list, result: ScanResult) -> None:
        """Scan SSM Parameter Store for insecure parameters."""
        try:
            paginator = self.client.get_paginator("describe_parameters")
            for page in paginator.paginate():
                for param in page.get("Parameters", []):
                    result.resources_found += 1
                    param_name = param["Name"]
                    param_type = param.get("Type", "String")

                    # Check for SecureString parameters
                    if param_type != "SecureString":
                        # Try to get value to scan for secrets
                        try:
                            param_response = self.client.get_parameters(Names=[param_name], WithDecryption=True)
                            for p in param_response.get("Parameters", []):
                                value = p.get("Value", "")
                                self._scan_content(value, f"SSM parameter {param_name}", findings, {
                                    "resource_type": "ssm_parameter",
                                    "resource_id": param_name,
                                    "parameter_type": param_type,
                                })
                        except botocore.exceptions.ClientError:
                            pass
                    else:
                        # Check if using default KMS key
                        key_id = param.get("KeyId")
                        if not key_id or key_id == "alias/aws/ssm":
                            findings.append(self.create_finding(
                                title=f"SSM parameter {param_name} uses default KMS key",
                                description="SecureString parameter uses AWS managed key instead of customer managed key",
                                severity="low",
                                category="weak_configuration",
                                resource_type="ssm_parameter",
                                resource_id=param_name,
                                resource_name=param_name,
                                region=self.region,
                                rule_id="ssm_parameter_aws_managed_key",
                            ))

        except botocore.exceptions.ClientError as e:
            self.handle_client_error(e, "DescribeParameters")

    async def _scan_codebuild_projects(self, scan_id: str, findings: list, result: ScanResult) -> None:
        """Scan CodeBuild projects for secrets in environment."""
        try:
            paginator = self.client.get_paginator("list_projects")
            for page in paginator.paginate():
                for project_name in page.get("projects", []):
                    result.resources_found += 1

                    try:
                        project_response = self.client.batch_get_projects(names=[project_name])
                        for project in project_response.get("projects", []):
                            env = project.get("environment", {})
                            env_vars = env.get("environmentVariables", [])

                            for var in env_vars:
                                name = var.get("name", "")
                                value = var.get("value", "")
                                var_type = var.get("type", "PLAINTEXT")

                                if var_type == "PLAINTEXT":
                                    self._scan_content(value, f"CodeBuild env var {name} for {project_name}", findings, {
                                        "resource_type": "codebuild_project",
                                        "resource_id": project_name,
                                        "variable_name": name,
                                    })
                                elif var_type == "SECRETS_MANAGER" or var_type == "PARAMETER_STORE":
                                    # These are references, not actual secrets - check they're valid
                                    pass
                    except botocore.exceptions.ClientError:
                        pass

        except botocore.exceptions.ClientError as e:
            self.handle_client_error(e, "ListProjects")

    async def _scan_ecs_task_definitions(self, scan_id: str, findings: list, result: ScanResult) -> None:
        """Scan ECS task definitions for secrets in environment variables."""
        try:
            # List task definition families
            paginator = self.client.get_paginator("list_task_definition_families")
            for page in paginator.paginate():
                for family in page.get("families", []):
                    # Get latest task definition
                    try:
                        td_response = self.client.describe_task_definition(taskDefinition=family)
                        td = td_response.get("taskDefinition", {})
                        result.resources_found += 1

                        container_defs = td.get("containerDefinitions", [])
                        for container in container_defs:
                            # Check environment variables
                            env_vars = container.get("environment", [])
                            for var in env_vars:
                                name = var.get("name", "")
                                value = var.get("value", "")
                                self._scan_content(value, f"ECS task env var {name} for {family}", findings, {
                                    "resource_type": "ecs_task_definition",
                                    "resource_id": family,
                                    "container_name": container.get("name", ""),
                                    "variable_name": name,
                                })

                            # Check secrets
                            secrets = container.get("secrets", [])
                            for secret in secrets:
                                name = secret.get("name", "")
                                value_from = secret.get("valueFrom", "")
                                # This is a reference to Secrets Manager or SSM - just note it
                                if "secretsmanager" in value_from or "ssm" in value_from:
                                    pass  # Valid reference
                                else:
                                    findings.append(self.create_finding(
                                        title=f"ECS task {family} container {container.get('name')} has unknown secret reference",
                                        description=f"Secret {name} references unknown source: {value_from}",
                                        severity="medium",
                                        category="weak_configuration",
                                        resource_type="ecs_task_definition",
                                        resource_id=family,
                                        resource_name=family,
                                        region=self.region,
                                        rule_id="ecs_unknown_secret_ref",
                                    ))
                    except botocore.exceptions.ClientError:
                        pass

        except botocore.exceptions.ClientError as e:
            self.handle_client_error(e, "ListTaskDefinitionFamilies")

    def _scan_content(self, content: str, context: str, findings: list, resource_info: dict) -> None:
        """Scan content for secret patterns."""
        if not content or not isinstance(content, str):
            return

        for pattern, secret_type in self.SECRET_PATTERNS:
            matches = pattern.findall(content)
            if matches:
                # Redact the actual secret in the finding
                redacted_content = pattern.sub(r'\1=***REDACTED***', content)

                # Limit context for display
                display_content = redacted_content[:500] + ("..." if len(redacted_content) > 500 else "")

                findings.append(self.create_finding(
                    title=f"Potential {secret_type} found in {context}",
                    description=f"Detected pattern matching {secret_type} in {context}",
                    severity="high",
                    category="credential_exposure",
                    resource_type=resource_info.get("resource_type", "unknown"),
                    resource_id=resource_info.get("resource_id", "unknown"),
                    resource_name=resource_info.get("resource_id", "unknown"),
                    region=self.region,
                    evidence=[{
                        "type": "secret_detection",
                        "description": f"Found {secret_type} pattern",
                        "data": {
                            "context": context,
                            "pattern": secret_type,
                            "redacted_snippet": display_content,
                        }
                    }],
                    remediation={
                        "summary": "Remove secret and rotate credentials",
                        "steps": [
                            "Remove the secret from the source",
                            "Rotate the exposed credential",
                            "Store secrets in Secrets Manager or Parameter Store",
                            "Use IAM roles instead of hardcoded credentials",
                        ],
                        "effort": "high",
                        "automatable": False,
                    },
                    rule_id=f"secret_hunter_{secret_type.lower().replace(' ', '_').replace('/', '_')}",
                ))

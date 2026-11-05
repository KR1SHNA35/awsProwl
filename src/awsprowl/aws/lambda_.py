"""Lambda scanner for awsProwl."""

from __future__ import annotations

import asyncio
import hashlib
import json

import botocore.exceptions

from awsprowl.aws.base import AWSServiceBase, ScanResult
from awsprowl.core.auth import AWSAuthManager
from awsprowl.core.logging import get_logger

log = get_logger(__name__)


class LambdaScanner(AWSServiceBase):
    """Scanner for Lambda resources."""

    SERVICE_NAME = "lambda"
    REQUIRED_PERMISSIONS = [
        "lambda:ListFunctions",
        "lambda:GetFunction",
        "lambda:GetFunctionConfiguration",
        "lambda:GetPolicy",
        "lambda:GetFunctionUrlConfig",
        "lambda:ListFunctionUrlConfigs",
        "lambda:ListAliases",
        "lambda:ListVersionsByFunction",
        "lambda:ListEventSourceMappings",
        "lambda:GetEventSourceMapping",
        "lambda:ListLayers",
        "lambda:ListLayerVersions",
        "lambda:GetLayerVersion",
        "lambda:GetLayerVersionPolicy",
        "lambda:ListCodeSigningConfigs",
        "lambda:GetCodeSigningConfig",
        "lambda:GetFunctionConcurrency",
        "lambda:GetAccountConcurrency",
        "iam:GetRole",
        "iam:GetRolePolicy",
        "iam:ListAttachedRolePolicies",
    ]

    def __init__(self, auth_manager: AWSAuthManager, region: str | None = None):
        super().__init__(auth_manager, region)

    async def scan(self, scan_id: str, findings: list) -> ScanResult:
        """Scan Lambda resources for security issues."""
        result = ScanResult(service=self.SERVICE_NAME, region=self.region)

        try:
            await asyncio.gather(
                self._scan_functions(scan_id, findings, result),
                self._scan_layers(scan_id, findings, result),
                self._scan_function_urls(scan_id, findings, result),
                self._scan_aliases_versions(scan_id, findings, result),
                self._scan_event_source_mappings(scan_id, findings, result),
                self._scan_code_signing_configs(scan_id, findings, result),
                self._scan_account_concurrency(scan_id, findings, result),
                return_exceptions=True,
            )

        except Exception as e:
            log.error("Error in Lambda scan: {}", e)
            result.errors.append(str(e))

        return result

    async def _scan_functions(self, scan_id: str, findings: list, result: ScanResult) -> None:
        """Scan Lambda functions."""
        try:
            paginator = self.client.get_paginator("list_functions")
            for page in paginator.paginate():
                for function in page.get("Functions", []):
                    result.resources_found += 1
                    await self._analyze_function(function, scan_id, findings)

        except botocore.exceptions.ClientError as e:
            self.handle_client_error(e, "ListFunctions", findings)

    async def _analyze_function(self, function: dict, scan_id: str, findings: list) -> None:
        """Analyze a single Lambda function for security issues."""
        function_name = function["FunctionName"]
        function_arn = function["FunctionArn"]
        runtime = function.get("Runtime", "")
        role_arn = function.get("Role", "")
        handler = function.get("Handler", "")
        memory_size = function.get("MemorySize", 128)
        timeout = function.get("Timeout", 3)
        last_modified = function.get("LastModified", "")
        code_size = function.get("CodeSize", 0)

        # Add enumeration finding for the function
        await self._add_enumeration_finding("lambda_function", function_name, function_name, {
            "arn": function_arn,
            "runtime": runtime,
            "handler": handler,
            "memory_size": memory_size,
            "timeout": timeout,
            "last_modified": last_modified,
            "code_size": code_size,
            "role_arn": role_arn,
        }, findings, scan_id)

        # Check for deprecated runtimes
        deprecated_runtimes = [
            "nodejs", "nodejs4.3", "nodejs6.10", "nodejs8.10", "nodejs10.x", "nodejs12.x",
            "python2.7", "python3.6", "python3.7",
            "ruby2.5", "ruby2.7",
            "java8", "java8.al2",
            "go1.x",
            "dotnetcore1.0", "dotnetcore2.0", "dotnetcore2.1", "dotnetcore3.1",
            "provided", "provided.al2",
        ]

        if runtime in deprecated_runtimes:
            self._add_finding_deduped(findings, self.create_finding(
                title=f"Lambda function {function_name} uses deprecated runtime: {runtime}",
                description=f"Function uses deprecated runtime {runtime} which may have unpatched vulnerabilities",
                severity="high",
                category="vulnerable_configuration",
                resource_type="lambda_function",
                resource_id=function_name,
                resource_name=function_name,
                region=self.region,
                evidence=[{"type": "function_config", "description": "Runtime configuration", "data": {"runtime": runtime}}],
                remediation={
                    "summary": "Upgrade to supported runtime",
                    "steps": [
                        "Identify supported runtime version",
                        "Test function with new runtime",
                        "Update function configuration",
                    ],
                    "effort": "medium",
                    "automatable": False,
                },
                rule_id="lambda_deprecated_runtime",
            ))

        # Check function policy for public access
        await self._check_function_policy(function_name, function_arn, scan_id, findings)

        # Check environment variables for secrets
        await self._check_environment_variables(function_name, scan_id, findings)

        # Check IAM role permissions
        await self._check_function_role(role_arn, function_name, scan_id, findings)

        # Check VPC configuration
        vpc_config = function.get("VpcConfig", {})
        if vpc_config.get("VpcId"):
            vpc_id = vpc_config["VpcId"]
            subnet_ids = vpc_config.get("SubnetIds", [])
            sg_ids = vpc_config.get("SecurityGroupIds", [])

            # Check if subnets are private (no direct internet access)
            # This is informational - functions in public subnets can still be secure
            if subnet_ids:
                try:
                    ec2 = self.session.client("ec2", region_name=self.region)
                    for subnet_id in subnet_ids:
                        subnet_info = ec2.describe_subnets(SubnetIds=[subnet_id])
                        for subnet in subnet_info.get("Subnets", []):
                            map_public = subnet.get("MapPublicIpOnLaunch", False)
                            if map_public:
                                self._add_finding_deduped(findings, self.create_finding(
                                    title=f"Lambda function {function_name} uses public subnet {subnet_id}",
                                    description=f"Function is configured with subnet {subnet_id} that assigns public IPs. Functions in public subnets have direct internet access.",
                                    severity="medium",
                                    category="network_exposure",
                                    resource_type="lambda_function",
                                    resource_id=function_name,
                                    resource_name=function_name,
                                    region=self.region,
                                    evidence=[{"type": "vpc_config", "description": "Public subnet configuration", "data": {"vpc_id": vpc_id, "subnet_id": subnet_id, "map_public_ip_on_launch": map_public}}],
                                    remediation={
                                        "summary": "Move Lambda to private subnets with NAT Gateway",
                                        "steps": [
                                            "Create private subnets in VPC",
                                            "Configure NAT Gateway in public subnet",
                                            "Update Lambda VPC configuration to use private subnets",
                                        ],
                                        "effort": "medium",
                                        "automatable": False,
                                    },
                                    rule_id="lambda_public_subnet",
                                ))
                except Exception:
                    pass

            # Check security groups for overly permissive rules
            if sg_ids:
                try:
                    ec2 = self.session.client("ec2", region_name=self.region)
                    for sg_id in sg_ids:
                        sg_info = ec2.describe_security_groups(GroupIds=[sg_id])
                        for sg in sg_info.get("SecurityGroups", []):
                            for rule in sg.get("IpPermissions", []):
                                for ip_range in rule.get("IpRanges", []):
                                    if ip_range.get("CidrIp") == "0.0.0.0/0":
                                        from_port = rule.get("FromPort", 0)
                                        to_port = rule.get("ToPort", 65535)
                                        if from_port <= 22 <= to_port or from_port == 0:
                                            self._add_finding_deduped(findings, self.create_finding(
                                                title=f"Lambda function {function_name} security group {sg_id} allows unrestricted inbound access",
                                                description=f"Security group {sg_id} allows 0.0.0.0/0 on port range {from_port}-{to_port}",
                                                severity="high",
                                                category="network_exposure",
                                                resource_type="lambda_function",
                                                resource_id=function_name,
                                                resource_name=function_name,
                                                region=self.region,
                                                evidence=[{"type": "security_group_rule", "description": "Overly permissive inbound rule", "data": {"sg_id": sg_id, "cidr": "0.0.0.0/0", "from_port": from_port, "to_port": to_port}}],
                                                remediation={
                                                    "summary": "Restrict security group inbound rules",
                                                    "steps": [
                                                        "Identify required inbound ports/sources",
                                                        "Update security group rules to specific CIDRs",
                                                    ],
                                                    "effort": "low",
                                                    "automatable": True,
                                                },
                                                rule_id="lambda_sg_unrestricted_inbound",
                                            ))
                except Exception:
                    pass
        else:
            # No VPC configured - function has public internet access by default
            self._add_finding_deduped(findings, self.create_finding(
                title=f"Lambda function {function_name} is not configured with VPC",
                description="Function has no VPC configuration, meaning it has public internet access and cannot access VPC resources (RDS, ElastiCache, etc.)",
                severity="info",
                category="network_configuration",
                resource_type="lambda_function",
                resource_id=function_name,
                resource_name=function_name,
                region=self.region,
                remediation={
                    "summary": "Configure VPC if function needs private resource access",
                    "steps": [
                        "Determine if function needs VPC access",
                        "If yes, configure VPC, subnets, and security groups",
                        "Ensure NAT Gateway for outbound internet access",
                    ],
                    "effort": "medium",
                    "automatable": False,
                },
                rule_id="lambda_no_vpc",
            ))

        # Check tracing
        tracing = function.get("TracingConfig", {}).get("Mode", "PassThrough")
        if tracing == "PassThrough":
            self._add_finding_deduped(findings, self.create_finding(
                title=f"Lambda function {function_name} does not have active tracing",
                description="X-Ray active tracing is not enabled, limiting observability",
                severity="low",
                category="logging_missing",
                resource_type="lambda_function",
                resource_id=function_name,
                resource_name=function_name,
                region=self.region,
                remediation={
                    "summary": "Enable X-Ray active tracing",
                    "steps": [
                        "Enable active tracing in function configuration",
                        "Ensure X-Ray daemon permissions in role",
                    ],
                    "effort": "low",
                    "automatable": True,
                    "cli_commands": [
                        f"aws lambda update-function-configuration --function-name {function_name} --tracing-config Mode=Active",
                    ],
                },
                rule_id="lambda_tracing_disabled",
            ))

        # Check for reserved concurrency (DoS protection)
        try:
            concurrency = self.client.get_function_concurrency(FunctionName=function_name)
            if "ReservedConcurrentExecutions" not in concurrency:
                self._add_finding_deduped(findings, self.create_finding(
                    title=f"Lambda function {function_name} has no reserved concurrency limit",
                    description="Function has no reserved concurrency, could consume all account concurrency",
                    severity="medium",
                    category="dos_risk",
                    resource_type="lambda_function",
                    resource_id=function_name,
                    resource_name=function_name,
                    region=self.region,
                    remediation={
                        "summary": "Set reserved concurrency limit",
                        "steps": [
                            "Determine appropriate concurrency limit",
                            "Configure reserved concurrency",
                        ],
                        "effort": "low",
                        "automatable": True,
                    },
                    rule_id="lambda_no_concurrency_limit",
                ))
        except botocore.exceptions.ClientError:
            pass

    async def _check_function_policy(self, function_name: str, function_arn: str, scan_id: str, findings: list) -> None:
        """Check Lambda function resource policy."""
        try:
            policy = self.client.get_policy(FunctionName=function_name)
            policy_doc = json.loads(policy["Policy"])

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
                if principal == "*" or principal.get("Service") == "*" or principal.get("AWS") == "*":
                    self._add_finding_deduped(findings, self.create_finding(
                        title=f"Lambda function {function_name} has public resource policy",
                        description="Function policy allows invocation by any principal",
                        severity="critical",
                        category="data_exposure",
                        resource_type="lambda_function",
                        resource_id=function_name,
                        resource_name=function_name,
                        region=self.region,
                        evidence=[{"type": "function_policy", "description": "Public function policy", "data": policy_doc}],
                        remediation={
                            "summary": "Restrict function policy to specific principals",
                            "steps": [
                                "Identify required invokers (API Gateway, EventBridge, etc.)",
                                "Update policy with specific service/principal ARNs",
                                "Add SourceArn/SourceAccount conditions",
                            ],
                            "effort": "medium",
                            "automatable": False,
                        },
                        rule_id="lambda_public_policy",
                    ))

                # Check for cross-account access without conditions
                if principal.get("AWS"):
                    aws_principals = principal["AWS"]
                    if isinstance(aws_principals, str):
                        aws_principals = [aws_principals]

                    for p in aws_principals:
                        if p.startswith("arn:aws:iam::") and ":root" in p:
                            condition = stmt.get("Condition", {})
                            if not condition:
                                self._add_finding_deduped(findings, self.create_finding(
                                    title=f"Lambda function {function_name} allows cross-account root access without conditions",
                                    description=f"Function policy allows {p} to invoke without source restrictions",
                                    severity="high",
                                    category="cross_account_access",
                                    resource_type="lambda_function",
                                    resource_id=function_name,
                                    resource_name=function_name,
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
                                    rule_id="lambda_cross_account_no_condition",
                                ))

        except botocore.exceptions.ClientError as e:
            if e.response["Error"]["Code"] != "ResourceNotFoundException":
                pass

    async def _check_environment_variables(self, function_name: str, scan_id: str, findings: list) -> None:
        """Check function environment variables for secrets."""
        try:
            config = self.client.get_function_configuration(FunctionName=function_name)
            env_vars = config.get("Environment", {}).get("Variables", {})

            secret_keywords = [
                "password", "secret", "key", "token", "api_key", "apikey",
                "access_key", "secret_key", "private_key", "cert",
                "connection_string", "conn_string", "database_url", "db_password",
            ]

            for key, value in env_vars.items():
                if any(kw in key.lower() for kw in secret_keywords):
                    self._add_finding_deduped(findings, self.create_finding(
                        title=f"Lambda function {function_name} has potential secret in environment variable: {key}",
                        description=f"Environment variable {key} appears to contain sensitive data",
                        severity="high",
                        category="secrets_exposure",
                        resource_type="lambda_function",
                        resource_id=function_name,
                        resource_name=function_name,
                        region=self.region,
                        evidence=[{"type": "environment_variable", "description": f"Env var {key}", "data": {"key": key, "value_preview": value[:20] + "..." if len(value) > 20 else value}}],
                        remediation={
                            "summary": "Move secrets to AWS Secrets Manager or Parameter Store",
                            "steps": [
                                "Create secret in Secrets Manager",
                                "Grant function role permission to read secret",
                                "Update function code to fetch secret at runtime",
                                "Remove secret from environment variables",
                            ],
                            "effort": "medium",
                            "automatable": False,
                        },
                        rule_id="lambda_env_var_secret",
                    ))

        except botocore.exceptions.ClientError:
            pass

    async def _check_function_role(self, role_arn: str, function_name: str, scan_id: str, findings: list) -> None:
        """Check Lambda function's IAM role for excessive permissions."""
        if not role_arn:
            return

        try:
            role_name = role_arn.split("/")[-1]

            # Get inline policies
            inline = self.client.list_role_policies(RoleName=role_name)
            for policy_name in inline.get("PolicyNames", []):
                policy = self.client.get_role_policy(RoleName=role_name, PolicyName=policy_name)
                await self._check_policy_document(policy["PolicyDocument"], f"lambda_role/{role_name}/inline/{policy_name}", function_name, scan_id, findings)

            # Get attached policies
            attached = self.client.list_attached_role_policies(RoleName=role_name)
            for policy in attached.get("AttachedPolicies", []):
                policy_detail = self.client.get_policy(PolicyArn=policy["PolicyArn"])
                version = self.client.get_policy_version(
                    PolicyArn=policy["PolicyArn"],
                    VersionId=policy_detail["Policy"]["DefaultVersionId"],
                )
                await self._check_policy_document(version["PolicyVersion"]["Document"], f"lambda_role/{role_name}/attached/{policy['PolicyName']}", function_name, scan_id, findings)

        except botocore.exceptions.ClientError:
            pass

    async def _check_policy_document(self, policy_doc: dict, policy_id: str, function_name: str, scan_id: str, findings: list) -> None:
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

            # Check for wildcard action + wildcard resource
            has_wildcard_action = "*" in actions or any(a.endswith("*") for a in actions)
            has_wildcard_resource = "*" in resources

            if has_wildcard_action and has_wildcard_resource:
                self._add_finding_deduped(findings, self.create_finding(
                    title=f"Lambda function {function_name} role has overly permissive policy: {policy_id}",
                    description="Role policy allows all actions on all resources (full admin access)",
                    severity="critical",
                    category="excessive_permissions",
                    resource_type="lambda_function",
                    resource_id=function_name,
                    resource_name=function_name,
                    region=self.region,
                    evidence=[{"type": "role_policy", "description": f"Overly permissive policy {policy_id}", "data": policy_doc}],
                    remediation={
                        "summary": "Apply least privilege to Lambda role",
                        "steps": [
                            "Identify minimum required permissions",
                            "Create new policy with specific actions and resources",
                            "Attach new policy and remove overly permissive one",
                        ],
                        "effort": "medium",
                        "automatable": False,
                    },
                    rule_id="lambda_role_wildcard_policy",
                ))

    async def _scan_layers(self, scan_id: str, findings: list, result: ScanResult) -> None:
        """Scan Lambda layers."""
        try:
            # First list all layers
            paginator = self.client.get_paginator("list_layers")
            for page in paginator.paginate():
                for layer in page.get("Layers", []):
                    layer_name = layer["LayerName"]
                    layer_arn = layer["LayerArn"]
                    result.resources_found += 1

                    # Get latest layer version
                    try:
                        versions = self.client.list_layer_versions(LayerName=layer_name)
                        layer_versions = versions.get("LayerVersions", [])
                        if not layer_versions:
                            continue

                        latest_version = layer_versions[0]
                        version_number = latest_version["Version"]
                        version_arn = latest_version["LayerVersionArn"]
                        compatible_runtimes = latest_version.get("CompatibleRuntimes", [])
                        license_info = latest_version.get("LicenseInfo", "")
                        created_date = latest_version.get("CreatedDate", "")

                        # Add enumeration finding for the layer
                        await self._add_enumeration_finding("lambda_layer", layer_name, layer_name, {
                            "arn": layer_arn,
                            "latest_version": version_number,
                            "version_arn": version_arn,
                            "compatible_runtimes": compatible_runtimes,
                            "license_info": license_info,
                            "created_date": created_date,
                        }, findings, scan_id)

                        # Check for deprecated runtimes in layer compatibility
                        deprecated_runtimes = [
                            "nodejs", "nodejs4.3", "nodejs6.10", "nodejs8.10", "nodejs10.x", "nodejs12.x",
                            "python2.7", "python3.6", "python3.7",
                            "ruby2.5", "ruby2.7",
                            "java8", "java8.al2",
                            "go1.x",
                            "dotnetcore1.0", "dotnetcore2.0", "dotnetcore2.1", "dotnetcore3.1",
                            "provided", "provided.al2",
                        ]

                        deprecated_in_layer = [rt for rt in compatible_runtimes if rt in deprecated_runtimes]
                        if deprecated_in_layer:
                            self._add_finding_deduped(findings, self.create_finding(
                                title=f"Lambda layer {layer_name} (v{version_number}) supports deprecated runtimes",
                                description=f"Layer is compatible with deprecated runtimes: {', '.join(deprecated_in_layer)}",
                                severity="medium",
                                category="vulnerable_configuration",
                                resource_type="lambda_layer",
                                resource_id=layer_name,
                                resource_name=layer_name,
                                region=self.region,
                                evidence=[{"type": "layer_config", "description": "Compatible runtimes", "data": {"layer_arn": layer_arn, "version": version_number, "deprecated_runtimes": deprecated_in_layer, "all_runtimes": compatible_runtimes}}],
                                remediation={
                                    "summary": "Update layer to support current runtimes",
                                    "steps": [
                                        "Create new layer version with updated runtimes",
                                        "Update functions using this layer",
                                    ],
                                    "effort": "medium",
                                    "automatable": False,
                                },
                                rule_id="lambda_layer_deprecated_runtimes",
                            ))

                        # Check layer permissions
                        try:
                            policy = self.client.get_layer_version_policy(LayerName=layer_name, VersionNumber=version_number)
                            policy_doc = json.loads(policy.get("Policy", "{}"))
                            statements = policy_doc.get("Statement", [])
                            if not isinstance(statements, list):
                                statements = [statements]

                            for stmt in statements:
                                if stmt.get("Effect") != "Allow":
                                    continue
                                principal = stmt.get("Principal", {})
                                if principal == "*" or principal.get("AWS") == "*":
                                    self._add_finding_deduped(findings, self.create_finding(
                                        title=f"Lambda layer {layer_name} (v{version_number}) has public policy",
                                        description="Layer version policy allows access from any principal",
                                        severity="critical",
                                        category="data_exposure",
                                        resource_type="lambda_layer",
                                        resource_id=layer_name,
                                        resource_name=layer_name,
                                        region=self.region,
                                        evidence=[{"type": "layer_policy", "description": "Public layer policy", "data": policy_doc}],
                                        remediation={
                                            "summary": "Restrict layer policy to specific accounts/principals",
                                            "steps": [
                                                "Identify required accounts/principals",
                                                "Update layer policy with specific ARNs",
                                            ],
                                            "effort": "low",
                                            "automatable": True,
                                        },
                                        rule_id="lambda_layer_public_policy",
                                    ))

                        except botocore.exceptions.ClientError as e:
                            if e.response["Error"]["Code"] != "ResourceNotFoundException":
                                pass

                    except botocore.exceptions.ClientError:
                        pass

        except botocore.exceptions.ClientError as e:
            self.handle_client_error(e, "ListLayers", findings)

    async def _scan_function_urls(self, scan_id: str, findings: list, result: ScanResult) -> None:
        """Scan Lambda Function URLs for public access."""
        try:
            paginator = self.client.get_paginator("list_function_url_configs")
            for page in paginator.paginate():
                for url_config in page.get("FunctionUrlConfigs", []):
                    result.resources_found += 1
                    function_name = url_config["FunctionName"]
                    function_url = url_config["FunctionUrl"]
                    auth_type = url_config.get("AuthType", "NONE")
                    cors = url_config.get("Cors", {})

                    await self._add_enumeration_finding("lambda_function_url", function_name, function_name, {
                        "function_url": function_url,
                        "auth_type": auth_type,
                        "cors": cors,
                        "creation_time": url_config.get("CreationTime", ""),
                        "last_modified_time": url_config.get("LastModifiedTime", ""),
                    }, findings, scan_id)

                    if auth_type == "NONE":
                        self._add_finding_deduped(findings, self.create_finding(
                            title=f"Lambda function {function_name} has public Function URL (no auth)",
                            description=f"Function URL {function_url} allows unauthenticated invocation",
                            severity="critical",
                            category="data_exposure",
                            resource_type="lambda_function",
                            resource_id=function_name,
                            resource_name=function_name,
                            region=self.region,
                            evidence=[{"type": "function_url", "description": "Public function URL", "data": url_config}],
                            remediation={
                                "summary": "Require authentication for Function URL",
                                "steps": [
                                    "Update Function URL auth type to AWS_IAM",
                                    "Configure IAM policies for authorized invokers",
                                ],
                                "effort": "low",
                                "automatable": True,
                                "cli_commands": [
                                    f"aws lambda update-function-url-config --function-name {function_name} --auth-type AWS_IAM",
                                ],
                            },
                            rule_id="lambda_function_url_public",
                        ))

                    # Check CORS configuration
                    allowed_origins = cors.get("AllowedOrigins", [])
                    if "*" in allowed_origins:
                        self._add_finding_deduped(findings, self.create_finding(
                            title=f"Lambda function {function_name} Function URL has wildcard CORS origin",
                            description="Function URL CORS allows any origin (*)",
                            severity="medium",
                            category="weak_configuration",
                            resource_type="lambda_function",
                            resource_id=function_name,
                            resource_name=function_name,
                            region=self.region,
                            evidence=[{"type": "function_url_cors", "description": "Wildcard CORS origin", "data": cors}],
                            remediation={
                                "summary": "Restrict CORS to specific origins",
                                "steps": [
                                    "Identify required origins",
                                    "Update Function URL CORS configuration",
                                ],
                                "effort": "low",
                                "automatable": True,
                            },
                            rule_id="lambda_function_url_cors_wildcard",
                        ))

        except botocore.exceptions.ClientError as e:
            if e.response["Error"]["Code"] != "ResourceNotFoundException":
                self.handle_client_error(e, "ListFunctionUrlConfigs", findings)

    async def _scan_aliases_versions(self, scan_id: str, findings: list, result: ScanResult) -> None:
        """Scan Lambda function aliases and versions."""
        try:
            paginator = self.client.get_paginator("list_functions")
            for page in paginator.paginate():
                for function in page.get("Functions", []):
                    function_name = function["FunctionName"]
                    function_arn = function["FunctionArn"]

                    # List aliases
                    try:
                        aliases = self.client.list_aliases(FunctionName=function_name)
                        for alias in aliases.get("Aliases", []):
                            result.resources_found += 1
                            alias_name = alias["Name"]
                            alias_arn = alias["AliasArn"]
                            version = alias["FunctionVersion"]
                            description = alias.get("Description", "")
                            routing_config = alias.get("RoutingConfig", {})

                            await self._add_enumeration_finding("lambda_alias", f"{function_name}/{alias_name}", alias_name, {
                                "function_name": function_name,
                                "arn": alias_arn,
                                "version": version,
                                "description": description,
                                "routing_config": routing_config,
                            }, findings, scan_id)

                            # Check for weighted aliases (canary deployments)
                            if routing_config.get("AdditionalVersionWeights"):
                                self._add_finding_deduped(findings, self.create_finding(
                                    title=f"Lambda alias {alias_name} has weighted routing (canary)",
                                    description=f"Alias routes traffic to multiple versions: {routing_config}",
                                    severity="info",
                                    category="enumeration",
                                    resource_type="lambda_alias",
                                    resource_id=f"{function_name}/{alias_name}",
                                    resource_name=alias_name,
                                    region=self.region,
                                    rule_id="lambda_alias_weighted_routing",
                                ))

                    except botocore.exceptions.ClientError as e:
                        if e.response["Error"]["Code"] != "ResourceNotFoundException":
                            pass

                    # List versions
                    try:
                        versions = self.client.list_versions_by_function(FunctionName=function_name)
                        for version in versions.get("Versions", []):
                            if version["Version"] == "$LATEST":
                                continue
                            result.resources_found += 1
                            version_arn = version["FunctionArn"]
                            await self._add_enumeration_finding("lambda_version", f"{function_name}/{version['Version']}", version["Version"], {
                                "function_name": function_name,
                                "arn": version_arn,
                                "description": version.get("Description", ""),
                                "last_modified": version.get("LastModified", ""),
                                "code_sha256": version.get("CodeSha256", ""),
                            }, findings, scan_id)
                    except botocore.exceptions.ClientError as e:
                        if e.response["Error"]["Code"] != "ResourceNotFoundException":
                            pass

        except botocore.exceptions.ClientError as e:
            self.handle_client_error(e, "ListFunctions/ListAliases/ListVersions", findings)

    async def _scan_event_source_mappings(self, scan_id: str, findings: list, result: ScanResult) -> None:
        """Scan Lambda event source mappings."""
        try:
            paginator = self.client.get_paginator("list_event_source_mappings")
            for page in paginator.paginate():
                for mapping in page.get("EventSourceMappings", []):
                    result.resources_found += 1
                    uuid = mapping["UUID"]
                    function_arn = mapping.get("FunctionArn", "")
                    event_source_arn = mapping.get("EventSourceArn", "")
                    state = mapping.get("State", "")
                    batch_size = mapping.get("BatchSize", 0)
                    starting_position = mapping.get("StartingPosition", "")
                    maximum_batching_window = mapping.get("MaximumBatchingWindowInSeconds", 0)
                    destination_config = mapping.get("DestinationConfig", {})

                    await self._add_enumeration_finding("lambda_event_source_mapping", uuid, uuid, {
                        "function_arn": function_arn,
                        "event_source_arn": event_source_arn,
                        "state": state,
                        "batch_size": batch_size,
                        "starting_position": starting_position,
                        "maximum_batching_window": maximum_batching_window,
                        "destination_config": destination_config,
                        "topics": mapping.get("Topics", []),
                        "queues": mapping.get("Queues", []),
                    }, findings, scan_id)

                    # Check for disabled mappings
                    if state == "Disabled":
                        self._add_finding_deduped(findings, self.create_finding(
                            title=f"Lambda event source mapping {uuid} is disabled",
                            description=f"Event source mapping for {event_source_arn} is disabled",
                            severity="medium",
                            category="weak_configuration",
                            resource_type="lambda_event_source_mapping",
                            resource_id=uuid,
                            resource_name=uuid,
                            region=self.region,
                            remediation={
                                "summary": "Enable or remove disabled event source mapping",
                                "steps": [
                                    "Determine if mapping should be enabled",
                                    "Enable mapping or delete if unused",
                                ],
                                "effort": "low",
                                "automatable": True,
                            },
                            rule_id="lambda_esm_disabled",
                        ))

                    # Check for missing DLQ on failure
                    if not destination_config.get("OnFailure"):
                        self._add_finding_deduped(findings, self.create_finding(
                            title=f"Lambda event source mapping {uuid} has no DLQ configured",
                            description="Failed event processing has no destination for failed records",
                            severity="medium",
                            category="data_loss_risk",
                            resource_type="lambda_event_source_mapping",
                            resource_id=uuid,
                            resource_name=uuid,
                            region=self.region,
                            remediation={
                                "summary": "Configure DLQ for failed events",
                                "steps": [
                                    "Create SQS queue or SNS topic for failed events",
                                    "Update event source mapping with OnFailure destination",
                                ],
                                "effort": "medium",
                                "automatable": True,
                            },
                            rule_id="lambda_esm_no_dlq",
                        ))

        except botocore.exceptions.ClientError as e:
            self.handle_client_error(e, "ListEventSourceMappings", findings)

    async def _scan_code_signing_configs(self, scan_id: str, findings: list, result: ScanResult) -> None:
        """Scan Lambda code signing configurations."""
        try:
            paginator = self.client.get_paginator("list_code_signing_configs")
            for page in paginator.paginate():
                for config in page.get("CodeSigningConfigs", []):
                    result.resources_found += 1
                    config_arn = config["CodeSigningConfigArn"]
                    config_id = config_arn.split("/")[-1]
                    allowed_publishers = config.get("AllowedPublishers", {})
                    signing_profiles = allowed_publishers.get("SigningProfileVersionArns", [])
                    policies = config.get("CodeSigningPolicies", {})
                    untrusted_artifacts = policies.get("UntrustedArtifactOnDeployment", "Warn")

                    await self._add_enumeration_finding("lambda_code_signing_config", config_id, config_id, {
                        "arn": config_arn,
                        "signing_profiles": signing_profiles,
                        "untrusted_artifact_policy": untrusted_artifacts,
                        "description": config.get("Description", ""),
                    }, findings, scan_id)

                    # Check for permissive untrusted artifact policy
                    if untrusted_artifacts == "Warn":
                        self._add_finding_deduped(findings, self.create_finding(
                            title=f"Lambda code signing config {config_id} allows untrusted artifacts (Warn mode)",
                            description="Code signing config warns but allows deployment of untrusted artifacts",
                            severity="medium",
                            category="weak_configuration",
                            resource_type="lambda_code_signing_config",
                            resource_id=config_id,
                            resource_name=config_id,
                            region=self.region,
                            remediation={
                                "summary": "Enforce code signing (Enforce mode)",
                                "steps": [
                                    "Update code signing config to Enforce untrusted artifacts",
                                    "Ensure all deployment artifacts are signed",
                                ],
                                "effort": "low",
                                "automatable": True,
                            },
                            rule_id="lambda_code_signing_warn_mode",
                        ))

        except botocore.exceptions.ClientError as e:
            if e.response["Error"]["Code"] != "ResourceNotFoundException":
                self.handle_client_error(e, "ListCodeSigningConfigs", findings)

    async def _scan_account_concurrency(self, scan_id: str, findings: list, result: ScanResult) -> None:
        """Scan account-level Lambda concurrency settings."""
        try:
            concurrency = self.client.get_account_concurrency()
            unreserved = concurrency.get("UnreservedConcurrentExecutions", 0)
            total_limit = 1000  # Default account limit

            await self._add_enumeration_finding("lambda_account_concurrency", "account", "account", {
                "unreserved_concurrency": unreserved,
                "total_account_limit": total_limit,
            }, findings, scan_id)

            if unreserved < 100:
                self._add_finding_deduped(findings, self.create_finding(
                    title="Lambda account has low unreserved concurrency",
                    description=f"Only {unreserved} unreserved concurrent executions available (default limit: {total_limit})",
                    severity="medium",
                    category="dos_risk",
                    resource_type="lambda_account",
                    resource_id="account",
                    resource_name="account",
                    region=self.region,
                    remediation={
                        "summary": "Request concurrency limit increase or optimize usage",
                        "steps": [
                            "Review function concurrency usage",
                            "Set reserved concurrency for critical functions",
                            "Request limit increase from AWS Support if needed",
                        ],
                        "effort": "medium",
                        "automatable": False,
                    },
                    rule_id="lambda_account_low_unreserved_concurrency",
                ))

        except botocore.exceptions.ClientError:
            pass

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
            rule_id=f"lambda_enum_{resource_type}",
        )
        self._add_finding_deduped(findings, finding)

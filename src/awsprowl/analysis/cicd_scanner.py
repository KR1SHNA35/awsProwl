"""CI/CD scanner module for awsProwl."""

from __future__ import annotations

import asyncio

import botocore.exceptions

from awsprowl.aws.base import AWSServiceBase, ScanResult
from awsprowl.core.auth import AWSAuthManager
from awsprowl.core.logging import get_logger

log = get_logger(__name__)


class CICDScanner(AWSServiceBase):
    """Scanner for CI/CD pipeline security issues."""

    SERVICE_NAME = "cicd"
    REQUIRED_PERMISSIONS = [
        "codepipeline:ListPipelines",
        "codepipeline:GetPipeline",
        "codepipeline:GetPipelineState",
        "codebuild:ListProjects",
        "codebuild:BatchGetProjects",
        "codebuild:ListBuildsForProject",
        "codebuild:BatchGetBuilds",
        "codecommit:ListRepositories",
        "codecommit:GetRepository",
        "codecommit:GetBranch",
        "codecommit:ListBranches",
        "codecommit:GetCommit",
        "codecommit:GetDifferences",
        "codecommit:DescribePullRequestEvents",
        "codecommit:ListPullRequests",
        "codecommit:GetPullRequest",
        "codecommit:ListPullRequests",
        "codecommit:GetPullRequestApprovalStates",
        "codecommit:GetPullRequestOverrideState",
    ]

    def __init__(self, auth_manager: AWSAuthManager, region: str | None = None):
        super().__init__(auth_manager, region)

    async def scan(self, scan_id: str, findings: list) -> ScanResult:
        """Scan CI/CD resources for security issues."""
        result = ScanResult(service=self.SERVICE_NAME, region=self.region)

        try:
            await asyncio.gather(
                self._scan_codepipeline(scan_id, findings, result),
                self._scan_codebuild(scan_id, findings, result),
                self._scan_codecommit(scan_id, findings, result),
                return_exceptions=True,
            )

        except Exception as e:
            log.error("Error in CI/CD scan: {}", e)
            result.errors.append(str(e))

        return result

    async def _scan_codepipeline(self, scan_id: str, findings: list, result: ScanResult) -> None:
        """Scan CodePipeline for security issues."""
        try:
            paginator = self.client.get_paginator("list_pipelines")
            for page in paginator.paginate():
                for pipeline_summary in page.get("pipelines", []):
                    result.resources_found += 1
                    pipeline_name = pipeline_summary["name"]

                    pipeline = self.client.get_pipeline(name=pipeline_name).get("pipeline", {})
                    await self._analyze_pipeline(pipeline, scan_id, findings)

        except botocore.exceptions.ClientError as e:
            self.handle_client_error(e, "ListPipelines")

    async def _analyze_pipeline(self, pipeline: dict, scan_id: str, findings: list) -> None:
        """Analyze a CodePipeline."""
        pipeline_name = pipeline.get("name", "")
        stages = pipeline.get("stages", [])
        artifact_store = pipeline.get("artifactStore", {})
        role_arn = pipeline.get("roleArn", "")

        # Check for artifact store encryption
        encryption_key = artifact_store.get("encryptionKey", {})
        if not encryption_key:
            findings.append(self.create_finding(
                title=f"CodePipeline {pipeline_name} artifact store not encrypted",
                description="Pipeline artifact store does not use KMS encryption",
                severity="high",
                category="encryption_missing",
                resource_type="codepipeline",
                resource_id=pipeline_name,
                resource_name=pipeline_name,
                region=self.region,
                remediation={
                    "summary": "Enable artifact store encryption",
                    "steps": [
                        "Create or use existing KMS key",
                        "Update pipeline artifact store to use KMS key",
                    ],
                    "effort": "low",
                    "automatable": True,
                },
                rule_id="codepipeline_artifact_store_unencrypted",
            ))

        # Check for cross-account artifact store
        artifact_location = artifact_store.get("location", "")
        if artifact_location:
            # Check if bucket is in different account
            pass

        # Analyze stages
        for stage in stages:
            stage_name = stage.get("name", "")
            actions = stage.get("actions", [])

            for action in actions:
                await self._analyze_pipeline_action(pipeline_name, stage_name, action, scan_id, findings)

        # Check pipeline role permissions
        await self._check_pipeline_role(role_arn, pipeline_name, scan_id, findings)

    async def _analyze_pipeline_action(self, pipeline_name: str, stage_name: str, action: dict, scan_id: str, findings: list) -> None:
        """Analyze a pipeline action."""
        action_name = action.get("name", "")
        action_type = action.get("actionTypeId", {})
        category = action_type.get("category", "")
        provider = action_type.get("provider", "")
        owner = action_type.get("owner", "")
        configuration = action.get("configuration", {})

        # Check for manual approval stages (good practice)
        if category == "Approval":
            findings.append(self.create_finding(
                title=f"CodePipeline {pipeline_name} has manual approval stage: {stage_name}",
                description="Pipeline includes manual approval - this is a security best practice",
                severity="info",
                category="informational",
                resource_type="codepipeline",
                resource_id=pipeline_name,
                resource_name=pipeline_name,
                region=self.region,
                rule_id="codepipeline_manual_approval",
            ))

        # Check for CodeBuild actions with privileged mode
        if provider == "CodeBuild" and category == "Build":
            project_name = configuration.get("ProjectName", "")
            if project_name:
                await self._check_codebuild_project(project_name, pipeline_name, scan_id, findings)

        # Check for deployment actions to production without approval
        if category == "Deploy" and "prod" in stage_name.lower():
            # Check if previous stage was approval
            pass

        # Check for S3 deployment without versioning
        if provider == "S3" and category == "Deploy":
            bucket_name = configuration.get("BucketName", "")
            if bucket_name:
                findings.append(self.create_finding(
                    title=f"CodePipeline {pipeline_name} deploys to S3 bucket {bucket_name}",
                    description="Ensure S3 bucket has versioning and encryption enabled",
                    severity="info",
                    category="informational",
                    resource_type="codepipeline",
                    resource_id=pipeline_name,
                    resource_name=pipeline_name,
                    region=self.region,
                    rule_id="codepipeline_s3_deploy",
                ))

    async def _check_pipeline_role(self, role_arn: str, pipeline_name: str, scan_id: str, findings: list) -> None:
        """Check pipeline service role for excessive permissions."""
        if not role_arn:
            return

        # Extract role name from ARN
        role_name = role_arn.split("/")[-1] if "/" in role_arn else role_arn

        try:
            iam_client = self.auth_manager.get_client("iam", self.region)
            role_response = iam_client.get_role(RoleName=role_name)
            role = role_response.get("Role", {})

            # Check attached policies
            attached_policies = iam_client.list_attached_role_policies(RoleName=role_name)
            for policy in attached_policies.get("AttachedPolicies", []):
                policy_arn = policy["PolicyArn"]
                if "AdministratorAccess" in policy_arn or "PowerUserAccess" in policy_arn:
                    findings.append(self.create_finding(
                        title=f"CodePipeline {pipeline_name} role has excessive permissions",
                        description=f"Pipeline role {role_name} has {policy['PolicyName']} policy attached",
                        severity="high",
                        category="excessive_permissions",
                        resource_type="codepipeline",
                        resource_id=pipeline_name,
                        resource_name=pipeline_name,
                        region=self.region,
                        evidence=[{"type": "iam_policy", "description": "Excessive policy on pipeline role", "data": {"role": role_name, "policy": policy['PolicyName']}}],
                        remediation={
                            "summary": "Apply least privilege to pipeline role",
                            "steps": [
                                "Create custom policy with minimum required permissions",
                                "Remove AdministratorAccess/PowerUserAccess",
                                "Test pipeline with restricted role",
                            ],
                            "effort": "medium",
                            "automatable": False,
                        },
                        rule_id="codepipeline_excessive_role_permissions",
                    ))

        except botocore.exceptions.ClientError:
            pass

    async def _check_codebuild_project(self, project_name: str, pipeline_name: str, scan_id: str, findings: list) -> None:
        """Check CodeBuild project used in pipeline."""
        try:
            project_response = self.client.batch_get_projects(names=[project_name])
            for project in project_response.get("projects", []):
                env = project.get("environment", {})
                privileged = env.get("privilegedMode", False)

                if privileged:
                    findings.append(self.create_finding(
                        title=f"CodeBuild project {project_name} used in pipeline {pipeline_name} has privileged mode enabled",
                        description="Privileged mode gives containers full access to host - security risk",
                        severity="high",
                        category="weak_configuration",
                        resource_type="codebuild_project",
                        resource_id=project_name,
                        resource_name=project_name,
                        region=self.region,
                        remediation={
                            "summary": "Disable privileged mode",
                            "steps": [
                                "Remove privilegedMode from build environment",
                                "Use alternative approaches for Docker builds (buildx, Kaniko)",
                            ],
                            "effort": "medium",
                            "automatable": True,
                        },
                        rule_id="codebuild_privileged_mode",
                    ))

                # Check for plaintext environment variables
                env_vars = env.get("environmentVariables", [])
                for var in env_vars:
                    if var.get("type") == "PLAINTEXT" and var.get("value"):
                        value = var["value"]
                        # Check for potential secrets
                        if any(keyword in var.get("name", "").lower() for keyword in ["key", "secret", "token", "password", "cred"]):
                            findings.append(self.create_finding(
                                title=f"CodeBuild project {project_name} has potential secret in plaintext env var",
                                description=f"Environment variable {var['name']} may contain sensitive data",
                                severity="medium",
                                category="credential_exposure",
                                resource_type="codebuild_project",
                                resource_id=project_name,
                                resource_name=project_name,
                                region=self.region,
                                rule_id="codebuild_plaintext_secret",
                            ))

        except botocore.exceptions.ClientError:
            pass

    async def _scan_codebuild(self, scan_id: str, findings: list, result: ScanResult) -> None:
        """Scan CodeBuild projects for security issues."""
        try:
            paginator = self.client.get_paginator("list_projects")
            for page in paginator.paginate():
                for project_name in page.get("projects", []):
                    result.resources_found += 1

                    project_response = self.client.batch_get_projects(names=[project_name])
                    for project in project_response.get("projects", []):
                        await self._analyze_codebuild_project(project, scan_id, findings)

        except botocore.exceptions.ClientError as e:
            self.handle_client_error(e, "ListProjects")

    async def _analyze_codebuild_project(self, project: dict, scan_id: str, findings: list) -> None:
        """Analyze a CodeBuild project."""
        project_name = project.get("name", "")
        env = project.get("environment", {})
        source = project.get("source", {})
        artifacts = project.get("artifacts", {})
        vpc_config = project.get("vpcConfig", {})
        logs_config = project.get("logsConfig", {})

        # Check for privileged mode
        if env.get("privilegedMode"):
            findings.append(self.create_finding(
                title=f"CodeBuild project {project_name} has privileged mode enabled",
                description="Privileged mode gives containers full access to host",
                severity="high",
                category="weak_configuration",
                resource_type="codebuild_project",
                resource_id=project_name,
                resource_name=project_name,
                region=self.region,
                rule_id="codebuild_privileged_mode",
            ))

        # Check for plaintext environment variables with secrets
        env_vars = env.get("environmentVariables", [])
        for var in env_vars:
            if var.get("type") == "PLAINTEXT":
                name = var.get("name", "").lower()
                value = var.get("value", "")
                if any(keyword in name for keyword in ["key", "secret", "token", "password", "cred", "api"]):
                    findings.append(self.create_finding(
                        title=f"CodeBuild project {project_name} has potential secret in plaintext env var: {var['name']}",
                        severity="medium",
                        category="credential_exposure",
                        resource_type="codebuild_project",
                        resource_id=project_name,
                        resource_name=project_name,
                        region=self.region,
                        rule_id="codebuild_plaintext_secret",
                    ))

        # Check source for GitHub webhook secrets
        if source.get("type") == "GITHUB" or source.get("type") == "GITHUB_ENTERPRISE":
            auth = source.get("auth", {})
            if auth.get("type") == "OAUTH" and not auth.get("resource"):
                findings.append(self.create_finding(
                    title=f"CodeBuild project {project_name} uses OAuth without personal access token",
                    description="GitHub source should use personal access token for better security",
                    severity="low",
                    category="weak_configuration",
                    resource_type="codebuild_project",
                    resource_id=project_name,
                    resource_name=project_name,
                    region=self.region,
                    rule_id="codebuild_github_oauth",
                ))

        # Check artifacts encryption
        if artifacts.get("type") == "S3":
            encryption = artifacts.get("encryptionDisabled", False)
            if encryption:
                findings.append(self.create_finding(
                    title=f"CodeBuild project {project_name} has artifact encryption disabled",
                    description="Build artifacts stored in S3 are not encrypted",
                    severity="medium",
                    category="encryption_missing",
                    resource_type="codebuild_project",
                    resource_id=project_name,
                    resource_name=project_name,
                    region=self.region,
                    rule_id="codebuild_artifacts_unencrypted",
                ))

        # Check VPC config
        if not vpc_config.get("vpcId"):
            findings.append(self.create_finding(
                title=f"CodeBuild project {project_name} does not run in VPC",
                description="Project runs in AWS managed VPC - consider using custom VPC for network isolation",
                severity="low",
                category="weak_configuration",
                resource_type="codebuild_project",
                resource_id=project_name,
                resource_name=project_name,
                region=self.region,
                rule_id="codebuild_no_vpc",
            ))

        # Check logging
        if not logs_config.get("cloudWatchLogs", {}).get("status") == "ENABLED":
            findings.append(self.create_finding(
                title=f"CodeBuild project {project_name} has CloudWatch logging disabled",
                description="Build logs are not sent to CloudWatch",
                severity="low",
                category="logging_missing",
                resource_type="codebuild_project",
                resource_id=project_name,
                resource_name=project_name,
                region=self.region,
                rule_id="codebuild_no_cloudwatch_logs",
            ))

    async def _scan_codecommit(self, scan_id: str, findings: list, result: ScanResult) -> None:
        """Scan CodeCommit repositories for security issues."""
        try:
            paginator = self.client.get_paginator("list_repositories")
            for page in paginator.paginate():
                for repo in page.get("repositories", []):
                    result.resources_found += 1
                    repo_name = repo["repositoryName"]

                    repo_detail = self.client.get_repository(repositoryName=repo_name).get("repositoryMetadata", {})
                    await self._analyze_repository(repo_detail, scan_id, findings)

        except botocore.exceptions.ClientError as e:
            self.handle_client_error(e, "ListRepositories")

    async def _analyze_repository(self, repo: dict, scan_id: str, findings: list) -> None:
        """Analyze a CodeCommit repository."""
        repo_name = repo.get("repositoryName", "")
        repo_id = repo.get("repositoryId", "")
        clone_url_http = repo.get("cloneUrlHttp", "")
        clone_url_ssh = repo.get("cloneUrlSsh", "")

        # Check for default branch protection (CodeCommit doesn't have native branch protection)
        # This would need to be enforced via IAM policies or approval rules

        # Check approval rules
        try:
            approval_rules = self.client.list_approval_rule_templates(repositoryName=repo_name)
            if not approval_rules.get("approvalRuleTemplates"):
                findings.append(self.create_finding(
                    title=f"CodeCommit repository {repo_name} has no approval rule templates",
                    description="No approval rules configured for pull requests",
                    severity="medium",
                    category="weak_configuration",
                    resource_type="codecommit_repository",
                    resource_id=repo_id,
                    resource_name=repo_name,
                    region=self.region,
                    remediation={
                        "summary": "Create approval rule templates",
                        "steps": [
                            "Create approval rule template for pull requests",
                            "Require minimum number of approvals",
                            "Associate template with repository",
                        ],
                        "effort": "medium",
                        "automatable": True,
                    },
                    rule_id="codecommit_no_approval_rules",
                ))
        except botocore.exceptions.ClientError:
            pass

        # Check for branch permissions (via IAM)
        # This would require checking IAM policies - simplified check
        findings.append(self.create_finding(
            title=f"CodeCommit repository {repo_name} - verify branch protection via IAM",
            description="Ensure IAM policies restrict force pushes and deletions on main branches",
            severity="info",
            category="informational",
            resource_type="codecommit_repository",
            resource_id=repo_id,
            resource_name=repo_name,
            region=self.region,
            rule_id="codecommit_verify_branch_protection",
        ))


class GitHubActionsScanner:
    """Scanner for GitHub Actions workflows (requires GitHub API access)."""

    def __init__(self, github_token: str | None = None):
        self.github_token = github_token

    async def scan_repository(self, owner: str, repo: str) -> list:
        """Scan GitHub Actions workflows in a repository."""
        findings = []
        # This would require GitHub API access
        # For now, return empty - would be implemented with GitHub integration
        return findings

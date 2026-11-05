"""Privilege escalation analysis engine for awsProwl."""

from __future__ import annotations

from dataclasses import dataclass, field

from awsprowl.core.logging import get_logger

log = get_logger(__name__)


@dataclass
class PrivescPath:
    """Represents a privilege escalation path."""

    technique_id: str
    technique_name: str
    description: str
    required_permissions: list[str]
    source_arn: str
    target_arn: str | None = None
    confidence: str = "high"  # high, medium, low
    mitigation: str = ""
    references: list[str] = field(default_factory=list)


# AWS Privilege Escalation Techniques (based on CloudTap and rhino security labs)
PRIVESC_TECHNIQUES = {
    # IAM Techniques
    "iam:AttachUserPolicy": PrivescPath(
        technique_id="iam:AttachUserPolicy",
        technique_name="Attach User Policy",
        description="Attach a managed policy to a user, potentially granting admin access",
        required_permissions=["iam:AttachUserPolicy"],
        source_arn="",
        mitigation="Restrict iam:AttachUserPolicy to specific policies and users",
        references=["https://rhinosecuritylabs.com/aws/aws-privilege-escalation-methods-mitigation/"],
    ),
    "iam:AttachRolePolicy": PrivescPath(
        technique_id="iam:AttachRolePolicy",
        technique_name="Attach Role Policy",
        description="Attach a managed policy to a role",
        required_permissions=["iam:AttachRolePolicy"],
        source_arn="",
        mitigation="Restrict iam:AttachRolePolicy to specific policies and roles",
        references=["https://rhinosecuritylabs.com/aws/aws-privilege-escalation-methods-mitigation/"],
    ),
    "iam:PutUserPolicy": PrivescPath(
        technique_id="iam:PutUserPolicy",
        technique_name="Put User Policy",
        description="Create or update an inline policy for a user",
        required_permissions=["iam:PutUserPolicy"],
        source_arn="",
        mitigation="Restrict iam:PutUserPolicy to specific users and policy content",
        references=["https://rhinosecuritylabs.com/aws/aws-privilege-escalation-methods-mitigation/"],
    ),
    "iam:PutRolePolicy": PrivescPath(
        technique_id="iam:PutRolePolicy",
        technique_name="Put Role Policy",
        description="Create or update an inline policy for a role",
        required_permissions=["iam:PutRolePolicy"],
        source_arn="",
        mitigation="Restrict iam:PutRolePolicy to specific roles and policy content",
        references=["https://rhinosecuritylabs.com/aws/aws-privilege-escalation-methods-mitigation/"],
    ),
    "iam:CreateAccessKey": PrivescPath(
        technique_id="iam:CreateAccessKey",
        technique_name="Create Access Key",
        description="Create access keys for another user",
        required_permissions=["iam:CreateAccessKey"],
        source_arn="",
        mitigation="Restrict iam:CreateAccessKey to specific users",
        references=["https://rhinosecuritylabs.com/aws/aws-privilege-escalation-methods-mitigation/"],
    ),
    "iam:CreateLoginProfile": PrivescPath(
        technique_id="iam:CreateLoginProfile",
        technique_name="Create Login Profile",
        description="Create a console password for another user",
        required_permissions=["iam:CreateLoginProfile"],
        source_arn="",
        mitigation="Restrict iam:CreateLoginProfile to specific users",
        references=["https://rhinosecuritylabs.com/aws/aws-privilege-escalation-methods-mitigation/"],
    ),
    "iam:UpdateLoginProfile": PrivescPath(
        technique_id="iam:UpdateLoginProfile",
        technique_name="Update Login Profile",
        description="Update console password for another user",
        required_permissions=["iam:UpdateLoginProfile"],
        source_arn="",
        mitigation="Restrict iam:UpdateLoginProfile to specific users",
        references=["https://rhinosecuritylabs.com/aws/aws-privilege-escalation-methods-mitigation/"],
    ),
    "iam:AddUserToGroup": PrivescPath(
        technique_id="iam:AddUserToGroup",
        technique_name="Add User to Group",
        description="Add a user to a group with higher privileges",
        required_permissions=["iam:AddUserToGroup"],
        source_arn="",
        mitigation="Restrict iam:AddUserToGroup to specific groups and users",
        references=["https://rhinosecuritylabs.com/aws/aws-privilege-escalation-methods-mitigation/"],
    ),
    "iam:CreatePolicyVersion": PrivescPath(
        technique_id="iam:CreatePolicyVersion",
        technique_name="Create Policy Version",
        description="Create a new version of a managed policy with escalated permissions",
        required_permissions=["iam:CreatePolicyVersion", "iam:SetDefaultPolicyVersion"],
        source_arn="",
        mitigation="Restrict iam:CreatePolicyVersion and iam:SetDefaultPolicyVersion",
        references=["https://rhinosecuritylabs.com/aws/aws-privilege-escalation-methods-mitigation/"],
    ),
    "iam:SetDefaultPolicyVersion": PrivescPath(
        technique_id="iam:SetDefaultPolicyVersion",
        technique_name="Set Default Policy Version",
        description="Set an older policy version as default (with more permissions)",
        required_permissions=["iam:SetDefaultPolicyVersion"],
        source_arn="",
        mitigation="Restrict iam:SetDefaultPolicyVersion",
        references=["https://rhinosecuritylabs.com/aws/aws-privilege-escalation-methods-mitigation/"],
    ),
    "iam:UpdateAssumeRolePolicy": PrivescPath(
        technique_id="iam:UpdateAssumeRolePolicy",
        technique_name="Update Assume Role Policy",
        description="Modify a role's trust policy to allow self to assume it",
        required_permissions=["iam:UpdateAssumeRolePolicy"],
        source_arn="",
        mitigation="Restrict iam:UpdateAssumeRolePolicy to specific roles",
        references=["https://rhinosecuritylabs.com/aws/aws-privilege-escalation-methods-mitigation/"],
    ),
    "iam:PassRole": PrivescPath(
        technique_id="iam:PassRole",
        technique_name="Pass Role",
        description="Pass a high-privilege role to a service (EC2, Lambda, etc.) to escalate",
        required_permissions=["iam:PassRole", "ec2:RunInstances"],
        source_arn="",
        mitigation="Restrict iam:PassRole to specific roles and services",
        references=["https://rhinosecuritylabs.com/aws/aws-privilege-escalation-methods-mitigation/"],
    ),

    # STS Techniques
    "sts:AssumeRole": PrivescPath(
        technique_id="sts:AssumeRole",
        technique_name="Assume Role",
        description="Assume a role with higher privileges",
        required_permissions=["sts:AssumeRole"],
        source_arn="",
        mitigation="Restrict sts:AssumeRole with conditions (aws:SourceArn, MFA, etc.)",
        references=["https://rhinosecuritylabs.com/aws/aws-privilege-escalation-methods-mitigation/"],
    ),

    # EC2 Techniques
    "ec2:RunInstances": PrivescPath(
        technique_id="ec2:RunInstances",
        technique_name="Run Instances with Instance Profile",
        description="Launch EC2 instance with an instance profile that has higher privileges",
        required_permissions=["ec2:RunInstances", "iam:PassRole"],
        source_arn="",
        mitigation="Restrict ec2:RunInstances and iam:PassRole",
        references=["https://rhinosecuritylabs.com/aws/aws-privilege-escalation-methods-mitigation/"],
    ),
    "ec2:CreateSnapshot": PrivescPath(
        technique_id="ec2:CreateSnapshot",
        technique_name="Create Snapshot",
        description="Create snapshot of encrypted volume, copy to own account, decrypt",
        required_permissions=["ec2:CreateSnapshot", "ec2:CopySnapshot", "kms:Decrypt"],
        source_arn="",
        mitigation="Restrict snapshot creation and KMS permissions",
        references=["https://rhinosecuritylabs.com/aws/aws-privilege-escalation-methods-mitigation/"],
    ),

    # Lambda Techniques
    "lambda:CreateFunction": PrivescPath(
        technique_id="lambda:CreateFunction",
        technique_name="Create Function",
        description="Create Lambda function with high-privilege role and invoke it",
        required_permissions=["lambda:CreateFunction", "lambda:InvokeFunction", "iam:PassRole"],
        source_arn="",
        mitigation="Restrict lambda:CreateFunction, lambda:InvokeFunction, and iam:PassRole",
        references=["https://rhinosecuritylabs.com/aws/aws-privilege-escalation-methods-mitigation/"],
    ),
    "lambda:UpdateFunctionCode": PrivescPath(
        technique_id="lambda:UpdateFunctionCode",
        technique_name="Update Function Code",
        description="Modify existing Lambda function code to perform privileged actions",
        required_permissions=["lambda:UpdateFunctionCode", "lambda:InvokeFunction"],
        source_arn="",
        mitigation="Restrict lambda:UpdateFunctionCode to specific functions",
        references=["https://rhinosecuritylabs.com/aws/aws-privilege-escalation-methods-mitigation/"],
    ),
    "lambda:UpdateFunctionConfiguration": PrivescPath(
        technique_id="lambda:UpdateFunctionConfiguration",
        technique_name="Update Function Configuration",
        description="Modify Lambda function configuration (role, env vars) to escalate",
        required_permissions=["lambda:UpdateFunctionConfiguration", "iam:PassRole"],
        source_arn="",
        mitigation="Restrict lambda:UpdateFunctionConfiguration and iam:PassRole",
        references=["https://rhinosecuritylabs.com/aws/aws-privilege-escalation-methods-mitigation/"],
    ),
    "lambda:AddPermission": PrivescPath(
        technique_id="lambda:AddPermission",
        technique_name="Add Permission",
        description="Add permission to invoke a high-privilege Lambda function",
        required_permissions=["lambda:AddPermission"],
        source_arn="",
        mitigation="Restrict lambda:AddPermission",
        references=["https://rhinosecuritylabs.com/aws/aws-privilege-escalation-methods-mitigation/"],
    ),

    # CloudFormation Techniques
    "cloudformation:CreateStack": PrivescPath(
        technique_id="cloudformation:CreateStack",
        technique_name="Create Stack",
        description="Create CloudFormation stack with IAM resources to escalate",
        required_permissions=["cloudformation:CreateStack", "iam:CreateRole", "iam:AttachRolePolicy"],
        source_arn="",
        mitigation="Restrict cloudformation:CreateStack with IAM capabilities",
        references=["https://rhinosecuritylabs.com/aws/aws-privilege-escalation-methods-mitigation/"],
    ),
    "cloudformation:UpdateStack": PrivescPath(
        technique_id="cloudformation:UpdateStack",
        technique_name="Update Stack",
        description="Update existing CloudFormation stack to add privileged resources",
        required_permissions=["cloudformation:UpdateStack"],
        source_arn="",
        mitigation="Restrict cloudformation:UpdateStack",
        references=["https://rhinosecuritylabs.com/aws/aws-privilege-escalation-methods-mitigation/"],
    ),

    # IAM User/Role Techniques
    "iam:CreateUser": PrivescPath(
        technique_id="iam:CreateUser",
        technique_name="Create User",
        description="Create new user and attach admin policy",
        required_permissions=["iam:CreateUser", "iam:AttachUserPolicy", "iam:CreateAccessKey"],
        source_arn="",
        mitigation="Restrict iam:CreateUser and related permissions",
        references=["https://rhinosecuritylabs.com/aws/aws-privilege-escalation-methods-mitigation/"],
    ),
    "iam:CreateRole": PrivescPath(
        technique_id="iam:CreateRole",
        technique_name="Create Role",
        description="Create role with admin permissions and assume it",
        required_permissions=["iam:CreateRole", "iam:AttachRolePolicy", "sts:AssumeRole"],
        source_arn="",
        mitigation="Restrict iam:CreateRole and iam:AttachRolePolicy",
        references=["https://rhinosecuritylabs.com/aws/aws-privilege-escalation-methods-mitigation/"],
    ),

    # Service-specific techniques
    "glue:CreateDevEndpoint": PrivescPath(
        technique_id="glue:CreateDevEndpoint",
        technique_name="Create Glue Dev Endpoint",
        description="Create Glue dev endpoint with high-privilege role",
        required_permissions=["glue:CreateDevEndpoint", "iam:PassRole"],
        source_arn="",
        mitigation="Restrict glue:CreateDevEndpoint and iam:PassRole",
        references=["https://rhinosecuritylabs.com/aws/aws-privilege-escalation-methods-mitigation/"],
    ),
    "datapipeline:CreatePipeline": PrivescPath(
        technique_id="datapipeline:CreatePipeline",
        technique_name="Create Data Pipeline",
        description="Create Data Pipeline with high-privilege role",
        required_permissions=["datapipeline:CreatePipeline", "iam:PassRole"],
        source_arn="",
        mitigation="Restrict datapipeline:CreatePipeline and iam:PassRole",
        references=["https://rhinosecuritylabs.com/aws/aws-privilege-escalation-methods-mitigation/"],
    ),
    "rds:AddRoleToDBInstance": PrivescPath(
        technique_id="rds:AddRoleToDBInstance",
        technique_name="Add Role to DB Instance",
        description="Associate high-privilege role with RDS instance",
        required_permissions=["rds:AddRoleToDBInstance", "iam:PassRole"],
        source_arn="",
        mitigation="Restrict rds:AddRoleToDBInstance and iam:PassRole",
        references=["https://rhinosecuritylabs.com/aws/aws-privilege-escalation-methods-mitigation/"],
    ),

    # Additional IAM Techniques
    "iam:DeleteAccessKey": PrivescPath(
        technique_id="iam:DeleteAccessKey",
        technique_name="Delete Access Key",
        description="Delete another user's access keys to deny access or force rotation",
        required_permissions=["iam:DeleteAccessKey"],
        source_arn="",
        mitigation="Restrict iam:DeleteAccessKey to specific users",
        references=["https://rhinosecuritylabs.com/aws/aws-privilege-escalation-methods-mitigation/"],
    ),
    "iam:DeleteLoginProfile": PrivescPath(
        technique_id="iam:DeleteLoginProfile",
        technique_name="Delete Login Profile",
        description="Delete another user's console password to deny console access",
        required_permissions=["iam:DeleteLoginProfile"],
        source_arn="",
        mitigation="Restrict iam:DeleteLoginProfile to specific users",
        references=["https://rhinosecuritylabs.com/aws/aws-privilege-escalation-methods-mitigation/"],
    ),
    "iam:DeleteUserPolicy": PrivescPath(
        technique_id="iam:DeleteUserPolicy",
        technique_name="Delete User Policy",
        description="Delete inline policy from user to remove permissions",
        required_permissions=["iam:DeleteUserPolicy"],
        source_arn="",
        mitigation="Restrict iam:DeleteUserPolicy to specific users and policies",
        references=["https://rhinosecuritylabs.com/aws/aws-privilege-escalation-methods-mitigation/"],
    ),
    "iam:DeleteRolePolicy": PrivescPath(
        technique_id="iam:DeleteRolePolicy",
        technique_name="Delete Role Policy",
        description="Delete inline policy from role to remove permissions",
        required_permissions=["iam:DeleteRolePolicy"],
        source_arn="",
        mitigation="Restrict iam:DeleteRolePolicy to specific roles and policies",
        references=["https://rhinosecuritylabs.com/aws/aws-privilege-escalation-methods-mitigation/"],
    ),
    "iam:DetachUserPolicy": PrivescPath(
        technique_id="iam:DetachUserPolicy",
        technique_name="Detach User Policy",
        description="Detach managed policy from user to remove permissions",
        required_permissions=["iam:DetachUserPolicy"],
        source_arn="",
        mitigation="Restrict iam:DetachUserPolicy to specific users and policies",
        references=["https://rhinosecuritylabs.com/aws/aws-privilege-escalation-methods-mitigation/"],
    ),
    "iam:DetachRolePolicy": PrivescPath(
        technique_id="iam:DetachRolePolicy",
        technique_name="Detach Role Policy",
        description="Detach managed policy from role to remove permissions",
        required_permissions=["iam:DetachRolePolicy"],
        source_arn="",
        mitigation="Restrict iam:DetachRolePolicy to specific roles and policies",
        references=["https://rhinosecuritylabs.com/aws/aws-privilege-escalation-methods-mitigation/"],
    ),
    "iam:DetachGroupPolicy": PrivescPath(
        technique_id="iam:DetachGroupPolicy",
        technique_name="Detach Group Policy",
        description="Detach managed policy from group to remove permissions",
        required_permissions=["iam:DetachGroupPolicy"],
        source_arn="",
        mitigation="Restrict iam:DetachGroupPolicy to specific groups and policies",
        references=["https://rhinosecuritylabs.com/aws/aws-privilege-escalation-methods-mitigation/"],
    ),
    "iam:RemoveUserFromGroup": PrivescPath(
        technique_id="iam:RemoveUserFromGroup",
        technique_name="Remove User from Group",
        description="Remove user from privileged group to reduce their permissions",
        required_permissions=["iam:RemoveUserFromGroup"],
        source_arn="",
        mitigation="Restrict iam:RemoveUserFromGroup to specific groups and users",
        references=["https://rhinosecuritylabs.com/aws/aws-privilege-escalation-methods-mitigation/"],
    ),

    # SSM Techniques
    "ssm:SendCommand": PrivescPath(
        technique_id="ssm:SendCommand",
        technique_name="Send SSM Command",
        description="Execute commands on managed instances via SSM",
        required_permissions=["ssm:SendCommand"],
        source_arn="",
        mitigation="Restrict ssm:SendCommand to specific instances and documents",
        references=["https://rhinosecuritylabs.com/aws/aws-privilege-escalation-methods-mitigation/"],
    ),
    "ssm:StartSession": PrivescPath(
        technique_id="ssm:StartSession",
        technique_name="Start SSM Session",
        description="Start interactive session on managed instances via SSM Session Manager",
        required_permissions=["ssm:StartSession"],
        source_arn="",
        mitigation="Restrict ssm:StartSession to specific instances",
        references=["https://rhinosecuritylabs.com/aws/aws-privilege-escalation-methods-mitigation/"],
    ),

    # ECS Techniques
    "ecs:RunTask": PrivescPath(
        technique_id="ecs:RunTask",
        technique_name="Run ECS Task",
        description="Run ECS task with high-privilege task role",
        required_permissions=["ecs:RunTask", "iam:PassRole"],
        source_arn="",
        mitigation="Restrict ecs:RunTask and iam:PassRole to specific task definitions and roles",
        references=["https://rhinosecuritylabs.com/aws/aws-privilege-escalation-methods-mitigation/"],
    ),
    "ecs:CreateService": PrivescPath(
        technique_id="ecs:CreateService",
        technique_name="Create ECS Service",
        description="Create ECS service with high-privilege task role",
        required_permissions=["ecs:CreateService", "iam:PassRole"],
        source_arn="",
        mitigation="Restrict ecs:CreateService and iam:PassRole",
        references=["https://rhinosecuritylabs.com/aws/aws-privilege-escalation-methods-mitigation/"],
    ),

    # EKS Techniques
    "eks:CreateCluster": PrivescPath(
        technique_id="eks:CreateCluster",
        technique_name="Create EKS Cluster",
        description="Create EKS cluster with high-privilege role",
        required_permissions=["eks:CreateCluster", "iam:PassRole"],
        source_arn="",
        mitigation="Restrict eks:CreateCluster and iam:PassRole",
        references=["https://rhinosecuritylabs.com/aws/aws-privilege-escalation-methods-mitigation/"],
    ),
    "eks:UpdateClusterConfig": PrivescPath(
        technique_id="eks:UpdateClusterConfig",
        technique_name="Update EKS Cluster Config",
        description="Update EKS cluster configuration to escalate",
        required_permissions=["eks:UpdateClusterConfig", "iam:PassRole"],
        source_arn="",
        mitigation="Restrict eks:UpdateClusterConfig and iam:PassRole",
        references=["https://rhinosecuritylabs.com/aws/aws-privilege-escalation-methods-mitigation/"],
    ),

    # Cloud9 Techniques
    "cloud9:CreateEnvironmentEC2": PrivescPath(
        technique_id="cloud9:CreateEnvironmentEC2",
        technique_name="Create Cloud9 Environment",
        description="Create Cloud9 environment with high-privilege role",
        required_permissions=["cloud9:CreateEnvironmentEC2", "iam:PassRole"],
        source_arn="",
        mitigation="Restrict cloud9:CreateEnvironmentEC2 and iam:PassRole",
        references=["https://rhinosecuritylabs.com/aws/aws-privilege-escalation-methods-mitigation/"],
    ),

    # CodeBuild Techniques
    "codebuild:StartBuild": PrivescPath(
        technique_id="codebuild:StartBuild",
        technique_name="Start CodeBuild Build",
        description="Start CodeBuild build with high-privilege service role",
        required_permissions=["codebuild:StartBuild", "iam:PassRole"],
        source_arn="",
        mitigation="Restrict codebuild:StartBuild and iam:PassRole",
        references=["https://rhinosecuritylabs.com/aws/aws-privilege-escalation-methods-mitigation/"],
    ),

    # Batch Techniques
    "batch:SubmitJob": PrivescPath(
        technique_id="batch:SubmitJob",
        technique_name="Submit Batch Job",
        description="Submit AWS Batch job with high-privilege job role",
        required_permissions=["batch:SubmitJob", "iam:PassRole"],
        source_arn="",
        mitigation="Restrict batch:SubmitJob and iam:PassRole",
        references=["https://rhinosecuritylabs.com/aws/aws-privilege-escalation-methods-mitigation/"],
    ),

    # AppStream Techniques
    "appstream:CreateStack": PrivescPath(
        technique_id="appstream:CreateStack",
        technique_name="Create AppStream Stack",
        description="Create AppStream stack with high-privilege role",
        required_permissions=["appstream:CreateStack", "iam:PassRole"],
        source_arn="",
        mitigation="Restrict appstream:CreateStack and iam:PassRole",
        references=["https://rhinosecuritylabs.com/aws/aws-privilege-escalation-methods-mitigation/"],
    ),
    "appstream:CreateFleet": PrivescPath(
        technique_id="appstream:CreateFleet",
        technique_name="Create AppStream Fleet",
        description="Create AppStream fleet with high-privilege role",
        required_permissions=["appstream:CreateFleet", "iam:PassRole"],
        source_arn="",
        mitigation="Restrict appstream:CreateFleet and iam:PassRole",
        references=["https://rhinosecuritylabs.com/aws/aws-privilege-escalation-methods-mitigation/"],
    ),

    # SageMaker Techniques
    "sagemaker:CreateNotebookInstance": PrivescPath(
        technique_id="sagemaker:CreateNotebookInstance",
        technique_name="Create SageMaker Notebook Instance",
        description="Create SageMaker notebook instance with high-privilege role",
        required_permissions=["sagemaker:CreateNotebookInstance", "iam:PassRole"],
        source_arn="",
        mitigation="Restrict sagemaker:CreateNotebookInstance and iam:PassRole",
        references=["https://rhinosecuritylabs.com/aws/aws-privilege-escalation-methods-mitigation/"],
    ),
    "sagemaker:CreateModel": PrivescPath(
        technique_id="sagemaker:CreateModel",
        technique_name="Create SageMaker Model",
        description="Create SageMaker model with high-privilege role",
        required_permissions=["sagemaker:CreateModel", "iam:PassRole"],
        source_arn="",
        mitigation="Restrict sagemaker:CreateModel and iam:PassRole",
        references=["https://rhinosecuritylabs.com/aws/aws-privilege-escalation-methods-mitigation/"],
    ),

    # IAM Service-Linked Role
    "iam:CreateServiceLinkedRole": PrivescPath(
        technique_id="iam:CreateServiceLinkedRole",
        technique_name="Create Service-Linked Role",
        description="Create service-linked roles that may have elevated permissions",
        required_permissions=["iam:CreateServiceLinkedRole"],
        source_arn="",
        mitigation="Restrict iam:CreateServiceLinkedRole to specific services",
        references=["https://rhinosecuritylabs.com/aws/aws-privilege-escalation-methods-mitigation/"],
    ),

    # Organizations Techniques
    "organizations:CreateAccount": PrivescPath(
        technique_id="organizations:CreateAccount",
        technique_name="Create Organization Account",
        description="Create new account in AWS Organization with admin access",
        required_permissions=["organizations:CreateAccount"],
        source_arn="",
        mitigation="Restrict organizations:CreateAccount, use SCP to limit new accounts",
        references=["https://rhinosecuritylabs.com/aws/aws-privilege-escalation-methods-mitigation/"],
    ),

    # S3 Bucket Takeover
    "s3:PutObject": PrivescPath(
        technique_id="s3:PutObject",
        technique_name="Put Object (Bucket Takeover)",
        description="Upload objects to S3 bucket to serve malicious content or take over bucket",
        required_permissions=["s3:PutObject", "s3:GetObject"],
        source_arn="",
        mitigation="Restrict s3:PutObject and s3:GetObject to specific buckets and prefixes",
        references=["https://rhinosecuritylabs.com/aws/aws-privilege-escalation-methods-mitigation/"],
    ),
}


class PrivescAnalyzer:
    """Analyzes IAM policies for privilege escalation paths."""

    def __init__(self):
        self.techniques = PRIVESC_TECHNIQUES

    def analyze_policy(self, policy_doc: dict, principal_arn: str = "") -> list[PrivescPath]:
        """Analyze a policy document for privilege escalation techniques."""
        findings = []

        statements = policy_doc.get("Statement", [])
        if not isinstance(statements, list):
            statements = [statements]

        allowed_actions = set()
        for stmt in statements:
            if stmt.get("Effect") != "Allow":
                continue

            actions = stmt.get("Action", [])
            if isinstance(actions, str):
                actions = [actions]

            for action in actions:
                allowed_actions.add(action)
                # Handle wildcards
                if action.endswith("*"):
                    prefix = action[:-1]
                    for tech_id in self.techniques:
                        if tech_id.startswith(prefix):
                            allowed_actions.add(tech_id)

        # Check each technique
        for tech_id, technique in self.techniques.items():
            if self._has_required_permissions(technique.required_permissions, allowed_actions):
                # Create a copy with source ARN
                path = PrivescPath(
                    technique_id=technique.technique_id,
                    technique_name=technique.technique_name,
                    description=technique.description,
                    required_permissions=technique.required_permissions,
                    source_arn=principal_arn,
                    target_arn=technique.target_arn,
                    confidence=technique.confidence,
                    mitigation=technique.mitigation,
                    references=technique.references,
                )
                findings.append(path)

        return findings

    def _has_required_permissions(self, required: list[str], allowed: set[str]) -> bool:
        """Check if all required permissions are allowed."""
        for perm in required:
            if perm not in allowed:
                # Check for wildcard match
                matched = False
                for allowed_perm in allowed:
                    if allowed_perm.endswith("*") and perm.startswith(allowed_perm[:-1]):
                        matched = True
                        break
                if not matched:
                    return False
        return True

    def analyze_findings(self, findings: list) -> list[PrivescPath]:
        """Analyze scan findings for privilege escalation paths."""
        all_paths = []

        for finding in findings:
            if finding.get("category") in ("excessive_permissions", "privilege_escalation"):
                evidence = finding.get("evidence", [])
                for ev in evidence:
                    if ev.get("type") == "policy_document":
                        policy_doc = ev.get("data", {})
                        principal = finding.get("resource_id", "")
                        paths = self.analyze_policy(policy_doc, principal)
                        all_paths.extend(paths)

        # Deduplicate
        seen = set()
        unique_paths = []
        for path in all_paths:
            key = (path.technique_id, path.source_arn)
            if key not in seen:
                seen.add(key)
                unique_paths.append(path)

        return unique_paths

    def get_attack_chains(self, paths: list[PrivescPath]) -> list[list[PrivescPath]]:
        """Find potential attack chains from privilege escalation paths."""
        # Group by source
        by_source = {}
        for path in paths:
            if path.source_arn not in by_source:
                by_source[path.source_arn] = []
            by_source[path.source_arn].append(path)

        # Find chains (simplified - in practice would do graph analysis)
        chains = []
        for source, source_paths in by_source.items():
            if len(source_paths) > 1:
                chains.append(source_paths)

        return chains


def create_privesc_analyzer() -> PrivescAnalyzer:
    """Create a privilege escalation analyzer."""
    return PrivescAnalyzer()

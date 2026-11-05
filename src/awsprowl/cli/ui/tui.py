"""Interactive TUI module browser for awsProwl - Professional Edition with Prowl Features."""

from __future__ import annotations

import asyncio
import os
import shlex
import subprocess
import time
from dataclasses import dataclass, field
from typing import Any, Callable, Optional, List
from datetime import datetime, timezone
from pathlib import Path

from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.text import Text
from rich.columns import Columns
from rich.align import Align
from rich import box

# prompt_toolkit for proper line editing (backspace, arrows, history)
from prompt_toolkit import PromptSession
from prompt_toolkit.history import InMemoryHistory
from prompt_toolkit.auto_suggest import AutoSuggestFromHistory
from prompt_toolkit.key_binding import KeyBindings
from prompt_toolkit.keys import Keys
from prompt_toolkit.styles import Style
from prompt_toolkit.formatted_text import HTML

from awsprowl.cli.ui.branding import (
    get_colors, BrandingColors, render_startup_banner, render_logo,
    render_section_header, StatusIndicator, Theme
)
from awsprowl.cli.ui.handlers import (
    run_iam_check_mfa, run_iam_check_access_keys, run_iam_check_wildcard_policies,
    run_iam_check_cross_account_trust, run_iam_check_privilege_escalation,
    run_iam_list_users, run_iam_list_roles, run_iam_list_policies, run_iam_list_groups,
    run_ec2_check_imds, run_ec2_check_public_ips, run_ec2_check_open_ports,
    run_ec2_check_unencrypted_volumes, run_ec2_list_instances, run_ec2_list_security_groups,
    run_ec2_list_vpcs, run_ec2_list_subnets, run_ec2_list_keypairs, run_ec2_check_instance_profiles,
    run_s3_check_public_access, run_s3_check_encryption, run_s3_check_versioning,
    run_s3_check_logging, run_s3_check_policies, run_s3_check_acls, run_s3_list_buckets,
    run_s3_list_objects, run_lambda_check_runtime, run_lambda_check_permissions,
    run_lambda_check_env_vars, run_lambda_list_functions, run_lambda_check_layers,
    run_lambda_check_vpc_config,
    run_full_iam_scan, run_full_ec2_scan, run_full_s3_scan, run_full_lambda_scan,
    run_full_ecs_scan, run_full_secretsmanager_scan, run_full_sns_scan,
    run_full_beanstalk_scan, run_full_cognito_scan, run_full_sts_scan,
    run_full_rds_scan, run_full_dynamodb_scan, run_full_cloudfront_scan,
    run_full_kms_scan,
    run_sts_get_caller_identity, run_sts_check_assume_role, run_sts_get_session_token,
    run_search_encryption, run_search_public, run_search_privesc, run_search_secrets,
    display_and_save_results,
    # Attack module handlers - ENUM
    run_iam_enum_users, run_iam_enum_roles, run_iam_enum_policies, run_iam_enum_groups,
    run_iam_enum_account_authorization, run_iam_enum_password_policy, run_iam_enum_account_aliases,
    run_iam_enum_service_linked_roles, run_iam_enum_org_accounts, run_iam_enum_cross_account_trusts,
    run_iam_enum_action_query, run_iam_enum_permissions, run_iam_enum_users_roles_policies_groups,
    run_iam_enum_credential_report, run_iam_enum_honeytokens,
    run_ec2_enum_resources, run_ec2_enum_ebs_snapshots_unauth, run_ec2_enum_volumes_snapshots,
    run_s3_enum_buckets, run_s3_enum_objects, run_s3_enum_bucket_policies,
    run_lambda_enum_functions, run_lambda_enum_layers, run_lambda_enum_event_source_mappings,
    run_sts_enum_caller_identity, run_sts_enum_assumable_roles,
    run_rds_enum_snapshots,
    run_cloudwatch_enum_log_groups, run_cloudwatch_enum_metric_alarms, run_cloudwatch_enum_dashboards,
    run_detection_enum_services,
    run_apigateway_enum_rest_apis, run_apigateway_enum_http_apis, run_apigateway_enum_api_keys,
    run_codebuild_enum_projects, run_codebuild_enum_build_details,
    run_elasticbeanstalk_enum_applications, run_elasticbeanstalk_enum_resources,
    run_elb_enum_load_balancers, run_elb_enum_logging, run_elb_enum_target_groups,
    run_transfer_enum_servers, run_transfer_enum_certificates, run_transfer_enum_connectors,
    run_vpc_enum_lateral_movement, run_vpc_enum_endpoints, run_vpc_enum_flow_logs,
    run_waf_enum_web_acls, run_waf_enum_rules, run_waf_enum_logging,
    run_ds_enum_directories, run_ds_enum_trusts, run_ds_enum_snapshots,
    run_lightsail_enum_instances, run_lightsail_enum_blueprints, run_lightsail_enum_databases,
    run_acm_enum_certificates, run_acm_enum_certificate_details,
    run_ecr_enum_repositories, run_ecr_enum_pull_through_cache,
    # New ENUM handlers (PROWL parity)
    run_organizations_enum_accounts, run_organizations_enum_roots_ous, run_organizations_enum_policies,
    run_organizations_enum_delegated_admins, run_organizations_enum_handshakes,
    run_sts_enum_identity,
    run_rds_enum_instances,
    run_dynamodb_enum_tables,
    run_ecs_enum_clusters,
    run_eks_enum_clusters, run_eks_enum_addons, run_eks_enum_identity_providers,
    run_secretsmanager_enum_secrets,
    run_cloudtrail_enum_trails, run_cloudtrail_enum_event_data_stores, run_cloudtrail_enum_channels,
    run_kms_enum_keys, run_kms_enum_aliases, run_kms_enum_grants,
    run_sns_enum_topics,
    # Attack module handlers - PRIVESC
    run_iam_privesc_full_scan, run_iam_privesc_create_access_key, run_iam_privesc_create_login_profile,
    run_iam_privesc_attach_user_policy, run_iam_privesc_put_user_policy, run_iam_privesc_attach_role_policy,
    run_iam_privesc_put_role_policy, run_iam_privesc_create_policy_version, run_iam_privesc_create_role,
    run_iam_privesc_update_assume_role_policy, run_iam_privesc_pass_role, run_iam_privesc_add_user_to_group,
    run_iam_privesc_service_linked_roles, run_iam_privesc_org_takeover,
    run_ec2_privesc_analysis,
    run_s3_privesc_analysis,
    run_lambda_privesc_analysis,
    run_codebuild_privesc_analysis,
    run_vpc_privesc_analysis,
    run_all_privesc,
    # Attack module handlers - EXFIL (read-only)
    run_iam_exfil_credential_report,
    run_s3_exfil_download_objects, run_s3_exfil_metadata,
    run_lambda_exfil_env_vars,
    run_cloudwatch_exfil_metric_data,
    run_detection_exfil_inspector_reports, run_detection_exfil_guardduty_accounts,
    run_acm_enum_certificates, run_acm_enum_certificate_details,
    # Attack module handlers - EXFIL (destructive)
    run_ec2_exfil_ebs_snapshot_download, run_ec2_exfil_ebs_snapshot_explore,
    run_rds_exfil_explore_snapshots,
    run_cloudtrail_exfil_download_event_history, run_cloudtrail_exfil_csv_injection,
    run_cloudwatch_exfil_logs,
    run_detection_exfil_guardduty_findings,
    run_lightsail_exfil_download_ssh_keys, run_lightsail_exfil_snapshots,
    run_ecr_exfil_pull_images,
    run_ssm_exfil_download_parameters,
    # Attack module handlers - EXPLOIT (destructive)
    run_iam_exploit_bruteforce_permissions, run_iam_exploit_decode_access_key_id,
    run_iam_exploit_create_user, run_iam_exploit_create_access_key, run_iam_exploit_attach_policy,
    run_iam_exploit_create_role, run_iam_exploit_update_assume_role_policy, run_iam_exploit_create_policy_version,
    run_iam_backdoor_assume_role, run_iam_backdoor_users_keys, run_iam_backdoor_users_password,
    run_iam_backdoor_service_role, run_iam_backdoor_oidc_provider, run_iam_backdoor_saml_provider,
    run_apigateway_exploit_create_api_key, run_apigateway_exploit_create_deployment, run_apigateway_exploit_update_stage,
    run_codebuild_exploit_start_build, run_codebuild_exploit_update_project, run_codebuild_exploit_create_webhook,
    run_elasticbeanstalk_exploit_create_environment, run_elasticbeanstalk_exploit_update_environment, run_elasticbeanstalk_exploit_deploy_version,
    run_elb_exploit_modify_attributes, run_elb_exploit_create_listener,
    run_organizations_exploit_assume_role,
    run_waf_exploit_update_ip_set, run_waf_exploit_update_rule_group,
    run_lightsail_exploit_create_instance, run_lightsail_exploit_generate_ssh_keys, run_lightsail_exploit_generate_temp_access,
    run_sns_exploit_subscribe, run_sns_exploit_publish, run_sns_exploit_create_topic,
    run_ssm_exploit_rce_ec2, run_ssm_exploit_session_manager,
    run_ec2_exploit_run_instances, run_ec2_exploit_modify_instance_attribute, run_ec2_exploit_create_security_group, run_ec2_exploit_create_launch_template,
    run_s3_exploit_put_bucket_policy, run_s3_exploit_put_bucket_acl, run_s3_exploit_put_object,
    run_lambda_exploit_create_function, run_lambda_exploit_update_function_code, run_lambda_exploit_add_permission, run_lambda_exploit_create_event_source_mapping,
    # Attack module handlers - PERSIST (destructive)
    run_detection_persist_disrupt_guardduty, run_detection_persist_disrupt_cloudtrail,
    run_detection_persist_disrupt_config, run_detection_persist_disrupt_securityhub,
    run_detection_persist_guardduty_whitelist_ip,
    run_iam_persist_create_user, run_iam_persist_create_role, run_iam_persist_create_access_key, run_iam_persist_create_login_profile,
    run_iam_persist_attach_admin_policy, run_iam_persist_update_assume_role_policy, run_iam_persist_create_policy_version,
    run_iam_persist_add_user_to_group, run_iam_persist_create_service_linked_role,
    run_ec2_persist_user_data, run_ec2_persist_launch_template, run_ec2_persist_ami,
    run_lambda_persist_alias, run_lambda_persist_layer,
    # Attack module handlers - BACKDOOR (destructive)
    # Attack module handlers - EXFIL (destructive)
    run_cloudformation_exploit_resource_injection, run_cloudformation_exfil_download_data,
    run_eks_exfil_collect_tokens,
)
from awsprowl.core.auth import AWSAuthManager, create_auth_manager
from awsprowl.core.config import AWSConfig, get_config
from awsprowl.core.logging import get_logger
from awsprowl.analysis.findings import FindingCollection, Finding, Severity, FindingCategory

# Attack module system imports
from awsprowl.modules import (
    ModuleCategory, ModuleMetadata, ModuleRisk, MODULE_REGISTRY,
    list_modules, get_modules_by_service, get_modules_by_service_and_category,
    search_modules as search_attack_modules
)

log = get_logger(__name__)


@dataclass
class ModuleAction:
    """Represents an actionable module operation - Prowl style."""
    name: str
    description: str
    service: str
    category: str
    handler: Callable | None = None
    requires_auth: bool = True
    args: dict = field(default_factory=dict)
    is_scan_all: bool = False


# Professional service markers (no emojis)
SERVICE_MARKERS = {
    "iam": "[IAM]",
    "ec2": "[EC2]",
    "s3": "[S3]",
    "lambda": "[LAMBDA]",
    "ecs": "[ECS]",
    "secretsmanager": "[SECRETS]",
    "sns": "[SNS]",
    "beanstalk": "[BEANSTALK]",
    "cognito": "[COGNITO]",
    "rds": "[RDS]",
    "dynamodb": "[DYNAMODB]",
    "cloudfront": "[CLOUDFRONT]",
    "kms": "[KMS]",
    "sts": "[STS]",
    "cross-service": "[X-SVC]",
}

CATEGORY_MARKERS = {
    "enumeration": "[ENUM]",
    "security": "[SEC]",
    "privilege-escalation": "[PRIV-ESC]",
    "cross-account": "[X-ACCT]",
    "analysis": "[ANALYSIS]",
    "exposure": "[EXPOSURE]",
    "encryption": "[ENCRYPT]",
    "configuration": "[CONFIG]",
    "policy": "[POLICY]",
    "secrets": "[SECRETS]",
    "network": "[NETWORK]",
    "full-scan": "[FULL-SCAN]",
    "informational": "[INFO]",
    "auth": "[AUTH]",
    "availability": "[AVAIL]",
    # Attack module categories
    "enum": "[ENUM]",
    "privesc": "[PRIV-ESC]",
    "exploit": "[EXPLOIT]",
    "persist": "[PERSIST]",
    "backdoor": "[BACKDOOR]",
    "exfil": "[EXFIL]",
}


def build_attack_module_actions() -> dict[str, list[ModuleAction]]:
    """Build ModuleAction objects for all attack modules grouped by service."""
    # Map attack categories to handler functions
    # For ENUM/PRIVESC: use existing scanner methods (read-only)
    # For EXPLOIT/PERSIST/BACKDOOR/EXFIL: implement or show warnings

    # Handler mapping for attack modules
    handler_map = {
        # IAM ENUM
        "iam_enum_users": run_iam_enum_users,
        "iam_enum_roles": run_iam_enum_roles,
        "iam_enum_policies": run_iam_enum_policies,
        "iam_enum_groups": run_iam_enum_groups,
        "iam_enum_account_authorization": run_iam_enum_account_authorization,
        "iam_enum_password_policy": run_iam_enum_password_policy,
        "iam_enum_account_aliases": run_iam_enum_account_aliases,
        "iam_enum_service_linked_roles": run_iam_enum_service_linked_roles,
        "iam_enum_org_accounts": run_iam_enum_org_accounts,
        "iam_enum_cross_account_trusts": run_iam_enum_cross_account_trusts,
        "iam_enum_action_query": run_iam_enum_action_query,
        "iam_enum_permissions": run_iam_enum_permissions,
        "iam_enum_users_roles_policies_groups": run_iam_enum_users_roles_policies_groups,
        "iam_enum_credential_report": run_iam_enum_credential_report,
        "iam_enum_honeytokens": run_iam_enum_honeytokens,
        # EC2 ENUM
        "ec2_enum_resources": run_ec2_enum_resources,
        "ec2_enum_ebs_snapshots_unauth": run_ec2_enum_ebs_snapshots_unauth,
        "ec2_enum_volumes_snapshots": run_ec2_enum_volumes_snapshots,
        # S3 ENUM
        "s3_enum_buckets": run_s3_enum_buckets,
        "s3_enum_objects": run_s3_enum_objects,
        "s3_enum_bucket_policies": run_s3_enum_bucket_policies,
        # LAMBDA ENUM
        "lambda_enum_functions": run_lambda_enum_functions,
        "lambda_enum_layers": run_lambda_enum_layers,
        "lambda_enum_event_source_mappings": run_lambda_enum_event_source_mappings,
        # STS ENUM
        "sts_enum_caller_identity": run_sts_enum_caller_identity,
        "sts_enum_assumable_roles": run_sts_enum_assumable_roles,
        # RDS ENUM
        "rds_enum_snapshots": run_rds_enum_snapshots,
        # CLOUDWATCH ENUM
        "cloudwatch_enum_log_groups": run_cloudwatch_enum_log_groups,
        "cloudwatch_enum_metric_alarms": run_cloudwatch_enum_metric_alarms,
        "cloudwatch_enum_dashboards": run_cloudwatch_enum_dashboards,
        # DETECTION ENUM
        "detection_enum_services": run_detection_enum_services,
        # APIGATEWAY ENUM
        "apigateway_enum_rest_apis": run_apigateway_enum_rest_apis,
        "apigateway_enum_http_apis": run_apigateway_enum_http_apis,
        "apigateway_enum_api_keys": run_apigateway_enum_api_keys,
        # CODEBUILD ENUM
        "codebuild_enum_projects": run_codebuild_enum_projects,
        "codebuild_enum_build_details": run_codebuild_enum_build_details,
        # ELASTICBEANSTALK ENUM
        "elasticbeanstalk_enum_applications": run_elasticbeanstalk_enum_applications,
        "elasticbeanstalk_enum_resources": run_elasticbeanstalk_enum_resources,
        # ELB ENUM
        "elb_enum_load_balancers": run_elb_enum_load_balancers,
        "elb_enum_logging": run_elb_enum_logging,
        "elb_enum_target_groups": run_elb_enum_target_groups,
        # TRANSFER ENUM
        "transfer_enum_servers": run_transfer_enum_servers,
        "transfer_enum_certificates": run_transfer_enum_certificates,
        "transfer_enum_connectors": run_transfer_enum_connectors,
        # VPC ENUM
        "vpc_enum_lateral_movement": run_vpc_enum_lateral_movement,
        "vpc_enum_endpoints": run_vpc_enum_endpoints,
        "vpc_enum_flow_logs": run_vpc_enum_flow_logs,
        # WAF ENUM
        "waf_enum_web_acls": run_waf_enum_web_acls,
        "waf_enum_rules": run_waf_enum_rules,
        "waf_enum_logging": run_waf_enum_logging,
        # DS ENUM
        "ds_enum_directories": run_ds_enum_directories,
        "ds_enum_trusts": run_ds_enum_trusts,
        "ds_enum_snapshots": run_ds_enum_snapshots,
        # LIGHTSAIL ENUM
        "lightsail_enum_instances": run_lightsail_enum_instances,
        "lightsail_enum_blueprints": run_lightsail_enum_blueprints,
        "lightsail_enum_databases": run_lightsail_enum_databases,
        # ACM ENUM
        "acm_enum_certificates": run_acm_enum_certificates,
        "acm_enum_certificate_details": run_acm_enum_certificate_details,
        # ECR ENUM
        "ecr_enum_repositories": run_ecr_enum_repositories,
        "ecr_enum_pull_through_cache": run_ecr_enum_pull_through_cache,
        # ORGANIZATIONS ENUM
        "organizations_enum_accounts": run_organizations_enum_accounts,
        "organizations_enum_roots_ous": run_organizations_enum_roots_ous,
        "organizations_enum_policies": run_organizations_enum_policies,
        "organizations_enum_delegated_admins": run_organizations_enum_delegated_admins,
        "organizations_enum_handshakes": run_organizations_enum_handshakes,
        # STS ENUM
        "sts_enum_identity": run_sts_enum_identity,
        # RDS ENUM
        "rds_enum_instances": run_rds_enum_instances,
        # DYNAMODB ENUM
        "dynamodb_enum_tables": run_dynamodb_enum_tables,
        # ECS ENUM
        "ecs_enum_clusters": run_ecs_enum_clusters,
        # EKS ENUM
        "eks_enum_clusters": run_eks_enum_clusters,
        "eks_enum_addons": run_eks_enum_addons,
        "eks_enum_identity_providers": run_eks_enum_identity_providers,
        # SECRETSMANAGER ENUM
        "secretsmanager_enum_secrets": run_secretsmanager_enum_secrets,
        # CLOUDTRAIL ENUM
        "cloudtrail_enum_trails": run_cloudtrail_enum_trails,
        "cloudtrail_enum_event_data_stores": run_cloudtrail_enum_event_data_stores,
        "cloudtrail_enum_channels": run_cloudtrail_enum_channels,
        # KMS ENUM
        "kms_enum_keys": run_kms_enum_keys,
        "kms_enum_aliases": run_kms_enum_aliases,
        "kms_enum_grants": run_kms_enum_grants,
        # SNS ENUM
        "sns_enum_topics": run_sns_enum_topics,
        # IAM PRIVESC
        "iam_privesc_full_scan": run_iam_privesc_full_scan,
        "iam_privesc_create_access_key": run_iam_privesc_create_access_key,
        "iam_privesc_create_login_profile": run_iam_privesc_create_login_profile,
        "iam_privesc_attach_user_policy": run_iam_privesc_attach_user_policy,
        "iam_privesc_put_user_policy": run_iam_privesc_put_user_policy,
        "iam_privesc_attach_role_policy": run_iam_privesc_attach_role_policy,
        "iam_privesc_put_role_policy": run_iam_privesc_put_role_policy,
        "iam_privesc_create_policy_version": run_iam_privesc_create_policy_version,
        "iam_privesc_create_role": run_iam_privesc_create_role,
        "iam_privesc_update_assume_role_policy": run_iam_privesc_update_assume_role_policy,
        "iam_privesc_pass_role": run_iam_privesc_pass_role,
        "iam_privesc_add_user_to_group": run_iam_privesc_add_user_to_group,
        "iam_privesc_service_linked_roles": run_iam_privesc_service_linked_roles,
        "iam_privesc_org_takeover": run_iam_privesc_org_takeover,
        # EC2 PRIVESC
        "ec2_privesc_analysis": run_ec2_privesc_analysis,
        # S3 PRIVESC
        "s3_privesc_analysis": run_s3_privesc_analysis,
        # LAMBDA PRIVESC
        "lambda_privesc_analysis": run_lambda_privesc_analysis,
        # CODEBUILD PRIVESC
        "codebuild_privesc_analysis": run_codebuild_privesc_analysis,
        # VPC PRIVESC
        "vpc_privesc_analysis": run_vpc_privesc_analysis,
        # IAM EXFIL (read-only)
        "iam_exfil_credential_report": run_iam_exfil_credential_report,
        # S3 EXFIL
        "s3_exfil_download_objects": run_s3_exfil_download_objects,
        "s3_exfil_metadata": run_s3_exfil_metadata,
        # LAMBDA EXFIL
        "lambda_exfil_env_vars": run_lambda_exfil_env_vars,
        # CLOUDWATCH EXFIL (read-only)
        "cloudwatch_exfil_metric_data": run_cloudwatch_exfil_metric_data,
        # DETECTION EXFIL (read-only)
        "detection_exfil_inspector_reports": run_detection_exfil_inspector_reports,
        "detection_exfil_guardduty_accounts": run_detection_exfil_guardduty_accounts,
        # ACM ENUM
        "acm_enum_certificates": run_acm_enum_certificates,
        "acm_enum_certificate_details": run_acm_enum_certificate_details,
        # EXFIL (destructive)
        "ec2_exfil_ebs_snapshot_download": run_ec2_exfil_ebs_snapshot_download,
        "ec2_exfil_ebs_snapshot_explore": run_ec2_exfil_ebs_snapshot_explore,
        "rds_exfil_explore_snapshots": run_rds_exfil_explore_snapshots,
        "cloudtrail_exfil_download_event_history": run_cloudtrail_exfil_download_event_history,
        "cloudtrail_exfil_csv_injection": run_cloudtrail_exfil_csv_injection,
        "cloudwatch_exfil_logs": run_cloudwatch_exfil_logs,
        "detection_exfil_guardduty_findings": run_detection_exfil_guardduty_findings,
        "lightsail_exfil_download_ssh_keys": run_lightsail_exfil_download_ssh_keys,
        "lightsail_exfil_snapshots": run_lightsail_exfil_snapshots,
        "ecr_exfil_pull_images": run_ecr_exfil_pull_images,
        "ssm_exfil_download_parameters": run_ssm_exfil_download_parameters,
        # EXPLOIT (destructive)
        "iam_exploit_bruteforce_permissions": run_iam_exploit_bruteforce_permissions,
        "iam_exploit_decode_access_key_id": run_iam_exploit_decode_access_key_id,
        "iam_exploit_create_user": run_iam_exploit_create_user,
        "iam_exploit_create_access_key": run_iam_exploit_create_access_key,
        "iam_exploit_attach_policy": run_iam_exploit_attach_policy,
        "iam_exploit_create_role": run_iam_exploit_create_role,
        "iam_exploit_update_assume_role_policy": run_iam_exploit_update_assume_role_policy,
        "iam_exploit_create_policy_version": run_iam_exploit_create_policy_version,
        "iam_backdoor_assume_role": run_iam_backdoor_assume_role,
        "iam_backdoor_users_keys": run_iam_backdoor_users_keys,
        "iam_backdoor_users_password": run_iam_backdoor_users_password,
        "iam_backdoor_service_role": run_iam_backdoor_service_role,
        "iam_backdoor_oidc_provider": run_iam_backdoor_oidc_provider,
        "iam_backdoor_saml_provider": run_iam_backdoor_saml_provider,
        "apigateway_exploit_create_api_key": run_apigateway_exploit_create_api_key,
        "apigateway_exploit_create_deployment": run_apigateway_exploit_create_deployment,
        "apigateway_exploit_update_stage": run_apigateway_exploit_update_stage,
        "codebuild_exploit_start_build": run_codebuild_exploit_start_build,
        "codebuild_exploit_update_project": run_codebuild_exploit_update_project,
        "codebuild_exploit_create_webhook": run_codebuild_exploit_create_webhook,
        "elasticbeanstalk_exploit_create_environment": run_elasticbeanstalk_exploit_create_environment,
        "elasticbeanstalk_exploit_update_environment": run_elasticbeanstalk_exploit_update_environment,
        "elasticbeanstalk_exploit_deploy_version": run_elasticbeanstalk_exploit_deploy_version,
        "elb_exploit_modify_attributes": run_elb_exploit_modify_attributes,
        "elb_exploit_create_listener": run_elb_exploit_create_listener,
        "organizations_exploit_assume_role": run_organizations_exploit_assume_role,
        "waf_exploit_update_ip_set": run_waf_exploit_update_ip_set,
        "waf_exploit_update_rule_group": run_waf_exploit_update_rule_group,
        "lightsail_exploit_create_instance": run_lightsail_exploit_create_instance,
        "lightsail_exploit_generate_ssh_keys": run_lightsail_exploit_generate_ssh_keys,
        "lightsail_exploit_generate_temp_access": run_lightsail_exploit_generate_temp_access,
        "sns_exploit_subscribe": run_sns_exploit_subscribe,
        "sns_exploit_publish": run_sns_exploit_publish,
        "sns_exploit_create_topic": run_sns_exploit_create_topic,
        "ssm_exploit_rce_ec2": run_ssm_exploit_rce_ec2,
        "ssm_exploit_session_manager": run_ssm_exploit_session_manager,
        "cloudformation_exploit_resource_injection": run_cloudformation_exploit_resource_injection,
        "ec2_exploit_run_instances": run_ec2_exploit_run_instances,
        "ec2_exploit_modify_instance_attribute": run_ec2_exploit_modify_instance_attribute,
        "ec2_exploit_create_security_group": run_ec2_exploit_create_security_group,
        "ec2_exploit_create_launch_template": run_ec2_exploit_create_launch_template,
        "s3_exploit_put_bucket_policy": run_s3_exploit_put_bucket_policy,
        "s3_exploit_put_bucket_acl": run_s3_exploit_put_bucket_acl,
        "s3_exploit_put_object": run_s3_exploit_put_object,
        "lambda_exploit_create_function": run_lambda_exploit_create_function,
        "lambda_exploit_update_function_code": run_lambda_exploit_update_function_code,
        "lambda_exploit_add_permission": run_lambda_exploit_add_permission,
        "lambda_exploit_create_event_source_mapping": run_lambda_exploit_create_event_source_mapping,
        # PERSIST (destructive)
        "detection_persist_disrupt_guardduty": run_detection_persist_disrupt_guardduty,
        "detection_persist_disrupt_cloudtrail": run_detection_persist_disrupt_cloudtrail,
        "detection_persist_disrupt_config": run_detection_persist_disrupt_config,
        "detection_persist_disrupt_securityhub": run_detection_persist_disrupt_securityhub,
        "detection_persist_guardduty_whitelist_ip": run_detection_persist_guardduty_whitelist_ip,
        "iam_persist_create_user": run_iam_persist_create_user,
        "iam_persist_create_role": run_iam_persist_create_role,
        "iam_persist_create_access_key": run_iam_persist_create_access_key,
        "iam_persist_create_login_profile": run_iam_persist_create_login_profile,
        "iam_persist_attach_admin_policy": run_iam_persist_attach_admin_policy,
        "iam_persist_update_assume_role_policy": run_iam_persist_update_assume_role_policy,
        "iam_persist_create_policy_version": run_iam_persist_create_policy_version,
        "iam_persist_add_user_to_group": run_iam_persist_add_user_to_group,
        "iam_persist_create_service_linked_role": run_iam_persist_create_service_linked_role,
        "ec2_persist_user_data": run_ec2_persist_user_data,
        "ec2_persist_launch_template": run_ec2_persist_launch_template,
        "ec2_persist_ami": run_ec2_persist_ami,
        "lambda_persist_alias": run_lambda_persist_alias,
        "lambda_persist_layer": run_lambda_persist_layer,
        # BACKDOOR (destructive)
        # EXFIL (destructive - cloudformation)
        "cloudformation_exploit_resource_injection": run_cloudformation_exploit_resource_injection,
        "cloudformation_exfil_download_data": run_cloudformation_exfil_download_data,
        # EKS EXFIL
        "eks_exfil_collect_tokens": run_eks_exfil_collect_tokens,
    }

    # Generic handlers for modules without explicit handlers
    from awsprowl.cli.ui.handlers import (
        run_generic_enum_handler,
        run_generic_privesc_handler,
        run_generic_destructive_handler,
    )

    # Categories that are read-only (safe)
    safe_categories = {ModuleCategory.ENUM, ModuleCategory.PRIVESC}

    # Categories that require confirmation and are destructive
    destructive_categories = {ModuleCategory.EXPLOIT, ModuleCategory.PERSIST, ModuleCategory.BACKDOOR}

    # EXFIL is mixed - some read-only, some destructive

    attack_modules: dict[str, list[ModuleAction]] = {}

    for module_name, metadata in MODULE_REGISTRY.items():
        service = metadata.supported_services[0] if metadata.supported_services else "unknown"
        if service not in attack_modules:
            attack_modules[service] = []

        # Get handler if available, otherwise use generic handlers as fallbacks
        handler = handler_map.get(module_name)

        # Use generic handlers for modules without explicit handlers
        # Wrap generic handlers to pass module_name and description
        # Use default args to capture values at creation time (avoid closure bug)
        if handler is None:
            if metadata.category == ModuleCategory.ENUM:
                handler = lambda auth_mgr, mn=module_name, md=metadata.description, **kw: run_generic_enum_handler(auth_mgr, mn, md, **kw)
            elif metadata.category == ModuleCategory.PRIVESC:
                handler = lambda auth_mgr, mn=module_name, md=metadata.description, **kw: run_generic_privesc_handler(auth_mgr, mn, md, **kw)
            elif metadata.category in {ModuleCategory.EXPLOIT, ModuleCategory.PERSIST, ModuleCategory.BACKDOOR, ModuleCategory.EXFIL}:
                handler = lambda auth_mgr, mn=module_name, md=metadata.description, **kw: run_generic_destructive_handler(auth_mgr, mn, md, **kw)

        # Determine if requires auth and confirmation
        requires_auth = True
        requires_confirmation = metadata.requires_confirmation
        destructive = metadata.destructive

        # Safe categories don't need confirmation
        if metadata.category in safe_categories:
            requires_confirmation = False
            destructive = False

        # Create description with risk indicator
        risk_indicator = ""
        if metadata.risk == ModuleRisk.CRITICAL:
            risk_indicator = " [CRITICAL]"
        elif metadata.risk == ModuleRisk.HIGH:
            risk_indicator = " [HIGH]"
        elif metadata.risk == ModuleRisk.MEDIUM:
            risk_indicator = " [MEDIUM]"

        desc = f"{metadata.description}{risk_indicator}"
        if destructive:
            desc += " [DESTRUCTIVE]"

        # Map category to string
        category_str = metadata.category.value

        action = ModuleAction(
            name=module_name,
            description=desc,
            service=service,
            category=category_str,
            handler=handler,
            requires_auth=requires_auth,
            args={},
        )

        # Add custom attributes for destructive modules
        action.destructive = destructive
        action.requires_confirmation = requires_confirmation
        action.mitre_techniques = metadata.mitre_techniques
        action.required_permissions = metadata.required_permissions
        action.risk_level = metadata.risk.value

        attack_modules[service].append(action)

    return attack_modules


# Build attack modules at module load time
ATTACK_MODULES = build_attack_module_actions()


# Define all available modules/operations per service - Prowl style
SERVICE_MODULES: dict[str, list[ModuleAction]] = {
    "iam": [
        ModuleAction("list-users", "List all IAM users", "iam", "enumeration", handler=run_iam_list_users),
        ModuleAction("list-roles", "List all IAM roles", "iam", "enumeration", handler=run_iam_list_roles),
        ModuleAction("list-policies", "List all IAM policies", "iam", "enumeration", handler=run_iam_list_policies),
        ModuleAction("list-groups", "List all IAM groups", "iam", "enumeration", handler=run_iam_list_groups),
        ModuleAction("check-mfa", "Check MFA status for all users", "iam", "security", handler=run_iam_check_mfa),
        ModuleAction("check-access-keys", "Check access key age and rotation", "iam", "security", handler=run_iam_check_access_keys),
        ModuleAction("check-wildcard-policies", "Find overly permissive policies", "iam", "privilege-escalation", handler=run_iam_check_wildcard_policies),
        ModuleAction("check-cross-account-trust", "Find cross-account role trust", "iam", "cross-account", handler=run_iam_check_cross_account_trust),
        ModuleAction("check-privilege-escalation", "Check for privesc paths", "iam", "privilege-escalation", handler=run_iam_check_privilege_escalation),
        ModuleAction("simulate-principal", "Simulate principal permissions", "iam", "analysis"),
        ModuleAction("scan-all", "Scan all IAM resources (users, roles, policies, groups, MFA, access keys)", "iam", "full-scan", handler=run_full_iam_scan, is_scan_all=True),
    ],
    "ec2": [
        ModuleAction("list-instances", "List all EC2 instances", "ec2", "enumeration", handler=run_ec2_list_instances),
        ModuleAction("list-security-groups", "List all security groups", "ec2", "enumeration", handler=run_ec2_list_security_groups),
        ModuleAction("list-vpcs", "List all VPCs", "ec2", "enumeration", handler=run_ec2_list_vpcs),
        ModuleAction("list-subnets", "List all subnets", "ec2", "enumeration", handler=run_ec2_list_subnets),
        ModuleAction("check-public-ips", "Find instances with public IPs", "ec2", "exposure", handler=run_ec2_check_public_ips),
        ModuleAction("check-open-ports", "Find security groups with open ports", "ec2", "exposure", handler=run_ec2_check_open_ports),
        ModuleAction("check-unencrypted-volumes", "Find unencrypted EBS volumes", "ec2", "encryption", handler=run_ec2_check_unencrypted_volumes),
        ModuleAction("check-imds", "Check IMDSv1/v2 configuration", "ec2", "security", handler=run_ec2_check_imds),
        ModuleAction("list-keypairs", "List all key pairs", "ec2", "enumeration", handler=run_ec2_list_keypairs),
        ModuleAction("check-instance-profiles", "Check instance profile permissions", "ec2", "privilege-escalation", handler=run_ec2_check_instance_profiles),
        ModuleAction("scan-all", "Scan all EC2 resources (instances, SGs, VPCs, volumes, IMDS, keypairs)", "ec2", "full-scan", handler=run_full_ec2_scan, is_scan_all=True),
    ],
    "s3": [
        ModuleAction("list-buckets", "List all S3 buckets", "s3", "enumeration", handler=run_s3_list_buckets),
        ModuleAction("check-public-access", "Check for public bucket access", "s3", "exposure", handler=run_s3_check_public_access),
        ModuleAction("check-encryption", "Check bucket encryption", "s3", "encryption", handler=run_s3_check_encryption),
        ModuleAction("check-versioning", "Check bucket versioning", "s3", "configuration", handler=run_s3_check_versioning),
        ModuleAction("check-logging", "Check bucket access logging", "s3", "configuration", handler=run_s3_check_logging),
        ModuleAction("check-policies", "Check bucket policies", "s3", "policy", handler=run_s3_check_policies),
        ModuleAction("check-acls", "Check bucket ACLs", "s3", "policy", handler=run_s3_check_acls),
        ModuleAction("list-objects", "List objects in bucket", "s3", "enumeration", handler=run_s3_list_objects),
        ModuleAction("scan-all", "Scan all S3 resources (buckets, encryption, public access, versioning, logging)", "s3", "full-scan", handler=run_full_s3_scan, is_scan_all=True),
    ],
    "lambda": [
        ModuleAction("list-functions", "List all Lambda functions", "lambda", "enumeration", handler=run_lambda_list_functions),
        ModuleAction("check-runtime", "Check for deprecated runtimes", "lambda", "security", handler=run_lambda_check_runtime),
        ModuleAction("check-permissions", "Check function permissions/policies", "lambda", "policy", handler=run_lambda_check_permissions),
        ModuleAction("check-env-vars", "Check environment variables for secrets", "lambda", "secrets", handler=run_lambda_check_env_vars),
        ModuleAction("check-layers", "Check Lambda layers", "lambda", "enumeration", handler=run_lambda_check_layers),
        ModuleAction("check-vpc-config", "Check VPC configuration", "lambda", "network", handler=run_lambda_check_vpc_config),
        ModuleAction("scan-all", "Scan all Lambda resources (functions, runtimes, permissions, env vars, layers)", "lambda", "full-scan", handler=run_full_lambda_scan, is_scan_all=True),
    ],
    "ecs": [
        ModuleAction("list-clusters", "List ECS clusters", "ecs", "enumeration"),
        ModuleAction("list-services", "List ECS services", "ecs", "enumeration"),
        ModuleAction("list-task-definitions", "List task definitions", "ecs", "enumeration"),
        ModuleAction("check-task-roles", "Check task execution roles", "ecs", "privilege-escalation"),
        ModuleAction("check-network-mode", "Check network mode configuration", "ecs", "network"),
        ModuleAction("scan-all", "Scan all ECS resources (clusters, services, tasks, roles, network)", "ecs", "full-scan", handler=run_full_ecs_scan, is_scan_all=True),
    ],
    "secretsmanager": [
        ModuleAction("list-secrets", "List all secrets", "secretsmanager", "enumeration"),
        ModuleAction("check-rotation", "Check secret rotation", "secretsmanager", "security"),
        ModuleAction("check-policies", "Check secret policies", "secretsmanager", "policy"),
        ModuleAction("scan-all", "Scan all Secrets Manager resources (secrets, rotation, policies)", "secretsmanager", "full-scan", handler=run_full_secretsmanager_scan, is_scan_all=True),
    ],
    "sns": [
        ModuleAction("list-topics", "List all SNS topics", "sns", "enumeration"),
        ModuleAction("check-subscriptions", "Check topic subscriptions", "sns", "enumeration"),
        ModuleAction("check-policies", "Check topic policies", "sns", "policy"),
        ModuleAction("scan-all", "Scan all SNS resources (topics, subscriptions, policies)", "sns", "full-scan", handler=run_full_sns_scan, is_scan_all=True),
    ],
    "beanstalk": [
        ModuleAction("list-applications", "List Beanstalk applications", "beanstalk", "enumeration"),
        ModuleAction("list-environments", "List Beanstalk environments", "beanstalk", "enumeration"),
        ModuleAction("check-platforms", "Check for deprecated platforms", "beanstalk", "security"),
        ModuleAction("check-ssh-access", "Check SSH access configuration", "beanstalk", "network"),
        ModuleAction("check-health", "Check environment health", "beanstalk", "availability"),
        ModuleAction("scan-all", "Scan all Beanstalk resources (apps, environments, platforms, SSH, health)", "beanstalk", "full-scan", handler=run_full_beanstalk_scan, is_scan_all=True),
    ],
    "cognito": [
        ModuleAction("list-user-pools", "List Cognito User Pools", "cognito", "enumeration"),
        ModuleAction("list-identity-pools", "List Cognito Identity Pools", "cognito", "enumeration"),
        ModuleAction("check-mfa", "Check MFA configuration", "cognito", "security"),
        ModuleAction("check-password-policy", "Check password policy", "cognito", "configuration"),
        ModuleAction("check-advanced-security", "Check advanced security", "cognito", "security"),
        ModuleAction("check-app-clients", "Check app client configurations", "cognito", "configuration"),
        ModuleAction("scan-all", "Scan all Cognito resources (user pools, identity pools, MFA, policies, clients)", "cognito", "full-scan", handler=run_full_cognito_scan, is_scan_all=True),
    ],
    "rds": [
        ModuleAction("list-instances", "List RDS instances", "rds", "enumeration"),
        ModuleAction("check-encryption", "Check storage encryption", "rds", "encryption"),
        ModuleAction("check-public-access", "Check public accessibility", "rds", "exposure"),
        ModuleAction("check-backups", "Check backup configuration", "rds", "configuration"),
        ModuleAction("scan-all", "Scan all RDS resources (instances, encryption, public access, backups)", "rds", "full-scan", handler=run_full_rds_scan, is_scan_all=True),
    ],
    "dynamodb": [
        ModuleAction("list-tables", "List DynamoDB tables", "dynamodb", "enumeration"),
        ModuleAction("check-encryption", "Check encryption at rest", "dynamodb", "encryption"),
        ModuleAction("check-backups", "Check PITR/backups", "dynamodb", "configuration"),
        ModuleAction("check-public-access", "Check public access", "dynamodb", "exposure"),
        ModuleAction("scan-all", "Scan all DynamoDB resources (tables, encryption, backups, public access)", "dynamodb", "full-scan", handler=run_full_dynamodb_scan, is_scan_all=True),
    ],
    "cloudfront": [
        ModuleAction("list-distributions", "List CloudFront distributions", "cloudfront", "enumeration"),
        ModuleAction("check-logging", "Check access logging", "cloudfront", "configuration"),
        ModuleAction("check-waf", "Check WAF association", "cloudfront", "security"),
        ModuleAction("check-https", "Check HTTPS enforcement", "cloudfront", "security"),
        ModuleAction("scan-all", "Scan all CloudFront resources (distributions, logging, WAF, HTTPS)", "cloudfront", "full-scan", handler=run_full_cloudfront_scan, is_scan_all=True),
    ],
    "kms": [
        ModuleAction("list-keys", "List KMS keys", "kms", "enumeration"),
        ModuleAction("check-key-policies", "Check key policies", "kms", "policy"),
        ModuleAction("check-rotation", "Check key rotation", "kms", "security"),
        ModuleAction("check-aliases", "List key aliases", "kms", "enumeration"),
        ModuleAction("scan-all", "Scan all KMS resources (keys, policies, rotation, aliases)", "kms", "full-scan", handler=run_full_kms_scan, is_scan_all=True),
    ],
    "sts": [
        ModuleAction("get-caller-identity", "Get caller identity", "sts", "enumeration", handler=run_sts_get_caller_identity),
        ModuleAction("check-assume-role", "Check assumable roles", "sts", "privilege-escalation", handler=run_sts_check_assume_role),
        ModuleAction("get-session-token", "Get session token", "sts", "auth", handler=run_sts_get_session_token),
        ModuleAction("scan-all", "Scan all STS resources (identity, assumable roles, session tokens)", "sts", "full-scan", handler=run_full_sts_scan, is_scan_all=True),
    ],
}

# Cross-service search handlers
CROSS_SERVICE_HANDLERS = {
    "encryption": run_search_encryption,
    "public": run_search_public,
    "privesc": run_search_privesc,
    "privilege-escalation": run_search_privesc,
    "secrets": run_search_secrets,
}


class ModuleBrowserTUI:
    """Professional TUI with Prowl-style functional features."""

    def __init__(self, console: Console | None = None, config=None):
        self.console = console or Console()
        self.config = config or get_config()
        self.colors = get_colors(self.config.ui)
        self.auth_manager: Optional[AWSAuthManager] = None
        self.selected_service = None
        self.running = False
        self._profiles_cache: list[str] = []
        self._profiles_loaded = False
        self.status_indicator = StatusIndicator(self.console, self.colors)

        # prompt_toolkit session for proper line editing (backspace, arrows, history)
        # Define prompt_toolkit style for colored prompts
        self._pt_style = Style.from_dict({
            'prompt': 'ansicyan bold',
            'view': 'ansimagenta',
            'arrow': 'ansicyan bold',
        })
        self._prompt_session = PromptSession(
            history=InMemoryHistory(),
            auto_suggest=AutoSuggestFromHistory(),
            key_bindings=self._create_key_bindings(),
            style=self._pt_style,
        )

        # UI State
        self.current_view = "profile_select"  # profile_select, services, modules, search, help, json_view
        self.json_view_data = None
        self.json_view_path = None
        self.search_text = ""
        self.current_profile = self.config.aws.profile
        if not self.current_profile:
            profiles = self._load_profiles_fast()
            if profiles:
                self.current_profile = profiles[0]
                self.config.aws.profile = self.current_profile
        self.last_results: list[dict] = []
        self.running_module_names: List[str] = []
        self._module_running: bool = False

        # Track if we just ran a module to avoid re-printing search results
        self._just_ran_module = False
        # Current scan region (set after region selection)
        self.current_scan_region: Optional[str] = None
        # Region selection mode (for interactive number selection)
        self._region_selection_mode: bool = False
        # Command history
        self.command_history: list[str] = []
        # Last module name for 'last' command
        self.last_module_name: Optional[str] = None
        # Category filter for modules (None = all, or 'enum', 'privesc', 'exploit', 'persist', 'backdoor', 'exfil')
        self.category_filter: Optional[str] = None
        # Whether to show view content (set True when view changes via navigation)
        self._show_view: bool = False

    def _create_key_bindings(self) -> KeyBindings:
        """Create custom key bindings for prompt_toolkit."""
        kb = KeyBindings()

        @kb.add(Keys.ControlC)
        def _(event):
            """Handle Ctrl+C - abort current input."""
            event.current_buffer.reset()
            raise KeyboardInterrupt()

        @kb.add(Keys.ControlD)
        def _(event):
            """Handle Ctrl+D - EOF."""
            if not event.current_buffer.text:
                raise EOFError()
            event.current_buffer.validate_and_handle()

        return kb

    def input(self, prompt: str = "") -> str:
        """Get user input with proper line editing (backspace, arrows, history)."""
        # Convert Rich markup to prompt_toolkit HTML for colored prompts
        # Expected format: [bold cyan]awsprowl[view_name][/bold cyan] ›
        # Convert to: <prompt>awsprowl</prompt><view>[view_name]</view><arrow> › </arrow>
        try:
            html_prompt = self._rich_to_html(prompt)
            # Wrap in HTML class for prompt_toolkit to interpret
            from prompt_toolkit.formatted_text import HTML
            return self._prompt_session.prompt(HTML(html_prompt))
        except (KeyboardInterrupt, EOFError):
            raise

    def _rich_to_html(self, text: str) -> str:
        """Convert Rich-style markup to prompt_toolkit HTML."""
        # Handle [bold cyan]...[/bold cyan] -> <prompt>...</prompt>
        # Handle [view_name] -> <view>[view_name]</view> (preserve brackets for view indicator)
        # Handle trailing › or similar -> <arrow>...</arrow>

        import re

        # First, handle the main prompt pattern: [bold cyan]awsprowl[view][/bold cyan] ›
        # Pattern: [bold cyan]text[view][/bold cyan] arrow
        pattern = r'\[bold cyan\](.*?)\[(\w+)\]\[/bold cyan\](\s*[›>]\s*)'

        def replace_prompt(match):
            prefix = match.group(1)  # "awsprowl"
            view = match.group(2)    # "search", "profile_select", etc.
            arrow = match.group(3)   # " › "
            return f'<prompt>{prefix}</prompt><view>[{view}]</view><arrow>{arrow}</arrow>'

        result = re.sub(pattern, replace_prompt, text)

        # If no match, just strip markup and return plain
        if result == text:
            result = self._strip_markup(text)

        return result

    def _strip_markup(self, text: str) -> str:
        """Strip Rich markup tags from text for prompt_toolkit fallback."""
        import re
        # Remove Rich style tags like [bold cyan], [/bold cyan], [red], [/red], etc.
        return re.sub(r'\[/?(?:bold|dim|italic|underline|blink|reverse|strike|red|green|blue|cyan|yellow|magenta|white|black|bright_?(?:red|green|blue|cyan|yellow|magenta|white|black)|#[0-9a-fA-F]{6})(?:\s+(?:bold|dim|italic|underline|blink|reverse|strike|red|green|blue|cyan|yellow|magenta|white|black|bright_?(?:red|green|blue|cyan|yellow|magenta|white|black)|#[0-9a-fA-F]{6}))*\]', '', text)

    def _strip_markup(self, text: str) -> str:
        """Strip Rich markup tags from text for prompt_toolkit."""
        import re
        # Remove Rich style tags like [bold cyan], [/bold cyan], [red], [/red], etc.
        # Rich tags contain style names: bold, dim, italic, underline, blink, reverse,
        # strike, color names (red, green, blue, cyan, yellow, magenta, white, black)
        # and hex colors (#rrggbb), plus combinations like "bold cyan"
        return re.sub(r'\[/?(?:bold|dim|italic|underline|blink|reverse|strike|red|green|blue|cyan|yellow|magenta|white|black|bright_?(?:red|green|blue|cyan|yellow|magenta|white|black)|#[0-9a-fA-F]{6})(?:\s+(?:bold|dim|italic|underline|blink|reverse|strike|red|green|blue|cyan|yellow|magenta|white|black|bright_?(?:red|green|blue|cyan|yellow|magenta|white|black)|#[0-9a-fA-F]{6}))*\]', '', text)

    def _load_profiles_fast(self) -> list[str]:
        """Load AWS profiles quickly using aws CLI (cached)."""
        if self._profiles_loaded:
            return self._profiles_cache
        try:
            result = subprocess.run(
                ["aws", "configure", "list-profiles"],
                capture_output=True, text=True, timeout=3
            )
            if result.returncode == 0:
                profiles = [p.strip() for p in result.stdout.strip().split('\n') if p.strip()]
                self._profiles_cache = profiles if profiles else ["default"]
            else:
                self._profiles_cache = ["default"]
        except Exception:
            self._profiles_cache = ["default"]
        self._profiles_loaded = True
        return self._profiles_cache

    def _refresh_profiles(self) -> list[str]:
        """Force refresh AWS profiles from CLI."""
        self._profiles_loaded = False
        self._profiles_cache = []
        return self._load_profiles_fast()

    def _ensure_auth(self) -> bool:
        """Ensure we have valid authentication for current profile."""
        if self.auth_manager is not None:
            return True
        try:
            self.auth_manager = create_auth_manager(AWSConfig(profile=self.current_profile))
            self.auth_manager.get_caller_identity()
            return True
        except Exception as e:
            self.auth_manager = None
            self.console.print(f"[red]Authentication failed for profile '{self.current_profile}':[/red] {e}")
            return False

    def get_services(self) -> list[str]:
        """Get list of available services."""
        # Combine services from both SERVICE_MODULES and ATTACK_MODULES
        services = set(SERVICE_MODULES.keys()) | set(ATTACK_MODULES.keys())
        return sorted(services)

    def get_modules_for_service(self, service: str) -> list[ModuleAction]:
        """Get modules for a specific service - combines SERVICE_MODULES and ATTACK_MODULES."""
        modules = SERVICE_MODULES.get(service, [])
        attack_modules = ATTACK_MODULES.get(service, [])
        return modules + attack_modules

    def search_modules(self, query: str) -> list[tuple[str, ModuleAction]]:
        """Search modules across all services - Prowl style, includes attack modules."""
        query = query.lower().strip()
        results = []

        # Search query mapping for user-friendly terms
        # "iam_priv" or "iam_privesc" -> all iam_privesc_* modules
        # "iam_enum" -> all iam_enum_* modules
        # "ec2_enum" -> all ec2_enum_* modules
        # "ec2_privesc" -> all ec2_privesc_* modules
        # "s3_exploit" -> all s3_exploit_* modules
        # "privesc" -> all privesc modules across services
        # "enum" -> all enum modules across services
        # "exploit" -> all exploit modules across services
        # "persist" -> all persist modules across services
        # "backdoor" -> all backdoor modules across services
        # "exfil" -> all exfil modules across services

        # Check for category-wide searches first
        category_searches = {
            "privesc": ModuleCategory.PRIVESC,
            "privilege-escalation": ModuleCategory.PRIVESC,
            "enum": ModuleCategory.ENUM,
            "enumeration": ModuleCategory.ENUM,
            "exploit": ModuleCategory.EXPLOIT,
            "persist": ModuleCategory.PERSIST,
            "persistence": ModuleCategory.PERSIST,
            "backdoor": ModuleCategory.BACKDOOR,
            "exfil": ModuleCategory.EXFIL,
            "exfiltration": ModuleCategory.EXFIL,
        }

        # Check for service+category searches
        service_category_searches = {
            "iam_priv": ("iam", ModuleCategory.PRIVESC),
            "iam_privesc": ("iam", ModuleCategory.PRIVESC),
            "iam_enum": ("iam", ModuleCategory.ENUM),
            "iam_enumeration": ("iam", ModuleCategory.ENUM),
            "iam_exploit": ("iam", ModuleCategory.EXPLOIT),
            "iam_persist": ("iam", ModuleCategory.PERSIST),
            "iam_persistence": ("iam", ModuleCategory.PERSIST),
            "iam_backdoor": ("iam", ModuleCategory.BACKDOOR),
            "iam_exfil": ("iam", ModuleCategory.EXFIL),
            "ec2_enum": ("ec2", ModuleCategory.ENUM),
            "ec2_enumeration": ("ec2", ModuleCategory.ENUM),
            "ec2_privesc": ("ec2", ModuleCategory.PRIVESC),
            "ec2_exploit": ("ec2", ModuleCategory.EXPLOIT),
            "ec2_persist": ("ec2", ModuleCategory.PERSIST),
            "ec2_backdoor": ("ec2", ModuleCategory.BACKDOOR),
            "ec2_exfil": ("ec2", ModuleCategory.EXFIL),
            "s3_enum": ("s3", ModuleCategory.ENUM),
            "s3_enumeration": ("s3", ModuleCategory.ENUM),
            "s3_privesc": ("s3", ModuleCategory.PRIVESC),
            "s3_exploit": ("s3", ModuleCategory.EXPLOIT),
            "s3_persist": ("s3", ModuleCategory.PERSIST),
            "s3_backdoor": ("s3", ModuleCategory.BACKDOOR),
            "s3_exfil": ("s3", ModuleCategory.EXFIL),
            "lambda_enum": ("lambda", ModuleCategory.ENUM),
            "lambda_enumeration": ("lambda", ModuleCategory.ENUM),
            "lambda_privesc": ("lambda", ModuleCategory.PRIVESC),
            "lambda_exploit": ("lambda", ModuleCategory.EXPLOIT),
            "lambda_persist": ("lambda", ModuleCategory.PERSIST),
            "lambda_backdoor": ("lambda", ModuleCategory.BACKDOOR),
            "lambda_exfil": ("lambda", ModuleCategory.EXFIL),
            "sts_enum": ("sts", ModuleCategory.ENUM),
            "sts_privesc": ("sts", ModuleCategory.PRIVESC),
            "sts_exfil": ("sts", ModuleCategory.EXFIL),
        }

        # First check for service+category search terms
        if query in service_category_searches:
            service, category = service_category_searches[query]
            attack_results = search_attack_modules("", category=category, service=service)
            for module in attack_results:
                results.append((service, self._convert_attack_module_to_action(module)))

        # Then check for category-wide searches
        elif query in category_searches:
            category = category_searches[query]
            attack_results = search_attack_modules("", category=category)
            for module in attack_results:
                service = module.supported_services[0] if module.supported_services else "unknown"
                results.append((service, self._convert_attack_module_to_action(module)))

        # Then do normal search across both SERVICE_MODULES and ATTACK_MODULES
        else:
            # Search SERVICE_MODULES
            if query.startswith("search "):
                service_query = query[7:].strip()
                for service in self.get_services():
                    if service_query in service.lower():
                        for module in self.get_modules_for_service(service):
                            results.append((service, module))
            else:
                for service in self.get_services():
                    for module in self.get_modules_for_service(service):
                        if (query in service.lower() or
                            query in module.name.lower() or
                            query in module.description.lower() or
                            query in module.category.lower()):
                            results.append((service, module))

                # Also search attack modules directly via registry
                attack_results = search_attack_modules(query)
                for module in attack_results:
                    service = module.supported_services[0] if module.supported_services else "unknown"
                    # Avoid duplicates
                    if not any(r[1].name == module.name for r in results):
                        results.append((service, self._convert_attack_module_to_action(module)))

                if query in CROSS_SERVICE_HANDLERS:
                    @dataclass
                    class VirtualModule:
                        name: str = f"search-{query}"
                        description: str = f"Cross-service {query} check across all services"
                        service: str = "cross-service"
                        category: str = query
                        handler: Callable = field(default=CROSS_SERVICE_HANDLERS[query])
                        requires_auth: bool = True
                        args: dict = field(default_factory=dict)

                    results.append(("cross-service", VirtualModule()))

        return results

    def _convert_attack_module_to_action(self, module: ModuleMetadata) -> ModuleAction:
        """Convert attack ModuleMetadata to ModuleAction for display."""
        # Map category to string
        category_str = module.category.value

        # Risk indicator
        risk_indicator = ""
        if module.risk == ModuleRisk.CRITICAL:
            risk_indicator = " [CRITICAL]"
        elif module.risk == ModuleRisk.HIGH:
            risk_indicator = " [HIGH]"
        elif module.risk == ModuleRisk.MEDIUM:
            risk_indicator = " [MEDIUM]"

        desc = f"{module.description}{risk_indicator}"
        if module.destructive:
            desc += " [DESTRUCTIVE]"

        # Look up handler from ATTACK_MODULES
        handler = None
        service = module.supported_services[0] if module.supported_services else "unknown"
        attack_modules = ATTACK_MODULES.get(service, [])
        for am in attack_modules:
            if am.name == module.name:
                handler = am.handler
                break

        return ModuleAction(
            name=module.name,
            description=desc,
            service=service,
            category=category_str,
            handler=handler,
            requires_auth=True,
            args={},
        )

    def print_banner(self):
        """Print the professional startup banner."""
        self.console.clear()
        banner = render_startup_banner(self.console, profile=self.current_profile)
        self.console.print(banner)
        self.console.print()

        profiles = self._load_profiles_fast()
        services = self.get_services()
        total_modules = sum(len(self.get_modules_for_service(s)) for s in services)

        stats_panel = Panel(
            f"[bold]AWS Profile:[/bold] [cyan]{self.current_profile or 'default'}[/cyan]  "
            f"[bold]Profiles:[/bold] [green]{len(profiles)}[/green]  "
            f"[bold]Services:[/bold] [yellow]{len(services)}[/yellow]  "
            f"[bold]Modules:[/bold] [magenta]{total_modules}[/magenta]",
            border_style="cyan", padding=(0, 2), box=box.HEAVY,
        )
        self.console.print(stats_panel)
        self.console.print()

        # Print profile selection once here (not in run())
        self.print_profile_selection()

    def print_services(self):
        """Print services list with professional formatting."""
        services = self.get_services()

        # Create grid of service cards
        cards = []
        for i, service in enumerate(services, 1):
            modules = self.get_modules_for_service(service)
            categories = set(m.category for m in modules)
            cat_markers = " ".join(CATEGORY_MARKERS.get(c, "[MOD]") for c in sorted(categories)[:4])

            marker = SERVICE_MARKERS.get(service, "[MOD]")

            card = Panel(
                f"[bold cyan]{marker} {service}[/bold cyan]\n"
                f"[dim]{len(modules)} modules[/dim]  {cat_markers}",
                border_style="cyan",
                padding=(0, 1),
                width=42,
            )
            cards.append(card)

        self.console.print(Columns(cards, equal=True, expand=True))
        self.console.print()

    def print_modules(self, service: str):
        """Print modules for a service with professional table."""
        modules = self.get_modules_for_service(service)

        # Apply category filter if set
        if self.category_filter:
            modules = [m for m in modules if m.category == self.category_filter]
            filter_info = f" [dim](filtered: {self.category_filter})[/dim]"
        else:
            filter_info = ""

        marker = SERVICE_MARKERS.get(service, "[MOD]")

        table = Table(
            title=f"{marker} {service.upper()} Modules{filter_info}",
            show_header=True, header_style="bold cyan",
            box=box.HEAVY, border_style="cyan", expand=True,
        )
        table.add_column("#", style="dim", width=4, justify="right")
        table.add_column("Module", style="cyan", width=30)
        table.add_column("Category", style="yellow", width=18)
        table.add_column("Description", min_width=40)
        table.add_column("Auth", style="dim", width=6, justify="center")

        for i, module in enumerate(modules, 1):
            auth_marker = "[AUTH]" if module.requires_auth else "[OPEN]"
            cat_display = f"{CATEGORY_MARKERS.get(module.category, '[MOD]')} {module.category.replace('_', ' ').title()}"
            prefix = "[ALL] " if module.is_scan_all else "      "
            table.add_row(str(i), f"{prefix}{module.name}", cat_display, module.description, auth_marker)

        if not modules:
            self.console.print(f"[yellow]No modules found for category '{self.category_filter}' in service '{service}'[/yellow]")

        self.console.print(table)
        self.console.print()

    def print_search_results(self, query: str):
        """Print search results with professional formatting."""
        results = self.search_modules(query)

        # Apply category filter if set
        if self.category_filter:
            results = [(s, m) for s, m in results if m.category == self.category_filter]
            filter_info = f" [dim](filtered: {self.category_filter})[/dim]"
        else:
            filter_info = ""

        table = Table(
            title=f"[bold cyan]Search Results for '{query}' ({len(results)} matches){filter_info}[/bold cyan]",
            show_header=True, header_style="bold cyan",
            box=box.HEAVY, border_style="cyan", expand=True,
        )
        table.add_column("#", style="dim", width=4, justify="right")
        table.add_column("Service", style="cyan", width=18)
        table.add_column("Module", style="green", width=28)
        table.add_column("Category", style="yellow", width=16)
        table.add_column("Description", min_width=40)

        for i, (service, module) in enumerate(results, 1):
            if hasattr(module, 'service') and module.service == "cross-service":
                service_display = f"[magenta]{SERVICE_MARKERS.get('cross-service', '[X-SVC]')} cross-service[/magenta]"
                module_name = f"[bold]{module.name}[/bold]"
            else:
                service_display = f"{SERVICE_MARKERS.get(service, '[MOD]')} {service}"
                module_name = module.name

            table.add_row(
                str(i), service_display, module_name,
                f"{CATEGORY_MARKERS.get(module.category, '[MOD]')} {module.category.replace('_', ' ').title()}",
                module.description,
            )

        if not results:
            self.console.print(f"[yellow]No results found for category '{self.category_filter}'[/yellow]")

        self.console.print(table)
        self.console.print()

    def print_profile_selection(self):
        """Print profile selection with professional table."""
        profiles = self._refresh_profiles()

        table = Table(
            title="[bold cyan]AWS Profiles[/bold cyan]",
            show_header=True, header_style="bold cyan",
            box=box.HEAVY, border_style="cyan",
        )
        table.add_column("#", style="dim", width=4, justify="right")
        table.add_column("Profile", style="cyan", width=30)
        table.add_column("Status", style="green", width=20)
        table.add_column("Current", style="yellow", width=10, justify="center")

        for i, profile in enumerate(profiles, 1):
            is_current = profile == self.current_profile
            current_marker = "[yellow]✓[/yellow]" if is_current else ""
            table.add_row(
                str(i),
                profile + (" (current)" if is_current else ""),
                "available", current_marker,
            )

        self.console.print(table)
        self.console.print()

    def print_help(self):
        """Print help with professional formatting."""
        help_items = [
            ("Navigation", [
                ("help / h / ?", "Show this help"),
                ("info <module>", "Show detailed module information (what it does, permissions, MITRE techniques, usage)"),
                ("modules / all-modules", "Show ALL modules across all services with categories, risk, destructive flags"),
                ("modules <service>", "Show modules for specific service (e.g., 'modules iam')"),
                ("whoami", "Show current AWS caller identity"),
                ("services / list / s", "Show all services"),
                ("modules / m", "Show modules for selected service"),
                ("profiles / p", "Switch AWS profile"),
                ("region / r", "Show/set current scan region"),
                ("clear / c", "Clear search results or JSON view"),
                ("last / l", "Show last module results"),
                ("history", "Show command history"),
                ("search <query>", "Search modules (e.g., 'search iam', 'search encryption')"),
                ("run <module>", "Run module by name"),
                ("run <service> <module>", "Run specific module in service"),
                ("run <service> <module> <region>", "Run module in specific region (e.g., 'run ec2 list-instances us-east-1')"),
                ("run <service>", "Run full service scanner (scan-all)"),
                ("privesc / privesc-all", "Run ALL privilege escalation modules across all services"),
                ("view_json <path>", "Open and view JSON file (alias: oj)"),
                ("back / b", "Go back"),
                ("exit / quit / q", "Exit the browser"),
            ]),
            ("Category Filter", [
                ("category / cat / filter", "Show current category filter"),
                ("category <type>", "Filter modules by category: enum, privesc, exploit, persist, backdoor, exfil"),
                ("category clear", "Clear category filter (show all)"),
            ]),
            ("Quick Searches", [
                ("search iam", "All IAM modules (users, roles, policies, MFA, privesc)"),
                ("search ec2", "All EC2 modules (instances, SGs, VPCs, volumes)"),
                ("search s3", "All S3 modules (buckets, encryption, public access)"),
                ("search lambda", "All Lambda modules (functions, runtimes, env vars)"),
                ("search encryption", "Cross-service encryption checks"),
                ("search public", "Cross-service public exposure checks"),
                ("search privesc", "Cross-service privilege escalation checks"),
                ("search secrets", "Find secrets across services"),
                # Attack module searches
                ("search iam_priv", "IAM privilege escalation modules"),
                ("search iam_enum", "IAM enumeration modules"),
                ("search ec2_enum", "EC2 enumeration modules"),
                ("search ec2_privesc", "EC2 privilege escalation modules"),
                ("search s3_exploit", "S3 exploitation modules"),
                ("search enum", "All enumeration modules across services"),
                ("search exploit", "All exploitation modules across services"),
                ("search persist", "All persistence modules across services"),
                ("search backdoor", "All backdoor modules across services"),
                ("search exfil", "All exfiltration modules across services"),
            ]),
            ("Module Examples", [
                ("run iam", "Run IAM scanner (all checks)"),
                ("run ec2", "Run EC2 scanner (all checks)"),
                ("run s3", "Run S3 scanner (all checks)"),
                ("run iam list-users", "Run specific IAM module"),
                ("run ec2 check-public-ips", "Run specific EC2 module"),
                ("run lambda list-functions us-east-1", "Run Lambda module in specific region"),
                ("run iam iam_enum_users", "Run IAM enumeration module"),
                ("run iam iam_privesc_full_scan", "Run IAM privilege escalation scan"),
                ("run ec2 ec2_enum_resources", "Run EC2 enumeration module"),
                ("run s3 s3_enum_buckets", "Run S3 enumeration module"),
            ]),
            ("Scan-All Behavior", [
                ("run <service> (e.g., run lambda)", "Run full scan - prompts for region before scanning"),
                ("  Press Enter at prompt", "Use current/default region"),
                ("  Type region (e.g., us-west-2)", "Scan specific region"),
                ("  Type 'all'", "Scan all regions"),
                ("  Results saved to:", "output/{profile}/{service}_scan-all.json"),
            ]),
            ("Region Commands", [
                ("region", "Show current scan region"),
                ("region us-east-1", "Set default scan region"),
                ("region all", "Scan all regions"),
                ("region list", "List available regions"),
            ]),
            ("Export & Diff", [
                ("export_csv [file.json] [out.csv]", "Export findings to CSV (uses last results or loads from JSON)"),
                ("diff <old.json> <new.json>", "Compare two scan files and show differences"),
                ("tag list", "List tags for all findings in last results"),
                ("tag add <idx> <tags...>", "Add tags to finding (comma-separated)"),
                ("tag remove <idx> <tags...>", "Remove tags from finding"),
                ("tag set <idx> <tags...>", "Set tags for finding (replace all)"),
            ]),
        ]

        for section_title, items in help_items:
            self.console.print(f"\n[bold cyan]{section_title}:[/bold cyan]")
            for cmd, desc in items:
                self.console.print(f"  [bold]{cmd:<32}[/bold] {desc}")
        self.console.print()

    def print_json_view(self):
        """Print the JSON file view with syntax highlighting."""
        if not self.json_view_data or not self.json_view_path:
            self.console.print("[yellow]No JSON file loaded[/yellow]")
            return

        from rich.syntax import Syntax
        from rich.panel import Panel
        import json

        # Pretty print the JSON
        json_str = json.dumps(self.json_view_data, indent=2, default=str)

        # Create syntax highlighted view
        syntax = Syntax(json_str, "json", theme="monokai", line_numbers=True, word_wrap=True)

        self.console.print()
        self.console.print(f"[bold cyan]📄 JSON View: {self.json_view_path}[/bold cyan]")
        self.console.print(f"[dim]Type 'clear' or 'c' to return to previous view[/dim]\n")
        self.console.print(Panel(syntax, border_style="cyan", box=box.ROUNDED, padding=(1, 2)))
        self.console.print()

    def print_status_bar(self):
        """Print professional status bar."""
        creds = "No Keys Set"
        if self.auth_manager and self.auth_manager.credentials:
            creds = self.auth_manager.credentials.access_key[:8] + "****"

        status_items = [
            f"[bold]Profile:[/bold] [cyan]{self.current_profile}[/cyan]",
            f"[bold]Creds:[/bold] [yellow]{creds}[/yellow]",
        ]
        if self.selected_service:
            status_items.append(f"[bold]Service:[/bold] [green]{self.selected_service}[/green]")
        if self.current_scan_region:
            status_items.append(f"[bold]Region:[/bold] [magenta]{self.current_scan_region}[/magenta]")
        if self.current_view == "search":
            status_items.append(f"[bold]Search:[/bold] [magenta]{self.search_text}[/magenta]")
        if self.category_filter:
            status_items.append(f"[bold]Filter:[/bold] [yellow]{self.category_filter}[/yellow]")

        status_bar = "  |  ".join(status_items)
        self.console.print(Panel(status_bar, border_style="dim", padding=(0, 1), box=box.HEAVY))
        self.console.print()

    def print_footer(self):
        """Print footer with context-aware shortcuts."""
        shortcuts = {
            "profile_select": ["Enter Continue", "services", "modules", "region", "search", "history", "help", "quit"],
            "services": ["services", "modules", "profiles", "region", "category", "view_json", "search", "history", "run", "export_csv", "diff", "tag", "clear", "last", "back", "help", "quit", "info"],
            "modules": ["back", "profiles", "region", "category", "view_json", "search", "history", "run", "export_csv", "diff", "tag", "clear", "last", "help", "quit", "info"],
            "search": ["back", "category", "view_json", "region", "export_csv", "diff", "tag", "clear", "last", "help", "quit", "info"],
            "help": ["services", "modules", "profiles", "region", "back", "quit"],
        }
        items = shortcuts.get(self.current_view, [])
        shortcut_text = "  ".join(f"[dim]{s}[/dim]" for s in items)
        self.console.print(Align.center(Text.from_markup(shortcut_text)))
        self.console.print()

    def _suppress_logs(self):
        """Context manager to suppress INFO/DEBUG logs during module execution."""
        import logging
        from loguru import logger

        # Store original handlers
        original_handlers = logger._core.handlers.copy()

        # Remove all handlers and add a null handler for WARNING+
        logger.remove()
        null_handler_id = logger.add(lambda _: None, level="WARNING")

        # Also suppress standard logging
        original_levels = {}
        for logger_name in ['awsprowl.core.auth', 'awsprowl.aws', 'awsprowl.cli', '']:
            lg = logging.getLogger(logger_name)
            original_levels[logger_name] = lg.level
            lg.setLevel(logging.WARNING)

        class LogSuppressor:
            def __enter__(self):
                return self

            def __exit__(self, exc_type, exc_val, exc_tb):
                # Restore loguru handlers
                logger.remove()
                for handler_id, handler in original_handlers.items():
                    # Re-add original handlers
                    pass  # loguru doesn't easily support restoring handlers

                # Re-setup logging from config
                from awsprowl.core.logging import setup_logging
                from awsprowl.core.config import get_config
                setup_logging(get_config().logging)

                # Restore standard logging levels
                for logger_name, level in original_levels.items():
                    logging.getLogger(logger_name).setLevel(level)

        return LogSuppressor()

    def run_module(self, service: str, module: ModuleAction) -> bool:
        """Run a specific module with progress - Prowl style with prefix output."""
        # Check for destructive modules requiring confirmation
        if getattr(module, 'destructive', False) and getattr(module, 'requires_confirmation', True):
            self.console.print(f"\n[bold red]⚠ WARNING: DESTRUCTIVE MODULE[/bold red]")
            self.console.print(f"[red]Module:[/red] {service}/{module.name}")
            self.console.print(f"[red]Description:[/red] {module.description}")
            self.console.print(f"[red]Risk Level:[/red] {getattr(module, 'risk_level', 'unknown').upper()}")
            self.console.print(f"[red]MITRE Techniques:[/red] {', '.join(getattr(module, 'mitre_techniques', []))}")
            self.console.print(f"\n[bold yellow]This module performs DESTRUCTIVE actions that modify AWS resources.[/bold yellow]")
            self.console.print(f"[yellow]It requires explicit authorization and confirmation.[/yellow]")
            self.console.print(f"\n[bold]Type 'CONFIRM' to proceed, or anything else to cancel:[/bold] ")

            try:
                confirmation = self.input("").strip()
                if confirmation != "CONFIRM":
                    self.console.print("[green]Operation cancelled.[/green]")
                    return False
                self.console.print("[red]Confirmation received. Executing...[/red]\n")
            except (KeyboardInterrupt, EOFError):
                self.console.print("\n[yellow]Operation cancelled.[/yellow]")
                return False

        self._module_running = True
        self.running_module_names.append(module.name)
        self._just_ran_module = True

        self.console.print(f"\n[bold cyan]Running {service}/{module.name}...[/bold cyan]")
        self.console.print(f"[dim]{module.description}[/dim]\n")

        # Suppress logs BEFORE auth check
        with self._suppress_logs():
            if module.requires_auth:
                if not self._ensure_auth():
                    self.console.print("[yellow]Run 'profiles' to select a different profile[/yellow]")
                    self.running_module_names.pop()
                    self._module_running = False
                    self._just_ran_module = False
                    return False

            # Determine region for this module (non-global services need region)
            global_services = {'iam', 'sts', 'cloudfront', 'organizations', 'route53', 'waf', 'wafv2'}
            region = module.args.get('region') if module.args else None

            # If no region specified and not a global service, prompt for region
            if not region and service not in global_services:
                # Check if user specified region via command line (already in module.args)
                # Otherwise prompt interactively
                scan_regions = self._get_scan_regions(service)
                if not scan_regions:
                    self.running_module_names.pop()
                    self._module_running = False
                    self._just_ran_module = False
                    return False
                region = scan_regions[0]
                if module.args is None:
                    module.args = {}
                module.args['region'] = region

            # Store current scan region for status bar - NEVER use "global" for regional services
            if region:
                self.current_scan_region = region
            elif service in global_services:
                self.current_scan_region = 'global'
            else:
                self.current_scan_region = "us-east-1"

            findings = []
            try:
                with self.console.status(f"[cyan]Executing {module.name}...[/cyan]", spinner="dots"):
                    # Get handler - try module.handler first, then fall back to ATTACK_MODULES
                    handler = module.handler
                    if handler is None:
                        # Look up handler from ATTACK_MODULES
                        attack_modules = ATTACK_MODULES.get(service, [])
                        for am in attack_modules:
                            if am.name == module.name:
                                handler = am.handler
                                break

                    if handler:
                        if asyncio.iscoroutinefunction(handler):
                            findings = asyncio.run(handler(self.auth_manager, **module.args))
                        else:
                            findings = handler(self.auth_manager, **module.args)
                    else:
                        findings = [{
                            "title": "Handler Not Implemented",
                            "description": f"The handler for {module.name} is not implemented yet.",
                            "severity": "info",
                            "category": "informational",
                            "resource_type": "other",
                            "resource_id": module.name,
                            "resource_name": module.name,
                            "region": "global",
                            "rule_id": f"{module.name}_not_implemented",
                        }]

                # Display and save results - Prowl style with module prefix
                self.last_results = findings
                self.last_module_name = module.name
                display_and_save_results(findings, self.console, module.name, self.current_profile, service)

                # Print Prowl-style summary
                self.print_module_summary(module.name, findings)

            except Exception as e:
                self.console.print(f"[red]Module failed:[/red] {e}")
                log.exception("Module execution failed")
                return False
            finally:
                self.running_module_names.pop()
                self._module_running = False

        return True

    def print_module_summary(self, module_name: str, findings: list):
        """Print Prowl-style module summary with severity breakdown."""
        self.console.print(f"\n[bold green]MODULE SUMMARY: {module_name}[/bold green]\n")

        if not findings:
            self.console.print("  No findings.")
            return

        severity_counts = {'critical': 0, 'high': 0, 'medium': 0, 'low': 0, 'info': 0}
        for finding in findings:
            severity = finding.get('severity', 'info').lower()
            if severity in severity_counts:
                severity_counts[severity] += 1

        self.console.print(f"  Total findings: {len(findings)}")
        for severity in ['critical', 'high', 'medium', 'low', 'info']:
            if severity_counts[severity] > 0:
                color = {'critical': 'red', 'high': 'red', 'medium': 'yellow', 'low': 'blue', 'info': 'green'}[severity]
                self.console.print(f"  [{color}]{severity.capitalize()}: {severity_counts[severity]}[/{color}]")

        self.console.print("\n  Top findings:")
        for finding in findings[:10]:
            severity = finding.get('severity', 'info').upper()
            title = finding.get('title', 'Unknown')
            resource = finding.get('resource_id', 'N/A')
            color = {'CRITICAL': 'red', 'HIGH': 'red', 'MEDIUM': 'yellow', 'LOW': 'blue', 'INFO': 'green'}.get(severity, 'white')
            self.console.print(f"  [{color}]{severity}[/{color}] {title} ({resource})")

        if len(findings) > 10:
            self.console.print(f"  ... and {len(findings) - 10} more findings")

    def run_service_scanner(self, service: str, module_name: str) -> bool:
        """Run an AWS service scanner - Prowl style."""
        self._module_running = True
        self.running_module_names.append(module_name)
        self._just_ran_module = True

        self.console.print(f"\n[bold cyan]Running {service} scanner...[/bold cyan]\n")

        # Suppress logs during entire scanner execution including auth
        with self._suppress_logs():
            if not self._ensure_auth():
                self.console.print("[yellow]Run 'profiles' to select a different profile[/yellow]")
                self.running_module_names.pop()
                self._module_running = False
                self._just_ran_module = False
                return False

            # Import scanner module
            import importlib
            module_file_map = {'lambda': 'lambda_', 'secretsmanager': 'secrets'}
            file_name = module_file_map.get(service, service)

            try:
                module = importlib.import_module(f"awsprowl.aws.{file_name}")
            except ImportError as e:
                self.console.print(f"[red]Failed to import {service} module: {e}[/red]")
                self.running_module_names.pop()
                self._module_running = False
                self._just_ran_module = False
                return False

            # Get scanner class
            class_name_map = {'lambda': 'Lambda', 'secretsmanager': 'Secrets'}
            class_suffix = class_name_map.get(service, service.capitalize())
            if service in ['iam', 'sts', 'ec2', 's3', 'sns', 'rds', 'kms', 'eks']:
                class_suffix = service.upper()

            scanner_class = getattr(module, f'{class_suffix}Scanner', None)
            if not scanner_class:
                for attr in dir(module):
                    if attr.endswith('Scanner') and service.lower() in attr.lower():
                        scanner_class = getattr(module, attr)
                        break

            if not scanner_class:
                self.console.print(f"[red]Could not find scanner class for {service}[/red]")
                self.running_module_names.pop()
                self._module_running = False
                self._just_ran_module = False
                return False

            # Determine regions - interactive selection with current region shown
            global_services = {'iam', 'sts', 'cloudfront', 'organizations', 'route53', 'waf', 'wafv2', 'iam', 'sts'}
            if service in global_services:
                scan_regions = ['us-east-1']
                self.current_scan_region = 'global'
            else:
                # Get current/default region - NEVER default to "global" for regional services
                # If current_scan_region is "global" or None, use configured region or us-east-1
                if self.current_scan_region and self.current_scan_region != "global":
                    current_region = self.current_scan_region
                elif self.config.scan.regions:
                    current_region = self.config.scan.regions[0]
                else:
                    current_region = "us-east-1"

                # Show current region and ask if user wants to change
                self.console.print(f"\n[bold]Region Selection for {service.upper()}[/bold]")
                self.console.print(f"  Current region: [cyan]{current_region}[/cyan]")
                self.console.print(f"  Press Enter to use current, or type a region code (e.g., us-west-2, eu-west-1)")
                self.console.print(f"  Type 'all' to scan all regions")
                self.console.print()

                try:
                    user_input = self.input("[cyan]Region [/cyan]").strip()

                    if not user_input:
                        # User pressed Enter - use current region
                        scan_regions = [current_region]
                    elif user_input.lower() == 'all':
                        # Scan all regions
                        scan_regions = [
                            "us-east-1", "us-east-2", "us-west-1", "us-west-2",
                            "eu-west-1", "eu-west-2", "eu-west-3", "eu-central-1",
                            "ap-southeast-1", "ap-southeast-2", "ap-northeast-1", "ap-northeast-2",
                            "ap-south-1", "ca-central-1", "sa-east-1"
                        ]
                    else:
                        # User typed a custom region
                        scan_regions = [user_input]

                    self.current_scan_region = scan_regions[0]

                except (KeyboardInterrupt, EOFError):
                    self.running_module_names.pop()
                    self._module_running = False
                    self._just_ran_module = False
                    return False

            self.console.print(f"\n  Scanning {service.upper()} in regions: {', '.join(scan_regions)}")

            all_findings = []
            total_resources = 0
            scan_id = f"scan-{service}-{time.strftime('%Y%m%d-%H%M%S')}"

            # For lambda scan-all, use the handler to get detailed output with env vars
            if service == 'lambda' and module_name == 'scan-all':
                try:
                    from awsprowl.cli.ui.handlers import run_full_lambda_scan
                    self.console.print(f"  Running {service} full scan via handler...")
                    # Run handler for each region
                    for region in scan_regions:
                        self.console.print(f"  Scanning {region}...")
                        findings = asyncio.run(run_full_lambda_scan(self.auth_manager, region=region))
                        all_findings.extend(findings)
                        total_resources += len(findings)
                except Exception as e:
                    self.console.print(f"[red]Handler failed:[/red] {e}")
                    log.exception("Handler execution failed")
                    # Fall back to scanner class
                    all_findings = []

            # For other services or if handler failed, use scanner class
            if not all_findings or not (service == 'lambda' and module_name == 'scan-all'):
                # Import scanner module
                import importlib
                module_file_map = {'lambda': 'lambda_', 'secretsmanager': 'secrets'}
                file_name = module_file_map.get(service, service)

                try:
                    module = importlib.import_module(f"awsprowl.aws.{file_name}")
                except ImportError as e:
                    self.console.print(f"[red]Failed to import {service} module: {e}[/red]")
                    self.running_module_names.pop()
                    self._module_running = False
                    self._just_ran_module = False
                    return False

                # Get scanner class
                class_name_map = {'lambda': 'Lambda', 'secretsmanager': 'Secrets'}
                class_suffix = class_name_map.get(service, service.capitalize())
                if service in ['iam', 'sts', 'ec2', 's3', 'sns', 'rds', 'kms', 'eks']:
                    class_suffix = service.upper()

                scanner_class = getattr(module, f'{class_suffix}Scanner', None)
                if not scanner_class:
                    for attr in dir(module):
                        if attr.endswith('Scanner') and service.lower() in attr.lower():
                            scanner_class = getattr(module, attr)
                            break

                if not scanner_class:
                    self.console.print(f"[red]Could not find scanner class for {service}[/red]")
                    self.running_module_names.pop()
                    self._module_running = False
                    self._just_ran_module = False
                    return False

                try:
                    for region in scan_regions:
                        if service not in global_services:
                            scanner = scanner_class(self.auth_manager, region=region)
                        else:
                            scanner = scanner_class(self.auth_manager)

                        self.console.print(f"  Scanning {region}...")
                        result = asyncio.run(scanner.scan(scan_id, all_findings))
                        total_resources += result.resources_found

                except Exception as e:
                    self.console.print(f"[red]Scanner failed:[/red] {e}")
                    log.exception("Scanner execution failed")
                    return False
                finally:
                    self.running_module_names.pop()
                    self._module_running = False

            # Store findings in session data
            service_key = service.upper()
            self.last_results = all_findings
            self.last_module_name = module_name

            # Print Prowl-style scanner summary
            self.print_scanner_summary(service, scan_regions, total_resources, all_findings)

            # Display detailed findings like individual modules (Prowl style)
            from awsprowl.cli.ui.prowl_display import ProwlDisplay
            display = ProwlDisplay(self.console, module_name)
            display.print_findings_detailed(all_findings, "finding")
            display.print_summary(module_name)

            # Save results with custom format: output/{profile}/{service}_option.json
            self._save_scan_results(service, module_name, all_findings, scan_regions, total_resources)

        return True

    def print_scanner_summary(self, service: str, regions: list, total_resources: int, findings: list):
        """Print Prowl-style scanner summary with severity breakdown."""
        self.console.print(f"\n[bold green]SCANNER SUMMARY: {service.upper()}[/bold green]\n")
        self.console.print(f"  Service: {service.upper()}")
        self.console.print(f"  Regions scanned: {', '.join(regions)}")
        self.console.print(f"  Resources found: {total_resources}")
        self.console.print(f"  Findings: {len(findings)}")

        if findings:
            self.console.print("\n  Findings by severity:")
            severity_counts = {'critical': 0, 'high': 0, 'medium': 0, 'low': 0, 'info': 0}
            for finding in findings:
                severity = finding.get('severity', 'info').lower()
                if severity in severity_counts:
                    severity_counts[severity] += 1

            for severity in ['critical', 'high', 'medium', 'low', 'info']:
                if severity_counts[severity] > 0:
                    color = {'critical': 'red', 'high': 'red', 'medium': 'yellow', 'low': 'blue', 'info': 'green'}[severity]
                    self.console.print(f"    [{color}]{severity.capitalize()}: {severity_counts[severity]}[/{color}]")

            self.console.print("\n  Top findings:")
            for finding in findings[:10]:
                severity = finding.get('severity', 'info').upper()
                title = finding.get('title', 'Unknown')
                resource = finding.get('resource_id', 'N/A')
                color = {'CRITICAL': 'red', 'HIGH': 'red', 'MEDIUM': 'yellow', 'LOW': 'blue', 'INFO': 'green'}.get(severity, 'white')
                self.console.print(f"  [{color}]{severity}[/{color}] {title} ({resource})")

            if len(findings) > 10:
                self.console.print(f"  ... and {len(findings) - 10} more findings")

    def _save_scan_results(self, service: str, module_name: str, findings: list, regions: list, total_resources: int) -> None:
        """Save scan results in output/{profile}/{service}_option.json format."""
        try:
            import json
            from pathlib import Path
            from datetime import datetime, timezone

            profile = self.current_profile or "default"
            output_dir = Path("output") / profile
            output_dir.mkdir(parents=True, exist_ok=True)

            timestamp = datetime.now(timezone.utc).strftime('%Y%m%d-%H%M%S')
            json_file = output_dir / f"{service}_{module_name}.json"

            output_data = {
                "profile": profile,
                "service": service,
                "module": module_name,
                "timestamp": timestamp,
                "regions_scanned": regions,
                "resources_found": total_resources,
                "findings_count": len(findings),
                "findings": findings,
            }

            with open(json_file, "w") as f:
                json.dump(output_data, f, indent=2, default=str)

            self.console.print(f"  [green]Results saved to: {json_file}[/green]")
        except Exception as e:
            log.error("Failed to save results: %s", e)

    def handle_command(self, command: str) -> bool:
        """Handle user command - Prowl style."""
        command = command.strip()
        if not command:
            # Empty command - at profile_select, continue to services with current profile
            if self.current_view == 'profile_select':
                self.current_view = 'services'
                self._show_view = True
            return True

        parts = shlex.split(command)
        cmd = parts[0].lower()

        # Add to command history (skip empty and exit commands)
        if cmd not in ('exit', 'quit', 'q'):
            self.command_history.append(command)

        # Exit commands
        if cmd in ('exit', 'quit', 'q'):
            return False

        # Help
        if cmd in ('help', 'h', '?'):
            self.current_view = 'help'
            self._show_view = True
            return True

        # Back command (full name)
        if cmd in ('back', 'b'):
            if self.current_view == 'modules':
                self.current_view = 'services'
                self.selected_service = None
                self._show_view = True
            elif self.current_view == 'search':
                self.current_view = 'services' if self.selected_service else 'profile_select'
                self.search_text = ""
                self._show_view = True
            elif self.current_view == 'profile_select':
                return False
            elif self.current_view == 'services':
                self.current_view = 'profile_select'
                self._show_view = True
            elif self.current_view == 'help':
                self.current_view = 'services' if self.selected_service else 'profile_select'
                self._show_view = True
            return True

        # Clear command (full name)
        if cmd in ('clear', 'c'):
            # If in JSON view, clear it and return to services
            if self.current_view == 'json_view':
                self.json_view_data = None
                self.json_view_path = None
                self.current_view = 'services'
                self._show_view = True
                self.console.print("[green]JSON view cleared[/green]")
                return True
            self.current_view = 'services'
            self.search_text = ""
            self.last_results = None
            self.last_module_name = None
            self._show_view = True
            self.console.print("[green]Search results cleared[/green]")
            return True

        # Open JSON command
        if cmd in ('open_json', 'oj', 'view_json'):
            if len(parts) < 2:
                self.console.print("[yellow]Usage: open_json <path/to/file.json>[/yellow]")
                self.console.print("[dim]Example: open_json output/cloudgoat/iam_scan-all.json[/dim]")
                return True

            json_path = parts[1]
            import os
            import json

            # Resolve path relative to current directory if not absolute
            if not os.path.isabs(json_path):
                json_path = os.path.join(os.getcwd(), json_path)

            if not os.path.exists(json_path):
                self.console.print(f"[red]File not found: {json_path}[/red]")
                return True

            if not json_path.endswith('.json'):
                self.console.print(f"[yellow]Warning: File doesn't have .json extension[/yellow]")

            try:
                with open(json_path, 'r') as f:
                    self.json_view_data = json.load(f)
                self.json_view_path = json_path
                self.current_view = 'json_view'
                self._show_view = True
                self.console.print(f"[green]✓ Loaded JSON file: {json_path}[/green]")
            except json.JSONDecodeError as e:
                self.console.print(f"[red]Invalid JSON: {e}[/red]")
            except Exception as e:
                self.console.print(f"[red]Error reading file: {e}[/red]")

            return True

        # Last command (full name)
        if cmd in ('last', 'l'):
            self._show_last_results()
            return True

        # History command (full name)
        if cmd in ('history', 'hist', 'h'):
            self._show_history()
            return True

        # Profile selection
        if cmd in ('profiles', 'profile', 'p'):
            self.current_view = 'profile_select'
            self._show_view = True
            return True

        # Services list
        if cmd in ('services', 'list', 'ls', 's'):
            self.current_view = 'services'
            self.selected_service = None
            self._show_view = True
            return True

        # Search
        if cmd == 'search':
            if len(parts) < 2:
                self.console.print("[yellow]Usage: search <query> (e.g., 'search iam', 'search encryption')[/yellow]")
            else:
                self.current_view = 'search'
                self.search_text = ' '.join(parts[1:])
                self._show_view = True
            return True

        # Whoami command - display current AWS caller identity
        if cmd in ('whoami', 'caller-identity'):
            return self._handle_whoami_command()

        # Info command - show module details
        if cmd in ('info', 'show-module', 'module-info'):
            # Check for info <number> in search view
            if self.current_view == 'search' and len(parts) >= 2:
                try:
                    num = int(parts[1])
                    results = self.search_modules(self.search_text)
                    if 1 <= num <= len(results):
                        service, module = results[num - 1]
                        return self._handle_info_command(['info', module.name])
                except ValueError:
                    pass
            # Check for info <number> in modules view
            if self.current_view == 'modules' and self.selected_service and len(parts) >= 2:
                try:
                    num = int(parts[1])
                    modules = self.get_modules_for_service(self.selected_service)
                    if 1 <= num <= len(modules):
                        module = modules[num - 1]
                        return self._handle_info_command(['info', module.name])
                except ValueError:
                    pass
            return self._handle_info_command(parts)

        # Modules command - list all modules
        if cmd in ('modules', 'all-modules', 'list-modules'):
            return self._handle_modules_command(parts)

        # Privesc command - run all privilege escalation modules
        if cmd in ('privesc', 'privilege-escalation', 'privesc-all'):
            return self._handle_privesc_command(parts)

        # Category filter
        if cmd in ('category', 'cat', 'filter'):
            valid_categories = ['enum', 'privesc', 'exploit', 'persist', 'backdoor', 'exfil']
            if len(parts) < 2:
                # Show current filter and available categories
                if self.category_filter:
                    self.console.print(f"[green]Current category filter:[/green] {self.category_filter}")
                else:
                    self.console.print("[yellow]No category filter active (showing all categories)[/yellow]")
                self.console.print(f"[dim]Available categories:[/dim] {', '.join(valid_categories)}")
                self.console.print("[dim]Usage:[/dim] category <enum|privesc|exploit|persist|backdoor|exfil>")
                self.console.print("[dim]Clear filter:[/dim] category clear")
                return True

            filter_value = parts[1].lower()
            if filter_value in ('clear', 'none', 'all', 'off'):
                self.category_filter = None
                self.console.print("[green]Category filter cleared - showing all modules[/green]")
            elif filter_value in valid_categories:
                self.category_filter = filter_value
                self.console.print(f"[green]Category filter set to:[/green] {filter_value}")
            else:
                self.console.print(f"[red]Invalid category: {filter_value}[/red]")
                self.console.print(f"[dim]Available categories:[/dim] {', '.join(valid_categories)}")
            return True

        # Run module
        if cmd in ('run', 'exec', 'use'):
            if len(parts) < 2:
                self.console.print("[yellow]Usage: run <module> or run <service> <module> [region][/yellow]")
                return True

            # Check for run <number> in search view
            if self.current_view == 'search' and len(parts) >= 2:
                try:
                    num = int(parts[1])
                    results = self.search_modules(self.search_text)
                    if 1 <= num <= len(results):
                        service, module = results[num - 1]
                        parts = ['run', module.name]
                except ValueError:
                    pass

            # Check for run <number> in modules view
            if self.current_view == 'modules' and self.selected_service and len(parts) >= 2:
                try:
                    num = int(parts[1])
                    modules = self.get_modules_for_service(self.selected_service)
                    if 1 <= num <= len(modules):
                        module = modules[num - 1]
                        parts = ['run', module.name]
                except ValueError:
                    pass

            # Check if last part is a region (e.g., us-east-1)
            region = None
            if len(parts) >= 3:
                # Check if the last part looks like a region
                last_part = parts[-1]
                common_regions = [
                    "us-east-1", "us-east-2", "us-west-1", "us-west-2",
                    "eu-west-1", "eu-west-2", "eu-west-3", "eu-central-1",
                    "ap-southeast-1", "ap-southeast-2", "ap-northeast-1", "ap-northeast-2",
                    "ap-south-1", "ca-central-1", "sa-east-1", "all"
                ]
                if last_part in common_regions or self._is_valid_region_code(last_part):
                    region = last_part
                    parts = parts[:-1]  # Remove region from parts

            if len(parts) == 2:
                # Try to find module across all services
                module_name = parts[1]
                found = False
                for service in self.get_services():
                    modules = self.get_modules_for_service(service)
                    for module in modules:
                        if module.name == module_name or service == module_name:
                            if service == module_name and module.is_scan_all:
                                if region:
                                    self.config.scan.regions = [region] if region != "all" else None
                                self.run_service_scanner(service, module_name)
                                found = True
                                break
                            elif module.name == module_name:
                                if region and module.args is not None:
                                    module.args['region'] = region
                                self.run_module(service, module)
                                found = True
                                break
                    if found:
                        break

                if not found:
                    self.console.print(f"[red]Module not found: {module_name}[/red]")
                    self.console.print("[dim]Use 'search' to find modules[/dim]")

            elif len(parts) >= 3:
                # run service module
                service = parts[1]
                module_name = parts[2]

                if service in self.get_services() and module_name == 'scan-all':
                    if region:
                        self.config.scan.regions = [region] if region != "all" else None
                    self.run_service_scanner(service, module_name)
                else:
                    modules = self.get_modules_for_service(service)
                    found = False
                    for module in modules:
                        if module.name == module_name:
                            if region and module.args is not None:
                                module.args['region'] = region
                            self.run_module(service, module)
                            found = True
                            break
                    if not found:
                        self.console.print(f"[red]Module not found: {service}/{module_name}[/red]")

            return True

        # Number selection in region selection mode
        if self._region_selection_mode:
            # If command has multiple parts (e.g., "region us-east-2"), it's a full command
            # not a menu response - skip region selection mode and let normal handler process
            if len(parts) > 1:
                self._region_selection_mode = False
            else:
                try:
                    num = int(cmd)
                    common_regions = [
                        "us-east-1", "us-east-2", "us-west-1", "us-west-2",
                        "eu-west-1", "eu-west-2", "eu-west-3", "eu-central-1",
                        "ap-southeast-1", "ap-southeast-2", "ap-northeast-1", "ap-northeast-2",
                        "ap-south-1", "ca-central-1", "sa-east-1"
                    ]
                    if 1 <= num <= len(common_regions):
                        self.current_scan_region = common_regions[num - 1]
                        self.config.scan.regions = [self.current_scan_region]
                        self.console.print(f"[green]✓ Set scan region to: {self.current_scan_region}[/green]")
                    self._region_selection_mode = False
                    return True
                except ValueError:
                    # If not a number, check for 'all' or custom region
                    if cmd.lower() == 'all':
                        self.current_scan_region = "all"
                        self.config.scan.regions = None
                        self.console.print("[green]✓ Set scan region to: all regions[/green]")
                    elif cmd and self._is_valid_region_code(cmd):
                        self.current_scan_region = cmd
                        self.config.scan.regions = [cmd]
                        self.console.print(f"[green]✓ Set scan region to: {cmd}[/green]")
                    else:
                        self.console.print(f"[red]Invalid region: {cmd}[/red]")
                        self.console.print(f"[dim]Valid regions:[/dim] us-east-1, us-east-2, us-west-1, us-west-2, eu-west-1, eu-west-2, eu-west-3, eu-central-1, ap-southeast-1, ap-southeast-2, ap-northeast-1, ap-northeast-2, ap-south-1, ca-central-1, sa-east-1, or 'all'")
                    self._region_selection_mode = False
                    return True

        # Number selection in profile view
        if self.current_view == 'profile_select':
            try:
                num = int(cmd)
                profiles = self._refresh_profiles()
                if 1 <= num <= len(profiles):
                    self.current_profile = profiles[num - 1]
                    self.auth_manager = None
                    self.config.aws.profile = self.current_profile
                    # Initialize auth to show credentials in status bar (suppress logs)
                    with self._suppress_logs():
                        auth_ok = self._ensure_auth()
                    self.current_view = 'services'
                    self._show_view = True
                    if auth_ok:
                        self.console.print(f"[green]✓ Switched to profile:[/green] {self.current_profile}")
                    else:
                        self.console.print(f"[yellow]⚠ Switched to profile:[/yellow] {self.current_profile} [dim](auth failed - some modules may not work)[/dim]")
                return True
            except ValueError:
                pass

        # Number selection in services view
        if self.current_view == 'services':
            try:
                num = int(cmd)
                services = self.get_services()
                if 1 <= num <= len(services):
                    self.selected_service = services[num - 1]
                    self.current_view = 'modules'
                    self._show_view = True
                    self.console.print(f"\n[green]Selected service:[/green] {self.selected_service}\n")
                return True
            except ValueError:
                pass

        # Number selection in modules view
        if self.current_view == 'modules' and self.selected_service:
            try:
                num = int(cmd)
                modules = self.get_modules_for_service(self.selected_service)
                if 1 <= num <= len(modules):
                    module = modules[num - 1]
                    if module.is_scan_all:
                        self.run_service_scanner(self.selected_service, module.name)
                    else:
                        self.run_module(self.selected_service, module)
                return True
            except ValueError:
                pass

        # Number selection in search view
        if self.current_view == 'search':
            try:
                num = int(cmd)
                results = self.search_modules(self.search_text)
                if 1 <= num <= len(results):
                    service, module = results[num - 1]
                    if module.is_scan_all:
                        self.run_service_scanner(service, module.name)
                    else:
                        self.run_module(service, module)
                return True
            except ValueError:
                pass

        # Region command - show/set current scan region
        if cmd in ('region', 'r'):
            return self._handle_region_command(parts)

        # Diff command - compare two scan files
        if cmd in ('diff', 'compare'):
            return self._handle_diff_command(parts)

        # Export CSV command
        if cmd in ('export_csv', 'csv', 'export'):
            return self._handle_export_csv_command(parts)

        # Tag command - manage finding tags
        if cmd in ('tag', 'tags'):
            return self._handle_tag_command(parts)

        # Unknown command - treat as search
        self.current_view = 'search'
        self.search_text = command
        self._show_view = True
        return True

    def _get_scan_regions(self, service: str) -> list[str]:
        """Get regions to scan - allows interactive selection."""
        global_services = {'iam', 'sts', 'cloudfront', 'organizations', 'route53', 'waf', 'wafv2'}
        if service in global_services:
            return ['us-east-1']

        # Get available regions
        common_regions = [
            "us-east-1", "us-east-2", "us-west-1", "us-west-2",
            "eu-west-1", "eu-west-2", "eu-west-3", "eu-central-1",
            "ap-southeast-1", "ap-southeast-2", "ap-northeast-1", "ap-northeast-2",
            "ap-south-1", "ca-central-1", "sa-east-1"
        ]

        # Use configured regions if set
        if self.config.scan.regions:
            return self.config.scan.regions

        # If current_scan_region is set and not "global", use it as default
        if self.current_scan_region and self.current_scan_region != "global":
            default_region = self.current_scan_region
        else:
            default_region = "us-east-1"

        # Prompt user for region selection
        self.console.print("\n[bold]Region Selection[/bold]")
        self.console.print("  [1] us-east-1 (N. Virginia)")
        self.console.print("  [2] us-east-2 (Ohio)")
        self.console.print("  [3] us-west-1 (N. California)")
        self.console.print("  [4] us-west-2 (Oregon)")
        self.console.print("  [5] eu-west-1 (Ireland)")
        self.console.print("  [6] eu-west-2 (London)")
        self.console.print("  [7] eu-central-1 (Frankfurt)")
        self.console.print("  [8] ap-southeast-1 (Singapore)")
        self.console.print("  [9] ap-southeast-2 (Sydney)")
        self.console.print("  [10] ap-northeast-1 (Tokyo)")
        self.console.print("  [11] all - Scan all regions")
        self.console.print("  [custom] Enter region code manually (e.g., eu-west-3)")
        self.console.print()

        try:
            choice = self.input("[cyan]Select region (1-11, 'all', or custom): [/cyan]").strip()

            if choice.lower() == 'all':
                return common_regions

            # Try to parse as number
            try:
                num = int(choice)
                if 1 <= num <= len(common_regions):
                    return [common_regions[num - 1]]
            except ValueError:
                # Treat as custom region code
                if choice:
                    return [choice]

            # Default to us-east-1 (or current region if set)
            return [default_region]
        except (KeyboardInterrupt, EOFError):
            return []

    def _handle_region_command(self, parts: list) -> bool:
        """Handle region command to show/set current scan region."""
        common_regions = [
            "us-east-1", "us-east-2", "us-west-1", "us-west-2",
            "eu-west-1", "eu-west-2", "eu-west-3", "eu-central-1",
            "ap-southeast-1", "ap-southeast-2", "ap-northeast-1", "ap-northeast-2",
            "ap-south-1", "ca-central-1", "sa-east-1"
        ]

        if len(parts) == 1:
            # Show current region and enter region selection mode
            current = self.current_scan_region if hasattr(self, 'current_scan_region') and self.current_scan_region else "us-east-1 (default)"
            self.console.print(f"\n[bold]Current Scan Region:[/bold] {current}")
            self.console.print(f"\n[bold]Available Regions:[/bold]")
            for i, r in enumerate(common_regions):
                marker = " ← current" if r == current.split()[0] else ""
                self.console.print(f"  {i+1:2}. {r}{marker}")
            self.console.print(f"  all - Scan all regions")
            self.console.print(f"  [dim]Enter number, region code, or 'all' to select[/dim]")
            self.console.print()
            # Enter region selection mode
            self._region_selection_mode = True
            return True

        region_arg = parts[1].lower()
        if region_arg == 'list':
            self.console.print("\n[bold]Available Regions:[/bold]")
            for i, r in enumerate(common_regions):
                self.console.print(f"  {i+1:2}. {r}")
            self.console.print("  all - Scan all regions")
            self.console.print()
            return True

        if region_arg == 'all':
            self.current_scan_region = "all"
            self.config.scan.regions = None  # None means all regions
            self.console.print("[green]✓ Set scan region to: all regions[/green]")
            return True

        if region_arg in common_regions:
            self.current_scan_region = region_arg
            self.config.scan.regions = [region_arg]
            self.console.print(f"[green]✓ Set scan region to: {region_arg}[/green]")
            return True

        # Try custom region - but validate it looks like an AWS region code
        if self._is_valid_region_code(region_arg):
            self.current_scan_region = region_arg
            self.config.scan.regions = [region_arg]
            self.console.print(f"[green]✓ Set scan region to: {region_arg}[/green]")
        else:
            self.console.print(f"[red]Invalid region: {region_arg}[/red]")
            self.console.print(f"[dim]Valid regions:[/dim] {', '.join(common_regions)}, or 'all'")
        return True

    def _is_valid_region_code(self, region: str) -> bool:
        """Check if a string looks like a valid AWS region code."""
        # AWS region pattern: partition-region-number (e.g., us-east-1, eu-west-2, cn-north-1)
        import re
        return bool(re.match(r'^[a-z]{2}-[a-z]+-\d+$', region))

    def _handle_whoami_command(self) -> bool:
        """Handle whoami command to display current AWS caller identity."""
        try:
            if self.auth_manager is None:
                from awsprowl.core.auth import create_auth_manager
                from awsprowl.core.config import AWSConfig
                self.auth_manager = create_auth_manager(AWSConfig(profile=self.current_profile))
            
            identity = self.auth_manager.get_caller_identity()
            
            from rich.panel import Panel
            from rich.json import JSON
            from rich.box import HEAVY
            
            self.console.print()
            self.console.print(Panel(
                JSON.from_data(identity),
                title="[bold]AWS Caller Identity[/bold]",
                border_style="cyan",
                box=HEAVY,
                padding=(1, 2),
                expand=False,
            ))
            self.console.print()
            return True
        except Exception as e:
            self.console.print(f"[red]Error getting caller identity: {e}[/red]")
            return True

    def _handle_info_command(self, parts: list) -> bool:
        """Handle info command to show module details."""
        if len(parts) < 2:
            self.console.print("[yellow]Usage: info <module_name>[/yellow]")
            self.console.print("[dim]Example: info iam_enum_users, info check-mfa, info iam_exploit_create_user[/dim]")
            return True

        module_name = parts[1]
        
        # First, try to find the module in the registry
        from awsprowl.modules import get_module, ModuleCategory, ModuleRisk
        module_meta = get_module(module_name)
        
        if not module_meta:
            # Try to find as a SERVICE_MODULES action (like check-mfa)
            found = False
            for service, modules in SERVICE_MODULES.items():
                for m in modules:
                    if m.name == module_name:
                        self._print_module_info_panel(service, m, module_meta)
                        found = True
                        break
                if found:
                    break
            
            # Also check ATTACK_MODULES
            if not found:
                for service, modules in ATTACK_MODULES.items():
                    for m in modules:
                        if m.name == module_name:
                            self._print_module_info_panel(service, m, module_meta)
                            found = True
                            break
                    if found:
                        break
            
            if not found:
                self.console.print(f"[red]Module not found: {module_name}[/red]")
                self.console.print("[dim]Use 'search' or 'list' to find available modules[/dim]")
            return True
        
        # Found in registry - get service from supported_services
        service = module_meta.supported_services[0] if module_meta.supported_services else "unknown"
        
        # Find the ModuleAction for this module to get handler info
        action = None
        for svc in [service] + self.get_services():
            modules = self.get_modules_for_service(svc)
            for m in modules:
                if m.name == module_name:
                    action = m
                    break
            if action:
                break
        
        self._print_module_info_panel(service, action, module_meta)
        return True

    def _handle_modules_command(self, parts: list) -> bool:
        """Handle modules command to list all modules across all services.
        
        Usage:
            modules                    # List all modules
            modules iam                # List only IAM modules
            modules ec2                # List only EC2 modules
        """
        from rich.table import Table
        from rich.box import HEAVY
        
        # Check if a service filter was provided
        service_filter = None
        if len(parts) >= 2:
            service_filter = parts[1].lower()
        
        # Get all modules from both SERVICE_MODULES and ATTACK_MODULES
        all_modules = []
        
        # Add SERVICE_MODULES
        for service, modules in SERVICE_MODULES.items():
            if service_filter and service.lower() != service_filter:
                continue
            for m in modules:
                all_modules.append({
                    'name': m.name,
                    'service': service,
                    'category': m.category,
                    'description': m.description,
                    'type': 'service'
                })
        
        # Add ATTACK_MODULES
        for service, modules in ATTACK_MODULES.items():
            if service_filter and service.lower() != service_filter:
                continue
            for m in modules:
                # Get metadata from registry if available
                from awsprowl.modules import get_module
                meta = get_module(m.name)
                category = meta.category.value if meta else m.category
                risk = meta.risk.value if meta else getattr(m, 'risk_level', 'unknown')
                destructive = meta.destructive if meta else getattr(m, 'destructive', False)
                all_modules.append({
                    'name': m.name,
                    'service': service,
                    'category': category,
                    'description': m.description,
                    'type': 'attack',
                    'risk': risk,
                    'destructive': destructive
                })
        
        if not all_modules:
            if service_filter:
                self.console.print(f"[red]No modules found for service: {service_filter}[/red]")
                self.console.print("[dim]Available services: " + ", ".join(sorted(set(list(SERVICE_MODULES.keys()) + list(ATTACK_MODULES.keys())))) + "[/dim]")
            else:
                self.console.print("[red]No modules found[/red]")
            return True
        
        # Sort by service, then category, then name
        all_modules.sort(key=lambda x: (x['service'], x['category'], x['name']))
        
        # Print summary
        if service_filter:
            self.console.print(f"\n[bold cyan]Modules for {service_filter.upper()} ({len(all_modules)} total)[/bold cyan]\n")
        else:
            self.console.print(f"\n[bold cyan]All Modules ({len(all_modules)} total)[/bold cyan]\n")
        
        # Group by service
        from collections import defaultdict
        by_service = defaultdict(list)
        for m in all_modules:
            by_service[m['service']].append(m)
        
        for service in sorted(by_service.keys()):
            modules = by_service[service]
            self.console.print(f"[bold green]{service.upper()}[/bold green] ({len(modules)} modules)")
            
            table = Table(box=HEAVY, show_header=True, header_style="bold cyan")
            table.add_column("Module Name", style="cyan", no_wrap=True, width=40)
            table.add_column("Category", style="yellow", width=15)
            if service in ATTACK_MODULES:
                table.add_column("Risk", style="red", width=8)
                table.add_column("Destructive", style="magenta", width=10)
            table.add_column("Description", style="white")
            
            for m in modules:
                category_display = m['category']
                # Add category marker
                from awsprowl.cli.ui.tui import CATEGORY_MARKERS
                cat_marker = CATEGORY_MARKERS.get(m['category'], '[MOD]')
                
                if service in ATTACK_MODULES and m.get('type') == 'attack':
                    risk = m.get('risk', 'unknown').upper()
                    risk_colors = {
                        'SAFE': 'green', 'LOW': 'blue', 'MEDIUM': 'yellow',
                        'HIGH': 'orange3', 'CRITICAL': 'red', 'UNKNOWN': 'white'
                    }
                    risk_color = risk_colors.get(risk, 'white')
                    risk_display = f"[{risk_color}]{risk}[/{risk_color}]"
                    
                    destructive = "✓" if m.get('destructive', False) else "✗"
                    destructive_color = "red" if m.get('destructive', False) else "green"
                    destructive_display = f"[{destructive_color}]{destructive}[/{destructive_color}]"
                    
                    table.add_row(
                        m['name'],
                        f"{cat_marker} {category_display}",
                        risk_display,
                        destructive_display,
                        m['description'][:80] + ("..." if len(m['description']) > 80 else "")
                    )
                else:
                    table.add_row(
                        m['name'],
                        f"{cat_marker} {category_display}",
                        m['description'][:80] + ("..." if len(m['description']) > 80 else "")
                    )
            
            self.console.print(table)
            self.console.print()
        
        # Footer hint
        self.console.print("[dim]Use 'info <module>' for detailed information about any module[/dim]")
        self.console.print("[dim]Use 'run <module>' to execute a module[/dim]")
        self.console.print("[dim]Use 'category <type>' to filter by category (enum, exploit, persist, backdoor, exfil, privesc)[/dim]")
        self.console.print("[dim]Use 'modules <service>' to filter modules by service (e.g., modules iam)[/dim]\n")
        
        return True

    def _print_module_info_panel(self, service: str, module_action, module_meta):
        """Print detailed module information panel."""
        from rich.panel import Panel
        from rich.table import Table
        from rich.text import Text
        from rich.box import HEAVY
        
        # Get metadata from either source
        if module_meta:
            name = module_meta.name
            description = module_meta.description
            category = module_meta.category.value
            risk = module_meta.risk.value
            required_permissions = module_meta.required_permissions
            mitre_techniques = module_meta.mitre_techniques
            destructive = module_meta.destructive
            requires_confirmation = module_meta.requires_confirmation
            tags = module_meta.tags
        else:
            name = module_action.name if module_action else "unknown"
            description = module_action.description if module_action else "No description available"
            category = module_action.category if module_action else "unknown"
            risk = getattr(module_action, 'risk_level', 'unknown')
            required_permissions = getattr(module_action, 'required_permissions', [])
            mitre_techniques = getattr(module_action, 'mitre_techniques', [])
            destructive = getattr(module_action, 'destructive', False)
            requires_confirmation = getattr(module_action, 'requires_confirmation', False)
            tags = []
        
        # Risk color
        risk_colors = {
            'safe': 'green',
            'low': 'blue',
            'medium': 'yellow',
            'high': 'orange3',
            'critical': 'red'
        }
        risk_color = risk_colors.get(risk, 'white')
        
        # Category marker
        from awsprowl.cli.ui.tui import CATEGORY_MARKERS
        cat_marker = CATEGORY_MARKERS.get(category, '[MOD]')
        
        # Build info text
        lines = []
        lines.append(f"[bold cyan]Module:[/bold cyan] {name}")
        lines.append(f"[bold cyan]Service:[/bold cyan] {service}")
        lines.append(f"[bold cyan]Category:[/bold cyan] {cat_marker} {category.replace('_', ' ').title()}")
        lines.append(f"[bold cyan]Risk:[/bold cyan] [{risk_color}]{risk.upper()}[/{risk_color}]")
        lines.append(f"[bold cyan]Destructive:[/bold cyan] {'[red]Yes[/red]' if destructive else '[green]No[/green]'}")
        lines.append(f"[bold cyan]Requires Confirmation:[/bold cyan] {'[yellow]Yes[/yellow]' if requires_confirmation else '[green]No[/green]'}")
        lines.append(f"[bold cyan]Description:[/bold cyan] {description}")
        lines.append("")

        if required_permissions:
            lines.append("[bold cyan]Required Permissions:[/bold cyan]")
            for perm in required_permissions:
                lines.append(f"  • {perm}")
            lines.append("")

        if mitre_techniques:
            lines.append("[bold cyan]MITRE ATT&CK Techniques:[/bold cyan]")
            for tech in mitre_techniques:
                lines.append(f"  • {tech}")
            lines.append("")

        if tags:
            lines.append("[bold cyan]Tags:[/bold cyan]")
            lines.append(f"  {', '.join(tags)}")
            lines.append("")

        # Usage examples
        lines.append("[bold cyan]Usage Examples:[/bold cyan]")
        lines.append(f"  run {name}")
        if service not in {'iam', 'sts', 'cloudfront', 'organizations'}:
            lines.append(f"  run {service} {name} us-east-1")
        if requires_confirmation and destructive:
            lines.append(f"  # Note: Requires typing 'CONFIRM' to execute (destructive)")

        content = "\n".join(lines)
        
        panel = Panel(
            content,
            title=f"[bold]Module Info: {name}[/bold]",
            border_style="cyan",
            box=HEAVY,
            padding=(1, 2),
            expand=False,
        )
        self.console.print()
        self.console.print(panel)
        self.console.print()

    def _handle_privesc_command(self, parts: list) -> bool:
        """Handle privesc command to run all privilege escalation modules."""
        if not self._ensure_auth():
            self.console.print("[yellow]Run 'profiles' to select a different profile[/yellow]")
            return True

        self._module_running = True
        self.running_module_names.append("privesc-all")
        self._just_ran_module = True

        self.console.print("\n[bold cyan]Running ALL Privilege Escalation Modules...[/bold cyan]")
        self.console.print("[dim]This will run privesc checks across IAM, EC2, S3, Lambda, CodeBuild, VPC[/dim]\n")

        try:
            with self.console.status("[cyan]Running comprehensive privesc scan...[/cyan]", spinner="dots"):
                findings = asyncio.run(run_all_privesc(self.auth_manager))

            self.last_results = findings
            self.last_module_name = "privesc-all"

            # Display and save results
            display_and_save_results(findings, self.console, "privesc-all", self.current_profile, "privesc")

            # Print Prowl-style summary
            self._print_privesc_summary(findings)

        except Exception as e:
            self.console.print(f"[red]Privesc scan failed:[/red] {e}")
            log.exception("Privesc scan failed")
        finally:
            self.running_module_names.pop()
            self._module_running = False

        return True

    def _print_privesc_summary(self, findings: list[dict]) -> None:
        """Print privesc-specific summary with breakdown by service/module."""
        if not findings:
            self.console.print("\n[green]No privilege escalation paths found![/green]")
            return

        self.console.print(f"\n[bold green]PRIVESC SUMMARY: {len(findings)} total findings[/bold green]\n")

        # Group by source module
        from collections import defaultdict
        by_module = defaultdict(list)
        by_severity = defaultdict(int)

        for f in findings:
            module = f.get("source_module", "unknown")
            by_module[module].append(f)
            by_severity[f.get("severity", "info").lower()] += 1

        # Print by module
        for module, module_findings in sorted(by_module.items()):
            self.console.print(f"  [bold cyan]{module}[/bold cyan]: {len(module_findings)} findings")
            for f in module_findings[:3]:
                sev = f.get("severity", "info").upper()
                title = f.get("title", "Unknown")
                resource = f.get("resource_id", "N/A")
                color = {'CRITICAL': 'red', 'HIGH': 'red', 'MEDIUM': 'yellow', 'LOW': 'blue', 'INFO': 'green'}.get(sev, 'white')
                self.console.print(f"    [{color}]{sev}[/{color}] {title} ({resource})")
            if len(module_findings) > 3:
                self.console.print(f"    ... and {len(module_findings) - 3} more")

        # Print severity summary
        self.console.print("\n  [bold]By Severity:[/bold]")
        for sev in ['critical', 'high', 'medium', 'low', 'info']:
            count = by_severity.get(sev, 0)
            if count:
                color = {'critical': 'red', 'high': 'red', 'medium': 'yellow', 'low': 'blue', 'info': 'green'}[sev]
                self.console.print(f"    [{color}]{sev.capitalize()}: {count}[/{color}]")

    def _handle_diff_command(self, parts: list) -> bool:
        """Handle diff command to compare two scan files."""
        if len(parts) < 3:
            self.console.print("[yellow]Usage: diff <old_file.json> <new_file.json>[/yellow]")
            self.console.print("[dim]Example: diff output/prod/iam_scan-all.json output/staging/iam_scan-all.json[/dim]")
            return True

        import os
        import json

        old_path = parts[1]
        new_path = parts[2]

        # Resolve paths
        for i, path in enumerate([old_path, new_path]):
            if not os.path.isabs(path):
                path = os.path.join(os.getcwd(), path)
            if i == 0:
                old_path = path
            else:
                new_path = path

        for path, label in [(old_path, "old"), (new_path, "new")]:
            if not os.path.exists(path):
                self.console.print(f"[red]{label} file not found: {path}[/red]")
                return True
            if not path.endswith('.json'):
                self.console.print(f"[yellow]Warning: {label} file doesn't have .json extension[/yellow]")

        try:
            with open(old_path, 'r') as f:
                old_data = json.load(f)
            with open(new_path, 'r') as f:
                new_data = json.load(f)

            old_findings = old_data.get("findings", [])
            new_findings = new_data.get("findings", [])

            self.console.print(f"\n[bold]Comparing scans:[/bold]")
            self.console.print(f"  Old: {old_path} ({len(old_findings)} findings)")
            self.console.print(f"  New: {new_path} ({len(new_findings)} findings)")

            # Use ProwlDisplay to diff
            from awsprowl.cli.ui.prowl_display import ProwlDisplay
            display = ProwlDisplay(self.console)
            diff_result = display.diff_scans(old_findings, new_findings)
            display.print_diff(diff_result)

        except json.JSONDecodeError as e:
            self.console.print(f"[red]Invalid JSON: {e}[/red]")
        except Exception as e:
            self.console.print(f"[red]Error comparing files: {e}[/red]")

        return True

    def _handle_export_csv_command(self, parts: list) -> bool:
        """Handle CSV export command."""
        # Use last results if available, otherwise load from JSON file
        findings = self.last_results
        module_name = self.last_module_name or "export"
        output_path = None

        if len(parts) >= 2:
            # Check if first arg is a file path
            if parts[1].endswith('.json') or parts[1].endswith('.csv') or '/' in parts[1] or os.path.sep in parts[1]:
                # It's a file path - load findings from JSON
                json_path = parts[1]
                import os
                import json
                if not os.path.isabs(json_path):
                    json_path = os.path.join(os.getcwd(), json_path)
                if not os.path.exists(json_path):
                    self.console.print(f"[red]File not found: {json_path}[/red]")
                    return True
                try:
                    with open(json_path, 'r') as f:
                        data = json.load(f)
                    findings = data.get("findings", [])
                    module_name = data.get("module", "export")
                    self.console.print(f"[green]Loaded {len(findings)} findings from {json_path}[/green]")
                except Exception as e:
                    self.console.print(f"[red]Error reading file: {e}[/red]")
                    return True
            elif parts[1].endswith('.csv'):
                output_path = parts[1]
            else:
                # It's an output path
                output_path = parts[1]

        if len(parts) >= 3 and not output_path:
            output_path = parts[2]

        if not findings:
            self.console.print("[yellow]No findings to export. Run a module first or specify a JSON file.[/yellow]")
            self.console.print("[dim]Usage: export_csv [file.json] [output.csv][/dim]")
            return True

        from awsprowl.cli.ui.prowl_display import ProwlDisplay
        display = ProwlDisplay(self.console, module_name)
        csv_file = display.export_csv(findings, module_name, output_path)

        if csv_file:
            self.console.print(f"[green]✓ Exported {len(findings)} findings to CSV[/green]")

        return True

    def _handle_tag_command(self, parts: list) -> bool:
        """Handle tag command to manage finding tags."""
        if len(parts) < 2:
            self.console.print("[yellow]Usage: tag <add|remove|list|set> [finding_index] <tags...>[/yellow]")
            self.console.print("[dim]Examples:[/dim]")
            self.console.print("  tag add 1 critical,prod          # Add tags to finding #1")
            self.console.print("  tag remove 1 prod                # Remove tag from finding #1")
            self.console.print("  tag set 1 critical,prod,ticket-123  # Set tags (replace all)")
            self.console.print("  tag list                         # Show tags for all findings")
            return True

        subcmd = parts[1].lower()
        findings = self.last_results

        if not findings:
            self.console.print("[yellow]No findings loaded. Run a module or use 'last' first.[/yellow]")
            return True

        if subcmd == 'list':
            self.console.print(f"\n[bold]Tags for {len(findings)} findings:[/bold]")
            for i, finding in enumerate(findings, 1):
                tags = finding.get("tags", [])
                tag_str = ", ".join(tags) if tags else "[none]"
                title = finding.get("title", "Unknown")[:50]
                self.console.print(f"  {i:3}. {tag_str}  [dim]({title})[/dim]")
            return True

        if len(parts) < 3:
            self.console.print("[yellow]Usage: tag <add|remove|set> <finding_index> <tags...>[/yellow]")
            return True

        try:
            finding_idx = int(parts[2]) - 1
            if finding_idx < 0 or finding_idx >= len(findings):
                self.console.print(f"[red]Invalid finding index. Must be 1-{len(findings)}[/red]")
                return True
        except ValueError:
            self.console.print("[red]Finding index must be a number[/red]")
            return True

        tags = []
        if len(parts) > 3:
            # Join remaining parts and split by comma
            tag_str = " ".join(parts[3:])
            tags = [t.strip() for t in tag_str.split(",") if t.strip()]

        if subcmd == 'add':
            current_tags = set(findings[finding_idx].get("tags", []))
            current_tags.update(tags)
            findings[finding_idx]["tags"] = list(current_tags)
            findings[finding_idx]["updated_at"] = datetime.now(timezone.utc).isoformat()
            self.console.print(f"[green]✓ Added tags to finding #{finding_idx + 1}: {', '.join(tags)}[/green]")

        elif subcmd == 'remove':
            current_tags = set(findings[finding_idx].get("tags", []))
            current_tags.difference_update(tags)
            findings[finding_idx]["tags"] = list(current_tags)
            findings[finding_idx]["updated_at"] = datetime.now(timezone.utc).isoformat()
            self.console.print(f"[green]✓ Removed tags from finding #{finding_idx + 1}: {', '.join(tags)}[/green]")

        elif subcmd == 'set':
            findings[finding_idx]["tags"] = tags
            findings[finding_idx]["updated_at"] = datetime.now(timezone.utc).isoformat()
            self.console.print(f"[green]✓ Set tags for finding #{finding_idx + 1}: {', '.join(tags)}[/green]")

        else:
            self.console.print(f"[red]Unknown subcommand: {subcmd}. Use add, remove, set, or list[/red]")

        return True

    def _show_last_results(self) -> bool:
        """Show last module results."""
        if not self.last_results:
            self.console.print("[yellow]No previous results to display[/yellow]")
            return True

        module_name = self.last_module_name or "unknown"
        self.console.print(f"\n[bold cyan]=== Last Results: {module_name} ===[/bold cyan]\n")

        # Print detailed findings like Prowl
        from awsprowl.cli.ui.prowl_display import ProwlDisplay
        display = ProwlDisplay(self.console, module_name)
        display.print_findings_detailed(self.last_results, "finding")

        display.print_summary(module_name)
        return True

    def _show_history(self) -> bool:
        """Show command history."""
        if not self.command_history:
            self.console.print("[yellow]No command history[/yellow]")
            return True

        self.console.print("\n[bold]Command History:[/bold]")
        for i, cmd in enumerate(self.command_history, 1):
            self.console.print(f"  {i:3}. {cmd}")
        self.console.print()
        return True

    def run(self):
        """Run the interactive TUI loop."""
        self.running = True
        self.current_view = 'profile_select'
        self._refresh_profiles()

        # Track if view content should be printed (starts False since banner is printed)
        self._show_view = False

        # Print initial banner (includes profile selection)
        self.print_banner()
        self.console.print("[dim]Enter profile number, 'services' to browse modules, or 'help' for commands[/dim]\n")

        while self.running:
            try:
                # Print status bar
                self.print_status_bar()

                # Show current view content only when _show_view is True
                if self._show_view:
                    if self.current_view == 'profile_select':
                        self.print_profile_selection()
                    elif self.current_view == 'services':
                        self.print_services()
                    elif self.current_view == 'modules' and self.selected_service:
                        self.print_modules(self.selected_service)
                    elif self.current_view == 'search':
                        self.print_search_results(self.search_text)
                    elif self.current_view == 'help':
                        self.print_help()
                    elif self.current_view == 'json_view':
                        self.print_json_view()
                    # Reset after showing
                    self._show_view = False

                # Print footer
                self.print_footer()

                # Get input
                prompt = f"[bold cyan]awsprowl[{self.current_view}][/bold cyan] › "
                user_input = self.input(prompt)

                if not self.handle_command(user_input):
                    break

            except KeyboardInterrupt:
                if self._module_running:
                    self.console.print("\n[yellow]Module interrupted.[/yellow]")
                    self._module_running = False
                    if self.running_module_names:
                        self.running_module_names.pop()
                else:
                    self.console.print("\n[yellow]Type 'exit' to quit[/yellow]")
            except EOFError:
                break

        self.console.print("\n[bold cyan]Thanks for using awsProwl! Stay secure![/bold cyan]")


def run_tui(config=None, console: Console | None = None):
    """Entry point for the TUI."""
    browser = ModuleBrowserTUI(console=console, config=config)
    browser.run()
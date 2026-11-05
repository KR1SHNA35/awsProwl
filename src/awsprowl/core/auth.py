"""AWS Authentication and Session Management for awsProwl."""

from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import boto3
import botocore.config
import botocore.exceptions

from awsprowl.core.config import AWSConfig, get_config
from awsprowl.core.exceptions import AuthenticationError, AuthorizationError
from awsprowl.core.logging import get_logger

log = get_logger(__name__)


@dataclass
class AWSCredentials:
    """AWS Credentials container."""

    access_key: str
    secret_key: str
    session_token: str | None = None
    region: str = "us-east-1"
    expires_at: float | None = None

    def to_session_params(self) -> dict[str, Any]:
        """Convert to boto3 session parameters."""
        params = {
            "aws_access_key_id": self.access_key,
            "aws_secret_access_key": self.secret_key,
            "region_name": self.region,
        }
        if self.session_token:
            params["aws_session_token"] = self.session_token
        return params


class AWSAuthManager:
    """Manages AWS authentication and session creation."""

    def __init__(self, config: AWSConfig | None = None):
        self.config = config or get_config().aws
        self._session: boto3.Session | None = None
        self._credentials: AWSCredentials | None = None

    def load_credentials(self) -> AWSCredentials:
        """Load credentials from various sources in order of precedence."""
        # 1. Explicit config (CLI args, env vars via pydantic-settings)
        if self.config.access_key_id and self.config.secret_access_key:
            log.info("Using credentials from configuration")
            return AWSCredentials(
                access_key=self.config.access_key_id,
                secret_key=self.config.secret_access_key,
                session_token=self.config.session_token,
                region=self.config.region,
            )

        # 2. AWS CLI profile
        if self.config.profile:
            try:
                session = boto3.Session(profile_name=self.config.profile)
                creds = session.get_credentials()
                if creds:
                    log.info("Using credentials from AWS profile: {}", self.config.profile)
                    return AWSCredentials(
                        access_key=creds.access_key,
                        secret_key=creds.secret_key,
                        session_token=creds.token,
                        region=session.region_name or self.config.region,
                    )
            except botocore.exceptions.ProfileNotFound:
                raise AuthenticationError(
                    f"AWS profile '{self.config.profile}' not found",
                    profile=self.config.profile,
                )
            except Exception as e:
                raise AuthenticationError(
                    f"Error loading profile '{self.config.profile}': {e}",
                    profile=self.config.profile,
                )

        # 3. Environment variables (standard AWS vars)
        env_access = os.environ.get("AWS_ACCESS_KEY_ID")
        env_secret = os.environ.get("AWS_SECRET_ACCESS_KEY")
        if env_access and env_secret:
            log.info("Using credentials from environment variables")
            return AWSCredentials(
                access_key=env_access,
                secret_key=env_secret,
                session_token=os.environ.get("AWS_SESSION_TOKEN"),
                region=os.environ.get("AWS_REGION", self.config.region),
            )

        # 4. Default profile
        try:
            session = boto3.Session()
            creds = session.get_credentials()
            if creds:
                log.info("Using credentials from default AWS profile")
                return AWSCredentials(
                    access_key=creds.access_key,
                    secret_key=creds.secret_key,
                    session_token=creds.token,
                    region=session.region_name or self.config.region,
                )
        except Exception:
            pass

        # 5. EC2 Instance Metadata (IMDS)
        try:
            session = boto3.Session()
            creds = session.get_credentials()
            if creds:
                log.info("Using credentials from EC2 instance metadata")
                return AWSCredentials(
                    access_key=creds.access_key,
                    secret_key=creds.secret_key,
                    session_token=creds.token,
                    region=self.config.region,
                )
        except Exception:
            pass

        raise AuthenticationError(
            "No valid AWS credentials found. "
            "Provide credentials via --profile, environment variables, "
            "AWS CLI configuration, or EC2 instance metadata.",
            remediation="Run 'aws configure' or set AWS_ACCESS_KEY_ID/AWS_SECRET_ACCESS_KEY",
        )

    def get_session(self) -> boto3.Session:
        """Get or create a boto3 session."""
        if self._session is None:
            credentials = self.load_credentials()
            self._credentials = credentials

            # Create custom config with retries and timeouts
            boto_config = botocore.config.Config(
                retries={
                    "max_attempts": self.config.max_retries,
                    "mode": "adaptive",
                },
                connect_timeout=self.config.timeout,
                read_timeout=self.config.timeout,
            )

            self._session = boto3.Session(**credentials.to_session_params())
            # Set default config for all clients
            self._session._session.set_config_variable("region", credentials.region)

        return self._session

    def get_client(self, service: str, region: str | None = None, **kwargs) -> Any:
        """Get a boto3 client with standardized configuration."""
        session = self.get_session()

        client_kwargs = {}
        if region:
            client_kwargs["region_name"] = region
        elif self.config.region:
            client_kwargs["region_name"] = self.config.region

        # Apply custom config
        boto_config = botocore.config.Config(
            retries={
                "max_attempts": self.config.max_retries,
                "mode": "adaptive",
            },
            connect_timeout=self.config.timeout,
            read_timeout=self.config.timeout,
        )
        client_kwargs["config"] = boto_config
        client_kwargs.update(kwargs)

        return session.client(service, **client_kwargs)

    def get_resource(self, service: str, region: str | None = None, **kwargs) -> Any:
        """Get a boto3 resource with standardized configuration."""
        session = self.get_session()

        resource_kwargs = {}
        if region:
            resource_kwargs["region_name"] = region
        elif self.config.region:
            resource_kwargs["region_name"] = self.config.region

        boto_config = botocore.config.Config(
            retries={
                "max_attempts": self.config.max_retries,
                "mode": "adaptive",
            },
            connect_timeout=self.config.timeout,
            read_timeout=self.config.timeout,
        )
        resource_kwargs["config"] = boto_config
        resource_kwargs.update(kwargs)

        return session.resource(service, **resource_kwargs)

    def get_available_regions(self, service: str = "ec2") -> list[str]:
        """Get list of available regions for a service."""
        try:
            session = self.get_session()
            return session.get_available_regions(service)
        except Exception as e:
            log.warning("Could not get regions for {}: {}", service, e)
            # Return common regions as fallback
            return [
                "us-east-1",
                "us-east-2",
                "us-west-1",
                "us-west-2",
                "eu-west-1",
                "eu-west-2",
                "eu-west-3",
                "eu-central-1",
                "eu-north-1",
                "ap-southeast-1",
                "ap-southeast-2",
                "ap-northeast-1",
                "ap-northeast-2",
                "ap-south-1",
                "ca-central-1",
                "sa-east-1",
            ]

    def get_caller_identity(self) -> dict[str, Any]:
        """Get the caller identity using STS."""
        try:
            sts = self.get_client("sts")
            return sts.get_caller_identity()
        except botocore.exceptions.ClientError as e:
            error_code = e.response["Error"]["Code"]
            if error_code in ("InvalidClientTokenId", "SignatureDoesNotMatch"):
                raise AuthenticationError(
                    "Invalid AWS credentials",
                    remediation="Check your access key and secret key",
                )
            if error_code == "ExpiredToken":
                raise AuthenticationError(
                    "AWS session token has expired",
                    remediation="Refresh your session token or use permanent credentials",
                )
            raise AuthorizationError(
                f"Failed to get caller identity: {e}",
                action="sts:GetCallerIdentity",
            )

    def assume_role(
        self,
        role_arn: str,
        session_name: str = "awsprowl-session",
        external_id: str | None = None,
        duration_seconds: int = 3600,
    ) -> AWSCredentials:
        """Assume an IAM role and return temporary credentials."""
        try:
            sts = self.get_client("sts")

            params = {
                "RoleArn": role_arn,
                "RoleSessionName": session_name,
                "DurationSeconds": duration_seconds,
            }
            if external_id:
                params["ExternalId"] = external_id

            response = sts.assume_role(**params)
            creds = response["Credentials"]

            log.info("Successfully assumed role: {}", role_arn)

            return AWSCredentials(
                access_key=creds["AccessKeyId"],
                secret_key=creds["SecretAccessKey"],
                session_token=creds["SessionToken"],
                region=self.config.region,
            )
        except botocore.exceptions.ClientError as e:
            error_code = e.response["Error"]["Code"]
            if error_code == "AccessDenied":
                raise AuthorizationError(
                    f"Access denied assuming role {role_arn}",
                    action="sts:AssumeRole",
                    resource=role_arn,
                )
            raise ServiceError(
                f"Failed to assume role: {e}",
                service="sts",
                operation="AssumeRole",
                error_code=error_code,
            )

    def list_profiles(self) -> list[str]:
        """List available AWS CLI profiles."""
        profiles = []

        # Check credentials file
        aws_dir = Path.home() / ".aws"
        credentials_file = aws_dir / "credentials"
        config_file = aws_dir / "config"

        if credentials_file.exists():
            try:
                import configparser

                config = configparser.ConfigParser()
                config.read(credentials_file)
                profiles.extend(config.sections())
            except Exception as e:
                log.debug("Error reading credentials file: {}", e)

        if config_file.exists():
            try:
                import configparser

                config = configparser.ConfigParser()
                config.read(config_file)
                for section in config.sections():
                    if section.startswith("profile "):
                        profile_name = section.replace("profile ", "")
                        if profile_name not in profiles:
                            profiles.append(profile_name)
            except Exception as e:
                log.debug("Error reading config file: {}", e)

        # Add default profile
        if "default" not in profiles:
            profiles.insert(0, "default")

        return profiles

    @property
    def credentials(self) -> AWSCredentials | None:
        """Get current credentials."""
        return self._credentials

    @property
    def region(self) -> str:
        """Get current region."""
        return self.config.region

    def reset(self) -> None:
        """Reset session and credentials."""
        self._session = None
        self._credentials = None


def create_auth_manager(config: AWSConfig | None = None) -> AWSAuthManager:
    """Factory function to create an auth manager."""
    return AWSAuthManager(config)

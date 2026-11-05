"""Cached AWS client factory for awsProwl."""

from __future__ import annotations

import threading
from typing import Any

import boto3
import botocore.config

from awsprowl.core.auth import AWSAuthManager
from awsprowl.core.config import get_config
from awsprowl.core.logging import get_logger

log = get_logger(__name__)


class AWSClientFactory:
    """Factory for creating and caching boto3 clients with consistent configuration.

    Caches clients by (service, region, profile) tuple to avoid repeated
    session/client creation overhead.
    """

    _clients: dict[tuple[str, str | None, str | None], Any] = {}
    _lock: threading.Lock = threading.Lock()
    _default_config: botocore.config.Config | None = None

    @classmethod
    def _get_default_config(cls) -> botocore.config.Config:
        """Get default boto3 config with retries and timeouts."""
        if cls._default_config is None:
            config = get_config()
            cls._default_config = botocore.config.Config(
                retries={
                    "max_attempts": config.aws.max_retries,
                    "mode": "adaptive"
                },
                connect_timeout=config.aws.timeout,
                read_timeout=config.aws.timeout,
                max_pool_connections=10,
            )
        return cls._default_config

    @classmethod
    def get_client(
        cls,
        service: str,
        session: boto3.Session,
        region: str | None = None,
        profile: str | None = None
    ) -> Any:
        """Get cached or new boto3 client.

        Args:
            service: AWS service name (e.g., 'iam', 'ec2', 's3')
            session: boto3 Session to use
            region: AWS region (None for global services)
            profile: AWS profile name (for cache key)

        Returns:
            boto3 client for the service
        """
        cache_key = (service, region, profile)

        with cls._lock:
            if cache_key not in cls._clients:
                client = session.client(
                    service,
                    region_name=region,
                    config=cls._get_default_config()
                )
                cls._clients[cache_key] = client
                log.debug(f"Created new client for {service} in {region or 'global'}")

            return cls._clients[cache_key]

    @classmethod
    def get_client_from_auth(
        cls,
        service: str,
        auth_manager: AWSAuthManager,
        region: str | None = None
    ) -> Any:
        """Get client using auth manager's session."""
        return cls.get_client(
            service,
            auth_manager.get_session(),
            region,
            auth_manager.profile
        )

    @classmethod
    def invalidate(
        cls,
        service: str | None = None,
        region: str | None = None,
        profile: str | None = None
    ) -> None:
        """Invalidate cached clients.

        Args:
            service: Invalidate only this service (None for all)
            region: Invalidate only this region (None for all)
            profile: Invalidate only this profile (None for all)
        """
        with cls._lock:
            if service is None and region is None and profile is None:
                cls._clients.clear()
                log.debug("Invalidated all cached clients")
            else:
                keys_to_remove = [
                    k for k in cls._clients
                    if (service is None or k[0] == service) and
                       (region is None or k[1] == region) and
                       (profile is None or k[2] == profile)
                ]
                for key in keys_to_remove:
                    del cls._clients[key]
                log.debug(f"Invalidated {len(keys_to_remove)} cached clients")

    @classmethod
    def get_cached_services(cls) -> list[str]:
        """Get list of services with cached clients."""
        with cls._lock:
            return list(set(k[0] for k in cls._clients.keys()))

    @classmethod
    def clear_cache(cls) -> None:
        """Clear all cached clients."""
        with cls._lock:
            cls._clients.clear()
            log.debug("Cleared all client cache")


# Convenience function for direct use
def get_client(
    service: str,
    auth_manager: AWSAuthManager,
    region: str | None = None
) -> Any:
    """Get AWS client for a service using auth manager."""
    return AWSClientFactory.get_client_from_auth(service, auth_manager, region)

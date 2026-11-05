"""Custom exceptions for awsProwl."""

from __future__ import annotations

from typing import Any


class AwsProwlError(Exception):
    """Base exception for all awsProwl errors."""

    def __init__(
        self,
        message: str,
        *,
        code: str | None = None,
        details: dict[str, Any] | None = None,
        remediation: str | None = None,
    ):
        super().__init__(message)
        self.message = message
        self.code = code or self.__class__.__name__.upper()
        self.details = details or {}
        self.remediation = remediation

    def __str__(self) -> str:
        return self.message

    def to_dict(self) -> dict[str, Any]:
        """Convert exception to dictionary for JSON serialization."""
        return {
            "error": self.code,
            "message": self.message,
            "details": self.details,
            "remediation": self.remediation,
        }


class ConfigurationError(AwsProwlError):
    """Configuration-related errors."""

    def __init__(
        self,
        message: str,
        *,
        config_key: str | None = None,
        config_file: str | None = None,
        remediation: str | None = None,
        **kwargs: Any,
    ) -> None:
        details: dict[str, Any] = kwargs.pop("details", {})
        if config_key:
            details["config_key"] = config_key
        if config_file:
            details["config_file"] = config_file
        super().__init__(message, code="CONFIG_ERROR", details=details, remediation=remediation, **kwargs)


class AuthenticationError(AwsProwlError):
    """AWS authentication errors."""

    def __init__(
        self,
        message: str,
        *,
        profile: str | None = None,
        region: str | None = None,
        remediation: str | None = None,
        **kwargs: Any,
    ) -> None:
        details: dict[str, Any] = kwargs.pop("details", {})
        if profile:
            details["profile"] = profile
        if region:
            details["region"] = region
        super().__init__(message, code="AUTH_ERROR", details=details, remediation=remediation, **kwargs)


class AuthorizationError(AwsProwlError):
    """AWS authorization/permission errors."""

    def __init__(
        self,
        message: str,
        *,
        action: str | None = None,
        resource: str | None = None,
        **kwargs: Any,
    ) -> None:
        details: dict[str, Any] = kwargs.pop("details", {})
        if action:
            details["action"] = action
        if resource:
            details["resource"] = resource
        super().__init__(
            message,
            code="AUTHZ_ERROR",
            details=details,
            remediation="Check IAM permissions for the required action/resource",
            **kwargs,
        )


class ServiceError(AwsProwlError):
    """AWS service API errors."""

    def __init__(
        self,
        message: str,
        *,
        service: str | None = None,
        operation: str | None = None,
        error_code: str | None = None,
        **kwargs: Any,
    ) -> None:
        details: dict[str, Any] = kwargs.pop("details", {})
        if service:
            details["service"] = service
        if operation:
            details["operation"] = operation
        if error_code:
            details["error_code"] = error_code
        super().__init__(message, code="SERVICE_ERROR", details=details, **kwargs)


class ResourceNotFoundError(AwsProwlError):
    """Resource not found errors."""

    def __init__(
        self,
        message: str,
        *,
        resource_type: str | None = None,
        resource_id: str | None = None,
        **kwargs: Any,
    ) -> None:
        details: dict[str, Any] = kwargs.pop("details", {})
        if resource_type:
            details["resource_type"] = resource_type
        if resource_id:
            details["resource_id"] = resource_id
        super().__init__(message, code="RESOURCE_NOT_FOUND", details=details, **kwargs)


class ValidationError(AwsProwlError):
    """Input validation errors."""

    def __init__(
        self,
        message: str,
        *,
        field: str | None = None,
        value: Any = None,
        **kwargs: Any,
    ) -> None:
        details: dict[str, Any] = kwargs.pop("details", {})
        if field:
            details["field"] = field
        if value is not None:
            details["value"] = str(value)
        super().__init__(message, code="VALIDATION_ERROR", details=details, **kwargs)


class ScanError(AwsProwlError):
    """Scan execution errors."""

    def __init__(
        self,
        message: str,
        *,
        scan_id: str | None = None,
        service: str | None = None,
        region: str | None = None,
        **kwargs: Any,
    ) -> None:
        details: dict[str, Any] = kwargs.pop("details", {})
        if scan_id:
            details["scan_id"] = scan_id
        if service:
            details["service"] = service
        if region:
            details["region"] = region
        super().__init__(message, code="SCAN_ERROR", details=details, **kwargs)


class ReportError(AwsProwlError):
    """Report generation errors."""

    def __init__(
        self,
        message: str,
        *,
        format: str | None = None,
        output_path: str | None = None,
        **kwargs: Any,
    ) -> None:
        details: dict[str, Any] = kwargs.pop("details", {})
        if format:
            details["format"] = format
        if output_path:
            details["output_path"] = output_path
        super().__init__(message, code="REPORT_ERROR", details=details, **kwargs)


class WebServerError(AwsProwlError):
    """Web server errors."""

    def __init__(
        self,
        message: str,
        *,
        host: str | None = None,
        port: int | None = None,
        **kwargs: Any,
    ) -> None:
        details: dict[str, Any] = kwargs.pop("details", {})
        if host:
            details["host"] = host
        if port:
            details["port"] = port
        super().__init__(message, code="WEBSERVER_ERROR", details=details, **kwargs)


class SessionError(AwsProwlError):
    """Session management errors."""

    def __init__(
        self,
        message: str,
        *,
        session_id: str | None = None,
        **kwargs: Any,
    ) -> None:
        details: dict[str, Any] = kwargs.pop("details", {})
        if session_id:
            details["session_id"] = session_id
        super().__init__(message, code="SESSION_ERROR", details=details, **kwargs)


class PluginError(AwsProwlError):
    """Plugin/extension errors."""

    def __init__(
        self,
        message: str,
        *,
        plugin_name: str | None = None,
        **kwargs: Any,
    ) -> None:
        details: dict[str, Any] = kwargs.pop("details", {})
        if plugin_name:
            details["plugin_name"] = plugin_name
        super().__init__(message, code="PLUGIN_ERROR", details=details, **kwargs)

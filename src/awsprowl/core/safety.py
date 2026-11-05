"""Safety layer for awsProwl - Dry-run, rollback, confirmations, and audit logging."""

from __future__ import annotations

import json
import threading
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from rich.console import Console
from rich.panel import Panel
from rich.prompt import Confirm
from rich.table import Table

from awsprowl.core.config import get_config
from awsprowl.core.logging import get_logger
from awsprowl.modules import ModuleMetadata, ModuleRisk

log = get_logger(__name__)


# ============================================================================
# DryRunGuard - Global dry-run mode enforcement
# ============================================================================

class DryRunGuard:
    """Global dry-run mode guard. When enabled, no AWS mutations occur."""

    _enabled: bool = False
    _lock: threading.Lock = threading.Lock()

    @classmethod
    def enable(cls) -> None:
        """Enable dry-run mode globally."""
        with cls._lock:
            cls._enabled = True
            log.warning("DRY-RUN MODE ENABLED - No AWS mutations will occur")

    @classmethod
    def disable(cls) -> None:
        """Disable dry-run mode globally."""
        with cls._lock:
            cls._enabled = False
            log.warning("DRY-RUN MODE DISABLED - AWS mutations will occur")

    @classmethod
    def is_enabled(cls) -> bool:
        """Check if dry-run mode is enabled."""
        return cls._enabled

    @classmethod
    def check(cls, operation: str) -> bool:
        """Check if operation should be skipped due to dry-run mode.

        Args:
            operation: Description of the operation being checked

        Returns:
            True if in dry-run mode (operation should be skipped), False otherwise
        """
        if cls._enabled:
            log.warning(f"DRY-RUN: Would execute {operation}")
            return True
        return False


# ============================================================================
# RollbackManager - Track and revert destructive changes
# ============================================================================

@dataclass
class RollbackOperation:
    """Represents a rollback operation for a destructive action."""
    service: str
    operation: str
    resource_id: str
    resource_type: str
    params: dict[str, Any]
    reverse_operation: str | None = None  # Name of reverse operation
    reverse_params: dict[str, Any] | None = None
    timestamp: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    executed: bool = False
    result: str | None = None


@dataclass
class RollbackResult:
    """Result of a rollback attempt."""
    operation: RollbackOperation
    success: bool
    message: str
    timestamp: datetime = field(default_factory=lambda: datetime.now(timezone.utc))


class RollbackManager:
    """Manages rollback operations for destructive actions."""

    _instance: RollbackManager | None = None
    _lock: threading.Lock = threading.Lock()

    def __init__(self):
        self.operations: list[RollbackOperation] = []
        self._lock = threading.Lock()

    @classmethod
    def get_instance(cls) -> RollbackManager:
        """Get singleton instance."""
        if cls._instance is None:
            with cls._lock:
                if cls._instance is None:
                    cls._instance = cls()
        return cls._instance

    def register(self, operation: RollbackOperation) -> None:
        """Register a rollback operation."""
        with self._lock:
            self.operations.append(operation)
            log.debug(f"Registered rollback: {operation.service}:{operation.operation} -> {operation.resource_id}")

    def clear(self) -> None:
        """Clear all registered operations."""
        with self._lock:
            self.operations.clear()

    def rollback_all(self, auth_manager) -> list[RollbackResult]:
        """Execute all rollbacks in reverse order (LIFO).

        Args:
            auth_manager: AWSAuthManager for making rollback API calls

        Returns:
            List of RollbackResult for each operation
        """
        results = []
        with self._lock:
            # Reverse order for proper cleanup
            for operation in reversed(self.operations):
                if operation.executed:
                    log.info(f"Skipping already executed rollback: {operation.resource_id}")
                    results.append(RollbackResult(
                        operation=operation,
                        success=False,
                        message="Already executed"
                    ))
                    continue

                result = self._execute_rollback(operation, auth_manager)
                results.append(result)
                operation.executed = True
                operation.result = "success" if result.success else f"failed: {result.message}"

            # Clear after rollback
            self.operations.clear()

        return results

    def _execute_rollback(self, operation: RollbackOperation, auth_manager) -> RollbackResult:
        """Execute a single rollback operation."""
        try:
            client = auth_manager.get_client(operation.service)
            reverse_op = operation.reverse_operation or self._get_default_reverse(operation.operation)

            if not reverse_op:
                return RollbackResult(
                    operation=operation,
                    success=False,
                    message=f"No reverse operation defined for {operation.operation}"
                )

            # Merge params with reverse_params
            params = {**operation.params}
            if operation.reverse_params:
                params.update(operation.reverse_params)

            method = getattr(client, reverse_op)
            method(**params)

            log.info(f"Rollback successful: {operation.service}:{reverse_op} for {operation.resource_id}")
            return RollbackResult(
                operation=operation,
                success=True,
                message=f"Rolled back {operation.operation} via {reverse_op}"
            )

        except Exception as e:
            log.error(f"Rollback failed for {operation.resource_id}: {e}")
            return RollbackResult(
                operation=operation,
                success=False,
                message=str(e)
            )

    def _get_default_reverse(self, operation: str) -> str | None:
        """Get default reverse operation for common AWS operations."""
        reverse_map = {
            "create_user": "delete_user",
            "create_access_key": "delete_access_key",
            "attach_user_policy": "detach_user_policy",
            "put_user_policy": "delete_user_policy",
            "create_role": "delete_role",
            "update_assume_role_policy": "update_assume_role_policy",  # Would need original policy
            "create_policy_version": "delete_policy_version",
            "put_role_policy": "delete_role_policy",
            "attach_role_policy": "detach_role_policy",
            "put_group_policy": "delete_group_policy",
            "attach_group_policy": "detach_group_policy",
            "create_function": "delete_function",
            "update_function_code": "update_function_code",  # Would need previous version
            "put_bucket_policy": "delete_bucket_policy",
            "put_bucket_acl": "put_bucket_acl",  # Would need original ACL
            "put_bucket_replication": "delete_bucket_replication",
            "put_object": "delete_object",
            "create_stack": "delete_stack",
            "create_dev_endpoint": "delete_dev_endpoint",
            "start_build": "batch_get_builds",  # Can't really rollback a build
            "send_command": "cancel_command",
            "create_association": "delete_association",
            "run_task": "stop_task",
            "create_cluster": "delete_cluster",
            "submit_job": "terminate_job",
            "create_notebook_instance": "delete_notebook_instance",
            "create_environment": "delete_environment",
        }
        return reverse_map.get(operation)


# ============================================================================
# ConfirmationService - Rich confirmation dialogs
# ============================================================================

class ConfirmationService:
    """Provides rich confirmation dialogs for destructive operations."""

    def __init__(self, console: Console | None = None):
        self.console = console or Console()

    async def confirm_destructive(
        self,
        module: ModuleMetadata,
        params: dict[str, Any],
        default: bool = False
    ) -> bool:
        """Show detailed confirmation dialog for destructive operations.

        Args:
            module: Module metadata
            params: Parameters that will be passed to the operation
            default: Default choice

        Returns:
            True if confirmed, False if cancelled
        """
        self._display_confirmation_panel(module, params)

        # Double confirmation for CRITICAL risk
        if module.risk == ModuleRisk.CRITICAL:
            self.console.print()
            return Confirm.ask(
                "[bold red]This is a CRITICAL risk operation. Type 'YES' to confirm:[/bold red]",
                default=False,
                console=self.console,
                choices=["YES", "NO"]
            ) == "YES"

        return Confirm.ask(
            f"[bold yellow]Proceed with {module.name}?[/bold yellow]",
            default=default,
            console=self.console
        )

    async def confirm_batch(
        self,
        modules: list[ModuleMetadata],
        params: dict[str, Any] | None = None
    ) -> bool:
        """Single confirmation for multiple modules (scan-all operations).

        Args:
            modules: List of modules that will be executed
            params: Parameters for all modules

        Returns:
            True if confirmed, False if cancelled
        """
        self.console.print()
        self.console.print(Panel(
            f"[bold]Batch Operation Confirmation[/bold]\n\n"
            f"Will execute {len(modules)} modules:\n" +
            "\n".join(f"  • {m.name} ({m.risk.value.upper()})" for m in modules),
            title="[yellow]Batch Confirmation[/yellow]",
            border_style="yellow"
        ))

        return Confirm.ask(
            "[bold yellow]Execute all modules?[/bold yellow]",
            default=False,
            console=self.console
        )

    def _display_confirmation_panel(
        self,
        module: ModuleMetadata,
        params: dict[str, Any]
    ) -> None:
        """Display detailed confirmation panel with impact preview."""
        # Risk color mapping
        risk_colors = {
            ModuleRisk.SAFE: "green",
            ModuleRisk.LOW: "blue",
            ModuleRisk.MEDIUM: "yellow",
            ModuleRisk.HIGH: "orange3",
            ModuleRisk.CRITICAL: "red",
        }
        risk_color = risk_colors.get(module.risk, "white")

        # Build parameter table
        param_table = Table(show_header=True, header_style="bold")
        param_table.add_column("Parameter", style="cyan")
        param_table.add_column("Value", style="white")

        for key, value in params.items():
            if key.startswith("_"):  # Skip internal params
                continue
            # Mask sensitive values
            if any(sensitive in key.lower() for sensitive in ["key", "secret", "password", "token"]):
                value = "[MASKED]"
            param_table.add_row(key, str(value))

        # Build impact preview
        impact_lines = [
            f"[bold]Module:[/bold] {module.name}",
            f"[bold]Category:[/bold] {module.category.value}",
            f"[bold]Risk:[/bold] [{risk_color}]{module.risk.value.upper()}[/{risk_color}]",
            f"[bold]Destructive:[/bold] {'YES' if module.destructive else 'NO'}",
            f"[bold]Description:[/bold] {module.description}",
        ]

        if module.mitre_techniques:
            impact_lines.append(f"[bold]MITRE:[/bold] {', '.join(module.mitre_techniques)}")

        if module.required_permissions:
            impact_lines.append(f"[bold]Requires Permissions:[/bold] {', '.join(module.required_permissions[:5])}")

        content = "\n".join(impact_lines)
        if params:
            content += "\n\n[bold]Parameters:[/bold]"
            # We can't embed table in panel easily, so show key params
            for key, value in list(params.items())[:5]:
                if not key.startswith("_"):
                    if any(sensitive in key.lower() for sensitive in ["key", "secret", "password", "token"]):
                        value = "[MASKED]"
                    content += f"\n  {key}: {value}"

        self.console.print()
        self.console.print(Panel(
            content,
            title=f"[bold {risk_color}]⚠ Destructive Operation Confirmation[/bold {risk_color}]",
            border_style=risk_color,
            expand=False
        ))


# ============================================================================
# AuditLogger - Structured audit trail
# ============================================================================

@dataclass
class AuditEntry:
    """Single audit log entry."""
    timestamp: str
    module: str
    user: str
    params: dict[str, Any]
    result: str
    findings_count: int = 0
    destructive: bool = False

    def to_json(self) -> str:
        """Serialize to JSON."""
        return json.dumps(asdict(self), default=str)


class AuditLogger:
    """Logs all destructive operations to an audit trail."""

    def __init__(self, log_file: Path | None = None):
        config = get_config()
        self.log_file = log_file or Path(config.output.output_dir) / "audit.log.jsonl"
        self.log_file.parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.Lock()

    def log_execution(
        self,
        module: str,
        params: dict[str, Any],
        user: str,
        result: str,
        findings_count: int = 0,
        destructive: bool = False
    ) -> None:
        """Log a module execution to the audit trail."""
        # Filter sensitive params
        safe_params = self._sanitize_params(params)

        entry = AuditEntry(
            timestamp=datetime.now(timezone.utc).isoformat(),
            module=module,
            user=user,
            params=safe_params,
            result=result,
            findings_count=findings_count,
            destructive=destructive
        )

        with self._lock, open(self.log_file, "a") as f:
            f.write(entry.to_json() + "\n")

        log.info(f"AUDIT: {module} by {user} -> {result} ({findings_count} findings)")

    def _sanitize_params(self, params: dict[str, Any]) -> dict[str, Any]:
        """Remove or mask sensitive parameters."""
        sensitive_keys = {"password", "secret", "key", "token", "credential", "access_key", "secret_key"}
        safe = {}
        for k, v in params.items():
            if any(s in k.lower() for s in sensitive_keys):
                safe[k] = "[REDACTED]"
            else:
                safe[k] = v
        return safe

    def get_recent_entries(self, limit: int = 100) -> list[AuditEntry]:
        """Get recent audit entries."""
        entries = []
        if not self.log_file.exists():
            return entries

        with open(self.log_file) as f:
            for line in f:
                try:
                    data = json.loads(line.strip())
                    entries.append(AuditEntry(**data))
                except json.JSONDecodeError:
                    continue

        return entries[-limit:]


# ============================================================================
# Convenience functions for global access
# ============================================================================

_rollback_manager: RollbackManager | None = None
_audit_logger: AuditLogger | None = None
_confirmation_service: ConfirmationService | None = None


def get_rollback_manager() -> RollbackManager:
    """Get global rollback manager instance."""
    global _rollback_manager
    if _rollback_manager is None:
        _rollback_manager = RollbackManager.get_instance()
    return _rollback_manager


def get_audit_logger() -> AuditLogger:
    """Get global audit logger instance."""
    global _audit_logger
    if _audit_logger is None:
        _audit_logger = AuditLogger()
    return _audit_logger


def get_confirmation_service() -> ConfirmationService:
    """Get global confirmation service instance."""
    global _confirmation_service
    if _confirmation_service is None:
        _confirmation_service = ConfirmationService()
    return _confirmation_service

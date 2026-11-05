"""Unit tests for Safety Layer components."""

from __future__ import annotations

import threading
from datetime import datetime
from unittest.mock import MagicMock, patch

import pytest

from awsprowl.core.safety import (
    AuditEntry,
    AuditLogger,
    ConfirmationService,
    DryRunGuard,
    RollbackManager,
    RollbackOperation,
    get_audit_logger,
    get_confirmation_service,
    get_rollback_manager,
)
from awsprowl.modules import ModuleCategory, ModuleMetadata, ModuleRisk


class TestDryRunGuard:
    """Tests for DryRunGuard."""

    def setup_method(self):
        DryRunGuard.disable()

    def teardown_method(self):
        DryRunGuard.disable()

    def test_enable_disable(self):
        assert DryRunGuard.is_enabled() is False
        DryRunGuard.enable()
        assert DryRunGuard.is_enabled() is True
        DryRunGuard.disable()
        assert DryRunGuard.is_enabled() is False

    def test_check_when_enabled(self):
        DryRunGuard.enable()
        try:
            result = DryRunGuard.check("test_operation")
            assert result is True
        finally:
            DryRunGuard.disable()

    def test_check_when_disabled(self):
        DryRunGuard.disable()
        result = DryRunGuard.check("test_operation")
        assert result is False

    def test_thread_safety(self):
        """Test thread safety of enable/disable."""
        results = []

        def worker():
            for _ in range(100):
                DryRunGuard.enable()
                assert DryRunGuard.is_enabled() is True
                DryRunGuard.disable()
                assert DryRunGuard.is_enabled() is False
                results.append(True)

        threads = [threading.Thread(target=worker) for _ in range(10)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        assert len(results) == 1000


class TestRollbackManager:
    """Tests for RollbackManager."""

    def setup_method(self):
        RollbackManager.get_instance().clear()

    def teardown_method(self):
        RollbackManager.get_instance().clear()

    def test_singleton(self):
        mgr1 = RollbackManager.get_instance()
        mgr2 = RollbackManager.get_instance()
        assert mgr1 is mgr2

    def test_register_operation(self):
        mgr = RollbackManager.get_instance()
        op = RollbackOperation(
            service="test",
            operation="create",
            resource_id="test-id",
            resource_type="test_resource",
            params={"Name": "test"}
        )
        mgr.register(op)
        assert len(mgr.operations) == 1
        assert mgr.operations[0] is op

    def test_clear(self):
        mgr = RollbackManager.get_instance()
        op = RollbackOperation(
            service="test",
            operation="create",
            resource_id="test-id",
            resource_type="test_resource",
            params={}
        )
        mgr.register(op)
        mgr.clear()
        assert len(mgr.operations) == 0

    def test_rollback_all_empty(self):
        mgr = RollbackManager.get_instance()
        results = mgr.rollback_all(MagicMock())
        assert results == []

    def test_get_default_reverse(self):
        mgr = RollbackManager.get_instance()
        assert mgr._get_default_reverse("create_user") == "delete_user"
        assert mgr._get_default_reverse("create_access_key") == "delete_access_key"
        assert mgr._get_default_reverse("attach_user_policy") == "detach_user_policy"
        assert mgr._get_default_reverse("unknown_operation") is None


class TestRollbackOperation:
    """Tests for RollbackOperation dataclass."""

    def test_rollback_operation_creation(self):
        op = RollbackOperation(
            service="test",
            operation="create",
            resource_id="test-id",
            resource_type="test_resource",
            params={"Name": "test"},
            reverse_operation="delete"
        )

        assert op.service == "test"
        assert op.operation == "create"
        assert op.resource_id == "test-id"
        assert op.resource_type == "test_resource"
        assert op.params == {"Name": "test"}
        assert op.reverse_operation == "delete"
        assert op.executed is False
        assert op.result is None
        assert isinstance(op.timestamp, datetime)


class TestConfirmationService:
    """Tests for ConfirmationService."""

    @pytest.fixture
    def console(self):
        from io import StringIO

        from rich.console import Console
        return Console(file=StringIO(), force_terminal=True)

    @pytest.fixture
    def confirmation_service(self, console):
        return ConfirmationService(console)

    @pytest.fixture
    def module_metadata(self):
        return ModuleMetadata(
            name="test__handler",
            category=ModuleCategory.EXPLOIT,
            risk=ModuleRisk.HIGH,
            description="Test handler",
            required_permissions=["test:Permission"],
            supported_services=["test"],
            mitre_techniques=["T1000"],
            requires_confirmation=True,
            destructive=True,
        )

    @pytest.mark.asyncio
    async def test_confirm_destructive_high_risk(self, confirmation_service, module_metadata):
        # Mock Confirm.ask to return True
        with patch('awsprowl.core.safety.Confirm.ask', return_value=True):
            result = await confirmation_service.confirm_destructive(module_metadata, {})
            assert result is True

    @pytest.mark.asyncio
    async def test_confirm_destructive_cancelled(self, confirmation_service, module_metadata):
        # Mock Confirm.ask to return False
        with patch('awsprowl.core.safety.Confirm.ask', return_value=False):
            result = await confirmation_service.confirm_destructive(module_metadata, {})
            assert result is False

    @pytest.mark.asyncio
    async def test_confirm_batch(self, confirmation_service):
        modules = [
            ModuleMetadata(name="mod1", category=ModuleCategory.EXPLOIT, risk=ModuleRisk.HIGH, description="Mod 1", required_permissions=[], supported_services=["test"]),
            ModuleMetadata(name="mod2", category=ModuleCategory.EXPLOIT, risk=ModuleRisk.MEDIUM, description="Mod 2", required_permissions=[], supported_services=["test"]),
        ]

        with patch('awsprowl.core.safety.Confirm.ask', return_value=True):
            result = await confirmation_service.confirm_batch(modules)
            assert result is True


class TestAuditLogger:
    """Tests for AuditLogger."""

    @pytest.fixture
    def audit_logger(self, tmp_path):
        log_file = tmp_path / "audit.log.jsonl"
        return AuditLogger(log_file)

    def test_log_execution(self, audit_logger):
        audit_logger.log_execution(
            module="test__handler",
            params={"username": "test", "password": "secret"},
            user="arn:aws:iam::123456789012:user/test",
            result="success",
            findings_count=5,
            destructive=True
        )

        entries = audit_logger.get_recent_entries()
        assert len(entries) == 1
        entry = entries[0]
        assert entry.module == "test__handler"
        assert entry.user == "arn:aws:iam::123456789012:user/test"
        assert entry.result == "success"
        assert entry.findings_count == 5
        assert entry.destructive is True
        assert entry.params["username"] == "test"
        assert entry.params["password"] == "[REDACTED]"

    def test_log_execution_sanitizes_params(self, audit_logger):
        audit_logger.log_execution(
            module="test__handler",
            params={"secret_key": "secret", "normal": "value"},
            user="test-user",
            result="success"
        )

        entries = audit_logger.get_recent_entries()
        assert entries[0].params["secret_key"] == "[REDACTED]"
        assert entries[0].params["normal"] == "value"

    def test_get_recent_entries_limit(self, audit_logger):
        for i in range(150):
            audit_logger.log_execution(
                module=f"test_{i}",
                params={},
                user="test",
                result="success"
            )

        entries = audit_logger.get_recent_entries(limit=100)
        assert len(entries) == 100
        # Should get the last 100
        assert entries[0].module == "test_50"
        assert entries[-1].module == "test_149"

    def test_sanitize_params(self, audit_logger):
        params = {
            "username": "test",
            "password": "secret123",
            "api_key": "key123",
            "access_key": "AKIA...",
            "normal_param": "value"
        }

        safe = audit_logger._sanitize_params(params)

        assert safe["username"] == "test"
        assert safe["password"] == "[REDACTED]"
        assert safe["api_key"] == "[REDACTED]"
        assert safe["access_key"] == "[REDACTED]"
        assert safe["normal_param"] == "value"


class TestAuditEntry:
    """Tests for AuditEntry dataclass."""

    def test_audit_entry_serialization(self):
        entry = AuditEntry(
            timestamp="2024-01-01T00:00:00+00:00",
            module="test__handler",
            user="test-user",
            params={"key": "value"},
            result="success",
            findings_count=1,
            destructive=True
        )

        json_str = entry.to_json()
        assert "test__handler" in json_str
        assert "test-user" in json_str
        assert "success" in json_str


class TestGlobalAccessors:
    """Tests for global accessor functions."""

    def test_get_rollback_manager(self):
        mgr = get_rollback_manager()
        assert isinstance(mgr, RollbackManager)

    def test_get_audit_logger(self):
        logger = get_audit_logger()
        assert isinstance(logger, AuditLogger)

    def test_get_confirmation_service(self):
        service = get_confirmation_service()
        assert isinstance(service, ConfirmationService)

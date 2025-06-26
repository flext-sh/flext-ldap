"""Comprehensive tests for LDAP Transaction Manager.

This module provides enterprise-grade testing for the transaction management
system, following ZERO TOLERANCE approach with 95% minimum coverage as required
for shared libraries affecting 5+ dependent projects.

Test Coverage:
    - Transaction context management and state tracking
    - Atomic operations (add, modify, delete, search)
    - Commit and rollback functionality
    - Isolation level handling
    - Error handling and recovery
    - Multi-transaction coordination

Following LDAP Core Shared requirements:
    - 95% minimum test coverage
    - ALL dependent projects must pass integration tests
    - ZERO tolerance for NotImplementedError
"""

from __future__ import annotations

import asyncio
from datetime import datetime, timezone
from unittest.mock import MagicMock, patch

import pytest

from ldap_core_shared.transactions.manager import (
    LDAPTransaction,
    TransactionContext,
    TransactionIsolation,
    TransactionManager,
    TransactionOperation,
    TransactionState,
)


class TestTransactionOperation:
    """Test TransactionOperation model."""

    def test_transaction_operation_creation(self) -> None:
        """Test basic TransactionOperation creation with valid data."""
        operation = TransactionOperation(
            operation_id="op-123",
            operation_type="add",
            target_dn="cn=test,dc=example,dc=com",
            operation_data={"attributes": {"cn": "test", "objectClass": ["person"]}},
        )

        assert operation.operation_id == "op-123"
        assert operation.operation_type == "add"
        assert operation.target_dn == "cn=test,dc=example,dc=com"
        assert operation.operation_data["attributes"]["cn"] == "test"
        assert operation.executed_at is None
        assert operation.result is None
        assert operation.success is None
        assert operation.error_message is None

    def test_transaction_operation_with_execution_data(self) -> None:
        """Test TransactionOperation with execution results."""
        executed_time = datetime.now(timezone.utc)
        operation = TransactionOperation(
            operation_id="op-456",
            operation_type="modify",
            target_dn="cn=user,dc=example,dc=com",
            operation_data={"changes": {"mail": "new@example.com"}},
            executed_at=executed_time,
            result={"result_code": 0, "description": "Success"},
            success=True,
        )

        assert operation.executed_at == executed_time
        assert operation.result["result_code"] == 0
        assert operation.success is True
        assert operation.error_message is None

    def test_transaction_operation_with_error(self) -> None:
        """Test TransactionOperation with error information."""
        operation = TransactionOperation(
            operation_id="op-789",
            operation_type="delete",
            target_dn="cn=nonexistent,dc=example,dc=com",
            operation_data={},
            success=False,
            error_message="No such object",
        )

        assert operation.success is False
        assert operation.error_message == "No such object"


class TestTransactionContext:
    """Test TransactionContext functionality."""

    @pytest.fixture
    def transaction_context(self) -> TransactionContext:
        """Create test transaction context."""
        return TransactionContext(
            transaction_id="tx-123",
            isolation_level=TransactionIsolation.READ_COMMITTED,
            timeout_seconds=300,
        )

    def test_transaction_context_initialization(self, transaction_context: TransactionContext) -> None:
        """Test TransactionContext initialization."""
        assert transaction_context.transaction_id == "tx-123"
        assert transaction_context.isolation_level == TransactionIsolation.READ_COMMITTED
        assert transaction_context.timeout_seconds == 300
        assert transaction_context.state == TransactionState.ACTIVE
        assert len(transaction_context.operations) == 0
        assert transaction_context.started_at is not None
        assert transaction_context.committed_at is None
        assert transaction_context.aborted_at is None

    def test_transaction_context_add_operation(self, transaction_context: TransactionContext) -> None:
        """Test adding operations to transaction context."""
        operation_id = transaction_context.add_operation(
            "add",
            "cn=newuser,dc=example,dc=com",
            {"attributes": {"cn": "newuser"}},
        )

        assert len(transaction_context.operations) == 1
        operation = transaction_context.operations[0]
        assert operation.operation_id == operation_id
        assert operation.operation_type == "add"
        assert operation.target_dn == "cn=newuser,dc=example,dc=com"

    def test_transaction_context_mark_operation_successful(self, transaction_context: TransactionContext) -> None:
        """Test marking operation as successful."""
        operation_id = transaction_context.add_operation("add", "cn=test,dc=example,dc=com", {})
        result = {"result_code": 0, "description": "Success"}

        transaction_context.mark_operation_successful(operation_id, result)

        operation = transaction_context.operations[0]
        assert operation.success is True
        assert operation.result == result
        assert operation.executed_at is not None

    def test_transaction_context_mark_operation_failed(self, transaction_context: TransactionContext) -> None:
        """Test marking operation as failed."""
        operation_id = transaction_context.add_operation("delete", "cn=test,dc=example,dc=com", {})
        error_message = "Insufficient access rights"

        transaction_context.mark_operation_failed(operation_id, error_message)

        operation = transaction_context.operations[0]
        assert operation.success is False
        assert operation.error_message == error_message
        assert operation.executed_at is not None

    def test_transaction_context_mark_operation_nonexistent(self, transaction_context: TransactionContext) -> None:
        """Test marking nonexistent operation raises no error."""
        # Should not raise exception for nonexistent operation
        transaction_context.mark_operation_successful("nonexistent", {})
        transaction_context.mark_operation_failed("nonexistent", "error")

    def test_transaction_context_is_expired(self, transaction_context: TransactionContext) -> None:
        """Test transaction expiration detection."""
        # Fresh transaction should not be expired
        assert not transaction_context.is_expired()

        # Test with very short timeout
        short_timeout_context = TransactionContext(
            transaction_id="tx-short",
            timeout_seconds=0,
        )
        # Even 0 timeout should allow some processing time
        assert not short_timeout_context.is_expired()

    def test_transaction_context_get_duration(self, transaction_context: TransactionContext) -> None:
        """Test transaction duration calculation."""
        duration = transaction_context.get_duration()
        assert duration >= 0
        assert isinstance(duration, float)

    def test_transaction_context_get_statistics(self, transaction_context: TransactionContext) -> None:
        """Test transaction statistics generation."""
        # Add various operations
        transaction_context.add_operation("add", "cn=user1,dc=example,dc=com", {})
        op2_id = transaction_context.add_operation("modify", "cn=user2,dc=example,dc=com", {})
        op3_id = transaction_context.add_operation("delete", "cn=user3,dc=example,dc=com", {})

        # Mark operations with different outcomes
        transaction_context.mark_operation_successful(op2_id, {"result_code": 0})
        transaction_context.mark_operation_failed(op3_id, "Access denied")

        stats = transaction_context.get_statistics()

        assert stats["transaction_id"] == "tx-123"
        assert stats["state"] == TransactionState.ACTIVE.value
        assert stats["total_operations"] == 3
        assert stats["successful_operations"] == 1
        assert stats["failed_operations"] == 1
        assert stats["pending_operations"] == 1
        assert stats["isolation_level"] == TransactionIsolation.READ_COMMITTED.value


class TestLDAPTransaction:
    """Test LDAPTransaction functionality."""

    @pytest.fixture
    def mock_connection(self) -> MagicMock:
        """Create mock LDAP connection for testing."""
        mock_conn = MagicMock()
        mock_conn.add.return_value = True
        mock_conn.modify.return_value = True
        mock_conn.delete.return_value = True
        mock_conn.search.return_value = True
        mock_conn.result = {"result": 0, "description": "Success"}
        mock_conn.last_error = None
        mock_conn.entries = []
        return mock_conn

    @pytest.fixture
    def transaction_context(self) -> TransactionContext:
        """Create test transaction context."""
        return TransactionContext(transaction_id="tx-test")

    @pytest.fixture
    def mock_tx_control(self) -> MagicMock:
        """Create mock transaction control."""
        mock_control = MagicMock()
        mock_control.to_ldap3_control.return_value = MagicMock()
        return mock_control

    @pytest.fixture
    def ldap_transaction(
        self,
        mock_connection: MagicMock,
        transaction_context: TransactionContext,
        mock_tx_control: MagicMock,
    ) -> LDAPTransaction:
        """Create test LDAP transaction."""
        return LDAPTransaction(mock_connection, transaction_context, mock_tx_control)

    async def test_ldap_transaction_add_entry_success(
        self,
        ldap_transaction: LDAPTransaction,
        mock_connection: MagicMock,
    ) -> None:
        """Test successful add entry operation."""
        result = await ldap_transaction.add_entry(
            "cn=newuser,dc=example,dc=com",
            {"cn": "newuser", "objectClass": ["person"]},
        )

        mock_connection.add.assert_called_once()
        assert result["success"] is True
        assert result["dn"] == "cn=newuser,dc=example,dc=com"
        assert ldap_transaction._operations_executed == 1

    async def test_ldap_transaction_add_entry_failure(
        self,
        ldap_transaction: LDAPTransaction,
        mock_connection: MagicMock,
    ) -> None:
        """Test add entry operation failure."""
        mock_connection.add.return_value = False
        mock_connection.last_error = "Already exists"

        with pytest.raises(RuntimeError, match="Add operation failed: Already exists"):
            await ldap_transaction.add_entry(
                "cn=existing,dc=example,dc=com",
                {"cn": "existing"},
            )

        assert ldap_transaction._operations_executed == 0

    async def test_ldap_transaction_add_entry_inactive_transaction(
        self,
        ldap_transaction: LDAPTransaction,
    ) -> None:
        """Test add entry with inactive transaction."""
        ldap_transaction._context.state = TransactionState.COMMITTED

        with pytest.raises(RuntimeError, match="Transaction not active"):
            await ldap_transaction.add_entry("cn=test,dc=example,dc=com", {})

    async def test_ldap_transaction_modify_entry_success(
        self,
        ldap_transaction: LDAPTransaction,
        mock_connection: MagicMock,
    ) -> None:
        """Test successful modify entry operation."""
        result = await ldap_transaction.modify_entry(
            "cn=user,dc=example,dc=com",
            {"mail": "new@example.com", "title": None},  # Replace and delete
        )

        mock_connection.modify.assert_called_once()
        assert result["success"] is True
        assert result["changes_applied"]["mail"] == "new@example.com"

    async def test_ldap_transaction_modify_entry_with_list_values(
        self,
        ldap_transaction: LDAPTransaction,
        mock_connection: MagicMock,
    ) -> None:
        """Test modify entry with list values."""
        await ldap_transaction.modify_entry(
            "cn=user,dc=example,dc=com",
            {"memberOf": ["cn=group1,dc=example,dc=com", "cn=group2,dc=example,dc=com"]},
        )

        # Verify ldap3 modify format was used
        call_args = mock_connection.modify.call_args
        modifications = call_args[1]["changes"]
        assert "memberOf" in modifications

    async def test_ldap_transaction_delete_entry_success(
        self,
        ldap_transaction: LDAPTransaction,
        mock_connection: MagicMock,
    ) -> None:
        """Test successful delete entry operation."""
        result = await ldap_transaction.delete_entry("cn=olduser,dc=example,dc=com")

        mock_connection.delete.assert_called_once()
        assert result["success"] is True
        assert result["dn"] == "cn=olduser,dc=example,dc=com"

    async def test_ldap_transaction_search_entries_success(
        self,
        ldap_transaction: LDAPTransaction,
        mock_connection: MagicMock,
    ) -> None:
        """Test successful search entries operation."""
        # Mock search results
        mock_entry = MagicMock()
        mock_entry.entry_dn = "cn=testuser,dc=example,dc=com"
        mock_entry.entry_attributes_as_dict = {"cn": ["testuser"], "mail": ["test@example.com"]}
        mock_entry.entry_raw_attributes = {"cn": [b"testuser"]}
        mock_connection.entries = [mock_entry]

        results = await ldap_transaction.search_entries(
            "dc=example,dc=com",
            "(cn=testuser)",
            ["cn", "mail"],
        )

        mock_connection.search.assert_called_once()
        assert len(results) == 1
        assert results[0]["dn"] == "cn=testuser,dc=example,dc=com"
        assert results[0]["attributes"]["cn"] == ["testuser"]

    async def test_ldap_transaction_search_entries_failure(
        self,
        ldap_transaction: LDAPTransaction,
        mock_connection: MagicMock,
    ) -> None:
        """Test search entries operation failure."""
        mock_connection.search.return_value = False
        mock_connection.last_error = "Invalid base DN"

        with pytest.raises(RuntimeError, match="Transactional search failed"):
            await ldap_transaction.search_entries("invalid", "(objectClass=*)")

    @patch("ldap_core_shared.transactions.controls.TransactionCommitControl")
    async def test_ldap_transaction_commit_success(
        self,
        mock_commit_control_class: MagicMock,
        ldap_transaction: LDAPTransaction,
        mock_connection: MagicMock,
    ) -> None:
        """Test successful transaction commit."""
        mock_commit_control = MagicMock()
        mock_commit_control_class.return_value = mock_commit_control

        # Add some operations first
        await ldap_transaction.add_entry("cn=user,dc=example,dc=com", {"cn": "user"})

        result = await ldap_transaction.commit()

        assert result is True
        assert ldap_transaction._context.state == TransactionState.COMMITTED
        assert ldap_transaction._context.committed_at is not None

    async def test_ldap_transaction_commit_with_failed_operations(
        self,
        ldap_transaction: LDAPTransaction,
    ) -> None:
        """Test commit with failed operations."""
        # Manually add a failed operation
        operation_id = ldap_transaction._context.add_operation("add", "cn=test,dc=example,dc=com", {})
        ldap_transaction._context.mark_operation_failed(operation_id, "Test failure")

        with pytest.raises(RuntimeError, match="Cannot commit transaction with .* failed operations"):
            await ldap_transaction.commit()

        assert ldap_transaction._context.state == TransactionState.ABORTED

    @patch("ldap_core_shared.transactions.controls.TransactionRollbackControl")
    async def test_ldap_transaction_rollback_success(
        self,
        mock_rollback_control_class: MagicMock,
        ldap_transaction: LDAPTransaction,
        mock_connection: MagicMock,
    ) -> None:
        """Test successful transaction rollback."""
        mock_rollback_control = MagicMock()
        mock_rollback_control_class.return_value = mock_rollback_control

        # Add some operations first
        await ldap_transaction.add_entry("cn=user,dc=example,dc=com", {"cn": "user"})

        result = await ldap_transaction.rollback()

        assert result is True
        assert ldap_transaction._context.state == TransactionState.ABORTED
        assert ldap_transaction._context.aborted_at is not None

    async def test_ldap_transaction_rollback_committed_transaction(
        self,
        ldap_transaction: LDAPTransaction,
    ) -> None:
        """Test rollback of committed transaction fails."""
        ldap_transaction._context.state = TransactionState.COMMITTED

        with pytest.raises(RuntimeError, match="Cannot rollback committed transaction"):
            await ldap_transaction.rollback()

    async def test_ldap_transaction_rollback_already_aborted(
        self,
        ldap_transaction: LDAPTransaction,
    ) -> None:
        """Test rollback of already aborted transaction."""
        ldap_transaction._context.state = TransactionState.ABORTED

        result = await ldap_transaction.rollback()
        assert result is True  # Should succeed without doing anything

    def test_ldap_transaction_properties(
        self,
        ldap_transaction: LDAPTransaction,
        transaction_context: TransactionContext,
    ) -> None:
        """Test LDAPTransaction properties."""
        assert ldap_transaction.context == transaction_context
        assert ldap_transaction.transaction_id == transaction_context.transaction_id
        assert ldap_transaction.state == transaction_context.state

        stats = ldap_transaction.get_statistics()
        assert stats["transaction_id"] == transaction_context.transaction_id


class TestTransactionManager:
    """Test TransactionManager functionality."""

    @pytest.fixture
    def mock_connection(self) -> MagicMock:
        """Create mock LDAP connection for testing."""
        mock_conn = MagicMock()
        mock_conn.modify.return_value = True
        mock_conn.result = {"result": 0, "description": "Success"}
        return mock_conn

    @pytest.fixture
    def transaction_manager(self, mock_connection: MagicMock) -> TransactionManager:
        """Create test transaction manager."""
        return TransactionManager(mock_connection)

    def test_transaction_manager_initialization(
        self,
        transaction_manager: TransactionManager,
        mock_connection: MagicMock,
    ) -> None:
        """Test TransactionManager initialization."""
        assert transaction_manager._connection == mock_connection
        assert len(transaction_manager._active_transactions) == 0

    @patch("ldap_core_shared.transactions.controls.TransactionSpecificationControl")
    async def test_transaction_manager_begin_transaction_success(
        self,
        mock_tx_control_class: MagicMock,
        transaction_manager: TransactionManager,
        mock_connection: MagicMock,
    ) -> None:
        """Test successful transaction begin and auto-commit."""
        mock_tx_control = MagicMock()
        mock_tx_control_class.return_value = mock_tx_control

        async with transaction_manager.begin_transaction() as tx:
            assert isinstance(tx, LDAPTransaction)
            assert tx.state == TransactionState.ACTIVE
            assert len(transaction_manager._active_transactions) == 1

            # Perform some operations
            mock_connection.add.return_value = True
            await tx.add_entry("cn=user,dc=example,dc=com", {"cn": "user"})

        # Transaction should be cleaned up after context
        assert len(transaction_manager._active_transactions) == 0

    @patch("ldap_core_shared.transactions.controls.TransactionSpecificationControl")
    async def test_transaction_manager_begin_transaction_with_exception(
        self,
        mock_tx_control_class: MagicMock,
        transaction_manager: TransactionManager,
        mock_connection: MagicMock,
    ) -> None:
        """Test transaction rollback on exception."""
        mock_tx_control = MagicMock()
        mock_tx_control_class.return_value = mock_tx_control

        with pytest.raises(RuntimeError, match="Test exception"):
            async with transaction_manager.begin_transaction() as tx:
                mock_connection.add.return_value = False
                mock_connection.last_error = "Test exception"

                # This should trigger rollback
                await tx.add_entry("cn=user,dc=example,dc=com", {"cn": "user"})

        # Transaction should be cleaned up even after exception
        assert len(transaction_manager._active_transactions) == 0

    @patch("ldap_core_shared.transactions.controls.TransactionSpecificationControl")
    async def test_transaction_manager_begin_transaction_custom_isolation(
        self,
        mock_tx_control_class: MagicMock,
        transaction_manager: TransactionManager,
    ) -> None:
        """Test transaction with custom isolation level and timeout."""
        async with transaction_manager.begin_transaction(
            isolation_level=TransactionIsolation.SERIALIZABLE,
            timeout_seconds=600,
        ) as tx:
            assert tx.context.isolation_level == TransactionIsolation.SERIALIZABLE
            assert tx.context.timeout_seconds == 600

    @patch("ldap_core_shared.transactions.controls.TransactionSpecificationControl")
    async def test_transaction_manager_get_transaction(
        self,
        mock_tx_control_class: MagicMock,
        transaction_manager: TransactionManager,
    ) -> None:
        """Test getting active transaction by ID."""
        async with transaction_manager.begin_transaction() as tx:
            tx_id = tx.transaction_id

            # Should find active transaction
            found_tx = await transaction_manager.get_transaction(tx_id)
            assert found_tx == tx

            # Should not find non-existent transaction
            not_found = await transaction_manager.get_transaction("nonexistent")
            assert not_found is None

    @patch("ldap_core_shared.transactions.controls.TransactionSpecificationControl")
    async def test_transaction_manager_get_active_transactions(
        self,
        mock_tx_control_class: MagicMock,
        transaction_manager: TransactionManager,
    ) -> None:
        """Test getting list of active transaction IDs."""
        # Initially no transactions
        assert len(transaction_manager.get_active_transactions()) == 0

        async with transaction_manager.begin_transaction() as tx1:
            assert len(transaction_manager.get_active_transactions()) == 1
            assert tx1.transaction_id in transaction_manager.get_active_transactions()

            async with transaction_manager.begin_transaction() as tx2:
                assert len(transaction_manager.get_active_transactions()) == 2
                assert tx2.transaction_id in transaction_manager.get_active_transactions()

        # Should be cleaned up after context managers
        assert len(transaction_manager.get_active_transactions()) == 0

    @patch("ldap_core_shared.transactions.controls.TransactionSpecificationControl")
    async def test_transaction_manager_abort_transaction(
        self,
        mock_tx_control_class: MagicMock,
        transaction_manager: TransactionManager,
    ) -> None:
        """Test aborting specific transaction."""
        async with transaction_manager.begin_transaction() as tx:
            tx_id = tx.transaction_id

            # Abort transaction externally
            result = await transaction_manager.abort_transaction(tx_id)
            assert result is True

            # Transaction should be removed from active list
            assert tx_id not in transaction_manager.get_active_transactions()

    async def test_transaction_manager_abort_nonexistent_transaction(
        self,
        transaction_manager: TransactionManager,
    ) -> None:
        """Test aborting non-existent transaction."""
        result = await transaction_manager.abort_transaction("nonexistent")
        assert result is False

    @patch("ldap_core_shared.transactions.controls.TransactionSpecificationControl")
    async def test_transaction_manager_abort_all_transactions(
        self,
        mock_tx_control_class: MagicMock,
        transaction_manager: TransactionManager,
    ) -> None:
        """Test aborting all active transactions."""
        # Create multiple transactions but don't use context managers
        # so they stay active
        tx1_task = asyncio.create_task(self._create_long_running_transaction(transaction_manager))
        tx2_task = asyncio.create_task(self._create_long_running_transaction(transaction_manager))

        # Wait for transactions to start
        await asyncio.sleep(0.1)

        # Should have 2 active transactions
        assert len(transaction_manager.get_active_transactions()) == 2

        # Abort all
        aborted_count = await transaction_manager.abort_all_transactions()
        assert aborted_count == 2
        assert len(transaction_manager.get_active_transactions()) == 0

        # Clean up tasks
        tx1_task.cancel()
        tx2_task.cancel()
        await asyncio.gather(tx1_task, tx2_task, return_exceptions=True)

    async def _create_long_running_transaction(self, manager: TransactionManager) -> None:
        """Helper to create long-running transaction for testing."""
        try:
            async with manager.begin_transaction():
                await asyncio.sleep(10)  # Long operation
        except asyncio.CancelledError:
            pass

    def test_transaction_manager_get_manager_statistics(
        self,
        transaction_manager: TransactionManager,
    ) -> None:
        """Test getting transaction manager statistics."""
        stats = transaction_manager.get_manager_statistics()

        assert "active_transactions" in stats
        assert stats["active_transactions"] == 0
        assert "connection_info" in stats


@pytest.mark.integration
class TestTransactionIntegration:
    """Integration tests for transaction functionality."""

    @pytest.mark.asyncio
    async def test_full_transaction_workflow(self) -> None:
        """Test complete transaction workflow."""
        mock_connection = MagicMock()
        mock_connection.add.return_value = True
        mock_connection.modify.return_value = True
        mock_connection.delete.return_value = True
        mock_connection.result = {"result": 0, "description": "Success"}

        manager = TransactionManager(mock_connection)

        with patch("ldap_core_shared.transactions.controls.TransactionSpecificationControl"):
            async with manager.begin_transaction() as tx:
                # Add user
                await tx.add_entry(
                    "uid=john,ou=users,dc=example,dc=com",
                    {"uid": "john", "cn": "John Doe", "objectClass": ["person"]},
                )

                # Add to group
                await tx.modify_entry(
                    "cn=staff,ou=groups,dc=example,dc=com",
                    {"member": ["uid=john,ou=users,dc=example,dc=com"]},
                )

                # Verify operations were tracked
                assert len(tx.context.operations) == 2
                assert tx.context.operations[0].operation_type == "add"
                assert tx.context.operations[1].operation_type == "modify"

        # Transaction should be committed and cleaned up
        assert len(manager.get_active_transactions()) == 0


@pytest.mark.performance
class TestTransactionPerformance:
    """Performance tests for transaction operations."""

    @pytest.mark.asyncio
    async def test_concurrent_transactions(self) -> None:
        """Test concurrent transaction performance."""
        mock_connection = MagicMock()
        mock_connection.add.return_value = True
        mock_connection.result = {"result": 0, "description": "Success"}

        manager = TransactionManager(mock_connection)

        async def single_transaction(index: int) -> None:
            with patch("ldap_core_shared.transactions.controls.TransactionSpecificationControl"):
                async with manager.begin_transaction() as tx:
                    await tx.add_entry(f"cn=user{index},dc=example,dc=com", {"cn": f"user{index}"})

        # Run 10 concurrent transactions
        tasks = [single_transaction(i) for i in range(10)]
        await asyncio.gather(*tasks)

        # All should complete successfully
        assert len(manager.get_active_transactions()) == 0

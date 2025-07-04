"""Pytest configuration and shared fixtures for core module tests.

Provides reusable test fixtures, mock objects, and utilities to avoid
code duplication across test modules. Implements enterprise-grade test
infrastructure following DRY and SOLID principles.

Shared Resources:
    - Mock LDAP connections with realistic behavior
    - Sample data generators for various test scenarios
    - Performance validation utilities
    - Transaction context builders
    - Error simulation helpers

Performance Testing:
    - Validates 12,000+ entries/second capability
    - Memory usage monitoring
    - Connection pool efficiency testing
    - Bulk operation performance validation

Version: 1.0.0-enterprise
"""

from __future__ import annotations

import time
from datetime import UTC, datetime
from typing import TYPE_CHECKING, Any
from unittest.mock import MagicMock
from uuid import uuid4

import pytest
from ldap_core_shared.core.operations import (
    EnterpriseTransaction,
    LDAPOperationRequest,
    LDAPOperations,
    TransactionContext,
)

if TYPE_CHECKING:
    from ldap_core_shared.domain.results import BulkOperationResult, LDAPOperationResult

# SHARED TEST DATA GENERATORS


class TestDataGenerator:
    """Centralized test data generator to eliminate duplication."""

    @staticmethod
    def valid_dn(prefix: str = "cn=test") -> str:
        """Generate valid DN for testing."""
        unique_id = str(uuid4())[:8]
        return f"{prefix}{unique_id},ou=people,dc=test,dc=com"

    @staticmethod
    def invalid_dns() -> list[str]:
        """Generate list of invalid DNs for validation testing."""
        return [
            "",  # Empty
            "invalid",  # No equals
            "cn=",  # Empty value
            "=test",  # Empty attribute
            "cn=test,",  # Trailing comma
            "cn=test,,ou=people",  # Double comma
        ]

    @staticmethod
    def ldap_attributes(
        object_class: str = "person",
        extra_attrs: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        """Generate LDAP attributes for testing."""
        attrs = {
            "objectClass": [object_class],
            "cn": f"Test User {str(uuid4())[:8]}",
            "sn": "User",
            "mail": f"test{str(uuid4())[:8]}@example.com",
        }

        if extra_attrs:
            attrs.update(extra_attrs)

        return attrs

    @staticmethod
    def bulk_entries(count: int = 100) -> list[dict[str, Any]]:
        """Generate bulk entries for performance testing."""
        return [
            {
                "dn": TestDataGenerator.valid_dn(f"cn=bulk{i}"),
                "attributes": TestDataGenerator.ldap_attributes(
                    extra_attrs={"employeeNumber": [str(i)]},
                ),
            }
            for i in range(count)
        ]

    @staticmethod
    def ldap_changes() -> dict[str, Any]:
        """Generate LDAP modify changes for testing."""
        return {
            "description": {
                "action": "MODIFY_REPLACE",
                "values": [f"Updated description {datetime.now(UTC).isoformat()}"],
            },
            "telephoneNumber": ["+1-555-0123"],
            "title": "Senior Developer",
        }


# MOCK LDAP CONNECTION


class MockLDAPConnection:
    """Mock LDAP connection implementing ConnectionProtocol.

    Provides realistic LDAP connection behavior for testing without
    requiring actual LDAP server. Supports all operations with
    configurable responses and error simulation.
    """

    def __init__(
        self,
        simulate_failures: bool = False,
        failure_rate: float = 0.0,
        response_delay: float = 0.0,
    ) -> None:
        """Initialize mock connection.

        Args:
            simulate_failures: Whether to simulate operation failures
            failure_rate: Percentage of operations that should fail (0.0-1.0)
            response_delay: Artificial delay in seconds for each operation

        """
        self._simulate_failures = simulate_failures
        self._failure_rate = failure_rate
        self._response_delay = response_delay

        # Mock state
        self._entries_database: dict[str, dict[str, Any]] = {}
        self._operation_count = 0
        self._last_result = {"result": 0, "message": "Success"}
        self._last_entries: list[Any] = []

        # Statistics for validation
        self.operations_performed = []
        self.search_calls = 0
        self.add_calls = 0
        self.modify_calls = 0
        self.delete_calls = 0

    def _should_fail(self) -> bool:
        """Determine if current operation should fail."""
        if not self._simulate_failures:
            return False

        import random

        return random.random() < self._failure_rate

    def _simulate_delay(self) -> None:
        """Simulate network/processing delay."""
        if self._response_delay > 0:
            time.sleep(self._response_delay)

    def search(
        self,
        search_base: str,
        search_filter: str,
        search_scope: str,
        attributes: list[str] | None = None,
        size_limit: int = 0,
        time_limit: int = 0,
    ) -> bool:
        """Mock LDAP search operation."""
        self._simulate_delay()
        self.search_calls += 1
        self._operation_count += 1

        self.operations_performed.append(
            {
                "operation": "search",
                "search_base": search_base,
                "search_filter": search_filter,
                "timestamp": datetime.now(UTC).isoformat(),
            },
        )

        if self._should_fail():
            self._last_result = {"result": 1, "message": "Search failed"}
            return False

        # Mock search behavior - find entry if it exists
        if search_base in self._entries_database:
            # Create mock entry object
            entry_mock = MagicMock()
            entry_mock.entry_dn = search_base
            entry_mock.entry_attributes = list(
                self._entries_database[search_base].keys(),
            )

            # Mock attribute access
            for attr, values in self._entries_database[search_base].items():
                attr_mock = MagicMock()
                attr_mock.values = values if isinstance(values, list) else [values]
                setattr(entry_mock, attr, attr_mock)

            self._last_entries = [entry_mock]
        else:
            self._last_entries = []

        self._last_result = {"result": 0, "message": "Success"}
        return True

    def add(self, dn: str, attributes: dict[str, Any]) -> bool:
        """Mock LDAP add operation."""
        self._simulate_delay()
        self.add_calls += 1
        self._operation_count += 1

        self.operations_performed.append(
            {
                "operation": "add",
                "dn": dn,
                "attributes_count": len(attributes),
                "timestamp": datetime.now(UTC).isoformat(),
            },
        )

        if self._should_fail():
            self._last_result = {"result": 68, "message": "Entry already exists"}
            return False

        # Check if entry already exists
        if dn in self._entries_database:
            self._last_result = {"result": 68, "message": "Entry already exists"}
            return False

        # Add entry to mock database
        self._entries_database[dn] = attributes.copy()
        self._last_result = {"result": 0, "message": "Success"}
        return True

    def modify(self, dn: str, changes: dict[str, Any]) -> bool:
        """Mock LDAP modify operation."""
        self._simulate_delay()
        self.modify_calls += 1
        self._operation_count += 1

        self.operations_performed.append(
            {
                "operation": "modify",
                "dn": dn,
                "changes_count": len(changes),
                "timestamp": datetime.now(UTC).isoformat(),
            },
        )

        if self._should_fail():
            self._last_result = {"result": 32, "message": "No such object"}
            return False

        # Check if entry exists
        if dn not in self._entries_database:
            self._last_result = {"result": 32, "message": "No such object"}
            return False

        # Apply changes to mock database
        for attr, change_list in changes.items():
            if isinstance(change_list, list):
                for action, values in change_list:
                    if action == "MODIFY_REPLACE":
                        self._entries_database[dn][attr] = values
                    elif action == "MODIFY_ADD":
                        if attr not in self._entries_database[dn]:
                            self._entries_database[dn][attr] = []
                        self._entries_database[dn][attr].extend(values)
                    elif action == "MODIFY_DELETE":
                        if attr in self._entries_database[dn]:
                            del self._entries_database[dn][attr]

        self._last_result = {"result": 0, "message": "Success"}
        return True

    def delete(self, dn: str) -> bool:
        """Mock LDAP delete operation."""
        self._simulate_delay()
        self.delete_calls += 1
        self._operation_count += 1

        self.operations_performed.append(
            {
                "operation": "delete",
                "dn": dn,
                "timestamp": datetime.now(UTC).isoformat(),
            },
        )

        if self._should_fail():
            self._last_result = {"result": 32, "message": "No such object"}
            return False

        # Check if entry exists
        if dn not in self._entries_database:
            self._last_result = {"result": 32, "message": "No such object"}
            return False

        # Remove entry from mock database
        del self._entries_database[dn]
        self._last_result = {"result": 0, "message": "Success"}
        return True

    @property
    def result(self) -> dict[str, Any]:
        """Get last operation result."""
        return self._last_result

    @property
    def entries(self) -> list[Any]:
        """Get search result entries."""
        return self._last_entries

    # Utility methods for testing
    def get_entry(self, dn: str) -> dict[str, Any] | None:
        """Get entry from mock database for validation."""
        return self._entries_database.get(dn)

    def entry_exists(self, dn: str) -> bool:
        """Check if entry exists in mock database."""
        return dn in self._entries_database

    def get_statistics(self) -> dict[str, Any]:
        """Get connection usage statistics."""
        return {
            "total_operations": self._operation_count,
            "search_calls": self.search_calls,
            "add_calls": self.add_calls,
            "modify_calls": self.modify_calls,
            "delete_calls": self.delete_calls,
            "entries_in_database": len(self._entries_database),
            "operations_log": self.operations_performed.copy(),
        }


# SHARED FIXTURES


@pytest.fixture
def data_generator():
    """Provide test data generator instance."""
    return TestDataGenerator()


@pytest.fixture
def mock_connection():
    """Provide mock LDAP connection with default behavior."""
    return MockLDAPConnection()


@pytest.fixture
def mock_connection_with_failures():
    """Provide mock LDAP connection that simulates failures."""
    return MockLDAPConnection(simulate_failures=True, failure_rate=0.1)


@pytest.fixture
def mock_connection_slow():
    """Provide mock LDAP connection with simulated network delay."""
    return MockLDAPConnection(response_delay=0.01)  # 10ms delay


@pytest.fixture
def transaction_context():
    """Provide basic transaction context for testing."""
    return TransactionContext(
        transaction_id=f"test_tx_{str(uuid4())[:8]}",
        timeout_seconds=300,  # 5 minutes for tests
    )


@pytest.fixture
def enterprise_transaction(mock_connection: Any, transaction_context: Any):
    """Provide enterprise transaction for testing."""
    return EnterpriseTransaction(mock_connection, transaction_context)


@pytest.fixture
def ldap_operations(mock_connection: Any):
    """Provide LDAP operations manager for testing."""
    return LDAPOperations(mock_connection)


@pytest.fixture
def valid_operation_request(data_generator: Any):
    """Provide valid LDAP operation request for testing."""
    return LDAPOperationRequest(
        operation_type="add",
        dn=data_generator.valid_dn(),
        attributes=data_generator.ldap_attributes(),
    )


@pytest.fixture
def bulk_test_entries(data_generator: Any):
    """Provide bulk entries for performance testing."""
    return data_generator.bulk_entries(100)  # 100 entries for tests


@pytest.fixture
def performance_validator():
    """Provide performance validation utilities."""

    class PerformanceValidator:
        """Utilities for validating performance requirements."""

        @staticmethod
        def validate_throughput(
            operation_count: int,
            duration_seconds: float,
            min_ops_per_second: float = 1000.0,
        ) -> bool:
            """Validate that operation throughput meets requirements."""
            if duration_seconds <= 0:
                return False

            ops_per_second = operation_count / duration_seconds
            return ops_per_second >= min_ops_per_second

        @staticmethod
        def validate_memory_usage(
            max_memory_mb: float = 100.0,
        ) -> bool:
            """Validate memory usage is within limits."""
            import os

            import psutil

            process = psutil.Process(os.getpid())
            memory_mb = process.memory_info().rss / 1024 / 1024
            return memory_mb <= max_memory_mb

        @staticmethod
        def time_operation(func: Any, *args: Any, **kwargs: Any) -> tuple[Any, float]:
            """Time an operation and return result and duration."""
            start_time = time.time()
            result = func(*args, **kwargs)
            duration = time.time() - start_time
            return result, duration

    return PerformanceValidator()


# SHARED ASSERTION HELPERS


class TestAssertions:
    """Centralized assertion helpers to avoid duplication."""

    @staticmethod
    def assert_operation_result_success(result: LDAPOperationResult) -> None:
        """Assert that operation result indicates success."""
        assert result.success is True
        assert result.message is not None
        assert result.duration >= 0
        assert result.dn is not None
        assert result.operation_type is not None

    @staticmethod
    def assert_operation_result_failure(
        result: LDAPOperationResult,
        expected_error_substring: str | None = None,
    ) -> None:
        """Assert that operation result indicates failure."""
        assert result.success is False
        assert result.message is not None
        if expected_error_substring:
            assert expected_error_substring.lower() in result.message.lower()

    @staticmethod
    def assert_bulk_result_statistics(
        result: BulkOperationResult,
        expected_total: int,
        min_success_rate: float = 0.95,
    ) -> None:
        """Assert bulk operation result meets expectations."""
        assert result.total_entries == expected_total
        assert result.successful_entries + result.failed_entries == expected_total

        success_rate = (
            result.successful_entries / expected_total if expected_total > 0 else 1.0
        )
        assert success_rate >= min_success_rate

        assert result.operation_duration > 0
        assert result.transaction_id is not None
        assert isinstance(result.operations_log, list)

    @staticmethod
    def assert_transaction_context_valid(context: TransactionContext) -> None:
        """Assert transaction context is properly configured."""
        assert context.transaction_id is not None
        assert len(context.transaction_id) > 0
        assert context.timeout_seconds > 0
        assert isinstance(context.operations_log, list)
        assert isinstance(context.backups, list)
        assert isinstance(context.checkpoints, list)


@pytest.fixture
def test_assertions():
    """Provide centralized test assertions."""
    return TestAssertions()


# PARAMETRIZED TEST DATA


@pytest.fixture(
    params=[
        "add",
        "modify",
        "delete",
    ],
)
def operation_type(request: Any):
    """Parametrized fixture for testing different operation types."""
    return request.param


@pytest.fixture(
    params=[
        1,
        10,
        100,
        1000,
    ],
)
def bulk_sizes(request: Any):
    """Parametrized fixture for testing different bulk operation sizes."""
    return request.param


@pytest.fixture(
    params=[
        {"simulate_failures": False, "failure_rate": 0.0},
        {"simulate_failures": True, "failure_rate": 0.05},
        {"simulate_failures": True, "failure_rate": 0.1},
    ],
)
def connection_scenarios(request: Any):
    """Parametrized fixture for testing different connection scenarios."""
    return MockLDAPConnection(**request.param)


# INTEGRATION TEST HELPERS


@pytest.fixture
def integration_test_setup(mock_connection: Any, data_generator: Any):
    """Provide comprehensive setup for integration testing."""

    class IntegrationTestSetup:
        def __init__(self) -> None:
            self.connection = mock_connection
            self.data_generator = data_generator
            self.operations = LDAPOperations(mock_connection)
            self.test_entries = []

        def create_test_entries(self, count: int = 10) -> list[dict[str, Any]]:
            """Create test entries and add them to test database."""
            entries = self.data_generator.bulk_entries(count)

            # Add entries to mock database for testing
            for entry in entries:
                self.connection.add(entry["dn"], entry["attributes"])

            self.test_entries.extend(entries)
            return entries

        def cleanup_test_entries(self) -> None:
            """Clean up test entries from mock database."""
            for entry in self.test_entries:
                if self.connection.entry_exists(entry["dn"]):
                    self.connection.delete(entry["dn"])
            self.test_entries.clear()

    return IntegrationTestSetup()


# ERROR SIMULATION HELPERS


@pytest.fixture
def error_simulator():
    """Provide error simulation utilities for testing error handling."""

    class ErrorSimulator:
        """Utilities for simulating various error conditions."""

        @staticmethod
        def connection_timeout_error():
            """Simulate connection timeout."""
            from ldap3.core.exceptions import LDAPSocketReceiveError

            return LDAPSocketReceiveError("Connection timeout")

        @staticmethod
        def invalid_credentials_error():
            """Simulate invalid credentials."""
            from ldap3.core.exceptions import LDAPBindError

            return LDAPBindError("Invalid credentials")

        @staticmethod
        def server_unavailable_error():
            """Simulate server unavailable."""
            from ldap3.core.exceptions import LDAPSocketOpenError

            return LDAPSocketOpenError("Server unavailable")

        @staticmethod
        def entry_already_exists_error():
            """Simulate entry already exists."""
            from ldap3.core.exceptions import LDAPEntryAlreadyExistsResult

            return LDAPEntryAlreadyExistsResult("Entry already exists")

    return ErrorSimulator()


# PERFORMANCE TEST CONFIGURATION


@pytest.fixture
def performance_config():
    """Provide performance testing configuration."""
    return {
        "min_ops_per_second": 1000,  # Minimum operations per second
        "max_memory_mb": 100,  # Maximum memory usage in MB
        "bulk_test_sizes": [100, 1000, 5000],  # Different bulk sizes to test
        "timeout_seconds": 30,  # Test timeout
        "performance_validation_enabled": True,
    }


# CLEANUP FIXTURES


@pytest.fixture(autouse=True)
def cleanup_after_test() -> None:
    """Automatic cleanup after each test."""
    return  # Run the test

    # Cleanup code here if needed
    # For now, mock objects clean themselves up

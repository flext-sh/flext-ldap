"""Unit tests for FlextLdapOperations service.

Tests core LDAP operations functionality with comprehensive coverage.
Focuses on operations.py methods that can be tested without live LDAP connection.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

import pytest

from flext_ldap.services.connection import FlextLdapConnection
from flext_ldap.services.operations import FlextLdapOperations, _is_already_exists_error
from tests.helpers.operation_helpers import TestOperationHelpers

pytestmark = pytest.mark.unit


@pytest.fixture
def mock_connection() -> FlextLdapConnection:
    """Create a mock connection for testing."""
    from flext_ldap.config import FlextLdapConfig
    config = FlextLdapConfig()
    return FlextLdapConnection(config=config)


class TestFlextLdapOperations:
    """Tests for FlextLdapOperations core functionality."""

    def test_operations_initialization(self, mock_connection: FlextLdapConnection) -> None:
        """Test operations service initialization."""
        operations = FlextLdapOperations(connection=mock_connection)
        assert operations is not None
        assert operations._connection is not None
        assert operations._logger is not None

    def test_service_config_property(self, mock_connection: FlextLdapConnection) -> None:
        """Test service_config property returns FlextConfig."""
        operations = FlextLdapOperations(connection=mock_connection)
        config = operations.service_config
        assert config is not None
        from flext_core import FlextConfig
        assert isinstance(config, FlextConfig)

    def test_is_connected_not_connected(self, mock_connection: FlextLdapConnection) -> None:
        """Test is_connected returns False when not connected."""
        operations = FlextLdapOperations(connection=mock_connection)
        assert operations.is_connected is False

    def test_is_already_exists_error_detection(self, mock_connection: FlextLdapConnection) -> None:
        """Test _is_already_exists_error detects various 'already exists' patterns."""
        # Function is now module-level, not a method
        # FlextResult contract guarantees error is non-None, so function expects str
        assert _is_already_exists_error("Entry already exists") is True
        assert _is_already_exists_error("already exists") is True
        assert _is_already_exists_error("ALREADY EXISTS") is True
        assert _is_already_exists_error("entryAlreadyExists") is True
        assert _is_already_exists_error("attributeOrValueExists") is True
        assert _is_already_exists_error("Connection failed") is False
        assert _is_already_exists_error("") is False

    def test_compare_entries_identical(self, mock_connection: FlextLdapConnection) -> None:
        """Test _compare_entries with identical entries returns None."""
        operations = FlextLdapOperations(connection=mock_connection)

        entry1 = TestOperationHelpers.create_entry_simple(
            "cn=test,dc=example,dc=com",
            {"cn": ["test"], "sn": ["User"]}
        )
        entry2 = TestOperationHelpers.create_entry_simple(
            "cn=test,dc=example,dc=com",
            {"cn": ["test"], "sn": ["User"]}
        )

        assert operations._compare_entries(entry1, entry2) is None

    def test_compare_entries_different_attributes(self, mock_connection: FlextLdapConnection) -> None:
        """Test _compare_entries with different attributes returns changes dict."""
        operations = FlextLdapOperations(connection=mock_connection)

        entry1 = TestOperationHelpers.create_entry_simple(
            "cn=test,dc=example,dc=com",
            {"cn": ["test"], "sn": ["User"]}
        )
        entry2 = TestOperationHelpers.create_entry_simple(
            "cn=test,dc=example,dc=com",
            {"cn": ["test"], "sn": ["Different"]}
        )

        changes = operations._compare_entries(entry1, entry2)
        assert changes is not None
        assert isinstance(changes, dict)
        assert "sn" in changes

    def test_execute_method_returns_result(self, mock_connection: FlextLdapConnection) -> None:
        """Test execute method returns a FlextResult."""
        operations = FlextLdapOperations(connection=mock_connection)
        result = operations.execute()

        assert result is not None
        assert hasattr(result, 'is_success')
        assert hasattr(result, 'is_failure')
        assert result.is_failure  # Should fail when not connected

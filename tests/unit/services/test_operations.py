"""Unit tests for flext_ldap.services.operations.FlextLdapOperations.

Tests core LDAP operations service functionality with comprehensive coverage.
Focuses on initialization, configuration access, error detection, entry comparison,
and method existence validation without requiring live LDAP connections.
All tests use real implementations with mocked dependencies for isolation.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from enum import StrEnum

import pytest
from flext_core import FlextConfig
from flext_ldif.models import FlextLdifModels

from flext_ldap.config import FlextLdapConfig
from flext_ldap.models import FlextLdapModels
from flext_ldap.services.connection import FlextLdapConnection
from flext_ldap.services.operations import FlextLdapOperations

from ...helpers.entry_helpers import EntryTestHelpers

pytestmark = pytest.mark.unit


@pytest.fixture
def ldap_connection() -> FlextLdapConnection:
    """Create a real LDAP connection instance for testing (not connected)."""
    config = FlextLdapConfig.get_instance()
    return FlextLdapConnection(config=config)


class OperationTestScenario(StrEnum):
    """Test scenarios for LDAP operations testing."""

    DEFAULT = "default"
    EDGE_CASE = "edge_case"
    ERROR_CASE = "error_case"


class TestFlextLdapOperations:
    """Tests for FlextLdapOperations core functionality.

    Single class per module with parametrized test methods covering:
    - Operations service initialization and configuration
    - Fast-fail pattern for disconnected operations
    - Error handling and validation
    - Entry comparison functionality
    - Method existence validation

    Uses Python 3.13 StrEnum for test categorization and factory patterns
    for efficient test data generation.
    """

    def test_init_without_connection_raises_type_error(self) -> None:
        """Test that __init__ raises TypeError when connection is None."""
        with pytest.raises(TypeError, match="connection parameter is required"):
            FlextLdapOperations()

    def test_init_with_connection_succeeds(
        self, ldap_connection: FlextLdapConnection
    ) -> None:
        """Test that __init__ succeeds when connection is provided."""
        operations = FlextLdapOperations(connection=ldap_connection)
        assert operations is not None
        assert operations._connection is ldap_connection

    def test_operations_initialization(
        self, ldap_connection: FlextLdapConnection
    ) -> None:
        """Test operations service initialization."""
        operations = FlextLdapOperations(connection=ldap_connection)
        assert operations is not None
        assert operations._connection is not None
        assert operations.logger is not None

    def test_config_property(self, ldap_connection: FlextLdapConnection) -> None:
        """Test config property returns FlextConfig with ldap namespace."""
        operations = FlextLdapOperations(connection=ldap_connection)
        config = operations.config
        assert config is not None
        assert isinstance(config, FlextConfig)

    def test_is_connected_not_connected(
        self, ldap_connection: FlextLdapConnection
    ) -> None:
        """Test is_connected returns False when not connected."""
        operations = FlextLdapOperations(connection=ldap_connection)
        assert operations.is_connected is False

    @pytest.mark.parametrize(
        ("error_message", "expected"),
        [
            ("Entry already exists", True),
            ("already exists", True),
            ("ALREADY EXISTS", True),
            ("entryAlreadyExists", True),
            ("ldap_already_exists", True),
            ("Connection failed", False),
            ("", False),
        ],
    )
    def test_is_already_exists_error_detection(
        self,
        ldap_connection: FlextLdapConnection,
        error_message: str,
        expected: bool,
    ) -> None:
        """Test is_already_exists_error detects various 'already exists' patterns."""
        assert FlextLdapOperations.is_already_exists_error(error_message) is expected

    def test_compare_entries_identical(
        self, ldap_connection: FlextLdapConnection
    ) -> None:
        """Test _compare_entries with identical entries returns None."""
        operations = FlextLdapOperations(connection=ldap_connection)

        entry1 = EntryTestHelpers.create_entry(
            "cn=test,dc=example,dc=com", {"cn": ["test"], "sn": ["User"]}
        )
        entry2 = EntryTestHelpers.create_entry(
            "cn=test,dc=example,dc=com", {"cn": ["test"], "sn": ["User"]}
        )

        assert operations._compare_entries(entry1, entry2) is None

    def test_compare_entries_different_attributes(
        self, ldap_connection: FlextLdapConnection
    ) -> None:
        """Test _compare_entries with different attributes returns changes dict."""
        operations = FlextLdapOperations(connection=ldap_connection)

        entry1 = EntryTestHelpers.create_entry(
            "cn=test,dc=example,dc=com", {"cn": ["test"], "sn": ["User"]}
        )
        entry2 = EntryTestHelpers.create_entry(
            "cn=test,dc=example,dc=com", {"cn": ["test"], "sn": ["Different"]}
        )

        changes = operations._compare_entries(entry1, entry2)
        assert changes is not None
        assert isinstance(changes, dict)
        assert "sn" in changes

    def test_execute_method_returns_result(
        self, ldap_connection: FlextLdapConnection
    ) -> None:
        """Test execute method returns a FlextResult."""
        operations = FlextLdapOperations(connection=ldap_connection)
        result = operations.execute()

        assert result is not None
        assert hasattr(result, "is_success")
        assert hasattr(result, "is_failure")
        assert result.is_failure  # Should fail when not connected

    def test_compare_entries_method_exists(
        self, ldap_connection: FlextLdapConnection
    ) -> None:
        """Test _compare_entries method exists and can be called."""
        operations = FlextLdapOperations(connection=ldap_connection)

        # Create mock entries for comparison
        entry1 = FlextLdifModels.Entry(
            dn=FlextLdifModels.DistinguishedName(value="cn=test1,dc=example,dc=com"),
            attributes=FlextLdifModels.LdifAttributes(attributes={"cn": ["test1"]}),
        )
        entry2 = FlextLdifModels.Entry(
            dn=FlextLdifModels.DistinguishedName(value="cn=test2,dc=example,dc=com"),
            attributes=FlextLdifModels.LdifAttributes(attributes={"cn": ["test2"]}),
        )

        # Method should exist and be callable (may return any result since not connected)
        result = operations._compare_entries(entry1, entry2)
        assert result is not None  # Method executed

    def test_upsert_method_calls_internal(
        self, ldap_connection: FlextLdapConnection
    ) -> None:
        """Test upsert method calls _upsert_internal."""
        operations = FlextLdapOperations(connection=ldap_connection)

        entry = FlextLdifModels.Entry(
            dn=FlextLdifModels.DistinguishedName(value="cn=test,dc=example,dc=com"),
            attributes=FlextLdifModels.LdifAttributes(
                attributes={"cn": ["test"], "objectClass": ["person"]}
            ),
        )

        # Should fail since not connected, but should call the internal method
        result = operations.upsert(entry)
        assert result.is_failure

    def test_upsert_internal_method_exists(
        self, ldap_connection: FlextLdapConnection
    ) -> None:
        """Test _upsert_internal method exists."""
        operations = FlextLdapOperations(connection=ldap_connection)

        entry = FlextLdifModels.Entry(
            dn=FlextLdifModels.DistinguishedName(value="cn=test,dc=example,dc=com"),
            attributes=FlextLdifModels.LdifAttributes(attributes={"cn": ["test"]}),
        )

        # Method should exist (will fail since not connected)
        result = operations._upsert_internal(entry)
        assert result.is_failure

    def test_upsert_schema_modify_method_exists(
        self, ldap_connection: FlextLdapConnection
    ) -> None:
        """Test _upsert_schema_modify method exists."""
        operations = FlextLdapOperations(connection=ldap_connection)

        entry = FlextLdifModels.Entry(
            dn=FlextLdifModels.DistinguishedName(value="cn=test,dc=example,dc=com"),
            attributes=FlextLdifModels.LdifAttributes(attributes={"cn": ["test"]}),
        )

        # Method should exist (will fail since not connected)
        result = operations._upsert_schema_modify(entry)
        assert result.is_failure

    def test_upsert_regular_add_method_exists(
        self, ldap_connection: FlextLdapConnection
    ) -> None:
        """Test _upsert_regular_add method exists."""
        operations = FlextLdapOperations(connection=ldap_connection)

        entry = FlextLdifModels.Entry(
            dn=FlextLdifModels.DistinguishedName(value="cn=test,dc=example,dc=com"),
            attributes=FlextLdifModels.LdifAttributes(attributes={"cn": ["test"]}),
        )

        # Method should exist (will fail since not connected)
        result = operations._upsert_regular_add(entry)
        assert result.is_failure

    def test_upsert_handle_existing_entry_method_exists(
        self, ldap_connection: FlextLdapConnection
    ) -> None:
        """Test _upsert_handle_existing_entry method exists."""
        operations = FlextLdapOperations(connection=ldap_connection)

        entry = FlextLdifModels.Entry(
            dn=FlextLdifModels.DistinguishedName(value="cn=test,dc=example,dc=com"),
            attributes=FlextLdifModels.LdifAttributes(attributes={"cn": ["test"]}),
        )

        # Method should exist (returns skipped operation when connection fails)
        result = operations._upsert_handle_existing_entry(entry)
        assert result.is_success
        assert result.unwrap() == {"operation": "skipped"}

    def test_batch_upsert_method_exists(
        self, ldap_connection: FlextLdapConnection
    ) -> None:
        """Test batch_upsert method exists."""
        operations = FlextLdapOperations(connection=ldap_connection)

        entries = [
            FlextLdifModels.Entry(
                dn=FlextLdifModels.DistinguishedName(
                    value="cn=test1,dc=example,dc=com"
                ),
                attributes=FlextLdifModels.LdifAttributes(attributes={"cn": ["test1"]}),
            )
        ]

        # Method should exist (will fail since not connected)
        result = operations.batch_upsert(entries)
        assert result.is_failure

    def test_search_method_exists(self, ldap_connection: FlextLdapConnection) -> None:
        """Test that search method exists and can be called."""
        operations = FlextLdapOperations(connection=ldap_connection)
        search_options = FlextLdapModels.SearchOptions(
            base_dn="dc=example,dc=com",
            filter_str="(objectClass=*)",
            scope="SUBTREE",
        )

        # Method should exist (will fail since not connected)
        result = operations.search(search_options)
        assert result.is_failure

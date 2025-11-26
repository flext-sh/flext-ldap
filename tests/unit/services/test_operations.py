"""Unit tests for flext_ldap.services.operations.FlextLdapOperations.

**Modules Tested:**
- `flext_ldap.services.operations.FlextLdapOperations` - LDAP operations service

**Test Scope:**
- Operations service initialization and configuration access
- Fast-fail pattern for disconnected operations
- Error handling and validation
- Entry comparison functionality
- Method existence validation

All tests use real functionality without mocks, leveraging flext-core test utilities
and domain-specific helpers to reduce code duplication while maintaining 100% coverage.

Module: TestFlextLdapOperations
Scope: Comprehensive operations testing with maximum code reuse
Pattern: Parametrized tests using factories and constants

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

import pytest
from flext_core import FlextConfig

from flext_ldap.config import FlextLdapConfig
from flext_ldap.models import FlextLdapModels
from flext_ldap.services.connection import FlextLdapConnection
from flext_ldap.services.operations import FlextLdapOperations

from ...fixtures.constants import TestConstants
from ...helpers.entry_helpers import EntryTestHelpers

pytestmark = pytest.mark.unit


@pytest.fixture
def ldap_connection() -> FlextLdapConnection:
    """Create a real LDAP connection instance for testing (not connected)."""
    config = FlextLdapConfig.get_instance()
    return FlextLdapConnection(config=config)


class TestFlextLdapOperations:
    """Comprehensive tests for FlextLdapOperations using factories and DRY principles.

    Uses parametrized tests and constants for maximum code reuse.
    """

    def test_init_without_connection_raises_type_error(self) -> None:
        """Test that __init__ raises TypeError when connection is not provided."""
        # Dynamically call the class using getattr to bypass static analysis
        # This tests that Python enforces the required parameter at runtime
        cls = __import__("flext_ldap.services.operations", fromlist=["FlextLdapOperations"]).FlextLdapOperations
        with pytest.raises(TypeError, match="missing 1 required positional argument"):
            cls()

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
        error_message: str,
        expected: bool,
    ) -> None:
        """Test is_already_exists_error detects various 'already exists' patterns."""
        assert FlextLdapOperations.is_already_exists_error(error_message) is expected

    def test_entry_comparison_identical(
        self, ldap_connection: FlextLdapConnection
    ) -> None:
        """Test EntryComparison.compare with identical entries returns None."""
        entry1 = EntryTestHelpers.create_entry(
            TestConstants.Operations.TEST_DN,
            {"cn": ["test"], "sn": ["User"]},
        )
        entry2 = EntryTestHelpers.create_entry(
            TestConstants.Operations.TEST_DN,
            {"cn": ["test"], "sn": ["User"]},
        )
        assert FlextLdapOperations.EntryComparison.compare(entry1, entry2) is None

    def test_entry_comparison_different_attributes(
        self, ldap_connection: FlextLdapConnection
    ) -> None:
        """Test EntryComparison.compare with different attributes returns changes dict."""
        entry1 = EntryTestHelpers.create_entry(
            TestConstants.Operations.TEST_DN,
            {"cn": ["test"], "sn": ["User"]},
        )
        entry2 = EntryTestHelpers.create_entry(
            TestConstants.Operations.TEST_DN,
            {"cn": ["test"], "sn": ["Different"]},
        )
        changes = FlextLdapOperations.EntryComparison.compare(entry1, entry2)
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
        assert result.is_failure

    def test_upsert_method_calls_internal(
        self, ldap_connection: FlextLdapConnection
    ) -> None:
        """Test upsert method calls internal implementation."""
        operations = FlextLdapOperations(connection=ldap_connection)

        entry = EntryTestHelpers.create_entry(
            TestConstants.Operations.TEST_DN,
            {"cn": ["test"], "objectClass": ["person"]},
        )

        result = operations.upsert(entry)
        assert result.is_failure

    def test_batch_upsert_method_exists(
        self, ldap_connection: FlextLdapConnection
    ) -> None:
        """Test batch_upsert method exists."""
        operations = FlextLdapOperations(connection=ldap_connection)

        entries = [
            EntryTestHelpers.create_entry(
                TestConstants.Operations.TEST_DN_1,
                {"cn": ["test1"]},
            )
        ]

        result = operations.batch_upsert(entries)
        assert result.is_failure

    def test_search_method_exists(self, ldap_connection: FlextLdapConnection) -> None:
        """Test that search method exists and can be called."""
        operations = FlextLdapOperations(connection=ldap_connection)
        search_options = FlextLdapModels.SearchOptions(
            base_dn=TestConstants.Operations.BASE_DN,
            filter_str=TestConstants.Operations.DEFAULT_FILTER,
            scope="SUBTREE",
        )

        result = operations.search(search_options)
        assert result.is_failure

"""Unit tests for FlextLdapOperations service.

Tests core LDAP operations functionality with comprehensive coverage.
Focuses on operations.py methods that can be tested without live LDAP connection.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

import pytest
from flext_core import FlextConfig
from flext_ldif.models import FlextLdifModels

from flext_ldap.config import FlextLdapConfig
from flext_ldap.services.connection import FlextLdapConnection
from flext_ldap.services.operations import FlextLdapOperations

from ...helpers.entry_helpers import EntryTestHelpers

pytestmark = pytest.mark.unit


@pytest.fixture
def ldap_connection() -> FlextLdapConnection:
    """Create a real LDAP connection instance for testing (not connected)."""
    config = FlextLdapConfig()
    return FlextLdapConnection(config=config)


class TestFlextLdapOperations:
    """Tests for FlextLdapOperations core functionality."""

    def test_operations_initialization(
        self, ldap_connection: FlextLdapConnection
    ) -> None:
        """Test operations service initialization."""
        operations = FlextLdapOperations(connection=ldap_connection)
        assert operations is not None
        assert operations._connection is not None
        assert operations.logger is not None

    def test_service_config_property(
        self, ldap_connection: FlextLdapConnection
    ) -> None:
        """Test service_config property returns FlextConfig."""
        operations = FlextLdapOperations(connection=ldap_connection)
        config = operations.service_config
        assert config is not None

        assert isinstance(config, FlextConfig)

    def test_is_connected_not_connected(
        self, ldap_connection: FlextLdapConnection
    ) -> None:
        """Test is_connected returns False when not connected."""
        operations = FlextLdapOperations(connection=ldap_connection)
        assert operations.is_connected is False

    def test_is_already_exists_error_detection(
        self, ldap_connection: FlextLdapConnection
    ) -> None:
        """Test is_already_exists_error detects various 'already exists' patterns."""
        # Method is now static method of FlextLdapOperations class
        # FlextResult contract guarantees error is non-None, so function expects str
        assert (
            FlextLdapOperations.is_already_exists_error("Entry already exists") is True
        )
        assert FlextLdapOperations.is_already_exists_error("already exists") is True
        assert FlextLdapOperations.is_already_exists_error("ALREADY EXISTS") is True
        assert FlextLdapOperations.is_already_exists_error("entryAlreadyExists") is True
        assert (
            FlextLdapOperations.is_already_exists_error("ldap_already_exists") is True
        )
        assert FlextLdapOperations.is_already_exists_error("Connection failed") is False
        assert FlextLdapOperations.is_already_exists_error("") is False

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

    def test_normalize_dn_with_distinguished_name(
        self, ldap_connection: FlextLdapConnection
    ) -> None:
        """Test normalize_dn with DistinguishedName object (covers line 56)."""
        operations = FlextLdapOperations(connection=ldap_connection)
        dn_obj = FlextLdifModels.DistinguishedName(value="cn=test,dc=example,dc=com")

        result = operations.normalize_dn(dn_obj)
        assert result == dn_obj

    def test_normalize_dn_with_string(
        self, ldap_connection: FlextLdapConnection
    ) -> None:
        """Test normalize_dn with string (covers line 58)."""
        operations = FlextLdapOperations(connection=ldap_connection)
        dn_string = "cn=test,dc=example,dc=com"

        result = operations.normalize_dn(dn_string)
        assert isinstance(result, FlextLdifModels.DistinguishedName)
        assert result.value == dn_string

    def test_is_already_exists_error_various_messages(
        self, ldap_connection: FlextLdapConnection
    ) -> None:
        """Test is_already_exists_error with various error messages (covers line 62)."""
        operations = FlextLdapOperations(connection=ldap_connection)

        # Test various "already exists" error messages
        exists_messages = [
            "Entry already exists",
            "LDAPException: Already exists",
            "entryAlreadyExists",
            "LDAP_ALREADY_EXISTS",
        ]

        for msg in exists_messages:
            assert operations.is_already_exists_error(msg)

        # Test non-exists messages
        non_exists_messages = [
            "Entry not found",
            "Invalid credentials",
            "Connection failed",
        ]

        for msg in non_exists_messages:
            assert not operations.is_already_exists_error(msg)

    def test_is_connected_property_false(
        self, ldap_connection: FlextLdapConnection
    ) -> None:
        """Test is_connected property returns False when not connected (covers line 306)."""
        operations = FlextLdapOperations(connection=ldap_connection)
        assert operations.is_connected is False

    def test_compare_entries_method_exists(
        self, ldap_connection: FlextLdapConnection
    ) -> None:
        """Test _compare_entries method exists and can be called (covers line 315)."""
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
        """Test upsert method calls _upsert_internal (covers line 461)."""
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
        """Test _upsert_internal method exists (covers line 569)."""
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
        """Test _upsert_schema_modify method exists (covers line 594)."""
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
        """Test _upsert_regular_add method exists (covers line 700)."""
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
        """Test _upsert_handle_existing_entry method exists (covers line 739)."""
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
        """Test batch_upsert method exists (covers line 855)."""
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

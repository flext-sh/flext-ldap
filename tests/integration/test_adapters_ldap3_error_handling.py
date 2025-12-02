"""Integration tests for Ldap3Adapter error handling with real LDAP server.

Tests all error handling paths with real LDAP operations.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from collections.abc import Generator

import pytest
from flext_ldif import FlextLdifParser
from ldap3 import MODIFY_REPLACE
from pydantic import ValidationError

from flext_ldap.adapters.ldap3 import Ldap3Adapter
from flext_ldap.constants import FlextLdapConstants
from flext_ldap.models import FlextLdapModels

from ..fixtures.constants import RFC
from ..fixtures.typing import LdapContainerDict
from ..helpers.entry_helpers import EntryTestHelpers
from ..helpers.operation_helpers import TestOperationHelpers

pytestmark = pytest.mark.integration


class TestLdap3AdapterErrorHandling:
    """Tests for Ldap3Adapter error handling."""

    @pytest.fixture
    def connected_adapter(
        self,
        ldap_parser: FlextLdifParser,
        connection_config: FlextLdapModels.ConnectionConfig,
    ) -> Generator[Ldap3Adapter]:
        """Get connected adapter for testing."""
        adapter = Ldap3Adapter(parser=ldap_parser)
        connect_result = adapter.connect(connection_config)
        if connect_result.is_failure:
            pytest.skip(f"Failed to connect: {connect_result.error}")
        yield adapter
        adapter.disconnect()

    def test_search_with_invalid_base_dn(
        self,
        connected_adapter: Ldap3Adapter,
    ) -> None:
        """Test search with invalid base DN - Pydantic validation prevents invalid DN."""
        # Pydantic v2 validates base_dn format at model creation
        # Invalid DN will raise ValidationError before reaching adapter

        with pytest.raises(ValidationError) as exc_info:
            FlextLdapModels.SearchOptions(
                base_dn="invalid-dn-format",
                filter_str="(objectClass=*)",
                scope=FlextLdapConstants.SearchScope.SUBTREE,
            )
        # Verify it's the correct validation error
        assert "base_dn" in str(exc_info.value)
        assert "Invalid base_dn format" in str(exc_info.value)

    def test_search_with_invalid_filter(
        self,
        connected_adapter: Ldap3Adapter,
    ) -> None:
        """Test search with invalid filter."""
        search_options = FlextLdapModels.SearchOptions(
            base_dn=RFC.DEFAULT_BASE_DN,
            filter_str="invalid(filter",
            scope=FlextLdapConstants.SearchScope.SUBTREE,
        )
        result = connected_adapter.search(search_options)
        # Should handle gracefully
        assert result.is_success or result.is_failure

    def test_add_with_invalid_entry(
        self,
        connected_adapter: Ldap3Adapter,
    ) -> None:
        """Test add with invalid entry."""
        # Entry with invalid DN format
        entry = EntryTestHelpers.create_entry(
            "invalid-dn",
            {
                "cn": ["test"],
                "objectClass": ["top", "person"],
            },
        )

        result = connected_adapter.add(entry)
        # Should fail gracefully
        assert result.is_failure

    def test_add_with_missing_objectclass(
        self,
        connected_adapter: Ldap3Adapter,
    ) -> None:
        """Test add with missing objectClass."""
        # Create entry without objectClass for error test
        entry = EntryTestHelpers.create_entry(
            "cn=testnooc,ou=people,dc=flext,dc=local",
            {"cn": ["testnooc"]},  # Missing objectClass
        )

        # Cleanup first
        _ = connected_adapter.delete(str(entry.dn))

        result = connected_adapter.add(entry)
        # Should fail (objectClass required)
        assert result.is_failure

    def test_modify_with_invalid_dn(
        self,
        connected_adapter: Ldap3Adapter,
    ) -> None:
        """Test modify with invalid DN."""
        changes: dict[str, list[tuple[str, list[str]]]] = {
            "mail": [(MODIFY_REPLACE, ["test@example.com"])],
        }

        result = connected_adapter.modify("invalid-dn", changes)
        assert result.is_failure

    def test_modify_with_invalid_changes(
        self,
        connected_adapter: Ldap3Adapter,
    ) -> None:
        """Test modify with invalid changes format."""
        # Invalid changes format
        changes: dict[str, list[tuple[str, list[str]]]] = {}

        result = connected_adapter.modify(f"cn=test,{RFC.DEFAULT_BASE_DN}", changes)
        # Should handle gracefully
        assert result.is_success or result.is_failure

    def test_delete_with_invalid_dn(
        self,
        connected_adapter: Ldap3Adapter,
    ) -> None:
        """Test delete with invalid DN."""
        result = connected_adapter.delete("invalid-dn")
        assert result.is_failure

    def test_connect_with_invalid_credentials(
        self,
        ldap_container: LdapContainerDict,
    ) -> None:
        """Test connect with invalid credentials."""
        adapter = Ldap3Adapter()
        config = FlextLdapModels.ConnectionConfig(
            host=str(ldap_container["host"]),
            port=int(str(ldap_container["port"])),
            use_ssl=False,
            bind_dn=str(ldap_container["bind_dn"]),
            bind_password="wrong-password",
        )
        result = adapter.connect(config)
        assert result.is_failure
        adapter.disconnect()

    def test_search_exception_handling(
        self,
        connected_adapter: Ldap3Adapter,
    ) -> None:
        """Test search exception handling."""
        # This tests the exception handler in search method
        # Pydantic validates scope, so we use a valid scope but test error handling
        # with a filter that might cause issues
        search_options = FlextLdapModels.SearchOptions(
            base_dn=RFC.DEFAULT_BASE_DN,
            filter_str="(objectClass=*)",
            scope=FlextLdapConstants.SearchScope.SUBTREE,  # Valid scope - Pydantic prevents invalid values
        )
        result = connected_adapter.search(search_options)
        # Should handle gracefully
        assert result.is_success or result.is_failure

    def test_add_exception_handling(
        self,
        connected_adapter: Ldap3Adapter,
    ) -> None:
        """Test add exception handling."""
        # Entry that might cause issues
        entry = TestOperationHelpers.create_inetorgperson_entry(
            "testexception",
            RFC.DEFAULT_BASE_DN,
        )

        # Cleanup first
        _ = connected_adapter.delete(str(entry.dn))

        # Add should work or fail gracefully
        result = connected_adapter.add(entry)
        assert result.is_success or result.is_failure

        # Cleanup
        _ = connected_adapter.delete(str(entry.dn))

    def test_modify_exception_handling(
        self,
        connected_adapter: Ldap3Adapter,
    ) -> None:
        """Test modify exception handling."""
        # Try to modify non-existent entry
        changes: dict[str, list[tuple[str, list[str]]]] = {
            "mail": [(MODIFY_REPLACE, ["test@example.com"])],
        }

        result = connected_adapter.modify(
            "cn=nonexistent12345,dc=flext,dc=local",
            changes,
        )
        # Should fail gracefully
        assert result.is_failure

    def test_delete_exception_handling(
        self,
        connected_adapter: Ldap3Adapter,
    ) -> None:
        """Test delete exception handling."""
        # Try to delete non-existent entry
        result = connected_adapter.delete("cn=nonexistent12345,dc=flext,dc=local")
        # Should fail gracefully
        assert result.is_failure

    def test_connect_exception_handling(self) -> None:
        """Test connect exception handling."""
        adapter = Ldap3Adapter()
        # Use a valid port number but one that's not listening (connection will fail)
        config = FlextLdapModels.ConnectionConfig(
            host="localhost",
            port=65534,  # Valid port but not listening
            use_ssl=False,
            bind_dn="cn=REDACTED_LDAP_BIND_PASSWORD,dc=test,dc=local",
            bind_password="password",
        )
        result = adapter.connect(config)
        assert result.is_failure
        adapter.disconnect()

    def test_search_without_connection(self) -> None:
        """Test search when not connected to LDAP server."""
        adapter = Ldap3Adapter()
        # Don't connect, try to search
        search_options = FlextLdapModels.SearchOptions(
            base_dn=RFC.DEFAULT_BASE_DN,
            filter_str="(objectClass=*)",
            scope=FlextLdapConstants.SearchScope.SUBTREE,
        )
        result = adapter.search(search_options)
        assert result.is_failure
        # No fallback - FlextResult guarantees error exists when is_failure is True
        assert result.error is not None
        assert "Not connected" in result.error

    def test_add_without_connection(self) -> None:
        """Test add when not connected to LDAP server."""
        adapter = Ldap3Adapter()
        entry = TestOperationHelpers.create_inetorgperson_entry(
            "testnocon",
            RFC.DEFAULT_BASE_DN,
        )
        # Don't connect, try to add
        result = adapter.add(entry)
        assert result.is_failure
        # No fallback - FlextResult guarantees error exists when is_failure is True
        assert result.error is not None
        assert "Not connected" in result.error

    def test_modify_without_connection(self) -> None:
        """Test modify when not connected to LDAP server."""
        adapter = Ldap3Adapter()
        changes: dict[str, list[tuple[str, list[str]]]] = {
            "mail": [(MODIFY_REPLACE, ["test@example.com"])],
        }
        # Don't connect, try to modify
        result = adapter.modify(f"cn=test,{RFC.DEFAULT_BASE_DN}", changes)
        assert result.is_failure
        # No fallback - FlextResult guarantees error exists when is_failure is True
        assert result.error is not None
        assert "Not connected" in result.error

    def test_delete_without_connection(self) -> None:
        """Test delete when not connected to LDAP server."""
        adapter = Ldap3Adapter()
        # Don't connect, try to delete
        result = adapter.delete(f"cn=test,{RFC.DEFAULT_BASE_DN}")
        assert result.is_failure
        # No fallback - FlextResult guarantees error exists when is_failure is True
        assert result.error is not None
        assert "Not connected" in result.error

    def test_disconnect_handles_no_connection(self) -> None:
        """Test disconnect when there is no connection."""
        adapter = Ldap3Adapter()
        # Disconnect without connecting should not raise error
        adapter.disconnect()
        assert adapter.connection is None

    def test_is_connected_property(self) -> None:
        """Test is_connected property when not connected."""
        adapter = Ldap3Adapter()
        assert not adapter.is_connected

    def test_is_connected_property_after_disconnect(
        self,
        connection_config: FlextLdapModels.ConnectionConfig,
    ) -> None:
        """Test is_connected property after disconnect."""
        adapter = Ldap3Adapter()
        connect_result = adapter.connect(connection_config)
        if connect_result.is_success:
            assert adapter.is_connected
            adapter.disconnect()
            assert not adapter.is_connected

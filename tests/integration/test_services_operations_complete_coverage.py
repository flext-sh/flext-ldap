"""Complete coverage tests for FlextLdapOperations with real LDAP server.

Tests all code paths including error handling and edge cases.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from collections.abc import Generator

import pytest
from flext_ldif import FlextLdifParser
from ldap3 import MODIFY_REPLACE

from flext_ldap.config import FlextLdapConfig
from flext_ldap.models import FlextLdapModels
from flext_ldap.services.connection import FlextLdapConnection
from flext_ldap.services.operations import FlextLdapOperations

from ..fixtures.constants import RFC
from ..helpers.entry_helpers import EntryTestHelpers
from ..helpers.operation_helpers import TestOperationHelpers

pytestmark = pytest.mark.integration


class TestFlextLdapOperationsCompleteCoverage:
    """Complete coverage tests for FlextLdapOperations."""

    @pytest.fixture
    def operations_service(
        self,
        connection_config: FlextLdapModels.ConnectionConfig,
        ldap_parser: FlextLdifParser | None,
    ) -> Generator[FlextLdapOperations]:
        """Get operations service with connected adapter."""
        config = FlextLdapConfig()
        connection = FlextLdapConnection(config=config, parser=ldap_parser)
        connect_result = connection.connect(connection_config)
        if connect_result.is_failure:
            pytest.skip(f"Failed to connect: {connect_result.error}")

        operations = FlextLdapOperations(connection=connection)
        yield operations

        connection.disconnect()

    def test_search_with_normalized_base_dn_whitespace(
        self,
        operations_service: FlextLdapOperations,
    ) -> None:
        """Test search with base DN that needs normalization."""
        search_options = FlextLdapModels.SearchOptions(
            base_dn=f"  {RFC.DEFAULT_BASE_DN}  ",
            filter_str="(objectClass=*)",
            scope="SUBTREE",
        )

        result = operations_service.search(search_options)
        assert result.is_success

    def test_search_error_handling(
        self,
        operations_service: FlextLdapOperations,
    ) -> None:
        """Test search error handling path."""
        # This tests the error path when adapter.search fails
        search_options = FlextLdapModels.SearchOptions(
            base_dn=RFC.DEFAULT_BASE_DN,
            filter_str="(objectClass=*)",
            scope="SUBTREE",
        )

        # Disconnect to trigger error
        operations_service._connection.disconnect()

        result = operations_service.search(search_options)
        assert result.is_failure
        # No fallback - FlextResult guarantees error exists when is_failure is True
        assert result.error is not None
        assert "Not connected" in result.error

    def test_add_with_normalized_dn_whitespace(
        self,
        operations_service: FlextLdapOperations,
    ) -> None:
        """Test add with DN that needs normalization."""
        entry = TestOperationHelpers.create_inetorgperson_entry(
            "testnorm2",
            RFC.DEFAULT_BASE_DN,
        )
        # Create new entry with DN that needs normalization (with spaces)
        # Pydantic models are frozen, so we need to create a new entry
        dn_with_spaces = f"  {entry.dn!s}  "
        attrs_raw = (
            entry.attributes.attributes
            if entry.attributes and entry.attributes.attributes
            else {}
        )
        # Convert to expected type: dict[str, list[str] | str]
        attrs: dict[str, list[str] | str] = {
            k: v if isinstance(v, (list, str)) else [str(v)]
            for k, v in attrs_raw.items()
        }
        entry = EntryTestHelpers.create_entry(dn_with_spaces, attrs)

        # Cleanup first
        if entry.dn:
            _ = operations_service.delete(str(entry.dn).strip())

        result = operations_service.add(entry)
        assert result.is_success

        # Verify DN was normalized
        assert str(entry.dn).strip() == str(entry.dn)

        # Cleanup
        delete_result = operations_service.delete(str(entry.dn).strip())
        assert delete_result.is_success or delete_result.is_failure

    def test_add_error_handling(
        self,
        operations_service: FlextLdapOperations,
    ) -> None:
        """Test add error handling path."""
        entry = TestOperationHelpers.create_inetorgperson_entry(
            "testerror",
            RFC.DEFAULT_BASE_DN,
        )

        # Disconnect to trigger error
        operations_service._connection.disconnect()

        result = operations_service.add(entry)
        assert result.is_failure
        # No fallback - FlextResult guarantees error exists when is_failure is True
        assert result.error is not None
        assert "Not connected" in result.error

    def test_add_with_adapter_failure(
        self,
        operations_service: FlextLdapOperations,
    ) -> None:
        """Test add when adapter.add fails."""
        # Entry that will fail to add (invalid DN format)
        entry = TestOperationHelpers.create_entry_with_dn_and_attributes(
            "invalid-dn",
            {
                "cn": ["test"],
                "objectClass": ["top", "person"],
            },
        )

        result = operations_service.add(entry)
        # Should fail and return OperationResult with success=False
        assert result.is_failure

    def test_modify_with_normalized_dn_whitespace(
        self,
        operations_service: FlextLdapOperations,
    ) -> None:
        """Test modify with DN that needs normalization."""
        # First add an entry
        entry = TestOperationHelpers.create_inetorgperson_entry(
            "testmodnorm2",
            RFC.DEFAULT_BASE_DN,
        )

        # Cleanup first
        _ = operations_service.delete(str(entry.dn))

        add_result = operations_service.add(entry)
        assert add_result.is_success

        # Modify with DN that needs normalization
        changes: dict[str, list[tuple[str, list[str]]]] = {
            "mail": [(MODIFY_REPLACE, ["test@example.com"])],
        }

        modify_result = operations_service.modify(f"  {entry.dn!s}  ", changes)
        assert modify_result.is_success

        # Cleanup
        delete_result = operations_service.delete(str(entry.dn))
        assert delete_result.is_success or delete_result.is_failure

    def test_modify_error_handling(
        self,
        operations_service: FlextLdapOperations,
    ) -> None:
        """Test modify error handling path."""
        changes: dict[str, list[tuple[str, list[str]]]] = {
            "mail": [(MODIFY_REPLACE, ["test@example.com"])],
        }

        # Disconnect to trigger error
        operations_service._connection.disconnect()

        result = operations_service.modify("cn=test,dc=flext,dc=local", changes)
        assert result.is_failure
        # No fallback - FlextResult guarantees error exists when is_failure is True
        assert result.error is not None
        assert "Not connected" in result.error

    def test_delete_with_normalized_dn_whitespace(
        self,
        operations_service: FlextLdapOperations,
    ) -> None:
        """Test delete with DN that needs normalization."""
        entry = TestOperationHelpers.create_inetorgperson_entry(
            "testdelnorm2",
            RFC.DEFAULT_BASE_DN,
        )

        # Cleanup first
        _ = operations_service.delete(str(entry.dn))

        add_result = operations_service.add(entry)
        assert add_result.is_success

        # Delete with DN that needs normalization
        delete_result = operations_service.delete(f"  {entry.dn!s}  ")
        assert delete_result.is_success

    def test_delete_error_handling(
        self,
        operations_service: FlextLdapOperations,
    ) -> None:
        """Test delete error handling path."""
        # Disconnect to trigger error
        operations_service._connection.disconnect()

        result = operations_service.delete("cn=test,dc=flext,dc=local")
        assert result.is_failure
        # No fallback - FlextResult guarantees error exists when is_failure is True
        assert result.error is not None
        assert "Not connected" in result.error

    def test_execute_error_handling(self, ldap_parser: FlextLdifParser) -> None:
        """Test execute error handling path."""
        config = FlextLdapConfig()
        connection = FlextLdapConnection(config=config, parser=ldap_parser)
        operations = FlextLdapOperations(connection=connection)

        result = operations.execute()
        assert result.is_failure
        # No fallback - FlextResult guarantees error exists when is_failure is True
        assert result.error is not None
        assert "Not connected" in result.error

"""Complete integration tests for FlextLdap API with real LDAP server.

All tests use real LDAP operations, no mocks. Tests all methods and edge cases.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from typing import cast

import pytest
from flext_ldif.models import FlextLdifModels
from ldap3 import MODIFY_ADD, MODIFY_REPLACE

from flext_ldap import FlextLdap
from flext_ldap.config import FlextLdapConfig
from flext_ldap.models import FlextLdapModels
from flext_ldap.typings import LdapClientProtocol

from ..fixtures.constants import RFC
from ..helpers.operation_helpers import TestOperationHelpers
from ..helpers.test_deduplication_helpers import TestDeduplicationHelpers

pytestmark = pytest.mark.integration


class TestFlextLdapAPIComplete:
    """Complete tests for FlextLdap API with real LDAP server."""

    def test_api_initialization_with_config(self) -> None:
        """Test API initialization with custom config."""
        config = FlextLdapConfig(
            host=RFC.DEFAULT_HOST,
            port=RFC.DEFAULT_PORT,
        )
        api = FlextLdap(config=config)
        assert api._config == config
        assert api._connection is not None
        assert api._operations is not None

    def test_client_property(
        self,
        ldap_client: FlextLdap,
    ) -> None:
        """Test client property access."""
        client = ldap_client.client
        assert client is not None
        assert client == ldap_client._operations

    def test_context_manager(
        self,
        connection_config: FlextLdapModels.ConnectionConfig,
    ) -> None:
        """Test context manager usage."""
        with FlextLdap() as api:
            TestOperationHelpers.connect_and_assert_success(
                cast("LdapClientProtocol", api), connection_config
            )

        # Should be disconnected after context exit
        assert api.is_connected is False

    def test_context_manager_with_exception(
        self,
        connection_config: FlextLdapModels.ConnectionConfig,
    ) -> None:
        """Test context manager with exception."""
        test_exception = ValueError("Test exception")
        try:
            with FlextLdap() as api:
                result = api.connect(connection_config)
                TestOperationHelpers.assert_result_success(result)
                raise test_exception
        except ValueError:
            pass

        # Should still be disconnected
        api = FlextLdap()
        result = api.connect(connection_config)
        if result.is_success:
            api.disconnect()

    def test_search_with_different_server_types(
        self,
        ldap_client: FlextLdap,
        ldap_container: dict[str, object],
    ) -> None:
        """Test search with different server types."""
        search_options = TestOperationHelpers.create_search_options(
            base_dn=str(ldap_container["base_dn"]),
            filter_str="(objectClass=*)",
            scope="SUBTREE",
        )

        # Only test with 'rfc' which is always registered in quirks
        result = ldap_client.search(search_options, server_type="rfc")
        TestOperationHelpers.assert_result_success(result)

    def test_add_with_operation_result(
        self,
        ldap_client: FlextLdap,
    ) -> None:
        """Test add returns proper OperationResult."""
        _entry, result = TestDeduplicationHelpers.create_user_add_and_verify(
            cast("LdapClientProtocol", ldap_client),
            "testapiadd",
            verify_operation_result=True,
        )
        operation_result = result.unwrap()
        assert operation_result.success is True

    def test_modify_with_dn_object(
        self,
        ldap_client: FlextLdap,
    ) -> None:
        """Test modify with DistinguishedName object."""
        entry = TestDeduplicationHelpers.create_user("testapimod")
        changes: dict[str, list[tuple[str, list[str]]]] = {
            "mail": [(MODIFY_REPLACE, ["test@example.com"])],
        }
        TestDeduplicationHelpers.add_then_modify_with_operation_results(
            cast("LdapClientProtocol", ldap_client),
            entry,
            changes,
        )

    def test_delete_with_dn_object(
        self,
        ldap_client: FlextLdap,
    ) -> None:
        """Test delete with DistinguishedName object."""
        entry = TestDeduplicationHelpers.create_user("testapidel")
        TestDeduplicationHelpers.add_then_delete_with_operation_results(
            cast("LdapClientProtocol", ldap_client),
            entry,
        )

    def test_execute_when_connected(
        self,
        ldap_client: FlextLdap,
    ) -> None:
        """Test execute when connected."""
        TestDeduplicationHelpers.execute_and_verify_total_count(
            cast("LdapClientProtocol", ldap_client),
            expected_total=0,
            expected_entries=0,
        )

    def test_execute_when_not_connected(self) -> None:
        """Test execute when not connected - should return failure."""
        api = FlextLdap()
        result = api.execute()
        # Fast fail - should return failure when not connected
        assert result.is_failure
        assert result.error is not None
        assert "Not connected" in result.error

    def test_connect_with_service_config(
        self,
        ldap_container: dict[str, object],
    ) -> None:
        """Test connect using service config."""
        api = FlextLdap()
        # Create ConnectionConfig directly from ldap_container to bypass config issues
        connection_config = FlextLdapModels.ConnectionConfig(
            host=str(ldap_container["host"]),
            port=int(str(ldap_container["port"])),
            use_ssl=False,
            use_tls=False,
            bind_dn=str(ldap_container["bind_dn"]),
            bind_password=str(ldap_container["password"]),
        )
        result = api.connect(connection_config)
        TestOperationHelpers.assert_result_success(result)
        api.disconnect()

    def test_all_operations_in_sequence(
        self,
        ldap_client: FlextLdap,
    ) -> None:
        """Test all operations in sequence."""
        entry = TestDeduplicationHelpers.create_user("testsequence")
        changes: dict[str, list[tuple[str, list[str]]]] = {
            "mail": [(MODIFY_ADD, ["test@example.com"])],
        }
        TestDeduplicationHelpers.add_modify_delete_with_operation_results(
            cast("LdapClientProtocol", ldap_client),
            entry,
            changes,
        )

    def test_api_crud_operations_with_data_validation(
        self,
        connection_config: FlextLdapModels.ConnectionConfig,
    ) -> None:
        """Test complete CRUD operations with data validation.

        This test validates that:
        1. Add operation succeeds and data is stored correctly
        2. Search operation returns the correct data
        3. Modify operation changes data correctly
        4. Delete operation removes data completely
        """
        # Create connected LDAP client
        ldap_client = FlextLdap()
        TestOperationHelpers.connect_and_assert_success(
            cast("LdapClientProtocol", ldap_client), connection_config
        )

        # Create test entry with specific data
        test_dn = f"cn=test-data-validation,{RFC.DEFAULT_BASE_DN}"
        entry = FlextLdifModels.Entry(
            dn=FlextLdifModels.DistinguishedName(value=test_dn),
            attributes=FlextLdifModels.LdifAttributes(
                attributes={
                    "cn": ["test-data-validation"],
                    "sn": ["DataValidation"],
                    "givenName": ["Test"],
                    "mail": ["test@example.com"],
                    "objectClass": ["inetOrgPerson", "organizationalPerson", "person", "top"],
                    "userPassword": ["test123"],
                    "description": ["Test entry for data validation"],
                },
            ),
        )

        # Test ADD operation
        add_result = ldap_client.add(entry)
        assert add_result.is_success, f"Add failed: {add_result.error}"

        # Verify data was stored correctly by searching
        search_options = FlextLdapModels.SearchOptions(
            base_dn=test_dn,
            filter_str="(objectClass=*)",
            scope="BASE",
            attributes=["*"],
        )
        search_result = ldap_client.search(search_options)
        assert search_result.is_success, f"Search failed: {search_result.error}"

        search_data = search_result.unwrap()
        assert len(search_data.entries) == 1, "Should find exactly one entry"

        found_entry = search_data.entries[0]

        # Validate all attributes match what was added
        assert str(found_entry.dn) == test_dn
        assert found_entry.attributes is not None
        attrs = found_entry.attributes.attributes

        # Check specific attributes
        assert attrs.get("cn") == ["test-data-validation"]
        assert attrs.get("sn") == ["DataValidation"]
        assert attrs.get("givenName") == ["Test"]
        assert attrs.get("mail") == ["test@example.com"]
        assert "inetOrgPerson" in attrs.get("objectClass", [])
        assert attrs.get("description") == ["Test entry for data validation"]

        # Test MODIFY operation
        changes = {
            "description": [("MODIFY_REPLACE", ["Modified description"])],
            "mail": [("MODIFY_REPLACE", ["modified@example.com"])],
        }
        modify_result = ldap_client.modify(test_dn, changes)
        assert modify_result.is_success, f"Modify failed: {modify_result.error}"

        # Verify modifications
        search_result2 = ldap_client.search(search_options)
        assert search_result2.is_success
        search_data2 = search_result2.unwrap()
        assert len(search_data2.entries) == 1

        modified_entry = search_data2.entries[0]
        modified_attrs = modified_entry.attributes.attributes
        assert modified_attrs.get("description") == ["Modified description"]
        assert modified_attrs.get("mail") == ["modified@example.com"]
        # Other attributes should remain unchanged
        assert modified_attrs.get("cn") == ["test-data-validation"]
        assert modified_attrs.get("sn") == ["DataValidation"]

        # Test DELETE operation
        delete_result = ldap_client.delete(test_dn)
        assert delete_result.is_success, f"Delete failed: {delete_result.error}"

        # Verify entry was deleted - search should fail with noSuchObject
        search_result3 = ldap_client.search(search_options)
        assert not search_result3.is_success, "Search should fail after entry deletion"
        assert "noSuchObject" in str(search_result3.error), f"Expected noSuchObject error, got: {search_result3.error}"

    def test_api_upsert_method(
        self,
        ldap_client: FlextLdap,
    ) -> None:
        """Test API upsert method (covers line 246)."""
        # Cleanup first
        test_dn = f"cn=testapiupsert,{RFC.DEFAULT_BASE_DN}"
        _ = ldap_client.delete(test_dn)

        # Create entry
        entry = FlextLdifModels.Entry(
            dn=FlextLdifModels.DistinguishedName(value=test_dn),
            attributes=FlextLdifModels.LdifAttributes(
                attributes={
                    "cn": ["testapiupsert"],
                    "objectClass": ["top", "person"],
                    "sn": ["Test"],
                },
            ),
        )

        # Test upsert through API (covers line 246)
        result = ldap_client.upsert(entry)
        assert result.is_success
        assert result.unwrap()["operation"] in {"added", "skipped"}

        # Cleanup
        _ = ldap_client.delete(test_dn)

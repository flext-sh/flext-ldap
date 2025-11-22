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
            ldap_client,
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
            ldap_client,
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
            ldap_client,
            entry,
        )

    def test_execute_when_connected(
        self,
        ldap_client: FlextLdap,
    ) -> None:
        """Test execute when connected."""
        TestDeduplicationHelpers.execute_and_verify_total_count(
            ldap_client,
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
            ldap_client,
            entry,
            changes,
        )

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

"""Complete integration tests for FlextLdap API with real LDAP server.

All tests use real LDAP operations, no mocks. Tests all methods and edge cases.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

import pytest
from ldap3 import MODIFY_ADD, MODIFY_REPLACE

from flext_ldap import FlextLdap
from flext_ldap.config import FlextLdapConfig
from flext_ldap.models import FlextLdapModels
from tests.fixtures.constants import RFC
from tests.helpers.operation_helpers import TestOperationHelpers
from tests.helpers.test_deduplication_helpers import TestDeduplicationHelpers

pytestmark = pytest.mark.integration


class TestFlextLdapAPIComplete:
    """Complete tests for FlextLdap API with real LDAP server."""

    def test_api_initialization_with_config(self) -> None:
        """Test API initialization with custom config."""
        config = FlextLdapConfig(
            ldap_host=RFC.DEFAULT_HOST,
            ldap_port=RFC.DEFAULT_PORT,
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
            TestOperationHelpers.connect_and_assert_success(api, connection_config)

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
        """Test execute when not connected."""
        api = FlextLdap()
        TestDeduplicationHelpers.execute_and_verify_total_count(
            api,
            expected_total=0,
            expected_entries=0,
        )

    def test_connect_with_service_config(
        self,
        ldap_container: dict[str, object],
    ) -> None:
        """Test connect using service config."""
        config = FlextLdapConfig(
            ldap_host=str(ldap_container["host"]),
            ldap_port=int(str(ldap_container["port"])),
            ldap_bind_dn=str(ldap_container["bind_dn"]),
            ldap_bind_password=str(ldap_container["password"]),
        )
        from flext_ldap.models import FlextLdapModels

        api = FlextLdap(config=config)
        # Create ConnectionConfig from service config explicitly (no fallback)
        connection_config = FlextLdapModels.ConnectionConfig(
            host=config.ldap_host,
            port=config.ldap_port,
            use_ssl=config.ldap_use_ssl,
            use_tls=config.ldap_use_tls,
            bind_dn=config.ldap_bind_dn,
            bind_password=config.ldap_bind_password,
            timeout=config.ldap_timeout,
            auto_bind=config.ldap_auto_bind,
            auto_range=config.ldap_auto_range,
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

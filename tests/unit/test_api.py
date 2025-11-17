"""Unit tests for FlextLdap API.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT

"""

from __future__ import annotations

from flext_ldif.services.parser import FlextLdifParser
from ldap3 import MODIFY_REPLACE

from flext_ldap import FlextLdap
from flext_ldap.config import FlextLdapConfig
from flext_ldap.models import FlextLdapModels
from tests.helpers.test_deduplication_helpers import TestDeduplicationHelpers


class TestFlextLdapAPI:
    """Tests for FlextLdap main API facade."""

    def test_api_initialization(
        self,
        ldap_config: FlextLdapConfig,
        ldap_parser: FlextLdifParser,
    ) -> None:
        """Test API initialization."""
        api = FlextLdap(config=ldap_config, parser=ldap_parser)
        assert api is not None
        assert api._connection is not None
        assert api._operations is not None
        assert api._config is not None
        assert api.is_connected is False

    def test_api_initialization_with_config(self, ldap_parser: FlextLdifParser) -> None:
        """Test API initialization with custom config."""
        config = FlextLdapConfig(
            ldap_host="test.example.com",
            ldap_port=389,
        )
        api = FlextLdap(config=config, parser=ldap_parser)
        assert api._config == config

    def test_is_connected_property(
        self,
        ldap_config: FlextLdapConfig,
        ldap_parser: FlextLdifParser,
    ) -> None:
        """Test is_connected property."""
        api = FlextLdap(config=ldap_config, parser=ldap_parser)
        assert api.is_connected is False

    def test_search_when_not_connected(
        self,
        ldap_config: FlextLdapConfig,
        ldap_parser: FlextLdifParser,
    ) -> None:
        """Test search when not connected."""
        api = FlextLdap(config=ldap_config, parser=ldap_parser)
        # Use real helper to create search options
        search_options = TestDeduplicationHelpers.create_search(
            base_dn="dc=example,dc=com",
            filter_str="(objectClass=*)",
            scope="SUBTREE",
        )

        result = api.search(search_options)
        assert result.is_failure

    def test_add_when_not_connected(
        self,
        ldap_config: FlextLdapConfig,
        ldap_parser: FlextLdifParser,
    ) -> None:
        """Test add when not connected."""
        api = FlextLdap(config=ldap_config, parser=ldap_parser)
        # Use real helper to create entry
        entry = TestDeduplicationHelpers.create_entry(
            "cn=test,dc=example,dc=com",
            {"cn": ["test"], "objectClass": ["top", "person"]},
        )

        result = api.add(entry)
        assert result.is_failure

    def test_modify_when_not_connected(
        self,
        ldap_config: FlextLdapConfig,
        ldap_parser: FlextLdifParser,
    ) -> None:
        """Test modify when not connected."""
        api = FlextLdap(config=ldap_config, parser=ldap_parser)
        changes: dict[str, list[tuple[str, list[str]]]] = {
            "mail": [(MODIFY_REPLACE, ["test@example.com"])],
        }

        result = api.modify("cn=test,dc=example,dc=com", changes)
        assert result.is_failure

    def test_delete_when_not_connected(
        self,
        ldap_config: FlextLdapConfig,
        ldap_parser: FlextLdifParser,
    ) -> None:
        """Test delete when not connected."""
        api = FlextLdap(config=ldap_config, parser=ldap_parser)
        result = api.delete("cn=test,dc=example,dc=com")
        assert result.is_failure

    def test_disconnect_when_not_connected(
        self,
        ldap_config: FlextLdapConfig,
        ldap_parser: FlextLdifParser,
    ) -> None:
        """Test disconnect when not connected."""
        api = FlextLdap(config=ldap_config, parser=ldap_parser)
        # Should not raise exception
        api.disconnect()
        assert api.is_connected is False

    def test_execute_when_not_connected(
        self,
        ldap_config: FlextLdapConfig,
        ldap_parser: FlextLdifParser,
    ) -> None:
        """Test execute when not connected - fast-fail pattern."""
        api = FlextLdap(config=ldap_config, parser=ldap_parser)
        result = api.execute()
        # Fast-fail: execute() returns failure when not connected
        assert result.is_failure
        assert result.error is not None
        assert "Not connected" in result.error

    def test_connect_method(
        self,
        connection_config: FlextLdapModels.ConnectionConfig,
        ldap_config: FlextLdapConfig,
        ldap_parser: FlextLdifParser,
    ) -> None:
        """Test connect method (covers line 102)."""
        api = FlextLdap(config=ldap_config, parser=ldap_parser)
        result = api.connect(connection_config)

        # Should succeed
        assert result.is_success, f"Connect failed: {result.error}"
        assert api.is_connected is True

        # Cleanup
        api.disconnect()

    def test_client_property(
        self,
        ldap_config: FlextLdapConfig,
        ldap_parser: FlextLdifParser,
    ) -> None:
        """Test client property access (covers line 126)."""
        api = FlextLdap(config=ldap_config, parser=ldap_parser)
        client = api.client

        # Should return operations instance
        assert client is not None
        assert client == api._operations

    def test_context_manager_enter(
        self,
        ldap_config: FlextLdapConfig,
        ldap_parser: FlextLdifParser,
    ) -> None:
        """Test context manager __enter__ (covers line 135)."""
        api = FlextLdap(config=ldap_config, parser=ldap_parser)
        # Use with statement to test __enter__ (covers line 135)
        with api as entered:
            # Should return self
            assert entered is api

    def test_context_manager_exit(
        self,
        connection_config: FlextLdapModels.ConnectionConfig,
        ldap_config: FlextLdapConfig,
        ldap_parser: FlextLdifParser,
    ) -> None:
        """Test context manager __exit__ (covers line 153)."""
        api = FlextLdap(config=ldap_config, parser=ldap_parser)
        api.connect(connection_config)

        # Exit should disconnect
        api.__exit__(None, None, None)

        # Should be disconnected
        assert api.is_connected is False

    def test_context_manager_with_statement(
        self,
        connection_config: FlextLdapModels.ConnectionConfig,
        ldap_config: FlextLdapConfig,
        ldap_parser: FlextLdifParser,
    ) -> None:
        """Test context manager with statement."""
        with FlextLdap(config=ldap_config, parser=ldap_parser) as api:
            connect_result = api.connect(connection_config)
            if connect_result.is_success:
                assert api.is_connected is True

        # Should be disconnected after exiting context
        assert api.is_connected is False

    def test_execute_when_operations_fails(
        self,
        ldap_config: FlextLdapConfig,
        ldap_parser: FlextLdifParser,
    ) -> None:
        """Test execute when operations.execute() fails - fast-fail pattern.

        Uses real operations service that is not connected to trigger failure.
        """
        api = FlextLdap(config=ldap_config, parser=ldap_parser)

        # Operations service is not connected, so execute() will fail
        # Fast-fail: returns failure, not empty success
        result = api.execute()

        # Fast-fail: should return failure when not connected
        assert result.is_failure
        assert result.error is not None
        assert "Not connected" in result.error

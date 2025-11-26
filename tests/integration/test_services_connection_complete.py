"""Complete integration tests for FlextLdapConnection with real LDAP server.

All tests use real LDAP operations, no mocks. Tests all methods and edge cases.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from typing import cast

import pytest
from flext_ldif import FlextLdifParser

from flext_ldap.config import FlextLdapConfig
from flext_ldap.models import FlextLdapModels
from flext_ldap.services.connection import FlextLdapConnection
from flext_ldap.typings import LdapClientProtocol

from ..fixtures.constants import RFC
from ..helpers.operation_helpers import TestOperationHelpers

pytestmark = pytest.mark.integration


class TestFlextLdapConnectionComplete:
    """Complete tests for FlextLdapConnection with real LDAP server."""

    def test_connection_initialization_with_config(
        self,
        ldap_parser: FlextLdifParser,
    ) -> None:
        """Test connection initialization with custom config."""
        config = FlextLdapConfig(
            host=RFC.DEFAULT_HOST,
            port=RFC.DEFAULT_PORT,
        )
        connection = FlextLdapConnection(config=config, parser=ldap_parser)
        assert connection._config == config
        assert connection._adapter is not None

    def test_connection_initialization_with_parser(
        self,
        ldap_parser: FlextLdifParser,
    ) -> None:
        """Test connection initialization with custom parser."""
        config = FlextLdapConfig()
        connection = FlextLdapConnection(config=config, parser=ldap_parser)
        assert connection._adapter._parser == ldap_parser

    def test_connect_with_service_config(
        self,
        ldap_container: dict[str, object],
        ldap_parser: FlextLdifParser,
    ) -> None:
        """Test connect using service config."""
        config = FlextLdapConfig(
            host=str(ldap_container["host"]),
            port=int(str(ldap_container["port"])),
            bind_dn=str(ldap_container["bind_dn"]),
            bind_password=str(ldap_container["password"]),
        )
        connection = FlextLdapConnection(config=config, parser=ldap_parser)
        connection_config = FlextLdapModels.ConnectionConfig(
            host=str(ldap_container["host"]),
            port=int(str(ldap_container["port"])),
            bind_dn=str(ldap_container["bind_dn"]),
            bind_password=str(ldap_container["password"]),
        )
        result = connection.connect(connection_config)
        assert result.is_success
        connection.disconnect()

    def test_connect_with_connection_config(
        self,
        connection_config: FlextLdapModels.ConnectionConfig,
        ldap_parser: FlextLdifParser,
    ) -> None:
        """Test connect with explicit connection config."""
        config = FlextLdapConfig()
        connection = FlextLdapConnection(config=config, parser=ldap_parser)
        result = connection.connect(connection_config)
        assert result.is_success
        connection.disconnect()

    def test_connect_with_all_config_options(
        self,
        ldap_container: dict[str, object],
        ldap_parser: FlextLdifParser,
    ) -> None:
        """Test connect with all config options."""
        ldap_config = FlextLdapConfig()
        connection = FlextLdapConnection(config=ldap_config, parser=ldap_parser)
        connection_config = FlextLdapModels.ConnectionConfig(
            host=str(ldap_container["host"]),
            port=int(str(ldap_container["port"])),
            use_ssl=False,
            use_tls=False,
            bind_dn=str(ldap_container["bind_dn"]),
            bind_password=str(ldap_container["password"]),
            timeout=30,
            auto_bind=True,
            auto_range=True,
        )
        result = connection.connect(connection_config)
        assert result.is_success
        connection.disconnect()

    def test_disconnect_multiple_times(self, ldap_parser: FlextLdifParser) -> None:
        """Test disconnect can be called multiple times."""
        config = FlextLdapConfig()
        connection = FlextLdapConnection(config=config, parser=ldap_parser)
        connection.disconnect()
        connection.disconnect()  # Should not raise exception
        assert connection.is_connected is False

    def test_is_connected_property(
        self,
        connection_config: FlextLdapModels.ConnectionConfig,
        ldap_parser: FlextLdifParser,
    ) -> None:
        """Test is_connected property."""
        config = FlextLdapConfig()
        connection = FlextLdapConnection(config=config, parser=ldap_parser)
        assert connection.is_connected is False

        TestOperationHelpers.connect_and_assert_success(
            cast("LdapClientProtocol", connection), connection_config
        )

        connection.disconnect()
        assert connection.is_connected is False

    def test_adapter_property(
        self,
        connection_config: FlextLdapModels.ConnectionConfig,
        ldap_parser: FlextLdifParser,
    ) -> None:
        """Test adapter property access."""
        config = FlextLdapConfig()
        connection = FlextLdapConnection(config=config, parser=ldap_parser)
        adapter = connection.adapter
        assert adapter is not None

        result = connection.connect(connection_config)
        assert result.is_success
        assert connection.adapter.is_connected is True

        connection.disconnect()

    def test_execute_when_connected(
        self,
        connection_config: FlextLdapModels.ConnectionConfig,
        ldap_parser: FlextLdifParser,
    ) -> None:
        """Test execute when connected."""
        config = FlextLdapConfig()
        connection = FlextLdapConnection(config=config, parser=ldap_parser)
        connect_result = connection.connect(connection_config)
        assert connect_result.is_success

        result = TestOperationHelpers.execute_and_assert_success(
            cast("LdapClientProtocol", connection)
        )
        assert result is True

        connection.disconnect()

    def test_execute_when_not_connected(self, ldap_parser: FlextLdifParser) -> None:
        """Test execute when not connected."""
        config = FlextLdapConfig()
        connection = FlextLdapConnection(config=config, parser=ldap_parser)
        result = connection.execute()
        TestOperationHelpers.assert_result_failure(
            result,
            expected_error="Not connected",
        )

    def test_connect_failure_handling(self, ldap_parser: FlextLdifParser) -> None:
        """Test connection failure handling."""
        ldap_config = FlextLdapConfig()
        connection = FlextLdapConnection(config=ldap_config, parser=ldap_parser)
        connection_config = FlextLdapModels.ConnectionConfig(
            host="192.0.2.1",  # TEST-NET-1 reserved IP (instant fail, no DNS lookup)
            port=389,
            use_ssl=False,
            bind_dn="cn=admin,dc=test,dc=local",
            bind_password="password",
            timeout=2,  # Fast timeout for invalid host test
        )
        result = connection.connect(connection_config)
        assert result.is_failure
        assert connection.is_connected is False

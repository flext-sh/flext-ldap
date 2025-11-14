"""Complete integration tests for FlextLdapConnection with real LDAP server.

All tests use real LDAP operations, no mocks. Tests all methods and edge cases.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

import pytest
from flext_ldif.services.parser import FlextLdifParser

from flext_ldap.config import FlextLdapConfig
from flext_ldap.models import FlextLdapModels
from flext_ldap.services.connection import FlextLdapConnection
from tests.fixtures.constants import RFC

pytestmark = pytest.mark.integration


class TestFlextLdapConnectionComplete:
    """Complete tests for FlextLdapConnection with real LDAP server."""

    def test_connection_initialization_with_config(self) -> None:
        """Test connection initialization with custom config."""
        config = FlextLdapConfig(
            ldap_host=RFC.DEFAULT_HOST,
            ldap_port=RFC.DEFAULT_PORT,
        )
        connection = FlextLdapConnection(config=config)
        assert connection._config == config
        assert connection._adapter is not None

    def test_connection_initialization_with_parser(self) -> None:
        """Test connection initialization with custom parser."""
        parser = FlextLdifParser()
        connection = FlextLdapConnection(parser=parser)
        assert connection._adapter._parser == parser

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
        connection = FlextLdapConnection(config=config)
        result = connection.connect(None)  # Use service config
        assert result.is_success
        connection.disconnect()

    def test_connect_with_connection_config(
        self,
        connection_config: FlextLdapModels.ConnectionConfig,
    ) -> None:
        """Test connect with explicit connection config."""
        connection = FlextLdapConnection()
        result = connection.connect(connection_config)
        assert result.is_success
        connection.disconnect()

    def test_connect_with_all_config_options(
        self,
        ldap_container: dict[str, object],
    ) -> None:
        """Test connect with all config options."""
        connection = FlextLdapConnection()
        config = FlextLdapModels.ConnectionConfig(
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
        result = connection.connect(config)
        assert result.is_success
        connection.disconnect()

    def test_disconnect_multiple_times(self) -> None:
        """Test disconnect can be called multiple times."""
        connection = FlextLdapConnection()
        connection.disconnect()
        connection.disconnect()  # Should not raise exception
        assert connection.is_connected is False

    def test_is_connected_property(
        self,
        connection_config: FlextLdapModels.ConnectionConfig,
    ) -> None:
        """Test is_connected property."""
        connection = FlextLdapConnection()
        assert connection.is_connected is False

        result = connection.connect(connection_config)
        assert result.is_success
        assert connection.is_connected is True

        connection.disconnect()
        assert connection.is_connected is False

    def test_adapter_property(
        self,
        connection_config: FlextLdapModels.ConnectionConfig,
    ) -> None:
        """Test adapter property access."""
        connection = FlextLdapConnection()
        adapter = connection.adapter
        assert adapter is not None

        result = connection.connect(connection_config)
        assert result.is_success
        assert connection.adapter.is_connected is True

        connection.disconnect()

    def test_execute_when_connected(
        self,
        connection_config: FlextLdapModels.ConnectionConfig,
    ) -> None:
        """Test execute when connected."""
        connection = FlextLdapConnection()
        connect_result = connection.connect(connection_config)
        assert connect_result.is_success

        result = connection.execute()
        assert result.is_success
        assert result.unwrap() is True

        connection.disconnect()

    def test_execute_when_not_connected(self) -> None:
        """Test execute when not connected."""
        connection = FlextLdapConnection()
        result = connection.execute()
        assert result.is_failure
        assert "Not connected" in (result.error or "")

    def test_connect_failure_handling(self) -> None:
        """Test connection failure handling."""
        connection = FlextLdapConnection()
        config = FlextLdapModels.ConnectionConfig(
            host="invalid-host-that-does-not-exist",
            port=389,
            use_ssl=False,
            bind_dn="cn=admin,dc=test,dc=local",
            bind_password="password",
        )
        result = connection.connect(config)
        assert result.is_failure
        assert connection.is_connected is False

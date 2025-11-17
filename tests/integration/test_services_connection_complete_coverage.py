"""Complete coverage tests for FlextLdapConnection with real LDAP server.

Tests all code paths including error handling and edge cases.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

import pytest
from flext_ldif.services.parser import FlextLdifParser

from flext_ldap.config import FlextLdapConfig
from flext_ldap.models import FlextLdapModels
from flext_ldap.services.connection import FlextLdapConnection

pytestmark = pytest.mark.integration


class TestFlextLdapConnectionCompleteCoverage:
    """Complete coverage tests for FlextLdapConnection."""

    def test_connect_with_service_config_all_options(
        self,
        ldap_container: dict[str, object],
    ) -> None:
        """Test connect using service config with all options."""
        config = FlextLdapConfig(
            ldap_host=str(ldap_container["host"]),
            ldap_port=int(str(ldap_container["port"])),
            ldap_use_ssl=False,
            ldap_use_tls=False,
            ldap_bind_dn=str(ldap_container["bind_dn"]),
            ldap_bind_password=str(ldap_container["password"]),
            ldap_timeout=30,
            ldap_auto_bind=True,
            ldap_auto_range=True,
        )
        from flext_ldap.models import FlextLdapModels

        connection = FlextLdapConnection(config=config)
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
        result = connection.connect(connection_config)
        assert result.is_success
        connection.disconnect()

    def test_connect_with_connection_config_overrides(
        self,
        ldap_container: dict[str, object],
    ) -> None:
        """Test connect with connection config overriding service config."""
        service_config = FlextLdapConfig(
            ldap_host="wrong-host",
            ldap_port=9999,
        )
        connection = FlextLdapConnection(config=service_config)

        connection_config = FlextLdapModels.ConnectionConfig(
            host=str(ldap_container["host"]),
            port=int(str(ldap_container["port"])),
            use_ssl=False,
            bind_dn=str(ldap_container["bind_dn"]),
            bind_password=str(ldap_container["password"]),
        )

        result = connection.connect(connection_config)
        assert result.is_success
        connection.disconnect()

    def test_connection_with_parser_reuse(
        self,
        connection_config: FlextLdapModels.ConnectionConfig,
    ) -> None:
        """Test connection reuses parser instance."""
        parser = FlextLdifParser()
        connection1 = FlextLdapConnection(parser=parser)
        connection2 = FlextLdapConnection(parser=parser)

        # Both should use same parser instance
        assert connection1._adapter._parser == parser
        assert connection2._adapter._parser == parser

        # Connect and disconnect
        result1 = connection1.connect(connection_config)
        if result1.is_success:
            connection1.disconnect()

        result2 = connection2.connect(connection_config)
        if result2.is_success:
            connection2.disconnect()

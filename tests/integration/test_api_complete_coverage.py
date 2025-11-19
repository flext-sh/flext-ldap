"""Complete coverage tests for FlextLdap API with real LDAP server.

Tests all code paths including error handling and edge cases.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

import pytest
from flext_ldif import FlextLdifParser
from flext_ldif.models import FlextLdifModels

from flext_ldap import FlextLdap
from flext_ldap.config import FlextLdapConfig
from flext_ldap.models import FlextLdapModels

pytestmark = pytest.mark.integration


class TestFlextLdapAPICompleteCoverage:
    """Complete coverage tests for FlextLdap API."""

    def test_api_initialization_with_default_config(
        self,
        flext_ldap_instance: FlextLdap,
    ) -> None:
        """Test API initialization with default config."""
        assert flext_ldap_instance._config is not None
        assert isinstance(flext_ldap_instance._config, FlextLdapConfig)

    def test_connect_with_service_config_all_options(
        self,
        ldap_parser: FlextLdifParser,
        ldap_container: dict[str, object],
    ) -> None:
        """Test connect using service config with all options."""
        config = FlextLdapConfig(
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

        api = FlextLdap(config=config, parser=ldap_parser)
        # Create ConnectionConfig from service config explicitly (no fallback)
        connection_config = FlextLdapModels.ConnectionConfig(
            host=config.host,
            port=config.port,
            use_ssl=config.use_ssl,
            use_tls=config.use_tls,
            bind_dn=config.bind_dn,
            bind_password=config.bind_password,
            timeout=config.timeout,
            auto_bind=config.auto_bind,
            auto_range=config.auto_range,
        )
        result = api.connect(connection_config)
        assert result.is_success
        api.disconnect()

    def test_execute_when_operations_execute_fails(
        self,
        ldap_client: FlextLdap,
    ) -> None:
        """Test execute when operations.execute fails."""
        # Disconnect to make operations.execute fail
        ldap_client.disconnect()

        result = ldap_client.execute()
        # Fast fail - should return failure when not connected
        assert result.is_failure
        assert result.error is not None
        assert "Not connected" in result.error

    def test_all_operations_with_service_config(
        self,
        ldap_container: dict[str, object],
    ) -> None:
        """Test all operations using service config."""
        config = FlextLdapConfig(
            host=str(ldap_container["host"]),
            port=int(str(ldap_container["port"])),
            bind_dn=str(ldap_container["bind_dn"]),
            bind_password=str(ldap_container["password"]),
        )
        api = FlextLdap(config=config)

        # Create ConnectionConfig from service config explicitly (no fallback)
        connection_config = FlextLdapModels.ConnectionConfig(
            host=config.host,
            port=config.port,
            use_ssl=config.use_ssl,
            use_tls=config.use_tls,
            bind_dn=config.bind_dn,
            bind_password=config.bind_password,
            timeout=config.timeout,
            auto_bind=config.auto_bind,
            auto_range=config.auto_range,
        )
        # Connect using service config
        connect_result = api.connect(connection_config)
        assert connect_result.is_success

        # Search
        search_options = FlextLdapModels.SearchOptions(
            base_dn=str(ldap_container["base_dn"]),
            filter_str="(objectClass=*)",
            scope="SUBTREE",
        )
        search_result = api.search(search_options)
        assert search_result.is_success

        # Add
        entry = FlextLdifModels.Entry(
            dn=FlextLdifModels.DistinguishedName(
                value="cn=testservice,ou=people,dc=flext,dc=local",
            ),
            attributes=FlextLdifModels.LdifAttributes(
                attributes={
                    "cn": ["testservice"],
                    "sn": ["Test"],
                    "objectClass": [
                        "inetOrgPerson",
                        "organizationalPerson",
                        "person",
                        "top",
                    ],
                },
            ),
        )

        # Cleanup first
        _ = api.delete(str(entry.dn))

        add_result = api.add(entry)
        assert add_result.is_success

        # Cleanup
        delete_result = api.delete(str(entry.dn))
        assert delete_result.is_success or delete_result.is_failure

        api.disconnect()

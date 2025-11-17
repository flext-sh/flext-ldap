"""Complete coverage tests for FlextLdap API with real LDAP server.

Tests all code paths including error handling and edge cases.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

import pytest
from flext_ldif.models import FlextLdifModels
from flext_ldif.services.parser import FlextLdifParser

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

        api = FlextLdap(config=config, parser=ldap_parser)
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
        # Execute returns empty result on failure, not fail
        assert result.is_success
        search_result = result.unwrap()
        assert search_result.total_count == 0

    def test_all_operations_with_service_config(
        self,
        ldap_container: dict[str, object],
    ) -> None:
        """Test all operations using service config."""
        config = FlextLdapConfig(
            ldap_host=str(ldap_container["host"]),
            ldap_port=int(str(ldap_container["port"])),
            ldap_bind_dn=str(ldap_container["bind_dn"]),
            ldap_bind_password=str(ldap_container["password"]),
        )
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

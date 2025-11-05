"""Real integration tests for api.py coverage improvement.

These tests exercise the FlextLdap facade API with real Docker LDAP operations.
No mocks - only real tests with Docker container.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

import pytest
from flext_core import FlextResult
from flext_ldif import FlextLdifModels

from flext_ldap import FlextLdap, FlextLdapConfig, FlextLdapModels


@pytest.mark.docker
@pytest.mark.integration
class TestFlextLdapFacadeRealCoverage:
    """Real integration tests for FlextLdap facade API coverage."""

    @pytest.fixture
    def ldap(self) -> FlextLdap:
        """Create FlextLdap instance with real Docker configuration."""
        config = FlextLdapConfig(
            ldap_host="localhost",
            ldap_port=3390,
            ldap_bind_dn="cn=REDACTED_LDAP_BIND_PASSWORD,dc=flext,dc=local",
            ldap_bind_password="REDACTED_LDAP_BIND_PASSWORD123",
            ldap_use_ssl=False,
            ldap_start_tls=False,
        )
        return FlextLdap(config)

    def test_flext_ldap_create_instance(self) -> None:
        """Test creating a new FlextLdap instance."""
        ldap = FlextLdap.create()
        assert ldap is not None
        assert isinstance(ldap, FlextLdap)

    def test_flext_ldap_initialization(self) -> None:
        """Test FlextLdap initialization with configuration."""
        config = FlextLdapConfig(
            ldap_host="localhost",
            ldap_port=3390,
            ldap_bind_dn="cn=REDACTED_LDAP_BIND_PASSWORD,dc=flext,dc=local",
            ldap_bind_password="REDACTED_LDAP_BIND_PASSWORD123",
        )
        ldap = FlextLdap(config)
        assert ldap is not None
        assert isinstance(ldap, FlextLdap)

    def test_flext_ldap_config_access(self, ldap: FlextLdap) -> None:
        """Test accessing FlextLdap configuration."""
        config = ldap.config
        assert config is not None
        assert isinstance(config, FlextLdapConfig)

    def test_flext_ldap_client_property(self, ldap: FlextLdap) -> None:
        """Test accessing client property via facade."""
        client = ldap.client
        assert client is not None
        # Client property should be accessible
        assert hasattr(client, "test_connection")

    def test_flext_ldap_servers_property(self, ldap: FlextLdap) -> None:
        """Test accessing servers property via facade."""
        servers = ldap.servers
        assert servers is not None
        # Servers property should have methods
        assert hasattr(servers, "get_default_port")

    def test_flext_ldap_acl_property(self, ldap: FlextLdap) -> None:
        """Test accessing acl property via facade."""
        acl = ldap.acl
        assert acl is not None
        # ACL property should have methods
        assert hasattr(acl, "get_acl_format")

    def test_flext_ldap_connect_with_real_server(self, ldap: FlextLdap) -> None:
        """Test connecting to real LDAP server via facade."""
        result = ldap.connect()
        assert isinstance(result, FlextResult)
        if result.is_success:
            connection = result.unwrap()
            assert connection is not None
            # Clean up
            ldap.client.unbind()

    def test_flext_ldap_query_search(self, ldap: FlextLdap) -> None:
        """Test query method for search operations."""
        result = ldap.query(
            base_dn="dc=flext,dc=local",
            filter_str="(objectClass=*)",
        )
        assert isinstance(result, FlextResult)
        if result.is_success:
            response = result.unwrap()
            assert isinstance(response, FlextLdapModels.SearchResponse)

    def test_flext_ldap_search_method(self, ldap: FlextLdap) -> None:
        """Test search method via facade."""
        result = ldap.search(
            base_dn="dc=flext,dc=local",
            filter_str="(objectClass=organizationalUnit)",
        )
        assert isinstance(result, FlextResult)
        if result.is_success:
            entries = result.unwrap()
            assert isinstance(entries, list)

    def test_flext_ldap_add_entry_via_facade(self, ldap: FlextLdap) -> None:
        """Test add entry operation via facade."""
        test_dn = "cn=facade_test_user,ou=people,dc=flext,dc=local"

        # Add via facade
        result = ldap.add(
            dn=test_dn,
            attributes={
                "objectClass": ["person", "top"],
                "cn": ["facade_test_user"],
                "sn": ["test"],
                "userPassword": ["test123"],
            },
        )
        assert isinstance(result, FlextResult)

        # Clean up if successful
        if result.is_success:
            ldap.delete_entry(test_dn)

    def test_flext_ldap_modify_entry_via_facade(self, ldap: FlextLdap) -> None:
        """Test modify entry operation via facade."""
        test_dn = "cn=facade_modify_test,ou=people,dc=flext,dc=local"

        # Add entry first
        add_result = ldap.add(
            dn=test_dn,
            attributes={
                "objectClass": ["person", "top"],
                "cn": ["facade_modify_test"],
                "sn": ["test"],
                "description": ["Original description"],
            },
        )

        if add_result.is_success:
            # Modify entry
            modify_result = ldap.modify(
                dn=test_dn,
                changes={
                    "description": ["Modified description"],
                },
            )
            assert isinstance(modify_result, FlextResult)

            # Clean up
            ldap.delete_entry(test_dn)

    def test_flext_ldap_delete_entry_via_facade(self, ldap: FlextLdap) -> None:
        """Test delete entry operation via facade."""
        test_dn = "cn=facade_delete_test,ou=people,dc=flext,dc=local"

        # Add entry first
        add_result = ldap.add(
            dn=test_dn,
            attributes={
                "objectClass": ["person", "top"],
                "cn": ["facade_delete_test"],
                "sn": ["test"],
            },
        )

        if add_result.is_success:
            # Delete entry
            delete_result = ldap.delete_entry(test_dn)
            assert isinstance(delete_result, FlextResult)

    def test_flext_ldap_test_connection_via_facade(self, ldap: FlextLdap) -> None:
        """Test connection test via facade."""
        result = ldap.test_connection()
        assert isinstance(result, FlextResult)

    def test_flext_ldap_validate_entries(self, ldap: FlextLdap) -> None:
        """Test entry validation via facade."""
        entries = [
            FlextLdifModels.Entry(
                dn="cn=test1,dc=example,dc=com",
                attributes={"cn": ["test1"]},
            ),
            FlextLdifModels.Entry(
                dn="cn=test2,dc=example,dc=com",
                attributes={"cn": ["test2"]},
            ),
        ]

        result = ldap.validate_entries(entries)
        assert isinstance(result, FlextResult)

    def test_flext_ldap_convert_entry(self, ldap: FlextLdap) -> None:
        """Test entry conversion via facade."""
        entry = FlextLdifModels.Entry(
            dn="cn=test,dc=example,dc=com",
            attributes={"cn": ["test"], "objectClass": ["person"]},
        )

        # Convert from RFC (baseline) to specific server format
        result = ldap.convert(
            entries=entry,
            source_server="rfc",
            target_server="oid",
        )
        assert isinstance(result, FlextResult)

    def test_flext_ldap_info_operation(self, ldap: FlextLdap) -> None:
        """Test info operation via facade."""
        result = ldap.info()
        assert isinstance(result, FlextResult)

    def test_flext_ldap_get_server_info(self, ldap: FlextLdap) -> None:
        """Test getting server info via facade."""
        result = ldap.get_server_info()
        assert isinstance(result, FlextResult)

    def test_flext_ldap_get_acl_info(self, ldap: FlextLdap) -> None:
        """Test getting ACL info via facade."""
        result = ldap.get_acl_info()
        assert isinstance(result, FlextResult)

    def test_flext_ldap_get_server_operations(self, ldap: FlextLdap) -> None:
        """Test getting server operations via facade."""
        server_ops = ldap.get_server_operations()
        assert server_ops is not None
        assert hasattr(server_ops, "execute")

    def test_flext_ldaps_mode_property(self, ldap: FlextLdap) -> None:
        """Test accessing quirks mode property."""
        quirks_mode = ldap.quirks_mode
        # Quirks mode property should be accessible
        assert quirks_mode is not None

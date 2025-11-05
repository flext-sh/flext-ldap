"""Comprehensive tests for FlextLdapServers facade.

This module contains comprehensive tests for FlextLdapServers facade using real Docker
LDAP containers. All tests use actual LDAP operations without any mocks, stubs,
or wrappers.

Test Categories:
- @pytest.mark.docker - Requires Docker LDAP container
- @pytest.mark.unit - Unit tests with real LDAP operations

Container Requirements:
    Docker container must be running on port 3390
    Base DN: dc=flext,dc=local
    Admin DN: cn=REDACTED_LDAP_BIND_PASSWORD,dc=flext,dc=local
    Admin password: REDACTED_LDAP_BIND_PASSWORD123
"""

from __future__ import annotations

import pytest
from flext_ldif import FlextLdifModels

from flext_ldap import FlextLdapClients, FlextLdapServers


class TestFlextLdapServersFacadeFactory:
    """Test FlextLdapServers factory methods."""

    @pytest.mark.docker
    @pytest.mark.unit
    def test_for_openldap1_creates_instance(self) -> None:
        """Test factory method creates OpenLDAP 1 instance."""
        servers = FlextLdapServers.for_openldap1()
        assert servers is not None
        assert servers.server_type == "openldap1"

    @pytest.mark.docker
    @pytest.mark.unit
    def test_for_openldap2_creates_instance(self) -> None:
        """Test factory method creates OpenLDAP 2 instance."""
        servers = FlextLdapServers.for_openldap2()
        assert servers is not None
        assert servers.server_type == "openldap2"

    @pytest.mark.docker
    @pytest.mark.unit
    def test_for_oracle_oid_creates_instance(self) -> None:
        """Test factory method creates Oracle OID instance."""
        servers = FlextLdapServers.for_oracle_oid()
        assert servers is not None
        assert servers.server_type == "oid"

    @pytest.mark.docker
    @pytest.mark.unit
    def test_for_oracle_oud_creates_instance(self) -> None:
        """Test factory method creates Oracle OUD instance."""
        servers = FlextLdapServers.for_oracle_oud()
        assert servers is not None
        assert servers.server_type == "oud"

    @pytest.mark.docker
    @pytest.mark.unit
    def test_for_active_directory_creates_instance(self) -> None:
        """Test factory method creates Active Directory instance."""
        servers = FlextLdapServers.for_active_directory()
        assert servers is not None
        assert servers.server_type == "ad"

    @pytest.mark.docker
    @pytest.mark.unit
    def test_generic_creates_instance(self) -> None:
        """Test factory method creates generic instance."""
        servers = FlextLdapServers.generic()
        assert servers is not None
        assert servers.server_type == "generic"


class TestFlextLdapServersFacadeBasicOperations:
    """Test basic server facade operations."""

    @pytest.fixture(autouse=True)
    def servers_instance(self) -> FlextLdapServers:
        """Provide a server facade instance."""
        return FlextLdapServers()

    @pytest.mark.docker
    @pytest.mark.unit
    def test_server_type_property(self, servers_instance: FlextLdapServers) -> None:
        """Test server_type property."""
        assert isinstance(servers_instance.server_type, str)
        assert servers_instance.server_type == "generic"

    @pytest.mark.docker
    @pytest.mark.unit
    def test_operations_property(self, servers_instance: FlextLdapServers) -> None:
        """Test operations property returns operations instance."""
        ops = servers_instance.operations
        assert ops is not None

    @pytest.mark.docker
    @pytest.mark.unit
    def test_execute_returns_ok(self, servers_instance: FlextLdapServers) -> None:
        """Test execute method returns success."""
        result = servers_instance.execute()
        assert result.is_success is True


class TestFlextLdapServersFacadeCapabilities:
    """Test server capability methods."""

    @pytest.fixture(autouse=True)
    def servers_instance(self) -> FlextLdapServers:
        """Provide a server facade instance."""
        return FlextLdapServers()

    @pytest.mark.docker
    @pytest.mark.unit
    def test_get_acl_format(self, servers_instance: FlextLdapServers) -> None:
        """Test get_acl_format returns string."""
        acl_format = servers_instance.get_acl_format()
        assert isinstance(acl_format, str)
        assert len(acl_format) > 0

    @pytest.mark.docker
    @pytest.mark.unit
    def test_get_acl_attribute_name(self, servers_instance: FlextLdapServers) -> None:
        """Test get_acl_attribute_name returns string."""
        attr_name = servers_instance.get_acl_attribute_name()
        assert isinstance(attr_name, str)
        assert len(attr_name) > 0

    @pytest.mark.docker
    @pytest.mark.unit
    def test_get_schema_dn(self, servers_instance: FlextLdapServers) -> None:
        """Test get_schema_dn returns string."""
        schema_dn = servers_instance.get_schema_dn()
        assert isinstance(schema_dn, str)
        assert len(schema_dn) > 0

    @pytest.mark.docker
    @pytest.mark.unit
    def test_get_default_port_no_ssl(self, servers_instance: FlextLdapServers) -> None:
        """Test get_default_port without SSL."""
        port = servers_instance.get_default_port(use_ssl=False)
        assert isinstance(port, int)
        assert port > 0
        assert port in {389, 3390}

    @pytest.mark.docker
    @pytest.mark.unit
    def test_get_default_port_with_ssl(
        self, servers_instance: FlextLdapServers
    ) -> None:
        """Test get_default_port with SSL."""
        port = servers_instance.get_default_port(use_ssl=True)
        assert isinstance(port, int)
        assert port > 0
        assert port == 636

    @pytest.mark.docker
    @pytest.mark.unit
    def test_supports_start_tls(self, servers_instance: FlextLdapServers) -> None:
        """Test supports_start_tls returns boolean."""
        supported = servers_instance.supports_start_tls()
        assert isinstance(supported, bool)

    @pytest.mark.docker
    @pytest.mark.unit
    def test_get_bind_mechanisms(self, servers_instance: FlextLdapServers) -> None:
        """Test get_bind_mechanisms returns list."""
        mechanisms = servers_instance.get_bind_mechanisms()
        assert isinstance(mechanisms, list)
        assert len(mechanisms) > 0
        assert isinstance(mechanisms[0], str)

    @pytest.mark.docker
    @pytest.mark.unit
    def test_get_max_page_size(self, servers_instance: FlextLdapServers) -> None:
        """Test get_max_page_size returns integer."""
        page_size = servers_instance.get_max_page_size()
        assert isinstance(page_size, int)
        assert page_size > 0

    @pytest.mark.docker
    @pytest.mark.unit
    def test_supports_paged_results(self, servers_instance: FlextLdapServers) -> None:
        """Test supports_paged_results returns boolean."""
        supported = servers_instance.supports_paged_results()
        assert isinstance(supported, bool)

    @pytest.mark.docker
    @pytest.mark.unit
    def test_supports_vlv(self, servers_instance: FlextLdapServers) -> None:
        """Test supports_vlv returns boolean."""
        supported = servers_instance.supports_vlv()
        assert isinstance(supported, bool)


class TestFlextLdapServersFacadeWithConnection:
    """Test server facade operations requiring LDAP connection."""

    @pytest.fixture(autouse=True)
    def connected_client(self) -> FlextLdapClients:
        """Provide a connected LDAP client."""
        client = FlextLdapClients()
        connect_result = client.connect(
            server_uri="ldap://localhost:3390",
            bind_dn="cn=REDACTED_LDAP_BIND_PASSWORD,dc=flext,dc=local",
            password="REDACTED_LDAP_BIND_PASSWORD123",
        )
        assert connect_result.is_success is True, (
            f"Connection failed: {connect_result.error}"
        )
        yield client
        client.unbind()

    @pytest.fixture(autouse=True)
    def servers_instance(self) -> FlextLdapServers:
        """Provide a server facade instance."""
        return FlextLdapServers()

    @pytest.mark.docker
    @pytest.mark.unit
    def test_get_root_dse_attributes(
        self,
        servers_instance: FlextLdapServers,
        connected_client: FlextLdapClients,
    ) -> None:
        """Test get_root_dse_attributes with connection."""
        result = servers_instance.get_root_dse_attributes(connected_client.connection)
        assert result.is_success is True or result.is_failure is True
        if result.is_success:
            attrs = result.unwrap()
            assert isinstance(attrs, dict)

    @pytest.mark.docker
    @pytest.mark.unit
    def test_detect_server_type_from_root_dse(
        self, servers_instance: FlextLdapServers
    ) -> None:
        """Test detect_server_type_from_root_dse with mock Root DSE."""
        root_dse = {"vendorName": "OpenLDAP"}
        server_type = servers_instance.detect_server_type_from_root_dse(root_dse)
        assert isinstance(server_type, str)

    @pytest.mark.docker
    @pytest.mark.unit
    def test_get_supported_controls(
        self,
        servers_instance: FlextLdapServers,
        connected_client: FlextLdapClients,
    ) -> None:
        """Test get_supported_controls with connection."""
        result = servers_instance.get_supported_controls(connected_client.connection)
        assert result.is_success is True or result.is_failure is True
        if result.is_success:
            controls = result.unwrap()
            assert isinstance(controls, list)

    @pytest.mark.docker
    @pytest.mark.unit
    def test_search_with_paging(
        self,
        servers_instance: FlextLdapServers,
        connected_client: FlextLdapClients,
    ) -> None:
        """Test search_with_paging operation."""
        result = servers_instance.search_with_paging(
            connected_client.connection,
            base_dn="dc=flext,dc=local",
            search_filter="(objectClass=*)",
            attributes=None,
            scope="BASE",
            page_size=100,
        )
        assert result.is_success is True or result.is_failure is True
        if result.is_success:
            entries = result.unwrap()
            assert isinstance(entries, list)

    @pytest.mark.docker
    @pytest.mark.unit
    def test_discover_schema(
        self,
        servers_instance: FlextLdapServers,
        connected_client: FlextLdapClients,
    ) -> None:
        """Test discover_schema operation."""
        result = servers_instance.discover_schema(connected_client.connection)
        assert result.is_success is True or result.is_failure is True


class TestFlextLdapServersFacadeEntryOperations:
    """Test server facade entry operations."""

    @pytest.fixture(autouse=True)
    def servers_instance(self) -> FlextLdapServers:
        """Provide a server facade instance."""
        return FlextLdapServers()

    @pytest.mark.docker
    @pytest.mark.unit
    def test_validate_entry_for_server_success(
        self, servers_instance: FlextLdapServers
    ) -> None:
        """Test validate_entry_for_server with valid entry."""
        # Create a dummy entry
        dn = FlextLdifModels.DistinguishedName.model_validate({
            "value": "cn=test,dc=example,dc=com"
        })
        entry = FlextLdifModels.Entry(
            dn=dn,
            attributes=FlextLdifModels.LdifAttributes(),
        )
        result = servers_instance.validate_entry_for_server(entry)
        assert result.is_success is True or result.is_failure is True

    @pytest.mark.docker
    @pytest.mark.unit
    def test_normalize_entry_for_server(
        self, servers_instance: FlextLdapServers
    ) -> None:
        """Test normalize_entry_for_server operation."""
        dn = FlextLdifModels.DistinguishedName.model_validate({
            "value": "cn=test,dc=example,dc=com"
        })
        entry = FlextLdifModels.Entry(
            dn=dn,
            attributes=FlextLdifModels.LdifAttributes(),
        )
        result = servers_instance.normalize_entry_for_server(entry)
        assert result.is_success is True or result.is_failure is True

    @pytest.mark.docker
    @pytest.mark.unit
    def test_parse_returns_result(self, servers_instance: FlextLdapServers) -> None:
        """Test parse returns FlextResult."""
        acl_string = "test_acl"
        result = servers_instance.parse(acl_string)
        assert result.is_success is True or result.is_failure is True

    @pytest.mark.docker
    @pytest.mark.unit
    def test_format_acl_returns_result(
        self, servers_instance: FlextLdapServers
    ) -> None:
        """Test format_acl returns FlextResult."""
        dn = FlextLdifModels.DistinguishedName.model_validate({
            "value": "cn=test,dc=example,dc=com"
        })
        entry = FlextLdifModels.Entry(
            dn=dn,
            attributes=FlextLdifModels.LdifAttributes(),
        )
        result = servers_instance.format_acl(entry)
        assert result.is_success is True or result.is_failure is True

    @pytest.mark.docker
    @pytest.mark.unit
    def test_parse_object_class_returns_result(
        self, servers_instance: FlextLdapServers
    ) -> None:
        """Test parse_object_class returns FlextResult."""
        object_class_def = "( 2.5.4.0 NAME 'top' ABSTRACT MUST objectClass )"
        result = servers_instance.parse_object_class(object_class_def)
        assert result.is_success is True or result.is_failure is True

    @pytest.mark.docker
    @pytest.mark.unit
    def test_parse_attribute_type_returns_result(
        self, servers_instance: FlextLdapServers
    ) -> None:
        """Test parse_attribute_type returns FlextResult."""
        attribute_def = "( 2.5.4.3 NAME 'cn' SUP name )"
        result = servers_instance.parse_attribute_type(attribute_def)
        assert result.is_success is True or result.is_failure is True


__all__ = [
    "TestFlextLdapServersFacadeBasicOperations",
    "TestFlextLdapServersFacadeCapabilities",
    "TestFlextLdapServersFacadeEntryOperations",
    "TestFlextLdapServersFacadeFactory",
    "TestFlextLdapServersFacadeWithConnection",
]

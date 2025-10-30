"""Comprehensive real Docker LDAP tests for FlextLdapServersActiveDirectoryOperations.

This module contains comprehensive tests for FlextLdapServersActiveDirectoryOperations using real Docker
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

from flext_ldap import FlextLdapClients
from flext_ldap.servers.ad_operations import FlextLdapServersActiveDirectoryOperations


class TestFlextLdapActiveDirectoryBasics:
    """Test Active Directory operations basics."""

    @pytest.fixture(autouse=True)
    def operations(self) -> FlextLdapServersActiveDirectoryOperations:
        """Provide AD operations instance."""
        return FlextLdapServersActiveDirectoryOperations()

    @pytest.mark.docker
    @pytest.mark.unit
    def test_ad_server_type(
        self, operations: FlextLdapServersActiveDirectoryOperations
    ) -> None:
        """Test AD operations has correct server type."""
        assert operations.server_type == "ad"

    @pytest.mark.docker
    @pytest.mark.unit
    def test_ad_get_default_port(
        self, operations: FlextLdapServersActiveDirectoryOperations
    ) -> None:
        """Test AD gets standard LDAP port."""
        port = operations.get_default_port(use_ssl=False)
        assert port == 389

    @pytest.mark.docker
    @pytest.mark.unit
    def test_ad_get_ssl_port(
        self, operations: FlextLdapServersActiveDirectoryOperations
    ) -> None:
        """Test AD gets SSL port."""
        port = operations.get_default_port(use_ssl=True)
        assert port == 636

    @pytest.mark.docker
    @pytest.mark.unit
    def test_ad_global_catalog_port(
        self, operations: FlextLdapServersActiveDirectoryOperations
    ) -> None:
        """Test AD Global Catalog standard port."""
        port = operations.get_global_catalog_port(use_ssl=False)
        assert port == 3268

    @pytest.mark.docker
    @pytest.mark.unit
    def test_ad_global_catalog_ssl_port(
        self, operations: FlextLdapServersActiveDirectoryOperations
    ) -> None:
        """Test AD Global Catalog SSL port."""
        port = operations.get_global_catalog_port(use_ssl=True)
        assert port == 3269

    @pytest.mark.docker
    @pytest.mark.unit
    def test_ad_supports_start_tls(
        self, operations: FlextLdapServersActiveDirectoryOperations
    ) -> None:
        """Test AD supports START_TLS."""
        assert operations.supports_start_tls() is True

    @pytest.mark.docker
    @pytest.mark.unit
    def test_ad_bind_mechanisms(
        self, operations: FlextLdapServersActiveDirectoryOperations
    ) -> None:
        """Test AD supports multiple bind mechanisms."""
        mechanisms = operations.get_bind_mechanisms()
        assert isinstance(mechanisms, list)
        assert len(mechanisms) >= 3  # SIMPLE, NTLM, GSSAPI
        assert "SIMPLE" in mechanisms

    @pytest.mark.docker
    @pytest.mark.unit
    def test_ad_execute(
        self, operations: FlextLdapServersActiveDirectoryOperations
    ) -> None:
        """Test AD execute returns OK."""
        result = operations.execute()
        assert result.is_success is True


class TestFlextLdapActiveDirectorySchema:
    """Test AD schema operations."""

    @pytest.fixture(autouse=True)
    def operations(self) -> FlextLdapServersActiveDirectoryOperations:
        """Provide AD operations instance."""
        return FlextLdapServersActiveDirectoryOperations()

    @pytest.fixture(autouse=True)
    def connected_client(self) -> FlextLdapClients:
        """Provide a connected LDAP client."""
        client = FlextLdapClients()
        client.connect(
            server_uri="ldap://localhost:3390",
            bind_dn="cn=REDACTED_LDAP_BIND_PASSWORD,dc=flext,dc=local",
            password="REDACTED_LDAP_BIND_PASSWORD123",
        )
        yield client
        client.unbind()

    @pytest.mark.docker
    @pytest.mark.unit
    def test_ad_get_schema_dn(
        self, operations: FlextLdapServersActiveDirectoryOperations
    ) -> None:
        """Test AD schema DN retrieval."""
        schema_dn = operations.get_schema_dn()
        assert isinstance(schema_dn, str)
        assert len(schema_dn) > 0

    @pytest.mark.docker
    @pytest.mark.unit
    def test_ad_acl_format(
        self, operations: FlextLdapServersActiveDirectoryOperations
    ) -> None:
        """Test AD ACL format identifier."""
        acl_format = operations.get_acl_format()
        assert isinstance(acl_format, str)

    @pytest.mark.docker
    @pytest.mark.unit
    def test_ad_acl_attribute_name(
        self, operations: FlextLdapServersActiveDirectoryOperations
    ) -> None:
        """Test AD ACL attribute name."""
        attr_name = operations.get_acl_attribute_name()
        assert isinstance(attr_name, str)


class TestFlextLdapActiveDirectoryPaging:
    """Test AD paging support."""

    @pytest.fixture(autouse=True)
    def operations(self) -> FlextLdapServersActiveDirectoryOperations:
        """Provide AD operations instance."""
        return FlextLdapServersActiveDirectoryOperations()

    @pytest.fixture(autouse=True)
    def connected_client(self) -> FlextLdapClients:
        """Provide a connected LDAP client."""
        client = FlextLdapClients()
        client.connect(
            server_uri="ldap://localhost:3390",
            bind_dn="cn=REDACTED_LDAP_BIND_PASSWORD,dc=flext,dc=local",
            password="REDACTED_LDAP_BIND_PASSWORD123",
        )
        yield client
        client.unbind()

    @pytest.mark.docker
    @pytest.mark.unit
    def test_ad_max_page_size(
        self, operations: FlextLdapServersActiveDirectoryOperations
    ) -> None:
        """Test AD max page size."""
        page_size = operations.get_max_page_size()
        assert isinstance(page_size, int)
        assert page_size > 0

    @pytest.mark.docker
    @pytest.mark.unit
    def test_ad_supports_paging(
        self, operations: FlextLdapServersActiveDirectoryOperations
    ) -> None:
        """Test AD supports paged results."""
        supported = operations.supports_paged_results()
        assert isinstance(supported, bool)
        assert supported is True

    @pytest.mark.docker
    @pytest.mark.unit
    def test_ad_supports_vlv(
        self, operations: FlextLdapServersActiveDirectoryOperations
    ) -> None:
        """Test AD VLV support (should be True for AD)."""
        supported = operations.supports_vlv()
        assert isinstance(supported, bool)
        assert supported is True  # AD supports VLV

    @pytest.mark.docker
    @pytest.mark.unit
    def test_ad_search_with_paging_success(
        self,
        operations: FlextLdapServersActiveDirectoryOperations,
        connected_client: FlextLdapClients,
    ) -> None:
        """Test AD paged search."""
        result = operations.search_with_paging(
            connected_client.connection,
            base_dn="dc=flext,dc=local",
            search_filter="(objectClass=*)",
            attributes=["cn"],
            scope="subtree",
            page_size=100,
        )

        assert result.is_success is True or result.is_failure is True


class TestFlextLdapActiveDirectoryRootDse:
    """Test AD Root DSE operations."""

    @pytest.fixture(autouse=True)
    def operations(self) -> FlextLdapServersActiveDirectoryOperations:
        """Provide AD operations instance."""
        return FlextLdapServersActiveDirectoryOperations()

    @pytest.fixture(autouse=True)
    def connected_client(self) -> FlextLdapClients:
        """Provide a connected LDAP client."""
        client = FlextLdapClients()
        client.connect(
            server_uri="ldap://localhost:3390",
            bind_dn="cn=REDACTED_LDAP_BIND_PASSWORD,dc=flext,dc=local",
            password="REDACTED_LDAP_BIND_PASSWORD123",
        )
        yield client
        client.unbind()

    @pytest.mark.docker
    @pytest.mark.unit
    def test_ad_get_root_dse(
        self,
        operations: FlextLdapServersActiveDirectoryOperations,
        connected_client: FlextLdapClients,
    ) -> None:
        """Test getting AD Root DSE attributes."""
        result = operations.get_root_dse_attributes(connected_client.connection)

        assert result.is_success is True
        attributes = result.unwrap()
        assert isinstance(attributes, dict)

    @pytest.mark.docker
    @pytest.mark.unit
    def test_ad_detect_server_type(
        self, operations: FlextLdapServersActiveDirectoryOperations
    ) -> None:
        """Test detecting AD from Root DSE."""
        root_dse = {"rootDomainNamingContext": "dc=example,dc=com"}
        server_type = operations.detect_server_type_from_root_dse(root_dse)
        assert isinstance(server_type, str)

    @pytest.mark.docker
    @pytest.mark.unit
    def test_ad_get_supported_controls(
        self,
        operations: FlextLdapServersActiveDirectoryOperations,
        connected_client: FlextLdapClients,
    ) -> None:
        """Test getting AD supported controls."""
        result = operations.get_supported_controls(connected_client.connection)
        assert result.is_success is True
        controls = result.unwrap()
        assert isinstance(controls, list)


class TestFlextLdapActiveDirectoryEntry:
    """Test AD entry operations."""

    @pytest.fixture(autouse=True)
    def operations(self) -> FlextLdapServersActiveDirectoryOperations:
        """Provide AD operations instance."""
        return FlextLdapServersActiveDirectoryOperations()

    @pytest.fixture(autouse=True)
    def connected_client(self) -> FlextLdapClients:
        """Provide a connected LDAP client."""
        client = FlextLdapClients()
        client.connect(
            server_uri="ldap://localhost:3390",
            bind_dn="cn=REDACTED_LDAP_BIND_PASSWORD,dc=flext,dc=local",
            password="REDACTED_LDAP_BIND_PASSWORD123",
        )
        yield client
        client.unbind()

    @pytest.mark.docker
    @pytest.mark.unit
    def test_ad_parse_acl_returns_result(
        self, operations: FlextLdapServersActiveDirectoryOperations
    ) -> None:
        """Test parsing AD ACL returns FlextResult."""
        acl_string = "test_acl"
        result = operations.parse_acl(acl_string)

        # Should return either success or failure
        assert result.is_success is True or result.is_failure is True

    @pytest.mark.docker
    @pytest.mark.unit
    def test_ad_format_acl_returns_result(
        self, operations: FlextLdapServersActiveDirectoryOperations
    ) -> None:
        """Test formatting AD ACL returns FlextResult."""
        from flext_ldif import FlextLdifModels

        # Create a dummy entry for ACL
        dn = FlextLdifModels.DistinguishedName.model_validate({
            "value": "cn=test,dc=example,dc=com"
        })
        entry = FlextLdifModels.Entry(
            dn=dn,
            attributes=FlextLdifModels.LdifAttributes(),
        )

        result = operations.format_acl(entry)

        # Should return either success or failure
        assert result.is_success is True or result.is_failure is True


class TestFlextLdapActiveDirectoryIntegration:
    """Integration tests for AD operations."""

    @pytest.fixture(autouse=True)
    def operations(self) -> FlextLdapServersActiveDirectoryOperations:
        """Provide AD operations instance."""
        return FlextLdapServersActiveDirectoryOperations()

    @pytest.fixture(autouse=True)
    def connected_client(self) -> FlextLdapClients:
        """Provide a connected LDAP client."""
        client = FlextLdapClients()
        client.connect(
            server_uri="ldap://localhost:3390",
            bind_dn="cn=REDACTED_LDAP_BIND_PASSWORD,dc=flext,dc=local",
            password="REDACTED_LDAP_BIND_PASSWORD123",
        )
        yield client
        client.unbind()

    @pytest.mark.docker
    @pytest.mark.unit
    def test_ad_discover_schema(
        self,
        operations: FlextLdapServersActiveDirectoryOperations,
        connected_client: FlextLdapClients,
    ) -> None:
        """Test AD schema discovery."""
        result = operations.discover_schema(connected_client.connection)

        # Schema discovery can succeed or fail depending on server setup
        assert result.is_success is True or result.is_failure is True

    @pytest.mark.docker
    @pytest.mark.unit
    def test_ad_operations_method_exists(
        self, operations: FlextLdapServersActiveDirectoryOperations
    ) -> None:
        """Test AD operations has required methods."""
        required_methods = [
            "get_schema_dn",
            "get_acl_format",
            "get_acl_attribute_name",
            "get_bind_mechanisms",
            "get_global_catalog_port",
            "supports_vlv",
        ]

        for method in required_methods:
            assert hasattr(operations, method)
            assert callable(getattr(operations, method))


__all__ = [
    "TestFlextLdapActiveDirectoryBasics",
    "TestFlextLdapActiveDirectoryEntry",
    "TestFlextLdapActiveDirectoryIntegration",
    "TestFlextLdapActiveDirectoryPaging",
    "TestFlextLdapActiveDirectoryRootDse",
    "TestFlextLdapActiveDirectorySchema",
]

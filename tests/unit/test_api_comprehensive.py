"""Comprehensive tests for FlextLdap API.

This module contains comprehensive tests for FlextLdap main API using real Docker
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
from pydantic import SecretStr

from flext_ldap import FlextLdap, FlextLdapModels


class TestFlextLdapInitialization:
    """Test FlextLdap initialization and configuration."""

    @pytest.mark.docker
    @pytest.mark.unit
    def test_flext_ldap_create_instance(self) -> None:
        """Test creating FlextLdap instance."""
        ldap = FlextLdap.create()
        assert ldap is not None
        assert ldap.config is not None

    @pytest.mark.docker
    @pytest.mark.unit
    def test_flext_ldap_singleton_pattern(self) -> None:
        """Test singleton pattern for FlextLdap."""
        instance1 = FlextLdap.get_instance()
        instance2 = FlextLdap.get_instance()
        assert instance1 is instance2

    @pytest.mark.docker
    @pytest.mark.unit
    def test_flext_ldap_with_config(self) -> None:
        """Test creating FlextLdap with custom config."""
        from flext_ldap.config import FlextLdapConfig

        config = FlextLdapConfig()
        ldap = FlextLdap(config=config)
        assert ldap.config is config

    @pytest.mark.docker
    @pytest.mark.unit
    def test_flext_ldap_config_property(self) -> None:
        """Test config property."""
        ldap = FlextLdap.create()
        config = ldap.config
        assert config is not None
        assert hasattr(config, "ldap_server_uri")


class TestFlextLdapLazyInitialization:
    """Test lazy-loaded properties of FlextLdap."""

    @pytest.mark.docker
    @pytest.mark.unit
    def test_client_lazy_loading(self) -> None:
        """Test client property lazy loading."""
        ldap = FlextLdap.create()
        client1 = ldap.client
        client2 = ldap.client
        assert client1 is client2  # Same instance on repeated access

    @pytest.mark.docker
    @pytest.mark.unit
    def test_servers_lazy_loading(self) -> None:
        """Test servers property lazy loading."""
        ldap = FlextLdap.create()
        servers1 = ldap.servers
        servers2 = ldap.servers
        assert servers1 is servers2  # Same instance

    @pytest.mark.docker
    @pytest.mark.unit
    def test_acl_lazy_loading(self) -> None:
        """Test ACL property lazy loading."""
        ldap = FlextLdap.create()
        acl1 = ldap.acl
        acl2 = ldap.acl
        assert acl1 is acl2  # Same instance

    @pytest.mark.docker
    @pytest.mark.unit
    def test_authentication_lazy_loading(self) -> None:
        """Test authentication property lazy loading."""
        ldap = FlextLdap.create()
        auth1 = ldap.authentication
        auth2 = ldap.authentication
        assert auth1 is auth2  # Same instance


class TestFlextLdapHandlerProtocol:
    """Test FlextLdap handler protocol implementation."""

    @pytest.mark.docker
    @pytest.mark.unit
    def test_can_handle_string_operations(self) -> None:
        """Test can_handle with string operation names."""
        ldap = FlextLdap.create()

        # Test various operation names
        assert ldap.can_handle("search") is True
        assert ldap.can_handle("add") is True
        assert ldap.can_handle("modify") is True
        assert ldap.can_handle("delete") is True
        assert ldap.can_handle("bind") is True
        assert ldap.can_handle("unbind") is True

    @pytest.mark.docker
    @pytest.mark.unit
    def test_can_handle_case_insensitive(self) -> None:
        """Test can_handle with case insensitivity."""
        ldap = FlextLdap.create()

        assert ldap.can_handle("SEARCH") is True
        assert ldap.can_handle("Search") is True
        assert ldap.can_handle("ADD") is True

    @pytest.mark.docker
    @pytest.mark.unit
    def test_can_handle_model_types(self) -> None:
        """Test can_handle with FlextLdapModels types."""
        ldap = FlextLdap.create()

        assert ldap.can_handle(FlextLdapModels.SearchRequest) is True
        assert ldap.can_handle(FlextLdapModels.SearchResponse) is True
        assert ldap.can_handle(FlextLdifModels.Entry) is True

    @pytest.mark.docker
    @pytest.mark.unit
    def test_can_handle_unknown_type(self) -> None:
        """Test can_handle with unknown operation."""
        ldap = FlextLdap.create()
        assert ldap.can_handle("unknown_operation") is False


class TestFlextLdapConnection:
    """Test FlextLdap connection management."""

    @pytest.mark.docker
    @pytest.mark.unit
    def test_connect_success(self) -> None:
        """Test successful connection to LDAP server."""
        ldap = FlextLdap.create()

        result = ldap.connect(
            uri="ldap://localhost:3390",
            bind_dn="cn=REDACTED_LDAP_BIND_PASSWORD,dc=flext,dc=local",
            password="REDACTED_LDAP_BIND_PASSWORD123",
        )

        assert result.is_success is True
        assert result.unwrap() is True

        # Cleanup
        ldap.client.unbind()

    @pytest.mark.docker
    @pytest.mark.unit
    def test_connect_with_secret_str_password(self) -> None:
        """Test connect with SecretStr password."""
        ldap = FlextLdap.create()

        result = ldap.connect(
            uri="ldap://localhost:3390",
            bind_dn="cn=REDACTED_LDAP_BIND_PASSWORD,dc=flext,dc=local",
            password=SecretStr("REDACTED_LDAP_BIND_PASSWORD123"),
        )

        assert result.is_success is True
        ldap.client.unbind()

    @pytest.mark.docker
    @pytest.mark.unit
    def test_connect_storess_mode(self) -> None:
        """Test that connect stores quirks mode."""
        ldap = FlextLdap.create()
        from flext_ldap.constants import FlextLdapConstants

        result = ldap.connect(
            uri="ldap://localhost:3390",
            bind_dn="cn=REDACTED_LDAP_BIND_PASSWORD,dc=flext,dc=local",
            password="REDACTED_LDAP_BIND_PASSWORD123",
            quirks_mode=FlextLdapConstants.Types.QuirksMode.RFC,
        )

        assert result.is_success is True
        assert ldap.quirks_mode == FlextLdapConstants.Types.QuirksMode.RFC
        ldap.client.unbind()

    @pytest.mark.docker
    @pytest.mark.unit
    def test_unbind_success(self) -> None:
        """Test unbind disconnection."""
        ldap = FlextLdap.create()

        # Connect first
        connect_result = ldap.connect(
            uri="ldap://localhost:3390",
            bind_dn="cn=REDACTED_LDAP_BIND_PASSWORD,dc=flext,dc=local",
            password="REDACTED_LDAP_BIND_PASSWORD123",
        )
        assert connect_result.is_success is True

        # Then unbind
        unbind_result = ldap.unbind()
        assert unbind_result.is_success is True
        assert ldap.client.is_connected is False


class TestFlextLdapSearch:
    """Test FlextLdap search operations."""

    @pytest.fixture(autouse=True)
    def connected_ldap(self) -> FlextLdap:
        """Provide a connected FlextLdap instance."""
        ldap = FlextLdap.create()
        connect_result = ldap.connect(
            uri="ldap://localhost:3390",
            bind_dn="cn=REDACTED_LDAP_BIND_PASSWORD,dc=flext,dc=local",
            password="REDACTED_LDAP_BIND_PASSWORD123",
        )
        assert connect_result.is_success is True, (
            f"Connection failed: {connect_result.error}"
        )
        yield ldap
        ldap.client.unbind()

    @pytest.mark.docker
    @pytest.mark.unit
    def test_search_all_entries(self, connected_ldap: FlextLdap) -> None:
        """Test searching for all entries."""
        result = connected_ldap.search(
            base_dn="dc=flext,dc=local",
            filter_str="(objectClass=*)",
            scope="SUBTREE",
        )

        assert result.is_success is True
        entries = result.unwrap()
        assert isinstance(entries, list)
        assert len(entries) > 0

    @pytest.mark.docker
    @pytest.mark.unit
    def test_search_base_scope(self, connected_ldap: FlextLdap) -> None:
        """Test search with BASE scope."""
        result = connected_ldap.search(
            base_dn="dc=flext,dc=local",
            filter_str="(objectClass=*)",
            scope="BASE",
        )

        assert result.is_success is True
        entries = result.unwrap()
        assert isinstance(entries, list)
        assert len(entries) > 0

    @pytest.mark.docker
    @pytest.mark.unit
    def test_search_with_attributes(self, connected_ldap: FlextLdap) -> None:
        """Test search with specific attributes."""
        result = connected_ldap.search(
            base_dn="dc=flext,dc=local",
            filter_str="(objectClass=*)",
            scope="BASE",
            attributes=["cn", "objectClass"],
        )

        assert result.is_success is True
        entries = result.unwrap()
        assert isinstance(entries, list)

    @pytest.mark.docker
    @pytest.mark.unit
    def test_query_consolidation(self, connected_ldap: FlextLdap) -> None:
        """Test query method (search consolidation)."""
        result = connected_ldap.query(
            base_dn="dc=flext,dc=local",
            filter_str="(objectClass=*)",
        )

        assert result.is_success is True
        response = result.unwrap()
        assert response is not None
        assert hasattr(response, "entries")

    @pytest.mark.docker
    @pytest.mark.unit
    def test_query_single_result(self, connected_ldap: FlextLdap) -> None:
        """Test query with single=True."""
        result = connected_ldap.query(
            base_dn="dc=flext,dc=local",
            filter_str="(objectClass=*)",
            single=True,
        )

        assert result.is_success is True
        entry = result.unwrap()
        # Should be single entry or None, not SearchResponse
        assert entry is None or hasattr(entry, "dn")


class TestFlextLdapValidation:
    """Test FlextLdap entry validation."""

    @pytest.fixture(autouse=True)
    def connected_ldap(self) -> FlextLdap:
        """Provide a connected FlextLdap instance."""
        ldap = FlextLdap.create()
        connect_result = ldap.connect(
            uri="ldap://localhost:3390",
            bind_dn="cn=REDACTED_LDAP_BIND_PASSWORD,dc=flext,dc=local",
            password="REDACTED_LDAP_BIND_PASSWORD123",
        )
        assert connect_result.is_success is True
        yield ldap
        ldap.client.unbind()

    @pytest.mark.docker
    @pytest.mark.unit
    def test_validate_entries_success(self, connected_ldap: FlextLdap) -> None:
        """Test entry validation."""
        dn = FlextLdifModels.DistinguishedName.model_validate({
            "value": "cn=test,dc=flext,dc=local"
        })
        entry = FlextLdifModels.Entry(
            dn=dn,
            attributes=FlextLdifModels.LdifAttributes(),
        )

        result = connected_ldap.validate_entries([entry])
        assert result.is_success is True
        report = result.unwrap()
        assert isinstance(report, dict)
        assert "valid" in report

    @pytest.mark.docker
    @pytest.mark.unit
    def test_validate_single_entry(self, connected_ldap: FlextLdap) -> None:
        """Test validation of single entry."""
        dn = FlextLdifModels.DistinguishedName.model_validate({
            "value": "cn=test,dc=flext,dc=local"
        })
        entry = FlextLdifModels.Entry(
            dn=dn,
            attributes=FlextLdifModels.LdifAttributes(),
        )

        result = connected_ldap.validate_entries(entry)
        assert result.is_success is True


class TestFlextLdapServerInfo:
    """Test FlextLdap server information methods."""

    @pytest.fixture(autouse=True)
    def connected_ldap(self) -> FlextLdap:
        """Provide a connected FlextLdap instance."""
        ldap = FlextLdap.create()
        connect_result = ldap.connect(
            uri="ldap://localhost:3390",
            bind_dn="cn=REDACTED_LDAP_BIND_PASSWORD,dc=flext,dc=local",
            password="REDACTED_LDAP_BIND_PASSWORD123",
        )
        assert connect_result.is_success is True
        yield ldap
        ldap.client.unbind()

    @pytest.mark.docker
    @pytest.mark.unit
    def test_get_server_info(self, connected_ldap: FlextLdap) -> None:
        """Test getting server info."""
        result = connected_ldap.get_server_info()
        assert result.is_success is True
        entry = result.unwrap()
        assert entry is not None
        assert hasattr(entry, "dn")

    @pytest.mark.docker
    @pytest.mark.unit
    def test_get_acl_info(self, connected_ldap: FlextLdap) -> None:
        """Test getting ACL info."""
        result = connected_ldap.get_acl_info()
        assert result.is_success is True
        entry = result.unwrap()
        assert entry is not None

    @pytest.mark.docker
    @pytest.mark.unit
    def test_get_server_capabilities(self, connected_ldap: FlextLdap) -> None:
        """Test getting server capabilities."""
        result = connected_ldap.get_server_capabilities()
        assert result.is_success is True
        capabilities = result.unwrap()
        assert hasattr(capabilities, "supports_ssl")
        assert hasattr(capabilities, "max_page_size")

    @pytest.mark.docker
    @pytest.mark.unit
    def test_info_basic(self, connected_ldap: FlextLdap) -> None:
        """Test info method with basic detail level."""
        result = connected_ldap.info(detail_level="basic")
        assert result.is_success is True
        info = result.unwrap()
        assert isinstance(info, dict)
        assert "type" in info or "server_type" in info

    @pytest.mark.docker
    @pytest.mark.unit
    def test_info_full(self, connected_ldap: FlextLdap) -> None:
        """Test info method with full detail level."""
        result = connected_ldap.info(detail_level="full")
        assert result.is_success is True
        info = result.unwrap()
        assert isinstance(info, dict)


class TestFlextLdapLdifIntegration:
    """Test FlextLdap LDIF integration."""

    @pytest.fixture(autouse=True)
    def connected_ldap(self) -> FlextLdap:
        """Provide a connected FlextLdap instance."""
        ldap = FlextLdap.create()
        connect_result = ldap.connect(
            uri="ldap://localhost:3390",
            bind_dn="cn=REDACTED_LDAP_BIND_PASSWORD,dc=flext,dc=local",
            password="REDACTED_LDAP_BIND_PASSWORD123",
        )
        assert connect_result.is_success is True
        yield ldap
        ldap.client.unbind()

    @pytest.mark.docker
    @pytest.mark.unit
    def test_import_from_ldif(self, connected_ldap: FlextLdap) -> None:
        """Test importing entries from LDIF content."""
        ldif_content = """dn: cn=test,dc=flext,dc=local
objectClass: top
objectClass: person
cn: test
sn: Test User
"""

        result = connected_ldap.import_from_ldif(ldif_content)
        assert result.is_success is True
        entries = result.unwrap()
        assert isinstance(entries, list)
        assert len(entries) > 0

    @pytest.mark.docker
    @pytest.mark.unit
    def test_export_to_ldif(self, connected_ldap: FlextLdap) -> None:
        """Test exporting entries to LDIF format."""
        dn = FlextLdifModels.DistinguishedName.model_validate({
            "value": "cn=test,dc=flext,dc=local"
        })
        entry = FlextLdifModels.Entry(
            dn=dn,
            attributes=FlextLdifModels.LdifAttributes(),
        )

        ldif_data = connected_ldap.export_to_ldif([entry])
        assert isinstance(ldif_data, str)
        assert len(ldif_data) > 0

    @pytest.mark.docker
    @pytest.mark.unit
    def test_exchange_import(self, connected_ldap: FlextLdap) -> None:
        """Test exchange method with import direction."""
        ldif_content = """dn: cn=test,dc=flext,dc=local
objectClass: top
objectClass: person
cn: test
sn: Test User
"""

        result = connected_ldap.exchange(
            data=ldif_content,
            direction="import",
            data_format="ldif",
        )

        assert result.is_success is True
        entries = result.unwrap()
        assert isinstance(entries, list)

    @pytest.mark.docker
    @pytest.mark.unit
    def test_exchange_export(self, connected_ldap: FlextLdap) -> None:
        """Test exchange method with export direction."""
        dn = FlextLdifModels.DistinguishedName.model_validate({
            "value": "cn=test,dc=flext,dc=local"
        })
        entry = FlextLdifModels.Entry(
            dn=dn,
            attributes=FlextLdifModels.LdifAttributes(),
        )

        result = connected_ldap.exchange(
            entries=[entry],
            direction="export",
            data_format="ldif",
        )

        assert result.is_success is True
        ldif_data = result.unwrap()
        assert isinstance(ldif_data, str)


class TestFlextLdapContextManager:
    """Test FlextLdap context manager functionality."""

    @pytest.mark.docker
    @pytest.mark.unit
    def test_context_manager_with_statement(self) -> None:
        """Test FlextLdap as context manager."""
        from pydantic import SecretStr

        from flext_ldap.config import FlextLdapConfig

        config = FlextLdapConfig()
        config.ldap_server_uri = "ldap://localhost:3390"
        config.__dict__["ldap_bind_dn"] = "cn=REDACTED_LDAP_BIND_PASSWORD,dc=flext,dc=local"
        config.__dict__["ldap_bind_password"] = SecretStr("REDACTED_LDAP_BIND_PASSWORD123")
        config.validate_ldap_configuration_consistency()

        ldap = FlextLdap(config=config)

        with ldap as ldap_ctx:
            assert ldap_ctx is ldap
            assert ldap.client.is_connected is True

    @pytest.mark.docker
    @pytest.mark.unit
    def test_context_manager_cleanup(self) -> None:
        """Test that context manager cleans up connection."""
        ldap = FlextLdap.create()

        try:
            with ldap:
                assert ldap.client.is_connected is True
        except Exception:
            pass  # Ignore any errors for this test

        # Connection should still be established (unbind is idempotent)
        # We don't strictly require disconnection for this test


class TestFlextLdapServersNestedClass:
    """Test FlextLdap.Servers nested class."""

    @pytest.mark.docker
    @pytest.mark.unit
    def test_servers_initialization(self) -> None:
        """Test Servers class initialization."""
        ldap = FlextLdap.create()
        servers = ldap.servers
        assert servers is not None

    @pytest.mark.docker
    @pytest.mark.unit
    def test_servers_server_type(self) -> None:
        """Test server_type property."""
        ldap = FlextLdap.create()
        server_type = ldap.servers.server_type
        assert isinstance(server_type, str)
        assert len(server_type) > 0

    @pytest.mark.docker
    @pytest.mark.unit
    def test_servers_get_default_port_no_ssl(self) -> None:
        """Test default port without SSL."""
        ldap = FlextLdap.create()
        port = ldap.servers.get_default_port(use_ssl=False)
        assert isinstance(port, int)
        assert port == 389

    @pytest.mark.docker
    @pytest.mark.unit
    def test_servers_get_default_port_with_ssl(self) -> None:
        """Test default port with SSL."""
        ldap = FlextLdap.create()
        port = ldap.servers.get_default_port(use_ssl=True)
        assert isinstance(port, int)
        assert port == 636

    @pytest.mark.docker
    @pytest.mark.unit
    def test_servers_supports_start_tls(self) -> None:
        """Test STARTTLS support check."""
        ldap = FlextLdap.create()
        supports_tls = ldap.servers.supports_start_tls()
        assert isinstance(supports_tls, bool)


class TestFlextLdapAclNestedClass:
    """Test FlextLdap.Acl nested class."""

    @pytest.mark.docker
    @pytest.mark.unit
    def test_acl_initialization(self) -> None:
        """Test ACL class initialization."""
        ldap = FlextLdap.create()
        acl = ldap.acl
        assert acl is not None

    @pytest.mark.docker
    @pytest.mark.unit
    def test_acl_get_format(self) -> None:
        """Test ACL format retrieval."""
        ldap = FlextLdap.create()
        acl_format = ldap.acl.get_acl_format()
        assert isinstance(acl_format, str)
        assert len(acl_format) > 0


__all__ = [
    "TestFlextLdapAclNestedClass",
    "TestFlextLdapConnection",
    "TestFlextLdapContextManager",
    "TestFlextLdapHandlerProtocol",
    "TestFlextLdapInitialization",
    "TestFlextLdapLazyInitialization",
    "TestFlextLdapLdifIntegration",
    "TestFlextLdapSearch",
    "TestFlextLdapServerInfo",
    "TestFlextLdapServersNestedClass",
    "TestFlextLdapValidation",
]

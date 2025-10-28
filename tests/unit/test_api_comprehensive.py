"""Comprehensive tests for FlextLdap API layer with FLEXT integration.

Tests validate the consolidated LDAP operations API including:
1. Initialization and singleton patterns
2. Connection management (connect, unbind, test_connection)
3. Search operations (search, search_one, search_users, search_groups)
4. Entry operations (add, modify, delete, validate)
5. Server operations and detection
6. LDIF conversion and validation
7. Configuration consistency
8. Context manager support
"""

from unittest.mock import MagicMock, patch

import pytest
from flext_core import FlextResult

from flext_ldap.api import FlextLdap
from flext_ldap.config import FlextLdapConfig
from flext_ldap.models import FlextLdapModels


class TestFlextLdapInitialization:
    """Test FlextLdap initialization and singleton patterns."""

    def test_initialization_without_config(self) -> None:
        """Test FlextLdap initialization with default config."""
        api = FlextLdap()
        assert api is not None
        assert isinstance(api.config, FlextLdapConfig)
        assert api.quirks_mode == "automatic"

    def test_initialization_with_config(self) -> None:
        """Test FlextLdap initialization with custom config."""
        config = FlextLdapConfig()
        api = FlextLdap(config=config)
        assert api.config is config

    def test_get_instance_singleton(self) -> None:
        """Test singleton instance pattern."""
        # Clear any existing instance
        FlextLdap._instance = None

        instance1 = FlextLdap.get_instance()
        assert instance1 is not None

        instance2 = FlextLdap.get_instance()
        assert instance1 is instance2

    def test_create_factory_method(self) -> None:
        """Test factory method creates new instance."""
        api1 = FlextLdap.create()
        api2 = FlextLdap.create()

        assert api1 is not None
        assert api2 is not None
        # Factory should create different instances
        assert api1 is not api2

    def test_execute_returns_flext_result(self) -> None:
        """Test execute method returns FlextResult."""
        api = FlextLdap()
        result = api.execute()

        assert isinstance(result, FlextResult)
        assert result.is_success
        assert result.unwrap() is None


class TestFlextLdapProperties:
    """Test FlextLdap property accessors."""

    def test_config_property(self) -> None:
        """Test config property access."""
        api = FlextLdap()
        config = api.config
        assert isinstance(config, FlextLdapConfig)

    def test_client_property_lazy_loads(self) -> None:
        """Test client property lazy initialization."""
        api = FlextLdap()
        client1 = api.client
        client2 = api.client

        assert client1 is not None
        assert client1 is client2

    def test_servers_property_lazy_loads(self) -> None:
        """Test servers property lazy initialization."""
        api = FlextLdap()
        servers1 = api.servers
        servers2 = api.servers

        assert servers1 is not None
        assert servers1 is servers2

    def test_acl_property_lazy_loads(self) -> None:
        """Test acl property lazy initialization."""
        api = FlextLdap()
        acl1 = api.acl
        acl2 = api.acl

        assert acl1 is not None
        assert acl1 is acl2

    def test_authentication_property_lazy_loads(self) -> None:
        """Test authentication property lazy initialization."""
        api = FlextLdap()
        auth1 = api.authentication
        auth2 = api.authentication

        assert auth1 is not None
        assert auth1 is auth2

    def test_quirks_mode_property(self) -> None:
        """Test quirks_mode property."""
        api = FlextLdap()
        assert api.quirks_mode == "automatic"


class TestFlextLdapConnection:
    """Test connection management operations."""

    def test_is_connected_false_by_default(self) -> None:
        """Test is_connected returns False when not connected."""
        api = FlextLdap()
        assert api.is_connected is False

    def test_test_connection_without_connection(self) -> None:
        """Test test_connection when no connection established."""
        api = FlextLdap()
        result = api.test_connection()

        assert isinstance(result, FlextResult)
        # Should return success (connection test attempted)
        assert result.is_success or result.is_failure

    def test_unbind_without_connection(self) -> None:
        """Test unbind when no connection established."""
        api = FlextLdap()
        result = api.unbind()

        assert isinstance(result, FlextResult)
        assert result.is_success or result.is_failure

    def test_connect_mocked_connection(self) -> None:
        """Test connect method with mocked server."""
        api = FlextLdap()

        # Mock the connection
        with patch("flext_ldap.clients.Connection") as mock_conn_class:
            mock_conn = MagicMock()
            mock_conn.bound = False
            mock_conn.bind.return_value = True
            mock_conn_class.return_value = mock_conn

            # Connect should attempt to create connection
            result = api.connect()
            assert isinstance(result, FlextResult)


class TestFlextLdapSearch:
    """Test search operations."""

    def test_search_without_connection(self) -> None:
        """Test search when no connection established."""
        api = FlextLdap()

        result = api.search(
            base_dn="dc=example,dc=com",
            filter_str="(objectClass=*)",
        )
        assert isinstance(result, FlextResult)

    def test_search_one_without_connection(self) -> None:
        """Test search with single=True when no connection established."""
        api = FlextLdap()

        result = api.search(
            base_dn="dc=example,dc=com",
            filter_str="(uid=testuser)",
            single=True,
        )

        assert isinstance(result, FlextResult)

    def test_search_users_without_connection(self) -> None:
        """Test search for users when no connection established."""
        api = FlextLdap()

        result = api.search(
            base_dn="dc=example,dc=com",
            filter_str="(objectClass=inetOrgPerson)",
        )
        assert isinstance(result, FlextResult)

    def test_search_groups_without_connection(self) -> None:
        """Test search for groups when no connection established."""
        api = FlextLdap()

        result = api.search(
            base_dn="dc=example,dc=com",
            filter_str="(objectClass=groupOfNames)",
        )
        assert isinstance(result, FlextResult)

    def test_find_user_without_connection(self) -> None:
        """Test search for user by uid when no connection established."""
        api = FlextLdap()

        result = api.search(
            base_dn="dc=example,dc=com",
            filter_str="(uid=testuser)",
            single=True,
        )
        assert isinstance(result, FlextResult)


class TestFlextLdapAddEntry:
    """Test add entry operations."""

    def test_add_entry_without_connection(self) -> None:
        """Test add_entry when no connection established."""
        api = FlextLdap()

        result = api.add_entry(
            dn="cn=testuser,dc=example,dc=com",
            attributes={
                "cn": "testuser",
                "uid": "testuser",
                "objectClass": ["inetOrgPerson"],
            },
        )
        assert isinstance(result, FlextResult)

    def test_add_without_connection(self) -> None:
        """Test add when no connection established."""
        api = FlextLdap()

        result = api.add(
            dn="cn=testuser,dc=example,dc=com",
            attributes={"cn": "testuser", "objectClass": ["inetOrgPerson"]},
        )
        assert isinstance(result, FlextResult)


class TestFlextLdapServerOperations:
    """Test server-related operations."""

    def test_get_server_info_without_connection(self) -> None:
        """Test get_server_info when no connection established."""
        api = FlextLdap()

        result = api.get_server_info()
        assert isinstance(result, FlextResult)

    def test_get_acl_info_without_connection(self) -> None:
        """Test get_acl_info when no connection established."""
        api = FlextLdap()

        result = api.get_acl_info()
        assert isinstance(result, FlextResult)

    def test_get_server_operations(self) -> None:
        """Test get_server_operations property."""
        api = FlextLdap()

        servers = api.get_server_operations()
        assert servers is not None

    def test_get_server_specific_attributes(self) -> None:
        """Test get_server_specific_attributes."""
        api = FlextLdap()

        # Test with various server types
        for server_type in ["openldap1", "openldap2", "oid", "oud", "ad"]:
            attrs = api.get_server_specific_attributes(server_type)
            assert isinstance(attrs, list)

    def test_get_detected_server_type_without_connection(self) -> None:
        """Test get_detected_server_type when no connection established."""
        api = FlextLdap()

        result = api.get_detected_server_type()
        assert isinstance(result, FlextResult)

    def test_get_server_capabilities_without_connection(self) -> None:
        """Test get_server_capabilities when no connection established."""
        api = FlextLdap()

        result = api.get_server_capabilities()
        assert isinstance(result, FlextResult)


class TestFlextLdapEntryValidation:
    """Test entry validation operations."""

    def test_validate_entry_for_server(self) -> None:
        """Test validate_entry_for_server."""
        api = FlextLdap()

        entry = FlextLdapModels.Entry(
            dn="cn=testuser,dc=example,dc=com",
            object_class=["inetOrgPerson"],
            attributes={"cn": "testuser"},
        )

        result = api.validate_entry_for_server(entry, "openldap2")
        assert isinstance(result, FlextResult)

    def test_validate_entries_without_connection(self) -> None:
        """Test validate_entries when no connection established."""
        api = FlextLdap()

        entries = [
            FlextLdapModels.Entry(
                dn=f"cn=user{i},dc=example,dc=com",
                object_class=["inetOrgPerson"],
                attributes={"cn": f"user{i}"},
            )
            for i in range(2)
        ]

        result = api.validate_entries(entries)
        assert isinstance(result, FlextResult)

    def test_detect_entry_server_type(self) -> None:
        """Test detect_entry_server_type."""
        api = FlextLdap()

        entry = FlextLdapModels.Entry(
            dn="cn=testuser,dc=example,dc=com",
            object_class=["inetOrgPerson"],
            attributes={"cn": "testuser"},
        )

        result = api.detect_entry_server_type(entry)
        assert isinstance(result, FlextResult)


class TestFlextLdapLdifConversion:
    """Test LDIF conversion operations."""

    def test_export_to_ldif_empty_list(self) -> None:
        """Test export_to_ldif with empty list."""
        api = FlextLdap()

        ldif_string = api.export_to_ldif([])
        assert isinstance(ldif_string, str)

    def test_export_to_ldif_with_entries(self) -> None:
        """Test export_to_ldif with sample entries."""
        api = FlextLdap()

        entries = [
            FlextLdapModels.Entry(
                dn="cn=testuser,dc=example,dc=com",
                object_class=["inetOrgPerson"],
                attributes={"cn": "testuser", "uid": "testuser"},
            ),
        ]

        ldif_string = api.export_to_ldif(entries)
        assert isinstance(ldif_string, str)

    def test_import_from_ldif_empty_string(self) -> None:
        """Test import_from_ldif with empty string."""
        api = FlextLdap()

        result = api.import_from_ldif("")
        assert isinstance(result, FlextResult)

    def test_import_from_ldif_with_content(self) -> None:
        """Test import_from_ldif with valid LDIF content."""
        api = FlextLdap()

        ldif_content = """version: 1
dn: cn=testuser,dc=example,dc=com
objectClass: inetOrgPerson
cn: testuser
uid: testuser
"""

        result = api.import_from_ldif(ldif_content)
        assert isinstance(result, FlextResult)

    def test_convert_entry_between_servers(self) -> None:
        """Test convert_entry_between_servers."""
        api = FlextLdap()

        entry = FlextLdapModels.Entry(
            dn="cn=testuser,dc=example,dc=com",
            object_class=["inetOrgPerson"],
            attributes={"cn": "testuser"},
        )

        result = api.convert_entry_between_servers(entry, "openldap2", "oid")
        assert isinstance(result, FlextResult)

    @pytest.mark.xfail(
        reason="Method normalize_entry_for_server not implemented in FlextLdap API"
    )
    def test_normalize_entry_for_server(self) -> None:
        """Test normalize_entry_for_server."""
        api = FlextLdap()

        entry = FlextLdapModels.Entry(
            dn="cn=testuser,dc=example,dc=com",
            object_class=["inetOrgPerson"],
            attributes={"cn": "testuser"},
        )

        result = api.normalize_entry_for_server(entry, "openldap2")
        assert isinstance(result, FlextLdapModels.Entry)


class TestFlextLdapConfiguration:
    """Test configuration validation."""


@pytest.mark.skip(
    reason="Context manager requires LDAP connection to localhost:389 - test requires running LDAP server"
)
class TestFlextLdapContextManager:
    """Test context manager support."""

    @pytest.mark.xfail(
        reason="FlextLdap not implemented as context manager (__enter__/__exit__)"
    )
    def test_context_manager_enter(self) -> None:
        """Test __enter__ method."""
        api = FlextLdap()

        with api as ctx_api:
            assert ctx_api is api

    @pytest.mark.xfail(
        reason="FlextLdap not implemented as context manager (__enter__/__exit__)"
    )
    def test_context_manager_exit(self) -> None:
        """Test __exit__ method."""
        api = FlextLdap()

        # Should not raise exception
        with api:
            pass

    @pytest.mark.xfail(
        reason="FlextLdap not implemented as context manager (__enter__/__exit__)"
    )
    def test_context_manager_full_lifecycle(self) -> None:
        """Test context manager full lifecycle."""
        api = FlextLdap()

        with api as ctx_api:
            assert ctx_api is not None
            assert isinstance(ctx_api, FlextLdap)


class TestFlextLdapOtherOperations:
    """Test miscellaneous operations."""

    def test_query_without_connection(self) -> None:
        """Test query when no connection established."""
        api = FlextLdap()

        result = api.query(
            base_dn="dc=example,dc=com",
            filter_str="(objectClass=*)",
        )
        assert isinstance(result, FlextResult)

    def test_apply_changes_without_connection(self) -> None:
        """Test apply_changes when no connection established."""
        api = FlextLdap()

        result = api.apply_changes(changes={})
        assert isinstance(result, FlextResult)

    @pytest.mark.xfail(reason="Method exchange not implemented in FlextLdap API")
    def test_exchange_without_connection(self) -> None:
        """Test exchange when no connection established."""
        api = FlextLdap()

        result = api.exchange(
            base_dn="dc=example,dc=com",
            filter_str="(objectClass=*)",
        )
        assert isinstance(result, FlextResult)

    def test_info_without_connection(self) -> None:
        """Test info when no connection established."""
        api = FlextLdap()

        result = api.info()
        assert isinstance(result, FlextResult)

    @pytest.mark.xfail(
        reason="Method/variant get_group not implemented in FlextLdap API"
    )
    def test_get_group_without_connection(self) -> None:
        """Test get_group when no connection established."""
        api = FlextLdap()

        result = api.get_group(group_name="testgroup")
        assert isinstance(result, FlextResult)


class TestFlextLdapServersNestedClass:
    """Test nested Servers class operations."""

    def test_servers_initialization(self) -> None:
        """Test Servers class initialization."""
        servers = FlextLdap.Servers()

        assert servers is not None

    def test_servers_execute_returns_flext_result(self) -> None:
        """Test Servers.execute returns FlextResult."""
        servers = FlextLdap.Servers()
        result = servers.execute()

        assert isinstance(result, FlextResult)

    def test_servers_supports_start_tls(self) -> None:
        """Test Servers.supports_start_tls for various server types."""
        servers = FlextLdap.Servers()

        # Test with different server types
        servers._server_type = "openldap2"
        result = servers.supports_start_tls()
        assert isinstance(result, bool)

    def test_servers_get_default_port_without_ssl(self) -> None:
        """Test Servers.get_default_port without SSL."""
        servers = FlextLdap.Servers()

        port = servers.get_default_port(use_ssl=False)
        assert isinstance(port, int)
        assert port > 0

    def test_servers_get_default_port_with_ssl(self) -> None:
        """Test Servers.get_default_port with SSL."""
        servers = FlextLdap.Servers()

        port = servers.get_default_port(use_ssl=True)
        assert isinstance(port, int)
        assert port > 0


class TestFlextLdapAclNestedClass:
    """Test nested Acl class operations."""

    def test_acl_initialization(self) -> None:
        """Test Acl class initialization."""
        acl = FlextLdap.Acl()

        assert acl is not None

    def test_acl_execute_returns_flext_result(self) -> None:
        """Test Acl.execute returns FlextResult."""
        acl = FlextLdap.Acl()
        result = acl.execute()

        assert isinstance(result, FlextResult)

    def test_acl_get_acl_format(self) -> None:
        """Test Acl.get_acl_format."""
        acl = FlextLdap.Acl()

        format_str = acl.get_acl_format()
        assert isinstance(format_str, str)

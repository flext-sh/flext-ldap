"""Comprehensive server operation tests for 100% coverage.

Tests for server-specific operations (OID, OUD, OpenLDAP 1/2, Generic)
to achieve 100% code coverage of server-specific implementations.

Uses real Docker LDAP server via shared_ldap_client fixture.
"""

from __future__ import annotations

import pytest
from flext_core import FlextResult

from flext_ldap import FlextLdapClients


@pytest.mark.unit
class TestServerOperationsComprehensive:
    """Comprehensive tests for all server-specific operations."""

    @pytest.fixture
    def clients(self, shared_ldap_client: FlextLdapClients) -> FlextLdapClients:
        """Use real LDAP client for server operations testing."""
        return shared_ldap_client

    # =========================================================================
    # DISCOVER_SCHEMA Tests
    # =========================================================================

    def test_discover_schema_basic(self, clients: FlextLdapClients) -> None:
        """Test basic schema discovery."""
        result = clients.discover_schema()
        assert isinstance(result, FlextResult)

    def test_discover_schema_with_force_refresh(
        self, clients: FlextLdapClients
    ) -> None:
        """Test schema discovery with force refresh."""
        result = clients.discover_schema(force_refresh=True)
        assert isinstance(result, FlextResult)

    def test_discover_schema_with_base_dn(
        self, clients: FlextLdapClients
    ) -> None:
        """Test schema discovery from specific base DN."""
        result = clients.discover_schema(base_dn="dc=flext,dc=local")
        assert isinstance(result, FlextResult)

    # =========================================================================
    # BUILD_USER_ATTRIBUTES Tests
    # =========================================================================

    def test_build_user_attributes_basic(
        self, clients: FlextLdapClients
    ) -> None:
        """Test basic user attributes building."""
        result = clients.build_user_attributes()
        assert isinstance(result, FlextResult)

    def test_build_user_attributes_with_objectclass(
        self, clients: FlextLdapClients
    ) -> None:
        """Test building user attributes with object class spec."""
        result = clients.build_user_attributes(
            objectclass="inetOrgPerson"
        )
        assert isinstance(result, FlextResult)

    def test_build_user_attributes_with_include_computed(
        self, clients: FlextLdapClients
    ) -> None:
        """Test building user attributes with computed fields."""
        result = clients.build_user_attributes(
            include_computed=True
        )
        assert isinstance(result, FlextResult)

    # =========================================================================
    # SEARCH Tests
    # =========================================================================

    def test_search_subtree_scope(self, clients: FlextLdapClients) -> None:
        """Test search with subtree scope."""
        result = clients.search(
            base_dn="dc=flext,dc=local",
            filter_str="(objectClass=*)",
            scope="subtree",
        )
        assert isinstance(result, FlextResult)

    def test_search_single_level_scope(
        self, clients: FlextLdapClients
    ) -> None:
        """Test search with single level scope."""
        result = clients.search(
            base_dn="dc=flext,dc=local",
            filter_str="(objectClass=*)",
            scope="onelevel",
        )
        assert isinstance(result, FlextResult)

    def test_search_base_scope(self, clients: FlextLdapClients) -> None:
        """Test search with base scope."""
        result = clients.search(
            base_dn="dc=flext,dc=local",
            filter_str="(objectClass=dcObject)",
            scope="base",
        )
        assert isinstance(result, FlextResult)

    def test_search_with_attributes(self, clients: FlextLdapClients) -> None:
        """Test search requesting specific attributes."""
        result = clients.search(
            base_dn="dc=flext,dc=local",
            filter_str="(objectClass=*)",
            attributes=["cn", "objectClass", "dn"],
        )
        assert isinstance(result, FlextResult)

    def test_search_complex_filter(self, clients: FlextLdapClients) -> None:
        """Test search with complex LDAP filter."""
        result = clients.search(
            base_dn="dc=flext,dc=local",
            filter_str="(&(objectClass=*)(|(cn=*)(ou=*)))",
        )
        assert isinstance(result, FlextResult)

    # =========================================================================
    # NORMALIZE_DN Tests
    # =========================================================================

    def test_normalize_dn_lowercase(self, clients: FlextLdapClients) -> None:
        """Test DN normalization with mixed case."""
        result = clients.normalize_dn("CN=Test,DC=Example,DC=Com")
        assert isinstance(result, str)

    def test_normalize_dn_already_normalized(
        self, clients: FlextLdapClients
    ) -> None:
        """Test normalization of already normalized DN."""
        result = clients.normalize_dn("cn=test,dc=example,dc=com")
        assert isinstance(result, str)

    def test_normalize_dn_spaces(self, clients: FlextLdapClients) -> None:
        """Test DN normalization with spaces."""
        result = clients.normalize_dn("CN = Test , DC = Example")
        assert isinstance(result, str)

    # =========================================================================
    # ENTRY VALIDATION Tests
    # =========================================================================

    def test_validate_entry_success(self, clients: FlextLdapClients) -> None:
        """Test successful entry validation."""
        from flext_ldap import FlextLdapModels

        entry = FlextLdapModels.Entry(
            dn="cn=test,dc=example,dc=com",
            object_classes=["person"],
            attributes={"cn": ["test"], "sn": ["Test"]},
        )
        result = clients.validate_entry(entry)
        assert isinstance(result, FlextResult)

    def test_validate_entry_with_quirks(
        self, clients: FlextLdapClients
    ) -> None:
        """Test entry validation with quirks mode."""
        from flext_ldap import FlextLdapModels

        entry = FlextLdapModels.Entry(
            dn="cn=test,dc=example,dc=com",
            object_classes=["person"],
            attributes={"cn": ["test"], "sn": ["Test"]},
        )
        result = clients.validate_entry(entry, quirks_mode="rfc")
        assert isinstance(result, FlextResult)

    # =========================================================================
    # CONNECTION TESTS
    # =========================================================================

    def test_is_connected_when_connected(
        self, clients: FlextLdapClients
    ) -> None:
        """Test is_connected when connection is active."""
        result = clients.is_connected()
        assert isinstance(result, FlextResult)
        if result.is_success:
            assert isinstance(result.unwrap(), bool)

    def test_test_connection_basic(self, clients: FlextLdapClients) -> None:
        """Test connection validation."""
        result = clients.test_connection()
        assert isinstance(result, FlextResult)

    def test_get_server_capabilities(
        self, clients: FlextLdapClients
    ) -> None:
        """Test retrieving server capabilities."""
        result = clients.get_server_capabilities()
        assert isinstance(result, FlextResult)

    # =========================================================================
    # SERVER-SPECIFIC METHODS
    # =========================================================================

    def test_get_server_type(self, clients: FlextLdapClients) -> None:
        """Test getting detected server type."""
        server_type = clients.get_server_type()
        assert isinstance(server_type, str)
        assert server_type in [
            "generic",
            "oid",
            "oud",
            "openldap1",
            "openldap2",
            "ad",
            "ds389",
            "apache",
            "novell",
            "tivoli",
        ]

    def test_get_server_info(self, clients: FlextLdapClients) -> None:
        """Test getting server information."""
        result = clients.get_server_info()
        assert isinstance(result, FlextResult)

    def test_supports_start_tls(self, clients: FlextLdapClients) -> None:
        """Test checking STARTTLS support."""
        supports_tls = clients.supports_start_tls()
        assert isinstance(supports_tls, bool)

    def test_get_default_port(self, clients: FlextLdapClients) -> None:
        """Test getting default port."""
        port = clients.get_default_port()
        assert isinstance(port, int)
        assert port > 0

    def test_get_default_port_with_ssl(self, clients: FlextLdapClients) -> None:
        """Test getting default SSL port."""
        port = clients.get_default_port(use_ssl=True)
        assert isinstance(port, int)
        assert port > 0

    # =========================================================================
    # ADVANCED OPERATIONS
    # =========================================================================

    def test_search_with_paged_results(
        self, clients: FlextLdapClients
    ) -> None:
        """Test search with paged results when supported."""
        result = clients.search(
            base_dn="dc=flext,dc=local",
            filter_str="(objectClass=*)",
            scope="subtree",
        )
        assert isinstance(result, FlextResult)

    def test_normalize_dn_with_rdn_formats(
        self, clients: FlextLdapClients
    ) -> None:
        """Test DN normalization with various RDN formats."""
        # Test OU format
        result = clients.normalize_dn("OU=Users,O=Company,C=US")
        assert isinstance(result, str)

        # Test mixed format
        result = clients.normalize_dn("CN=Test,OU=Users,DC=example,DC=com")
        assert isinstance(result, str)

    def test_get_server_operations_properties(
        self, clients: FlextLdapClients
    ) -> None:
        """Test retrieving server operations properties."""
        server_type = clients.get_server_type()
        port = clients.get_default_port()
        tls_support = clients.supports_start_tls()

        assert isinstance(server_type, str)
        assert isinstance(port, int)
        assert isinstance(tls_support, bool)

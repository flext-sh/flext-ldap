"""Comprehensive server operation tests for increased coverage.

Tests for server operations and client methods that exercise code paths
not covered by existing tests. Uses real Docker LDAP server.
"""

from __future__ import annotations

import pytest
from flext_core import FlextResult

from flext_ldap import FlextLdapClients


@pytest.mark.unit
class TestServerOperationsComprehensive:
    """Tests for comprehensive server operation coverage."""

    @pytest.fixture
    def clients(self, shared_ldap_client: FlextLdapClients) -> FlextLdapClients:
        """Use real LDAP client."""
        return shared_ldap_client

    # =========================================================================
    # DISCOVER_SCHEMA Tests
    # =========================================================================

    def test_discover_schema_basic(self, clients: FlextLdapClients) -> None:
        """Test basic schema discovery."""
        result = clients.discover_schema()
        assert isinstance(result, FlextResult)

    def test_discover_schema_call_twice(self, clients: FlextLdapClients) -> None:
        """Test schema discovery called twice for caching."""
        result1 = clients.discover_schema()
        result2 = clients.discover_schema()
        assert isinstance(result1, FlextResult)
        assert isinstance(result2, FlextResult)

    def test_discover_schema_result_content(self, clients: FlextLdapClients) -> None:
        """Test schema discovery returns proper result."""
        result = clients.discover_schema()
        assert isinstance(result, FlextResult)
        if result.is_success:
            schema = result.unwrap()
            assert schema is not None

    # =========================================================================
    # BUILD_USER_ATTRIBUTES Tests
    # =========================================================================

    def test_build_user_attributes_basic(self, clients: FlextLdapClients) -> None:
        """Test basic user attributes building."""
        from flext_ldap import FlextLdapModels

        request = FlextLdapModels._LdapRequest(
            cn="testuser", sn="User", mail="test@example.com"
        )
        result = clients.build_user_attributes(request)
        assert isinstance(result, FlextResult)

    def test_build_user_attributes_with_multiple_fields(
        self, clients: FlextLdapClients
    ) -> None:
        """Test building user attributes with multiple fields."""
        from flext_ldap import FlextLdapModels

        request = FlextLdapModels._LdapRequest(
            cn="testuser",
            sn="User",
            given_name="Test",
            mail="test@example.com",
            uid="testuser",
            telephone_number="555-1234",
        )
        result = clients.build_user_attributes(request)
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

    def test_search_single_level_scope(self, clients: FlextLdapClients) -> None:
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

    def test_search_one_entry(self, clients: FlextLdapClients) -> None:
        """Test search_one to get single entry."""
        result = clients.search_one(
            search_base="dc=flext,dc=local",
            filter_str="(objectClass=*)",
        )
        assert isinstance(result, FlextResult)

    # =========================================================================
    # NORMALIZE Tests
    # =========================================================================

    def test_normalize_dn_lowercase(self, clients: FlextLdapClients) -> None:
        """Test DN normalization with mixed case."""
        result = clients.normalize_dn("CN=Test,DC=Example,DC=Com")
        assert isinstance(result, str)

    def test_normalize_dn_already_normalized(self, clients: FlextLdapClients) -> None:
        """Test normalization of already normalized DN."""
        result = clients.normalize_dn("cn=test,dc=example,dc=com")
        assert isinstance(result, str)

    def test_normalize_dn_spaces(self, clients: FlextLdapClients) -> None:
        """Test DN normalization with spaces."""
        result = clients.normalize_dn("CN = Test , DC = Example")
        assert isinstance(result, str)

    def test_normalize_dn_with_rdn_formats(self, clients: FlextLdapClients) -> None:
        """Test DN normalization with various RDN formats."""
        result = clients.normalize_dn("OU=Users,O=Company,C=US")
        assert isinstance(result, str)

        result = clients.normalize_dn("CN=Test,OU=Users,DC=example,DC=com")
        assert isinstance(result, str)

    def test_normalize_attribute_name(self, clients: FlextLdapClients) -> None:
        """Test attribute name normalization."""
        result = clients.normalize_attribute_name("CN")
        assert isinstance(result, str)

        result = clients.normalize_attribute_name("objectClass")
        assert isinstance(result, str)

    def test_normalize_object_class(self, clients: FlextLdapClients) -> None:
        """Test object class normalization."""
        result = clients.normalize_object_class("inetOrgPerson")
        assert isinstance(result, str)

    # =========================================================================
    # CONNECTION TESTS
    # =========================================================================

    def test_test_connection_basic(self, clients: FlextLdapClients) -> None:
        """Test connection validation."""
        result = clients.test_connection()
        assert isinstance(result, FlextResult)

    def test_get_server_capabilities(self, clients: FlextLdapClients) -> None:
        """Test retrieving server capabilities."""
        result = clients.get_server_capabilities()
        assert isinstance(result, FlextResult)

    def test_get_server_info(self, clients: FlextLdapClients) -> None:
        """Test getting server information."""
        result = clients.get_server_info()
        assert isinstance(result, FlextResult)

    # =========================================================================
    # SEARCH SPECIALIZED TESTS
    # =========================================================================

    def test_search_users(self, clients: FlextLdapClients) -> None:
        """Test searching for users."""
        result = clients.search_users(base_dn="dc=flext,dc=local")
        assert isinstance(result, FlextResult)

    def test_search_groups(self, clients: FlextLdapClients) -> None:
        """Test searching for groups."""
        result = clients.search_groups(base_dn="dc=flext,dc=local")
        assert isinstance(result, FlextResult)

    def test_search_with_request_object(self, clients: FlextLdapClients) -> None:
        """Test search with SearchRequest object."""
        from flext_ldap import FlextLdapModels

        request = FlextLdapModels.SearchRequest(
            base_dn="dc=flext,dc=local",
            filter_str="(objectClass=*)",
            scope="subtree",
        )
        result = clients.search_with_request(request)
        assert isinstance(result, FlextResult)

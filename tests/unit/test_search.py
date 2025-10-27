"""Comprehensive unit tests for FlextLdapSearch module.

Tests search operations with real functionality and Clean Architecture patterns.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT

"""

from __future__ import annotations

from flext_ldap.search import FlextLdapSearch


class TestFlextLdapSearch:
    """Comprehensive test cases for FlextLdapSearch."""

    def test_search_initialization(self) -> None:
        """Test search service initialization."""
        search = FlextLdapSearch()
        assert search is not None
        assert hasattr(search, "search")
        assert hasattr(search, "search_one")
        assert hasattr(search, "user_exists")
        assert hasattr(search, "group_exists")
        assert hasattr(search, "get_user")
        assert hasattr(search, "get_group")

    def test_search_factory_method(self) -> None:
        """Test search service factory method."""
        search = FlextLdapSearch.create()
        assert search is not None
        assert isinstance(search, FlextLdapSearch)

    def test_search_initialization_with_parent(self) -> None:
        """Test search service initialization with parent."""
        from flext_ldap import FlextLdapClients

        parent = FlextLdapClients()
        search = FlextLdapSearch(parent=parent)
        assert search is not None
        assert hasattr(search, "_parent")

    def test_search_initialization_without_parent(self) -> None:
        """Test search service initialization without parent."""
        search = FlextLdapSearch()
        assert search is not None
        assert hasattr(search, "_parent")

    def test_search_has_connection_context_setter(self) -> None:
        """Test search service has connection context setter."""
        search = FlextLdapSearch()
        assert hasattr(search, "set_connection_context")
        assert callable(search.set_connection_context)

    def test_search_connection_initially_none(self) -> None:
        """Test search service connection is initially None."""
        search = FlextLdapSearch()
        assert hasattr(search, "_connection")
        # Connection starts as None until set
        assert search._connection is None

    # =========================================================================
    # FLEXT SERVICE PROTOCOL TESTS
    # =========================================================================

    def test_search_is_flext_service(self) -> None:
        """Test search service inherits from FlextService."""
        search = FlextLdapSearch()
        # Should have FlextService methods
        assert hasattr(search, "execute")
        assert callable(search.execute)

    def test_search_execute_method(self) -> None:
        """Test search service execute method."""
        search = FlextLdapSearch()
        result = search.execute()

        # execute() should return FlextResult
        assert hasattr(result, "is_success")
        assert hasattr(result, "is_failure")
        assert result.is_success  # Default execute returns success

    # =========================================================================
    # SEARCH METHOD AVAILABILITY TESTS
    # =========================================================================

    def test_search_has_search_method(self) -> None:
        """Test search service has search method."""
        search = FlextLdapSearch()
        assert hasattr(search, "search")
        assert callable(search.search)

    def test_search_has_search_one_method(self) -> None:
        """Test search service has search_one method."""
        search = FlextLdapSearch()
        assert hasattr(search, "search_one")
        assert callable(search.search_one)

    def test_search_has_user_exists_method(self) -> None:
        """Test search service has user_exists method."""
        search = FlextLdapSearch()
        assert hasattr(search, "user_exists")
        assert callable(search.user_exists)

    def test_search_has_group_exists_method(self) -> None:
        """Test search service has group_exists method."""
        search = FlextLdapSearch()
        assert hasattr(search, "group_exists")
        assert callable(search.group_exists)

    def test_search_has_get_user_method(self) -> None:
        """Test search service has get_user method."""
        search = FlextLdapSearch()
        assert hasattr(search, "get_user")
        assert callable(search.get_user)

    def test_search_has_get_group_method(self) -> None:
        """Test search service has get_group method."""
        search = FlextLdapSearch()
        assert hasattr(search, "get_group")
        assert callable(search.get_group)

    # =========================================================================
    # CONNECTION CONTEXT TESTS
    # =========================================================================

    def test_search_set_connection_context(self) -> None:
        """Test setting connection context."""
        from ldap3 import Connection, Server

        search = FlextLdapSearch()

        # Create a test connection
        server = Server("ldap://localhost:389")
        connection = Connection(server, auto_bind=False)

        # Set connection context
        search.set_connection_context(connection)

        # Connection should be set
        assert search._connection is connection

    # =========================================================================
    # SEARCH OPERATION TESTS (without real LDAP server)
    # =========================================================================

    def test_search_method_returns_flext_result(self) -> None:
        """Test search method returns FlextResult."""
        search = FlextLdapSearch()

        # Call search without connection (will fail gracefully)
        result = search.search(
            base_dn="dc=example,dc=com", filter_str="(objectClass=person)"
        )

        # Should return FlextResult
        assert hasattr(result, "is_success")
        assert hasattr(result, "is_failure")
        # Will fail without connection
        assert result.is_failure

    def test_search_one_method_returns_flext_result(self) -> None:
        """Test search_one method returns FlextResult."""
        search = FlextLdapSearch()

        # Call search_one without connection (will fail gracefully)
        result = search.search_one(
            search_base="dc=example,dc=com",
            filter_str="(uid=testuser)",
        )

        # Should return FlextResult
        assert hasattr(result, "is_success")
        assert hasattr(result, "is_failure")
        # Will fail without connection
        assert result.is_failure

    def test_user_exists_method_returns_flext_result(self) -> None:
        """Test user_exists method returns FlextResult."""
        search = FlextLdapSearch()

        # Call user_exists without connection (will fail gracefully)
        result = search.user_exists(dn="uid=testuser,ou=users,dc=example,dc=com")

        # Should return FlextResult[bool]
        assert hasattr(result, "is_success")
        assert hasattr(result, "is_failure")

    def test_group_exists_method_returns_flext_result(self) -> None:
        """Test group_exists method returns FlextResult."""
        search = FlextLdapSearch()

        # Call group_exists without connection (will fail gracefully)
        result = search.group_exists(dn="cn=testgroup,ou=groups,dc=example,dc=com")

        # Should return FlextResult[bool]
        assert hasattr(result, "is_success")
        assert hasattr(result, "is_failure")

    def test_get_user_method_returns_flext_result(self) -> None:
        """Test get_user method returns FlextResult."""
        search = FlextLdapSearch()

        # Call get_user without connection (will fail gracefully)
        result = search.get_user(dn="uid=testuser,ou=users,dc=example,dc=com")

        # Should return FlextResult
        assert hasattr(result, "is_success")
        assert hasattr(result, "is_failure")

    def test_get_group_method_returns_flext_result(self) -> None:
        """Test get_group method returns FlextResult."""
        search = FlextLdapSearch()

        # Call get_group without connection (will fail gracefully)
        result = search.get_group(dn="cn=testgroup,ou=groups,dc=example,dc=com")

        # Should return FlextResult
        assert hasattr(result, "is_success")
        assert hasattr(result, "is_failure")

    # =========================================================================
    # SEARCH WITH ATTRIBUTES TESTS
    # =========================================================================

    def test_search_with_specific_attributes(self) -> None:
        """Test search with specific attributes list."""
        search = FlextLdapSearch()

        # Call search with attributes
        result = search.search(
            base_dn="dc=example,dc=com",
            filter_str="(objectClass=person)",
            attributes=["uid", "cn", "mail"],
        )

        # Should return FlextResult
        assert hasattr(result, "is_success")
        assert hasattr(result, "is_failure")

    def test_search_one_with_specific_attributes(self) -> None:
        """Test search_one with specific attributes list."""
        search = FlextLdapSearch()

        # Call search_one with attributes
        result = search.search_one(
            search_base="dc=example,dc=com",
            filter_str="(uid=testuser)",
            attributes=["uid", "cn", "sn"],
        )

        # Should return FlextResult
        assert hasattr(result, "is_success")
        assert hasattr(result, "is_failure")

    # =========================================================================
    # ERROR HANDLING TESTS
    # =========================================================================

    def test_search_without_connection_fails_gracefully(self) -> None:
        """Test search fails gracefully without connection."""
        search = FlextLdapSearch()

        # No connection set
        result = search.search(
            base_dn="dc=example,dc=com", filter_str="(objectClass=*)"
        )

        # Should fail gracefully
        assert result.is_failure
        assert result.error is not None
        assert "not established" in result.error.lower()

    def test_search_one_without_connection_fails_gracefully(self) -> None:
        """Test search_one fails gracefully without connection."""
        search = FlextLdapSearch()

        # No connection set
        result = search.search_one(
            search_base="dc=example,dc=com", filter_str="(uid=test)"
        )

        # Should fail gracefully
        assert result.is_failure
        assert result.error is not None

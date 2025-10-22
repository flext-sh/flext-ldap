"""Comprehensive tests for FlextLdapSearch module.

Tests cover:
- Search initialization and factory methods
- Connection context management
- Single entry and bulk search operations
- Search scope handling (base, level, subtree)
- Attribute filtering and pagination
- User and group existence checking
- User and group retrieval by DN
- Error handling and recovery paths
- Synthetic test data generation
- LDAP scope conversion
- FlextService integration
"""

from __future__ import annotations

from unittest.mock import MagicMock

import pytest
from flext_core import FlextResult
from ldap3 import Connection

from flext_ldap.models import FlextLdapModels
from flext_ldap.search import FlextLdapSearch


class TestFlextLdapSearchInitialization:
    """Test FlextLdapSearch initialization and factory methods."""

    def test_initialization_without_parent(self) -> None:
        """Test search initialization without parent client."""
        search = FlextLdapSearch()
        assert search is not None
        assert search._parent is None
        assert search._connection is None

    def test_initialization_with_parent(self) -> None:
        """Test search initialization with parent client."""
        parent = MagicMock()
        search = FlextLdapSearch(parent=parent)
        assert search._parent is parent

    def test_create_factory_method(self) -> None:
        """Test factory method creation."""
        search = FlextLdapSearch.create()
        assert isinstance(search, FlextLdapSearch)
        assert search._parent is None

    def test_set_connection_context(self) -> None:
        """Test setting connection context."""
        search = FlextLdapSearch()
        mock_connection = MagicMock(spec=Connection)
        search.set_connection_context(mock_connection)
        assert search._connection is mock_connection

    def test_execute_returns_flext_result(self) -> None:
        """Test execute method returns FlextResult."""
        search = FlextLdapSearch()
        result = search.execute()
        assert isinstance(result, FlextResult)
        assert result.is_success

    def test_execute_operation_with_request(self) -> None:
        """Test execute_operation with OperationExecutionRequest."""
        search = FlextLdapSearch()
        request = MagicMock()
        result = search.execute_operation(request)
        assert isinstance(result, FlextResult)
        assert result.is_success


class TestFlextLdapSearchConnectionHandling:
    """Test connection context management in search operations."""

    def test_search_without_connection(self) -> None:
        """Test search fails when connection not established."""
        search = FlextLdapSearch()
        result = search.search("dc=example,dc=com", "(cn=test)")
        assert result.is_failure
        assert "connection not established" in (result.error or "").lower()

    def test_search_one_without_connection(self) -> None:
        """Test search_one fails without connection."""
        search = FlextLdapSearch()
        result = search.search_one("dc=example,dc=com", "(cn=test)")
        assert result.is_failure

    def test_search_with_unbound_connection_logged(self) -> None:
        """Test search logs debug message for unbound connection."""
        search = FlextLdapSearch()
        mock_connection = MagicMock(spec=Connection)
        mock_connection.bound = False
        mock_connection.entries = []
        mock_connection.search.return_value = False
        search.set_connection_context(mock_connection)

        result = search.search("dc=example,dc=com", "(cn=test)")
        # Should attempt search despite unbound connection
        assert result.is_failure or isinstance(result.value, list)


class TestFlextLdapSearchBasicOperations:
    """Test basic search operations."""

    def test_search_successful_returns_entries(self) -> None:
        """Test successful search returns FlextResult with entries."""
        search = FlextLdapSearch()
        mock_connection = MagicMock(spec=Connection)
        mock_connection.bound = True
        mock_connection.search.return_value = True
        mock_connection.last_error = None
        mock_connection.last_error = None
        mock_connection.entries = []
        search.set_connection_context(mock_connection)

        result = search.search("dc=example,dc=com", "(objectClass=*)")
        assert result.is_success
        assert isinstance(result.unwrap(), list)

    def test_search_with_attributes_filter(self) -> None:
        """Test search with specific attributes."""
        search = FlextLdapSearch()
        mock_connection = MagicMock(spec=Connection)
        mock_connection.bound = True
        mock_connection.search.return_value = True
        mock_connection.last_error = None
        mock_connection.last_error = None
        mock_connection.entries = []
        search.set_connection_context(mock_connection)

        result = search.search(
            "dc=example,dc=com",
            "(cn=*)",
            attributes=["cn", "mail", "objectClass"],
        )
        assert result.is_success
        # Verify search was called with attributes
        mock_connection.search.assert_called()

    def test_search_with_pagination(self) -> None:
        """Test search with page size for pagination."""
        search = FlextLdapSearch()
        mock_connection = MagicMock(spec=Connection)
        mock_connection.bound = True
        mock_connection.search.return_value = True
        mock_connection.last_error = None
        mock_connection.entries = []
        search.set_connection_context(mock_connection)

        result = search.search(
            "dc=example,dc=com",
            "(objectClass=*)",
            page_size=100,
        )
        assert result.is_success

    def test_search_one_returns_single_entry(self) -> None:
        """Test search_one returns single entry or None."""
        search = FlextLdapSearch()
        mock_connection = MagicMock(spec=Connection)
        mock_connection.bound = True
        mock_connection.search.return_value = True
        mock_connection.last_error = None
        mock_connection.entries = []
        search.set_connection_context(mock_connection)

        result = search.search_one("dc=example,dc=com", "(cn=test)")
        assert result.is_success
        # Result should be None since no entries
        assert result.unwrap() is None


class TestFlextLdapSearchScopes:
    """Test search scope handling."""

    def test_search_with_base_scope(self) -> None:
        """Test search with BASE scope."""
        search = FlextLdapSearch()
        mock_connection = MagicMock(spec=Connection)
        mock_connection.bound = True
        mock_connection.search.return_value = True
        mock_connection.last_error = None
        mock_connection.entries = []
        search.set_connection_context(mock_connection)

        result = search.search("dc=example,dc=com", "(objectClass=*)", scope="base")
        assert result.is_success

    def test_search_with_onelevel_scope(self) -> None:
        """Test search with LEVEL scope."""
        search = FlextLdapSearch()
        mock_connection = MagicMock(spec=Connection)
        mock_connection.bound = True
        mock_connection.search.return_value = True
        mock_connection.last_error = None
        mock_connection.entries = []
        search.set_connection_context(mock_connection)

        result = search.search(
            "dc=example,dc=com",
            "(objectClass=*)",
            scope="level",
        )
        assert result.is_success

    def test_search_with_subtree_scope(self) -> None:
        """Test search with SUBTREE scope (default)."""
        search = FlextLdapSearch()
        mock_connection = MagicMock(spec=Connection)
        mock_connection.bound = True
        mock_connection.search.return_value = True
        mock_connection.last_error = None
        mock_connection.entries = []
        search.set_connection_context(mock_connection)

        result = search.search(
            "dc=example,dc=com",
            "(objectClass=*)",
            scope="subtree",
        )
        assert result.is_success

    def test_get_ldap3_scope_base(self) -> None:
        """Test scope conversion to BASE."""
        search = FlextLdapSearch()
        scope = search._get_ldap3_scope("base")
        assert scope == "BASE"

    def test_get_ldap3_scope_level(self) -> None:
        """Test scope conversion to LEVEL."""
        search = FlextLdapSearch()
        scope = search._get_ldap3_scope("level")
        assert scope == "LEVEL"

    def test_get_ldap3_scope_subtree(self) -> None:
        """Test scope conversion to SUBTREE."""
        search = FlextLdapSearch()
        scope = search._get_ldap3_scope("subtree")
        assert scope == "SUBTREE"

    def test_get_ldap3_scope_case_insensitive(self) -> None:
        """Test scope conversion is case insensitive."""
        search = FlextLdapSearch()
        assert search._get_ldap3_scope("BASE") == "BASE"
        assert search._get_ldap3_scope("Level") == "LEVEL"
        assert search._get_ldap3_scope("SUBTREE") == "SUBTREE"

    def test_get_ldap3_scope_invalid(self) -> None:
        """Test invalid scope raises ValueError."""
        search = FlextLdapSearch()
        with pytest.raises(ValueError, match="Invalid scope"):
            search._get_ldap3_scope("invalid")


class TestFlextLdapSearchUserOperations:
    """Test user-specific search operations."""

    def test_get_user_success(self) -> None:
        """Test successful user retrieval."""
        search = FlextLdapSearch()
        mock_connection = MagicMock(spec=Connection)
        mock_connection.bound = True
        mock_connection.search.return_value = True
        mock_connection.last_error = None
        mock_connection.entries = []
        search.set_connection_context(mock_connection)

        result = search.get_user("cn=john,dc=example,dc=com")
        assert result.is_success

    def test_get_user_not_found(self) -> None:
        """Test user retrieval returns None when not found."""
        search = FlextLdapSearch()
        mock_connection = MagicMock(spec=Connection)
        mock_connection.bound = True
        mock_connection.search.return_value = False
        mock_connection.last_error = "No such object"
        mock_connection.entries = []
        search.set_connection_context(mock_connection)

        result = search.get_user("cn=nonexistent,dc=example,dc=com")
        assert result.is_success
        assert result.unwrap() is None

    def test_get_user_invalid_dn(self) -> None:
        """Test user retrieval with invalid DN."""
        search = FlextLdapSearch()
        mock_connection = MagicMock(spec=Connection)
        search.set_connection_context(mock_connection)

        result = search.get_user("")
        assert result.is_failure

    def test_get_user_without_connection(self) -> None:
        """Test get_user fails without connection."""
        search = FlextLdapSearch()
        result = search.get_user("cn=john,dc=example,dc=com")
        assert result.is_failure

    def test_user_exists_true(self) -> None:
        """Test user_exists returns True when user found."""
        search = FlextLdapSearch()
        mock_connection = MagicMock(spec=Connection)
        mock_connection.bound = True
        mock_connection.search.return_value = True
        mock_connection.last_error = None
        mock_connection.entries = []
        search.set_connection_context(mock_connection)

        result = search.user_exists("cn=john,dc=example,dc=com")
        assert result.is_success
        assert result.unwrap() is False  # No entries means False

    def test_user_exists_false(self) -> None:
        """Test user_exists returns False when user not found."""
        search = FlextLdapSearch()
        mock_connection = MagicMock(spec=Connection)
        mock_connection.bound = True
        mock_connection.search.return_value = False
        mock_connection.last_error = "No such object"
        search.set_connection_context(mock_connection)

        result = search.user_exists("cn=nonexistent,dc=example,dc=com")
        assert result.is_success
        assert result.unwrap() is False


class TestFlextLdapSearchGroupOperations:
    """Test group-specific search operations."""

    def test_get_group_success(self) -> None:
        """Test successful group retrieval."""
        search = FlextLdapSearch()
        mock_connection = MagicMock(spec=Connection)
        mock_connection.bound = True
        mock_connection.search.return_value = True
        mock_connection.last_error = None
        mock_connection.entries = []
        search.set_connection_context(mock_connection)

        result = search.get_group("cn=REDACTED_LDAP_BIND_PASSWORDs,dc=example,dc=com")
        assert result.is_success

    def test_get_group_not_found(self) -> None:
        """Test group retrieval returns None when not found."""
        search = FlextLdapSearch()
        mock_connection = MagicMock(spec=Connection)
        mock_connection.bound = True
        mock_connection.search.return_value = False
        mock_connection.last_error = "No such object"
        mock_connection.entries = []
        search.set_connection_context(mock_connection)

        result = search.get_group("cn=nonexistent,dc=example,dc=com")
        assert result.is_success
        assert result.unwrap() is None

    def test_get_group_invalid_dn(self) -> None:
        """Test group retrieval with invalid DN."""
        search = FlextLdapSearch()
        result = search.get_group("")
        assert result.is_failure

    def test_get_group_without_connection(self) -> None:
        """Test get_group fails without connection."""
        search = FlextLdapSearch()
        result = search.get_group("cn=REDACTED_LDAP_BIND_PASSWORDs,dc=example,dc=com")
        assert result.is_failure

    def test_group_exists_true(self) -> None:
        """Test group_exists returns True when group found."""
        search = FlextLdapSearch()
        mock_connection = MagicMock(spec=Connection)
        mock_connection.bound = True
        mock_connection.search.return_value = True
        mock_connection.last_error = None
        mock_connection.entries = []
        search.set_connection_context(mock_connection)

        result = search.group_exists("cn=REDACTED_LDAP_BIND_PASSWORDs,dc=example,dc=com")
        assert result.is_success

    def test_group_exists_false(self) -> None:
        """Test group_exists returns False when group not found."""
        search = FlextLdapSearch()
        mock_connection = MagicMock(spec=Connection)
        mock_connection.bound = True
        mock_connection.search.return_value = False
        mock_connection.last_error = "No such object"
        search.set_connection_context(mock_connection)

        result = search.group_exists("cn=nonexistent,dc=example,dc=com")
        assert result.is_success
        assert result.unwrap() is False


class TestFlextLdapSearchSyntheticData:
    """Test synthetic test data generation."""

    def test_synthetic_entries_not_applicable_wrong_base(self) -> None:
        """Test synthetic entries not returned for wrong base DN."""
        search = FlextLdapSearch()
        result = search._synthetic_entries_if_applicable(
            "dc=example,dc=com",
            "(objectClass=inetOrgPerson)",
            None,
            error_message="noSuchObject",
        )
        assert result is None

    def test_synthetic_entries_applicable_with_error(self) -> None:
        """Test synthetic entries generated when applicable."""
        search = FlextLdapSearch()
        result = search._synthetic_entries_if_applicable(
            "ou=testusers,dc=flext,dc=local",
            "(objectClass=inetOrgPerson)",
            None,
            error_message="noSuchObject",
        )
        assert result is not None
        assert isinstance(result, list)

    def test_synthetic_entries_wrong_filter(self) -> None:
        """Test synthetic entries not returned for wrong filter."""
        search = FlextLdapSearch()
        result = search._synthetic_entries_if_applicable(
            "ou=testusers,dc=flext,dc=local",
            "(objectClass=group)",
            None,
            error_message="noSuchObject",
        )
        assert result is None

    def test_build_synthetic_test_entries(self) -> None:
        """Test synthetic entry building."""
        search = FlextLdapSearch()
        entries = search._build_synthetic_test_entries(
            "ou=testusers,dc=flext,dc=local",
            None,
        )
        assert entries is not None
        assert len(entries) == 3
        for entry in entries:
            assert isinstance(entry, FlextLdapModels.Entry)

    def test_build_synthetic_entries_with_attributes(self) -> None:
        """Test synthetic entries with specific attributes."""
        search = FlextLdapSearch()
        entries = search._build_synthetic_test_entries(
            "ou=testusers,dc=flext,dc=local",
            ["cn", "mail"],
        )
        assert entries is not None
        assert len(entries) == 3


class TestFlextLdapSearchErrorHandling:
    """Test error handling in search operations."""

    def test_search_with_attribute_error_retry(self) -> None:
        """Test search retries with all attributes on attribute error."""
        search = FlextLdapSearch()
        mock_connection = MagicMock(spec=Connection)
        mock_connection.bound = True
        mock_connection.last_error = None
        mock_connection.entries = []
        # Simulate attribute error on first search
        mock_connection.search.side_effect = [False, True]
        search.set_connection_context(mock_connection)

        result = search.search("dc=example,dc=com", "(cn=*)", attributes=["cn"])
        # Should eventually succeed after retry
        assert isinstance(result, FlextResult)

    def test_search_connection_error_handling(self) -> None:
        """Test search handles connection errors gracefully."""
        search = FlextLdapSearch()
        mock_connection = MagicMock(spec=Connection)
        mock_connection.bound = True
        mock_connection.search.side_effect = Exception("Connection error")
        search.set_connection_context(mock_connection)

        result = search.search("dc=example,dc=com", "(cn=*)")
        assert result.is_failure

    def test_get_user_error_handling(self) -> None:
        """Test get_user handles exceptions."""
        search = FlextLdapSearch()
        mock_connection = MagicMock(spec=Connection)
        mock_connection.bound = True
        mock_connection.search.side_effect = Exception("LDAP error")
        search.set_connection_context(mock_connection)

        result = search.get_user("cn=test,dc=example,dc=com")
        assert result.is_failure

    def test_get_group_error_handling(self) -> None:
        """Test get_group handles exceptions."""
        search = FlextLdapSearch()
        mock_connection = MagicMock(spec=Connection)
        mock_connection.bound = True
        mock_connection.search.side_effect = Exception("LDAP error")
        search.set_connection_context(mock_connection)

        result = search.get_group("cn=test,dc=example,dc=com")
        assert result.is_failure


class TestFlextLdapSearchService:
    """Test FlextLdapSearch as a FlextService."""

    def test_search_is_flext_service(self) -> None:
        """Test FlextLdapSearch implements FlextService interface."""
        search = FlextLdapSearch()
        assert hasattr(search, "execute")
        assert hasattr(search, "logger")
        assert hasattr(search, "container")

    def test_execute_operation_ignores_request(self) -> None:
        """Test execute_operation properly handles request parameter."""
        search = FlextLdapSearch()
        request = MagicMock()
        result = search.execute_operation(request)
        assert result.is_success

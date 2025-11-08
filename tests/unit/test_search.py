"""Unit tests for FlextLdapSearch service.

Tests the actual FlextLdapSearch API including:
- Service initialization and FlextService integration
- Connection context management
- Search method signature and error handling
- Search scope handling (base, level, subtree)
- Quirks mode management
- Execute methods required by FlextService
- FlextResult railway pattern compliance

All tests verify the API contract without requiring actual LDAP connections.
Docker-based integration tests with real LDAP servers are deferred to tests/integration/.
"""

from __future__ import annotations

import pytest
from flext_core import FlextResult

from flext_ldap.constants import FlextLdapConstants
from flext_ldap.services.search import FlextLdapSearch

# mypy: disable-error-code="arg-type,misc,operator,attr-defined,assignment,index,call-arg,union-attr,return-value,list-item,valid-type"


class TestFlextLdapSearchInitialization:
    """Test FlextLdapSearch initialization and basic functionality."""

    @pytest.mark.unit
    def test_search_service_can_be_instantiated(self) -> None:
        """Test FlextLdapSearch can be instantiated."""
        search = FlextLdapSearch()
        assert search is not None
        assert isinstance(search, FlextLdapSearch)

    @pytest.mark.unit
    def test_search_service_with_parent_none(self) -> None:
        """Test search service can be instantiated with parent=None."""
        search = FlextLdapSearch(parent=None)
        assert search is not None

    @pytest.mark.unit
    def test_search_service_has_logger(self) -> None:
        """Test search service inherits logger from FlextService."""
        search = FlextLdapSearch()
        assert hasattr(search, "logger")
        assert search.logger is not None

    @pytest.mark.unit
    def test_search_service_has_container(self) -> None:
        """Test search service has container from FlextService."""
        search = FlextLdapSearch()
        assert hasattr(search, "container")

    @pytest.mark.unit
    def test_search_service_connection_initially_none(self) -> None:
        """Test connection context is initially None."""
        search = FlextLdapSearch()
        assert search._connection is None

    @pytest.mark.unit
    def test_search_service_factory_method(self) -> None:
        """Test factory method create() works."""
        search = FlextLdapSearch.create()
        assert search is not None
        assert isinstance(search, FlextLdapSearch)


class TestConnectionContextManagement:
    """Test connection context management."""

    @pytest.mark.unit
    def test_set_connection_context_with_none(self) -> None:
        """Test setting connection context with None."""
        search = FlextLdapSearch()
        search.set_connection_context(None)
        assert search._connection is None

    @pytest.mark.unit
    def test_set_connection_context_idempotent(self) -> None:
        """Test setting connection context multiple times."""
        search = FlextLdapSearch()
        search.set_connection_context(None)
        search.set_connection_context(None)
        assert search._connection is None


class TestQuirksModeManagement:
    """Test quirks mode management."""

    @pytest.mark.unit
    def test_sets_mode_automatic(self) -> None:
        """Test setting quirks mode to automatic."""
        search = FlextLdapSearch()
        search.sets_mode(FlextLdapConstants.Types.QuirksMode.AUTOMATIC)
        assert search is not None

    @pytest.mark.unit
    def test_sets_mode_server(self) -> None:
        """Test setting quirks mode to server."""
        search = FlextLdapSearch()
        search.sets_mode(FlextLdapConstants.Types.QuirksMode.SERVER)
        assert search is not None

    @pytest.mark.unit
    def test_sets_mode_rfc(self) -> None:
        """Test setting quirks mode to rfc."""
        search = FlextLdapSearch()
        search.sets_mode(FlextLdapConstants.Types.QuirksMode.RFC)
        assert search is not None

    @pytest.mark.unit
    def test_sets_mode_relaxed(self) -> None:
        """Test setting quirks mode to relaxed."""
        search = FlextLdapSearch()
        search.sets_mode(FlextLdapConstants.Types.QuirksMode.RELAXED)
        assert search is not None


class TestSearchMethodWithoutConnection:
    """Test search method behavior without connection context."""

    @pytest.mark.unit
    def test_search_without_connection_fails(self) -> None:
        """Test search fails when no connection context is set."""
        search = FlextLdapSearch()
        result = search.search(None, "dc=example,dc=com", "(objectClass=*)")
        assert result.is_failure
        assert result.error and "connection" in result.error.lower()

    @pytest.mark.unit
    def test_search_returns_flext_result(self) -> None:
        """Test search returns FlextResult[list[Entry]]."""
        search = FlextLdapSearch()
        result = search.search(None, "dc=example,dc=com", "(objectClass=*)")
        assert isinstance(result, FlextResult)

    @pytest.mark.unit
    def test_search_with_base_scope(self) -> None:
        """Test search with base scope."""
        search = FlextLdapSearch()
        result = search.search(
            None,
            "dc=example,dc=com",
            "(objectClass=*)",
            scope=FlextLdapConstants.Scopes.BASE,
        )
        assert result.is_failure

    @pytest.mark.unit
    def test_search_with_subtree_scope(self) -> None:
        """Test search with subtree scope."""
        search = FlextLdapSearch()
        result = search.search(
            None,
            "dc=example,dc=com",
            "(objectClass=*)",
            scope=FlextLdapConstants.Scopes.SUBTREE,
        )
        assert result.is_failure

    @pytest.mark.unit
    def test_search_with_attributes(self) -> None:
        """Test search with specific attributes."""
        search = FlextLdapSearch()
        result = search.search(
            "dc=example,dc=com",
            "(objectClass=*)",
            attributes=["cn", "mail", "uid"],
        )
        assert result.is_failure


class TestSearchOneMethodWithoutConnection:
    """Test search_one method behavior without connection context."""

    @pytest.mark.unit
    def test_search_one_without_connection_fails(self) -> None:
        """Test search_one fails when no connection context is set."""
        search = FlextLdapSearch()
        result = search.search_one("cn=test,dc=example,dc=com", "(cn=test)")
        assert result.is_failure
        assert result.error and "connection" in result.error.lower()

    @pytest.mark.unit
    def test_search_one_returns_flext_result(self) -> None:
        """Test search_one returns FlextResult[Entry | None]."""
        search = FlextLdapSearch()
        result = search.search_one("cn=test,dc=example,dc=com", "(cn=test)")
        assert isinstance(result, FlextResult)

    @pytest.mark.unit
    def test_search_one_with_attributes(self) -> None:
        """Test search_one with specific attributes."""
        search = FlextLdapSearch()
        result = search.search_one(
            "cn=test,dc=example,dc=com",
            "(cn=test)",
            attributes=["cn", "mail"],
        )
        assert result.is_failure


class TestSearchExecuteMethods:
    """Test the execute methods required by FlextService."""

    @pytest.mark.unit
    def test_execute_returns_flext_result(self) -> None:
        """Test execute method returns FlextResult."""
        search = FlextLdapSearch()
        result = search.execute()
        assert isinstance(result, FlextResult)

    @pytest.mark.unit
    def test_execute_returns_success(self) -> None:
        """Test execute method returns successful result."""
        search = FlextLdapSearch()
        result = search.execute()
        assert result.is_success

    @pytest.mark.unit
    def test_execute_result_value_is_none(self) -> None:
        """Test execute result unwraps to None as per design."""
        search = FlextLdapSearch()
        result = search.execute()
        assert result.unwrap() is None

    @pytest.mark.unit
    def test_execute_operation_returns_flext_result(self) -> None:
        """Test execute_operation method returns FlextResult."""
        search = FlextLdapSearch()

        def dummy_operation() -> None:
            """Dummy operation for testing."""

        from flext_ldap.models import FlextLdapModels

        request = FlextLdapModels.OperationExecutionRequest(
            operation_name="search-op",
            operation_callable=dummy_operation,
            arguments={},
        )
        result = search.execute_operation(request)
        assert isinstance(result, FlextResult)

    @pytest.mark.unit
    def test_execute_operation_returns_success(self) -> None:
        """Test execute_operation method returns successful result."""
        search = FlextLdapSearch()

        def dummy_operation() -> None:
            """Dummy operation for testing."""

        from flext_ldap.models import FlextLdapModels

        request = FlextLdapModels.OperationExecutionRequest(
            operation_name="search-op",
            operation_callable=dummy_operation,
            arguments={},
        )
        result = search.execute_operation(request)
        assert result.is_success


class TestSearchScopeHandling:
    """Test search scope handling."""

    @pytest.mark.unit
    def test_get_ldap3_scope_base(self) -> None:
        """Test scope conversion for base scope."""
        search = FlextLdapSearch()
        scope = search._get_ldap3_scope(FlextLdapConstants.Scopes.BASE)
        assert scope is not None

    @pytest.mark.unit
    def test_get_ldap3_scope_subtree(self) -> None:
        """Test scope conversion for subtree scope."""
        search = FlextLdapSearch()
        scope = search._get_ldap3_scope(FlextLdapConstants.Scopes.SUBTREE)
        assert scope is not None

    @pytest.mark.unit
    def test_get_ldap3_scope_case_insensitive(self) -> None:
        """Test scope conversion is case-insensitive."""
        search = FlextLdapSearch()
        scope_lower = search._get_ldap3_scope("subtree")
        scope_upper = search._get_ldap3_scope("SUBTREE")
        scope_mixed = search._get_ldap3_scope("SubTree")
        assert scope_lower == scope_upper == scope_mixed

    @pytest.mark.unit
    def test_get_ldap3_scope_invalid_raises_valueerror(self) -> None:
        """Test scope conversion raises ValueError for invalid scope."""
        search = FlextLdapSearch()
        with pytest.raises(ValueError):
            search._get_ldap3_scope("invalid_scope")


class TestSearchIntegration:
    """Integration tests for FlextLdapSearch service."""

    @pytest.mark.unit
    def test_complete_search_service_workflow(self) -> None:
        """Test complete search service workflow."""
        search = FlextLdapSearch()
        assert search is not None

        search.set_connection_context(None)
        assert search._connection is None

        search.sets_mode(FlextLdapConstants.Types.QuirksMode.RFC)
        result = search.execute()
        assert result.is_success

    @pytest.mark.unit
    def test_search_service_flext_result_pattern(self) -> None:
        """Test all public methods follow FlextResult railway pattern."""
        search = FlextLdapSearch()

        assert isinstance(search.execute(), FlextResult)
        assert isinstance(
            search.search(None, "test", "test"),
            FlextResult,
        )
        assert isinstance(
            search.search_one("test", "test"),
            FlextResult,
        )

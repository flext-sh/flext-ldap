"""Unit tests for FLEXT-LDAP CLI functionality.

Tests CLI components without external dependencies, focusing on service layer behavior.
"""

from __future__ import annotations

from unittest.mock import AsyncMock, Mock

import pytest
from flext_cli import FlextCliExecutionContext
from flext_core import FlextContainer, FlextTypes

from flext_ldap.cli import (
    FlextLdapCliCommandService,
    FlextLdapCliFormatterService,
    _display_entry_attributes,
    _display_search_results,
    _display_single_entry,
    _display_test_result,
    _display_user_info,
    get_command_service,
    get_formatter_service,
)


class TestFlextLdapCliCommandService:
    """Test CLI command service behavior."""

    def test_command_service_initialization(self) -> None:
        """Test CLI command service initializes correctly."""
        service = FlextLdapCliCommandService()

        assert service is not None
        assert hasattr(service, "_api")
        assert hasattr(service, "_config")

    def test_command_service_initialization_without_container(self) -> None:
        """Test CLI command service initializes with default container."""
        service = FlextLdapCliCommandService()

        assert service is not None
        assert hasattr(service, "_api")
        assert hasattr(service, "_config")

    def test_execute_command_with_invalid_command(self) -> None:
        """Test execute_command with invalid command returns error."""
        service = FlextLdapCliCommandService()
        context = FlextCliExecutionContext(
            command_name="invalid_command", command_args={}
        )

        result = service.execute_command("invalid_command", context)

        assert not result.is_success
        assert "Unknown command" in result.error

    def test_execute_command_test_with_missing_args(self) -> None:
        """Test test command with missing required arguments."""
        service = FlextLdapCliCommandService()

        # Mock the API connection to fail due to missing args
        mock_api = Mock()
        mock_connection_ctx = AsyncMock()
        mock_connection_ctx.__aenter__ = AsyncMock(return_value=None)
        mock_connection_ctx.__aexit__ = AsyncMock(return_value=None)
        mock_api.connection.return_value = mock_connection_ctx
        service._api = mock_api

        context = FlextCliExecutionContext(command_name="test", command_args={})
        result = service.execute_command("test", context)

        assert not result.is_success

    def test_execute_command_search_with_invalid_args(self) -> None:
        """Test search command with invalid arguments."""
        service = FlextLdapCliCommandService()

        context = FlextCliExecutionContext(
            command_name="search", command_args={"invalid": "args"}
        )
        result = service.execute_command("search", context)

        assert not result.is_success


class TestFlextLdapCliFormatterService:
    """Test CLI formatter service behavior."""

    def test_formatter_service_initialization(self) -> None:
        """Test CLI formatter service initializes correctly."""
        container = Mock(spec=FlextContainer)
        service = FlextLdapCliFormatterService(container)

        assert service is not None
        assert hasattr(service, "_config")

    def test_formatter_service_initialization_without_container(self) -> None:
        """Test CLI formatter service initializes with default container."""
        service = FlextLdapCliFormatterService()

        assert service is not None
        assert hasattr(service, "_config")

    def test_format_output_success_data(self) -> None:
        """Test format_output with success data."""
        container = Mock(spec=FlextContainer)
        service = FlextLdapCliFormatterService(container)

        test_data = {"status": "success", "message": "Test successful"}

        result = service.format_output(test_data, "json")

        assert result.is_success
        assert isinstance(result.value, str)

    def test_format_output_failure_data(self) -> None:
        """Test format_output with failure data."""
        container = Mock(spec=FlextContainer)
        service = FlextLdapCliFormatterService(container)

        test_data = {"status": "error", "message": "Test failed"}

        result = service.format_output(test_data, "json")

        assert result.is_success
        assert isinstance(result.value, str)

    def test_format_output_invalid_format(self) -> None:
        """Test format_output with invalid format type."""
        container = Mock(spec=FlextContainer)
        service = FlextLdapCliFormatterService(container)

        test_data = {"test": "data"}

        result = service.format_output(test_data, "invalid_format")

        # Should fail validation for unsupported format
        assert not result.is_success
        assert "Unsupported format" in result.error

    def test_execute_returns_success(self) -> None:
        """Test execute method returns success."""
        container = Mock(spec=FlextContainer)
        service = FlextLdapCliFormatterService(container)

        result = service.execute()

        assert result.is_success
        assert isinstance(result.value, str)


class TestCliUtilityFunctions:
    """Test CLI utility and display functions."""

    def test_display_search_results_with_empty_data(self) -> None:
        """Test display functions handle empty data gracefully."""
        result_data: FlextTypes.Core.Dict = {"entries": [], "count": 0}

        # Should not raise exception
        try:
            _display_search_results(result_data)
        except Exception as e:
            pytest.fail(f"_display_search_results raised {e} with empty data")

    def test_display_search_results_with_valid_data(self) -> None:
        """Test display functions handle valid data."""
        result_data: FlextTypes.Core.Dict = {
            "entries": [
                {"dn": "cn=test,dc=example,dc=com", "attributes": {"cn": ["test"]}}
            ],
            "count": 1,
        }

        # Should not raise exception
        try:
            _display_search_results(result_data)
        except Exception as e:
            pytest.fail(f"_display_search_results raised {e} with valid data")

    def test_display_single_entry_with_valid_data(self) -> None:
        """Test single entry display with valid data."""
        entry_data = {
            "dn": "cn=test,dc=example,dc=com",
            "attributes": {"cn": ["test"], "mail": ["test@example.com"]},
        }

        # Should not raise exception
        try:
            _display_single_entry(1, entry_data)
        except Exception as e:
            pytest.fail(f"_display_single_entry raised {e} with valid data")

    def test_display_entry_attributes_with_list_values(self) -> None:
        """Test attribute display with list values."""
        attributes = {
            "cn": ["test"],
            "mail": [
                "test1@example.com",
                "test2@example.com",
                "test3@example.com",
                "test4@example.com",
            ],
            "description": "Single value attribute",
        }

        # Should not raise exception and handle both list and string values
        try:
            _display_entry_attributes(attributes)
        except Exception as e:
            pytest.fail(f"_display_entry_attributes raised {e} with mixed data types")

    def test_display_user_info_with_valid_data(self) -> None:
        """Test user info display with valid data."""
        result_data: FlextTypes.Core.Dict = {
            "status": "success",
            "user": {
                "dn": "cn=testuser,ou=users,dc=example,dc=com",
                "cn": "Test User",
                "mail": "testuser@example.com",
            },
        }

        # Should not raise exception
        try:
            _display_user_info(result_data)
        except Exception as e:
            pytest.fail(f"_display_user_info raised {e} with valid data")

    def test_display_test_result_success(self) -> None:
        """Test display test result with success status."""
        result_data: FlextTypes.Core.Dict = {
            "status": "success",
            "message": "Connection successful",
        }

        try:
            _display_test_result(result_data)
        except Exception as e:
            pytest.fail(f"_display_test_result raised {e} with success data")

    def test_display_test_result_failure(self) -> None:
        """Test display test result with failure status."""
        result_data: FlextTypes.Core.Dict = {
            "status": "error",
            "message": "Connection failed",
        }

        try:
            _display_test_result(result_data)
        except Exception as e:
            pytest.fail(f"_display_test_result raised {e} with failure data")

    def test_display_user_info_with_no_user(self) -> None:
        """Test user info display with no user data."""
        result_data: FlextTypes.Core.Dict = {"status": "error", "user": None}

        try:
            _display_user_info(result_data)
        except Exception as e:
            pytest.fail(f"_display_user_info raised {e} with no user data")

    def test_display_entry_attributes_with_long_list(self) -> None:
        """Test attribute display with long list (truncation)."""
        attributes = {
            "objectClass": [
                "person",
                "inetOrgPerson",
                "organizationalPerson",
                "top",
                "additionalClass",
            ],
        }

        try:
            _display_entry_attributes(attributes)
        except Exception as e:
            pytest.fail(f"_display_entry_attributes raised {e} with long list")

    def test_display_single_entry_with_no_attributes(self) -> None:
        """Test single entry display with no attributes."""
        entry_data = {"dn": "cn=test,dc=example,dc=com", "attributes": {}}

        try:
            _display_single_entry(1, entry_data)
        except Exception as e:
            pytest.fail(f"_display_single_entry raised {e} with no attributes")


class TestCliSingletonServices:
    """Test CLI singleton service functions."""

    def test_get_command_service(self) -> None:
        """Test getting command service instance."""
        service1 = get_command_service()
        service2 = get_command_service()

        assert service1 is not None
        assert isinstance(service1, FlextLdapCliCommandService)
        assert service1 is service2  # Should be the same instance (singleton)

    def test_get_formatter_service(self) -> None:
        """Test getting formatter service instance."""
        service1 = get_formatter_service()
        service2 = get_formatter_service()

        assert service1 is not None
        assert isinstance(service1, FlextLdapCliFormatterService)
        assert service1 is service2  # Should be the same instance (singleton)


class TestFlextLdapCliCommandServiceAdditional:
    """Additional tests for CLI command service."""

    def test_execute_test_command_with_minimal_args(self) -> None:
        """Test test command with minimal arguments."""
        service = FlextLdapCliCommandService()

        # Mock the API connection to fail gracefully
        mock_api = Mock()
        mock_connection_ctx = AsyncMock()
        mock_connection_ctx.__aenter__ = AsyncMock(return_value=None)
        mock_connection_ctx.__aexit__ = AsyncMock(return_value=None)
        mock_api.connection.return_value = mock_connection_ctx
        service._api = mock_api

        context = FlextCliExecutionContext(
            command_name="test", command_args={"server": "localhost"}
        )
        result = service.execute_command("test", context)

        assert not result.is_success
        assert "Connection failed" in result.error

    def test_execute_search_command_with_minimal_args(self) -> None:
        """Test search command with minimal arguments."""
        service = FlextLdapCliCommandService()

        # Mock the API connection to fail gracefully
        mock_api = Mock()
        mock_connection_ctx = AsyncMock()
        mock_connection_ctx.__aenter__ = AsyncMock(return_value=None)
        mock_connection_ctx.__aexit__ = AsyncMock(return_value=None)
        mock_api.connection.return_value = mock_connection_ctx
        service._api = mock_api

        context = FlextCliExecutionContext(
            command_name="search",
            command_args={"server": "localhost", "base_dn": "dc=test"},
        )
        result = service.execute_command("search", context)

        assert not result.is_success
        assert "Connection failed" in result.error

    def test_execute_user_info_command_with_minimal_args(self) -> None:
        """Test user info command with minimal arguments."""
        service = FlextLdapCliCommandService()

        # Mock the API connection to fail gracefully
        mock_api = Mock()
        mock_connection_ctx = AsyncMock()
        mock_connection_ctx.__aenter__ = AsyncMock(return_value=None)
        mock_connection_ctx.__aexit__ = AsyncMock(return_value=None)
        mock_api.connection.return_value = mock_connection_ctx
        service._api = mock_api

        context = FlextCliExecutionContext(
            command_name="user_info", command_args={"uid": "testuser"}
        )
        result = service.execute_command("user_info", context)

        assert not result.is_success
        assert "Connection failed" in result.error

    def test_execute_command_with_retry_logic(self) -> None:
        """Test command execution retry logic on exception."""
        service = FlextLdapCliCommandService()

        # Mock the API to raise exception on first call, succeed on second
        mock_api = Mock()
        mock_connection_ctx = AsyncMock()
        mock_connection_ctx.__aenter__ = AsyncMock(
            side_effect=[Exception("First failure"), None]
        )
        mock_connection_ctx.__aexit__ = AsyncMock(return_value=None)
        mock_api.connection.return_value = mock_connection_ctx
        service._api = mock_api

        context = FlextCliExecutionContext(
            command_name="test", command_args={"server": "localhost"}
        )
        result = service.execute_command("test", context)

        # Should fail after retries
        assert not result.is_success
        assert "First failure" in result.error


class TestFlextLdapCliFormatterServiceAdditional:
    """Additional tests for CLI formatter service."""

    def test_format_output_with_specific_format_types(self) -> None:
        """Test format_output with different format types."""
        container = Mock(spec=FlextContainer)
        service = FlextLdapCliFormatterService(container)

        test_data = {"test": "data"}

        # Test supported format types only
        supported_formats = ["table", "json", "csv", "plain"]

        for fmt in supported_formats:
            result = service.format_output(test_data, fmt)
            assert result.is_success  # Should handle all supported formats

        # Test unsupported format
        result = service.format_output(test_data, "yaml")
        assert not result.is_success
        assert "Unsupported format" in result.error

    def test_format_output_with_none_data(self) -> None:
        """Test format_output with None data."""
        container = Mock(spec=FlextContainer)
        service = FlextLdapCliFormatterService(container)

        result = service.format_output(None, "table")
        assert result.is_success

    def test_format_output_with_complex_data(self) -> None:
        """Test format_output with complex nested data."""
        container = Mock(spec=FlextContainer)
        service = FlextLdapCliFormatterService(container)

        complex_data = {
            "entries": [
                {
                    "dn": "cn=test,dc=example,dc=com",
                    "attributes": {
                        "cn": ["test"],
                        "mail": ["test@example.com"],
                        "objectClass": ["person", "inetOrgPerson"],
                    },
                }
            ],
            "count": 1,
        }

        result = service.format_output(complex_data, "json")
        assert result.is_success

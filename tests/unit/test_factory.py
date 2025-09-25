"""Comprehensive tests for FlextLdapFactory.

This module provides complete test coverage for the FlextLdapFactory class
following FLEXT standards with proper domain separation and centralized fixtures.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from unittest.mock import MagicMock, patch

from flext_core import FlextResult
from flext_ldap import FlextLdapFactory


class TestFlextLdapFactory:
    """Comprehensive test suite for FlextLdapFactory."""

    def test_factory_initialization(self, factory: FlextLdapFactory) -> None:
        """Test factory initialization."""
        assert factory is not None
        assert hasattr(factory, "_container")
        assert hasattr(factory, "_bus")
        assert hasattr(factory, "_dispatcher")
        assert hasattr(factory, "_processors")
        assert hasattr(factory, "_registry")
        assert hasattr(factory, "_context")

    def test_handle_advanced_service_success(self, factory: FlextLdapFactory) -> None:
        """Test successful advanced service creation via handle method."""
        message = {
            "factory_type": "advanced_service",
            "client_config": {
                "server_uri": "ldap://localhost:389",
                "bind_dn": "cn=admin,dc=example,dc=com",
                "bind_password": "admin123",
            },
        }

        with patch.object(factory, "create_client") as mock_create_client:
            mock_client = MagicMock()
            mock_create_client.return_value = FlextResult[object].ok(mock_client)

            result = factory.handle(message)

            assert result.is_success
            assert result.data is not None
            mock_create_client.assert_called_once()

    def test_handle_workflow_orchestrator_success(
        self, factory: FlextLdapFactory
    ) -> None:
        """Test successful workflow orchestrator creation via handle method."""
        message = {
            "factory_type": "workflow_orchestrator",
            "client_config": {
                "server_uri": "ldap://localhost:389",
                "bind_dn": "cn=admin,dc=example,dc=com",
                "bind_password": "admin123",
            },
        }

        with patch.object(factory, "create_client") as mock_create_client:
            mock_client = MagicMock()
            mock_create_client.return_value = FlextResult[object].ok(mock_client)

            result = factory.handle(message)

            assert result.is_success
            assert result.data is not None
            mock_create_client.assert_called_once()

    def test_handle_domain_services_success(self, factory: FlextLdapFactory) -> None:
        """Test successful domain services creation via handle method."""
        message = {
            "factory_type": "domain_services",
            "client_config": {
                "server_uri": "ldap://localhost:389",
                "bind_dn": "cn=admin,dc=example,dc=com",
                "bind_password": "admin123",
            },
        }

        with patch.object(factory, "create_client") as mock_create_client:
            mock_client = MagicMock()
            mock_create_client.return_value = FlextResult[object].ok(mock_client)

            result = factory.handle(message)

            assert result.is_success
            assert result.data is not None
            mock_create_client.assert_called_once()

    def test_handle_command_query_services_success(
        self, factory: FlextLdapFactory
    ) -> None:
        """Test successful command query services creation via handle method."""
        message = {
            "factory_type": "command_query_services",
            "client_config": {
                "server_uri": "ldap://localhost:389",
                "bind_dn": "cn=admin,dc=example,dc=com",
                "bind_password": "admin123",
            },
        }

        with patch.object(factory, "create_client") as mock_create_client:
            mock_client = MagicMock()
            mock_create_client.return_value = FlextResult[object].ok(mock_client)

            result = factory.handle(message)

            assert result.is_success
            assert result.data is not None
            mock_create_client.assert_called_once()

    def test_handle_saga_orchestrator_success(self, factory: FlextLdapFactory) -> None:
        """Test successful saga orchestrator creation via handle method."""
        message = {
            "factory_type": "saga_orchestrator",
            "client_config": {
                "server_uri": "ldap://localhost:389",
                "bind_dn": "cn=admin,dc=example,dc=com",
                "bind_password": "admin123",
            },
        }

        with patch.object(factory, "create_client") as mock_create_client:
            mock_client = MagicMock()
            mock_create_client.return_value = FlextResult[object].ok(mock_client)

            result = factory.handle(message)

            assert result.is_success
            assert result.data is not None
            mock_create_client.assert_called_once()

    def test_handle_invalid_message_type(self, factory: FlextLdapFactory) -> None:
        """Test handle method with invalid message type."""
        result = factory.handle("invalid_message")

        assert result.is_failure
        assert "Message must be a dictionary" in result.error

    def test_handle_missing_factory_type(self, factory: FlextLdapFactory) -> None:
        """Test handle method with missing factory type."""
        message = {"client_config": {}}

        result = factory.handle(message)

        assert result.is_failure
        assert "Factory type must be a string" in result.error

    def test_handle_unknown_factory_type(self, factory: FlextLdapFactory) -> None:
        """Test handle method with unknown factory type."""
        message = {"factory_type": "unknown_type", "client_config": {}}

        result = factory.handle(message)

        assert result.is_failure
        assert "Unknown factory type: unknown_type" in result.error

    def test_create_client_success(self) -> None:
        """Test successful client creation."""
        config = {
            "server_uri": "ldap://localhost:389",
            "bind_dn": "cn=admin,dc=example,dc=com",
            "bind_password": "admin123",
        }

        result = FlextLdapFactory.create_client(config)

        assert result.is_success
        assert result.data is not None

    def test_create_client_invalid_config(self) -> None:
        """Test client creation with invalid configuration."""
        config = {}  # Missing required server_uri

        result = FlextLdapFactory.create_client(config)

        assert result.is_failure
        assert "Missing required fields" in result.error

    def test_create_client_invalid_server_uri(self) -> None:
        """Test client creation with invalid server URI."""
        config = {
            "server_uri": "invalid://localhost:389",  # Invalid protocol
            "bind_dn": "cn=admin,dc=example,dc=com",
            "bind_password": "admin123",
        }

        result = FlextLdapFactory.create_client(config)

        assert result.is_failure
        assert "Server URI must start with ldap:// or ldaps://" in result.error

    def test_create_user_request_success(self) -> None:
        """Test successful user request creation."""
        user_data = {
            "dn": "uid=testuser,ou=people,dc=example,dc=com",
            "uid": "testuser",
            "cn": "Test User",
            "sn": "User",
            "mail": "testuser@example.com",
        }

        result = FlextLdapFactory.create_user_request(user_data)

        assert result.is_success
        assert result.data.dn == "uid=testuser,ou=people,dc=example,dc=com"
        assert result.data.uid == "testuser"
        assert result.data.cn == "Test User"
        assert result.data.sn == "User"
        assert result.data.mail == "testuser@example.com"

    def test_create_user_request_missing_fields(self) -> None:
        """Test user request creation with missing required fields."""
        user_data = {
            "uid": "testuser",
            "cn": "Test User",
            # Missing dn and sn
        }

        result = FlextLdapFactory.create_user_request(user_data)

        assert result.is_failure
        assert "Missing required fields" in result.error

    def test_create_user_request_invalid_email(self) -> None:
        """Test user request creation with invalid email."""
        user_data = {
            "dn": "uid=testuser,ou=people,dc=example,dc=com",
            "uid": "testuser",
            "cn": "Test User",
            "sn": "User",
            "mail": "invalid-email",  # Invalid email format
        }

        result = FlextLdapFactory.create_user_request(user_data, validation_strict=True)

        assert result.is_failure
        assert "Mail must be a valid email address" in result.error

    def test_create_user_request_non_strict_validation(self) -> None:
        """Test user request creation with non-strict validation."""
        user_data = {
            "dn": "uid=testuser,ou=people,dc=example,dc=com",
            "uid": "testuser",
            "cn": "Test User",
            "sn": "User",
            "mail": "testuser@example.com",  # Valid email format
        }

        result = FlextLdapFactory.create_user_request(
            user_data, validation_strict=False
        )

        assert result.is_success  # Should succeed with non-strict validation
        assert result.data.mail == "testuser@example.com"

    def test_create_search_request_success(self) -> None:
        """Test successful search request creation."""
        search_data = {
            "base_dn": "dc=example,dc=com",
            "filter_str": "(objectClass=person)",
            "attributes": ["cn", "sn", "mail"],
            "scope": "subtree",
        }

        result = FlextLdapFactory.create_search_request(search_data)

        assert result.is_success
        assert result.data.base_dn == "dc=example,dc=com"
        assert result.data.filter_str == "(objectClass=person)"
        assert result.data.attributes == ["cn", "sn", "mail"]
        assert result.data.scope == "subtree"

    def test_create_search_request_missing_fields(self) -> None:
        """Test search request creation with missing required fields."""
        search_data = {
            "base_dn": "dc=example,dc=com"
            # Missing filter_str
        }

        result = FlextLdapFactory.create_search_request(search_data)

        assert result.is_failure
        assert "Missing required fields" in result.error

    def test_create_search_request_with_defaults(self) -> None:
        """Test search request creation with default values."""
        search_data = {
            "base_dn": "dc=example,dc=com",
            "filter_str": "(objectClass=person)",
        }

        result = FlextLdapFactory.create_search_request(search_data)

        assert result.is_success
        assert result.data.scope == "subtree"  # Default value
        assert result.data.attributes == []  # Default value
        assert result.data.page_size > 0  # Default value from constants

    def test_create_bulk_operation_config_success(self) -> None:
        """Test successful bulk operation configuration creation."""
        operation_data = {
            "operation_type": "create",
            "items_data": [
                {"dn": "uid=user1,ou=people,dc=example,dc=com"},
                {"dn": "uid=user2,ou=people,dc=example,dc=com"},
            ],
            "batch_size": 5,
        }

        result = FlextLdapFactory.create_bulk_operation_config(operation_data)

        assert result.is_success
        assert result.data["operation_type"] == "create"
        assert len(result.data["items_data"]) == 2
        assert result.data["batch_size"] == 5
        assert result.data["continue_on_error"] is True  # Default value

    def test_create_bulk_operation_config_invalid_type(self) -> None:
        """Test bulk operation configuration with invalid operation type."""
        operation_data = {
            "operation_type": "invalid_operation",
            "items_data": [{"dn": "uid=user1,ou=people,dc=example,dc=com"}],
        }

        result = FlextLdapFactory.create_bulk_operation_config(operation_data)

        assert result.is_failure
        assert "Invalid operation type" in result.error

    def test_create_bulk_operation_config_empty_items(self) -> None:
        """Test bulk operation configuration with empty items data."""
        operation_data = {"operation_type": "create", "items_data": []}

        result = FlextLdapFactory.create_bulk_operation_config(operation_data)

        assert result.is_failure
        assert "Items data cannot be empty" in result.error

    def test_create_bulk_operation_config_invalid_batch_size(self) -> None:
        """Test bulk operation configuration with invalid batch size."""
        operation_data = {
            "operation_type": "create",
            "items_data": [{"dn": "uid=user1,ou=people,dc=example,dc=com"}],
            "batch_size": 0,  # Invalid batch size
        }

        result = FlextLdapFactory.create_bulk_operation_config(operation_data)

        assert result.is_failure
        assert "Batch size must be greater than 0" in result.error

    def test_create_advanced_service_deprecated(self) -> None:
        """Test deprecated create_advanced_service method."""
        client_config = {
            "server_uri": "ldap://localhost:389",
            "bind_dn": "cn=admin,dc=example,dc=com",
            "bind_password": "admin123",
        }

        result = FlextLdapFactory.create_advanced_service(client_config)

        assert result.is_success
        assert result.data is not None

    def test_create_advanced_service_invalid_config(self) -> None:
        """Test deprecated create_advanced_service with invalid config."""
        client_config = {}  # Missing required fields

        result = FlextLdapFactory.create_advanced_service(client_config)

        assert result.is_failure
        assert "Client configuration validation failed" in result.error

    def test_validation_methods(self) -> None:
        """Test validation helper methods."""
        # Test _validate_client_config with valid config
        valid_config = {
            "server_uri": "ldap://localhost:389",
            "bind_dn": "cn=admin,dc=example,dc=com",
            "bind_password": "admin123",
        }

        result = FlextLdapFactory._validate_client_config(valid_config)
        assert result.is_success

        # Test _validate_client_config with invalid config
        invalid_config = {}
        result = FlextLdapFactory._validate_client_config(invalid_config)
        assert result.is_failure
        assert "Missing required fields" in result.error

    def test_validate_user_data_methods(self) -> None:
        """Test user data validation methods."""
        # Test _validate_user_data with valid data
        valid_user_data = {
            "dn": "uid=testuser,ou=people,dc=example,dc=com",
            "uid": "testuser",
            "cn": "Test User",
            "sn": "User",
            "mail": "testuser@example.com",
        }

        result = FlextLdapFactory._validate_user_data(valid_user_data)
        assert result.is_success

        # Test _validate_user_data with invalid data
        invalid_user_data = {
            "dn": "",  # Empty DN
            "uid": "testuser",
            "cn": "Test User",
            "sn": "User",
        }

        result = FlextLdapFactory._validate_user_data(invalid_user_data)
        assert result.is_failure
        assert "DN must be a non-empty string" in result.error

    def test_apply_defaults_methods(self) -> None:
        """Test default application methods."""
        # Test _apply_user_defaults
        user_data = {"uid": "testuser", "cn": "Test User"}
        result = FlextLdapFactory._apply_user_defaults(user_data)

        assert "scope" in result
        assert "attributes" in result
        assert result["scope"] == "subtree"
        assert result["attributes"] == []

        # Test _apply_search_defaults
        search_data = {
            "base_dn": "dc=example,dc=com",
            "filter_str": "(objectClass=person)",
        }
        result = FlextLdapFactory._apply_search_defaults(search_data)

        assert "scope" in result
        assert "attributes" in result
        assert "page_size" in result
        assert "paged_cookie" in result
        assert result["scope"] == "subtree"
        assert result["attributes"] == []
        assert result["page_size"] > 0
        assert result["paged_cookie"] == b""

    def test_factory_error_handling_consistency(
        self, factory: FlextLdapFactory
    ) -> None:
        """Test consistent error handling across factory methods."""
        # Test handle method exception handling
        with patch.object(factory, "_create_advanced_service_ecosystem") as mock_create:
            mock_create.side_effect = Exception("Test exception")

            message = {"factory_type": "advanced_service", "client_config": {}}

            result = factory.handle(message)
            assert result.is_failure
            assert "Factory creation failed" in result.error

    def test_factory_ecosystem_integration(self, factory: FlextLdapFactory) -> None:
        """Test factory ecosystem integration."""
        # Test that all ecosystem components are properly initialized
        assert factory._container is not None
        assert factory._bus is not None
        assert factory._dispatcher is not None
        assert factory._processors is not None
        assert factory._registry is not None
        assert factory._context is not None

        # Test that registry is properly configured (check that it exists and is initialized)
        assert hasattr(factory._registry, "_dispatcher") or hasattr(
            factory._registry, "dispatcher"
        )

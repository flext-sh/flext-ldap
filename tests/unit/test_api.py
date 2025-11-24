"""Unit tests for FlextLdap API.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT

"""

from __future__ import annotations

import pytest
from flext_core import FlextContainer, FlextResult
from flext_ldif import FlextLdifParser
from ldap3 import MODIFY_REPLACE

from flext_ldap import FlextLdap
from flext_ldap.config import FlextLdapConfig
from flext_ldap.models import FlextLdapModels

from ..helpers.test_deduplication_helpers import TestDeduplicationHelpers

# Mark all tests in this module as unit tests (fast, no Docker)
pytestmark = pytest.mark.unit


class TestFlextLdapAPI:
    """Tests for FlextLdap main API facade."""

    def test_api_initialization(
        self,
        ldap_config: FlextLdapConfig,
        ldap_parser: FlextLdifParser,
    ) -> None:
        """Test API initialization."""
        api = FlextLdap(config=ldap_config, parser=ldap_parser)
        assert api is not None
        assert api._connection is not None
        assert api._operations is not None
        assert api._config is not None
        assert api.is_connected is False

    def test_api_initialization_with_config(self, ldap_parser: FlextLdifParser) -> None:
        """Test API initialization with custom config."""
        config = FlextLdapConfig(
            host="test.example.com",
            port=389,
        )
        api = FlextLdap(config=config, parser=ldap_parser)
        assert api._config == config

    def test_is_connected_property(
        self,
        ldap_config: FlextLdapConfig,
        ldap_parser: FlextLdifParser,
    ) -> None:
        """Test is_connected property."""
        api = FlextLdap(config=ldap_config, parser=ldap_parser)
        assert api.is_connected is False

    def test_search_when_not_connected(
        self,
        ldap_config: FlextLdapConfig,
        ldap_parser: FlextLdifParser,
    ) -> None:
        """Test search when not connected."""
        api = FlextLdap(config=ldap_config, parser=ldap_parser)
        # Use real helper to create search options
        search_options = TestDeduplicationHelpers.create_search(
            base_dn="dc=example,dc=com",
            filter_str="(objectClass=*)",
            scope="SUBTREE",
        )

        result = api.search(search_options)
        assert result.is_failure

    def test_add_when_not_connected(
        self,
        ldap_config: FlextLdapConfig,
        ldap_parser: FlextLdifParser,
    ) -> None:
        """Test add when not connected."""
        api = FlextLdap(config=ldap_config, parser=ldap_parser)
        # Use real helper to create entry
        entry = TestDeduplicationHelpers.create_entry(
            "cn=test,dc=example,dc=com",
            {"cn": ["test"], "objectClass": ["top", "person"]},
        )

        result = api.add(entry)
        assert result.is_failure

    def test_modify_when_not_connected(
        self,
        ldap_config: FlextLdapConfig,
        ldap_parser: FlextLdifParser,
    ) -> None:
        """Test modify when not connected."""
        api = FlextLdap(config=ldap_config, parser=ldap_parser)
        changes: dict[str, list[tuple[str, list[str]]]] = {
            "mail": [(MODIFY_REPLACE, ["test@example.com"])],
        }

        result = api.modify("cn=test,dc=example,dc=com", changes)
        assert result.is_failure

    def test_delete_when_not_connected(
        self,
        ldap_config: FlextLdapConfig,
        ldap_parser: FlextLdifParser,
    ) -> None:
        """Test delete when not connected."""
        api = FlextLdap(config=ldap_config, parser=ldap_parser)
        result = api.delete("cn=test,dc=example,dc=com")
        assert result.is_failure

    def test_disconnect_when_not_connected(
        self,
        ldap_config: FlextLdapConfig,
        ldap_parser: FlextLdifParser,
    ) -> None:
        """Test disconnect when not connected."""
        api = FlextLdap(config=ldap_config, parser=ldap_parser)
        # Should not raise exception
        api.disconnect()
        assert api.is_connected is False

    def test_execute_when_not_connected(
        self,
        ldap_config: FlextLdapConfig,
        ldap_parser: FlextLdifParser,
    ) -> None:
        """Test execute when not connected - fast-fail pattern."""
        api = FlextLdap(config=ldap_config, parser=ldap_parser)
        result = api.execute()
        # Fast-fail: execute() returns failure when not connected
        assert result.is_failure
        assert result.error is not None
        assert "Not connected" in result.error

    def test_connect_method(
        self,
        connection_config: FlextLdapModels.ConnectionConfig,
        ldap_config: FlextLdapConfig,
        ldap_parser: FlextLdifParser,
    ) -> None:
        """Test connect method (covers line 102)."""
        api = FlextLdap(config=ldap_config, parser=ldap_parser)
        result = api.connect(connection_config)

        # Should succeed
        assert result.is_success, f"Connect failed: {result.error}"
        assert api.is_connected is True

        # Cleanup
        api.disconnect()

    def test_client_property(
        self,
        ldap_config: FlextLdapConfig,
        ldap_parser: FlextLdifParser,
    ) -> None:
        """Test client property access (covers line 126)."""
        api = FlextLdap(config=ldap_config, parser=ldap_parser)
        client = api.client

        # Should return operations instance
        assert client is not None
        assert client == api._operations

    def test_context_manager_enter(
        self,
        ldap_config: FlextLdapConfig,
        ldap_parser: FlextLdifParser,
    ) -> None:
        """Test context manager __enter__ (covers line 135)."""
        api = FlextLdap(config=ldap_config, parser=ldap_parser)
        # Use with statement to test __enter__ (covers line 135)
        with api as entered:
            # Should return self
            assert entered is api

    def test_context_manager_exit(
        self,
        connection_config: FlextLdapModels.ConnectionConfig,
        ldap_config: FlextLdapConfig,
        ldap_parser: FlextLdifParser,
    ) -> None:
        """Test context manager __exit__ (covers line 153)."""
        api = FlextLdap(config=ldap_config, parser=ldap_parser)
        api.connect(connection_config)

        # Exit should disconnect
        api.__exit__(None, None, None)

        # Should be disconnected
        assert api.is_connected is False

    def test_context_manager_with_statement(
        self,
        connection_config: FlextLdapModels.ConnectionConfig,
        ldap_config: FlextLdapConfig,
        ldap_parser: FlextLdifParser,
    ) -> None:
        """Test context manager with statement."""
        with FlextLdap(config=ldap_config, parser=ldap_parser) as api:
            connect_result = api.connect(connection_config)
            if connect_result.is_success:
                assert api.is_connected is True

        # Should be disconnected after exiting context
        assert api.is_connected is False

    def test_execute_when_operations_fails(
        self,
        ldap_config: FlextLdapConfig,
        ldap_parser: FlextLdifParser,
    ) -> None:
        """Test execute when operations.execute() fails - fast-fail pattern.

        Uses real operations service that is not connected to trigger failure.
        """
        api = FlextLdap(config=ldap_config, parser=ldap_parser)

        # Operations service is not connected, so execute() will fail
        # Fast-fail: returns failure, not empty success
        result = api.execute()

        # Fast-fail: should return failure when not connected
        assert result.is_failure
        assert result.error is not None
        assert "Not connected" in result.error

    def test_register_core_services_success(
        self,
        ldap_config: FlextLdapConfig,
        ldap_parser: FlextLdifParser,
    ) -> None:
        """Test _register_core_services with empty container (covers lines 267-274, 277-282, 287-292)."""
        api = FlextLdap(config=ldap_config, parser=ldap_parser)
        container = FlextContainer()

        # Should succeed with empty container
        api._register_core_services(container)

        # Verify services were registered
        assert container.has("connection")
        assert container.has("operations")
        assert container.has("parser")

    def test_register_core_services_connection_failure(
        self,
        ldap_config: FlextLdapConfig,
        ldap_parser: FlextLdifParser,
    ) -> None:
        """Test _register_core_services when connection service registration fails (covers lines 269-272)."""
        api = FlextLdap(config=ldap_config, parser=ldap_parser)
        container = FlextContainer()

        # Ensure container doesn't have connection service
        if container.has("connection"):
            container.remove("connection")  # type: ignore[attr-defined]

        # Mock container to fail connection service registration
        original_register = container.register_service

        def mock_register_failure(
            service_name: str, service: object
        ) -> FlextResult[bool]:
            if service_name == "connection":
                return FlextResult.fail("Mock connection registration failure")
            return original_register(service_name, service)

        container.register_service = mock_register_failure  # type: ignore[method-assign]

        # Should raise RuntimeError
        with pytest.raises(RuntimeError, match="Failed to register connection service"):
            api._register_core_services(container)

    def test_register_core_services_operations_failure(
        self,
        ldap_config: FlextLdapConfig,
        ldap_parser: FlextLdifParser,
    ) -> None:
        """Test _register_core_services when operations service registration fails (covers lines 278-282)."""
        api = FlextLdap(config=ldap_config, parser=ldap_parser)
        container = FlextContainer()

        # Ensure container doesn't have operations service
        if container.has("operations"):
            container.remove("operations")  # type: ignore[attr-defined]  # type: ignore[attr-defined]

        # Mock container to fail operations service registration
        original_register = container.register_service

        def mock_register_failure(
            service_name: str, service: object
        ) -> FlextResult[bool]:
            if service_name == "operations":
                return FlextResult.fail("Mock operations registration failure")
            return original_register(service_name, service)

        container.register_service = mock_register_failure  # type: ignore[method-assign]

        # Should raise RuntimeError
        with pytest.raises(RuntimeError, match="Failed to register operations service"):
            api._register_core_services(container)

    def test_register_core_services_parser_failure(
        self,
        ldap_config: FlextLdapConfig,
        ldap_parser: FlextLdifParser,
    ) -> None:
        """Test _register_core_services when parser service registration fails (covers lines 288-292)."""
        api = FlextLdap(config=ldap_config, parser=ldap_parser)
        container = FlextContainer()

        # Ensure container doesn't have parser service
        if container.has("parser"):
            container.remove("parser")  # type: ignore[attr-defined]

        # Mock container to fail parser service registration
        original_register = container.register_service

        def mock_register_failure(
            service_name: str, service: object
        ) -> FlextResult[bool]:
            if service_name == "parser":
                return FlextResult.fail("Mock parser registration failure")
            return original_register(service_name, service)

        container.register_service = mock_register_failure  # type: ignore[method-assign]

        # Should raise RuntimeError
        with pytest.raises(RuntimeError, match="Failed to register parser service"):
            api._register_core_services(container)

    def test_register_core_services_existing_services(
        self,
        ldap_config: FlextLdapConfig,
        ldap_parser: FlextLdifParser,
    ) -> None:
        """Test _register_core_services when services already exist (services are not re-registered)."""
        api = FlextLdap(config=ldap_config, parser=ldap_parser)
        container = FlextContainer()

        # Pre-register services
        container.register_service("connection", api._connection)
        container.register_service("operations", api._operations)
        container.register_service("parser", api._ldif.parser)

        # Track registration calls
        registration_calls = []

        def mock_register(service_name: str, service: object) -> FlextResult[bool]:
            registration_calls.append(service_name)
            return container.register_service(service_name, service)

        original_register = container.register_service
        container.register_service = mock_register  # type: ignore[method-assign]

        try:
            api._register_core_services(container)

            # Should not have called register for existing services
            assert "connection" not in registration_calls
            assert "operations" not in registration_calls
            assert "parser" not in registration_calls
        finally:
            container.register_service = original_register

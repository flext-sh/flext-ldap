"""Unit tests for FlextLdap service registration error handling.

Tests error handling paths in _setup_services and _register_core_services.
These tests cover defensive code paths that are difficult to trigger in normal operation.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

import pytest
from flext_core import FlextContainer, FlextResult
from flext_ldif import FlextLdifParser

from flext_ldap import FlextLdap
from flext_ldap.config import FlextLdapConfig

pytestmark = pytest.mark.unit


class TestFlextLdapServiceRegistrationErrors:
    """Tests for service registration error handling in FlextLdap."""

    def test_register_core_services_connection_failure(
        self,
        ldap_parser: FlextLdifParser,
    ) -> None:
        """Test _register_core_services when connection registration fails (covers lines 281-283).

        Forces a failure in container.register_service for connection service
        to test the error handling path.
        """
        # Reset singleton
        FlextLdap._reset_instance()

        config = FlextLdapConfig()
        api = FlextLdap(config=config, parser=ldap_parser)

        # Get the container and clear it to allow re-registration
        container = api.container
        # Clear container to allow re-registration
        clear_result = container.clear()
        if clear_result.is_failure:
            pytest.skip(f"Failed to clear container: {clear_result.error}")

        original_register = container.register_service

        def failing_register_connection(name: str, service: object) -> FlextResult[bool]:
            """Register service that fails for connection."""
            if name == "connection":
                return FlextResult[bool].fail("Test failure for connection service")
            return original_register(name, service)

        # Replace register_service temporarily
        container.register_service = failing_register_connection  # type: ignore[assignment]

        try:
            # Try to register services again - should raise RuntimeError (covers lines 281-283)
            with pytest.raises(RuntimeError) as exc_info:
                api._register_core_services(container)

            assert "Failed to register connection service" in str(exc_info.value)
            assert "Test failure for connection service" in str(exc_info.value)
        finally:
            # Restore original method
            container.register_service = original_register  # type: ignore[assignment]
            FlextLdap._reset_instance()

    def test_register_core_services_operations_failure(
        self,
        ldap_parser: FlextLdifParser,
    ) -> None:
        """Test _register_core_services when operations registration fails (covers lines 291-293).

        Forces a failure in container.register_service for operations service
        to test the error handling path.
        """
        # Reset singleton
        FlextLdap._reset_instance()

        config = FlextLdapConfig()
        api = FlextLdap(config=config, parser=ldap_parser)

        # Get the container and clear it to allow re-registration
        container = api.container
        # Clear container to allow re-registration
        clear_result = container.clear()
        if clear_result.is_failure:
            pytest.skip(f"Failed to clear container: {clear_result.error}")

        original_register = container.register_service

        def failing_register_operations(name: str, service: object) -> FlextResult[bool]:
            """Register service that fails for operations."""
            if name == "operations":
                return FlextResult[bool].fail("Test failure for operations service")
            return original_register(name, service)

        # Replace register_service temporarily
        container.register_service = failing_register_operations  # type: ignore[assignment]

        try:
            # Try to register services again - should raise RuntimeError (covers lines 291-293)
            with pytest.raises(RuntimeError) as exc_info:
                api._register_core_services(container)

            assert "Failed to register operations service" in str(exc_info.value)
            assert "Test failure for operations service" in str(exc_info.value)
        finally:
            # Restore original method
            container.register_service = original_register  # type: ignore[assignment]
            FlextLdap._reset_instance()

    def test_register_core_services_parser_failure(
        self,
        ldap_parser: FlextLdifParser,
    ) -> None:
        """Test _register_core_services when parser registration fails (covers lines 301-303).

        Forces a failure in container.register_service for parser service
        to test the error handling path.
        """
        # Reset singleton
        FlextLdap._reset_instance()

        config = FlextLdapConfig()
        api = FlextLdap(config=config, parser=ldap_parser)

        # Get the container and clear it to allow re-registration
        container = api.container
        # Clear container to allow re-registration
        clear_result = container.clear()
        if clear_result.is_failure:
            pytest.skip(f"Failed to clear container: {clear_result.error}")

        original_register = container.register_service

        def failing_register_parser(name: str, service: object) -> FlextResult[bool]:
            """Register service that fails for parser."""
            if name == "parser":
                return FlextResult[bool].fail("Test failure for parser service")
            return original_register(name, service)

        # Replace register_service temporarily
        container.register_service = failing_register_parser  # type: ignore[assignment]

        try:
            # Try to register services again - should raise RuntimeError (covers lines 301-303)
            with pytest.raises(RuntimeError) as exc_info:
                api._register_core_services(container)

            assert "Failed to register parser service" in str(exc_info.value)
            assert "Test failure for parser service" in str(exc_info.value)
        finally:
            # Restore original method
            container.register_service = original_register  # type: ignore[assignment]
            FlextLdap._reset_instance()

    def test_setup_services_exception_handling(
        self,
        ldap_parser: FlextLdifParser,
    ) -> None:
        """Test _setup_services exception handling (covers lines 268-273).

        Forces an exception in _register_core_services to test the exception
        handling path in _setup_services.
        """
        # Reset singleton
        FlextLdap._reset_instance()

        config = FlextLdapConfig()
        api = FlextLdap(config=config, parser=ldap_parser)

        # Temporarily replace _register_core_services to raise exception
        original_register = api._register_core_services

        test_exception_message = "Test exception for coverage"

        def failing_register(container: FlextContainer) -> None:
            """Register services that raises exception."""
            raise ValueError(test_exception_message)

        api._register_core_services = failing_register  # type: ignore[assignment]

        try:
            # Try to setup services - should raise exception (covers lines 268-273)
            with pytest.raises(ValueError) as exc_info:
                api._setup_services()

            assert "Test exception for coverage" in str(exc_info.value)
        finally:
            # Restore original method
            api._register_core_services = original_register  # type: ignore[assignment]
            FlextLdap._reset_instance()

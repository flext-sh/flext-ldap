"""Tests for optimized FlextLdapContainer with FlextModels validation.

Validates the container refactor that uses FlextContainer patterns directly.
Uses Pydantic v2 models for test validation and removes ad-hoc assertions.

Test Strategy: REAL functionality tests without mocks, using FlextModels
for validation and testing the optimized container patterns.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

import pytest
from pydantic import Field

from flext_core import FlextContainer, FlextModels, FlextResult
from flext_ldap import FlextLdapClient, FlextLdapConfigs, FlextLdapContainer


# Test models using FlextModels for Pydantic v2 validation
class ContainerTestModels:
    """Test models using FlextModels for validation."""

    class ContainerState(FlextModels.Value):
        """Model for validating container state."""

        is_initialized: bool = Field(..., description="Container initialization state")
        has_client: bool = Field(..., description="Client availability")
        has_repository: bool = Field(..., description="Repository availability")
        container_instance: object = Field(..., description="Container instance")

        def validate_optimized_container(self) -> FlextResult[None]:
            """Validate the optimized container patterns."""
            if not self.is_initialized:
                return FlextResult[None].fail("Container must be initialized")
            if not isinstance(self.container_instance, FlextLdapContainer):
                return FlextResult[None].fail("Invalid container instance type")
            return FlextResult[None].ok(None)

    class ServiceRegistration(FlextModels.Value):
        """Model for validating service registration."""

        service_name: str = Field(..., min_length=1, description="Service name")
        service_type: str = Field(..., min_length=1, description="Service type")
        is_registered: bool = Field(..., description="Registration status")

        def validate_service_registration(self) -> FlextResult[None]:
            """Validate service registration using FlextContainer patterns."""
            if not self.is_registered:
                return FlextResult[None].fail(
                    f"Service {self.service_name} not registered",
                )
            if self.service_type not in {"client", "repository", "operations"}:
                return FlextResult[None].fail(
                    f"Invalid service type: {self.service_type}",
                )
            return FlextResult[None].ok(None)


class TestOptimizedFlextLdapContainer:
    """Test optimized FlextLdapContainer using FlextModels validation."""

    @pytest.fixture
    def container(self) -> FlextLdapContainer:
        """Create container instance for testing."""
        return FlextLdapContainer()

    @pytest.fixture
    def config(self) -> FlextLdapConfigs:
        """Create test configuration."""
        return FlextLdapConfigs()

    def test_optimized_container_initialization(
        self,
        container: FlextLdapContainer,
    ) -> None:
        """Test optimized FlextLdapContainer initialization with FlextModels validation."""
        # Create validation model for container state
        container_state = ContainerTestModels.ContainerState(
            is_initialized=True,
            has_client=hasattr(container, "get_client"),
            has_repository=hasattr(container, "get_repository"),
            container_instance=container,
        )

        # Use FlextModels validation instead of manual assertions
        validation_result = container_state.validate_optimized_container()
        assert validation_result.is_success, (
            f"Container validation failed: {validation_result.error}"
        )

        # Test optimized FlextContainer integration
        flext_container = container.get_container()
        assert isinstance(flext_container, FlextContainer)

    def test_optimized_container_uses_flext_container_directly(
        self,
        container: FlextLdapContainer,
    ) -> None:
        """Test that optimized container uses FlextContainer patterns directly."""
        # Validate that old caching patterns are removed
        assert not hasattr(container, "_client_cache"), (
            "Old caching patterns should be removed"
        )
        assert not hasattr(container, "_repository_cache"), (
            "Old caching patterns should be removed"
        )
        assert not hasattr(container, "_services_registered"), (
            "Old registration flag should be removed"
        )

        # Validate new optimized pattern
        assert hasattr(container, "_initialized"), (
            "New initialization flag should exist"
        )

    def test_container_service_registration_with_models(
        self,
        container: FlextLdapContainer,
    ) -> None:
        """Test service registration using FlextModels validation."""
        # Get FlextContainer and test service registration
        flext_container = container.get_container()

        # Create validation models for different services
        services = [
            ("ldap_client", "client"),
            ("ldap_repository", "repository"),
            ("ldap_operations", "operations"),
        ]

        for service_name, service_type in services:
            # Check if service is registered in FlextContainer
            service_result = flext_container.get(service_name)

            # Create validation model
            service_registration = ContainerTestModels.ServiceRegistration(
                service_name=service_name,
                service_type=service_type,
                is_registered=service_result.is_success,
            )

            # Use FlextModels validation
            validation_result = service_registration.validate_service_registration()
            assert validation_result.is_success, (
                f"Service registration validation failed: {validation_result.error}"
            )

    def test_optimized_client_retrieval_via_flext_container(
        self,
        container: FlextLdapContainer,
    ) -> None:
        """Test optimized client retrieval using FlextContainer patterns."""
        # Test that client is retrieved via FlextContainer, not custom caching
        client = container.get_client()

        # Use FlextLdapModels to validate the client
        assert isinstance(client, FlextLdapClient)

        # Test that multiple calls return the same instance (FlextContainer singleton)
        client2 = container.get_client()
        assert client is client2, "FlextContainer should provide singleton behavior"

    def test_optimized_repository_retrieval_via_flext_container(
        self,
        container: FlextLdapContainer,
    ) -> None:
        """Test optimized repository retrieval using FlextContainer patterns."""
        # Test that repository is retrieved via FlextContainer, not custom caching
        repository = container.get_repository()
        assert repository is not None

        # Test singleton behavior through FlextContainer
        repository2 = container.get_repository()
        assert repository is repository2, (
            "FlextContainer should provide singleton behavior"
        )

    def test_optimized_container_configuration_with_models(
        self,
        container: FlextLdapContainer,
        config: FlextLdapConfigs,
    ) -> None:
        """Test container configuration using FlextModels validation."""
        # Test configuration with FlextResult validation
        config_result = container.configure(config)
        assert config_result.is_success, f"Configuration failed: {config_result.error}"

        # Validate configuration was registered in FlextContainer
        flext_container = container.get_container()
        settings_result = flext_container.get("ldap_settings")
        assert settings_result.is_success, (
            "LDAP settings should be registered in FlextContainer"
        )

        # Validate the configuration instance using proper typing
        registered_config = settings_result.value
        assert isinstance(registered_config, FlextLdapConfigs)

    def test_container_validates_domain_boundaries(
        self,
        container: FlextLdapContainer,
    ) -> None:
        """Test that container only provides LDAP domain services."""
        # Validate that only LDAP domain services are available
        ldap_specific_methods = ["get_client", "get_repository", "configure"]

        for method_name in ldap_specific_methods:
            assert hasattr(container, method_name), (
                f"LDAP domain method {method_name} should exist"
            )

        # Test that non-LDAP methods don't exist (domain boundary validation)
        non_ldap_methods = ["get_http_client", "get_database", "get_email_service"]

        for method_name in non_ldap_methods:
            assert not hasattr(container, method_name), (
                f"Non-LDAP method {method_name} should not exist"
            )

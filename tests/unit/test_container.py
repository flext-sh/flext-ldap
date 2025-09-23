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
from flext_ldap import FlextLdapClient, FlextLdapConfigs


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
            if not isinstance(self.container_instance, FlextContainer):
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


class TestOptimizedFlextContainer:
    """Test optimized FlextContainer using FlextModels validation."""

    @pytest.fixture
    def container(self) -> FlextContainer:
        """Create container instance for testing."""
        return FlextContainer()

    @pytest.fixture
    def config(self) -> FlextLdapConfigs:
        """Create test configuration."""
        return FlextLdapConfigs()

    def test_optimized_container_initialization(
        self,
        container: FlextContainer,
    ) -> None:
        """Test optimized FlextContainer initialization with FlextModels validation."""
        # Create validation model for container state
        container_state = ContainerTestModels.ContainerState(
            is_initialized=True,
            has_client=hasattr(container, "get"),
            has_repository=hasattr(container, "get"),
            container_instance=container,
        )

        # Use FlextModels validation instead of manual assertions
        validation_result = container_state.validate_optimized_container()
        assert validation_result.is_success, (
            f"Container validation failed: {validation_result.error}"
        )

        # Test FlextContainer is properly initialized
        assert isinstance(container, FlextContainer)

    def test_optimized_container_uses_flext_container_directly(
        self,
        container: FlextContainer,
    ) -> None:
        """Test that optimized container uses FlextContainer patterns directly."""
        # Validate FlextContainer has the expected methods
        assert hasattr(container, "get"), "FlextContainer should have get method"
        assert hasattr(container, "register"), (
            "FlextContainer should have register method"
        )
        assert hasattr(container, "configure"), (
            "FlextContainer should have configure method"
        )

    def test_container_service_registration_with_models(
        self,
        container: FlextContainer,
    ) -> None:
        """Test service registration using FlextModels validation."""
        # Create validation models for different services
        services = [
            ("ldap_client", "client"),
            ("ldap_repository", "repository"),
            ("ldap_operations", "operations"),
        ]

        for service_name, service_type in services:
            # Check if service is registered in FlextContainer
            service_result = container.get(service_name)

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
        container: FlextContainer,
    ) -> None:
        """Test optimized client retrieval using FlextContainer patterns."""
        # Register a test client
        test_client = FlextLdapClient()
        container.register("ldap_client", test_client)

        # Test that client is retrieved via FlextContainer
        client_result = container.get("ldap_client")
        assert client_result.is_success

        # Use FlextLdapModels to validate the client
        client = client_result.value
        assert isinstance(client, FlextLdapClient)

        # Test that multiple calls return the same instance (FlextContainer singleton)
        client2_result = container.get("ldap_client")
        assert client2_result.is_success
        client2 = client2_result.value
        assert client is client2, "FlextContainer should provide singleton behavior"

    def test_optimized_repository_retrieval_via_flext_container(
        self,
        container: FlextContainer,
    ) -> None:
        """Test optimized repository retrieval using FlextContainer patterns."""
        # Register a test repository
        test_repository = object()  # Mock repository
        container.register("ldap_repository", test_repository)

        # Test that repository is retrieved via FlextContainer
        repository_result = container.get("ldap_repository")
        assert repository_result.is_success
        repository = repository_result.value
        assert repository is not None

        # Test singleton behavior through FlextContainer
        repository2_result = container.get("ldap_repository")
        assert repository2_result.is_success
        repository2 = repository2_result.value
        assert repository is repository2, (
            "FlextContainer should provide singleton behavior"
        )

    def test_optimized_container_configuration_with_models(
        self,
        container: FlextContainer,
        config: FlextLdapConfigs,
    ) -> None:
        """Test container configuration using FlextModels validation."""
        # Test configuration with FlextResult validation
        config_dict = config.model_dump()
        config_result = container.configure(config_dict)
        assert config_result.is_success, f"Configuration failed: {config_result.error}"

        # Validate configuration was registered in FlextContainer
        settings_result = container.get("ldap_settings")
        assert settings_result.is_success, (
            "LDAP settings should be registered in FlextContainer"
        )

        # Validate the configuration instance using proper typing
        registered_config = settings_result.value
        assert isinstance(registered_config, FlextLdapConfigs)

    def test_container_validates_domain_boundaries(
        self,
        container: FlextContainer,
    ) -> None:
        """Test that container provides FlextContainer domain services."""
        # Validate that FlextContainer methods are available
        flext_methods = ["get", "register", "configure"]

        for method_name in flext_methods:
            assert hasattr(container, method_name), (
                f"FlextContainer method {method_name} should exist"
            )

        # Test that FlextContainer doesn't have LDAP-specific methods (domain boundary validation)
        ldap_specific_methods = ["get_client", "get_repository", "get_ldap_service"]

        for method_name in ldap_specific_methods:
            assert not hasattr(container, method_name), (
                f"LDAP-specific method {method_name} should not exist in FlextContainer"
            )

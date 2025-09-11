"""FLEXT-LDAP Container - Class-based dependency injection using flext-core.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from typing import TypeVar, cast, final

from flext_core import (
    FlextContainer,
    FlextMixins,
    FlextResult,
)

from flext_ldap.clients import FlextLDAPClient
from flext_ldap.repositories import FlextLDAPRepositories
from flext_ldap.settings import FlextLDAPSettings

# Python 3.13 type aliases for container services
type LdapClientService = FlextLDAPClient
type LdapRepositoryService = FlextLDAPRepositories.Repository
type ContainerServiceKey = str

# Type variable for generic service resolution
T = TypeVar("T")


@final
class FlextLDAPContainer(FlextMixins.Service):
    """FLEXT-LDAP Container - Direct dependency injection using FlextContainer only.

    Uses FlextContainer from flext-core exclusively, NO custom registry duplication.
    Implements proper singleton pattern with logging via FlextMixins.Service.
    """

    def __init__(self, **data: object) -> None:
        """Initialize container manager using FlextContainer directly."""
        super().__init__(**data)
        self._services_registered = False
        self._client_cache: FlextLDAPClient | None = None
        self._repository_cache: FlextLDAPRepositories | None = None
        self.log_debug("FlextLDAPContainer initialized with FlextContainer")

    def get_container(self) -> FlextContainer:
        """Get flext-core container with LDAP services registered.

        Returns:
            FlextContainer: The global flext-core container with LDAP services

        """
        container = FlextContainer.get_global()

        # Register LDAP services once using FlextContainer directly
        if not self._services_registered:
            registration_result = self._register_services(container)
            if not registration_result.is_success:
                self.log_error(
                    "Failed to register LDAP services", error=registration_result.error
                )
                msg = f"LDAP service registration failed: {registration_result.error}"
                raise RuntimeError(msg)
            self._services_registered = True

        return container

    def _get_service(self, service_key: ContainerServiceKey) -> object:
        """Generic service resolver using FlextContainer directly.

        Uses flext-core FlextContainer ONLY - no custom service registry duplication.

        Args:
            service_key: Service name for FlextContainer lookup

        Returns:
            object: The resolved service instance

        Raises:
            RuntimeError: If service resolution fails

        """
        # Use FlextContainer directly - SOURCE OF TRUTH
        container = self.get_container()
        result = container.get(service_key)

        if not result.is_success:
            msg = f"Failed to get service '{service_key}': {result.error}"
            self.log_error(
                "Service resolution failed", service_key=service_key, error=result.error
            )
            raise RuntimeError(msg)

        return result.value

    def get_client(self) -> LdapClientService:
        """Get LDAP client using factory pattern with caching."""
        if self._client_cache is None:
            factory = self._get_service("ldap_client_factory")
            if callable(factory):
                self._client_cache = cast("FlextLDAPClient", factory())
            else:
                msg = "LDAP client factory is not callable"
                raise RuntimeError(msg)
        return self._client_cache

    def get_repository(self) -> LdapRepositoryService:
        """Get LDAP repository using factory pattern with caching."""
        if self._repository_cache is None:
            factory = self._get_service("ldap_repository_factory")
            if callable(factory):
                self._repository_cache = cast("FlextLDAPRepositories", factory())
            else:
                msg = "LDAP repository factory is not callable"
                raise RuntimeError(msg)
        # Return the actual Repository nested class, not the container
        return self._repository_cache.repository

    # Removed unnecessary alias methods - use get_repository() directly per SOURCE OF TRUTH

    def configure(self, settings: FlextLDAPSettings) -> FlextResult[None]:
        """Configure container with LDAP settings.

        Args:
            settings: LDAP settings to configure

        Returns:
            FlextResult[None]: Success or error result

        """
        try:
            # Validate and register settings in FlextContainer
            container = FlextContainer.get_global()
            settings_result = container.register("ldap_settings", settings)

            if not settings_result.is_success:
                return FlextResult.fail(
                    f"Settings registration failed: {settings_result.error}"
                )

            self.log_debug(
                "Container configured with settings",
                settings_type=type(settings).__name__,
            )
            return FlextResult.ok(None)

        except Exception as e:
            self.log_error("Configuration failed", error=str(e))
            return FlextResult.fail(f"Configuration failed: {e}")

    def _register_services(self, container: FlextContainer) -> FlextResult[None]:
        """Register LDAP service factories in FlextContainer directly.

        Uses lazy loading pattern to avoid instantiating abstract classes.
        """
        try:
            # Register service factories instead of instances to avoid abstract class issues
            def client_factory() -> FlextLDAPClient:
                """Factory for LDAP client using FlextLDAPClient directly."""
                # Local import to avoid circular imports - PLC0415 suppressed for factory pattern

                return FlextLDAPClient()

            def repository_factory() -> FlextLDAPRepositories:
                """Factory for LDAP repository using cached client."""
                # Get the cached client instance through the container's get_client method
                if hasattr(self, "_client_cache") and self._client_cache is not None:
                    client = self._client_cache
                else:
                    client = client_factory()
                return FlextLDAPRepositories(client)

            # Register service factories in FlextContainer
            services = [
                ("ldap_client_factory", client_factory),
                ("ldap_repository_factory", repository_factory),
            ]

            # Register all service factories in FlextContainer
            for service_name, service_factory in services:
                registration_result = container.register(service_name, service_factory)
                if not registration_result.is_success:
                    error_msg = f"Failed to register service '{service_name}': {registration_result.error}"
                    self.log_error(
                        "Service registration failed",
                        service=service_name,
                        error=registration_result.error,
                    )
                    return FlextResult.fail(error_msg)

            self.log_info(
                "LDAP service factories registered in FlextContainer",
                count=len(services),
            )
            return FlextResult.ok(None)

        except Exception as e:
            self.log_error("Failed to register LDAP services", error=str(e))
            return FlextResult.fail(f"Service registration error: {e}")

    def reset(self) -> None:
        """Reset LDAP service registrations using FlextContainer directly."""
        self._services_registered = False
        # Services are in FlextContainer global instance - reset flag only
        self.log_debug("LDAP service registration reset")

    def is_registered(self) -> bool:
        """Check if services are registered.

        Returns:
            bool: True if services are registered

        """
        return self._services_registered


__all__ = [
    "FlextLDAPContainer",
]

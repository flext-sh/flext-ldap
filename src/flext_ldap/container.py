"""FLEXT-LDAP Container - Class-based dependency injection using flext-core.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from typing import cast, final

from flext_core import (
    FlextContainer,
    FlextMixins,
    FlextResult,
)

from flext_ldap.clients import FlextLDAPClient
from flext_ldap.config import FlextLDAPConfig
from flext_ldap.operations import FlextLDAPOperations
from flext_ldap.repositories import FlextLDAPRepositories

# Python 3.13 type aliases for container services
type LdapClientService = FlextLDAPClient
type LdapRepositoryService = FlextLDAPRepositories.Repository
type ContainerServiceKey = str


@final
class FlextLDAPContainer(FlextMixins.Loggable):
    """FLEXT-LDAP Container - Direct FlextContainer patterns integration.

    Optimized to use FlextContainer patterns directly without custom caching/registry logic.
    Single responsibility: Bridge between LDAP components and flext-core DI patterns.
    """

    def __init__(self, **data: object) -> None:
        """Initialize container manager using pure FlextContainer patterns."""
        super().__init__(**data)
        self._initialized = False
        self.log_debug("FlextLDAPContainer initialized with FlextContainer patterns")

    def get_container(self) -> FlextContainer:
        """Get flext-core container with LDAP services registered.

        Returns:
            FlextContainer: The global flext-core container with LDAP services

        """
        container = FlextContainer.get_global()

        if not self._initialized:
            registration_result = self._register_services(container)
            if not registration_result.is_success:
                self.log_error(
                    "Failed to register LDAP services", error=registration_result.error
                )
                msg = f"LDAP service registration failed: {registration_result.error}"
                raise RuntimeError(msg)
            self._initialized = True

        return container

    def get_client(self) -> LdapClientService:
        """Get LDAP client using FlextContainer directly."""
        container = self.get_container()
        result = container.get("ldap_client")

        if not result.is_success:
            msg = f"Failed to get LDAP client: {result.error}"
            self.log_error("LDAP client resolution failed", error=result.error)
            raise RuntimeError(msg)

        return cast("FlextLDAPClient", result.value)

    def get_repository(self) -> LdapRepositoryService:
        """Get LDAP repository using FlextContainer directly."""
        container = self.get_container()
        result = container.get("ldap_repository")

        if not result.is_success:
            msg = f"Failed to get LDAP repository: {result.error}"
            self.log_error("LDAP repository resolution failed", error=result.error)
            raise RuntimeError(msg)

        return cast("LdapRepositoryService", result.value)

    # Removed unnecessary alias methods - use get_repository() directly per SOURCE OF TRUTH

    def configure(self, config: FlextLDAPConfig) -> FlextResult[None]:
        """Configure container with LDAP settings.

        Args:
            config: LDAP configuration to configure

        Returns:
            FlextResult[None]: Success or error result

        """
        try:
            # Validate and register settings in FlextContainer
            container = FlextContainer.get_global()

            # Use FlextContainer's built-in existence check
            settings_result = container.register("ldap_settings", config)

            if not settings_result.is_success:
                return FlextResult.fail(
                    f"Settings registration failed: {settings_result.error}"
                )

            self.log_debug(
                "Container configured with settings",
                settings_type=type(config).__name__,
            )
            return FlextResult.ok(None)

        except Exception as e:
            self.log_error("Configuration failed", error=str(e))
            return FlextResult.fail(f"Configuration failed: {e}")

    def _register_services(self, container: FlextContainer) -> FlextResult[None]:
        """Register LDAP services using FlextContainer singleton patterns.

        Uses FlextContainer's built-in singleton/factory patterns exclusively.
        """
        try:
            # Register concrete service instances directly - FlextContainer handles singletons
            client_result = container.register("ldap_client", FlextLDAPClient())
            if not client_result.is_success:
                return FlextResult.fail(
                    f"Failed to register LDAP client: {client_result.error}"
                )

            # Get client for repository dependency injection
            client_get_result = container.get("ldap_client")
            if not client_get_result.is_success:
                return FlextResult.fail(
                    f"Failed to retrieve LDAP client: {client_get_result.error}"
                )

            repository = FlextLDAPRepositories(
                cast("FlextLDAPClient", client_get_result.value)
            )
            repository_result = container.register(
                "ldap_repository", repository.repository
            )
            if not repository_result.is_success:
                return FlextResult.fail(
                    f"Failed to register LDAP repository: {repository_result.error}"
                )

            # Register operations
            operations_result = container.register(
                "ldap_operations", FlextLDAPOperations()
            )
            if not operations_result.is_success:
                return FlextResult.fail(
                    f"Failed to register LDAP operations: {operations_result.error}"
                )

            self.log_info(
                "LDAP services registered in FlextContainer using direct patterns",
                services_count=3,
            )
            return FlextResult.ok(None)

        except Exception as e:
            self.log_error("Failed to register LDAP services", error=str(e))
            return FlextResult.fail(f"Service registration error: {e}")

    def reset(self) -> None:
        """Reset LDAP container state."""
        self._initialized = False
        self.log_debug("LDAP container state reset")

    def is_registered(self) -> bool:
        """Check if services are registered.

        Returns:
            bool: True if services are registered

        """
        return self._initialized


__all__ = [
    "FlextLDAPContainer",
]

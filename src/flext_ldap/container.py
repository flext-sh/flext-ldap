"""FLEXT-LDAP Container - Class-based dependency injection using flext-core.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from typing import TYPE_CHECKING, TypeVar, cast

from flext_core import (
    FlextContainer,
    FlextLogger,
    FlextResult,
    FlextServices,
)

from flext_ldap.clients import FlextLDAPClient
from flext_ldap.repositories import FlextLDAPRepositories

if TYPE_CHECKING:
    from flext_ldap.settings import FlextLDAPSettings

# Type variable for generic service resolution
T = TypeVar("T")

logger = FlextLogger(__name__)


class FlextLDAPContainer:
    """FLEXT-LDAP Container - Advanced dependency injection using FlextServices patterns.

    Uses FlextServices.ServiceRegistry from flext-core to eliminate code duplication
    and provide enterprise-grade service discovery and management with backward compatibility.
    """

    def __init__(self) -> None:
        """Initialize container manager with FlextServices.ServiceRegistry."""
        self._services_registered = False
        self._service_registry = FlextServices.ServiceRegistry()
        logger.debug(
            "FlextLDAPContainer initialized with FlextServices.ServiceRegistry",
        )

    def get_container(self) -> FlextContainer:
        """Get flext-core container with LDAP services registered.

        Returns:
            FlextContainer: The global flext-core container with LDAP services

        Raises:
            RuntimeError: If service registration fails

        """
        container = FlextContainer.get_global()

        # Register LDAP services once
        if not self._services_registered:
            registration_result = self._register_services(container)
            if not registration_result.is_success:
                logger.error(
                    "Failed to register LDAP services: %s",
                    registration_result.error,
                )
                error_msg = (
                    f"LDAP service registration failed: {registration_result.error}"
                )
                raise RuntimeError(error_msg)
            self._services_registered = True

        return container

    def _get_service(self, service_key: str) -> object:
        """Generic service resolver using FlextServices.ServiceRegistry.

        Uses flext-core ServiceRegistry for service discovery instead of custom logic.

        Args:
            service_key: Service name for registry lookup
            service_type: Expected service type for type safety

        Returns:
            T: The resolved service instance

        Raises:
            RuntimeError: If service resolution fails

        """
        # Use FlextServices.ServiceRegistry for service discovery
        discovery_result = self._service_registry.discover(service_key)
        if not discovery_result.is_success:
            # Fallback to legacy container for backward compatibility
            container = self.get_container()
            result = container.get(service_key)
            if not result.is_success:
                msg = f"Failed to discover service '{service_key}': {discovery_result.error}"
                raise RuntimeError(msg)
            return result.value

        service_info = discovery_result.value
        service_instance = service_info.get("instance")
        if not service_instance:
            msg = f"Service '{service_key}' has no instance registered"
            raise RuntimeError(msg)

        return service_instance

    def get_client(self) -> FlextLDAPClient:
        """Get LDAP client using generic resolver."""
        return cast("FlextLDAPClient", self._get_service("FlextLDAPClient"))

    def get_repository(self) -> FlextLDAPRepositories.Repository:
        """Get LDAP repository using generic resolver."""
        return cast(
            "FlextLDAPRepositories.Repository",
            self._get_service("FlextLDAPRepositories.Repository"),
        )

    def get_user_repository(self) -> FlextLDAPRepositories.UserRepository:
        """Get LDAP user repository using generic resolver."""
        return cast(
            "FlextLDAPRepositories.UserRepository",
            self._get_service("FlextLDAPRepositories.UserRepository"),
        )

    def get_group_repository(self) -> FlextLDAPRepositories.GroupRepository:
        """Get LDAP group repository using generic resolver."""
        return cast(
            "FlextLDAPRepositories.GroupRepository",
            self._get_service("FlextLDAPRepositories.GroupRepository"),
        )

    def configure(self, settings: FlextLDAPSettings) -> FlextResult[None]:
        """Configure container with LDAP settings.

        Args:
            settings: LDAP settings to configure

        Returns:
            FlextResult[None]: Success or error result

        """
        try:
            # For now, just validate settings exist
            logger.debug("Container configured with settings: %s", type(settings))
            return FlextResult.ok(None)
        except Exception as e:
            return FlextResult.fail(f"Configuration failed: {e}")

    def _register_services(self, container: FlextContainer) -> FlextResult[None]:
        """Register LDAP services in container."""
        try:
            # Create service instances using dependency injection pattern
            client = FlextLDAPClient()
            repository = FlextLDAPRepositories.Repository(client)
            user_repository = FlextLDAPRepositories.UserRepository(repository)
            group_repository = FlextLDAPRepositories.GroupRepository(repository)

            # Register services using FlextServices.ServiceRegistry pattern
            services = [
                {
                    "name": "FlextLDAPClient",
                    "instance": client,
                    "type": "infrastructure",
                },
                {
                    "name": "FlextLDAPRepositories.Repository",
                    "instance": repository,
                    "type": "application",
                },
                {
                    "name": "FlextLDAPRepositories.UserRepository",
                    "instance": user_repository,
                    "type": "domain",
                },
                {
                    "name": "FlextLDAPRepositories.GroupRepository",
                    "instance": group_repository,
                    "type": "domain",
                },
            ]

            # Register all services in the registry
            for service_info in services:
                registration_result = self._service_registry.register(service_info)
                if not registration_result.is_success:
                    return FlextResult.fail(
                        f"Failed to register service '{service_info['name']}': {registration_result.error}",
                    )

                # Also register in legacy container for backward compatibility
                service_name = service_info["name"]
                service_instance = service_info["instance"]
                if isinstance(service_name, str):
                    legacy_result = container.register(service_name, service_instance)
                else:
                    legacy_result = FlextResult.fail(
                        "Service name must be string",
                    )
                if not legacy_result.is_success:
                    logger.warning(
                        "Failed to register '%s' in legacy container: %s",
                        service_info["name"],
                        legacy_result.error,
                    )

            logger.info("LDAP services registered with FlextServices.ServiceRegistry")
            return FlextResult.ok(None)

        except Exception as e:
            logger.exception("Failed to register LDAP services")
            return FlextResult.fail(f"Service registration error: {e}")

    def reset(self) -> None:
        """Reset LDAP service registrations using FlextServices pattern."""
        self._services_registered = False
        # Reinitialize service registry to clear all registrations
        self._service_registry = FlextServices.ServiceRegistry()
        logger.debug("LDAP service registration reset with new ServiceRegistry")

    def is_registered(self) -> bool:
        """Check if services are registered.

        Returns:
            bool: True if services are registered

        """
        return self._services_registered


__all__ = [
    "FlextLDAPContainer",
]

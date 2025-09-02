"""FLEXT-LDAP Container - Class-based dependency injection using flext-core."""

from flext_core import FlextContainer, FlextLogger, FlextResult

from flext_ldap.clients import FlextLDAPClient
from flext_ldap.configuration import FlextLDAPSettings
from flext_ldap.repositories import (
    FlextLDAPGroupRepository,
    FlextLDAPRepository,
    FlextLDAPUserRepository,
)

logger = FlextLogger(__name__)


class FlextLDAPContainer:
    """FLEXT-LDAP Container - Class-based dependency injection management.

    Eliminates all standalone functions and provides clean class-based API
    for managing LDAP service dependencies through flext-core container.
    """

    def __init__(self) -> None:
        """Initialize container manager."""
        self._services_registered = False
        logger.debug("FlextLDAPContainer initialized")

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
                    f"Failed to register LDAP services: {registration_result.error}"
                )
                error_msg = (
                    f"LDAP service registration failed: {registration_result.error}"
                )
                raise RuntimeError(error_msg)
            self._services_registered = True

        return container

    def _register_services(self, container: FlextContainer) -> FlextResult[None]:
        """Register LDAP services with flext-core container.

        Args:
            container: The flext-core container to register services with

        Returns:
            FlextResult[None]: Success or error result

        """
        try:
            # Register LDAP client instance
            client = FlextLDAPClient()
            client_result = container.register("FlextLDAPClient", client)
            if not client_result.is_success:
                return FlextResult[None].fail(
                    f"Failed to register client: {client_result.error}"
                )

            # Register repository with client dependency
            repository = FlextLDAPRepository(client)
            repo_result = container.register("FlextLDAPRepository", repository)
            if not repo_result.is_success:
                return FlextResult[None].fail(
                    f"Failed to register repository: {repo_result.error}"
                )

            # Register user repository
            user_repository = FlextLDAPUserRepository(repository)
            user_repo_result = container.register(
                "FlextLDAPUserRepository", user_repository
            )
            if not user_repo_result.is_success:
                return FlextResult[None].fail(
                    f"Failed to register user repository: {user_repo_result.error}"
                )

            # Register group repository
            group_repository = FlextLDAPGroupRepository(repository)
            group_repo_result = container.register(
                "FlextLDAPGroupRepository", group_repository
            )
            if not group_repo_result.is_success:
                return FlextResult[None].fail(
                    f"Failed to register group repository: {group_repo_result.error}"
                )

            logger.info("LDAP services registered with flext-core container")
            return FlextResult[None].ok(None)

        except Exception as e:
            logger.exception("Failed to register LDAP services")
            return FlextResult[None].fail(f"Service registration error: {e}")

    def configure(self, settings: FlextLDAPSettings) -> FlextResult[None]:
        """Configure LDAP services with settings.

        Args:
            settings: LDAP settings configuration

        Returns:
            FlextResult[None]: Success or error result

        """
        container = self.get_container()

        # Register settings as a service
        settings_result = container.register("FlextLDAPSettings", settings)

        if settings_result.is_success:
            logger.info("LDAP container configured with settings")
            return FlextResult[None].ok(None)
        return FlextResult[None].fail(
            f"Failed to register settings: {settings_result.error}"
        )

    def reset(self) -> None:
        """Reset LDAP service registrations."""
        self._services_registered = False
        logger.debug("LDAP service registration reset")

    def is_registered(self) -> bool:
        """Check if services are registered.

        Returns:
            bool: True if services are registered

        """
        return self._services_registered


__all__ = [
    "FlextLDAPContainer",
]

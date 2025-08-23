"""LDAP dependency injection container extending flext-core patterns."""

from __future__ import annotations

from typing import Protocol

from flext_core import FlextContainer, FlextResult, get_logger

from flext_ldap.clients import FlextLdapClient
from flext_ldap.configuration import FlextLdapSettings
from flext_ldap.interfaces import IFlextLdapClient, IFlextLdapRepository
from flext_ldap.repositories import (
    FlextLdapGroupRepository,
    FlextLdapRepository,
    FlextLdapUserRepository,
)

logger = get_logger(__name__)


class IFlextLdapContainer(Protocol):
    """Protocol for LDAP dependency injection container."""

    def get_client(self) -> FlextLdapClient:
        """Get LDAP client instance."""
        ...

    def get_repository(self) -> FlextLdapRepository:
        """Get LDAP repository instance."""
        ...

    def get_user_repository(self) -> FlextLdapUserRepository:
        """Get user repository instance."""
        ...

    def get_group_repository(self) -> FlextLdapGroupRepository:
        """Get group repository instance."""
        ...

    def configure(self, settings: FlextLdapSettings) -> FlextResult[None]:
        """Configure container with settings."""
        ...


class FlextLdapContainer(FlextContainer):
    """LDAP dependency injection container extending flext-core."""

    def __init__(self) -> None:
        """Initialize LDAP container."""
        super().__init__()
        self._settings: FlextLdapSettings | None = None
        self._client_instance: FlextLdapClient | None = None
        self._repository_instance: FlextLdapRepository | None = None
        self._user_repository_instance: FlextLdapUserRepository | None = None
        self._group_repository_instance: FlextLdapGroupRepository | None = None

    def configure(self, settings: FlextLdapSettings) -> FlextResult[None]:
        """Configure container with settings."""
        # Validate settings
        validation_result = settings.validate_business_rules()
        if not validation_result.is_success:
            return FlextResult[None].fail(
                f"Settings validation failed: {validation_result.error}",
            )

        self._settings = settings

        # Reset instances to force recreation with new settings
        self._client_instance = None
        self._repository_instance = None
        self._user_repository_instance = None
        self._group_repository_instance = None

        logger.info("Container configured with new settings")
        return FlextResult[None].ok(None)

    def get_client(self) -> FlextLdapClient:
        """Get LDAP client instance (singleton)."""
        if self._client_instance is None:
            self._client_instance = FlextLdapClient()
            logger.debug("Created new LDAP client instance")

        return self._client_instance

    def get_repository(self) -> FlextLdapRepository:
        """Get LDAP repository instance (singleton)."""
        if self._repository_instance is None:
            client = self.get_client()
            self._repository_instance = FlextLdapRepository(client)
            logger.debug("Created new LDAP repository instance")

        return self._repository_instance

    def get_user_repository(self) -> FlextLdapUserRepository:
        """Get user repository instance (singleton)."""
        if self._user_repository_instance is None:
            base_repo = self.get_repository()
            self._user_repository_instance = FlextLdapUserRepository(base_repo)
            logger.debug("Created new user repository instance")

        return self._user_repository_instance

    def get_group_repository(self) -> FlextLdapGroupRepository:
        """Get group repository instance (singleton)."""
        if self._group_repository_instance is None:
            base_repo = self.get_repository()
            self._group_repository_instance = FlextLdapGroupRepository(base_repo)
            logger.debug("Created new group repository instance")

        return self._group_repository_instance

    def get_settings(self) -> FlextLdapSettings:
        """Get current settings."""
        if self._settings is None:
            # Return default settings if none configured
            self._settings = FlextLdapSettings()
            logger.warning(
                "Using default settings - consider configuring container explicitly",
            )

        return self._settings

    def register_client(self, client: IFlextLdapClient) -> FlextResult[None]:
        """Register custom client implementation."""
        if not isinstance(client, FlextLdapClient):
            return FlextResult[None].fail("Client must be instance of FlextLdapClient")

        self._client_instance = client
        # Reset dependent instances
        self._repository_instance = None
        self._user_repository_instance = None
        self._group_repository_instance = None

        logger.info("Custom client registered")
        return FlextResult[None].ok(None)

    def register_repository(
        self, repository: IFlextLdapRepository,
    ) -> FlextResult[None]:
        """Register custom repository implementation."""
        if not isinstance(repository, FlextLdapRepository):
            return FlextResult[None].fail(
                "Repository must be instance of FlextLdapRepository",
            )

        self._repository_instance = repository
        # Reset dependent instances
        self._user_repository_instance = None
        self._group_repository_instance = None

        logger.info("Custom repository registered")
        return FlextResult[None].ok(None)

    def reset(self) -> None:
        """Reset all instances (useful for testing)."""
        self._client_instance = None
        self._repository_instance = None
        self._user_repository_instance = None
        self._group_repository_instance = None
        self._settings = None

        logger.debug("Container reset - all instances cleared")

    async def cleanup(self) -> FlextResult[None]:
        """Cleanup resources."""
        if self._client_instance:
            try:
                await self._client_instance.unbind()
            except Exception as e:
                logger.exception("Error during client cleanup", extra={"error": str(e)})
                return FlextResult[None].fail(f"Cleanup failed: {e}")

        self.reset()
        logger.info("Container cleanup completed")
        return FlextResult[None].ok(None)


# Global container instance
_ldap_container: FlextLdapContainer | None = None


def get_ldap_container() -> FlextLdapContainer:
    """Get global LDAP container instance."""
    global _ldap_container  # noqa: PLW0603
    if _ldap_container is None:
        _ldap_container = FlextLdapContainer()
        logger.debug("Created global LDAP container")

    return _ldap_container


def configure_ldap_container(settings: FlextLdapSettings) -> FlextResult[None]:
    """Configure global LDAP container."""
    container = get_ldap_container()
    return container.configure(settings)


def reset_ldap_container() -> None:
    """Reset global LDAP container (useful for testing)."""
    global _ldap_container  # noqa: PLW0603
    if _ldap_container:
        _ldap_container.reset()
        _ldap_container = None
        logger.debug("Global LDAP container reset")

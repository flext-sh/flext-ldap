"""LDAP dependency injection using flext-core container - ELIMINATES LOCAL CONTAINER."""

from __future__ import annotations

from flext_core import FlextContainer, FlextResult, get_flext_container, get_logger

from flext_ldap.clients import FlextLdapClient
from flext_ldap.configuration import FlextLdapSettings
from flext_ldap.repositories import (
    FlextLdapGroupRepository,
    FlextLdapRepository,
    FlextLdapUserRepository,
)

logger = get_logger(__name__)


# =============================================================================
# FLEXT-CORE INTEGRATION - LOCAL CONTAINER ELIMINATED
# =============================================================================

# LOCAL CONTAINER PROTOCOL ELIMINATED - USE FlextProtocols FROM FLEXT-CORE
# Per CLAUDE.md: "Dependency Injection: Use get_flext_container() from flext-core, NO local containers"


# =============================================================================
# SERVICE REGISTRATION WITH FLEXT-CORE CONTAINER
# =============================================================================

# Factory functions removed - using direct instantiation with flext-core container.register()


def _register_ldap_services(container: FlextContainer) -> FlextResult[None]:
    """Register LDAP services with flext-core container using proper API."""
    try:
        # Register LDAP client instance
        client = FlextLdapClient()
        client_result = container.register("FlextLdapClient", client)
        if not client_result.is_success:
            return FlextResult[None].fail(f"Failed to register client: {client_result.error}")

        # Register repository with client dependency
        repository = FlextLdapRepository(client)
        repo_result = container.register("FlextLdapRepository", repository)
        if not repo_result.is_success:
            return FlextResult[None].fail(f"Failed to register repository: {repo_result.error}")

        # Register user repository
        user_repository = FlextLdapUserRepository(repository)
        user_repo_result = container.register("FlextLdapUserRepository", user_repository)
        if not user_repo_result.is_success:
            return FlextResult[None].fail(f"Failed to register user repository: {user_repo_result.error}")

        # Register group repository
        group_repository = FlextLdapGroupRepository(repository)
        group_repo_result = container.register("FlextLdapGroupRepository", group_repository)
        if not group_repo_result.is_success:
            return FlextResult[None].fail(f"Failed to register group repository: {group_repo_result.error}")

        logger.info("LDAP services registered with flext-core container")
        return FlextResult[None].ok(None)

    except Exception as e:
        logger.exception("Failed to register LDAP services")
        return FlextResult[None].fail(f"Service registration error: {e}")


# =============================================================================
# FLEXT-CORE CONTAINER INTEGRATION - LOCAL CONTAINER ELIMINATED
# =============================================================================

class _LdapContainerRegistry:
    """Registry to track LDAP service registration state."""

    def __init__(self) -> None:
        self.services_registered = False

    def mark_registered(self) -> None:
        """Mark services as registered."""
        self.services_registered = True

    def reset(self) -> None:
        """Reset registration state."""
        self.services_registered = False

    def is_registered(self) -> bool:
        """Check if services are registered."""
        return self.services_registered


_registry = _LdapContainerRegistry()


def get_ldap_container() -> FlextContainer:
    """Get flext-core container with LDAP services registered.

    CLAUDE.md COMPLIANCE: Uses get_flext_container() instead of local container.
    """
    # Get the central flext-core container
    container = get_flext_container()

    # Register LDAP services once
    if not _registry.is_registered():
        registration_result = _register_ldap_services(container)
        if not registration_result.is_success:
            logger.error(f"Failed to register LDAP services: {registration_result.error}")
            error_msg = f"LDAP service registration failed: {registration_result.error}"
            raise RuntimeError(error_msg)
        _registry.mark_registered()

    return container


def configure_ldap_container(settings: FlextLdapSettings) -> FlextResult[None]:
    """Configure LDAP services in flext-core container with settings."""
    container = get_ldap_container()  # Now returns flext-core container

    # Register settings as a service
    settings_result = container.register("FlextLdapSettings", settings)

    if settings_result.is_success:
        logger.info("LDAP container configured with settings using flext-core")
        return FlextResult[None].ok(None)
    return FlextResult[None].fail(f"Failed to register settings: {settings_result.error}")


def reset_ldap_container() -> None:
    """Reset LDAP service registrations in flext-core container."""
    # Reset registration flag to allow re-registration
    _registry.reset()
    logger.debug("LDAP service registration reset - will re-register on next access")

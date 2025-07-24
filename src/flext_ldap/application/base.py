"""Base service classes to eliminate massive code duplication in FLEXT LDAP services.

This module provides foundational base classes that encapsulate common patterns
used across ALL LDAP application services, following DRY principles and Clean
Architecture.

ELIMINATES DUPLICATIONS:
- Dictionary-based storage patterns (4 services with identical patterns)
- CRUD operation patterns (get, list, delete - massively repeated)
- Error handling patterns (try/catch blocks repeated everywhere)
- Not found validation patterns (identical logic in all services)
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any, Protocol, TypeVar, cast
from uuid import UUID

# 🚨 ARCHITECTURAL COMPLIANCE: Using flext-core root imports
from flext_core import FlextResult


# Protocol for entities with ID attribute
class FlextLdapEntityWithId(Protocol):
    """Protocol for entities that have an id attribute."""

    id: str


# Generic types for entity storage patterns
TEntity = TypeVar("TEntity", bound=FlextLdapEntityWithId)


class FlextLdapBaseService:
    """Base class for all LDAP application services.

    Provides common initialization pattern to eliminate
    basic duplication across service classes.
    """

    def __init__(self) -> None:
        """Initialize base LDAP service."""


class FlextLdapDictionaryStorageService[TEntity](FlextLdapBaseService):
    """Base class for services using dictionary-based entity storage.

    Eliminates massive duplication across LDAPUserService, LDAPGroupService,
    LDAPConnectionService, and LDAPOperationService - ALL use identical
    dict[UUID, EntityType] = {} patterns.
    """

    def __init__(self) -> None:
        """Initialize service with dictionary storage."""
        super().__init__()
        self._entities: dict[str, TEntity] = {}

    async def get_entity(self, entity_id: UUID | str) -> FlextResult[Any]:
        """Get an entity by ID - ELIMINATES MASSIVE DUPLICATION.

        This method replaces IDENTICAL implementations in:
        - LDAPUserService.get_user()
        - LDAPGroupService.get_group()
        - LDAPConnectionService.get_connection()
        - LDAPOperationService.get_operation()

        Args:
            entity_id: The unique identifier of the entity

        Returns:
            FlextResult containing the entity if found, None if not found, or error

        """
        try:
            # Convert UUID to string if needed
            key = str(entity_id) if isinstance(entity_id, UUID) else entity_id
            entity = self._entities.get(key)
            return FlextResult.ok(entity)
        except (KeyError, AttributeError) as e:
            return FlextResult.fail(f"Failed to get entity: {e}")

    async def delete_entity(self, entity_id: UUID | str) -> FlextResult[Any]:
        """Delete an entity by ID - ELIMINATES MASSIVE DUPLICATION.

        This method replaces IDENTICAL implementations in:
        - LDAPUserService.delete_user()
        - LDAPGroupService.delete_group()

        Args:
            entity_id: The unique identifier of the entity to delete

        Returns:
            FlextResult containing True if deleted successfully, or error

        """
        try:
            # Convert UUID to string if needed
            key = str(entity_id) if isinstance(entity_id, UUID) else entity_id
            if key in self._entities:
                del self._entities[key]
                return FlextResult.ok(True)
            return FlextResult.fail("Entity not found")
        except (KeyError, ValueError) as e:
            return FlextResult.fail(f"Failed to delete entity: {e}")

    async def list_entities_by_ou(
        self,
        ou: str | None = None,
        limit: int = 100,
    ) -> FlextResult[Any]:
        """List entities with organizational unit filtering - ELIMINATES DUPLICATION.

        This method replaces SIMILAR implementations in:
        - LDAPUserService.list_users()
        - LDAPGroupService.list_groups()

        Args:
            ou: Organizational unit to filter by (optional)
            limit: Maximum number of entities to return

        Returns:
            FlextResult containing list of entities or error

        """
        try:
            entities = list(self._entities.values())

            if ou:
                # Filter by OU if entity has ou attribute
                entities = [e for e in entities if getattr(e, "ou", None) == ou]

            return FlextResult.ok(entities[:limit])
        except (KeyError, ValueError) as e:
            return FlextResult.fail(f"Failed to list entities: {e}")

    def _store_entity(self, entity: TEntity) -> None:
        """Store entity in internal dictionary.

        Args:
            entity: Entity to store (must have 'id' attribute)

        """
        entity_id = cast(
            "EntityWithId",
            entity,
        ).id  # Guaranteed by EntityWithId protocol
        self._entities[entity_id] = entity


class FlextLdapDNSearchService(FlextLdapDictionaryStorageService[TEntity]):
    """Base class for services that search entities by distinguished name.

    Eliminates MASSIVE duplication in:
    - LDAPUserService.find_user_by_dn()
    - LDAPGroupService.find_group_by_dn()
    """

    async def find_entity_by_dn(self, dn: str) -> FlextResult[Any]:
        """Find entity by distinguished name - ELIMINATES DUPLICATION.

        Args:
            dn: Distinguished name to search for

        Returns:
            FlextResult containing the entity if found, None if not found, or error

        """
        try:
            for entity in self._entities.values():
                if getattr(entity, "dn", None) == dn:
                    return FlextResult.ok(entity)
            return FlextResult.ok(None)
        except (KeyError, AttributeError) as e:
            return FlextResult.fail(f"Failed to find entity by DN: {e}")


class FlextLdapClientService(FlextLdapBaseService):
    """Base class for services that require LDAP client infrastructure.

    Eliminates duplication in LDAPUserService and LDAPConnectionService
    initialization patterns.
    """

    def __init__(self, ldap_client: Any | None = None) -> None:
        """Initialize service with LDAP client dependency.

        Args:
            ldap_client: LDAP infrastructure client (optional)

        """
        super().__init__()
        # Import here to avoid circular imports
        from flext_ldap.infrastructure.ldap_client import FlextLdapInfrastructureClient

        self._ldap_client = ldap_client or FlextLdapInfrastructureClient()


class FlextLdapConnectionAwareService(FlextLdapClientService):
    """Base class for services that maintain connection state.

    Eliminates duplication in LDAPUserService connection management.
    """

    def __init__(self, ldap_client: Any | None = None) -> None:
        """Initialize service with connection awareness."""
        super().__init__(ldap_client)
        self._connection_id: str | None = None

    async def set_connection(self, connection_id: str) -> FlextResult[Any]:
        """Set the LDAP connection ID for directory operations.

        Args:
            connection_id: The LDAP connection identifier

        Returns:
            FlextResult indicating success or failure

        """
        try:
            self._connection_id = connection_id
            return FlextResult.ok(True)
        except (ValueError, TypeError) as e:
            return FlextResult.fail(f"Failed to set connection: {e}")

    async def clear_connection(self) -> FlextResult[Any]:
        """Clear the LDAP connection (revert to memory-only mode).

        Returns:
            FlextResult indicating success or failure

        """
        try:
            self._connection_id = None
            return FlextResult.ok(True)
        except (ValueError, TypeError) as e:
            return FlextResult.fail(f"Failed to clear connection: {e}")


# Specialized base classes for specific LDAP entity types
class FlextLdapUserBaseService(
    FlextLdapDNSearchService[Any],
    FlextLdapConnectionAwareService,
):
    """Specialized base class for LDAP user services.

    Combines all patterns needed by LDAPUserService:
    - Dictionary storage (from DictionaryStorageService)
    - DN search capability (from DNSearchService)
    - LDAP client integration (from LDAPClientService)
    - Connection awareness (from ConnectionAwareService)
    """

    def __init__(self, ldap_client: Any | None = None) -> None:
        """Initialize user service with all required capabilities."""
        # Initialize both parent classes properly
        FlextLdapDNSearchService.__init__(self)
        FlextLdapConnectionAwareService.__init__(self, ldap_client)

    async def find_entity_by_uid(self, uid: str) -> FlextResult[Any]:
        """Find user by UID - specific to user entities.

        Args:
            uid: User identifier to search for

        Returns:
            FlextResult containing the user if found, None if not found, or error

        """
        try:
            for entity in self._entities.values():
                if getattr(entity, "uid", None) == uid:
                    return FlextResult.ok(entity)
            return FlextResult.ok(None)
        except (KeyError, AttributeError) as e:
            return FlextResult.fail(f"Failed to find entity by UID: {e}")


class FlextLdapGroupBaseService(
    FlextLdapDNSearchService[Any],
    FlextLdapConnectionAwareService,
):
    """Specialized base class for LDAP group services.

    Combines all patterns needed by LDAPGroupService:
    - Dictionary storage (from DictionaryStorageService)
    - DN search capability (from DNSearchService)
    - LDAP client integration (from LDAPClientService)
    - Connection awareness (from ConnectionAwareService)
    """

    def __init__(self, ldap_client: Any | None = None) -> None:
        """Initialize group service with all required capabilities."""
        # Initialize both parent classes properly
        FlextLdapDNSearchService.__init__(self)
        FlextLdapConnectionAwareService.__init__(self, ldap_client)


class FlextLdapConnectionBaseService(
    FlextLdapDictionaryStorageService[Any],
    FlextLdapClientService,
):
    """Specialized base class for LDAP connection services.

    Combines dictionary storage with LDAP client integration.
    """

    def __init__(self, ldap_client: Any | None = None) -> None:
        """Initialize connection service with required capabilities."""
        FlextLdapDictionaryStorageService.__init__(self)
        FlextLdapClientService.__init__(self, ldap_client)


class FlextLdapOperationBaseService(FlextLdapDictionaryStorageService[Any]):
    """Specialized base class for LDAP operation services."""

    async def list_entities_by_connection(
        self,
        connection_id: UUID | None = None,
        limit: int = 100,
    ) -> FlextResult[Any]:
        """List operations filtered by connection ID.

        Args:
            connection_id: Filter by connection ID (optional)
            limit: Maximum number of operations to return

        Returns:
            FlextResult containing list of operations or error

        """
        try:
            operations = list(self._entities.values())

            if connection_id:
                operations = [
                    op
                    for op in operations
                    if getattr(op, "connection_id", None) == str(connection_id)
                ]

            # Sort by started_at descending (handle None values)
            operations.sort(
                key=lambda op: getattr(op, "started_at", None) or "",
                reverse=True,
            )

            return FlextResult.ok(operations[:limit])
        except (KeyError, ValueError, AttributeError) as e:
            return FlextResult.fail(f"Failed to list operations: {e}")


# Backward compatibility alias
EntityWithId = FlextLdapEntityWithId

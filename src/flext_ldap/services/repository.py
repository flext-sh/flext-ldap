"""Domain.Repository pattern implementation for LDAP data access.

Provides abstract repository base class with standardized CRUD interface
following Clean Architecture and FlextResult railway-oriented error handling.

Implements generic Repository[T_co] protocol for type-safe data access layer.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from abc import ABC, abstractmethod

from flext_core import FlextResult

# Type parameters using PEP 695 syntax (Python 3.12+)
type T_co = object  # Covariant type variable for Repository return types
type T_in = object  # Contravariant type variables for input parameters
type ID_Type = object


class RepositoryBase[T_co](ABC):
    """Abstract repository base class implementing Domain.Repository protocol.

    Provides standardized CRUD (Create, Read, Update, Delete) interface with
    FlextResult-based error handling for all operations.

    **Pattern**: Domain-Driven Design Repository pattern
    **Error Handling**: Railway-Oriented Programming via FlextResult[T]
    **Inheritance**: Derive from this class and implement abstract methods

    **Standard CRUD Methods**:
    - `get_by_id(id)` -> FlextResult[T_co | None]: Retrieve single entity
    - `get_all()` -> FlextResult[list[T_co]]: Retrieve all entities
    - `add(entity)` -> FlextResult[T_co]: Create new entity
    - `update(entity)` -> FlextResult[T_co]: Update existing entity
    - `delete(id)` -> FlextResult[bool]: Delete entity (returns success/failure)
    - `exists(id)` -> FlextResult[bool]: Check entity existence

    **FlextResult Semantics**:
    - Success: Result.is_success=True, contains entity or bool
    - Failure: Result.is_failure=True, contains error message
    - Chain operations: Use .flat_map() for composable error handling

    **Example Usage**:
    ```python
    from flext_ldap.services.repository import RepositoryBase
    from flext_core import FlextResult


    class UserRepository(RepositoryBase[User]):
        def get_by_id(self, user_id: str) -> FlextResult[User | None]:
            # Implementation
            return FlextResult.ok(user)

        def get_all(self) -> FlextResult[list[User]]:
            # Implementation
            return FlextResult.ok(users)

        def add(self, entity: User) -> FlextResult[User]:
            # Implementation
            return FlextResult.ok(entity)
    ```
    """

    @abstractmethod
    def get_by_id(self, entity_id: object) -> FlextResult[T_co | None]:
        """Retrieve entity by ID.

        Args:
            entity_id: Unique identifier for the entity

        Returns:
            FlextResult[T_co | None]: Entity if found, None if not found
                                      or error if operation fails

        **Examples**:
        - Success (found): FlextResult.ok(entity)
        - Success (not found): FlextResult.ok(None)
        - Failure: FlextResult.fail("Entity not found or database error")

        """
        ...

    @abstractmethod
    def get_all(self) -> FlextResult[list[T_co]]:
        """Retrieve all entities.

        Returns:
            FlextResult[list[T_co]]: List of entities (empty list if none)
                                    or error if operation fails

        **Examples**:
        - Success: FlextResult.ok([entity1, entity2, ...])
        - Empty: FlextResult.ok([])
        - Failure: FlextResult.fail("Database error")

        """
        ...

    @abstractmethod
    def add(self, entity: object) -> FlextResult[T_co]:
        """Create new entity in repository.

        Args:
            entity: Entity to create

        Returns:
            FlextResult[T_co]: Created entity with persistence applied
                               or error if operation fails

        **Guarantees**:
        - Entity is validated before creation
        - ID is assigned if auto-generated
        - All constraints are enforced
        - Returns created entity with assigned ID

        **Examples**:
        - Success: FlextResult.ok(created_entity_with_id)
        - Failure: FlextResult.fail("Validation error: Email already exists")

        """
        ...

    @abstractmethod
    def update(self, entity: object) -> FlextResult[T_co]:
        """Update existing entity in repository.

        Args:
            entity: Entity with updated values (must have ID)

        Returns:
            FlextResult[T_co]: Updated entity or error if operation fails

        **Guarantees**:
        - Only existing entities can be updated
        - All constraints are enforced
        - Optimistic locking may be applied
        - Returns updated entity

        **Examples**:
        - Success: FlextResult.ok(updated_entity)
        - Entity not found: FlextResult.fail("Entity not found")
        - Failure: FlextResult.fail("Update failed: constraint violation")

        """
        ...

    @abstractmethod
    def delete(self, entity_id: object) -> FlextResult[bool]:
        """Delete entity from repository.

        Args:
            entity_id: ID of entity to delete

        Returns:
            FlextResult[bool]: True if deleted, False if not found
                               or error if operation fails

        **Semantics**:
        - Returns True if entity existed and was deleted
        - Returns False if entity not found (still success)
        - Returns error if operation fails (database error, etc.)

        **Examples**:
        - Success (deleted): FlextResult.ok(True)
        - Success (not found): FlextResult.ok(False)
        - Failure: FlextResult.fail("Delete failed: constraint violation")

        """
        ...

    @abstractmethod
    def exists(self, entity_id: object) -> FlextResult[bool]:
        """Check if entity exists by ID.

        Args:
            entity_id: ID to check for existence

        Returns:
            FlextResult[bool]: True if entity exists, False otherwise
                               or error if operation fails

        **Performance**: Should be optimized for existence check only
        (avoid loading full entity if possible)

        **Examples**:
        - Exists: FlextResult.ok(True)
        - Not exists: FlextResult.ok(False)
        - Failure: FlextResult.fail("Database error")

        """
        ...


class LdapEntryRepository[T_co](RepositoryBase[T_co]):
    """LDAP Entry repository with DN-based identification.

    Specialized repository for LDAP entries using Distinguished Names (DN)
    as the unique identifier instead of simple IDs.

    **DN Semantics**:
    - DN (Distinguished Name) is the unique identifier for LDAP entries
    - DN format: cn=user,ou=people,dc=example,dc=com
    - Case-insensitive comparison for LDAP DNs

    **Additional Methods** (beyond RepositoryBase):
    - `search()` - Search entries by filter
    - `search_by_cn()` - Search by common name
    - `search_by_mail()` - Search by email address
    """

    @abstractmethod
    def search_by_attribute(
        self,
        attribute: str,
        value: str,
    ) -> FlextResult[list[T_co]]:
        """Search entries by LDAP attribute.

        Args:
            attribute: LDAP attribute name (e.g., 'mail', 'cn', 'uid')
            value: Value to search for

        Returns:
            FlextResult[list[T_co]]: Matching entries or error

        **Examples**:
        - Search by email: search_by_attribute('mail', 'user@example.com')
        - Search by UID: search_by_attribute('uid', 'jdoe')

        """
        ...


__all__ = [
    "ID_Type",
    "LdapEntryRepository",
    "RepositoryBase",
    "T_co",
    "T_in",
]

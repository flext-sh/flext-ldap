"""Protocol definitions for LDAP Core Shared interfaces.

This module defines the protocol interfaces that enable dependency injection
and polymorphism throughout the library, following the Interface Segregation
Principle from SOLID.

Design principles:
- Small, focused protocols for specific capabilities
- Zero implementation details - pure interfaces
- Type-safe contracts for all implementations
- Enable dependency injection and testing through abstractions
"""

from __future__ import annotations

from abc import abstractmethod
from typing import TYPE_CHECKING, Any, Protocol, runtime_checkable

if TYPE_CHECKING:
    import uuid
    from collections.abc import AsyncIterator

    from flext_ldap.types.aliases import (
        DN,
        Attributes,
        FilterExpression,
        OperationResult,
        SearchScope,
    )


@runtime_checkable
class Connectable(Protocol):
    """Protocol for objects that can establish LDAP connections.

    This protocol defines the interface for connection management,
    enabling different connection implementations while maintaining
    type safety and consistent behavior.

    Example:
        >>> class MyConnection:
        ...     async def connect(self, server_uri: str) -> bool:
        ...         # Implementation specific logic
        ...         return True
        ...
        ...     async def disconnect(self) -> bool:
        ...         return True
        ...
        ...     def is_connected(self) -> bool:
        ...         return True
        >>>
        >>> def use_connection(conn: Connectable) -> None:
        ...     # Type-safe usage of any Connectable implementation
        ...     if conn.is_connected():
        ...         print("Already connected")
    """

    @abstractmethod
    async def connect(self, server_uri: str, **kwargs: Any) -> bool:
        """Establish connection to LDAP server.

        Args:
            server_uri: URI of the LDAP server to connect to
            **kwargs: Additional connection parameters

        Returns:
            True if connection successful, False otherwise
        """

    @abstractmethod
    async def disconnect(self) -> bool:
        """Close the LDAP connection.

        Returns:
            True if disconnection successful, False otherwise
        """

    @abstractmethod
    def is_connected(self) -> bool:
        """Check if currently connected to LDAP server.

        Returns:
            True if connected, False otherwise
        """


@runtime_checkable
class Bindable(Protocol):
    """Protocol for objects that can perform LDAP bind operations.

    This protocol defines the interface for authentication operations,
    supporting both simple and SASL bind mechanisms.
    """

    @abstractmethod
    async def bind(self, user_dn: DN, password: str) -> bool:
        """Perform simple bind authentication.

        Args:
            user_dn: Distinguished name of the user
            password: User's password

        Returns:
            True if bind successful, False otherwise
        """

    @abstractmethod
    async def bind_sasl(self, mechanism: str, **kwargs: Any) -> bool:
        """Perform SASL bind authentication.

        Args:
            mechanism: SASL mechanism to use (e.g., 'GSSAPI', 'DIGEST-MD5')
            **kwargs: Mechanism-specific parameters

        Returns:
            True if bind successful, False otherwise
        """

    @abstractmethod
    async def unbind(self) -> bool:
        """Unbind from the LDAP server.

        Returns:
            True if unbind successful, False otherwise
        """


@runtime_checkable
class Searchable(Protocol):
    """Protocol for objects that can perform LDAP search operations.

    This protocol defines the interface for search functionality,
    supporting both synchronous and asynchronous result iteration.
    """

    @abstractmethod
    async def search(
        self,
        base_dn: DN,
        search_filter: FilterExpression,
        scope: SearchScope = "subtree",
        attributes: list[str] | None = None,
        **kwargs: Any,
    ) -> AsyncIterator[dict[str, Any]]:
        """Perform LDAP search operation.

        Args:
            base_dn: Base DN for the search
            search_filter: LDAP filter expression
            scope: Search scope (base, onelevel, subtree)
            attributes: List of attributes to retrieve
            **kwargs: Additional search parameters

        Yields:
            Dictionary representing each found entry
        """

    @abstractmethod
    async def search_one(
        self,
        base_dn: DN,
        search_filter: FilterExpression,
        attributes: list[str] | None = None,
        **kwargs: Any,
    ) -> dict[str, Any] | None:
        """Search for a single entry.

        Args:
            base_dn: Base DN for the search
            search_filter: LDAP filter expression
            attributes: List of attributes to retrieve
            **kwargs: Additional search parameters

        Returns:
            Dictionary representing the found entry, or None if not found
        """


@runtime_checkable
class Modifiable(Protocol):
    """Protocol for objects that can perform LDAP modification operations.

    This protocol defines the interface for add, modify, and delete operations.
    """

    @abstractmethod
    async def add(self, dn: DN, attributes: Attributes) -> OperationResult:
        """Add a new entry to the directory.

        Args:
            dn: Distinguished name of the new entry
            attributes: Attributes for the new entry

        Returns:
            Result of the add operation
        """

    @abstractmethod
    async def modify(self, dn: DN, changes: dict[str, Any]) -> OperationResult:
        """Modify an existing entry in the directory.

        Args:
            dn: Distinguished name of the entry to modify
            changes: Dictionary of changes to apply

        Returns:
            Result of the modify operation
        """

    @abstractmethod
    async def delete(self, dn: DN) -> OperationResult:
        """Delete an entry from the directory.

        Args:
            dn: Distinguished name of the entry to delete

        Returns:
            Result of the delete operation
        """


@runtime_checkable
class Validatable(Protocol):
    """Protocol for objects that can validate their state or data.

    This protocol enables validation capabilities across different
    components while maintaining separation of concerns.
    """

    @abstractmethod
    def validate(self) -> bool:
        """Validate the object's current state.

        Returns:
            True if object is in a valid state, False otherwise
        """

    @abstractmethod
    def get_validation_errors(self) -> list[str]:
        """Get detailed validation error messages.

        Returns:
            List of validation error messages, empty if valid
        """


@runtime_checkable
class Serializable(Protocol):
    """Protocol for objects that can be serialized and deserialized.

    This protocol enables consistent serialization across the library,
    supporting both JSON and binary formats.
    """

    @abstractmethod
    def to_dict(self) -> dict[str, Any]:
        """Convert object to dictionary representation.

        Returns:
            Dictionary representation of the object
        """

    @abstractmethod
    def to_json(self) -> str:
        """Convert object to JSON string.

        Returns:
            JSON string representation of the object
        """

    @classmethod
    @abstractmethod
    def from_dict(cls, data: dict[str, Any]) -> Serializable:
        """Create object from dictionary representation.

        Args:
            data: Dictionary representation

        Returns:
            New object instance
        """

    @classmethod
    @abstractmethod
    def from_json(cls, json_str: str) -> Serializable:
        """Create object from JSON string.

        Args:
            json_str: JSON string representation

        Returns:
            New object instance
        """


@runtime_checkable
class Cacheable(Protocol):
    """Protocol for objects that can be cached and retrieved.

    This protocol enables efficient caching strategies while
    maintaining cache consistency and invalidation.
    """

    @abstractmethod
    def get_cache_key(self) -> str:
        """Generate unique cache key for this object.

        Returns:
            String key that uniquely identifies this object
        """

    @abstractmethod
    def get_cache_ttl(self) -> int:
        """Get time-to-live for cache entry in seconds.

        Returns:
            Number of seconds this object should remain cached
        """

    @abstractmethod
    def should_cache(self) -> bool:
        """Determine if this object should be cached.

        Returns:
            True if object should be cached, False otherwise
        """


@runtime_checkable
class Observable(Protocol):
    """Protocol for objects that can emit events and be observed.

    This protocol enables event-driven architecture and monitoring
    throughout the library.
    """

    @abstractmethod
    async def emit_event(self, event_type: str, data: dict[str, Any]) -> None:
        """Emit an event with associated data.

        Args:
            event_type: Type/name of the event
            data: Event data payload
        """

    @abstractmethod
    def add_observer(self, observer: Observer) -> None:
        """Add an observer to receive events.

        Args:
            observer: Observer object to add
        """

    @abstractmethod
    def remove_observer(self, observer: Observer) -> None:
        """Remove an observer.

        Args:
            observer: Observer object to remove
        """


@runtime_checkable
class Observer(Protocol):
    """Protocol for objects that can observe events.

    This protocol defines the interface for event observers,
    enabling reactive programming patterns.
    """

    @abstractmethod
    async def on_event(self, event_type: str, data: dict[str, Any]) -> None:
        """Handle an observed event.

        Args:
            event_type: Type/name of the event
            data: Event data payload
        """


@runtime_checkable
class Identifiable(Protocol):
    """Protocol for objects that have a unique identifier.

    This protocol ensures consistent identity handling across
    entities and value objects.
    """

    @abstractmethod
    def get_id(self) -> uuid.UUID:
        """Get the unique identifier for this object.

        Returns:
            UUID that uniquely identifies this object
        """

    @abstractmethod
    def get_id_str(self) -> str:
        """Get the unique identifier as a string.

        Returns:
            String representation of the unique identifier
        """


@runtime_checkable
class Trackable(Protocol):
    """Protocol for objects that track creation and modification times.

    This protocol enables audit trails and temporal queries.
    """

    @abstractmethod
    def get_created_at(self) -> str:
        """Get creation timestamp in ISO format.

        Returns:
            ISO formatted creation timestamp
        """

    @abstractmethod
    def get_updated_at(self) -> str:
        """Get last update timestamp in ISO format.

        Returns:
            ISO formatted update timestamp
        """

    @abstractmethod
    def get_version(self) -> int:
        """Get version number for optimistic locking.

        Returns:
            Current version number
        """


@runtime_checkable
class Comparable(Protocol):
    """Protocol for objects that can be compared and ordered.

    This protocol enables sorting and comparison operations
    while maintaining type safety.
    """

    @abstractmethod
    def __lt__(self, other: Comparable) -> bool:
        """Less than comparison.

        Args:
            other: Object to compare against

        Returns:
            True if this object is less than other
        """

    @abstractmethod
    def __le__(self, other: Comparable) -> bool:
        """Less than or equal comparison.

        Args:
            other: Object to compare against

        Returns:
            True if this object is less than or equal to other
        """

    @abstractmethod
    def __gt__(self, other: Comparable) -> bool:
        """Greater than comparison.

        Args:
            other: Object to compare against

        Returns:
            True if this object is greater than other
        """

    @abstractmethod
    def __ge__(self, other: Comparable) -> bool:
        """Greater than or equal comparison.

        Args:
            other: Object to compare against

        Returns:
            True if this object is greater than or equal to other
        """

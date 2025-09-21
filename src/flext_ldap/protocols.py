"""FLEXT-LDAP Unified Protocols Module.

This module provides unified protocol interfaces for FLEXT-LDAP, following the FLEXT standards
of having a single unified class per module that inherits from FlextProtocols.

All LDAP-specific protocol interfaces are consolidated here as nested classes within
FlextLdapProtocols to maintain the clean architecture and single-class-per-module principle.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from abc import abstractmethod
from typing import TYPE_CHECKING, Protocol, runtime_checkable

from ldap3 import SUBTREE

from flext_core import FlextProtocols, FlextResult, FlextTypes

if TYPE_CHECKING:
    from flext_ldap.models import FlextLdapModels

__all__ = ["FlextLdapProtocols"]


class FlextLdapProtocols(FlextProtocols):
    """LDAP Protocols class."""

    @runtime_checkable
    class Connection(Protocol):
        """Protocol for LDAP connection management."""

        @abstractmethod
        def connect(self) -> FlextResult[None]:
            """Establish LDAP connection."""
            ...

        @abstractmethod
        def disconnect(self) -> FlextResult[None]:
            """Close LDAP connection."""
            ...

        @abstractmethod
        def is_connected(self) -> bool:
            """Check if connection is active."""
            ...

        @abstractmethod
        def test_connection(self) -> FlextResult[bool]:
            """Test connection health."""
            ...

    @runtime_checkable
    class Authentication(Protocol):
        """Protocol for LDAP authentication operations."""

        @abstractmethod
        def bind(self, dn: str, password: str) -> FlextResult[None]:
            """Bind to LDAP with credentials."""
            ...

        @abstractmethod
        def unbind(self) -> FlextResult[None]:
            """Unbind from LDAP."""
            ...

        @abstractmethod
        def authenticate(self, username: str, password: str) -> FlextResult[bool]:
            """Authenticate user credentials."""
            ...

    @runtime_checkable
    class Search(Protocol):
        """Protocol for LDAP search operations."""

        @abstractmethod
        def search(
            self,
            request: FlextLdapModels.SearchRequest,
        ) -> FlextResult[FlextLdapModels.SearchResponse]:
            """Perform LDAP search operation."""
            ...

        @abstractmethod
        def search_users(
            self,
            base_dn: str,
            filter_str: str | None = None,
        ) -> FlextResult[list[FlextLdapModels.LdapUser]]:
            """Search for users."""
            ...

        @abstractmethod
        def search_groups(
            self,
            base_dn: str,
            filter_str: str | None = None,
        ) -> FlextResult[list[FlextLdapModels.Group]]:
            """Search for groups."""
            ...

        @abstractmethod
        def find_by_dn(self, dn: str) -> FlextResult[FlextLdapModels.Entry | None]:
            """Find entry by distinguished name."""
            ...

    @runtime_checkable
    class Crud(Protocol):
        """Protocol for LDAP CRUD operations."""

        @abstractmethod
        def create(self, entry: FlextLdapModels.Entry) -> FlextResult[str]:
            """Create LDAP entry."""
            ...

        @abstractmethod
        def read(self, dn: str) -> FlextResult[FlextLdapModels.Entry | None]:
            """Read LDAP entry by DN."""
            ...

        @abstractmethod
        def update(
            self,
            dn: str,
            updates: FlextTypes.Core.Dict,
        ) -> FlextResult[None]:
            """Update LDAP entry."""
            ...

        @abstractmethod
        def delete(self, dn: str) -> FlextResult[None]:
            """Delete LDAP entry."""
            ...

        @abstractmethod
        def exists(self, dn: str) -> FlextResult[bool]:
            """Check if entry exists."""
            ...

    @runtime_checkable
    class UserManagement(Protocol):
        """Protocol for LDAP user management operations."""

        @abstractmethod
        def create_user(
            self,
            request: FlextLdapModels.CreateUserRequest,
        ) -> FlextResult[FlextLdapModels.LdapUser]:
            """Create new user."""
            ...

        @abstractmethod
        def get_user(self, dn: str) -> FlextResult[FlextLdapModels.LdapUser | None]:
            """Get user by DN."""
            ...

        @abstractmethod
        def update_user(
            self,
            dn: str,
            updates: FlextTypes.Core.Dict,
        ) -> FlextResult[FlextLdapModels.LdapUser]:
            """Update user."""
            ...

        @abstractmethod
        def delete_user(self, dn: str) -> FlextResult[None]:
            """Delete user."""
            ...

        @abstractmethod
        def user_exists(self, dn: str) -> FlextResult[bool]:
            """Check if user exists."""
            ...

        @abstractmethod
        def change_password(self, dn: str, new_password: str) -> FlextResult[None]:
            """Change user password."""
            ...

    @runtime_checkable
    class GroupManagement(Protocol):
        """Protocol for LDAP group management operations."""

        @abstractmethod
        def create_group(
            self,
            request: FlextLdapModels.CreateGroupRequest,
        ) -> FlextResult[FlextLdapModels.Group]:
            """Create new group."""
            ...

        @abstractmethod
        def get_group(self, dn: str) -> FlextResult[FlextLdapModels.Group | None]:
            """Get group by DN."""
            ...

        @abstractmethod
        def update_group(
            self,
            request: FlextLdapModels.UpdateGroupRequest,
        ) -> FlextResult[FlextLdapModels.Group]:
            """Update group."""
            ...

        @abstractmethod
        def delete_group(self, dn: str) -> FlextResult[None]:
            """Delete group."""
            ...

        @abstractmethod
        def group_exists(self, dn: str) -> FlextResult[bool]:
            """Check if group exists."""
            ...

        @abstractmethod
        def add_member(self, group_dn: str, member_dn: str) -> FlextResult[None]:
            """Add member to group."""
            ...

        @abstractmethod
        def remove_member(self, group_dn: str, member_dn: str) -> FlextResult[None]:
            """Remove member from group."""
            ...

        @abstractmethod
        def get_members(self, group_dn: str) -> FlextResult[list[str]]:
            """Get group members."""
            ...

    @runtime_checkable
    class Repository(Protocol):
        """Protocol for LDAP repository operations."""

        @abstractmethod
        def save(self, entity: object) -> FlextResult[object]:
            """Save entity to repository."""
            ...

        @abstractmethod
        def find_by_id(self, entity_id: str) -> FlextResult[object | None]:
            """Find entity by ID."""
            ...

        @abstractmethod
        def find_all(self) -> FlextResult[list[object]]:
            """Find all entities."""
            ...

        @abstractmethod
        def delete_by_id(self, entity_id: str) -> FlextResult[None]:
            """Delete entity by ID."""
            ...

    @runtime_checkable
    class Validation(Protocol):
        """Protocol for LDAP validation operations."""

        @abstractmethod
        def validate_dn(self, dn: str) -> FlextResult[None]:
            """Validate distinguished name format."""
            ...

        @abstractmethod
        def validate_filter(self, filter_str: str) -> FlextResult[None]:
            """Validate LDAP filter format."""
            ...

        @abstractmethod
        def validate_attributes(
            self,
            attributes: FlextTypes.Core.Dict,
        ) -> FlextResult[None]:
            """Validate LDAP attributes."""
            ...

        @abstractmethod
        def validate_object_classes(
            self,
            object_classes: list[str],
        ) -> FlextResult[None]:
            """Validate object classes."""
            ...

    @runtime_checkable
    class Configuration(Protocol):
        """Protocol for LDAP configuration management."""

        @abstractmethod
        def get_connection_config(
            self,
        ) -> FlextResult[object]:
            """Get connection configuration."""
            ...

        @abstractmethod
        def update_connection_config(
            self,
            config: object,
        ) -> FlextResult[None]:
            """Update connection configuration."""
            ...

        @abstractmethod
        def validate_configuration(self) -> FlextResult[None]:
            """Validate current configuration."""
            ...

    @runtime_checkable
    class Cache(Protocol):
        """Protocol for LDAP caching operations."""

        @abstractmethod
        def get(self, key: str) -> FlextResult[object | None]:
            """Get value from cache."""
            ...

        @abstractmethod
        def set(
            self,
            key: str,
            value: object,
            ttl: int | None = None,
        ) -> FlextResult[None]:
            """Set value in cache."""
            ...

        @abstractmethod
        def delete(self, key: str) -> FlextResult[None]:
            """Delete value from cache."""
            ...

        @abstractmethod
        def clear(self) -> FlextResult[None]:
            """Clear all cache."""
            ...

        @abstractmethod
        def exists(self, key: str) -> FlextResult[bool]:
            """Check if key exists in cache."""
            ...

    @runtime_checkable
    class Logging(Protocol):
        """Protocol for LDAP logging operations."""

        @abstractmethod
        def log_operation(
            self,
            operation: str,
            details: FlextTypes.Core.Dict,
        ) -> FlextResult[None]:
            """Log LDAP operation."""
            ...

        @abstractmethod
        def log_error(
            self,
            error: Exception,
            context: FlextTypes.Core.Dict,
        ) -> FlextResult[None]:
            """Log LDAP error."""
            ...

        @abstractmethod
        def log_performance(
            self,
            operation: str,
            duration: float,
        ) -> FlextResult[None]:
            """Log operation performance."""
            ...

    @runtime_checkable
    class Client(Protocol):
        """Protocol for LDAP client operations."""

        @abstractmethod
        def initialize(self) -> FlextResult[None]:
            """Initialize LDAP client."""
            ...

        @abstractmethod
        def cleanup(self) -> FlextResult[None]:
            """Cleanup LDAP client resources."""
            ...

        @abstractmethod
        def execute_operation(
            self,
            operation: str,
            parameters: FlextTypes.Core.Dict,
        ) -> FlextResult[object]:
            """Execute LDAP operation."""
            ...

    @runtime_checkable
    class Adapter(Protocol):
        """Protocol for LDAP adapter operations."""

        @abstractmethod
        def adapt_request(self, request: object) -> FlextResult[object]:
            """Adapt incoming request."""
            ...

        @abstractmethod
        def adapt_response(self, response: object) -> FlextResult[object]:
            """Adapt outgoing response."""
            ...

        @abstractmethod
        def transform_data(self, data: object) -> FlextResult[object]:
            """Transform data format."""
            ...

    @runtime_checkable
    class Service(Protocol):
        """Protocol for LDAP service operations."""

        @abstractmethod
        def handle(self, request: object) -> FlextResult[object]:
            """Handle service request."""
            ...

        @abstractmethod
        def process(self, data: object) -> FlextResult[object]:
            """Process service data."""
            ...

        @abstractmethod
        def build(self, specification: object) -> FlextResult[object]:
            """Build service component."""
            ...

    # Composite Protocols for common use cases
    @runtime_checkable
    class LdapClient(
        Connection,
        Authentication,
        Search,
        Crud,
        Protocol,
    ):
        """Composite protocol for full LDAP client functionality."""

    @runtime_checkable
    class LdapService(
        UserManagement,
        GroupManagement,
        Validation,
        Service,
        Protocol,
    ):
        """Composite protocol for LDAP service functionality."""

    @runtime_checkable
    class LdapRepository(
        Repository,
        Search,
        Crud,
        Protocol,
    ):
        """Composite protocol for LDAP repository functionality."""

    class LdapEntry(Protocol):
        """Protocol for LDAP entry objects (ldap3.Entry or compatible)."""

        entry_dn: str
        entry_attributes: dict[str, object] | list[str]

    class LdapConnection(Protocol):
        """Protocol for LDAP connection objects (ldap3.Connection or compatible).

        This Protocol defines the interface for LDAP connections, providing type safety
        for external library calls while maintaining FLEXT zero tolerance policies.
        """

        # Attributes that are accessed on the connection
        bound: bool
        entries: list[FlextLdapProtocols.LdapEntry]
        result: dict[str, object]

        def unbind(self) -> bool:
            """Unbind from LDAP server."""
            ...

        def rebind(self, user: str | None, password: str | None) -> bool:
            """Rebind with different credentials."""
            ...

        def add(
            self,
            dn: str,
            object_classes: list[str] | None = None,
            attributes: dict[str, object] | None = None,
        ) -> bool:
            """Add LDAP entry."""
            ...

        def modify(self, dn: str, changes: dict[str, object]) -> bool:
            """Modify LDAP entry."""
            ...

        def delete(self, dn: str) -> bool:
            """Delete LDAP entry."""
            ...

        def search(
            self,
            search_base: str,
            search_filter: str,
            *,
            search_scope: str = SUBTREE,
            dereference_aliases: str = "NEVER",
            attributes: list[str]
            | str
            | None = None,  # Allow ALL_ATTRIBUTES which is a string
            size_limit: int = 0,
            time_limit: int = 0,
            types_only: bool = False,
            get_operational_attributes: bool = False,
            controls: list[object] | None = None,
            paged_size: int | None = None,
            paged_criticality: bool = False,
            paged_cookie: bytes | None = None,
        ) -> bool:
            """Search LDAP entries."""
            ...

    # Factory methods for protocol validation
    @classmethod
    def validate_connection_implementation(cls, instance: object) -> FlextResult[None]:
        """Validate that instance implements Connection protocol."""
        if not isinstance(instance, cls.Connection):
            return FlextResult[None].fail(
                f"Instance does not implement Connection protocol: {type(instance)}",
            )
        return FlextResult[None].ok(None)

    @classmethod
    def validate_service_implementation(cls, instance: object) -> FlextResult[None]:
        """Validate that instance implements Service protocol."""
        if not isinstance(instance, cls.Service):
            return FlextResult[None].fail(
                f"Instance does not implement Service protocol: {type(instance)}",
            )
        return FlextResult[None].ok(None)

    @classmethod
    def validate_repository_implementation(cls, instance: object) -> FlextResult[None]:
        """Validate that instance implements Repository protocol."""
        if not isinstance(instance, cls.Repository):
            return FlextResult[None].fail(
                f"Instance does not implement Repository protocol: {type(instance)}",
            )
        return FlextResult[None].ok(None)

    @classmethod
    def get_protocol_registry(cls) -> dict[str, type]:
        """Get registry of all available protocols."""
        return {
            "connection": cls.Connection,
            "authentication": cls.Authentication,
            "search": cls.Search,
            "crud": cls.Crud,
            "user_management": cls.UserManagement,
            "group_management": cls.GroupManagement,
            "repository": cls.Repository,
            "validation": cls.Validation,
            "configuration": cls.Configuration,
            "cache": cls.Cache,
            "logging": cls.Logging,
            "client": cls.Client,
            "adapter": cls.Adapter,
            "service": cls.Service,
            "ldap_client": cls.LdapClient,
            "ldap_service": cls.LdapService,
            "ldap_repository": cls.LdapRepository,
        }

    # =========================================================================
    # PROTOCOL TYPES - LDAP Protocol Extensions (moved from typings.py)
    # =========================================================================

    class LdapProtocol(Protocol):
        """LDAP protocol that defines the interface for ldap3.Connection or compatible objects.

        This Protocol provides type safety for external library calls while maintaining
        FLEXT zero tolerance policies. It defines the attributes and methods that must
        be available on LDAP connection objects.
        """

        # Required attributes that are accessed on the connection
        bound: bool
        entries: list[FlextLdapProtocols.LdapEntry]
        result: dict[str, object]

        def unbind(self) -> bool:
            """Unbind from LDAP server."""
            ...

        def rebind(self, user: str | None, password: str | None) -> bool:
            """Rebind with different credentials."""
            ...

        def add(
            self,
            dn: str,
            object_classes: list[str] | None = None,
            attributes: dict[str, object] | None = None,
        ) -> bool:
            """Add LDAP entry."""
            ...

        def modify(self, dn: str, changes: dict[str, object]) -> bool:
            """Modify LDAP entry."""
            ...

        def delete(self, dn: str) -> bool:
            """Delete LDAP entry."""
            ...

        def search(
            self,
            search_base: str,
            search_filter: str,
            *,
            search_scope: str = SUBTREE,
            dereference_aliases: str = "NEVER",
            attributes: list[str] | str | None = None,
            size_limit: int = 0,
            time_limit: int = 0,
            types_only: bool = False,
            get_operational_attributes: bool = False,
            controls: list[object] | None = None,
            paged_size: int | None = None,
            paged_criticality: bool = False,
            paged_cookie: bytes | None = None,
        ) -> bool:
            """Search LDAP entries."""
            ...  # Proper validator signature

    # =========================================================================
    # ASYNC PROTOCOLS - Async and callable patterns (moved from typings.py)
    # =========================================================================

    @runtime_checkable
    class AsyncCallable(Protocol):
        """Async callable protocol for LDAP operations."""

        def __call__(self, *args: object, **kwargs: object) -> None:  # pragma: no cover
            """Execute async callable with arbitrary arguments."""
            ...

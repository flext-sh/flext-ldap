"""LDAP Domain Protocols - CONSOLIDATED SINGLE SOURCE OF TRUTH.

🎯 ELIMINATES MASSIVE DUPLICATIONS - Centralized LDAP abstractions
Following advanced Python 3.13 + flext-core patterns with zero duplication.

CONSOLIDATES AND REPLACES (single source of truth):
- domain/ports.py: FlextLdapConnectionService, FlextLdapSearchService, etc. (5+ classes)
- adapters/directory_adapter.py: Directory protocols (4+ protocols)
- protocols_consolidated.py: Repository and service protocols (6+ protocols)
- abstracts.py: Abstract base classes
- domain/repositories.py: Repository abstractions
- utils.py: Utility protocols

This module provides COMPREHENSIVE protocol consolidation using:
- Advanced Python 3.13 Protocol patterns with runtime_checkable
- flext-core foundation patterns without duplication
- SOLID principles and Clean Architecture contracts
- Type-safe DI interfaces (not service implementations)
- Railway-oriented programming with FlextResult[T]

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any, Protocol, runtime_checkable

# ✅ CORRECT: Import by root from flext-core (not submodules)
from flext_core import (
    FlextResult,
    get_logger,
)

# ✅ CORRECT: Import centralized types from flext-core foundation

if TYPE_CHECKING:
    from contextlib import AbstractAsyncContextManager
    from typing import Any

    JsonDict = dict[str, Any]

logger = get_logger(__name__)

# =============================================================================
# CORE LDAP PROTOCOLS - Foundation DI Interfaces
# =============================================================================


@runtime_checkable
class FlextLdapConnectionProtocol(Protocol):
    """Core LDAP connection protocol extending flext-core patterns.

    🎯 CONSOLIDATES AND REPLACES:
    - FlextLdapConnectionService (domain/ports.py:21)
    - FlextLdapDirectoryConnectionProtocol (adapters/directory_adapter.py:50)
    - LdapConnectionProtocol (protocols.py:35)
    - All connection abstractions scattered across modules

    DI Interface Pattern: Provides connection contracts for dependency injection.
    """

    async def bind(
        self,
        dn: str,
        password: str,
        auth_method: str = "simple",
    ) -> FlextResult[None]:
        """Bind (authenticate) with LDAP server.

        Args:
            dn: Distinguished name for authentication
            password: Password for authentication
            auth_method: Authentication method (simple, SASL, etc.)

        Returns:
            FlextResult indicating authentication success or error

        """
        ...

    async def test_health(self) -> FlextResult[JsonDict]:
        """Test connection health and gather diagnostics.

        Returns:
            FlextResult containing health status and diagnostics

        """
        ...

    async def get_statistics(self) -> FlextResult[JsonDict]:
        """Get connection statistics and metrics.

        Returns:
            FlextResult containing connection statistics

        """
        ...

    def connect(
        self,
        host: str,
        port: int = 389,
        use_ssl: bool = False,
        bind_dn: str | None = None,
        bind_password: str | None = None,
        **kwargs: object,
    ) -> FlextResult[object]:
        """Establish LDAP connection with comprehensive error handling.

        Args:
            host: LDAP server hostname
            port: LDAP server port (389 for LDAP, 636 for LDAPS)
            use_ssl: Whether to use SSL/TLS connection
            bind_dn: Distinguished name for authentication
            bind_password: Password for authentication
            **kwargs: Additional connection parameters

        Returns:
            FlextResult containing connection object or error

        """
        ...

    def disconnect(self, connection: object) -> FlextResult[None]:
        """Close LDAP connection safely.

        Args:
            connection: Active LDAP connection object

        Returns:
            FlextResult indicating success or failure

        """
        ...

    def is_connected(self, connection: object) -> bool:
        """Check if connection is active.

        Args:
            connection: LDAP connection object to check

        Returns:
            True if connection is active, False otherwise

        """
        ...

    def get_connection_info(self, connection: object) -> FlextResult[JsonDict]:
        """Get connection information and status.

        Args:
            connection: Active LDAP connection

        Returns:
            FlextResult containing connection information

        """
        ...


@runtime_checkable
class FlextLdapSearchProtocol(Protocol):
    """Advanced LDAP search protocol with comprehensive query capabilities.

    🎯 CONSOLIDATES AND REPLACES:
    - FlextLdapSearchService (domain/ports.py:71)
    - LdapSearchProtocol (protocols.py:89)
    - Search functionality scattered across multiple modules

    DI Interface Pattern: Provides search contracts for dependency injection.
    """

    async def search_entries(
        self,
        connection: object,
        base_dn: str,
        search_filter: str,
        attributes: list[str] | None = None,
        scope: str = "SUBTREE",
        size_limit: int = 1000,
        time_limit: int = 30,
        **kwargs: object,
    ) -> FlextResult[list[JsonDict]]:
        """Search LDAP entries with advanced filtering and pagination.

        Args:
            connection: Active LDAP connection
            base_dn: Base distinguished name for search
            search_filter: LDAP search filter (RFC 4515 compliant)
            attributes: Attributes to retrieve (None for all)
            scope: Search scope (BASE, ONELEVEL, SUBTREE)
            size_limit: Maximum number of results
            time_limit: Search timeout in seconds
            **kwargs: Additional search parameters

        Returns:
            FlextResult containing list of LDAP entries

        """
        ...

    async def search_single_entry(
        self,
        connection: object,
        dn: str,
        attributes: list[str] | None = None,
    ) -> FlextResult[JsonDict | None]:
        """Search for a single entry by DN.

        Args:
            connection: Active LDAP connection
            dn: Distinguished name of entry to retrieve
            attributes: Attributes to retrieve (None for all)

        Returns:
            FlextResult containing entry or None if not found

        """
        ...

    async def count_entries(
        self,
        connection: object,
        base_dn: str,
        search_filter: str,
        scope: str = "SUBTREE",
    ) -> FlextResult[int]:
        """Count entries matching search criteria.

        Args:
            connection: Active LDAP connection
            base_dn: Base distinguished name for search
            search_filter: LDAP search filter
            scope: Search scope

        Returns:
            FlextResult containing count of matching entries

        """
        ...


@runtime_checkable
class FlextLdapWriteProtocol(Protocol):
    """Advanced LDAP write operations protocol.

    🎯 CONSOLIDATES AND REPLACES:
    - LdapWriteProtocol (protocols.py:154)
    - Write operations scattered across adapters and services
    - CRUD functionality duplications

    DI Interface Pattern: Provides write contracts for dependency injection.
    """

    async def add_entry(
        self,
        connection: object,
        dn: str,
        attributes: JsonDict,
    ) -> FlextResult[None]:
        """Add new LDAP entry with validation.

        Args:
            connection: Active LDAP connection
            dn: Distinguished name for new entry
            attributes: Entry attributes dictionary

        Returns:
            FlextResult indicating success or failure

        """
        ...

    async def modify_entry(
        self,
        connection: object,
        dn: str,
        changes: JsonDict,
    ) -> FlextResult[None]:
        """Modify existing LDAP entry.

        Args:
            connection: Active LDAP connection
            dn: Distinguished name of entry to modify
            changes: Modifications to apply

        Returns:
            FlextResult indicating success or failure

        """
        ...

    async def delete_entry(
        self,
        connection: object,
        dn: str,
    ) -> FlextResult[None]:
        """Delete LDAP entry.

        Args:
            connection: Active LDAP connection
            dn: Distinguished name of entry to delete

        Returns:
            FlextResult indicating success or failure

        """
        ...

    async def move_entry(
        self,
        connection: object,
        old_dn: str,
        new_dn: str,
    ) -> FlextResult[None]:
        """Move/rename LDAP entry.

        Args:
            connection: Active LDAP connection
            old_dn: Current distinguished name
            new_dn: New distinguished name

        Returns:
            FlextResult indicating success or failure

        """
        ...


@runtime_checkable
class FlextLdapPoolProtocol(Protocol):
    """LDAP connection pool protocol for enterprise scalability.

    🎯 CONSOLIDATES AND REPLACES:
    - LdapPoolProtocol (protocols.py:65)
    - Connection pool abstractions scattered across infrastructure

    DI Interface Pattern: Provides pool management contracts.
    """

    async def create_connection(
        self,
        connection_id: str,
        host: str,
        port: int,
        use_ssl: bool,
        timeout: int,
        pool_size: int,
    ) -> FlextResult[Any]:
        """Create connection via pool.

        Args:
            connection_id: Unique connection identifier
            host: LDAP server hostname
            port: LDAP server port
            use_ssl: Whether to use SSL/TLS
            timeout: Connection timeout
            pool_size: Pool size configuration

        Returns:
            FlextResult containing connection or error

        """
        ...

    async def close_connection(
        self,
        connection_id: str,
        force: bool = False,
    ) -> FlextResult[None]:
        """Close connection in pool.

        Args:
            connection_id: Connection identifier
            force: Force close even if operations pending

        Returns:
            FlextResult indicating success or error

        """
        ...

    async def get_statistics(self) -> FlextResult[JsonDict]:
        """Get pool statistics.

        Returns:
            FlextResult containing statistics

        """
        ...

    async def reset_pool(self) -> FlextResult[None]:
        """Reset connection pool.

        Returns:
            FlextResult indicating success or error

        """
        ...

    def get_connection(self) -> AbstractAsyncContextManager[object]:
        """Get connection from pool with context manager.

        Returns:
            Async context manager for LDAP connection

        """
        ...

    def get_pool_stats(self) -> FlextResult[JsonDict]:
        """Get connection pool statistics.

        Returns:
            FlextResult containing pool statistics

        """
        ...

    def health_check(self) -> FlextResult[bool]:
        """Check pool health status.

        Returns:
            FlextResult containing health status

        """
        ...


# =============================================================================
# DOMAIN SERVICE PROTOCOLS - Business Logic DI Interfaces
# =============================================================================


@runtime_checkable
class FlextLdapUserServiceProtocol(Protocol):
    """User management service protocol with comprehensive CRUD operations.

    🎯 CONSOLIDATES AND REPLACES:
    - FlextLdapUserService (domain/ports.py:97)
    - LdapUserServiceProtocol (protocols.py:286)
    - User service abstractions across domain and application layers

    DI Interface Pattern: Business logic contracts for user operations.
    """

    def create_user(
        self,
        connection: object,
        user_data: JsonDict,
    ) -> FlextResult[JsonDict]:
        """Create new LDAP user with validation.

        Args:
            connection: Active LDAP connection
            user_data: User creation data

        Returns:
            FlextResult containing created user data

        """
        ...

    def get_user(
        self,
        connection: object,
        user_identifier: str,
    ) -> FlextResult[JsonDict | None]:
        """Retrieve user by identifier (DN, uid, email).

        Args:
            connection: Active LDAP connection
            user_identifier: User identifier (DN/uid/email)

        Returns:
            FlextResult containing user data or None

        """
        ...

    def update_user(
        self,
        connection: object,
        user_dn: str,
        updates: JsonDict,
    ) -> FlextResult[JsonDict]:
        """Update user attributes.

        Args:
            connection: Active LDAP connection
            user_dn: User distinguished name
            updates: Attributes to update

        Returns:
            FlextResult containing updated user data

        """
        ...

    def delete_user(
        self,
        connection: object,
        user_dn: str,
    ) -> FlextResult[None]:
        """Delete user account.

        Args:
            connection: Active LDAP connection
            user_dn: User distinguished name

        Returns:
            FlextResult indicating success or failure

        """
        ...

    def list_users(
        self,
        connection: object,
        base_dn: str,
        filter_criteria: JsonDict | None = None,
        page_size: int = 100,
        page_token: str | None = None,
    ) -> FlextResult[JsonDict]:
        """List users with pagination and filtering.

        Args:
            connection: Active LDAP connection
            base_dn: Base DN for user search
            filter_criteria: Optional filter criteria
            page_size: Number of results per page
            page_token: Pagination token

        Returns:
            FlextResult containing paginated user list

        """
        ...


@runtime_checkable
class FlextLdapGroupServiceProtocol(Protocol):
    """Group management service protocol with membership operations.

    🎯 CONSOLIDATES AND REPLACES:
    - LdapGroupServiceProtocol (protocols.py:313)
    - Group service abstractions scattered across modules

    DI Interface Pattern: Business logic contracts for group operations.
    """

    def create_group(
        self,
        connection: object,
        group_data: JsonDict,
    ) -> FlextResult[JsonDict]:
        """Create new LDAP group.

        Args:
            connection: Active LDAP connection
            group_data: Group creation data

        Returns:
            FlextResult containing created group data

        """
        ...

    def add_member(
        self,
        connection: object,
        group_dn: str,
        member_dn: str,
    ) -> FlextResult[None]:
        """Add member to group.

        Args:
            connection: Active LDAP connection
            group_dn: Group distinguished name
            member_dn: Member distinguished name

        Returns:
            FlextResult indicating success or failure

        """
        ...

    def remove_member(
        self,
        connection: object,
        group_dn: str,
        member_dn: str,
    ) -> FlextResult[None]:
        """Remove member from group.

        Args:
            connection: Active LDAP connection
            group_dn: Group distinguished name
            member_dn: Member distinguished name

        Returns:
            FlextResult indicating success or failure

        """
        ...

    def get_group_members(
        self,
        connection: object,
        group_dn: str,
    ) -> FlextResult[list[str]]:
        """Get all group members.

        Args:
            connection: Active LDAP connection
            group_dn: Group distinguished name

        Returns:
            FlextResult containing list of member DNs

        """
        ...


@runtime_checkable
class FlextLdapSchemaServiceProtocol(Protocol):
    """Schema management service protocol for LDAP schema operations.

    🎯 CONSOLIDATES AND REPLACES:
    - FlextLdapSchemaService (domain/ports.py:149)
    - Schema functionality scattered across modules

    DI Interface Pattern: Schema management contracts.
    """

    def get_schema(
        self,
        connection: object,
    ) -> FlextResult[JsonDict]:
        """Retrieve LDAP schema information.

        Args:
            connection: Active LDAP connection

        Returns:
            FlextResult containing schema data

        """
        ...

    def validate_entry_schema(
        self,
        connection: object,
        dn: str,
        attributes: JsonDict,
    ) -> FlextResult[bool]:
        """Validate entry against schema.

        Args:
            connection: Active LDAP connection
            dn: Entry distinguished name
            attributes: Entry attributes

        Returns:
            FlextResult containing validation result

        """
        ...


@runtime_checkable
class FlextLdapMigrationServiceProtocol(Protocol):
    """Migration service protocol for LDAP data migrations.

    🎯 CONSOLIDATES AND REPLACES:
    - FlextLdapMigrationService (domain/ports.py:171)
    - Migration abstractions scattered across modules

    DI Interface Pattern: Migration management contracts.
    """

    def migrate_entries(
        self,
        source_connection: object,
        target_connection: object,
        migration_config: JsonDict,
    ) -> FlextResult[JsonDict]:
        """Migrate entries between LDAP servers.

        Args:
            source_connection: Source LDAP connection
            target_connection: Target LDAP connection
            migration_config: Migration configuration

        Returns:
            FlextResult containing migration report

        """
        ...

    def validate_migration(
        self,
        source_connection: object,
        target_connection: object,
        migration_config: JsonDict,
    ) -> FlextResult[JsonDict]:
        """Validate migration configuration.

        Args:
            source_connection: Source LDAP connection
            target_connection: Target LDAP connection
            migration_config: Migration configuration

        Returns:
            FlextResult containing validation report

        """
        ...


# =============================================================================
# REPOSITORY PROTOCOLS - Data Access DI Interfaces
# =============================================================================


@runtime_checkable
class FlextLdapRepositoryProtocol(Protocol):
    """Generic LDAP repository protocol for data access patterns.

    🎯 CONSOLIDATES AND REPLACES:
    - FlextLdapRepositoryProtocol (protocols_consolidated.py:230)
    - Repository abstractions in domain/repositories.py
    - All repository duplications across modules

    DI Interface Pattern: Data access layer contracts.
    """

    async def search_entries(
        self,
        connection_id: str,
        config: JsonDict,  # FlextLdapSearchConfig
    ) -> FlextResult[list[JsonDict]]:
        """Search LDAP entries with configuration.

        Args:
            connection_id: Connection identifier
            config: Search configuration object

        Returns:
            FlextResult containing list of LDAP entries

        """
        ...

    async def create_entry(
        self,
        connection_id: str,
        entry_data: JsonDict,
    ) -> FlextResult[None]:
        """Create new LDAP entry.

        Args:
            connection_id: Connection identifier
            entry_data: Entry attributes dictionary

        Returns:
            FlextResult indicating success or error

        """
        ...

    async def modify_entry(
        self,
        connection_id: str,
        entry_dn: str,
        modifications: JsonDict,
        operation: str,
    ) -> FlextResult[None]:
        """Modify existing LDAP entry.

        Args:
            connection_id: Connection identifier
            entry_dn: Distinguished name of entry
            modifications: Attribute modifications
            operation: Modification operation (add, replace, delete)

        Returns:
            FlextResult indicating success or error

        """
        ...

    async def delete_entry(
        self,
        connection_id: str,
        entry_dn: str,
    ) -> FlextResult[None]:
        """Delete LDAP entry.

        Args:
            connection_id: Connection identifier
            entry_dn: Distinguished name of entry to delete

        Returns:
            FlextResult indicating success or error

        """
        ...

    def find_by_dn(
        self,
        connection: object,
        dn: str,
    ) -> FlextResult[JsonDict | None]:
        """Find entity by distinguished name.

        Args:
            connection: Active LDAP connection
            dn: Distinguished name to search for

        Returns:
            FlextResult containing entity or None

        """
        ...

    def find_by_filter(
        self,
        connection: object,
        base_dn: str,
        search_filter: str,
        limit: int = 100,
    ) -> FlextResult[list[JsonDict]]:
        """Find entities by LDAP filter.

        Args:
            connection: Active LDAP connection
            base_dn: Base DN for search
            search_filter: LDAP search filter
            limit: Maximum results to return

        Returns:
            FlextResult containing list of entities

        """
        ...

    def save(
        self,
        connection: object,
        entity: JsonDict,
    ) -> FlextResult[JsonDict]:
        """Save entity (create or update).

        Args:
            connection: Active LDAP connection
            entity: Entity data to save

        Returns:
            FlextResult containing saved entity

        """
        ...

    def delete(
        self,
        connection: object,
        dn: str,
    ) -> FlextResult[None]:
        """Delete entity by DN.

        Args:
            connection: Active LDAP connection
            dn: Distinguished name to delete

        Returns:
            FlextResult indicating success or failure

        """
        ...


# =============================================================================
# VALIDATION PROTOCOLS - Advanced Validation DI Interfaces
# =============================================================================


@runtime_checkable
class FlextLdapValidationProtocol(Protocol):
    """Advanced LDAP validation protocol with comprehensive checks.

    🎯 CONSOLIDATES AND REPLACES:
    - LdapValidationProtocol (protocols.py:236)
    - Validation logic scattered across utils and domain

    DI Interface Pattern: Validation service contracts.
    """

    def validate_dn(self, dn: str) -> FlextResult[bool]:
        """Validate distinguished name format.

        Args:
            dn: Distinguished name to validate

        Returns:
            FlextResult containing validation result

        """
        ...

    def validate_filter(self, search_filter: str) -> FlextResult[bool]:
        """Validate LDAP filter syntax.

        Args:
            search_filter: LDAP filter to validate

        Returns:
            FlextResult containing validation result

        """
        ...

    def validate_attributes(
        self,
        attributes: JsonDict,
        object_classes: list[str],
    ) -> FlextResult[bool]:
        """Validate attributes against object classes.

        Args:
            attributes: Attributes to validate
            object_classes: Required object classes

        Returns:
            FlextResult containing validation result

        """
        ...


# =============================================================================
# FACTORY PROTOCOLS - DI Factory Patterns
# =============================================================================


@runtime_checkable
class FlextLdapFactoryProtocol(Protocol):
    """Factory protocol for LDAP service creation with DI patterns.

    🎯 CONSOLIDATES AND REPLACES:
    - FlextLdapFactoryProtocol (protocols_consolidated.py:659)
    - Factory patterns scattered across modules

    DI Interface Pattern: Service factory contracts.
    """

    def create_connection_service(
        self,
        config: JsonDict,
    ) -> FlextResult[FlextLdapConnectionProtocol]:
        """Create connection service instance.

        Args:
            config: Service configuration

        Returns:
            FlextResult containing connection service

        """
        ...

    def create_user_service(
        self,
        config: JsonDict,
    ) -> FlextResult[FlextLdapUserServiceProtocol]:
        """Create user service instance.

        Args:
            config: Service configuration

        Returns:
            FlextResult containing user service

        """
        ...

    def create_group_service(
        self,
        config: JsonDict,
    ) -> FlextResult[FlextLdapGroupServiceProtocol]:
        """Create group service instance.

        Args:
            config: Service configuration

        Returns:
            FlextResult containing group service

        """
        ...


# =============================================================================
# CONSOLIDATED EXPORTS - SINGLE SOURCE OF TRUTH
# =============================================================================

__all__ = [
    # Alphabetically sorted protocol exports
    "FlextLdapConnectionProtocol",
    "FlextLdapFactoryProtocol",
    "FlextLdapGroupServiceProtocol",
    "FlextLdapMigrationServiceProtocol",
    "FlextLdapPoolProtocol",
    "FlextLdapRepositoryProtocol",
    "FlextLdapSchemaServiceProtocol",
    "FlextLdapSearchProtocol",
    "FlextLdapUserServiceProtocol",
    "FlextLdapValidationProtocol",
    "FlextLdapWriteProtocol",
]

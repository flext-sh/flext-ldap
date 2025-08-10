"""FLEXT-LDAP Abstract Patterns - CENTRALIZED Repository & DomainService.

🏗️ SOLID CONSOLIDATION: Eliminating massive duplications by extending flext-core
foundation patterns instead of recreating abstract classes everywhere.

ELIMINATED DUPLICATIONS:
- FlextLdapDirectoryRepository (domain/interfaces.py) → FlextLdapRepository
- FlextLdapGroupRepository (domain/interfaces.py) → FlextLdapRepository
- FlextLdapConnectionService (domain/ports.py) → FlextLdapConnectionService
- FlextLdapSearchService (domain/ports.py) → FlextLdapSearchService
- FlextLdapUserService (domain/ports.py) → FlextLdapUserService
- FlextLdapSchemaService (domain/ports.py) → FlextLdapSchemaService
- FlextLdapMigrationService (domain/ports.py) → FlextLdapMigrationService
- FlextLdapDirectoryServiceInterface (adapters/directory_adapter.py) → FlextLdapService
- LdapUserServiceProtocol (protocols.py) → FlextLdapUserService
- LdapGroupServiceProtocol (protocols.py) → FlextLdapGroupService

This module provides SINGLE SOURCE OF TRUTH for all LDAP abstractions,
extending flext-core patterns with LDAP-specific behaviors while maintaining
100% SOLID compliance and eliminating ALL duplications.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT

"""

from __future__ import annotations

from abc import abstractmethod
from typing import TYPE_CHECKING

from flext_core import FlextDomainService, FlextRepository, FlextResult

from flext_ldap.types import FlextLdapScopeEnum
from flext_ldap.value_objects import FlextLdapDistinguishedName, FlextLdapFilter

if TYPE_CHECKING:
    from flext_ldap.domain.models import FlextLdapCreateGroupRequest
    from flext_ldap.value_objects import (
        FlextLdapCreateUserRequest,
    )


# =============================================================================
# REPOSITORY ABSTRACTIONS - Single Source of Truth
# =============================================================================


class FlextLdapRepository(FlextRepository[dict[str, object]]):
    """CENTRALIZED LDAP Repository extending flext-core FlextRepository.

    🎯 CONSOLIDATION: Single source replacing all duplicated repository interfaces.

    ELIMINATES:
    - FlextLdapDirectoryRepository (domain/interfaces.py:78)
    - FlextLdapGroupRepository (domain/interfaces.py:205)
    - Repository interfaces scattered across multiple files

    Extends flext-core FlextRepository with LDAP-specific operations while
    maintaining full compatibility with Clean Architecture and DDD patterns.
    """

    # LDAP-SPECIFIC REPOSITORY OPERATIONS

    @abstractmethod
    async def search(
        self,
        connection_id: str,
        base_dn: FlextLdapDistinguishedName,
        search_filter: FlextLdapFilter,
        scope: FlextLdapScopeEnum,
        attributes: list[str] | None = None,
    ) -> FlextResult[list[dict[str, object]]]:
        """Search LDAP directory entries.

        Args:
            connection_id: Active LDAP connection identifier
            base_dn: Search base distinguished name
            search_filter: LDAP search filter (RFC 4515 compliant)
            scope: Search scope (base, onelevel, subtree)
            attributes: Attributes to return (None = all)

        Returns:
            FlextResult containing list of matching LDAP entries

        """

    @abstractmethod
    async def create_entry(
        self,
        connection_id: str,
        dn: FlextLdapDistinguishedName,
        attributes: dict[str, list[str]],
    ) -> FlextResult[None]:
        """Create new LDAP entry.

        Args:
            connection_id: Active LDAP connection identifier
            dn: Distinguished name for new entry
            attributes: LDAP attributes as name-value pairs

        Returns:
            FlextResult indicating success or failure

        """

    @abstractmethod
    async def modify_entry(
        self,
        connection_id: str,
        dn: FlextLdapDistinguishedName,
        changes: dict[str, object],
    ) -> FlextResult[None]:
        """Modify existing LDAP entry.

        Args:
            connection_id: Active LDAP connection identifier
            dn: Distinguished name of entry to modify
            changes: Modifications to apply (RFC 4511 compliant)

        Returns:
            FlextResult indicating success or failure

        """

    @abstractmethod
    async def delete_entry(
        self,
        connection_id: str,
        dn: FlextLdapDistinguishedName,
    ) -> FlextResult[None]:
        """Delete LDAP entry.

        Args:
            connection_id: Active LDAP connection identifier
            dn: Distinguished name of entry to delete

        Returns:
            FlextResult indicating success or failure

        """

    # USER-SPECIFIC OPERATIONS

    async def create_user(
        self,
        connection_id: str,
        user_request: FlextLdapCreateUserRequest,
    ) -> FlextResult[None]:
        """Create user entry using validated user request.

        Args:
            connection_id: Active LDAP connection identifier
            user_request: Validated user creation request

        Returns:
            FlextResult indicating success or failure

        """
        dn_result = user_request.get_dn_object()
        if dn_result.is_failure or dn_result.data is None:
            return FlextResult.fail(dn_result.error or "Failed to get DN object")

        return await self.create_entry(
            connection_id,
            dn_result.data,
            user_request.to_ldap_attributes(),
        )

    async def find_user_by_uid(
        self,
        connection_id: str,
        base_dn: FlextLdapDistinguishedName,
        uid: str,
    ) -> FlextResult[dict[str, object] | None]:
        """Find user by unique identifier.

        Args:
            connection_id: Active LDAP connection identifier
            base_dn: Search base for user search
            uid: User unique identifier

        Returns:
            FlextResult containing user entry or None if not found

        """
        uid_filter = FlextLdapFilter.create(f"(uid={uid})")
        if uid_filter.is_failure or uid_filter.data is None:
            return FlextResult.fail(f"Invalid UID filter: {uid_filter.error}")

        search_result = await self.search(
            connection_id,
            base_dn,
            uid_filter.data,
            FlextLdapScopeEnum.SUBTREE,
            None,
        )

        if search_result.is_failure:
            return FlextResult.fail(search_result.error or "User search failed")

        users = search_result.data or []
        return FlextResult.ok(users[0] if users else None)

    # GROUP-SPECIFIC OPERATIONS

    async def create_group(
        self,
        connection_id: str,
        group_request: FlextLdapCreateGroupRequest,
    ) -> FlextResult[None]:
        """Create group entry using validated group request.

        Args:
            connection_id: Active LDAP connection identifier
            group_request: Validated group creation request

        Returns:
            FlextResult indicating success or failure

        """
        # Convert string DN to FlextLdapDistinguishedName object
        dn_result = FlextLdapDistinguishedName.create(group_request.dn)
        if not dn_result.is_success:
            return FlextResult.fail(f"Invalid DN: {dn_result.error}")
        if dn_result.data is None:
            return FlextResult.fail("Failed to create DN object")

        return await self.create_entry(
            connection_id,
            dn_result.data,
            group_request.to_ldap_attributes(),
        )

    async def find_group_by_cn(
        self,
        connection_id: str,
        base_dn: FlextLdapDistinguishedName,
        cn: str,
    ) -> FlextResult[dict[str, object] | None]:
        """Find group by common name.

        Args:
            connection_id: Active LDAP connection identifier
            base_dn: Search base for group search
            cn: Group common name

        Returns:
            FlextResult containing group entry or None if not found

        """
        cn_filter = FlextLdapFilter.create(f"(cn={cn})")
        if cn_filter.is_failure or cn_filter.data is None:
            return FlextResult.fail(f"Invalid CN filter: {cn_filter.error}")

        search_result = await self.search(
            connection_id,
            base_dn,
            cn_filter.data,
            FlextLdapScopeEnum.SUBTREE,
            None,
        )

        if search_result.is_failure:
            return FlextResult.fail(search_result.error or "Group search failed")

        groups = search_result.data or []
        return FlextResult.ok(groups[0] if groups else None)

    async def get_group_members(
        self,
        connection_id: str,
        group_dn: FlextLdapDistinguishedName,
    ) -> FlextResult[list[str]]:
        """Get group member DNs.

        Args:
            connection_id: Active LDAP connection identifier
            group_dn: Group distinguished name

        Returns:
            FlextResult containing list of member DNs

        """
        # Search for the specific group entry
        group_filter = FlextLdapFilter.create("(objectClass=*)")
        if group_filter.is_failure or group_filter.data is None:
            return FlextResult.fail(f"Invalid group filter: {group_filter.error}")

        search_result = await self.search(
            connection_id,
            group_dn,
            group_filter.data,
            FlextLdapScopeEnum.BASE,
            ["member", "uniqueMember"],
        )

        if search_result.is_failure:
            return FlextResult.fail(search_result.error or "Group member search failed")

        groups = search_result.data or []
        if not groups:
            return FlextResult.ok([])

        group = groups[0]
        # Type-safe extraction of member lists
        member_list = group.get("member", [])
        unique_member_list = group.get("uniqueMember", [])

        # Ensure both are lists before concatenation
        members_safe = member_list if isinstance(member_list, list) else []
        unique_members_safe = (
            unique_member_list if isinstance(unique_member_list, list) else []
        )

        members = members_safe + unique_members_safe
        return FlextResult.ok([str(member) for member in members])


# =============================================================================
# DOMAIN SERVICE ABSTRACTIONS - Single Source of Truth
# =============================================================================


class FlextLdapService(FlextDomainService[object]):
    """CENTRALIZED LDAP Domain Service extending flext-core FlextDomainService.

    🎯 CONSOLIDATION: Single source replacing all duplicated service interfaces.

    ELIMINATES:
    - FlextLdapConnectionService (domain/ports.py:21)
    - FlextLdapSearchService (domain/ports.py:71)
    - FlextLdapUserService (domain/ports.py:97)
    - FlextLdapSchemaService (domain/ports.py:149)
    - FlextLdapMigrationService (domain/ports.py:171)
    - FlextLdapDirectoryServiceInterface (adapters/directory_adapter.py:72)
    - LdapUserServiceProtocol (protocols.py:286)
    - LdapGroupServiceProtocol (protocols.py:313)

    Extends flext-core FlextDomainService with LDAP-specific business operations
    while maintaining stateless design and full SOLID compliance.
    """

    # CONNECTION MANAGEMENT OPERATIONS

    @abstractmethod
    async def connect(
        self,
        server_url: str,
        bind_dn: str | None = None,
        password: str | None = None,
    ) -> FlextResult[str]:
        """Establish LDAP connection.

        Args:
            server_url: LDAP server URL (ldap:// or ldaps://)
            bind_dn: Bind distinguished name (None for anonymous)
            password: Bind password (None for anonymous)

        Returns:
            FlextResult containing connection ID if successful

        """

    @abstractmethod
    async def disconnect(self, connection_id: str) -> FlextResult[None]:
        """Disconnect from LDAP server.

        Args:
            connection_id: Connection identifier to disconnect

        Returns:
            FlextResult indicating success or failure

        """

    @abstractmethod
    async def test_connection(self, connection_id: str) -> FlextResult[bool]:
        """Test LDAP connection health.

        Args:
            connection_id: Connection identifier to test

        Returns:
            FlextResult containing True if connection is healthy

        """

    # SCHEMA VALIDATION OPERATIONS

    @abstractmethod
    async def get_schema(self, connection_id: str) -> FlextResult[dict[str, object]]:
        """Get LDAP schema information.

        Args:
            connection_id: Active connection identifier

        Returns:
            FlextResult containing schema information

        """

    @abstractmethod
    async def validate_entry_schema(
        self,
        connection_id: str,
        dn: FlextLdapDistinguishedName,
        attributes: dict[str, list[str]],
    ) -> FlextResult[list[str]]:
        """Validate entry against LDAP schema.

        Args:
            connection_id: Active connection identifier
            dn: Entry distinguished name
            attributes: Entry attributes to validate

        Returns:
            FlextResult containing list of validation errors (empty = valid)

        """

    # MIGRATION OPERATIONS

    @abstractmethod
    async def export_entries(
        self,
        connection_id: str,
        base_dn: FlextLdapDistinguishedName,
        search_filter: FlextLdapFilter,
        output_format: str = "ldif",
    ) -> FlextResult[str]:
        """Export LDAP entries to specified format.

        Args:
            connection_id: Active connection identifier
            base_dn: Export base distinguished name
            search_filter: Filter for entries to export
            output_format: Export format (ldif, json, etc.)

        Returns:
            FlextResult containing exported data as string

        """

    @abstractmethod
    async def import_entries(
        self,
        connection_id: str,
        data: str,
        data_format: str = "ldif",
        *,
        dry_run: bool = False,
    ) -> FlextResult[dict[str, int]]:
        """Import LDAP entries from specified format.

        Args:
            connection_id: Active connection identifier
            data: Data to import as string
            data_format: Data format (ldif, json, etc.)
            dry_run: If True, validate only without importing

        Returns:
            FlextResult containing import statistics

        """


class FlextLdapConnectionService(FlextLdapService):
    """LDAP Connection Management Service - Specialized from FlextLdapService."""

    def execute(self) -> FlextResult[object]:
        """Execute connection management operation.

        Default implementation - override in concrete implementations.

        Returns:
            FlextResult indicating execution success

        """
        return FlextResult.fail("Connection service execute method not implemented")


class FlextLdapUserService(FlextLdapService):
    """LDAP User Management Service - Specialized from FlextLdapService."""

    def execute(self) -> FlextResult[object]:
        """Execute user management operation.

        Default implementation - override in concrete implementations.

        Returns:
            FlextResult indicating execution success

        """
        return FlextResult.fail("User service execute method not implemented")


class FlextLdapGroupService(FlextLdapService):
    """LDAP Group Management Service - Specialized from FlextLdapService."""

    def execute(self) -> FlextResult[object]:
        """Execute group management operation.

        Default implementation - override in concrete implementations.

        Returns:
            FlextResult indicating execution success

        """
        return FlextResult.fail("Group service execute method not implemented")


class FlextLdapSchemaService(FlextLdapService):
    """LDAP Schema Validation Service - Specialized from FlextLdapService."""

    def execute(self) -> FlextResult[object]:
        """Execute schema validation operation.

        Default implementation - override in concrete implementations.

        Returns:
            FlextResult indicating execution success

        """
        return FlextResult.fail("Schema service execute method not implemented")


class FlextLdapMigrationService(FlextLdapService):
    """LDAP Migration Service - Specialized from FlextLdapService."""

    def execute(self) -> FlextResult[object]:
        """Execute migration operation.

        Default implementation - override in concrete implementations.

        Returns:
            FlextResult indicating execution success

        """
        return FlextResult.fail("Migration service execute method not implemented")


# =============================================================================
# FACTORY FUNCTIONS - Eliminate Service Instantiation Boilerplate
# =============================================================================


def create_ldap_repository() -> FlextLdapRepository:
    """Factory for creating LDAP repositories.

    Returns:
        Concrete LDAP repository instance

    Raises:
        NotImplementedError: Must be implemented by concrete implementation

    """
    error_msg = "LDAP repository factory not implemented - use concrete implementation"
    raise NotImplementedError(error_msg)


def create_ldap_service() -> FlextLdapService:
    """Factory for creating LDAP services.

    Returns:
        Concrete LDAP service instance

    Raises:
        NotImplementedError: Must be implemented by concrete implementation

    """
    error_msg = "LDAP service factory not implemented - use concrete implementation"
    raise NotImplementedError(error_msg)


# =============================================================================
# PUBLIC API EXPORTS - CENTRALIZED ABSTRACTIONS
# =============================================================================


__all__ = [
    "FlextLdapConnectionService",
    "FlextLdapGroupService",
    "FlextLdapMigrationService",
    "FlextLdapRepository",
    "FlextLdapSchemaService",
    "FlextLdapService",
    "FlextLdapUserService",
    "create_ldap_repository",
    "create_ldap_service",
]

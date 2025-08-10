"""LDAP Group Operations - DEDICATED PEP8 MODULE FOR CONCRETE CLASSES.

🎯 ELIMINATES DUPLICATIONS - Dedicated group management operations module
Following advanced Python 3.13 + flext-core patterns with zero duplication.

CONSOLIDATES GROUP OPERATIONS FROM:
- group_management.py: Group operation logic (scattered)
- application/group_service.py: Application layer group services
- domain/group_operations.py: Domain group business logic
- infrastructure/group_repository.py: Group data access patterns
- All group-related operations across 10+ files

This module provides DEDICATED group management operations using:
- Advanced Python 3.13 features extensively
- flext-core foundation patterns (FlextResult, DI interfaces)
- Consolidated foundation modules (protocols.py, models.py, constants.py)
- Clean Architecture and Domain-Driven Design principles
- Proper DI library interfaces (not service implementation)

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""


from __future__ import annotations

from datetime import UTC, datetime
from typing import TYPE_CHECKING

# ✅ CORRECT: Import by root from flext-core (not submodules)
from flext_core import FlextResult, get_flext_container, get_logger

# ✅ CORRECT: Use consolidated foundation modules
from .constants import FlextLdapAttributeConstants, FlextLdapObjectClassConstants
from .models import (
    FlextLdapCreateGroupRequest,
    FlextLdapDistinguishedName,
    FlextLdapFilter,
    FlextLdapGroup,
    FlextLdapSearchConfig,
    FlextLdapSearchResult,
)
from .protocols import FlextLdapConnectionProtocol, FlextLdapRepositoryProtocol

if TYPE_CHECKING:
    from collections.abc import AsyncGenerator

logger = get_logger(__name__)

# =============================================================================
# GROUP MANAGEMENT INTERFACE - DI Library Pattern
# =============================================================================


class FlextLdapGroupOperations:
    """LDAP Group Management Operations following DI library patterns.

    🎯 CONSOLIDATES AND REPLACES:
    - FlextLdapGroupService (application/group_service.py)
    - FlextLdapGroupManager (group_management.py)
    - Group operation patterns scattered across domain/application layers
    - All group-specific business operations duplications

    DI LIBRARY PATTERN:
    This class provides group operation interfaces for dependency injection.
    It does NOT implement services - it provides operation contracts.
    """

    def __init__(
        self,
        connection: FlextLdapConnectionProtocol,
        repository: FlextLdapRepositoryProtocol,
    ) -> None:
        """Initialize group operations with DI dependencies.

        Args:
            connection: LDAP connection protocol implementation
            repository: LDAP repository protocol implementation

        """
        self._connection = connection
        self._repository = repository
        self._container = get_flext_container()

    # =========================================================================
    # GROUP CREATION OPERATIONS - Advanced Python 3.13 patterns
    # =========================================================================

    async def create_group(
        self,
        connection_id: str,
        request: FlextLdapCreateGroupRequest,
    ) -> FlextResult[FlextLdapGroup]:
        """Create new LDAP group with comprehensive validation.

        🎯 CONSOLIDATES AND REPLACES:
        - create_group() functions scattered across multiple modules
        - Group creation logic duplicated in application/domain layers
        - Validation patterns repeated in different group operations

        Args:
            connection_id: LDAP connection identifier
            request: Group creation request with validation

        Returns:
            FlextResult containing created group or error details

        """
        logger.debug(f"Creating group with DN: {request.dn.value}")

        # Validate group creation preconditions
        validation_result = await self._validate_group_creation_preconditions(
            connection_id, request
        )
        if validation_result.is_failure:
            return validation_result

        # Create and validate group entity
        group_result = await self._create_and_validate_group_entity(request)
        if group_result.is_failure:
            return group_result

        group = group_result.data

        # Persist group to LDAP
        persistence_result = await self._persist_group_to_ldap(connection_id, group)
        if persistence_result.is_failure:
            return persistence_result

        logger.info(f"Successfully created group: {request.dn.value}")
        return FlextResult.ok(group)

    async def create_organizational_unit_group(
        self,
        connection_id: str,
        parent_dn: FlextLdapDistinguishedName,
        ou_name: str,
        description: str | None = None,
    ) -> FlextResult[FlextLdapGroup]:
        """Create organizational unit group with standard attributes.

        🎯 CONSOLIDATES OU group creation patterns scattered across modules.

        Args:
            connection_id: LDAP connection identifier
            parent_dn: Parent DN where OU group will be created
            ou_name: Organizational unit name
            description: Optional group description

        Returns:
            FlextResult containing created OU group or error details

        """
        logger.debug(f"Creating organizational unit group: {ou_name}")

        # Construct DN for OU
        group_dn = FlextLdapDistinguishedName(value=f"ou={ou_name},{parent_dn.value}")

        # Create request with OU-specific object classes
        request = FlextLdapCreateGroupRequest(
            dn=group_dn,
            cn=ou_name,
            description=description,
            object_classes=[
                FlextLdapObjectClassConstants.TOP,
                FlextLdapObjectClassConstants.ORGANIZATIONAL_UNIT,
            ],
            additional_attributes={
                FlextLdapAttributeConstants.ORGANIZATIONAL_UNIT: [ou_name],
            },
        )

        return await self.create_group(connection_id, request)

    # =========================================================================
    # GROUP SEARCH OPERATIONS - Comprehensive query capabilities
    # =========================================================================

    async def search_groups(
        self,
        connection_id: str,
        config: FlextLdapSearchConfig,
    ) -> FlextResult[FlextLdapSearchResult]:
        """Search for groups with comprehensive filtering.

        🎯 CONSOLIDATES group search patterns scattered across search operations.

        Args:
            connection_id: LDAP connection identifier
            config: Search configuration with filters and limits

        Returns:
            FlextResult containing search results or error details

        """
        logger.debug(f"Searching groups in base DN: {config.base_dn.value}")

        # Validate search configuration
        config_validation = config.validate_business_rules()
        if config_validation.is_failure:
            return FlextResult.fail(f"Invalid search config: {config_validation.error}")

        # Execute search via repository
        search_result = await self._repository.search_entries(connection_id, config)
        if search_result.is_failure:
            return search_result

        # Convert LDAP entries to Group entities
        groups: list[FlextLdapGroup] = []
        for entry_data in search_result.data:
            group_result = self._ldap_attributes_to_group(entry_data)
            if group_result.is_success:
                groups.append(group_result.data)

        # Create search result
        result = FlextLdapSearchResult(
            entries=groups,
            total_count=len(groups),
            page_size=config.size_limit,
            search_time_ms=0,  # Would be measured in real implementation
        )

        logger.debug(f"Group search completed: found {len(groups)} groups")
        return FlextResult.ok(result)

    async def find_group_by_cn(
        self,
        connection_id: str,
        base_dn: FlextLdapDistinguishedName,
        cn: str,
    ) -> FlextResult[FlextLdapGroup | None]:
        """Find group by common name with optimized search.

        🎯 CONSOLIDATES find_group operations across multiple modules.

        Args:
            connection_id: LDAP connection identifier
            base_dn: Base DN for search
            cn: Group common name to search for

        Returns:
            FlextResult containing group or None if not found

        """
        logger.debug(f"Finding group by CN: {cn}")

        # Create optimized search filter for CN
        filter_obj = FlextLdapFilter.create_equality(
            FlextLdapAttributeConstants.COMMON_NAME, cn
        )

        search_config = FlextLdapSearchConfig(
            base_dn=base_dn,
            filter=filter_obj,
            size_limit=1,  # Only need one result
            attributes=[
                FlextLdapAttributeConstants.COMMON_NAME,
                FlextLdapAttributeConstants.DESCRIPTION,
                FlextLdapAttributeConstants.MEMBER,
                FlextLdapAttributeConstants.UNIQUE_MEMBER,
            ],
        )

        search_result = await self.search_groups(connection_id, search_config)
        if search_result.is_failure:
            return FlextResult.fail(f"Error searching for group: {search_result.error}")

        groups = search_result.data.entries
        if not groups:
            logger.debug(f"Group not found: {cn}")
            return FlextResult.ok(None)

        logger.debug(f"Found group by CN: {cn}")
        return FlextResult.ok(groups[0])

    async def find_groups_by_type(
        self,
        connection_id: str,
        base_dn: FlextLdapDistinguishedName,
        group_type: str,
    ) -> AsyncGenerator[FlextResult[FlextLdapGroup]]:
        """Find groups by type using async generator for large results.

        🎯 CONSOLIDATES type-based group search patterns.

        Args:
            connection_id: LDAP connection identifier
            base_dn: Base DN for search
            group_type: Group object class type (e.g., "groupOfNames")

        Yields:
            FlextResult containing individual groups or errors

        """
        logger.debug(f"Finding groups by type: {group_type}")

        # Create search filter for group type
        filter_obj = FlextLdapFilter.create_equality(
            FlextLdapAttributeConstants.OBJECT_CLASS, group_type
        )

        search_config = FlextLdapSearchConfig(
            base_dn=base_dn,
            filter=filter_obj,
            size_limit=0,  # Unlimited for streaming
        )

        search_result = await self.search_groups(connection_id, search_config)
        if search_result.is_failure:
            yield FlextResult.fail(
                f"Error searching groups by type: {search_result.error}"
            )
            return

        # Stream results one by one
        for group in search_result.data.entries:
            yield FlextResult.ok(group)

    # =========================================================================
    # GROUP MEMBERSHIP OPERATIONS - Member management
    # =========================================================================

    async def add_member_to_group(
        self,
        connection_id: str,
        group_dn: FlextLdapDistinguishedName,
        member_dn: FlextLdapDistinguishedName,
    ) -> FlextResult[None]:
        """Add member to group with validation.

        🎯 CONSOLIDATES group membership operations scattered across modules.

        Args:
            connection_id: LDAP connection identifier
            group_dn: Group distinguished name
            member_dn: Member distinguished name to add

        Returns:
            FlextResult indicating success or error

        """
        logger.debug(f"Adding member {member_dn.value} to group {group_dn.value}")

        # Get group to determine membership attribute
        group_result = await self._get_group_by_dn(connection_id, group_dn)
        if group_result.is_failure:
            return FlextResult.fail(f"Failed to get group: {group_result.error}")

        group = group_result.data
        if not group:
            return FlextResult.fail(f"Group not found: {group_dn.value}")

        # Check if member already exists
        if group.is_member(member_dn):
            return FlextResult.fail(f"Member {member_dn.value} already in group")

        # Determine membership attribute based on group type
        if group.group_type == "groupOfNames":
            member_attr = FlextLdapAttributeConstants.MEMBER
        elif group.group_type == "groupOfUniqueNames":
            member_attr = FlextLdapAttributeConstants.UNIQUE_MEMBER
        else:
            member_attr = FlextLdapAttributeConstants.MEMBER  # Default

        # Add member via repository
        modification_data = {
            member_attr: [member_dn.value],
        }

        result = await self._repository.modify_entry(
            connection_id=connection_id,
            entry_dn=group_dn.value,
            modifications=modification_data,
            operation="add",  # Add operation
        )

        if result.is_failure:
            return FlextResult.fail(f"Failed to add member to group: {result.error}")

        logger.info(
            f"Successfully added member {member_dn.value} to group {group_dn.value}"
        )
        return FlextResult.ok(None)

    async def remove_member_from_group(
        self,
        connection_id: str,
        group_dn: FlextLdapDistinguishedName,
        member_dn: FlextLdapDistinguishedName,
    ) -> FlextResult[None]:
        """Remove member from group with validation.

        Args:
            connection_id: LDAP connection identifier
            group_dn: Group distinguished name
            member_dn: Member distinguished name to remove

        Returns:
            FlextResult indicating success or error

        """
        logger.debug(f"Removing member {member_dn.value} from group {group_dn.value}")

        # Get group to determine membership attribute
        group_result = await self._get_group_by_dn(connection_id, group_dn)
        if group_result.is_failure:
            return FlextResult.fail(f"Failed to get group: {group_result.error}")

        group = group_result.data
        if not group:
            return FlextResult.fail(f"Group not found: {group_dn.value}")

        # Check if member exists
        if not group.is_member(member_dn):
            return FlextResult.fail(f"Member {member_dn.value} not in group")

        # Determine membership attribute based on group type
        if group.group_type == "groupOfNames":
            member_attr = FlextLdapAttributeConstants.MEMBER
        elif group.group_type == "groupOfUniqueNames":
            member_attr = FlextLdapAttributeConstants.UNIQUE_MEMBER
        else:
            member_attr = FlextLdapAttributeConstants.MEMBER  # Default

        # Remove member via repository
        modification_data = {
            member_attr: [member_dn.value],
        }

        result = await self._repository.modify_entry(
            connection_id=connection_id,
            entry_dn=group_dn.value,
            modifications=modification_data,
            operation="delete",  # Delete operation
        )

        if result.is_failure:
            return FlextResult.fail(
                f"Failed to remove member from group: {result.error}"
            )

        logger.info(
            f"Successfully removed member {member_dn.value} from group {group_dn.value}"
        )
        return FlextResult.ok(None)

    async def get_group_members(
        self,
        connection_id: str,
        group_dn: FlextLdapDistinguishedName,
    ) -> FlextResult[list[FlextLdapDistinguishedName]]:
        """Get all members of a group.

        Args:
            connection_id: LDAP connection identifier
            group_dn: Group distinguished name

        Returns:
            FlextResult containing list of member DNs or error

        """
        logger.debug(f"Getting members for group: {group_dn.value}")

        group_result = await self._get_group_by_dn(connection_id, group_dn)
        if group_result.is_failure:
            return FlextResult.fail(f"Failed to get group: {group_result.error}")

        group = group_result.data
        if not group:
            return FlextResult.fail(f"Group not found: {group_dn.value}")

        logger.debug(f"Found {len(group.members)} members in group {group_dn.value}")
        return FlextResult.ok(group.members)

    async def bulk_add_members_to_group(
        self,
        connection_id: str,
        group_dn: FlextLdapDistinguishedName,
        member_dns: list[FlextLdapDistinguishedName],
        *,
        batch_size: int = 20,
        fail_fast: bool = False,
    ) -> FlextResult[list[FlextLdapDistinguishedName]]:
        """Add multiple members to group in batches.

        Args:
            connection_id: LDAP connection identifier
            group_dn: Group distinguished name
            member_dns: List of member DNs to add
            batch_size: Number of members to process in each batch
            fail_fast: Stop on first error if True, continue if False

        Returns:
            FlextResult containing list of successfully added members or error

        """
        logger.debug(f"Bulk adding {len(member_dns)} members to group {group_dn.value}")

        if not member_dns:
            return FlextResult.ok([])

        added_members: list[FlextLdapDistinguishedName] = []
        errors: list[str] = []

        # Process members in batches
        for i in range(0, len(member_dns), batch_size):
            batch = member_dns[i : i + batch_size]

            for member_dn in batch:
                result = await self.add_member_to_group(
                    connection_id, group_dn, member_dn
                )

                if result.is_success:
                    added_members.append(member_dn)
                else:
                    error_msg = (
                        f"Failed to add member {member_dn.value}: {result.error}"
                    )
                    errors.append(error_msg)
                    logger.warning(error_msg)

                    if fail_fast:
                        return FlextResult.fail(
                            f"Bulk member addition failed: {result.error}"
                        )

        if errors:
            max_errors_to_show = 3
            error_summary = f"Bulk addition completed with {len(errors)} errors: {'; '.join(errors[:max_errors_to_show])}"
            if len(errors) > max_errors_to_show:
                error_summary += f" (and {len(errors) - max_errors_to_show} more)"
            logger.warning(error_summary)

        logger.info(
            f"Bulk addition completed: {len(added_members)} members added, {len(errors)} errors"
        )
        return FlextResult.ok(added_members)

    # =========================================================================
    # GROUP DELETION OPERATIONS - Removal and cleanup
    # =========================================================================

    async def delete_group(
        self,
        connection_id: str,
        group_dn: FlextLdapDistinguishedName,
        *,
        force: bool = False,
    ) -> FlextResult[None]:
        """Delete group with safety checks.

        Args:
            connection_id: LDAP connection identifier
            group_dn: Group distinguished name
            force: Skip safety checks if True

        Returns:
            FlextResult indicating success or error

        """
        logger.debug(f"Deleting group: {group_dn.value}")

        if not force:
            # Check if group exists before deletion
            exists_result = await self._check_group_exists(connection_id, group_dn)
            if exists_result.is_failure:
                return FlextResult.fail(
                    f"Error checking group existence: {exists_result.error}"
                )

            if not exists_result.data:
                return FlextResult.fail(f"Group does not exist: {group_dn.value}")

            # Check if group has members
            members_result = await self.get_group_members(connection_id, group_dn)
            if members_result.is_success and members_result.data:
                return FlextResult.fail(
                    f"Cannot delete group with {len(members_result.data)} members. Remove members first or use force=True"
                )

        # Delete via repository
        result = await self._repository.delete_entry(
            connection_id=connection_id,
            entry_dn=group_dn.value,
        )

        if result.is_failure:
            return FlextResult.fail(f"Failed to delete group: {result.error}")

        logger.info(f"Successfully deleted group: {group_dn.value}")
        return FlextResult.ok(None)

    # =========================================================================
    # PRIVATE HELPER METHODS - Internal operation support
    # =========================================================================

    async def _validate_group_creation_preconditions(
        self,
        connection_id: str,
        request: FlextLdapCreateGroupRequest,
    ) -> FlextResult[None]:
        """Validate preconditions for group creation."""
        # Validate request business rules
        validation_result = request.validate_business_rules()
        if validation_result.is_failure:
            return FlextResult.fail(
                f"Invalid group creation request: {validation_result.error}"
            )

        # Check if group already exists
        exists_result = await self._check_group_exists(connection_id, request.dn)
        if exists_result.is_failure:
            return FlextResult.fail(
                f"Error checking group existence: {exists_result.error}"
            )

        if exists_result.data:
            return FlextResult.fail(f"Group already exists: {request.dn.value}")

        return FlextResult.ok(None)

    async def _create_and_validate_group_entity(
        self,
        request: FlextLdapCreateGroupRequest,
    ) -> FlextResult[FlextLdapGroup]:
        """Create and validate group entity from request."""
        # Create group entity from request
        group_result = self._create_group_entity_from_request(request)
        if group_result.is_failure:
            return group_result

        group = group_result.data

        # Validate group business rules
        group_validation = group.validate_business_rules()
        if group_validation.is_failure:
            return FlextResult.fail(
                f"Group validation failed: {group_validation.error}"
            )

        return FlextResult.ok(group)

    async def _persist_group_to_ldap(
        self,
        connection_id: str,
        group: FlextLdapGroup,
    ) -> FlextResult[None]:
        """Persist group to LDAP repository."""
        create_result = await self._repository.create_entry(
            connection_id=connection_id,
            entry_data=self._group_to_ldap_attributes(group),
        )

        if create_result.is_failure:
            return FlextResult.fail(
                f"Failed to create group in LDAP: {create_result.error}"
            )

        return FlextResult.ok(None)

    async def _check_group_exists(
        self,
        connection_id: str,
        group_dn: FlextLdapDistinguishedName,
    ) -> FlextResult[bool]:
        """Check if group exists in directory."""
        config = FlextLdapSearchConfig(
            base_dn=group_dn,
            filter=FlextLdapFilter(value="(objectClass=*)"),
            size_limit=1,
        )

        result = await self._repository.search_entries(connection_id, config)
        if result.is_failure:
            return result

        return FlextResult.ok(len(result.data) > 0)

    async def _get_group_by_dn(
        self,
        connection_id: str,
        group_dn: FlextLdapDistinguishedName,
    ) -> FlextResult[FlextLdapGroup | None]:
        """Get group by DN."""
        config = FlextLdapSearchConfig(
            base_dn=group_dn,
            filter=FlextLdapFilter(value="(objectClass=*)"),
            size_limit=1,
        )

        search_result = await self.search_groups(connection_id, config)
        if search_result.is_failure:
            return FlextResult.fail(f"Error searching for group: {search_result.error}")

        groups = search_result.data.entries
        if not groups:
            return FlextResult.ok(None)

        return FlextResult.ok(groups[0])

    def _create_group_entity_from_request(
        self,
        request: FlextLdapCreateGroupRequest,
    ) -> FlextResult[FlextLdapGroup]:
        """Create group entity from creation request."""
        try:
            # Build attributes dictionary
            attributes = {
                FlextLdapAttributeConstants.OBJECT_CLASS: request.object_classes,
                FlextLdapAttributeConstants.COMMON_NAME: [request.cn],
            }

            if request.description:
                attributes[FlextLdapAttributeConstants.DESCRIPTION] = [
                    request.description
                ]

            # Add initial members if provided
            if request.initial_members:
                # Determine membership attribute based on object class
                if "groupOfNames" in request.object_classes:
                    member_attr = FlextLdapAttributeConstants.MEMBER
                elif "groupOfUniqueNames" in request.object_classes:
                    member_attr = FlextLdapAttributeConstants.UNIQUE_MEMBER
                else:
                    member_attr = FlextLdapAttributeConstants.MEMBER  # Default

                attributes[member_attr] = [
                    member.value for member in request.initial_members
                ]

            # Add additional attributes
            attributes.update(request.additional_attributes)

            # Determine group type from object classes
            group_type = "groupOfNames"  # Default
            if "groupOfUniqueNames" in request.object_classes:
                group_type = "groupOfUniqueNames"
            elif "posixGroup" in request.object_classes:
                group_type = "posixGroup"

            # Create group entity
            group = FlextLdapGroup(
                dn=request.dn,
                cn=request.cn,
                description=request.description,
                object_classes=request.object_classes,
                attributes=attributes,
                members=request.initial_members,
                group_type=group_type,
                created_at=datetime.now(UTC),
                modified_at=datetime.now(UTC),
            )

            return FlextResult.ok(group)

        except Exception as e:
            return FlextResult.fail(f"Error creating group entity: {e}")

    def _group_to_ldap_attributes(self, group: FlextLdapGroup) -> dict[str, list[str]]:
        """Convert group entity to LDAP attributes."""
        # This would return the group's attributes dictionary
        # In a real implementation, this might include additional transformation
        return group.attributes

    def _ldap_attributes_to_group(
        self,
        entry_data: dict[str, object],
    ) -> FlextResult[FlextLdapGroup]:
        """Convert LDAP entry data to group entity."""
        try:
            # Extract required fields
            dn_value = entry_data.get("dn", "")
            if not dn_value or not isinstance(dn_value, str):
                return FlextResult.fail("Missing or invalid DN in entry data")

            dn = FlextLdapDistinguishedName(value=dn_value)
            attributes = entry_data.get("attributes", {})
            if not isinstance(attributes, dict):
                return FlextResult.fail("Invalid attributes in entry data")

            # Extract group-specific fields
            cn_values = attributes.get(FlextLdapAttributeConstants.COMMON_NAME, [])
            cn = cn_values[0] if cn_values and isinstance(cn_values, list) else ""

            if not cn:
                return FlextResult.fail("Missing CN in group entry")

            description_values = attributes.get(
                FlextLdapAttributeConstants.DESCRIPTION, []
            )
            description = (
                description_values[0]
                if description_values and isinstance(description_values, list)
                else None
            )

            object_classes = attributes.get(
                FlextLdapAttributeConstants.OBJECT_CLASS, []
            )
            if not isinstance(object_classes, list):
                object_classes = []

            # Extract members based on group type
            members: list[FlextLdapDistinguishedName] = []
            member_values = attributes.get(FlextLdapAttributeConstants.MEMBER, [])
            unique_member_values = attributes.get(
                FlextLdapAttributeConstants.UNIQUE_MEMBER, []
            )

            # Use appropriate member attribute
            if member_values and isinstance(member_values, list):
                members = [
                    FlextLdapDistinguishedName(value=member) for member in member_values
                ]
            elif unique_member_values and isinstance(unique_member_values, list):
                members = [
                    FlextLdapDistinguishedName(value=member)
                    for member in unique_member_values
                ]

            # Determine group type
            group_type = "groupOfNames"  # Default
            if "groupOfUniqueNames" in object_classes:
                group_type = "groupOfUniqueNames"
            elif "posixGroup" in object_classes:
                group_type = "posixGroup"

            # Create group entity
            group = FlextLdapGroup(
                dn=dn,
                cn=cn,
                description=description,
                object_classes=object_classes,
                attributes=attributes,
                members=members,
                group_type=group_type,
                created_at=datetime.now(UTC),
                modified_at=datetime.now(UTC),
            )

            return FlextResult.ok(group)

        except Exception as e:
            return FlextResult.fail(f"Error converting LDAP data to group: {e}")


# =============================================================================
# CONVENIENCE FACTORY FUNCTIONS - DI Container Integration
# =============================================================================


def create_group_operations(
    connection: FlextLdapConnectionProtocol,
    repository: FlextLdapRepositoryProtocol,
) -> FlextLdapGroupOperations:
    """Create group operations instance with DI dependencies.

    🎯 FACTORY PATTERN for dependency injection integration.

    Args:
        connection: LDAP connection protocol implementation
        repository: LDAP repository protocol implementation

    Returns:
        Configured group operations instance

    """
    return FlextLdapGroupOperations(
        connection=connection,
        repository=repository,
    )


async def get_group_operations() -> FlextResult[FlextLdapGroupOperations]:
    """Get group operations from DI container.

    🎯 FLEXT-CORE INTEGRATION for container-based dependency resolution.

    Returns:
        FlextResult containing group operations instance or error

    """
    try:
        container = get_flext_container()

        # Get dependencies from container using typed accessors
        connection_result = container.get_typed(
            "FlextLdapConnectionProtocol", FlextLdapConnectionProtocol
        )
        if connection_result.is_failure:
            return FlextResult.fail(connection_result.error or "Connection not found")
        connection = connection_result.unwrap()

        repository_result = container.get_typed(
            "FlextLdapRepositoryProtocol", FlextLdapRepositoryProtocol
        )
        if repository_result.is_failure:
            return FlextResult.fail(repository_result.error or "Repository not found")
        repository = repository_result.unwrap()

        operations = create_group_operations(connection, repository)
        return FlextResult.ok(operations)

    except Exception as e:
        return FlextResult.fail(
            f"Failed to create group operations from container: {e}"
        )


# =============================================================================
# MODULE EXPORTS - Clean public interface
# =============================================================================

__all__ = [
    "FlextLdapGroupOperations",
    "create_group_operations",
    "get_group_operations",
]

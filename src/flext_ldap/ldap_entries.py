"""LDAP Entry Operations - DEDICATED PEP8 MODULE FOR CONCRETE CLASSES.

🎯 ELIMINATES DUPLICATIONS - Dedicated entry operations module
Following advanced Python 3.13 + flext-core patterns with zero duplication.

CONSOLIDATES ENTRY OPERATIONS FROM:
- entry_management.py: Entry operation logic (scattered)
- application/entry_service.py: Application layer entry services
- domain/entry_operations.py: Domain entry business logic
- infrastructure/entry_repository.py: Entry data access patterns
- All entry-related operations across 18+ files

This module provides DEDICATED entry operations using:
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
from typing import TYPE_CHECKING, cast

from flext_core import FlextIdGenerator, FlextResult, get_flext_container, get_logger

from flext_ldap.constants import (
    FlextLdapAttributeConstants,
    FlextLdapObjectClassConstants,
)
from flext_ldap.models import (
    FlextLdapDistinguishedName,
    FlextLdapEntry,
    FlextLdapEntryCreated,
    FlextLdapFilter,
    FlextLdapScope,
    FlextLdapSearchConfig,
)
from flext_ldap.protocols import (
    FlextLdapConnectionProtocol,
    FlextLdapRepositoryProtocol,
)

if TYPE_CHECKING:
    from flext_ldap.protocols import (
        FlextLdapConnectionProtocol,
        FlextLdapRepositoryProtocol,
    )

logger = get_logger(__name__)

# =============================================================================
# ENTRY OPERATIONS INTERFACE - DI Library Pattern
# =============================================================================


class FlextLdapEntryOperations:
    """LDAP Entry Operations following DI library patterns.

    🎯 CONSOLIDATES AND REPLACES:
    - FlextLdapEntryService (application/entry_service.py)
    - FlextLdapEntryManager (entry_management.py)
    - Entry operation patterns scattered across domain/application layers
    - All entry-specific business operations duplications

    DI LIBRARY PATTERN:
    This class provides entry operation interfaces for dependency injection.
    It does NOT implement services - it provides operation contracts.
    """

    def __init__(
        self,
        connection: FlextLdapConnectionProtocol,
        repository: FlextLdapRepositoryProtocol,
    ) -> None:
        """Initialize entry operations with DI dependencies.

        Args:
            connection: LDAP connection protocol implementation
            repository: LDAP repository protocol implementation

        """
        self._connection = connection
        self._repository = repository
        self._container = get_flext_container()

    # =========================================================================
    # ENTRY CREATION OPERATIONS - Advanced Python 3.13 patterns
    # =========================================================================

    async def create_entry(
        self,
        connection_id: str,
        entry: FlextLdapEntry,
        *,
        publish_events: bool = True,
    ) -> FlextResult[FlextLdapEntry]:
        """Create new LDAP entry with comprehensive validation and event publishing.

        🎯 CONSOLIDATES AND REPLACES:
        - create_entry() functions scattered across multiple modules
        - Entry creation logic duplicated in application/domain layers
        - Event publishing patterns repeated across operations

        Args:
            connection_id: LDAP connection identifier
            entry: Entry to create with validation
            publish_events: Whether to publish domain events

        Returns:
            FlextResult containing created entry or error details

        """
        logger.debug(f"Creating entry with DN: {entry.dn.value}")

        # Validate entry business rules
        validation_result = entry.validate_business_rules()
        if validation_result.is_failure:
            return FlextResult.fail(f"Invalid entry: {validation_result.error}")

        # Check if entry already exists
        exists_result = await self._check_entry_exists(connection_id, entry.dn)
        if exists_result.is_failure:
            return FlextResult.fail(
                f"Error checking entry existence: {exists_result.error}",
            )

        if exists_result.data:
            return FlextResult.fail(f"Entry already exists: {entry.dn.value}")

        # Prepare entry data for persistence
        # Normalize entry data to dict[str, object]
        entry_data_dict = self._entry_to_ldap_attributes(entry)
        entry_data: dict[str, object] = dict(entry_data_dict)

        # Create entry via repository
        create_result = await self._repository.create_entry(
            connection_id=connection_id,
            entry_data=entry_data,
        )

        if create_result.is_failure:
            return FlextResult.fail(
                f"Failed to create entry in LDAP: {create_result.error}",
            )

        # Update entity timestamp via flext-core convention
        entry.updated_at = datetime.now(UTC)

        # Publish domain events if enabled
        if publish_events:
            await self._publish_entry_created_event(entry)

        logger.info(f"Successfully created entry: {entry.dn.value}")
        return FlextResult.ok(entry)

    async def create_organizational_unit(
        self,
        connection_id: str,
        parent_dn: FlextLdapDistinguishedName,
        ou_name: str,
        description: str | None = None,
    ) -> FlextResult[FlextLdapEntry]:
        """Create organizational unit entry with standard attributes.

        🎯 CONSOLIDATES OU creation patterns scattered across modules.

        Args:
            connection_id: LDAP connection identifier
            parent_dn: Parent DN where OU will be created
            ou_name: Organizational unit name
            description: Optional OU description

        Returns:
            FlextResult containing created OU entry or error details

        """
        logger.debug(f"Creating organizational unit: {ou_name}")

        # Construct DN for OU
        ou_dn = FlextLdapDistinguishedName(value=f"ou={ou_name},{parent_dn.value}")

        # Build OU attributes
        attributes = {
            FlextLdapAttributeConstants.OBJECT_CLASS: [
                FlextLdapObjectClassConstants.TOP,
                FlextLdapObjectClassConstants.ORGANIZATIONAL_UNIT,
            ],
            FlextLdapAttributeConstants.ORGANIZATIONAL_UNIT: [ou_name],
        }

        if description:
            attributes[FlextLdapAttributeConstants.DESCRIPTION] = [description]

        # Create entry
        ou_entry = FlextLdapEntry(
            id=FlextIdGenerator.generate_id(),
            dn=ou_dn,
            object_classes=[
                FlextLdapObjectClassConstants.TOP,
                FlextLdapObjectClassConstants.ORGANIZATIONAL_UNIT,
            ],
            attributes=attributes,
        )

        return await self.create_entry(connection_id, ou_entry)

    async def bulk_create_entries(
        self,
        connection_id: str,
        entries: list[FlextLdapEntry],
        *,
        batch_size: int = 20,
        fail_fast: bool = False,
        publish_events: bool = True,
    ) -> FlextResult[list[FlextLdapEntry]]:
        """Create multiple entries in batches with error handling.

        🎯 CONSOLIDATES bulk entry operations scattered across modules.

        Args:
            connection_id: LDAP connection identifier
            entries: List of entries to create
            batch_size: Number of entries to process in each batch
            fail_fast: Stop on first error if True, continue if False
            publish_events: Whether to publish domain events

        Returns:
            FlextResult containing list of created entries or error details

        """
        logger.debug(f"Bulk creating {len(entries)} entries in batches of {batch_size}")

        if not entries:
            return FlextResult.ok([])

        created_entries: list[FlextLdapEntry] = []
        errors: list[str] = []

        # Process entries in batches
        for i in range(0, len(entries), batch_size):
            batch = entries[i : i + batch_size]

            for entry in batch:
                result = await self.create_entry(
                    connection_id,
                    entry,
                    publish_events=publish_events,
                )

                if result.is_success and result.data is not None:
                    created_entries.append(result.data)
                else:
                    error_msg = (
                        f"Failed to create entry {entry.dn.value}: {result.error}"
                    )
                    errors.append(error_msg)
                    logger.warning(error_msg)

                    if fail_fast:
                        return FlextResult.fail(f"Bulk creation failed: {result.error}")

        if errors:
            max_errors_to_show = 3
            error_summary = f"Bulk creation completed with {len(errors)} errors: {'; '.join(errors[:max_errors_to_show])}"
            if len(errors) > max_errors_to_show:
                error_summary += f" (and {len(errors) - max_errors_to_show} more)"
            logger.warning(error_summary)

        logger.info(
            f"Bulk creation completed: {len(created_entries)} entries created, {len(errors)} errors",
        )
        return FlextResult.ok(created_entries)

    # =========================================================================
    # ENTRY MODIFICATION OPERATIONS - Update and maintenance
    # =========================================================================

    async def modify_entry_attributes(
        self,
        connection_id: str,
        entry_dn: FlextLdapDistinguishedName,
        modifications: dict[str, list[str]],
        *,
        operation: str = "replace",
    ) -> FlextResult[None]:
        """Modify entry attributes with specified operation.

        🎯 CONSOLIDATES entry modification patterns across modules.

        Args:
            connection_id: LDAP connection identifier
            entry_dn: Distinguished name of entry to modify
            modifications: Dictionary of attribute modifications
            operation: Modification operation (replace, add, delete)

        Returns:
            FlextResult indicating success or error

        """
        logger.debug(f"Modifying entry {entry_dn.value} with {operation} operation")

        # Validate DN
        dn_validation = entry_dn.validate_business_rules()
        if dn_validation.is_failure:
            return FlextResult.fail(f"Invalid entry DN: {dn_validation.error}")

        # Check if entry exists
        exists_result = await self._check_entry_exists(connection_id, entry_dn)
        if exists_result.is_failure:
            return FlextResult.fail(
                f"Error checking entry existence: {exists_result.error}",
            )

        if not exists_result.data:
            return FlextResult.fail(f"Entry does not exist: {entry_dn.value}")

        # Perform modification via repository
        modify_result = await self._repository.modify_entry(
            connection_id=connection_id,
            entry_dn=entry_dn.value,
            modifications=cast("dict[str, object]", modifications),
            operation=operation,
        )

        if modify_result.is_failure:
            return FlextResult.fail(f"Failed to modify entry: {modify_result.error}")

        logger.info(f"Successfully modified entry: {entry_dn.value}")
        return FlextResult.ok(None)

    async def add_attribute_values(
        self,
        connection_id: str,
        entry_dn: FlextLdapDistinguishedName,
        attribute_name: str,
        values: list[str],
    ) -> FlextResult[None]:
        """Add values to an entry attribute.

        Args:
            connection_id: LDAP connection identifier
            entry_dn: Distinguished name of entry
            attribute_name: Name of attribute to modify
            values: Values to add

        Returns:
            FlextResult indicating success or error

        """
        logger.debug(
            f"Adding values to attribute {attribute_name} on entry {entry_dn.value}",
        )

        modifications = {attribute_name: values}
        return await self.modify_entry_attributes(
            connection_id=connection_id,
            entry_dn=entry_dn,
            modifications=modifications,
            operation="add",
        )

    async def remove_attribute_values(
        self,
        connection_id: str,
        entry_dn: FlextLdapDistinguishedName,
        attribute_name: str,
        values: list[str] | None = None,
    ) -> FlextResult[None]:
        """Remove values from an entry attribute.

        Args:
            connection_id: LDAP connection identifier
            entry_dn: Distinguished name of entry
            attribute_name: Name of attribute to modify
            values: Values to remove (None removes all values)

        Returns:
            FlextResult indicating success or error

        """
        logger.debug(
            f"Removing values from attribute {attribute_name} on entry {entry_dn.value}",
        )

        if values is None:
            # Remove entire attribute
            modifications: dict[str, list[str]] = {attribute_name: []}
        else:
            modifications = {attribute_name: values}

        return await self.modify_entry_attributes(
            connection_id=connection_id,
            entry_dn=entry_dn,
            modifications=modifications,
            operation="delete",
        )

    async def replace_attribute_values(
        self,
        connection_id: str,
        entry_dn: FlextLdapDistinguishedName,
        attribute_name: str,
        values: list[str],
    ) -> FlextResult[None]:
        """Replace all values of an entry attribute.

        Args:
            connection_id: LDAP connection identifier
            entry_dn: Distinguished name of entry
            attribute_name: Name of attribute to modify
            values: New values to set

        Returns:
            FlextResult indicating success or error

        """
        logger.debug(
            f"Replacing values of attribute {attribute_name} on entry {entry_dn.value}",
        )

        modifications = {attribute_name: values}
        return await self.modify_entry_attributes(
            connection_id=connection_id,
            entry_dn=entry_dn,
            modifications=modifications,
            operation="replace",
        )

    # =========================================================================
    # ENTRY RETRIEVAL OPERATIONS - Read and query operations
    # =========================================================================

    async def get_entry(
        self,
        connection_id: str,
        entry_dn: FlextLdapDistinguishedName,
        attributes: list[str] | None = None,
    ) -> FlextResult[FlextLdapEntry | None]:
        """Get entry by distinguished name.

        🎯 CONSOLIDATES entry retrieval patterns across modules.

        Args:
            connection_id: LDAP connection identifier
            entry_dn: Distinguished name of entry to retrieve
            attributes: Optional list of attributes to retrieve (None for all)

        Returns:
            FlextResult containing entry or None if not found

        """
        logger.debug(f"Getting entry: {entry_dn.value}")

        # Create search config for specific entry
        config = FlextLdapSearchConfig(
            base_dn=entry_dn,
            filter=FlextLdapFilter(value="(objectClass=*)"),
            attributes=attributes,
            size_limit=1,
        )

        # Execute search via repository
        search_result = await self._repository.search_entries(
            connection_id,
            cast("dict[str, object]", config.model_dump()),
        )
        if search_result.is_failure:
            return FlextResult.fail(f"Failed to get entry: {search_result.error}")

        # Convert results to entry objects
        if not search_result.data:
            logger.debug(f"Entry not found: {entry_dn.value}")
            return FlextResult.ok(None)

        # Convert first result to entry
        entry_data = search_result.data[0]
        entry_result = self._convert_entry_data(entry_data)
        if entry_result.is_failure:
            return FlextResult.fail(entry_result.error or "Entry conversion failed")

        logger.debug(f"Successfully retrieved entry: {entry_dn.value}")
        return FlextResult.ok(entry_result.data)

    async def get_entry_attributes(
        self,
        connection_id: str,
        entry_dn: FlextLdapDistinguishedName,
        attribute_names: list[str],
    ) -> FlextResult[dict[str, list[str]]]:
        """Get specific attributes from an entry.

        Args:
            connection_id: LDAP connection identifier
            entry_dn: Distinguished name of entry
            attribute_names: List of attribute names to retrieve

        Returns:
            FlextResult containing attribute dictionary or error

        """
        logger.debug(
            f"Getting attributes {attribute_names} from entry {entry_dn.value}",
        )

        # Get entry with specific attributes
        entry_result = await self.get_entry(
            connection_id=connection_id,
            entry_dn=entry_dn,
            attributes=attribute_names,
        )

        if entry_result.is_failure:
            return FlextResult.fail(
                f"Failed to get entry attributes: {entry_result.error}",
            )

        if entry_result.data is None:
            return FlextResult.fail(f"Entry not found: {entry_dn.value}")

        entry = entry_result.data

        # Filter requested attributes
        filtered_attributes = {
            name: entry.attributes.get(name, []) for name in attribute_names
        }

        logger.debug(f"Retrieved {len(filtered_attributes)} attributes from entry")
        return FlextResult.ok(filtered_attributes)

    # =========================================================================
    # ENTRY DELETION OPERATIONS - Removal and cleanup
    # =========================================================================

    async def delete_entry(
        self,
        connection_id: str,
        entry_dn: FlextLdapDistinguishedName,
        *,
        recursive: bool = False,
        force: bool = False,
    ) -> FlextResult[None]:
        """Delete entry with safety checks.

        🎯 CONSOLIDATES entry deletion patterns across modules.

        Args:
            connection_id: LDAP connection identifier
            entry_dn: Distinguished name of entry to delete
            recursive: Delete child entries recursively
            force: Skip safety checks if True

        Returns:
            FlextResult indicating success or error

        """
        logger.debug(f"Deleting entry: {entry_dn.value} (recursive={recursive})")

        # Perform pre-deletion validations
        validation_result = await self._validate_delete_preconditions(
            connection_id=connection_id,
            entry_dn=entry_dn,
            recursive=recursive,
            force=force,
        )
        if validation_result.is_failure:
            return validation_result

        # Execute deletion strategy
        deletion_result = await self._execute_deletion_strategy(
            connection_id=connection_id,
            entry_dn=entry_dn,
            recursive=recursive,
        )
        if deletion_result.is_failure:
            return deletion_result

        logger.info(f"Successfully deleted entry: {entry_dn.value}")
        return FlextResult.ok(None)

    async def bulk_delete_entries(
        self,
        connection_id: str,
        entry_dns: list[FlextLdapDistinguishedName],
        *,
        batch_size: int = 10,
        fail_fast: bool = False,
        force: bool = False,
    ) -> FlextResult[list[FlextLdapDistinguishedName]]:
        """Delete multiple entries in batches.

        Args:
            connection_id: LDAP connection identifier
            entry_dns: List of entry DNs to delete
            batch_size: Number of entries to process in each batch
            fail_fast: Stop on first error if True, continue if False
            force: Skip safety checks if True

        Returns:
            FlextResult containing list of successfully deleted entry DNs or error

        """
        logger.debug(
            f"Bulk deleting {len(entry_dns)} entries in batches of {batch_size}",
        )

        if not entry_dns:
            return FlextResult.ok([])

        deleted_entries: list[FlextLdapDistinguishedName] = []
        errors: list[str] = []

        # Process entries in batches
        for i in range(0, len(entry_dns), batch_size):
            batch = entry_dns[i : i + batch_size]

            for entry_dn in batch:
                result = await self.delete_entry(
                    connection_id=connection_id,
                    entry_dn=entry_dn,
                    force=force,
                )

                if result.is_success:
                    deleted_entries.append(entry_dn)
                else:
                    error_msg = (
                        f"Failed to delete entry {entry_dn.value}: {result.error}"
                    )
                    errors.append(error_msg)
                    logger.warning(error_msg)

                    if fail_fast:
                        return FlextResult.fail(f"Bulk deletion failed: {result.error}")

        if errors:
            max_errors_to_show = 3
            error_summary = f"Bulk deletion completed with {len(errors)} errors: {'; '.join(errors[:max_errors_to_show])}"
            if len(errors) > max_errors_to_show:
                error_summary += f" (and {len(errors) - max_errors_to_show} more)"
            logger.warning(error_summary)

        logger.info(
            f"Bulk deletion completed: {len(deleted_entries)} entries deleted, {len(errors)} errors",
        )
        return FlextResult.ok(deleted_entries)

    # =========================================================================
    # PRIVATE HELPER METHODS - Internal operation support
    # =========================================================================

    async def _validate_delete_preconditions(
        self,
        connection_id: str,
        entry_dn: FlextLdapDistinguishedName,
        *,
        recursive: bool,
        force: bool,
    ) -> FlextResult[None]:
        """Validate preconditions for entry deletion."""
        if force:
            return FlextResult.ok(None)

        # Check if entry exists before deletion
        exists_result = await self._check_entry_exists(connection_id, entry_dn)
        if exists_result.is_failure:
            return FlextResult.fail(
                f"Error checking entry existence: {exists_result.error}",
            )

        if not exists_result.data:
            return FlextResult.fail(f"Entry does not exist: {entry_dn.value}")

        # Check for child entries if not recursive
        if not recursive:
            has_children_result = await self._check_has_children(
                connection_id,
                entry_dn,
            )
            if has_children_result.is_failure:
                return FlextResult.fail(
                    f"Error checking for child entries: {has_children_result.error}",
                )

            if has_children_result.data:
                return FlextResult.fail(
                    f"Entry has child entries. Use recursive=True or remove children first: {entry_dn.value}",
                )

        return FlextResult.ok(None)

    async def _execute_deletion_strategy(
        self,
        connection_id: str,
        entry_dn: FlextLdapDistinguishedName,
        *,
        recursive: bool,
    ) -> FlextResult[None]:
        """Execute the appropriate deletion strategy."""
        if recursive:
            return await self._delete_entry_recursive(connection_id, entry_dn)

        # Delete single entry via repository
        delete_result = await self._repository.delete_entry(
            connection_id=connection_id,
            entry_dn=entry_dn.value,
        )

        if delete_result.is_failure:
            return FlextResult.fail(f"Failed to delete entry: {delete_result.error}")

        return FlextResult.ok(None)

    async def _check_entry_exists(
        self,
        connection_id: str,
        entry_dn: FlextLdapDistinguishedName,
    ) -> FlextResult[list[dict[str, object]]]:
        """Check if entry exists."""
        try:
            # Create search config
            config = FlextLdapSearchConfig(
                base_dn=entry_dn,
                filter=FlextLdapFilter.create_presence(
                    FlextLdapAttributeConstants.OBJECT_CLASS,
                ),
                scope=FlextLdapScope.base(),
                attributes=[FlextLdapAttributeConstants.OBJECT_CLASS],
            )

            search_result = await self._repository.search_entries(
                connection_id,
                config.model_dump(),
            )

            if search_result.is_failure:
                return FlextResult.fail(f"Search failed: {search_result.error}")

            if search_result.data is None:
                return FlextResult.ok([])

            return FlextResult.ok(search_result.data)

        except Exception as e:
            return FlextResult.fail(f"Failed to check entry existence: {e}")

    async def _check_has_children(
        self,
        connection_id: str,
        entry_dn: FlextLdapDistinguishedName,
    ) -> FlextResult[list[dict[str, object]]]:
        """Check if entry has children."""
        try:
            # Create search config
            config = FlextLdapSearchConfig(
                base_dn=entry_dn,
                filter=FlextLdapFilter.create_presence(
                    FlextLdapAttributeConstants.OBJECT_CLASS,
                ),
                scope=FlextLdapScope.one_level(),
                attributes=[FlextLdapAttributeConstants.OBJECT_CLASS],
            )

            search_result = await self._repository.search_entries(
                connection_id,
                config.model_dump(),
            )

            if search_result.is_failure:
                return FlextResult.fail(f"Search failed: {search_result.error}")

            if search_result.data is None:
                return FlextResult.ok([])

            return FlextResult.ok(search_result.data)

        except Exception as e:
            return FlextResult.fail(f"Failed to check children: {e}")

    async def _delete_entry_recursive(
        self,
        connection_id: str,
        entry_dn: FlextLdapDistinguishedName,
    ) -> FlextResult[None]:
        """Delete entry and all its children recursively."""
        try:
            # First delete all children
            children_result = await self._check_has_children(connection_id, entry_dn)
            if children_result.is_failure:
                return FlextResult.fail(
                    f"Failed to check children: {children_result.error}",
                )

            if children_result.data:
                for child_data in children_result.data:
                    if isinstance(child_data, dict):
                        child_dn_value = child_data.get("distinguished_name")
                        if isinstance(child_dn_value, str):
                            child_dn = FlextLdapDistinguishedName(value=child_dn_value)
                            await self._delete_entry_recursive(connection_id, child_dn)

            # Then delete the entry itself
            delete_result = await self._repository.delete_entry(
                connection_id,
                entry_dn.value,
            )
            if delete_result.is_failure:
                return FlextResult.fail(
                    f"Failed to delete entry: {delete_result.error}",
                )

            return FlextResult.ok(None)

        except Exception as e:
            return FlextResult.fail(f"Failed to delete entry recursively: {e}")

    @staticmethod
    def _entry_to_ldap_attributes(entry: FlextLdapEntry) -> dict[str, list[str]]:
        """Convert entry entity to LDAP attributes."""
        # This would return the entry's attributes dictionary
        # In a real implementation, this might include additional transformation
        return entry.attributes

    @staticmethod
    def _convert_entry_data(
        entry_data: dict[str, object],
    ) -> FlextResult[FlextLdapEntry]:
        """Convert raw entry data to FlextLdapEntry object."""
        try:
            # Extract DN
            dn_value = entry_data.get("dn", "")
            if not dn_value or not isinstance(dn_value, str):
                return FlextResult.fail("Missing or invalid DN in entry data")

            dn = FlextLdapDistinguishedName(value=dn_value)

            # Extract attributes
            attributes = entry_data.get("attributes", {})
            if not isinstance(attributes, dict):
                return FlextResult.fail("Invalid attributes in entry data")

            # Extract object classes
            object_classes = attributes.get(
                FlextLdapAttributeConstants.OBJECT_CLASS,
                [],
            )
            if not isinstance(object_classes, list):
                object_classes = []

            # Create entry
            entry = FlextLdapEntry(
                id=FlextIdGenerator.generate_id(),
                dn=dn,
                object_classes=object_classes,
                attributes=attributes,
            )

            return FlextResult.ok(entry)

        except Exception as e:
            return FlextResult.fail(f"Error converting entry data: {e}")

    @staticmethod
    async def _publish_entry_created_event(entry: FlextLdapEntry) -> None:
        """Publish entry created domain event."""
        try:
            event = FlextLdapEntryCreated(
                aggregate_id=entry.id,
                entry_dn=entry.dn,
                event_data={
                    "entry_type": "ldap_entry",
                    "created_at": entry.created_at.isoformat()
                    if entry.created_at
                    else None,
                },
            )
            logger.debug(f"Entry created event: {event.event_type}")

        except Exception as e:
            logger.warning(f"Failed to publish entry created event: {e}")


# =============================================================================
# CONVENIENCE FACTORY FUNCTIONS - DI Container Integration
# =============================================================================


def create_entry_operations(
    connection: FlextLdapConnectionProtocol,
    repository: FlextLdapRepositoryProtocol,
) -> FlextLdapEntryOperations:
    """Create entry operations instance with DI dependencies.

    🎯 FACTORY PATTERN for dependency injection integration.

    Args:
        connection: LDAP connection protocol implementation
        repository: LDAP repository protocol implementation

    Returns:
        Configured entry operations instance

    """
    return FlextLdapEntryOperations(
        connection=connection,
        repository=repository,
    )


async def get_entry_operations() -> FlextResult[FlextLdapEntryOperations]:
    """Get entry operations instance with proper dependency injection."""
    try:
        container = get_flext_container()

        connection_res = container.get("FlextLdapConnectionProtocol")
        if connection_res.is_failure:
            return FlextResult.fail(connection_res.error or "Connection not found")
        connection = cast("FlextLdapConnectionProtocol", connection_res.unwrap())

        repository_res = container.get("FlextLdapRepositoryProtocol")
        if repository_res.is_failure:
            return FlextResult.fail(repository_res.error or "Repository not found")
        repository = cast("FlextLdapRepositoryProtocol", repository_res.unwrap())

        operations = FlextLdapEntryOperations(
            connection=connection,
            repository=repository,
        )
        return FlextResult.ok(operations)
    except Exception as e:
        return FlextResult.fail(
            f"Failed to create entry operations from container: {e}",
        )


# =============================================================================
# MODULE EXPORTS - Clean public interface
# =============================================================================

__all__ = [
    "FlextLdapEntryOperations",
    "create_entry_operations",
    "get_entry_operations",
]

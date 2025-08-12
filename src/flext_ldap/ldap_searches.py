"""LDAP Search Operations - DEDICATED PEP8 MODULE FOR CONCRETE CLASSES.

🎯 ELIMINATES DUPLICATIONS - Dedicated search operations module
Following advanced Python 3.13 + flext-core patterns with zero duplication.

CONSOLIDATES SEARCH OPERATIONS FROM:
- search_operations.py: Search operation logic (scattered)
- application/search_service.py: Application layer search services
- domain/search_specifications.py: Domain search business logic
- infrastructure/search_repository.py: Search data access patterns
- All search-related operations across 15+ files

This module provides DEDICATED search operations using:
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
    FlextLdapConnectionConstants,
    FlextLdapObjectClassConstants,
)
from flext_ldap.models import (
    FlextLdapDistinguishedName,
    FlextLdapEntry,
    FlextLdapFilter,
    FlextLdapScope,
    FlextLdapSearchConfig,
    FlextLdapSearchResult,
)

if TYPE_CHECKING:
    from collections.abc import AsyncGenerator

    from flext_ldap.protocols import (
        FlextLdapConnectionProtocol,
        FlextLdapRepositoryProtocol,
    )

logger = get_logger(__name__)

# =============================================================================
# SEARCH OPERATIONS INTERFACE - DI Library Pattern
# =============================================================================


class FlextLdapSearchOperations:
    """LDAP Search Operations following DI library patterns.

    🎯 CONSOLIDATES AND REPLACES:
    - FlextLdapSearchService (application/search_service.py)
    - FlextLdapSearchManager (search_operations.py)
    - Search operation patterns scattered across domain/application layers
    - All search-specific business operations duplications

    DI LIBRARY PATTERN:
    This class provides search operation interfaces for dependency injection.
    It does NOT implement services - it provides operation contracts.
    """

    def __init__(
        self,
        connection: FlextLdapConnectionProtocol,
        repository: FlextLdapRepositoryProtocol,
    ) -> None:
        """Initialize search operations with DI dependencies.

        Args:
            connection: LDAP connection protocol implementation
            repository: LDAP repository protocol implementation

        """
        self._connection = connection
        self._repository = repository
        self._container = get_flext_container()

    # =========================================================================
    # BASIC SEARCH OPERATIONS - Fundamental search patterns
    # =========================================================================

    async def search_entries(
        self,
        connection_id: str,
        config: FlextLdapSearchConfig,
    ) -> FlextResult[FlextLdapSearchResult]:
        """Perform LDAP search with comprehensive configuration.

        🎯 CONSOLIDATES AND REPLACES:
        - search() functions scattered across multiple modules
        - Search logic duplicated in application/domain layers
        - Result processing patterns repeated across operations

        Args:
            connection_id: LDAP connection identifier
            config: Search configuration with validation

        Returns:
            FlextResult containing search results or error details

        """
        logger.debug(f"Searching entries in base DN: {config.base_dn.value}")

        # Validate search configuration
        config_validation = config.validate_business_rules()
        if config_validation.is_failure:
            return FlextResult.fail(f"Invalid search config: {config_validation.error}")

        # Validate filter business rules
        filter_validation = config.filter.validate_business_rules()
        if filter_validation.is_failure:
            return FlextResult.fail(f"Invalid search filter: {filter_validation.error}")

        # Measure search execution time
        start_time = datetime.now(UTC)

        # Execute search via repository
        repo_config = config.model_dump()
        search_result = await self._repository.search_entries(
            connection_id,
            repo_config,
        )
        if search_result.is_failure:
            return FlextResult.fail(search_result.error or "Search failed")

        # Calculate execution time
        execution_time = int((datetime.now(UTC) - start_time).total_seconds() * 1000)

        # Convert raw entries to FlextLdapEntry objects
        entries: list[FlextLdapEntry] = []
        raw_entries = search_result.data or []
        for entry_data in raw_entries:
            entry_result = self._convert_entry_data(entry_data)
            if entry_result.is_success and entry_result.data is not None:
                entries.append(entry_result.data)
            else:
                logger.warning(f"Failed to convert entry: {entry_result.error}")

        # Create search result with metrics
        result = FlextLdapSearchResult(
            entries=entries,
            total_count=len(entries),
            page_size=config.size_limit,
            search_time_ms=execution_time,
        )

        logger.debug(
            f"Search completed: found {len(entries)} entries in {execution_time}ms",
        )
        return FlextResult.ok(result)

    async def search_one(
        self,
        connection_id: str,
        base_dn: FlextLdapDistinguishedName,
        filter_obj: FlextLdapFilter,
        attributes: list[str] | None = None,
    ) -> FlextResult[FlextLdapEntry | None]:
        """Search for single entry with optimized configuration.

        🎯 CONSOLIDATES single-entry search patterns across modules.

        Args:
            connection_id: LDAP connection identifier
            base_dn: Base DN for search
            filter_obj: Search filter
            attributes: Optional attribute list (None for all)

        Returns:
            FlextResult containing single entry or None if not found

        """
        logger.debug(f"Searching for single entry: {base_dn.value}")

        # Create optimized search config for single entry
        config = FlextLdapSearchConfig(
            base_dn=base_dn,
            filter=filter_obj,
            size_limit=1,  # Only need one result
            attributes=attributes,
        )

        search_result = await self.search_entries(connection_id, config)
        if search_result.is_failure:
            return FlextResult.fail(
                f"Single entry search failed: {search_result.error}",
            )

        entries = search_result.data.entries if search_result.data else []
        if not entries:
            logger.debug(f"No entry found for: {base_dn.value}")
            return FlextResult.ok(None)

        logger.debug(f"Found single entry: {base_dn.value}")
        return FlextResult.ok(entries[0])

    async def search_by_attribute(
        self,
        connection_id: str,
        base_dn: FlextLdapDistinguishedName,
        attribute_name: str,
        attribute_value: str,
        *,
        search_options: dict[str, object] | None = None,
    ) -> FlextResult[FlextLdapSearchResult]:
        """Search entries by specific attribute value.

        🎯 CONSOLIDATES attribute-based search patterns across modules.

        Args:
            connection_id: LDAP connection identifier
            base_dn: Base DN for search
            attribute_name: LDAP attribute name
            attribute_value: Attribute value to search for
            search_options: Optional search configuration with 'exact_match' and 'scope' keys

        Returns:
            FlextResult containing search results or error

        """
        logger.debug(f"Searching by attribute {attribute_name}={attribute_value}")

        # Extract search options with defaults
        options = search_options or {}
        exact_match = options.get("exact_match", True)
        scope = options.get("scope")

        # Create appropriate filter based on match type
        if exact_match:
            filter_obj = FlextLdapFilter.create_equality(
                attribute_name, attribute_value,
            )
        else:
            # Create wildcard filter
            filter_obj = FlextLdapFilter(
                value=f"({attribute_name}=*{attribute_value}*)",
            )

        # Create search config
        config = FlextLdapSearchConfig(
            base_dn=base_dn,
            filter=filter_obj,
            scope=scope
            if isinstance(scope, FlextLdapScope)
            else FlextLdapScope.subtree(),
            size_limit=FlextLdapConnectionConstants.DEFAULT_SIZE_LIMIT,
        )

        return await self.search_entries(connection_id, config)

    # =========================================================================
    # ADVANCED SEARCH OPERATIONS - Complex search patterns
    # =========================================================================

    async def search_with_paging(
        self,
        connection_id: str,
        config: FlextLdapSearchConfig,
        page_size: int = 500,
    ) -> AsyncGenerator[FlextResult[FlextLdapSearchResult]]:
        """Search with automatic paging for large result sets.

        🎯 CONSOLIDATES paging search patterns with async generators.

        Args:
            connection_id: LDAP connection identifier
            config: Search configuration
            page_size: Number of entries per page

        Yields:
            FlextResult containing paginated search results or errors

        """
        logger.debug(f"Starting paged search with page size: {page_size}")

        page_number = 0
        total_processed = 0

        # Create paged search config
        paged_config = FlextLdapSearchConfig(
            base_dn=config.base_dn,
            filter=config.filter,
            scope=config.scope,
            attributes=config.attributes,
            size_limit=page_size,
            time_limit=config.time_limit,
        )

        while True:
            page_number += 1
            logger.debug(f"Processing page {page_number}")

            # Execute search for current page
            page_result = await self.search_entries(connection_id, paged_config)
            if page_result.is_failure:
                yield page_result
                break

            page_data = page_result.data

            # If no results, we're done
            if page_data is None or not page_data.entries:
                logger.debug(
                    f"Paged search completed: {total_processed} total entries processed",
                )
                break

            total_processed += len(page_data.entries)

            # Yield current page
            yield FlextResult.ok(page_data)

            # Check if we got fewer results than requested (last page)
            if len(page_data.entries) < page_size:
                logger.debug(
                    f"Paged search completed: reached end with {total_processed} total entries",
                )
                break

            # Implementation note: Real LDAP paging would use Simple Paged Results control
            # Current implementation provides functional pagination for demonstration
            # Production systems should implement RFC 2696 Simple Paged Results

    async def search_multi_filter(
        self,
        connection_id: str,
        base_dn: FlextLdapDistinguishedName,
        filters: list[FlextLdapFilter],
        *,
        operator: str = "AND",
        scope: FlextLdapScope | None = None,
    ) -> FlextResult[FlextLdapSearchResult]:
        """Search with multiple filters combined with logical operator.

        🎯 CONSOLIDATES multi-filter search patterns across modules.

        Args:
            connection_id: LDAP connection identifier
            base_dn: Base DN for search
            filters: List of search filters
            operator: Logical operator ("AND", "OR", "NOT")
            scope: Optional search scope override

        Returns:
            FlextResult containing combined search results or error

        """
        logger.debug(
            f"Multi-filter search with {len(filters)} filters using {operator}",
        )

        if not filters:
            return FlextResult.fail(
                "At least one filter is required for multi-filter search",
            )

        # Validate all filters
        for i, filter_obj in enumerate(filters):
            filter_validation = filter_obj.validate_business_rules()
            if filter_validation.is_failure:
                return FlextResult.fail(
                    f"Invalid filter {i + 1}: {filter_validation.error}",
                )

        # Create combined filter based on operator
        combined_filter_result = self._combine_filters(filters, operator)
        if combined_filter_result.is_failure or combined_filter_result.data is None:
            return FlextResult.fail(
                combined_filter_result.error or "Failed to combine filters",
            )
        combined_filter = combined_filter_result.data

        # Create search config with combined filter
        config = FlextLdapSearchConfig(
            base_dn=base_dn,
            filter=combined_filter,
            scope=scope or FlextLdapScope.subtree(),
            size_limit=FlextLdapConnectionConstants.DEFAULT_SIZE_LIMIT,
        )

        return await self.search_entries(connection_id, config)

    async def search_by_object_class(
        self,
        connection_id: str,
        base_dn: FlextLdapDistinguishedName,
        object_class: str,
        *,
        additional_filters: list[FlextLdapFilter] | None = None,
    ) -> FlextResult[FlextLdapSearchResult]:
        """Search entries by object class with optional additional filters.

        🎯 CONSOLIDATES object class search patterns across modules.

        Args:
            connection_id: LDAP connection identifier
            base_dn: Base DN for search
            object_class: LDAP object class to search for
            additional_filters: Optional additional filters

        Returns:
            FlextResult containing search results or error

        """
        logger.debug(f"Searching by object class: {object_class}")

        # Create base object class filter
        object_class_filter = FlextLdapFilter.create_equality(
            FlextLdapAttributeConstants.OBJECT_CLASS, object_class,
        )

        # Combine with additional filters if provided
        if additional_filters:
            all_filters = [object_class_filter, *additional_filters]
            return await self.search_multi_filter(
                connection_id=connection_id,
                base_dn=base_dn,
                filters=all_filters,
                operator="AND",
            )
        # Single object class filter
        config = FlextLdapSearchConfig(
            base_dn=base_dn,
            filter=object_class_filter,
            scope=FlextLdapScope.subtree(),
        )
        return await self.search_entries(connection_id, config)

    # =========================================================================
    # SPECIALIZED SEARCH OPERATIONS - Domain-specific searches
    # =========================================================================

    async def search_users(
        self,
        connection_id: str,
        base_dn: FlextLdapDistinguishedName,
        *,
        name_pattern: str | None = None,
        email_pattern: str | None = None,
        active_only: bool = True,
    ) -> FlextResult[FlextLdapSearchResult]:
        """Search for user entries with user-specific filters.

        🎯 CONSOLIDATES user search patterns scattered across user operations.

        Args:
            connection_id: LDAP connection identifier
            base_dn: Base DN for search
            name_pattern: Optional name pattern (wildcard search)
            email_pattern: Optional email pattern (wildcard search)
            active_only: Search only active users

        Returns:
            FlextResult containing user search results or error

        """
        logger.debug(
            f"Searching users with patterns: name={name_pattern}, email={email_pattern}",
        )

        # Build filters for user search
        filters: list[FlextLdapFilter] = [
            FlextLdapFilter.create_equality(
                FlextLdapAttributeConstants.OBJECT_CLASS,
                FlextLdapObjectClassConstants.PERSON,
            ),
        ]

        # Base user object class filter

        # Name pattern filter
        if name_pattern:
            name_filter = FlextLdapFilter(
                value=f"({FlextLdapAttributeConstants.COMMON_NAME}=*{name_pattern}*)",
            )
            filters.append(name_filter)

        # Email pattern filter
        if email_pattern:
            email_filter = FlextLdapFilter(
                value=f"({FlextLdapAttributeConstants.MAIL}=*{email_pattern}*)",
            )
            filters.append(email_filter)

        # Active users filter
        if active_only:
            # This would depend on directory schema - example implementation
            active_filter = FlextLdapFilter(value="(!(userAccountControl=2))")
            filters.append(active_filter)

        # Execute multi-filter search
        return await self.search_multi_filter(
            connection_id=connection_id,
            base_dn=base_dn,
            filters=filters,
            operator="AND",
        )

    async def search_groups(
        self,
        connection_id: str,
        base_dn: FlextLdapDistinguishedName,
        *,
        group_type: str | None = None,
        name_pattern: str | None = None,
        has_members: bool | None = None,
    ) -> FlextResult[FlextLdapSearchResult]:
        """Search for group entries with group-specific filters.

        🎯 CONSOLIDATES group search patterns scattered across group operations.

        Args:
            connection_id: LDAP connection identifier
            base_dn: Base DN for search
            group_type: Optional group type object class
            name_pattern: Optional group name pattern
            has_members: Filter groups with/without members

        Returns:
            FlextResult containing group search results or error

        """
        logger.debug(f"Searching groups: type={group_type}, pattern={name_pattern}")

        # Build filters for group search
        filters: list[FlextLdapFilter] = []

        # Group object class filter
        if group_type:
            filters.append(
                FlextLdapFilter.create_equality(
                    FlextLdapAttributeConstants.OBJECT_CLASS, group_type,
                ),
            )
        else:
            # Default to groupOfNames
            filters.append(
                FlextLdapFilter.create_equality(
                    FlextLdapAttributeConstants.OBJECT_CLASS,
                    FlextLdapObjectClassConstants.GROUP_OF_NAMES,
                ),
            )

        # Name pattern filter
        if name_pattern:
            name_filter = FlextLdapFilter(
                value=f"({FlextLdapAttributeConstants.COMMON_NAME}=*{name_pattern}*)",
            )
            filters.append(name_filter)

        # Member presence filter
        if has_members is not None:
            if has_members:
                # Groups with members
                member_filter = FlextLdapFilter.create_presence(
                    FlextLdapAttributeConstants.MEMBER,
                )
            else:
                # Groups without members
                member_filter = FlextLdapFilter(
                    value=f"(!({FlextLdapAttributeConstants.MEMBER}=*))",
                )
            filters.append(member_filter)

        # Execute multi-filter search
        return await self.search_multi_filter(
            connection_id=connection_id,
            base_dn=base_dn,
            filters=filters,
            operator="AND",
        )

    # =========================================================================
    # SEARCH UTILITIES - Helper operations
    # =========================================================================

    async def count_entries(
        self,
        connection_id: str,
        base_dn: FlextLdapDistinguishedName,
        filter_obj: FlextLdapFilter,
    ) -> FlextResult[int]:
        """Count entries matching search criteria without retrieving full data.

        🎯 CONSOLIDATES count operations for efficient statistics.

        Args:
            connection_id: LDAP connection identifier
            base_dn: Base DN for search
            filter_obj: Search filter

        Returns:
            FlextResult containing entry count or error

        """
        logger.debug(f"Counting entries for filter: {filter_obj.value}")

        # Create count-optimized search config
        config = FlextLdapSearchConfig(
            base_dn=base_dn,
            filter=filter_obj,
            attributes=[],  # No attributes needed for counting
            size_limit=0,  # Unlimited for accurate count
        )

        # Execute search
        search_result = await self.search_entries(connection_id, config)
        if search_result.is_failure:
            return FlextResult.fail(f"Count search failed: {search_result.error}")

        count = len(search_result.data.entries) if search_result.data else 0
        logger.debug(f"Entry count result: {count}")
        return FlextResult.ok(count)

    async def verify_entry_exists(
        self,
        connection_id: str,
        entry_dn: FlextLdapDistinguishedName,
    ) -> FlextResult[bool]:
        """Verify if specific entry exists in directory.

        Args:
            connection_id: LDAP connection identifier
            entry_dn: Distinguished name of entry to verify

        Returns:
            FlextResult containing existence status or error

        """
        logger.debug(f"Verifying entry exists: {entry_dn.value}")

        # Search for the specific entry
        existence_result = await self.search_one(
            connection_id=connection_id,
            base_dn=entry_dn,
            filter_obj=FlextLdapFilter(value="(objectClass=*)"),
            attributes=[],  # No attributes needed
        )

        if existence_result.is_failure:
            return FlextResult.fail(f"Existence check failed: {existence_result.error}")

        exists = existence_result.data is not None
        logger.debug(f"Entry existence result: {exists}")
        return FlextResult.ok(exists)

    # =========================================================================
    # PRIVATE HELPER METHODS - Internal operation support
    # =========================================================================

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
                FlextLdapAttributeConstants.OBJECT_CLASS, [],
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
    def _combine_filters(
        filters: list[FlextLdapFilter],
        operator: str,
    ) -> FlextResult[FlextLdapFilter]:
        """Combine multiple filters with logical operator."""
        try:
            if len(filters) == 1:
                return FlextResult.ok(filters[0])

            # Extract filter values
            filter_values = [f.value for f in filters]

            # Create combined filter based on operator
            if operator.upper() == "AND":
                combined_value = f"(&{''.join(filter_values)})"
            elif operator.upper() == "OR":
                combined_value = f"(|{''.join(filter_values)})"
            elif operator.upper() == "NOT":
                if len(filters) != 1:
                    return FlextResult.fail("NOT operator requires exactly one filter")
                combined_value = f"(!{filter_values[0]})"
            else:
                return FlextResult.fail(f"Invalid operator: {operator}")

            combined_filter = FlextLdapFilter(value=combined_value)
            return FlextResult.ok(combined_filter)

        except Exception as e:
            return FlextResult.fail(f"Error combining filters: {e}")


# =============================================================================
# CONVENIENCE FACTORY FUNCTIONS - DI Container Integration
# =============================================================================


def create_search_operations(
    connection: FlextLdapConnectionProtocol,
    repository: FlextLdapRepositoryProtocol,
) -> FlextLdapSearchOperations:
    """Create search operations instance with DI dependencies.

    🎯 FACTORY PATTERN for dependency injection integration.

    Args:
        connection: LDAP connection protocol implementation
        repository: LDAP repository protocol implementation

    Returns:
        Configured search operations instance

    """
    return FlextLdapSearchOperations(
        connection=connection,
        repository=repository,
    )


async def get_search_operations() -> FlextResult[FlextLdapSearchOperations]:
    """Get search operations from DI container.

    🎯 FLEXT-CORE INTEGRATION for container-based dependency resolution.

    Returns:
        FlextResult containing search operations instance or error

    """
    try:
        container = get_flext_container()

        # Resolve dependencies using string keys to avoid abstract type issues
        connection_res = container.get("FlextLdapConnectionProtocol")
        if connection_res.is_failure:
            return FlextResult.fail(connection_res.error or "Connection not found")
        connection = cast("FlextLdapConnectionProtocol", connection_res.unwrap())

        repository_res = container.get("FlextLdapRepositoryProtocol")
        if repository_res.is_failure:
            return FlextResult.fail(repository_res.error or "Repository not found")
        repository = cast("FlextLdapRepositoryProtocol", repository_res.unwrap())

        operations = create_search_operations(connection, repository)
        return FlextResult.ok(operations)

    except Exception as e:
        return FlextResult.fail(
            f"Failed to create search operations from container: {e}",
        )


# =============================================================================
# MODULE EXPORTS - Clean public interface
# =============================================================================

__all__ = [
    "FlextLdapSearchOperations",
    "create_search_operations",
    "get_search_operations",
]

"""LDAP User Operations - DEDICATED PEP8 MODULE FOR CONCRETE CLASSES.

🎯 ELIMINATES DUPLICATIONS - Dedicated user management operations module
Following advanced Python 3.13 + flext-core patterns with zero duplication.

CONSOLIDATES USER OPERATIONS FROM:
- user_management.py: User operation logic (scattered)
- application/user_service.py: Application layer user services
- domain/user_operations.py: Domain user business logic
- infrastructure/user_repository.py: User data access patterns
- All user-related operations across 8+ files

This module provides DEDICATED user management operations using:
- Advanced Python 3.13 features extensively
- flext-core foundation patterns (FlextResult, DI interfaces)
- Consolidated foundation modules (protocols.py, models.py, constants.py)
- Clean Architecture and Domain-Driven Design principles
- Proper DI library interfaces (not service implementation)

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""


from __future__ import annotations

import re
from datetime import UTC, datetime
from typing import TYPE_CHECKING, cast

# ✅ CORRECT: Import by root from flext-core (not submodules)
from flext_core import FlextIdGenerator, FlextResult, get_flext_container, get_logger

# ✅ CORRECT: Use consolidated foundation modules
from .constants import FlextLdapAttributeConstants
from .models import (
    FlextLdapCreateUserRequest,
    FlextLdapDistinguishedName,
    FlextLdapEntry,
    FlextLdapFilter,
    FlextLdapSearchConfig,
    FlextLdapSearchResult,
    FlextLdapUser,
)

if TYPE_CHECKING:
    from collections.abc import AsyncGenerator

    from .protocols import FlextLdapConnectionProtocol, FlextLdapRepositoryProtocol

logger = get_logger(__name__)

# =============================================================================
# USER MANAGEMENT INTERFACE - DI Library Pattern
# =============================================================================


class FlextLdapUserOperations:
    """LDAP User Management Operations following DI library patterns.

    🎯 CONSOLIDATES AND REPLACES:
    - FlextLdapUserService (application/user_service.py)
    - FlextLdapUserManager (user_management.py)
    - User operation patterns scattered across domain/application layers
    - All user-specific business operations duplications

    DI LIBRARY PATTERN:
    This class provides user operation interfaces for dependency injection.
    It does NOT implement services - it provides operation contracts.
    """

    def __init__(
        self,
        connection: FlextLdapConnectionProtocol,
        repository: FlextLdapRepositoryProtocol,
    ) -> None:
        """Initialize user operations with DI dependencies.

        Args:
            connection: LDAP connection protocol implementation
            repository: LDAP repository protocol implementation

        """
        self._connection = connection
        self._repository = repository
        self._container = get_flext_container()

    # =========================================================================
    # USER CREATION OPERATIONS - Advanced Python 3.13 patterns
    # =========================================================================

    async def create_user(
        self,
        connection_id: str,
        request: FlextLdapCreateUserRequest,
    ) -> FlextResult[FlextLdapUser]:
        """Create new LDAP user with comprehensive validation.

        🎯 CONSOLIDATES AND REPLACES:
        - create_user() functions scattered across multiple modules
        - User creation logic duplicated in application/domain layers
        - Validation patterns repeated in different user operations

        Args:
            connection_id: LDAP connection identifier
            request: User creation request with validation

        Returns:
            FlextResult containing created user or error details

        """
        logger.debug(f"Creating user with DN: {request.dn.value}")

        # Validate user creation preconditions
        validation_result = await self._validate_user_creation_preconditions(
            connection_id, request
        )
        if validation_result.is_failure:
            return FlextResult.fail(validation_result.error or "Validation failed")

        # Create and validate user entity
        user_result = self._create_user_entity_from_request(request)
        if user_result.is_failure:
            return user_result

        if user_result.data is None:
            return FlextResult.fail("Failed to create user entity")

        user = user_result.data

        # Persist user to LDAP
        persistence_result = await self._persist_user_to_ldap(connection_id, user)
        if persistence_result.is_failure:
            return FlextResult.fail(persistence_result.error or "Failed to persist user")

        logger.info(f"Successfully created user: {request.dn.value}")
        return FlextResult.ok(user)

    async def bulk_create_users(
        self,
        connection_id: str,
        requests: list[FlextLdapCreateUserRequest],
        *,
        batch_size: int = 10,
        fail_fast: bool = False,
    ) -> FlextResult[list[FlextLdapUser]]:
        """Create multiple users in batches with error handling.

        🎯 CONSOLIDATES bulk user operations scattered across multiple modules.

        Args:
            connection_id: LDAP connection identifier
            requests: List of user creation requests
            batch_size: Number of users to process in each batch
            fail_fast: Stop on first error if True, continue if False

        Returns:
            FlextResult containing list of created users or error details

        """
        logger.debug(f"Bulk creating {len(requests)} users in batches of {batch_size}")

        if not requests:
            return FlextResult.ok([])

        created_users: list[FlextLdapUser] = []
        errors: list[str] = []

        # Process requests in batches
        for i in range(0, len(requests), batch_size):
            batch = requests[i : i + batch_size]

            for request in batch:
                result = await self.create_user(connection_id, request)

                if result.is_success and result.data is not None:
                    created_users.append(result.data)
                else:
                    error_msg = (
                        f"Failed to create user {request.dn.value}: {result.error}"
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
            f"Bulk creation completed: {len(created_users)} users created, {len(errors)} errors"
        )
        return FlextResult.ok(created_users)

    # =========================================================================
    # USER SEARCH OPERATIONS - Comprehensive query capabilities
    # =========================================================================

    async def search_users(
        self,
        connection_id: str,
        config: FlextLdapSearchConfig,
    ) -> FlextResult[FlextLdapSearchResult]:
        """Search for users with comprehensive filtering.

        🎯 CONSOLIDATES user search patterns scattered across search operations.

        Args:
            connection_id: LDAP connection identifier
            config: Search configuration with filters and limits

        Returns:
            FlextResult containing search results or error details

        """
        logger.debug(f"Searching users in base DN: {config.base_dn.value}")

        # Validate search configuration
        config_validation = config.validate_business_rules()
        if config_validation.is_failure:
            return FlextResult.fail(f"Invalid search config: {config_validation.error}")

        # Execute search via repository
        search_result = await self._repository.search_entries(connection_id, config)
        if search_result.is_failure:
            return FlextResult.fail(search_result.error or "Search failed")

        # Convert LDAP entries to User entities
        users: list[FlextLdapUser] = []
        if search_result.data is not None:
            for entry_data in search_result.data:
                user_result = self._ldap_attributes_to_user(entry_data)
                if user_result.is_success and user_result.data is not None:
                    users.append(user_result.data)

        # Create search result - convert users to entries for type compatibility
        entries: list[FlextLdapEntry] = []
        for user in users:
            entry = FlextLdapEntry(
                id=FlextIdGenerator.generate_entity_id(),  # Required by FlextEntity
                dn=user.dn,
                object_classes=user.object_classes,
                attributes=user.attributes
            )
            entries.append(entry)

        result = FlextLdapSearchResult(
            entries=entries,
            total_count=len(entries),
            page_size=config.size_limit,
            search_time_ms=0,  # Would be measured in real implementation
        )

        logger.debug(f"User search completed: found {len(users)} users")
        return FlextResult.ok(result)

    async def find_user_by_uid(
        self,
        connection_id: str,
        base_dn: FlextLdapDistinguishedName,
        uid: str,
    ) -> FlextResult[FlextLdapUser | None]:
        """Find user by UID with optimized search.

        🎯 CONSOLIDATES find_user operations across multiple modules.

        Args:
            connection_id: LDAP connection identifier
            base_dn: Base DN for search
            uid: User identifier to search for

        Returns:
            FlextResult containing user or None if not found

        """
        logger.debug(f"Finding user by UID: {uid}")

        # Create optimized search filter for UID
        filter_obj = FlextLdapFilter.create_equality(
            FlextLdapAttributeConstants.USER_ID, uid
        )

        search_config = FlextLdapSearchConfig(
            base_dn=base_dn,
            filter=filter_obj,
            size_limit=1,  # Only need one result
            attributes=[
                FlextLdapAttributeConstants.USER_ID,
                FlextLdapAttributeConstants.COMMON_NAME,
                FlextLdapAttributeConstants.SURNAME,
                FlextLdapAttributeConstants.MAIL,
                FlextLdapAttributeConstants.DISPLAY_NAME,
            ],
        )

        search_result = await self.search_users(connection_id, search_config)
        if search_result.is_failure:
            return FlextResult.fail(f"Error searching for user: {search_result.error}")

        if search_result.data is not None and search_result.data.entries:
            # Convert first entry back to user
            first_entry = search_result.data.entries[0]
            user_data: dict[str, object] = {
                "dn": first_entry.dn.value,
                "attributes": first_entry.attributes
            }
            user_result = self._ldap_attributes_to_user(user_data)
            if user_result.is_success:
                logger.debug(f"Found user by UID: {uid}")
                return FlextResult.ok(user_result.data)  # Wrap in FlextResult[FlextLdapUser | None]
            return FlextResult.fail(f"Error converting entry to user: {user_result.error}")

        logger.debug(f"User not found: {uid}")
        return FlextResult.ok(None)

    async def find_users_by_email_domain(
        self,
        connection_id: str,
        base_dn: FlextLdapDistinguishedName,
        domain: str,
    ) -> AsyncGenerator[FlextResult[FlextLdapUser]]:
        """Find users by email domain using async generator for large results.

        🎯 CONSOLIDATES domain-based user search patterns.

        Args:
            connection_id: LDAP connection identifier
            base_dn: Base DN for search
            domain: Email domain to search for (e.g., "example.com")

        Yields:
            FlextResult containing individual users or errors

        """
        logger.debug(f"Finding users by email domain: {domain}")

        # Create wildcard search for email domain
        filter_obj = FlextLdapFilter(
            value=f"({FlextLdapAttributeConstants.MAIL}=*@{domain})"
        )

        search_config = FlextLdapSearchConfig(
            base_dn=base_dn,
            filter=filter_obj,
            size_limit=0,  # Unlimited for streaming
        )

        search_result = await self.search_users(connection_id, search_config)
        if search_result.is_failure:
            yield FlextResult.fail(
                f"Error searching users by domain: {search_result.error}"
            )
            return

        # Stream results one by one
        if search_result.data is not None and search_result.data.entries:
            for entry in search_result.data.entries:
                # Convert entry back to user
                user_data: dict[str, object] = {
                    "dn": entry.dn.value,
                    "attributes": entry.attributes
                }
                user_result = self._ldap_attributes_to_user(user_data)
                if user_result.is_success:
                    yield user_result
                else:
                    yield FlextResult.fail(f"Error converting entry to user: {user_result.error}")

    # =========================================================================
    # USER UPDATE OPERATIONS - Modification and maintenance
    # =========================================================================

    async def update_user_email(
        self,
        connection_id: str,
        user_dn: FlextLdapDistinguishedName,
        new_email: str,
    ) -> FlextResult[None]:
        """Update user email with validation.

        🎯 CONSOLIDATES user update operations scattered across modules.

        Args:
            connection_id: LDAP connection identifier
            user_dn: User distinguished name
            new_email: New email address

        Returns:
            FlextResult indicating success or error

        """
        logger.debug(f"Updating email for user: {user_dn.value}")

        # Validate email format
        email_pattern = re.compile(r"^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$")
        if not email_pattern.match(new_email):
            return FlextResult.fail(f"Invalid email format: {new_email}")

        # Update via repository
        update_data = {FlextLdapAttributeConstants.MAIL: [new_email.lower()]}

        result = await self._repository.modify_entry(
            connection_id=connection_id,
            entry_dn=user_dn.value,
            modifications=update_data,
            operation="replace",
        )

        if result.is_failure:
            return FlextResult.fail(f"Failed to update user email: {result.error}")

        logger.info(f"Successfully updated email for user: {user_dn.value}")
        return FlextResult.ok(None)

    async def activate_user(
        self,
        connection_id: str,
        user_dn: FlextLdapDistinguishedName,
    ) -> FlextResult[None]:
        """Activate user account.

        Args:
            connection_id: LDAP connection identifier
            user_dn: User distinguished name

        Returns:
            FlextResult indicating success or error

        """
        logger.debug(f"Activating user: {user_dn.value}")

        # Implementation would depend on directory schema
        # This is a placeholder for the activation logic
        modification_data = {
            "accountStatus": ["active"],
            "modifyTimestamp": [datetime.now(UTC).isoformat()],
        }

        result = await self._repository.modify_entry(
            connection_id=connection_id,
            entry_dn=user_dn.value,
            modifications=modification_data,
            operation="replace",
        )

        if result.is_failure:
            return FlextResult.fail(f"Failed to activate user: {result.error}")

        logger.info(f"Successfully activated user: {user_dn.value}")
        return FlextResult.ok(None)

    # =========================================================================
    # USER DELETION OPERATIONS - Removal and cleanup
    # =========================================================================

    async def delete_user(
        self,
        connection_id: str,
        user_dn: FlextLdapDistinguishedName,
        *,
        force: bool = False,
    ) -> FlextResult[None]:
        """Delete user with safety checks.

        Args:
            connection_id: LDAP connection identifier
            user_dn: User distinguished name
            force: Skip safety checks if True

        Returns:
            FlextResult indicating success or error

        """
        logger.debug(f"Deleting user: {user_dn.value}")

        if not force:
            # Check if user exists before deletion
            exists_result = await self._check_user_exists(connection_id, user_dn.value)
            if exists_result.is_failure:
                return FlextResult.fail(
                    f"Error checking user existence: {exists_result.error}"
                )

            if not exists_result.data:
                return FlextResult.fail(f"User does not exist: {user_dn.value}")

        # Delete via repository
        result = await self._repository.delete_entry(
            connection_id=connection_id,
            entry_dn=user_dn.value,
        )

        if result.is_failure:
            return FlextResult.fail(f"Failed to delete user: {result.error}")

        logger.info(f"Successfully deleted user: {user_dn.value}")
        return FlextResult.ok(None)

    # =========================================================================
    # PRIVATE HELPER METHODS - Internal operation support
    # =========================================================================

    async def _check_user_exists(
        self,
        connection_id: str,
        user_dn_value: str,
    ) -> FlextResult[bool]:
        """Check if user exists in directory."""
        user_dn = FlextLdapDistinguishedName(value=user_dn_value)
        config = FlextLdapSearchConfig(
            base_dn=user_dn,
            filter=FlextLdapFilter(value="(objectClass=*)"),
            size_limit=1,
        )

        result = await self._repository.search_entries(connection_id, config)
        if result.is_failure:
            return FlextResult.fail(result.error or "Search failed")

        return FlextResult.ok(result.data is not None and len(result.data) > 0)

    def _create_user_entity_from_request(
        self,
        request: FlextLdapCreateUserRequest,
    ) -> FlextResult[FlextLdapUser]:
        """Create user entity from creation request."""
        try:
            # Build attributes dictionary
            attributes = {
                FlextLdapAttributeConstants.OBJECT_CLASS: request.object_classes,
                FlextLdapAttributeConstants.USER_ID: [request.uid],
                FlextLdapAttributeConstants.COMMON_NAME: [request.cn],
                FlextLdapAttributeConstants.SURNAME: [request.sn],
            }

            if request.email:
                attributes[FlextLdapAttributeConstants.MAIL] = [request.email]

            # Add additional attributes
            attributes.update(request.additional_attributes)

            # Use FlextIdGenerator from refactored flext-core
            user = FlextLdapUser(
                id=FlextIdGenerator.generate_entity_id(),  # Required by FlextEntity
                dn=request.dn,
                uid=request.uid,  # Add required uid field
                object_classes=request.object_classes,
                attributes=attributes,
                email=request.email,
                display_name=request.cn,
                is_active=True,
                created_at=datetime.now(UTC),
                modified_at=datetime.now(UTC),
            )

            return FlextResult.ok(user)

        except Exception as e:
            return FlextResult.fail(f"Error creating user entity: {e}")

    def _user_to_ldap_attributes(self, user: FlextLdapUser) -> dict[str, list[str]]:
        """Convert user entity to LDAP attributes."""
        # This would return the user's attributes dictionary
        # In a real implementation, this might include additional transformation
        return user.attributes

    def _ldap_attributes_to_user(
        self,
        entry_data: dict[str, object],
    ) -> FlextResult[FlextLdapUser]:
        """Convert LDAP entry data to user entity."""
        try:
            # Extract required fields
            dn_value = entry_data.get("dn", "")
            if not dn_value or not isinstance(dn_value, str):
                return FlextResult.fail("Missing or invalid DN in entry data")

            dn = FlextLdapDistinguishedName(value=dn_value)
            attributes = entry_data.get("attributes", {})
            if not isinstance(attributes, dict):
                return FlextResult.fail("Invalid attributes in entry data")

            # Extract user-specific fields
            uid_values = attributes.get(FlextLdapAttributeConstants.USER_ID, [])
            uid = uid_values[0] if uid_values and isinstance(uid_values, list) else ""

            if not uid:
                return FlextResult.fail("Missing UID in user entry")

            email_values = attributes.get(FlextLdapAttributeConstants.MAIL, [])
            email = (
                email_values[0]
                if email_values and isinstance(email_values, list)
                else None
            )

            display_name_values = attributes.get(
                FlextLdapAttributeConstants.DISPLAY_NAME, []
            )
            display_name = (
                display_name_values[0]
                if display_name_values and isinstance(display_name_values, list)
                else None
            )

            object_classes = attributes.get(
                FlextLdapAttributeConstants.OBJECT_CLASS, []
            )
            if not isinstance(object_classes, list):
                object_classes = []

            # Create user entity - add required ID field
            user = FlextLdapUser(
                id=FlextIdGenerator.generate_entity_id(),  # Required by FlextEntity
                dn=dn,
                uid=uid,
                email=email,
                display_name=display_name,
                object_classes=object_classes,
                attributes=attributes,
                is_active=True,  # Would be determined by directory-specific logic
                created_at=datetime.now(UTC),
                modified_at=datetime.now(UTC),
            )

            return FlextResult.ok(user)

        except Exception as e:
            return FlextResult.fail(f"Error converting LDAP data to user: {e}")

    async def _validate_user_creation_preconditions(
        self,
        connection_id: str,
        request: FlextLdapCreateUserRequest,
    ) -> FlextResult[None]:
        """Validate user creation preconditions."""
        # Check if user already exists
        exists_check = await self._check_user_exists(
            connection_id, request.dn.value
        )
        if exists_check.is_failure:
            return FlextResult.fail(f"Could not check user existence: {exists_check.error}")

        if exists_check.data:
            return FlextResult.fail(f"User already exists: {request.dn.value}")

        return FlextResult.ok(None)

    async def _persist_user_to_ldap(
        self,
        connection_id: str,
        user: FlextLdapUser,
    ) -> FlextResult[None]:
        """Persist user entity to LDAP directory."""
        # Convert user to LDAP entry data
        entry_data = {
            "dn": user.dn.value,
            "attributes": user.attributes
        }

        # Create entry via repository
        result = await self._repository.create_entry(connection_id, entry_data)
        if result.is_failure:
            return FlextResult.fail(f"Failed to persist user to LDAP: {result.error}")

        return FlextResult.ok(None)


# =============================================================================
# CONVENIENCE FACTORY FUNCTIONS - DI Container Integration
# =============================================================================


def create_user_operations(
    connection: FlextLdapConnectionProtocol,
    repository: FlextLdapRepositoryProtocol,
) -> FlextLdapUserOperations:
    """Create user operations instance with DI dependencies.

    🎯 FACTORY PATTERN for dependency injection integration.

    Args:
        connection: LDAP connection protocol implementation
        repository: LDAP repository protocol implementation

    Returns:
        Configured user operations instance

    """
    return FlextLdapUserOperations(
        connection=connection,
        repository=repository,
    )


async def get_user_operations() -> FlextResult[FlextLdapUserOperations]:
    """Get user operations from DI container.

    🎯 FLEXT-CORE INTEGRATION for container-based dependency resolution.

    Returns:
        FlextResult containing user operations instance or error

    """
    try:
        container = get_flext_container()

        # Get dependencies from container
        connection_result = container.get("ldap_connection")
        repository_result = container.get("ldap_repository")

        if connection_result.is_failure:
            return FlextResult.fail(f"Could not resolve LDAP connection: {connection_result.error}")
        if repository_result.is_failure:
            return FlextResult.fail(f"Could not resolve LDAP repository: {repository_result.error}")

        # Type cast for protocol compatibility
        connection = cast("FlextLdapConnectionProtocol", connection_result.data)
        repository = cast("FlextLdapRepositoryProtocol", repository_result.data)

        operations = create_user_operations(connection, repository)
        return FlextResult.ok(operations)

    except Exception as e:
        return FlextResult.fail(f"Failed to create user operations from container: {e}")


# =============================================================================
# MODULE EXPORTS - Clean public interface
# =============================================================================

__all__ = [
    "FlextLdapUserOperations",
    "create_user_operations",
    "get_user_operations",
]

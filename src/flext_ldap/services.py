"""LDAP Services - Single FlextLdapServices class following FLEXT patterns.

Single class inheriting from FlextServiceProcessor with all LDAP services
organized as internal classes and methods for complete backward compatibility.

Follows FLEXT architectural standards:
    - Single Responsibility: All LDAP services consolidated
    - Open/Closed: Extends FlextServiceProcessor without modification
    - Liskov Substitution: Can be used anywhere FlextServiceProcessor is expected
    - Interface Segregation: Organized by domain for specific access
    - Dependency Inversion: Depends on FlextServiceProcessor abstraction

Examples:
    Modern usage::

        from services import FlextLdapServices

        # Direct service usage
        service = FlextLdapServices()
        result = await service.create_user(request)

        # Domain-specific access
        user_result = await FlextLdapServices.User.create(request)
        group_result = await FlextLdapServices.Group.create(group)

    Legacy compatibility::

        from services import FlextLdapService

        service = FlextLdapService()  # Still works with deprecation warning

"""

# Import current service implementation for compatibility
from __future__ import annotations

from typing import TYPE_CHECKING, cast

from flext_core import FlextContainer, FlextLogger, FlextResult, FlextServiceProcessor

from flext_ldap.container import get_ldap_container
from flext_ldap.entities import (
    FlextLdapCreateUserRequest,
    FlextLdapGroup,
    FlextLdapSearchRequest,
    FlextLdapSearchResponse,
    FlextLdapUser,
)
from flext_ldap.repositories import FlextLdapRepositories
from flext_ldap.typings import LdapAttributeDict
from flext_ldap.value_objects import FlextLdapDistinguishedName, FlextLdapFilter

logger = FlextLogger(__name__)


# =============================================================================
# SINGLE FLEXT LDAP SERVICES CLASS - Inheriting from FlextServiceProcessor
# =============================================================================


if TYPE_CHECKING:
    _ServiceProcessorBase = FlextServiceProcessor[
        dict[str, object], object, dict[str, object]
    ]
else:
    _ServiceProcessorBase = FlextServiceProcessor


class FlextLdapServices(_ServiceProcessorBase):
    """Single FlextLdapServices class inheriting from FlextServiceProcessor.

    Consolidates ALL LDAP services into a single class following FLEXT patterns.
    Everything from the previous service definitions is now available as
    internal methods and classes with full backward compatibility.

    This class follows SOLID principles:
        - Single Responsibility: All LDAP services consolidated
        - Open/Closed: Extends FlextServiceProcessor without modification
        - Liskov Substitution: Can be used anywhere FlextServiceProcessor is expected
        - Interface Segregation: Organized by domain for specific access
        - Dependency Inversion: Depends on FlextServiceProcessor abstraction

    Examples:
        Direct usage::

            service = FlextLdapServices()
            result = await service.create_user(request)

        Domain-specific usage::

            result = await FlextLdapServices.User.create(request)
            groups = await FlextLdapServices.Group.search(filter)

    """

    def __init__(self, container: FlextContainer | None = None) -> None:
        """Initialize FlextLdapServices with flext-core dependency injection."""
        super().__init__()
        self._container = container or get_ldap_container()

    def process(self, request: dict[str, object]) -> FlextResult[object]:
        """Process the LDAP request and return domain object result.

        Args:
            request: LDAP operation request dictionary

        Returns:
            FlextResult containing processed domain object

        """
        # This is a base implementation - specific operations handled by methods
        return FlextResult[object].ok(request)

    def build(self, domain: object, *, correlation_id: str) -> dict[str, object]:
        """Build the final output from the domain object (pure function).

        Args:
            domain: Domain object from process method
            correlation_id: Correlation ID for tracking

        Returns:
            Built result dictionary

        """
        if isinstance(domain, dict):
            domain["correlation_id"] = correlation_id
            return domain
        return {"result": domain, "correlation_id": correlation_id}

    def _get_repository(self) -> FlextResult[object]:
        """Get LDAP repository from flext-core container."""
        repository_result = self._container.get("FlextLdapRepository")
        if not repository_result.is_success:
            logger.error(f"Failed to get LDAP repository: {repository_result.error}")
        return repository_result

    async def initialize(self) -> FlextResult[None]:
        """Initialize service and dependencies."""
        logger.info("LDAP service initializing")
        return FlextResult[None].ok(None)

    async def cleanup(self) -> FlextResult[None]:
        """Cleanup service resources."""
        logger.info("LDAP service cleaning up")
        # FlextContainer doesn't have cleanup method, just clear and return success
        self._container.clear()
        return FlextResult[None].ok(None)

    # =========================================================================
    # USER OPERATIONS - Consolidated user management
    # =========================================================================

    async def create_user(
        self,
        request: FlextLdapCreateUserRequest,
    ) -> FlextResult[FlextLdapUser]:
        """Create new user in LDAP directory.

        Args:
            request: User creation request with all required attributes

        Returns:
            FlextResult containing created user or error

        """
        user_entity = request.to_user_entity()

        # Validate user business rules
        validation_result = user_entity.validate_business_rules()
        if not validation_result.is_success:
            return FlextResult[FlextLdapUser].fail(
                f"User validation failed: {validation_result.error}",
            )

        # Save user via repository from flext-core container
        repository_result = self._get_repository()
        if not repository_result.is_success:
            return FlextResult[FlextLdapUser].fail(
                f"Repository access failed: {repository_result.error}"
            )

        # Type cast repository to correct interface
        repository = cast("FlextLdapRepositories.Repository", repository_result.value)
        save_result = await repository.save_async(user_entity)

        if not save_result.is_success:
            return FlextResult[FlextLdapUser].fail(save_result.error or "Save failed")

        logger.info(
            "LDAP user created successfully",
            extra={
                "operation": "create_user",
                "dn": user_entity.dn,
                "uid": user_entity.uid,
                "object_classes": user_entity.object_classes,
                "execution_context": "FlextLdapServices.create_user",
            },
        )
        return FlextResult[FlextLdapUser].ok(user_entity)

    async def get_user(self, dn: str) -> FlextResult[FlextLdapUser | None]:
        """Get user by distinguished name.

        Args:
            dn: Distinguished name of the user

        Returns:
            FlextResult containing user or None if not found

        """
        repository_result = self._get_repository()
        if not repository_result.is_success:
            return FlextResult[FlextLdapUser | None].fail(
                f"Repository access failed: {repository_result.error}"
            )

        # Type cast repository to correct interface
        repository = cast("FlextLdapRepositories.Repository", repository_result.value)
        entry_result = await repository.find_by_dn(dn)

        if not entry_result.is_success:
            return FlextResult[FlextLdapUser | None].fail(
                entry_result.error or "User lookup failed"
            )

        if not entry_result.value:
            return FlextResult[FlextLdapUser | None].ok(None)

        # Convert entry to user - entry is already FlextLdapEntry, extract user fields
        entry = entry_result.value
        user_entity = FlextLdapUser(
            id=entry.id,
            dn=entry.dn,
            object_classes=entry.object_classes,
            attributes=entry.attributes,
            uid=str(entry.get_attribute("uid") or "unknown"),
            cn=str(entry.get_attribute("cn")) if entry.get_attribute("cn") else None,
            sn=str(entry.get_attribute("sn")) if entry.get_attribute("sn") else None,
            given_name=str(entry.get_attribute("givenName"))
            if entry.get_attribute("givenName")
            else None,
            mail=str(entry.get_attribute("mail"))
            if entry.get_attribute("mail")
            else None,
            user_password=str(entry.get_attribute("userPassword"))
            if entry.get_attribute("userPassword")
            else None,
            created_at=entry.created_at,
            modified_at=entry.modified_at,
        )
        return FlextResult[FlextLdapUser | None].ok(user_entity)

    async def update_user(
        self,
        dn: str,
        updates: LdapAttributeDict,
    ) -> FlextResult[FlextLdapUser]:
        """Update user attributes.

        Args:
            dn: Distinguished name of the user
            updates: Dictionary of attributes to update

        Returns:
            FlextResult containing updated user

        """
        repository_result = self._get_repository()
        if not repository_result.is_success:
            return FlextResult[FlextLdapUser].fail(
                f"Repository access failed: {repository_result.error}"
            )

        # Type cast repository to correct interface
        repository = cast("FlextLdapRepositories.Repository", repository_result.value)
        update_result = await repository.update(dn, updates)

        if not update_result.is_success:
            return FlextResult[FlextLdapUser].fail(
                update_result.error or "User update failed"
            )

        # Get updated user - handle potential None return
        user_result = await self.get_user(dn)
        if user_result.value is None:
            return FlextResult[FlextLdapUser].fail("Updated user not found")
        return FlextResult[FlextLdapUser].ok(user_result.value)

    async def delete_user(self, dn: str) -> FlextResult[bool]:
        """Delete user from directory.

        Args:
            dn: Distinguished name of the user

        Returns:
            FlextResult containing success status

        """
        repository_result = self._get_repository()
        if not repository_result.is_success:
            return FlextResult[bool].fail(
                f"Repository access failed: {repository_result.error}"
            )

        # Type cast repository to correct interface
        repository = cast("FlextLdapRepositories.Repository", repository_result.value)
        delete_result = await repository.delete_async(dn)

        if not delete_result.is_success:
            return FlextResult[bool].fail(delete_result.error or "User deletion failed")

        logger.info(
            "LDAP user deleted successfully",
            extra={
                "operation": "delete_user",
                "dn": dn,
                "execution_context": "FlextLdapServices.delete_user",
            },
        )
        success = True
        return FlextResult[bool].ok(success)

    # =========================================================================
    # GROUP OPERATIONS - Consolidated group management
    # =========================================================================

    async def create_group(self, group: FlextLdapGroup) -> FlextResult[FlextLdapGroup]:
        """Create new group in LDAP directory.

        Args:
            group: Group entity to create

        Returns:
            FlextResult containing created group

        """
        # Validate group business rules
        validation_result = group.validate_business_rules()
        if not validation_result.is_success:
            return FlextResult[FlextLdapGroup].fail(
                f"Group validation failed: {validation_result.error}",
            )

        # Save group via repository
        repository_result = self._get_repository()
        if not repository_result.is_success:
            return FlextResult[FlextLdapGroup].fail(
                f"Repository access failed: {repository_result.error}"
            )

        # Type cast repository to correct interface
        repository = cast("FlextLdapRepositories.Repository", repository_result.value)
        save_result = await repository.save_async(group)

        if not save_result.is_success:
            return FlextResult[FlextLdapGroup].fail(
                save_result.error or "Group save failed"
            )

        logger.info(
            "LDAP group created successfully",
            extra={
                "operation": "create_group",
                "dn": group.dn,
                "cn": group.cn,
                "execution_context": "FlextLdapServices.create_group",
            },
        )
        return FlextResult[FlextLdapGroup].ok(group)

    async def update_group(
        self, dn: str, attributes: LdapAttributeDict
    ) -> FlextResult[None]:
        """Update group attributes."""
        repository_result = self._get_repository()
        if not repository_result.is_success:
            return FlextResult[None].fail(
                f"Repository access failed: {repository_result.error}"
            )

        # Type cast repository to correct interface
        repository = cast("FlextLdapRepositories.Repository", repository_result.value)
        result = await repository.update(dn, attributes)
        if not result.is_success:
            return FlextResult[None].fail(result.error or "Update failed")
        return FlextResult[None].ok(None)

    async def delete_group(self, dn: str) -> FlextResult[None]:
        """Delete group by DN."""
        repository_result = self._get_repository()
        if not repository_result.is_success:
            return FlextResult[None].fail(
                f"Repository access failed: {repository_result.error}"
            )

        # Type cast repository to correct interface
        repository = cast("FlextLdapRepositories.Repository", repository_result.value)
        result = await repository.delete_async(dn)
        if not result.is_success:
            return FlextResult[None].fail(result.error or "Delete failed")
        return FlextResult[None].ok(None)

    async def add_member(self, group_dn: str, member_dn: str) -> FlextResult[None]:
        """Add member to group."""
        repository_result = self._get_repository()
        if not repository_result.is_success:
            return FlextResult[None].fail(
                f"Repository access failed: {repository_result.error}"
            )

        # Type cast repository to correct interface
        base_repository = cast(
            "FlextLdapRepositories.Repository", repository_result.value
        )
        group_repository = FlextLdapRepositories.GroupRepository(base_repository)
        result = await group_repository.add_member_to_group(group_dn, member_dn)
        if not result.is_success:
            return FlextResult[None].fail(result.error or "Add member failed")
        return FlextResult[None].ok(None)

    async def remove_member(self, group_dn: str, member_dn: str) -> FlextResult[None]:
        """Remove member from group."""
        # Get current members
        repository_result = self._get_repository()
        if not repository_result.is_success:
            return FlextResult[None].fail(
                f"Repository access failed: {repository_result.error}"
            )

        # Type cast repository to correct interface
        base_repository = cast(
            "FlextLdapRepositories.Repository", repository_result.value
        )
        group_repository = FlextLdapRepositories.GroupRepository(base_repository)
        members_result = await group_repository.get_group_members(group_dn)
        if not members_result.is_success:
            return FlextResult[None].fail(
                f"Failed to get members: {members_result.error}"
            )

        current_members = members_result.value
        if member_dn not in current_members:
            return FlextResult[None].fail(f"Member {member_dn} not found in group")

        # Remove member and update
        updated_members = [m for m in current_members if m != member_dn]
        attributes: LdapAttributeDict = {"member": updated_members}
        result = await base_repository.update(group_dn, attributes)
        if not result.is_success:
            return FlextResult[None].fail(result.error or "Remove member failed")
        return FlextResult[None].ok(None)

    async def get_members(self, group_dn: str) -> FlextResult[list[str]]:
        """Get group members."""
        repository_result = self._get_repository()
        if not repository_result.is_success:
            return FlextResult[list[str]].fail(
                f"Repository access failed: {repository_result.error}"
            )

        # Type cast repository to correct interface
        base_repository = cast(
            "FlextLdapRepositories.Repository", repository_result.value
        )
        group_repository = FlextLdapRepositories.GroupRepository(base_repository)
        return await group_repository.get_group_members(group_dn)

    # Validation methods needed by API
    def validate_dn(self, dn: str) -> FlextResult[None]:
        """Validate DN format."""
        result = FlextLdapDistinguishedName.create(dn)
        if result.is_success:
            return FlextResult[None].ok(None)
        return FlextResult[None].fail(result.error or "Invalid DN")

    def validate_filter(self, filter_str: str) -> FlextResult[None]:
        """Validate LDAP filter format."""
        result = FlextLdapFilter.create(filter_str)
        if result.is_success:
            return FlextResult[None].ok(None)
        return FlextResult[None].fail(result.error or "Invalid filter")

    # =========================================================================
    # SEARCH OPERATIONS - Consolidated search functionality
    # =========================================================================

    async def search(
        self, request: FlextLdapSearchRequest
    ) -> FlextResult[FlextLdapSearchResponse]:
        """Perform LDAP search operation.

        Args:
            request: Search request with filters and scope

        Returns:
            FlextResult containing search response

        """
        repository_result = self._get_repository()
        if not repository_result.is_success:
            return FlextResult[FlextLdapSearchResponse].fail(
                f"Repository access failed: {repository_result.error}"
            )

        # Type cast repository to correct interface
        repository = cast("FlextLdapRepositories.Repository", repository_result.value)
        search_result = await repository.search(request)

        if not search_result.is_success:
            return FlextResult[FlextLdapSearchResponse].fail(
                search_result.error or "Search failed"
            )

        return FlextResult[FlextLdapSearchResponse].ok(search_result.value)

    # =========================================================================
    # DOMAIN-SPECIFIC STATIC CLASSES - Hierarchical organization
    # =========================================================================

    class User:
        """User-specific operations with static methods."""

        @staticmethod
        async def create(
            request: FlextLdapCreateUserRequest,
        ) -> FlextResult[FlextLdapUser]:
            """Create user using default service instance."""
            service = FlextLdapServices()
            return await service.create_user(request)

        @staticmethod
        async def get(dn: str) -> FlextResult[FlextLdapUser | None]:
            """Get user using default service instance."""
            service = FlextLdapServices()
            return await service.get_user(dn)

        @staticmethod
        async def update(
            dn: str, updates: LdapAttributeDict
        ) -> FlextResult[FlextLdapUser]:
            """Update user using default service instance."""
            service = FlextLdapServices()
            return await service.update_user(dn, updates)

        @staticmethod
        async def delete(dn: str) -> FlextResult[bool]:
            """Delete user using default service instance."""
            service = FlextLdapServices()
            return await service.delete_user(dn)

    class Group:
        """Group-specific operations with static methods."""

        @staticmethod
        async def create(group: FlextLdapGroup) -> FlextResult[FlextLdapGroup]:
            """Create group using default service instance."""
            service = FlextLdapServices()
            return await service.create_group(group)

    class Search:
        """Search-specific operations with static methods."""

        @staticmethod
        async def execute(
            request: FlextLdapSearchRequest,
        ) -> FlextResult[FlextLdapSearchResponse]:
            """Execute search using default service instance."""
            service = FlextLdapServices()
            return await service.search(request)


# =============================================================================
# LEGACY COMPATIBILITY ALIASES
# =============================================================================

# Export legacy alias
FlextLdapService = FlextLdapServices


# =============================================================================
# MODULE EXPORTS
# =============================================================================

__all__ = [
    # Legacy service (deprecated but still exported)
    "FlextLdapService",
    # Main class
    "FlextLdapServices",
]

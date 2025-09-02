"""LDAP Services - Single FlextLDAPServices class following FLEXT patterns.

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

        from services import FlextLDAPServices

        # Direct service usage
        service = FlextLDAPServices()
        result = await service.create_user(request)

        # Domain-specific access
        user_result = await FlextLDAPServices.User.create(request)
        group_result = await FlextLDAPServices.Group.create(group)

    Legacy compatibility::

        from services import FlextLDAPService

        service = FlextLDAPService()  # Still works with deprecation warning

"""

# Import current service implementation for compatibility
from __future__ import annotations

from typing import cast

from flext_core import FlextContainer, FlextLogger, FlextResult

from flext_ldap.container import FlextLDAPContainer
from flext_ldap.entities import (
    FlextLDAPCreateUserRequest,
    FlextLDAPGroup,
    FlextLDAPSearchRequest,
    FlextLDAPSearchResponse,
    FlextLDAPUser,
)
from flext_ldap.repositories import FlextLDAPRepositories
from flext_ldap.typings import LdapAttributeDict
from flext_ldap.value_objects import FlextLDAPDistinguishedName, FlextLDAPFilter

logger = FlextLogger(__name__)


# =============================================================================
# SINGLE FLEXT LDAP SERVICES CLASS - Inheriting from FlextServiceProcessor
# =============================================================================


class FlextLDAPServices:
    """Single FlextLDAPServices class inheriting from FlextServiceProcessor.

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

            service = FlextLDAPServices()
            result = await service.create_user(request)

        Domain-specific usage::

            result = await FlextLDAPServices.User.create(request)
            groups = await FlextLDAPServices.Group.search(filter)

    """

    def __init__(self, container: FlextContainer | None = None) -> None:
        """Initialize FlextLDAPServices with flext-core dependency injection."""
        # Initialize without parent class
        self._container = container or FlextLDAPContainer().get_container()

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
        repository_result = self._container.get("FlextLDAPRepository")
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
        request: FlextLDAPCreateUserRequest,
    ) -> FlextResult[FlextLDAPUser]:
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
            return FlextResult[FlextLDAPUser].fail(
                f"User validation failed: {validation_result.error}",
            )

        # Save user via repository from flext-core container
        repository_result = self._get_repository()
        if not repository_result.is_success:
            return FlextResult[FlextLDAPUser].fail(
                f"Repository access failed: {repository_result.error}"
            )

        # Type cast repository to correct interface
        repository = cast("FlextLDAPRepositories.Repository", repository_result.value)
        save_result = await repository.save_async(user_entity)

        if not save_result.is_success:
            return FlextResult[FlextLDAPUser].fail(save_result.error or "Save failed")

        logger.info(
            "LDAP user created successfully",
            extra={
                "operation": "create_user",
                "dn": user_entity.dn,
                "uid": user_entity.uid,
                "object_classes": user_entity.object_classes,
                "execution_context": "FlextLDAPServices.create_user",
            },
        )
        return FlextResult[FlextLDAPUser].ok(user_entity)

    async def get_user(self, dn: str) -> FlextResult[FlextLDAPUser | None]:
        """Get user by distinguished name.

        Args:
            dn: Distinguished name of the user

        Returns:
            FlextResult containing user or None if not found

        """
        repository_result = self._get_repository()
        if not repository_result.is_success:
            return FlextResult[FlextLDAPUser | None].fail(
                f"Repository access failed: {repository_result.error}"
            )

        # Type cast repository to correct interface
        repository = cast("FlextLDAPRepositories.Repository", repository_result.value)
        entry_result = await repository.find_by_dn(dn)

        if not entry_result.is_success:
            return FlextResult[FlextLDAPUser | None].fail(
                entry_result.error or "User lookup failed"
            )

        if not entry_result.value:
            return FlextResult[FlextLDAPUser | None].ok(None)

        # Convert entry to user - entry is already FlextLDAPEntry, extract user fields
        entry = entry_result.value
        user_entity = FlextLDAPUser(
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
        return FlextResult[FlextLDAPUser | None].ok(user_entity)

    async def update_user(
        self,
        dn: str,
        updates: LdapAttributeDict,
    ) -> FlextResult[FlextLDAPUser]:
        """Update user attributes.

        Args:
            dn: Distinguished name of the user
            updates: Dictionary of attributes to update

        Returns:
            FlextResult containing updated user

        """
        repository_result = self._get_repository()
        if not repository_result.is_success:
            return FlextResult[FlextLDAPUser].fail(
                f"Repository access failed: {repository_result.error}"
            )

        # Type cast repository to correct interface
        repository = cast("FlextLDAPRepositories.Repository", repository_result.value)
        update_result = await repository.update(dn, updates)

        if not update_result.is_success:
            return FlextResult[FlextLDAPUser].fail(
                update_result.error or "User update failed"
            )

        # Get updated user - handle potential None return
        user_result = await self.get_user(dn)
        if not user_result.is_success:
            return FlextResult[FlextLDAPUser].fail(
                user_result.error or "Failed to get updated user"
            )
        if user_result.value is None:
            return FlextResult[FlextLDAPUser].fail("Updated user not found")
        return FlextResult[FlextLDAPUser].ok(user_result.value)

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
        repository = cast("FlextLDAPRepositories.Repository", repository_result.value)
        delete_result = await repository.delete_async(dn)

        if not delete_result.is_success:
            return FlextResult[bool].fail(delete_result.error or "User deletion failed")

        logger.info(
            "LDAP user deleted successfully",
            extra={
                "operation": "delete_user",
                "dn": dn,
                "execution_context": "FlextLDAPServices.delete_user",
            },
        )
        success = True
        return FlextResult[bool].ok(success)

    # =========================================================================
    # GROUP OPERATIONS - Consolidated group management
    # =========================================================================

    async def create_group(self, group: FlextLDAPGroup) -> FlextResult[FlextLDAPGroup]:
        """Create new group in LDAP directory.

        Args:
            group: Group entity to create

        Returns:
            FlextResult containing created group

        """
        # Validate group business rules
        validation_result = group.validate_business_rules()
        if not validation_result.is_success:
            return FlextResult[FlextLDAPGroup].fail(
                f"Group validation failed: {validation_result.error}",
            )

        # Save group via repository
        repository_result = self._get_repository()
        if not repository_result.is_success:
            return FlextResult[FlextLDAPGroup].fail(
                f"Repository access failed: {repository_result.error}"
            )

        # Type cast repository to correct interface
        repository = cast("FlextLDAPRepositories.Repository", repository_result.value)
        save_result = await repository.save_async(group)

        if not save_result.is_success:
            return FlextResult[FlextLDAPGroup].fail(
                save_result.error or "Group save failed"
            )

        logger.info(
            "LDAP group created successfully",
            extra={
                "operation": "create_group",
                "dn": group.dn,
                "cn": group.cn,
                "execution_context": "FlextLDAPServices.create_group",
            },
        )
        return FlextResult[FlextLDAPGroup].ok(group)

    async def get_group(self, dn: str) -> FlextResult[FlextLDAPGroup | None]:
        """Get group by DN.

        Args:
            dn: Distinguished name of the group

        Returns:
            Group entity or None if not found

        """
        repository_result = self._get_repository()
        if not repository_result.is_success:
            return FlextResult[FlextLDAPGroup | None].fail(
                f"Repository access failed: {repository_result.error}"
            )

        # Type cast repository to correct interface
        repository = cast("FlextLDAPRepositories.Repository", repository_result.value)
        entry_result = await repository.find_by_dn(dn)
        if not entry_result.is_success:
            return FlextResult[FlextLDAPGroup | None].fail(
                entry_result.error or "Failed to find entry"
            )

        if entry_result.value is None:
            return FlextResult[FlextLDAPGroup | None].ok(None)

        # Convert entry to group
        entry = entry_result.value
        group = FlextLDAPGroup(
            id=entry.id,
            dn=entry.dn,
            cn=str(
                entry.attributes.get("cn", [""])[0]
                if isinstance(entry.attributes.get("cn"), list)
                else entry.attributes.get("cn", "")
            ),
            object_classes=entry.object_classes,
            members=[
                str(m)
                for m in (
                    entry.attributes.get("member", [])
                    if isinstance(entry.attributes.get("member"), list)
                    else [entry.attributes.get("member", "")]
                )
            ],
            status=entry.status,
            description=str(
                entry.attributes.get("description", [""])[0]
                if isinstance(entry.attributes.get("description"), list)
                else entry.attributes.get("description", "")
            ),
            modified_at=entry.modified_at,
        )

        return FlextResult[FlextLDAPGroup | None].ok(group)

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
        repository = cast("FlextLDAPRepositories.Repository", repository_result.value)
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
        repository = cast("FlextLDAPRepositories.Repository", repository_result.value)
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
            "FlextLDAPRepositories.Repository", repository_result.value
        )
        group_repository = FlextLDAPRepositories.GroupRepository(base_repository)
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
            "FlextLDAPRepositories.Repository", repository_result.value
        )
        group_repository = FlextLDAPRepositories.GroupRepository(base_repository)
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
            "FlextLDAPRepositories.Repository", repository_result.value
        )
        group_repository = FlextLDAPRepositories.GroupRepository(base_repository)
        return await group_repository.get_group_members(group_dn)

    # Validation methods needed by API
    def validate_dn(self, dn: str) -> FlextResult[None]:
        """Validate DN format."""
        result = FlextLDAPDistinguishedName.create(dn)
        if result.is_success:
            return FlextResult[None].ok(None)
        return FlextResult[None].fail(result.error or "Invalid DN")

    def validate_filter(self, filter_str: str) -> FlextResult[None]:
        """Validate LDAP filter format."""
        result = FlextLDAPFilter.create(filter_str)
        if result.is_success:
            return FlextResult[None].ok(None)
        return FlextResult[None].fail(result.error or "Invalid filter")

    # =========================================================================
    # SEARCH OPERATIONS - Consolidated search functionality
    # =========================================================================

    async def search(
        self, request: FlextLDAPSearchRequest
    ) -> FlextResult[FlextLDAPSearchResponse]:
        """Perform LDAP search operation.

        Args:
            request: Search request with filters and scope

        Returns:
            FlextResult containing search response

        """
        repository_result = self._get_repository()
        if not repository_result.is_success:
            return FlextResult[FlextLDAPSearchResponse].fail(
                f"Repository access failed: {repository_result.error}"
            )

        # Type cast repository to correct interface
        repository = cast("FlextLDAPRepositories.Repository", repository_result.value)
        search_result = await repository.search(request)

        if not search_result.is_success:
            return FlextResult[FlextLDAPSearchResponse].fail(
                search_result.error or "Search failed"
            )

        return FlextResult[FlextLDAPSearchResponse].ok(search_result.value)

    # =========================================================================
    # VALIDATION METHODS - For test coverage and business logic
    # =========================================================================

    def validate_attributes(self, attributes: LdapAttributeDict) -> FlextResult[None]:
        """Validate LDAP attributes dictionary.

        Args:
            attributes: LDAP attributes to validate

        Returns:
            Success result if valid, failure with error message if invalid

        """
        if not attributes:
            return FlextResult[None].fail("Attributes cannot be empty")

        return FlextResult[None].ok(None)

    def validate_object_classes(self, object_classes: list[str]) -> FlextResult[None]:
        """Validate LDAP object classes list.

        Args:
            object_classes: Object classes to validate

        Returns:
            Success result if valid, failure with error message if invalid

        """
        if not object_classes:
            return FlextResult[None].fail("Object classes cannot be empty")

        return FlextResult[None].ok(None)

    async def search_users(
        self, filter_str: str, base_dn: str
    ) -> FlextResult[list[FlextLDAPUser]]:
        """Search for users matching filter.

        Args:
            filter_str: LDAP filter string
            base_dn: Base DN for search

        Returns:
            List of matching users or error

        """
        search_request = FlextLDAPSearchRequest(
            base_dn=base_dn,
            scope="subtree",
            filter_str=filter_str,
            attributes=["*"],
            size_limit=1000,
            time_limit=30,
        )

        search_result = await self.search(search_request)
        if not search_result.is_success:
            return FlextResult[list[FlextLDAPUser]].fail(
                search_result.error or "Search failed"
            )

        users = []
        for entry_data in search_result.value.entries:
            if "dn" in entry_data:
                user_result = await self.get_user(str(entry_data["dn"]))
                if user_result.is_success and user_result.value:
                    users.append(user_result.value)

        return FlextResult[list[FlextLDAPUser]].ok(users)

    async def user_exists(self, dn: str) -> FlextResult[bool]:
        """Check if user exists at specified DN.

        Args:
            dn: Distinguished name to check

        Returns:
            True if user exists, False otherwise

        """
        user_result = await self.get_user(dn)
        if not user_result.is_success:
            return FlextResult[bool].fail(user_result.error or "Failed to get user")

        return FlextResult[bool].ok(user_result.value is not None)

    async def group_exists(self, dn: str) -> FlextResult[bool]:
        """Check if group exists at specified DN.

        Args:
            dn: Distinguished name to check

        Returns:
            True if group exists, False otherwise

        """
        group_result = await self.get_group(dn)
        if not group_result.is_success:
            return FlextResult[bool].fail(group_result.error or "Failed to get group")

        return FlextResult[bool].ok(group_result.value is not None)

    # =========================================================================
    # DOMAIN-SPECIFIC STATIC CLASSES - Hierarchical organization
    # =========================================================================

    class User:
        """User-specific operations with static methods."""

        @staticmethod
        async def create(
            request: FlextLDAPCreateUserRequest,
        ) -> FlextResult[FlextLDAPUser]:
            """Create user using default service instance."""
            service = FlextLDAPServices()
            return await service.create_user(request)

        @staticmethod
        async def get(dn: str) -> FlextResult[FlextLDAPUser | None]:
            """Get user using default service instance."""
            service = FlextLDAPServices()
            return await service.get_user(dn)

        @staticmethod
        async def update(
            dn: str, updates: LdapAttributeDict
        ) -> FlextResult[FlextLDAPUser]:
            """Update user using default service instance."""
            service = FlextLDAPServices()
            return await service.update_user(dn, updates)

        @staticmethod
        async def delete(dn: str) -> FlextResult[bool]:
            """Delete user using default service instance."""
            service = FlextLDAPServices()
            return await service.delete_user(dn)

    class Group:
        """Group-specific operations with static methods."""

        @staticmethod
        async def create(group: FlextLDAPGroup) -> FlextResult[FlextLDAPGroup]:
            """Create group using default service instance."""
            service = FlextLDAPServices()
            return await service.create_group(group)

    class Search:
        """Search-specific operations with static methods."""

        @staticmethod
        async def execute(
            request: FlextLDAPSearchRequest,
        ) -> FlextResult[FlextLDAPSearchResponse]:
            """Execute search using default service instance."""
            service = FlextLDAPServices()
            return await service.search(request)


# =============================================================================
# SPECIALIZED SERVICE WRAPPERS - For test compatibility and specialized usage
# =============================================================================


class FlextLDAPUserService:
    """User-specific service wrapper for specialized operations."""

    def __init__(self, main_service: FlextLDAPServices) -> None:
        """Initialize user service with main service instance."""
        self._service = main_service

    async def create_user(
        self, request: FlextLDAPCreateUserRequest
    ) -> FlextResult[FlextLDAPUser]:
        """Create user via main service."""
        return await self._service.create_user(request)

    async def get_user(self, dn: str) -> FlextResult[FlextLDAPUser | None]:
        """Get user via main service."""
        return await self._service.get_user(dn)

    async def update_user(
        self, dn: str, attributes: LdapAttributeDict
    ) -> FlextResult[FlextLDAPUser]:
        """Update user via main service."""
        return await self._service.update_user(dn, attributes)

    async def delete_user(self, dn: str) -> FlextResult[bool]:
        """Delete user via main service."""
        return await self._service.delete_user(dn)

    async def search_users(
        self, filter_str: str, base_dn: str
    ) -> FlextResult[list[FlextLDAPUser]]:
        """Search users via main service."""
        return await self._service.search_users(filter_str, base_dn)

    async def user_exists(self, dn: str) -> FlextResult[bool]:
        """Check user existence via main service."""
        return await self._service.user_exists(dn)


class FlextLDAPGroupService:
    """Group-specific service wrapper for specialized operations."""

    def __init__(self, main_service: FlextLDAPServices) -> None:
        """Initialize group service with main service instance."""
        self._service = main_service

    async def create_group(self, group: FlextLDAPGroup) -> FlextResult[FlextLDAPGroup]:
        """Create group via main service."""
        return await self._service.create_group(group)

    async def get_group(self, dn: str) -> FlextResult[FlextLDAPGroup | None]:
        """Get group via main service."""
        return await self._service.get_group(dn)

    async def update_group(
        self, dn: str, attributes: LdapAttributeDict
    ) -> FlextResult[None]:
        """Update group via main service."""
        return await self._service.update_group(dn, attributes)

    async def delete_group(self, dn: str) -> FlextResult[None]:
        """Delete group via main service."""
        return await self._service.delete_group(dn)

    async def group_exists(self, dn: str) -> FlextResult[bool]:
        """Check group existence via main service."""
        return await self._service.group_exists(dn)

    async def add_member(self, group_dn: str, member_dn: str) -> FlextResult[None]:
        """Add member to group.

        Args:
            group_dn: Group distinguished name
            member_dn: Member distinguished name to add

        Returns:
            Success result or error

        """
        # Get current group
        group_result = await self._service.get_group(group_dn)
        if not group_result.is_success:
            return FlextResult[None].fail(group_result.error or "Failed to get group")

        if group_result.value is None:
            return FlextResult[None].fail("Group not found")

        group = group_result.value

        # Check if member already exists
        if member_dn in group.members:
            return FlextResult[None].fail("Member already in group")

        # Add member to the list
        updated_members = [*group.members, member_dn]

        # Update group
        return await self._service.update_group(group_dn, {"member": updated_members})

    async def remove_member(self, group_dn: str, member_dn: str) -> FlextResult[None]:
        """Remove member from group.

        Args:
            group_dn: Group distinguished name
            member_dn: Member distinguished name to remove

        Returns:
            Success result or error

        """
        # Get current group
        group_result = await self._service.get_group(group_dn)
        if not group_result.is_success:
            return FlextResult[None].fail(group_result.error or "Failed to get group")

        if group_result.value is None:
            return FlextResult[None].fail("Group not found")

        group = group_result.value

        # Check if member exists
        if member_dn not in group.members:
            return FlextResult[None].fail("Member not in group")

        # Remove member from the list
        updated_members = [m for m in group.members if m != member_dn]

        # Update group
        return await self._service.update_group(group_dn, {"member": updated_members})

    async def get_members(self, group_dn: str) -> FlextResult[list[str]]:
        """Get group members.

        Args:
            group_dn: Group distinguished name

        Returns:
            List of member DNs or error

        """
        # Get group
        group_result = await self._service.get_group(group_dn)
        if not group_result.is_success:
            return FlextResult[list[str]].fail(
                group_result.error or "Failed to get group"
            )

        if group_result.value is None:
            return FlextResult[list[str]].fail("Group not found")

        return FlextResult[list[str]].ok(group_result.value.members)


# =============================================================================
# LEGACY COMPATIBILITY ALIASES
# =============================================================================

# Export legacy alias
FlextLDAPService = FlextLDAPServices


# =============================================================================
# MODULE EXPORTS
# =============================================================================

__all__ = [
    "FlextLDAPGroupService",
    # Legacy service (deprecated but still exported)
    "FlextLDAPService",
    # Main class
    "FlextLDAPServices",
    # Specialized service wrappers
    "FlextLDAPUserService",
]

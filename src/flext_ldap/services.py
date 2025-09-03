"""FLEXT LDAP Services - Single class following flext-core patterns.

Unified service class consolidating ALL LDAP operations including user and group
management. Eliminates separate service classes using composition patterns.
"""

# Import current service implementation for compatibility
from __future__ import annotations

from typing import cast

from flext_core import FlextContainer, FlextLogger, FlextResult

from flext_ldap.container import FlextLDAPContainer
from flext_ldap.entities import FlextLDAPEntities
from flext_ldap.repositories import FlextLDAPRepositories
from flext_ldap.typings import LdapAttributeDict
from flext_ldap.value_objects import FlextLDAPValueObjects

logger = FlextLogger(__name__)


class FlextLDAPServices:
    """Single FLEXT LDAP Services class following flext-core patterns.

    Consolidates ALL LDAP operations including user, group, and search functionality
    using Python standard libraries and flext-core patterns.

    No custom helpers, no multiple classes, no workarounds.
    """

    def __init__(self, container: FlextContainer | None = None) -> None:
        """Initialize FlextLDAPServices with flext-core dependency injection."""
        # Initialize without parent class
        self._ldap_container = FlextLDAPContainer()
        self._container = container or self._ldap_container.get_container()

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
        """Get LDAP repository from LDAP container."""
        # Get the repository through the LDAP container method
        repository = self._ldap_container.get_repository()
        return FlextResult.ok(repository)

    async def initialize(self) -> FlextResult[None]:
        """Initialize service and dependencies."""
        logger.info("LDAP service initializing")
        return FlextResult[None].ok(None)

    async def cleanup(self) -> FlextResult[None]:
        """Cleanup service resources."""
        logger.info("LDAP service cleaning up")
        # Handle different container types safely
        if hasattr(self._container, "reset"):
            self._container.reset()  # type: ignore[attr-defined]
        elif hasattr(self._container, "clear"):
            self._container.clear()  # type: ignore[attr-defined]
        # If no cleanup method available, just log success
        return FlextResult[None].ok(None)

    # =========================================================================
    # USER OPERATIONS - Consolidated user management
    # =========================================================================

    async def create_user(
        self,
        request: FlextLDAPEntities.CreateUserRequest,
    ) -> FlextResult[FlextLDAPEntities.User]:
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
            return FlextResult[FlextLDAPEntities.User].fail(
                f"User validation failed: {validation_result.error}",
            )

        # Save user via repository from flext-core container
        repository_result = self._get_repository()
        if not repository_result.is_success:
            return FlextResult[FlextLDAPEntities.User].fail(
                f"Repository access failed: {repository_result.error}"
            )

        # Type cast repository to correct interface
        repository = cast("FlextLDAPRepositories.Repository", repository_result.value)
        save_result = await repository.save_async(user_entity)

        if not save_result.is_success:
            return FlextResult[FlextLDAPEntities.User].fail(
                save_result.error or "Save failed"
            )

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
        return FlextResult[FlextLDAPEntities.User].ok(user_entity)

    async def get_user(self, dn: str) -> FlextResult[FlextLDAPEntities.User | None]:
        """Get user by distinguished name.

        Args:
            dn: Distinguished name of the user

        Returns:
            FlextResult containing user or None if not found

        """
        repository_result = self._get_repository()
        if not repository_result.is_success:
            return FlextResult[FlextLDAPEntities.User | None].fail(
                f"Repository access failed: {repository_result.error}"
            )

        # Type cast repository to correct interface
        repository = cast("FlextLDAPRepositories.Repository", repository_result.value)
        entry_result = await repository.find_by_dn(dn)

        if not entry_result.is_success:
            return FlextResult[FlextLDAPEntities.User | None].fail(
                entry_result.error or "User lookup failed"
            )

        if not entry_result.value:
            return FlextResult[FlextLDAPEntities.User | None].ok(None)

        # Convert entry to user - entry is already FlextLDAPEntry, extract user fields
        entry = entry_result.value
        user_entity = FlextLDAPEntities.User(
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
        return FlextResult[FlextLDAPEntities.User | None].ok(user_entity)

    async def update_user(
        self,
        dn: str,
        updates: LdapAttributeDict,
    ) -> FlextResult[FlextLDAPEntities.User]:
        """Update user attributes.

        Args:
            dn: Distinguished name of the user
            updates: Dictionary of attributes to update

        Returns:
            FlextResult containing updated user

        """
        repository_result = self._get_repository()
        if not repository_result.is_success:
            return FlextResult[FlextLDAPEntities.User].fail(
                f"Repository access failed: {repository_result.error}"
            )

        # Type cast repository to correct interface
        repository = cast("FlextLDAPRepositories.Repository", repository_result.value)
        update_result = await repository.update(dn, updates)

        if not update_result.is_success:
            return FlextResult[FlextLDAPEntities.User].fail(
                update_result.error or "User update failed"
            )

        # Get updated user - handle potential None return
        user_result = await self.get_user(dn)
        if not user_result.is_success:
            return FlextResult[FlextLDAPEntities.User].fail(
                user_result.error or "Failed to get updated user"
            )
        if user_result.value is None:
            return FlextResult[FlextLDAPEntities.User].fail("Updated user not found")
        return FlextResult[FlextLDAPEntities.User].ok(user_result.value)

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

    async def create_group(
        self, group: FlextLDAPEntities.Group
    ) -> FlextResult[FlextLDAPEntities.Group]:
        """Create new group in LDAP directory.

        Args:
            group: Group entity to create

        Returns:
            FlextResult containing created group

        """
        # Validate group business rules
        validation_result = group.validate_business_rules()
        if not validation_result.is_success:
            return FlextResult[FlextLDAPEntities.Group].fail(
                f"Group validation failed: {validation_result.error}",
            )

        # Save group via repository
        repository_result = self._get_repository()
        if not repository_result.is_success:
            return FlextResult[FlextLDAPEntities.Group].fail(
                f"Repository access failed: {repository_result.error}"
            )

        # Type cast repository to correct interface
        repository = cast("FlextLDAPRepositories.Repository", repository_result.value)
        save_result = await repository.save_async(group)

        if not save_result.is_success:
            return FlextResult[FlextLDAPEntities.Group].fail(
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
        return FlextResult[FlextLDAPEntities.Group].ok(group)

    async def get_group(self, dn: str) -> FlextResult[FlextLDAPEntities.Group | None]:
        """Get group by DN.

        Args:
            dn: Distinguished name of the group

        Returns:
            Group entity or None if not found

        """
        repository_result = self._get_repository()
        if not repository_result.is_success:
            return FlextResult[FlextLDAPEntities.Group | None].fail(
                f"Repository access failed: {repository_result.error}"
            )

        # Type cast repository to correct interface
        repository = cast("FlextLDAPRepositories.Repository", repository_result.value)
        entry_result = await repository.find_by_dn(dn)
        if not entry_result.is_success:
            return FlextResult[FlextLDAPEntities.Group | None].fail(
                entry_result.error or "Failed to find entry"
            )

        if entry_result.value is None:
            return FlextResult[FlextLDAPEntities.Group | None].ok(None)

        # Convert entry to group
        entry = entry_result.value
        group = FlextLDAPEntities.Group(
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

        return FlextResult[FlextLDAPEntities.Group | None].ok(group)

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
        result = FlextLDAPValueObjects.DistinguishedName.create(dn)
        if result.is_success:
            return FlextResult[None].ok(None)
        return FlextResult[None].fail(result.error or "Invalid DN")

    def validate_filter(self, filter_str: str) -> FlextResult[None]:
        """Validate LDAP filter format."""
        result = FlextLDAPValueObjects.Filter.create(filter_str)
        if result.is_success:
            return FlextResult[None].ok(None)
        return FlextResult[None].fail(result.error or "Invalid filter")

    # =========================================================================
    # SEARCH OPERATIONS - Consolidated search functionality
    # =========================================================================

    async def search(
        self, request: FlextLDAPEntities.SearchRequest
    ) -> FlextResult[FlextLDAPEntities.SearchResponse]:
        """Perform LDAP search operation.

        Args:
            request: Search request with filters and scope

        Returns:
            FlextResult containing search response

        """
        repository_result = self._get_repository()
        if not repository_result.is_success:
            return FlextResult[FlextLDAPEntities.SearchResponse].fail(
                f"Repository access failed: {repository_result.error}"
            )

        # Type cast repository to correct interface
        repository = cast("FlextLDAPRepositories.Repository", repository_result.value)
        search_result = await repository.search(request)

        if not search_result.is_success:
            return FlextResult[FlextLDAPEntities.SearchResponse].fail(
                search_result.error or "Search failed"
            )

        return FlextResult[FlextLDAPEntities.SearchResponse].ok(search_result.value)

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
    ) -> FlextResult[list[FlextLDAPEntities.User]]:
        """Search for users matching filter.

        Args:
            filter_str: LDAP filter string
            base_dn: Base DN for search

        Returns:
            List of matching users or error

        """
        search_request = FlextLDAPEntities.SearchRequest(
            base_dn=base_dn,
            scope="subtree",
            filter_str=filter_str,
            attributes=["*"],
            size_limit=1000,
            time_limit=30,
        )

        search_result = await self.search(search_request)
        if not search_result.is_success:
            return FlextResult[list[FlextLDAPEntities.User]].fail(
                search_result.error or "Search failed"
            )

        users = []
        for entry_data in search_result.value.entries:
            if "dn" in entry_data:
                user_result = await self.get_user(str(entry_data["dn"]))
                if user_result.is_success and user_result.value:
                    users.append(user_result.value)

        return FlextResult[list[FlextLDAPEntities.User]].ok(users)

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
    # GROUP MEMBER MANAGEMENT - Specialized group operations using Python standard libraries
    # =========================================================================

    async def add_member_to_group(
        self, group_dn: str, member_dn: str
    ) -> FlextResult[None]:
        """Add member to group using Python standard libraries (no custom wrappers)."""
        # Get current group
        group_result = await self.get_group(group_dn)
        if not group_result.is_success:
            return FlextResult[None].fail(group_result.error or "Failed to get group")

        if group_result.value is None:
            return FlextResult[None].fail("Group not found")

        group = group_result.value

        # Check if member already exists using Python standard library
        if member_dn in group.members:
            return FlextResult[None].fail("Member already in group")

        # Add member using Python standard list operations
        updated_members = [*group.members, member_dn]
        return await self.update_group(group_dn, {"member": updated_members})

    async def remove_member_from_group(
        self, group_dn: str, member_dn: str
    ) -> FlextResult[None]:
        """Remove member from group using Python standard libraries."""
        # Get current group
        group_result = await self.get_group(group_dn)
        if not group_result.is_success:
            return FlextResult[None].fail(group_result.error or "Failed to get group")

        if group_result.value is None:
            return FlextResult[None].fail("Group not found")

        group = group_result.value

        # Check if member exists using Python standard library
        if member_dn not in group.members:
            return FlextResult[None].fail("Member not in group")

        # Remove member using Python list comprehension
        updated_members = [m for m in group.members if m != member_dn]
        return await self.update_group(group_dn, {"member": updated_members})

    async def get_group_members_list(self, group_dn: str) -> FlextResult[list[str]]:
        """Get group members list using direct group access."""
        group_result = await self.get_group(group_dn)
        if not group_result.is_success:
            return FlextResult[list[str]].fail(
                group_result.error or "Failed to get group"
            )

        if group_result.value is None:
            return FlextResult[list[str]].fail("Group not found")

        return FlextResult[list[str]].ok(group_result.value.members)


# =============================================================================
# MODULE EXPORTS
# =============================================================================

__all__ = [
    "FlextLDAPServices",
]

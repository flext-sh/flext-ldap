"""LDAP service layer following Clean Architecture patterns."""

from __future__ import annotations

from typing import cast, override

from flext_core import FlextEntityId, FlextResult, get_logger

from flext_ldap.container import FlextLdapContainer, get_ldap_container
from flext_ldap.entities import (
    FlextLdapCreateUserRequest,
    FlextLdapGroup,
    FlextLdapSearchRequest,
    FlextLdapSearchResponse,
    FlextLdapUser,
)
from flext_ldap.interfaces import (
    IFlextLdapFullService,
    IFlextLdapGroupService,
    IFlextLdapUserService,
)
from flext_ldap.typings import LdapAttributeDict
from flext_ldap.value_objects import FlextLdapDistinguishedName

logger = get_logger(__name__)


class FlextLdapService(IFlextLdapFullService):
    """Main LDAP service implementing all operations."""

    def __init__(self, container: FlextLdapContainer | None = None) -> None:
        """Initialize LDAP service with dependency injection."""
        self._container = container or get_ldap_container()

    async def initialize(self) -> FlextResult[None]:
        """Initialize service and dependencies."""
        logger.info("LDAP service initializing")
        return FlextResult[None].ok(None)

    async def cleanup(self) -> FlextResult[None]:
        """Cleanup service resources."""
        logger.info("LDAP service cleaning up")
        return await self._container.cleanup()

    # User Service Methods

    @override
    async def create_user(
        self, request: FlextLdapCreateUserRequest,
    ) -> FlextResult[FlextLdapUser]:
        """Create new user in LDAP directory."""
        user_entity = request.to_user_entity()

        # Validate user business rules
        validation_result = user_entity.validate_business_rules()
        if not validation_result.is_success:
            return FlextResult[FlextLdapUser].fail(
                f"User validation failed: {validation_result.error}",
            )

        # Save user via repository
        repository = self._container.get_repository()
        save_result = await repository.save(user_entity)

        if not save_result.is_success:
            return FlextResult[FlextLdapUser].fail(save_result.error or "Save failed")

        # Using flext-core logging format with enhanced structured data
        logger.info(
            "LDAP user created successfully",
            extra={
                "operation": "create_user",
                "dn": user_entity.dn,
                "uid": user_entity.uid,
                "object_classes": user_entity.object_classes,
                "status": user_entity.status.value if user_entity.status else None,
                "execution_context": "FlextLdapService.create_user",
            },
        )
        return FlextResult[FlextLdapUser].ok(user_entity)

    @override
    async def get_user(self, dn: str) -> FlextResult[FlextLdapUser | None]:
        """Get user by distinguished name."""
        repository = self._container.get_repository()
        entry_result = await repository.find_by_dn(dn)

        if not entry_result.is_success:
            return FlextResult[FlextLdapUser | None].fail(
                entry_result.error or "Entry lookup failed",
            )

        if not entry_result.value:
            return FlextResult[FlextLdapUser | None].ok(None)

        entry = entry_result.value

        # Convert to user entity
        user = FlextLdapUser(
            id=FlextEntityId(
                f"service_user_{entry.dn.replace(',', '_').replace('=', '_')}",
            ),
            dn=entry.dn,
            uid=entry.get_single_attribute_value("uid") or "",
            cn=entry.get_single_attribute_value("cn") or "",
            sn=entry.get_single_attribute_value("sn") or "",
            given_name=entry.get_single_attribute_value("givenName"),
            mail=entry.get_single_attribute_value("mail"),
            phone=entry.get_single_attribute_value("telephoneNumber"),
            object_classes=entry.object_classes,
            attributes=entry.attributes,
            status=entry.status,
        )

        return FlextResult[FlextLdapUser | None].ok(user)

    @override
    async def update_user(
        self, dn: str, attributes: LdapAttributeDict,
    ) -> FlextResult[None]:
        """Update user attributes."""
        repository = self._container.get_repository()
        result = await repository.update(dn, attributes)

        if result.is_success:
            logger.info("User updated successfully", extra={"dn": dn})

        return result

    @override
    # Enhanced logging for user deletion operations
    async def delete_user(self, dn: str) -> FlextResult[None]:
        """Delete user from directory."""
        repository = self._container.get_repository()
        result = await repository.delete(dn)

        if result.is_success:
            logger.info("User deleted successfully", extra={"dn": dn})

        return result

    @override
    async def search_users(
        self,
        filter_str: str,
        base_dn: str,
        scope: str = "subtree",
    ) -> FlextResult[list[FlextLdapUser]]:
        """Search users with filter."""
        search_request = FlextLdapSearchRequest(
            base_dn=base_dn,
            scope=scope,
            filter_str=f"(&(objectClass=inetOrgPerson){filter_str})",
            attributes=None,
            size_limit=1000,
            time_limit=30,
        )

        repository = self._container.get_repository()
        search_result = await repository.search(search_request)

        if not search_result.is_success:
            return FlextResult[list[FlextLdapUser]].fail(
                search_result.error or "Search failed",
            )

        users: list[FlextLdapUser] = []
        for entry_data in search_result.value.entries:
            typed_entry_data: dict[str, object] = cast("dict[str, object]", entry_data)
            entry_dn = typed_entry_data.get("dn")
            if not entry_dn:
                continue

            user_result = await self.get_user(str(entry_dn))
            # Use simplified pattern with .value access
            if user_result.is_success:
                user = user_result.value
                if user:
                    users.append(user)

        return FlextResult[list[FlextLdapUser]].ok(users)

    @override
    async def user_exists(self, dn: str) -> FlextResult[bool]:
        """Check if user exists."""
        repository = self._container.get_repository()
        return await repository.exists(dn)

    # Group Service Methods

    @override
    async def create_group(self, group: FlextLdapGroup) -> FlextResult[None]:
        """Create new group in LDAP directory."""
        # Validate group business rules
        validation_result = group.validate_business_rules()
        if not validation_result.is_success:
            return FlextResult[None].fail(
                f"Group validation failed: {validation_result.error}",
            )

        # Save group via repository
        repository = self._container.get_repository()
        result = await repository.save(group)

        if result.is_success:
            logger.info(
                "Group created successfully", extra={"dn": group.dn, "cn": group.cn},
            )

        return result

    @override
    async def get_group(self, dn: str) -> FlextResult[FlextLdapGroup | None]:
        """Get group by distinguished name."""
        repository = self._container.get_repository()
        entry_result = await repository.find_by_dn(dn)

        if not entry_result.is_success:
            return FlextResult[FlextLdapGroup | None].fail(
                entry_result.error or "Group lookup failed",
            )

        if not entry_result.value:
            return FlextResult[FlextLdapGroup | None].ok(None)

        entry = entry_result.value

        # Convert to group entity
        group = FlextLdapGroup(
            id=FlextEntityId(
                f"service_group_{entry.dn.replace(',', '_').replace('=', '_')}",
            ),
            dn=entry.dn,
            cn=entry.get_single_attribute_value("cn") or "",
            description=entry.get_single_attribute_value("description"),
            members=entry.get_attribute_values("member"),
            object_classes=entry.object_classes,
            attributes=entry.attributes,
            status=entry.status,
        )

        return FlextResult[FlextLdapGroup | None].ok(group)

    @override
    async def update_group(
        self, dn: str, attributes: LdapAttributeDict,
    ) -> FlextResult[None]:
        """Update group attributes."""
        repository = self._container.get_repository()
        result = await repository.update(dn, attributes)

        if result.is_success:
            logger.info("Group updated successfully", extra={"dn": dn})

        return result

    @override
    # Enhanced logging for group deletion operations
    async def delete_group(self, dn: str) -> FlextResult[None]:
        """Delete group from directory."""
        repository = self._container.get_repository()
        result = await repository.delete(dn)

        if result.is_success:
            logger.info("Group deleted successfully", extra={"dn": dn})

        return result

    @override
    async def add_member(self, group_dn: str, member_dn: str) -> FlextResult[None]:
        """Add member to group."""
        group_repo = self._container.get_group_repository()
        result = await group_repo.add_member_to_group(group_dn, member_dn)

        if result.is_success:
            logger.info(
                "Member added to group",
                extra={"group_dn": group_dn, "member_dn": member_dn},
            )

        return result

    @override
    async def remove_member(self, group_dn: str, member_dn: str) -> FlextResult[None]:
        """Remove member from group."""
        # Get current members
        group_repo = self._container.get_group_repository()
        members_result = await group_repo.get_group_members(group_dn)

        if not members_result.is_success:
            return FlextResult[None].fail(
                members_result.error or "Members lookup failed",
            )

        current_members = members_result.value
        if member_dn not in current_members:
            return FlextResult[None].fail("Member not in group")

        # Remove member
        new_members = [m for m in current_members if m != member_dn]
        attributes: LdapAttributeDict = {"member": new_members}

        repository = self._container.get_repository()
        result = await repository.update(group_dn, attributes)

        if result.is_success:
            logger.info(
                "Member removed from group",
                extra={"group_dn": group_dn, "member_dn": member_dn},
            )

        return result

    @override
    async def get_members(self, group_dn: str) -> FlextResult[list[str]]:
        """Get group members."""
        group_repo = self._container.get_group_repository()
        return await group_repo.get_group_members(group_dn)

    @override
    async def group_exists(self, dn: str) -> FlextResult[bool]:
        """Check if group exists."""
        repository = self._container.get_repository()
        return await repository.exists(dn)

    # Validation methods

    @override
    def validate_dn(self, dn: str) -> FlextResult[None]:
        """Validate distinguished name format."""
        try:
            dn_result = FlextLdapDistinguishedName.create(dn)
            if not dn_result.is_success:
                return FlextResult[None].fail(dn_result.error or "DN validation failed")
            return FlextResult[None].ok(None)
        except Exception as e:
            return FlextResult[None].fail(f"DN validation error: {e}")

    @override
    def validate_filter(self, filter_str: str) -> FlextResult[None]:
        """Validate LDAP search filter."""
        try:
            if not filter_str.strip():
                return FlextResult[None].fail("Filter cannot be empty")

            if not (filter_str.startswith("(") and filter_str.endswith(")")):
                return FlextResult[None].fail("Filter must be enclosed in parentheses")

            return FlextResult[None].ok(None)
        except Exception as e:
            return FlextResult[None].fail(f"Filter validation error: {e}")

    @override
    def validate_attributes(self, attributes: LdapAttributeDict) -> FlextResult[None]:
        """Validate attribute dictionary."""
        try:
            if not attributes:
                return FlextResult[None].fail("Attributes cannot be empty")

            for name in attributes:
                if not name or not name.strip():
                    return FlextResult[None].fail("Attribute name cannot be empty")

                # Note: value cannot be None due to LdapAttributeDict typing

            return FlextResult[None].ok(None)
        except Exception as e:
            return FlextResult[None].fail(f"Attributes validation error: {e}")

    @override
    def validate_object_classes(self, object_classes: list[str]) -> FlextResult[None]:
        """Validate object class list."""
        try:
            if not object_classes:
                return FlextResult[None].fail("Object classes cannot be empty")

            for oc in object_classes:
                if not oc or not oc.strip():
                    return FlextResult[None].fail("Object class cannot be empty")

            return FlextResult[None].ok(None)
        except Exception as e:
            return FlextResult[None].fail(f"Object classes validation error: {e}")

    # Search methods

    async def search(
        self, request: FlextLdapSearchRequest,
    ) -> FlextResult[FlextLdapSearchResponse]:
        """Search entries."""
        repository = self._container.get_repository()
        return await repository.search(request)


# Specialized service classes for focused operations


class FlextLdapUserService(IFlextLdapUserService):
    """Specialized service for user operations."""

    def __init__(self, main_service: FlextLdapService) -> None:
        """Initialize with main service."""
        self._service = main_service

    @override
    async def create_user(
        self, request: FlextLdapCreateUserRequest,
    ) -> FlextResult[FlextLdapUser]:
        """Create new user."""
        return await self._service.create_user(request)

    @override
    async def get_user(self, dn: str) -> FlextResult[FlextLdapUser | None]:
        """Get user by DN."""
        return await self._service.get_user(dn)

    @override
    async def update_user(
        self, dn: str, attributes: LdapAttributeDict,
    ) -> FlextResult[None]:
        """Update user."""
        return await self._service.update_user(dn, attributes)

    @override
    async def delete_user(self, dn: str) -> FlextResult[None]:
        """Delete user."""
        return await self._service.delete_user(dn)

    @override
    async def search_users(
        self, filter_str: str, base_dn: str, scope: str = "subtree",
    ) -> FlextResult[list[FlextLdapUser]]:
        """Search users."""
        return await self._service.search_users(filter_str, base_dn, scope)

    @override
    async def user_exists(self, dn: str) -> FlextResult[bool]:
        """Check if user exists."""
        return await self._service.user_exists(dn)


class FlextLdapGroupService(IFlextLdapGroupService):
    """Specialized service for group operations."""

    def __init__(self, main_service: FlextLdapService) -> None:
        """Initialize with main service."""
        self._service = main_service

    @override
    async def create_group(self, group: FlextLdapGroup) -> FlextResult[None]:
        """Create group."""
        return await self._service.create_group(group)

    @override
    async def get_group(self, dn: str) -> FlextResult[FlextLdapGroup | None]:
        """Get group by DN."""
        return await self._service.get_group(dn)

    @override
    async def update_group(
        self, dn: str, attributes: LdapAttributeDict,
    ) -> FlextResult[None]:
        """Update group."""
        return await self._service.update_group(dn, attributes)

    @override
    async def delete_group(self, dn: str) -> FlextResult[None]:
        """Delete group."""
        return await self._service.delete_group(dn)

    @override
    async def add_member(self, group_dn: str, member_dn: str) -> FlextResult[None]:
        """Add member to group."""
        return await self._service.add_member(group_dn, member_dn)

    @override
    async def remove_member(self, group_dn: str, member_dn: str) -> FlextResult[None]:
        """Remove member from group."""
        return await self._service.remove_member(group_dn, member_dn)

    @override
    async def get_members(self, group_dn: str) -> FlextResult[list[str]]:
        """Get group members."""
        return await self._service.get_members(group_dn)

    @override
    async def group_exists(self, dn: str) -> FlextResult[bool]:
        """Check if group exists."""
        return await self._service.group_exists(dn)

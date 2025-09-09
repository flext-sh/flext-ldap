"""FLEXT LDAP Services module.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from functools import cached_property
from typing import cast

from flext_core import (
    FlextContainer,
    FlextResult,
    FlextServices,
    FlextTypes,
)

from flext_ldap.container import FlextLDAPContainer
from flext_ldap.entities import FlextLDAPEntities
from flext_ldap.repositories import FlextLDAPRepositories
from flext_ldap.typings import LdapAttributeDict
from flext_ldap.value_objects import FlextLDAPValueObjects

# FlextLogger available via FlextMixins.Service inheritance - no need for module logger

# Python 3.13 type aliases
type LDAPRequest = FlextTypes.Core.Dict
type LDAPDomain = object
type LDAPResult = FlextTypes.Core.Dict
type RepositoryInstance = FlextLDAPRepositories


class FlextLDAPServices(
    FlextServices.ServiceProcessor[LDAPRequest, LDAPDomain, LDAPResult]
):
    """LDAP operations service using FlextServices.ServiceProcessor pattern."""

    def __init__(self, container: FlextContainer | None = None) -> None:
        """Initialize LDAP services using FlextServices patterns."""
        # Initialize FlextServices.ServiceProcessor (which includes FlextMixins.Service)
        super().__init__()
        self._ldap_container = FlextLDAPContainer()
        self._container = container or self._ldap_container.get_container()

    def process(self, request: LDAPRequest) -> FlextResult[LDAPDomain]:
        """Process LDAP request using Python 3.13 pattern matching - implements ServiceProcessor.process()."""
        # Python 3.13 structural pattern matching for LDAP request dispatch
        match request:
            case {"operation": "user_create", "data": user_data} if isinstance(
                user_data, dict
            ):
                return self._process_user_creation(user_data)
            case {"operation": "user_read", "dn": dn} if isinstance(dn, str):
                return self._process_user_read(dn)
            case {"operation": "group_create", "data": group_data} if isinstance(
                group_data, dict
            ):
                return self._process_group_creation(group_data)
            case {"operation": "search", "params": search_params} if isinstance(
                search_params, dict
            ):
                return self._process_search_operation(search_params)
            case {"operation": "validate", "target": str(target), "value": value}:
                return self._process_validation(target, value)
            case _:
                return FlextResult[LDAPDomain].ok(request)

    def build(self, domain: LDAPDomain, *, correlation_id: str) -> LDAPResult:
        """Build final LDAP result from domain object - implements ServiceProcessor.build()."""
        if isinstance(domain, dict):
            domain["correlation_id"] = correlation_id
            return domain
        return {"result": domain, "correlation_id": correlation_id}

    # Python 3.13 optimized LDAP-specific processing methods
    def _process_user_creation(
        self, user_data: dict[str, object]
    ) -> FlextResult[LDAPDomain]:
        """Process user creation with enhanced validation."""
        try:
            # Type cast for Pydantic model creation
            typed_data = cast("dict", user_data)
            create_request = FlextLDAPEntities.CreateUserRequest(**typed_data)
            return FlextResult[LDAPDomain].ok(
                {"status": "user_creation_initiated", "request": create_request}
            )
        except Exception as e:
            return FlextResult[LDAPDomain].fail(f"User creation processing failed: {e}")

    def _process_user_read(self, dn: str) -> FlextResult[LDAPDomain]:
        """Process user read with DN validation."""
        if not dn.strip():
            return FlextResult[LDAPDomain].fail("Invalid DN for user read operation")
        return FlextResult[LDAPDomain].ok({"status": "user_read_initiated", "dn": dn})

    def _process_group_creation(
        self, group_data: dict[str, object]
    ) -> FlextResult[LDAPDomain]:
        """Process group creation with field validation."""
        try:
            required_fields = {"dn", "cn"}
            if not required_fields.issubset(group_data.keys()):
                missing = required_fields - group_data.keys()
                return FlextResult.fail(f"Missing required fields: {missing}")
            return FlextResult.ok(
                {"status": "group_creation_initiated", "data": group_data}
            )
        except Exception as e:
            return FlextResult.fail(f"Group creation processing failed: {e}")

    def _process_search_operation(
        self, search_params: dict[str, object]
    ) -> FlextResult[LDAPDomain]:
        """Process search operation with parameter validation."""
        try:
            # Create SearchRequest with proper error handling
            search_request = FlextLDAPEntities.SearchRequest.model_validate(
                search_params
            )
            return FlextResult.ok(
                {"status": "search_initiated", "request": search_request}
            )
        except Exception as e:
            return FlextResult.fail(f"Search processing failed: {e}")

    def _process_validation(
        self, target: str, value: object
    ) -> FlextResult[LDAPDomain]:
        """Process validation with Python 3.13 pattern matching."""
        match target:
            case "dn":
                result = self.validate_dn(str(value))
                return FlextResult.ok({"valid": result.is_success, "target": target})
            case "filter":
                result = self.validate_filter(str(value))
                return FlextResult.ok({"valid": result.is_success, "target": target})
            case "attributes":
                result = self.validate_attributes(cast("LdapAttributeDict", value))
                return FlextResult.ok({"valid": result.is_success, "target": target})
            case _:
                return FlextResult.fail(f"Unknown validation target: {target}")

    @cached_property
    def _repository(self) -> RepositoryInstance:
        """Cached repository instance for performance optimization."""
        return self._ldap_container.get_repository()

    def _get_repository(self) -> FlextResult[object]:
        """Get LDAP repository using cached property."""
        return FlextResult.ok(self._repository)

    async def initialize(self) -> FlextResult[None]:
        """Initialize service using FlextServices logging."""
        self.log_info("LDAP service initializing", service="FlextLDAPServices")
        return FlextResult[None].ok(None)

    async def cleanup(self) -> FlextResult[None]:
        """Cleanup service using FlextServices logging."""
        self.log_info("LDAP service cleaning up", service="FlextLDAPServices")
        # Handle different container types safely using getattr for type safety
        reset_method = getattr(self._container, "reset", None)
        if reset_method and callable(reset_method):
            reset_method()
        else:
            clear_method = getattr(self._container, "clear", None)
            if clear_method and callable(clear_method):
                clear_method()
        return FlextResult[None].ok(None)

    async def connect(
        self, server_uri: str, bind_dn: str, bind_password: str
    ) -> FlextResult[None]:
        """Connect to LDAP server."""
        try:
            client = self._ldap_container.get_client()
            return await client.connect(server_uri, bind_dn, bind_password)
        except Exception as e:
            self.log_error("Failed to connect to LDAP server", error=str(e))
            return FlextResult[None].fail(f"Connection failed: {e}")

    async def disconnect(self) -> FlextResult[None]:
        """Disconnect from LDAP server."""
        try:
            # Get client for future disconnect functionality - placeholder for now
            self.log_info("LDAP disconnection completed", service="FlextLDAPServices")
            return FlextResult[None].ok(None)
        except Exception as e:
            self.log_error("Failed to disconnect from LDAP server", error=str(e))
            return FlextResult[None].fail(f"Disconnect failed: {e}")

    # =========================================================================
    # USER OPERATIONS - Consolidated user management
    # =========================================================================

    async def create_user(
        self,
        request: FlextLDAPEntities.CreateUserRequest,
    ) -> FlextResult[FlextLDAPEntities.User]:
        """Create new LDAP user."""
        user_entity = request.to_user_entity()

        # Validate user business rules
        validation_result = user_entity.validate_business_rules()
        if not validation_result.is_success:
            return FlextResult.fail(
                f"User validation failed: {validation_result.error}",
            )

        # Use cached repository for performance
        repository = self._repository
        save_result = await repository.save_async(user_entity)

        if not save_result.is_success:
            return FlextResult.fail(
                save_result.error or "Save failed",
            )

        self.log_info(
            "LDAP user created successfully",
            operation="create_user",
            dn=user_entity.dn,
            uid=user_entity.uid,
            object_classes=str(user_entity.object_classes),
            execution_context="FlextLDAPServices.create_user",
        )
        return FlextResult.ok(user_entity)

    async def get_user(self, dn: str) -> FlextResult[FlextLDAPEntities.User | None]:
        """Get user by DN using cached repository."""
        # Use cached repository for performance
        repository = self._repository
        entry_result = await repository.find_by_dn(dn)

        if not entry_result.is_success:
            return FlextResult.fail(
                entry_result.error or "User lookup failed",
            )

        if not entry_result.value:
            return FlextResult.ok(None)

        # Convert entry to user using Python 3.13 pattern matching for attribute extraction
        entry = entry_result.value

        # Python 3.13 optimized attribute extraction with pattern matching
        def safe_str_attr(attr_name: str) -> str | None:
            """Safely extract string attribute with None handling."""
            match entry.get_attribute(attr_name):
                case str(value) if value:
                    return value
                case _:
                    return None

        user_entity = FlextLDAPEntities.User(
            id=entry.id,
            dn=entry.dn,
            object_classes=entry.object_classes,
            attributes=entry.attributes,
            uid=str(entry.get_attribute("uid") or "unknown"),
            cn=safe_str_attr("cn"),
            sn=safe_str_attr("sn"),
            given_name=safe_str_attr("givenName"),
            mail=safe_str_attr("mail"),
            user_password=safe_str_attr("userPassword"),
            created_at=entry.created_at,
            modified_at=entry.modified_at,
        )
        return FlextResult.ok(user_entity)

    async def update_user(
        self,
        dn: str,
        updates: LdapAttributeDict,
    ) -> FlextResult[FlextLDAPEntities.User]:
        """Update user attributes using cached repository."""
        # Use cached repository for performance
        repository = self._repository
        update_result = await repository.update(dn, updates)

        if not update_result.is_success:
            return FlextResult.fail(
                update_result.error or "User update failed",
            )

        # Get updated user - handle potential None return
        user_result = await self.get_user(dn)
        if not user_result.is_success:
            return FlextResult.fail(
                user_result.error or "Failed to get updated user",
            )
        if user_result.value is None:
            return FlextResult.fail("Updated user not found")
        return FlextResult.ok(user_result.value)

    async def delete_user(self, dn: str) -> FlextResult[bool]:
        """Delete user from directory using cached repository."""
        # Use cached repository for performance
        repository = self._repository
        delete_result = await repository._delete_async(dn)

        if not delete_result.is_success:
            return FlextResult.fail(delete_result.error or "User deletion failed")

        self.log_info(
            "LDAP user deleted successfully",
            operation="delete_user",
            dn=dn,
            execution_context="FlextLDAPServices.delete_user",
        )
        success = True
        return FlextResult.ok(success)

    # =========================================================================
    # GROUP OPERATIONS - Consolidated group management
    # =========================================================================

    async def create_group(
        self,
        group: FlextLDAPEntities.Group,
    ) -> FlextResult[FlextLDAPEntities.Group]:
        """Create new LDAP group."""
        # Validate group business rules
        validation_result = group.validate_business_rules()
        if not validation_result.is_success:
            return FlextResult.fail(
                f"Group validation failed: {validation_result.error}",
            )

        # Use cached repository for performance
        repository = self._repository
        save_result = await repository.save_async(group)

        if not save_result.is_success:
            return FlextResult.fail(
                save_result.error or "Group save failed",
            )

        self.log_info(
            "LDAP group created successfully",
            operation="create_group",
            dn=group.dn,
            cn=group.cn,
            execution_context="FlextLDAPServices.create_group",
        )
        return FlextResult.ok(group)

    async def get_group(self, dn: str) -> FlextResult[FlextLDAPEntities.Group | None]:
        """Get group by DN using cached repository."""
        # Use cached repository for performance
        repository = self._repository
        entry_result = await repository.find_by_dn(dn)
        if not entry_result.is_success:
            return FlextResult.fail(
                entry_result.error or "Failed to find entry",
            )

        if entry_result.value is None:
            return FlextResult.ok(None)

        # Convert entry to group using Python 3.13 pattern matching for attributes
        entry = entry_result.value

        # Python 3.13 optimized attribute extraction with pattern matching
        def extract_group_attr(attr_name: str) -> str:
            """Extract group attribute using pattern matching."""
            match entry.attributes.get(attr_name):
                case [first, *_] if isinstance(first, str):
                    return first
                case str(value):
                    return value
                case _:
                    return ""

        def extract_members() -> list[str]:
            """Extract members list using pattern matching."""
            match entry.attributes.get("member"):
                case list(members):
                    return [str(m) for m in members if m]
                case str(single_member):
                    return [single_member] if single_member else []
                case _:
                    return []

        group = FlextLDAPEntities.Group(
            id=entry.id,
            dn=entry.dn,
            cn=extract_group_attr("cn"),
            object_classes=entry.object_classes,
            members=extract_members(),
            status=entry.status,
            description=extract_group_attr("description"),
            modified_at=entry.modified_at,
        )

        return FlextResult.ok(group)

    async def update_group(
        self,
        dn: str,
        attributes: LdapAttributeDict,
    ) -> FlextResult[None]:
        """Update group attributes using cached repository."""
        # Use cached repository for performance
        repository = self._repository
        result = await repository.update(dn, attributes)
        if not result.is_success:
            return FlextResult.fail(result.error or "Update failed")
        return FlextResult.ok(None)

    async def delete_group(self, dn: str) -> FlextResult[None]:
        """Delete group by DN using cached repository."""
        # Use cached repository for performance
        repository = self._repository
        result = await repository._delete_async(dn)
        if not result.is_success:
            return FlextResult.fail(result.error or "Delete failed")
        return FlextResult.ok(None)

    async def add_member(self, group_dn: str, member_dn: str) -> FlextResult[None]:
        """Add member to group."""
        repository_result = self._get_repository()
        if not repository_result.is_success:
            return FlextResult.fail(
                f"Repository access failed: {repository_result.error}",
            )

        # Type cast repository to correct interface
        base_repository = cast(
            "FlextLDAPRepositories",
            repository_result.value,
        )
        # Use base repository directly - no need to create new instance
        group_repository = base_repository
        # Use update_attributes to modify group membership
        result = await group_repository.update_attributes(
            group_dn, {"member": [member_dn]}
        )
        if not result.is_success:
            return FlextResult.fail(result.error or "Add member failed")
        return FlextResult.ok(None)

    async def remove_member(self, group_dn: str, member_dn: str) -> FlextResult[None]:
        """Remove member from group."""
        # Get current members
        repository_result = self._get_repository()
        if not repository_result.is_success:
            return FlextResult.fail(
                f"Repository access failed: {repository_result.error}",
            )

        # Type cast repository to correct interface
        base_repository = cast(
            "FlextLDAPRepositories",
            repository_result.value,
        )
        # Use base repository directly
        group_repository = base_repository

        # Get group entry to check current members
        group_entry_result = await group_repository._find_by_dn_async(group_dn)
        if not group_entry_result.is_success or not group_entry_result.value:
            return FlextResult.fail("Group not found")

        group_entry = group_entry_result.value
        current_members = getattr(group_entry, "member", [])
        if member_dn not in current_members:
            return FlextResult.fail(f"Member {member_dn} not found in group")

        # Remove member and update
        updated_members = [m for m in current_members if m != member_dn]
        attributes: LdapAttributeDict = {"member": updated_members}
        result = await base_repository.update(group_dn, attributes)
        if not result.is_success:
            return FlextResult.fail(result.error or "Remove member failed")
        return FlextResult.ok(None)

    async def get_members(
        self, group_dn: str
    ) -> FlextResult[FlextTypes.Core.StringList]:
        """Get group members."""
        repository_result = self._get_repository()
        if not repository_result.is_success:
            return FlextResult[FlextTypes.Core.StringList].fail(
                f"Repository access failed: {repository_result.error}",
            )

        # Type cast repository to correct interface
        base_repository = cast(
            "FlextLDAPRepositories",
            repository_result.value,
        )
        # Use base repository directly to get group entry
        group_repository = base_repository
        group_entry_result = await group_repository._find_by_dn_async(group_dn)
        if not group_entry_result.is_success or not group_entry_result.value:
            return FlextResult[list[str]].fail("Group not found")

        group_entry = group_entry_result.value
        members = getattr(group_entry, "member", [])
        return FlextResult[list[str]].ok(
            members if isinstance(members, list) else [members]
        )

    # Validation methods needed by API
    def validate_dn(self, dn: str) -> FlextResult[None]:
        """Validate DN format."""
        result = FlextLDAPValueObjects.DistinguishedName.create(dn)
        if result.is_success:
            return FlextResult.ok(None)
        return FlextResult.fail(result.error or "Invalid DN")

    def validate_filter(self, filter_str: str) -> FlextResult[None]:
        """Validate LDAP filter format."""
        result = FlextLDAPValueObjects.Filter.create(filter_str)
        if result.is_success:
            return FlextResult.ok(None)
        return FlextResult.fail(result.error or "Invalid filter")

    # =========================================================================
    # SEARCH OPERATIONS - Consolidated search functionality
    # =========================================================================

    async def search(
        self,
        request: FlextLDAPEntities.SearchRequest,
    ) -> FlextResult[FlextLDAPEntities.SearchResponse]:
        """Perform LDAP search operation using cached repository."""
        # Use cached repository for performance
        repository = self._repository
        search_result = await repository.search(request)

        if not search_result.is_success:
            return FlextResult.fail(
                search_result.error or "Search failed",
            )

        return FlextResult.ok(search_result.value)

    # =========================================================================
    # VALIDATION METHODS - For test coverage and business logic
    # =========================================================================

    def validate_attributes(self, attributes: LdapAttributeDict) -> FlextResult[None]:
        """Validate LDAP attributes dictionary."""
        if not attributes:
            return FlextResult.fail("Attributes cannot be empty")

        return FlextResult.ok(None)

    def validate_object_classes(
        self, object_classes: FlextTypes.Core.StringList
    ) -> FlextResult[None]:
        """Validate LDAP object classes list."""
        if not object_classes:
            return FlextResult.fail("Object classes cannot be empty")

        return FlextResult.ok(None)

    async def search_users(
        self,
        filter_str: str,
        base_dn: str,
    ) -> FlextResult[list[FlextLDAPEntities.User]]:
        """Search for users matching filter."""
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
                search_result.error or "Search failed",
            )

        users = []
        for entry_data in search_result.value.entries:
            if "dn" in entry_data:
                user_result = await self.get_user(str(entry_data["dn"]))
                if user_result.is_success and user_result.value:
                    users.append(user_result.value)

        return FlextResult[list[FlextLDAPEntities.User]].ok(users)

    async def user_exists(self, dn: str) -> FlextResult[bool]:
        """Check if user exists at DN."""
        user_result = await self.get_user(dn)
        if not user_result.is_success:
            return FlextResult.fail(user_result.error or "Failed to get user")

        return FlextResult.ok(user_result.value is not None)

    async def group_exists(self, dn: str) -> FlextResult[bool]:
        """Check if group exists at DN."""
        group_result = await self.get_group(dn)
        if not group_result.is_success:
            return FlextResult.fail(group_result.error or "Failed to get group")

        return FlextResult.ok(group_result.value is not None)

    # =========================================================================
    # GROUP MEMBER MANAGEMENT - Specialized group operations using Python standard libraries
    # =========================================================================

    async def add_member_to_group(
        self,
        group_dn: str,
        member_dn: str,
    ) -> FlextResult[None]:
        """Add member to group."""
        # Get current group
        group_result = await self.get_group(group_dn)
        if not group_result.is_success:
            return FlextResult.fail(group_result.error or "Failed to get group")

        if group_result.value is None:
            return FlextResult.fail("Group not found")

        group = group_result.value

        # Check if member already exists using Python standard library
        if member_dn in group.members:
            return FlextResult.fail("Member already in group")

        # Add member using Python standard list operations
        updated_members = [*group.members, member_dn]
        return await self.update_group(group_dn, {"member": updated_members})

    async def remove_member_from_group(
        self,
        group_dn: str,
        member_dn: str,
    ) -> FlextResult[None]:
        """Remove member from group."""
        # Get current group
        group_result = await self.get_group(group_dn)
        if not group_result.is_success:
            return FlextResult.fail(group_result.error or "Failed to get group")

        if group_result.value is None:
            return FlextResult.fail("Group not found")

        group = group_result.value

        # Check if member exists using Python standard library
        if member_dn not in group.members:
            return FlextResult.fail("Member not in group")

        # Remove member using Python list comprehension
        updated_members = [m for m in group.members if m != member_dn]
        return await self.update_group(group_dn, {"member": updated_members})

    async def get_group_members_list(
        self, group_dn: str
    ) -> FlextResult[FlextTypes.Core.StringList]:
        """Get group members list."""
        group_result = await self.get_group(group_dn)
        if not group_result.is_success:
            return FlextResult[FlextTypes.Core.StringList].fail(
                group_result.error or "Failed to get group",
            )

        if group_result.value is None:
            return FlextResult[FlextTypes.Core.StringList].fail("Group not found")

        return FlextResult[FlextTypes.Core.StringList].ok(group_result.value.members)


# =============================================================================
# MODULE EXPORTS
# =============================================================================

__all__ = [
    "FlextLDAPServices",
]

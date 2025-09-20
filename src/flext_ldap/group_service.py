"""Group domain service for LDAP operations.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from flext_core import FlextDomainService, FlextResult
from flext_ldap.clients import FlextLdapClient
from flext_ldap.models import FlextLdapModels
from flext_ldap.typings import FlextLdapTypes
from flext_ldap.validations import FlextLdapValidations


class FlextLdapGroupService(FlextDomainService):
    """Domain service for LDAP group operations.

    This service encapsulates all group-related business logic and operations
    following Domain-Driven Design patterns. It provides a clean interface
    for group management operations while maintaining proper separation of concerns.

    Attributes:
        _client: LDAP client for infrastructure operations.

    """

    def __init__(self, client: FlextLdapClient) -> None:
        """Initialize group service with LDAP client.

        Args:
            client: LDAP client for performing infrastructure operations.

        """
        super().__init__()
        self._client = client

    def execute(self) -> FlextResult[dict[str, str]]:
        """Execute the main domain service operation.

        Returns basic service information for the group service.
        """
        return FlextResult[dict[str, str]].ok({
            "service": "FlextLdapGroupService",
            "status": "ready",
            "operations": "create_group,get_group,update_group,delete_group,add_member,remove_member,get_members"
        })

    async def create_group(
        self,
        group_request_or_dn: FlextLdapModels.CreateGroupRequest | str,
        cn: str | None = None,
        description: str | None = None,
        members: list[str] | None = None,
    ) -> FlextResult[FlextLdapModels.Group]:
        """Create group using proper service layer - supports both request object and individual parameters."""
        # Handle both request object and individual parameters
        if isinstance(group_request_or_dn, FlextLdapModels.CreateGroupRequest):
            # First overload: request object only
            request = group_request_or_dn
        else:
            # Second overload: individual parameters (cn is required)
            dn = group_request_or_dn
            if cn is None:
                return FlextResult[FlextLdapModels.Group].fail(
                    "cn is required when using individual parameters"
                )
            request = FlextLdapModels.CreateGroupRequest(
                dn=dn,
                cn=cn,
                description=description,
                member_dns=members or [],
            )

        # Validate DN format
        dn_validation = FlextLdapValidations.validate_dn(request.dn)
        if dn_validation.is_failure:
            return FlextResult[FlextLdapModels.Group].fail(f"Invalid DN: {dn_validation.error}")

        # Create LDAP attributes for the group
        attributes: dict[str, list[str] | list[bytes] | str | bytes] = {
            "cn": [request.cn],
            "objectClass": ["groupOfNames"],
        }
        if request.description:
            attributes["description"] = [request.description]
        if request.member_dns:
            attributes["member"] = request.member_dns
        else:
            # Add a dummy member since groupOfNames requires at least one member
            attributes["member"] = ["cn=dummy"]

        # Railway pattern: add entry >> create group object
        add_result = await self._client.add_entry(request.dn, attributes)
        return (
            add_result >> (lambda _: self._create_group_object(request))
        ).with_context(lambda err: f"Failed to create group {request.dn}: {err}")

    def _create_group_object(
        self, request: FlextLdapModels.CreateGroupRequest
    ) -> FlextResult[FlextLdapModels.Group]:
        """Create group object from request - railway helper method."""
        created_group = FlextLdapModels.Group(
            id=f"group_{request.dn.replace(',', '_').replace('=', '_')}",
            dn=request.dn,
            cn=request.cn,
            description=request.description,
            members=request.member_dns,
            modified_at=None,
        )
        return FlextResult[FlextLdapModels.Group].ok(created_group)

    async def get_group(self, dn: str) -> FlextResult[FlextLdapModels.Group | None]:
        """Get group by DN."""
        # Validate DN format
        dn_validation = FlextLdapValidations.validate_dn(dn)
        if dn_validation.is_failure:
            return FlextResult[FlextLdapModels.Group | None].fail(f"Invalid DN: {dn_validation.error}")

        # Search for the group by DN
        search_request = FlextLdapModels.SearchRequest(
            base_dn=dn,
            filter_str="(objectClass=groupOfNames)",
            scope="base",
            attributes=["cn", "description", "member"],
            size_limit=1,
            time_limit=30,
        )

        # Railway pattern: search >> process entries >> convert to group
        search_result = await self._client.search_with_request(search_request)
        return (
            search_result
            >> (lambda response: self._process_group_search_entries(response, dn))
        ).with_context(lambda err: f"Failed to get group {dn}: {err}")

    def _process_group_search_entries(
        self, search_response: FlextLdapModels.SearchResponse, dn: str
    ) -> FlextResult[FlextLdapModels.Group | None]:
        """Process search response entries for group retrieval - railway helper method."""
        if not search_response.entries:
            return FlextResult[FlextLdapModels.Group | None].ok(None)

        # Convert the first entry to a Group object
        entry = search_response.entries[0]
        cn = self._get_entry_attribute(entry, "cn", "unknown")
        description = self._get_entry_attribute(entry, "description")
        members = self._get_entry_attribute_list(entry, "member")

        group = FlextLdapModels.Group(
            id=f"group_{dn.replace(',', '_').replace('=', '_')}",
            dn=dn,
            cn=cn,
            description=description if description else None,
            members=members,
            modified_at=None,
        )
        return FlextResult[FlextLdapModels.Group | None].ok(group)

    async def update_group(
        self,
        dn: str,
        attributes: FlextLdapTypes.Entry.AttributeDict,
    ) -> FlextResult[None]:
        """Update group attributes using railway pattern."""
        # Validate DN format
        dn_validation = FlextLdapValidations.validate_dn(dn)
        if dn_validation.is_failure:
            return FlextResult[None].fail(f"Invalid DN: {dn_validation.error}")

        # Railway pattern: modify entry with context
        modify_result = await self._client.modify_entry(dn, attributes)
        return modify_result.with_context(
            lambda err: f"Failed to update group {dn}: {err}"
        )

    async def delete_group(self, dn: str) -> FlextResult[None]:
        """Delete group using railway pattern."""
        # Validate DN format
        dn_validation = FlextLdapValidations.validate_dn(dn)
        if dn_validation.is_failure:
            return FlextResult[None].fail(f"Invalid DN: {dn_validation.error}")

        # Railway pattern: delete entry with context
        delete_result = await self._client.delete(dn)
        return delete_result.with_context(
            lambda err: f"Failed to delete group {dn}: {err}"
        )

    async def add_member(self, group_dn: str, member_dn: str) -> FlextResult[None]:
        """Add member to group using railway pattern."""
        # Validate DNs
        group_dn_validation = FlextLdapValidations.validate_dn(group_dn)
        if group_dn_validation.is_failure:
            return FlextResult[None].fail(f"Invalid group DN: {group_dn_validation.error}")

        member_dn_validation = FlextLdapValidations.validate_dn(member_dn)
        if member_dn_validation.is_failure:
            return FlextResult[None].fail(f"Invalid member DN: {member_dn_validation.error}")

        # Railway pattern: modify group entry with context
        modifications: dict[str, list[str] | list[bytes] | str | bytes] = {
            "member": [member_dn]
        }
        modify_result = await self._client.modify_entry(group_dn, modifications)
        return modify_result.with_context(
            lambda err: f"Failed to add member {member_dn} to group {group_dn}: {err}"
        )

    async def remove_member(self, group_dn: str, member_dn: str) -> FlextResult[None]:
        """Remove member from group using explicit async/await pattern."""
        # Validate DNs
        group_dn_validation = FlextLdapValidations.validate_dn(group_dn)
        if group_dn_validation.is_failure:
            return FlextResult[None].fail(f"Invalid group DN: {group_dn_validation.error}")

        member_dn_validation = FlextLdapValidations.validate_dn(member_dn)
        if member_dn_validation.is_failure:
            return FlextResult[None].fail(f"Invalid member DN: {member_dn_validation.error}")

        # Get group
        group_result = await self.get_group(group_dn)
        if group_result.is_failure:
            return FlextResult[None].fail(
                f"Failed to remove member {member_dn} from group {group_dn}: {group_result.error}"
            )

        group = group_result.unwrap()
        if group is None:
            return FlextResult[None].fail(f"Group {group_dn} not found")

        # Validate member exists
        member_validation = self._validate_member_exists(group, member_dn)
        if member_validation.is_failure:
            return FlextResult[None].fail(
                f"Failed to remove member {member_dn} from group {group_dn}: {member_validation.error}"
            )

        # Remove member from list
        updated_members_result = self._remove_member_from_list(
            member_validation.unwrap(), member_dn
        )
        if updated_members_result.is_failure:
            return FlextResult[None].fail(
                f"Failed to remove member {member_dn} from group {group_dn}: {updated_members_result.error}"
            )

        # Update group members
        update_result = await self._update_group_members(
            group_dn, updated_members_result.unwrap()
        )
        if update_result.is_failure:
            return FlextResult[None].fail(
                f"Failed to remove member {member_dn} from group {group_dn}: {update_result.error}"
            )

        return FlextResult[None].ok(None)

    def _validate_member_exists(
        self, group: FlextLdapModels.Group, member_dn: str
    ) -> FlextResult[list[str]]:
        """Validate that member exists in group - railway helper method."""
        if member_dn not in group.members:
            return FlextResult[list[str]].fail(f"Member {member_dn} not found in group")
        return FlextResult[list[str]].ok(group.members)

    def _remove_member_from_list(
        self, members: list[str], member_dn: str
    ) -> FlextResult[list[str]]:
        """Remove member from list - railway helper method."""
        updated_members = [m for m in members if m != member_dn]
        return FlextResult[list[str]].ok(updated_members)

    async def _update_group_members(
        self, group_dn: str, members: list[str]
    ) -> FlextResult[None]:
        """Update group members - railway helper method."""
        modifications: dict[str, list[str] | list[bytes] | str | bytes] = {
            "member": members if members else ["cn=dummy"]
        }
        return await self._client.modify_entry(group_dn, modifications)

    async def get_members(self, group_dn: str) -> FlextResult[list[str]]:
        """Get group members using railway pattern."""
        # Railway pattern: get group >> extract members
        group_result = await self.get_group(group_dn)
        return (group_result >> self._extract_group_members).with_context(
            lambda err: f"Failed to get members for group {group_dn}: {err}"
        )

    def _extract_group_members(
        self, group: FlextLdapModels.Group | None
    ) -> FlextResult[list[str]]:
        """Extract members from group - railway helper method."""
        if group is None:
            return FlextResult[list[str]].fail("Group not found")
        return FlextResult[list[str]].ok(group.members)

    async def group_exists(self, dn: str) -> FlextResult[bool]:
        """Check if group exists at DN using railway pattern."""
        # Railway pattern: get group >> check existence
        group_result = await self.get_group(dn)
        return (
            group_result >> (lambda group: FlextResult[bool].ok(group is not None))
        ).with_context(lambda err: f"Failed to check if group exists at {dn}: {err}")

    def _get_entry_attribute(
        self,
        entry: FlextLdapTypes.Core.Dict | FlextLdapModels.Entry,
        key: str,
        default: str = "",
    ) -> str:
        """Extract string attribute from entry using FlextResult monadic pipeline."""
        # Railway pattern: extract value >> convert to string >> unwrap with default
        extract_result = self._extract_entry_value(entry, key)
        return (
            extract_result >> self._convert_to_safe_string
        ).unwrap_or(default)

    def _get_entry_attribute_list(
        self,
        entry: FlextLdapTypes.Core.Dict | FlextLdapModels.Entry,
        key: str,
    ) -> list[str]:
        """Extract list attribute from entry."""
        # Handle FlextLdapModels.Entry type
        if isinstance(entry, FlextLdapModels.Entry):
            attr_values = entry.attributes.get(key, [])
            return [str(value) for value in attr_values if value]

        # Handle dict type
        dict_value: object = entry.get(key, [])
        if isinstance(dict_value, list):
            return [str(value) for value in dict_value if value]
        if dict_value:
            return [str(dict_value)]
        return []

    def _extract_entry_value(
        self, entry: FlextLdapTypes.Core.Dict | FlextLdapModels.Entry, key: str
    ) -> FlextResult[object]:
        """Extract value from entry using type checking."""
        # Handle FlextLdapModels.Entry type
        if isinstance(entry, FlextLdapModels.Entry):
            attr_values = entry.attributes.get(key, [])
            value = attr_values[0] if attr_values else None
            return (
                FlextResult[object].ok(value)
                if value is not None
                else FlextResult[object].fail("No value found")
            )

        # Handle dict type (covers all remaining cases based on type annotation)
        dict_value: object = entry.get(key)
        return (
            FlextResult[object].ok(dict_value)
            if dict_value is not None
            else FlextResult[object].fail("No value found")
        )

    def _convert_to_safe_string(self, raw_value: object) -> FlextResult[str]:
        """Convert value to string using FlextResult railway pattern."""
        # Railway pattern: process through type handlers >> convert to string
        result = (
            FlextResult[object].ok(raw_value)
            >> self._handle_string_type
            >> self._handle_bytes_type
            >> self._handle_list_type
            >> self._handle_numeric_type
            >> (lambda value: FlextResult[str].ok(str(value)))
        )

        return result.with_context(lambda err: f"String conversion failed: {err}")

    def _handle_string_type(self, value: object) -> FlextResult[object]:
        """Handle string type conversion."""
        if isinstance(value, str):
            return (
                FlextResult[object].ok(value)
                if value
                else FlextResult[object].fail("Empty string")
            )
        return FlextResult[object].ok(value)  # Pass through for next handler

    def _handle_bytes_type(self, value: object) -> FlextResult[object]:
        """Handle bytes type conversion."""
        if isinstance(value, bytes):
            return FlextResult[object].ok(value.decode("utf-8", errors="replace"))
        return FlextResult[object].ok(value)  # Pass through for next handler

    def _handle_list_type(self, value: object) -> FlextResult[object]:
        """Handle list type conversion."""
        if isinstance(value, list):
            if not value:
                return FlextResult[object].fail("Empty list")
            first_element = value[0]
            if first_element is None or first_element == "":
                return FlextResult[object].fail("List contains None or empty first element")
            return FlextResult[object].ok(str(first_element))
        return FlextResult[object].ok(value)  # Pass through for next handler

    def _handle_numeric_type(self, value: object) -> FlextResult[object]:
        """Handle numeric type conversion."""
        if isinstance(value, (int, float, bool)):
            return FlextResult[object].ok(str(value))
        return FlextResult[object].ok(value)  # Pass through for next handler

    async def batch_create_groups(
        self, group_requests: list[FlextLdapModels.CreateGroupRequest]
    ) -> FlextResult[list[FlextLdapModels.Group]]:
        """Create multiple groups using monadic traverse pattern."""
        results: list[FlextLdapModels.Group] = []
        for request in group_requests:
            result = await self.create_group(request)
            if result.is_failure:
                return FlextResult[list[FlextLdapModels.Group]].fail(
                    f"Group creation failed: {result.error}"
                )
            results.append(result.unwrap())
        return FlextResult[list[FlextLdapModels.Group]].ok(results)

    async def batch_add_members(
        self, operations: list[tuple[str, str]]
    ) -> FlextResult[list[None]]:
        """Add multiple members to groups using monadic traverse pattern."""
        results: list[None] = []
        for group_dn, member_dn in operations:
            result = await self.add_member(group_dn, member_dn)
            if result.is_failure:
                return FlextResult[list[None]].fail(
                    f"Member addition failed: {result.error}"
                )
            results.append(result.unwrap())
        return FlextResult[list[None]].ok(results)

    async def batch_remove_members(
        self, operations: list[tuple[str, str]]
    ) -> FlextResult[list[None]]:
        """Remove multiple members from groups using monadic traverse pattern."""
        results: list[None] = []
        for group_dn, member_dn in operations:
            result = await self.remove_member(group_dn, member_dn)
            if result.is_failure:
                return FlextResult[list[None]].fail(
                    f"Member removal failed: {result.error}"
                )
            results.append(result.unwrap())
        return FlextResult[list[None]].ok(results)

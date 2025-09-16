"""Class for all LDAP repository functionality.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

import asyncio
from typing import cast

from flext_core import (
    FlextLogger,
    FlextMixins,
    FlextProtocols,
    FlextResult,
)

from flext_ldap.clients import FlextLDAPClient
from flext_ldap.entities import FlextLDAPEntities
from flext_ldap.typings import LdapAttributeDict
from flext_ldap.value_objects import FlextLDAPValueObjects

# Python 3.13 type aliases
type SearchResult = FlextResult[FlextLDAPEntities.Entry | None]
type SaveResult = FlextResult[None]

# FlextLogger available via FlextMixins.Service inheritance


class FlextLDAPRepositories(FlextMixins.Service):
    """LDAP repositories container with nested repository classes.

    Contains Repository, UserRepository, and GroupRepository classes.
    Uses FlextMixins.Service for logging capabilities from flext-core.
    """

    def __init__(self, client: FlextLDAPClient, **data: object) -> None:
        """Initialize repositories container with LDAP client."""
        super().__init__(**data)
        self._client = client
        self._base_repo = self.Repository(client)
        self._user_repo = self.UserRepository(self._base_repo)
        self._group_repo = self.GroupRepository(self._base_repo)

    @property
    def repository(self) -> "FlextLDAPRepositories.Repository":
        """Get base repository."""
        return self._base_repo

    @property
    def users(self) -> "FlextLDAPRepositories.UserRepository":
        """Get user repository."""
        return self._user_repo

    @property
    def groups(self) -> "FlextLDAPRepositories.GroupRepository":
        """Get group repository."""
        return self._group_repo

    # ==========================================================================
    # FACADE METHODS - Delegate to base repository for convenience
    # ==========================================================================

    async def find_by_dn(self, dn: str) -> FlextResult[FlextLDAPEntities.Entry | None]:
        """Find entry by DN - facade method delegating to repository public interface."""
        return await self._base_repo.find_by_dn(dn)

    async def search(
        self, request: FlextLDAPEntities.SearchRequest
    ) -> FlextResult[FlextLDAPEntities.SearchResponse]:
        """Search entries - facade method delegating to repository."""
        return await self._base_repo.search(request)

    async def save_async(self, entity: FlextLDAPEntities.Entry) -> FlextResult[None]:
        """Save entry - facade method delegating to repository public interface."""
        return await self._base_repo.save_async(entity)

    async def delete_async(self, dn: str) -> FlextResult[None]:
        """Delete entry - facade method delegating to repository public interface."""
        return await self._base_repo.delete_async(dn)

    async def exists(self, dn: str) -> FlextResult[bool]:
        """Check if entry exists - facade method delegating to repository public interface."""
        result = await self._base_repo.find_by_dn(dn)
        if not result.is_success:
            return FlextResult[bool].fail(result.error or "Find failed")
        return FlextResult[bool].ok(result.value is not None)

    async def update(self, dn: str, attributes: LdapAttributeDict) -> FlextResult[None]:
        """Update entry attributes - facade method delegating to repository."""
        return await self._base_repo.update_attributes(dn, attributes)

    class Repository(
        FlextMixins.Service,
        FlextProtocols.Domain.Repository[FlextLDAPEntities.Entry],
    ):
        """Base LDAP repository implementing Domain.Repository protocol from flext-core.

        Implements FlextProtocols.Domain.Repository[Entry] protocol correctly without duplication.
        Uses FlextMixins.Service for logging capabilities from flext-core.
        Single consolidated class
        """

        def __init__(self, client: FlextLDAPClient, **data: object) -> None:
            """Initialize repository with LDAP client and FlextMixins.Service."""
            super().__init__(**data)
            self._client = client
            self._logger = FlextLogger(__name__)
            # For test compatibility - user/group repositories can access main repository via _repo
            self._repo = self

        # ==========================================================================
        # DOMAIN.REPOSITORY PROTOCOL IMPLEMENTATION - FlextProtocols.Domain.Repository
        # ==========================================================================

        # Protocol methods from FlextProtocols.Domain.Repository[FlextLDAPEntities.Entry]
        def get_by_id(self, entity_id: str) -> FlextResult[FlextLDAPEntities.Entry]:
            """Get entry by ID (DN) - implements FlextProtocols.Domain.Repository."""
            try:
                result = asyncio.run(self._find_by_dn_async(entity_id))
                if result.is_success and result.value:
                    return FlextResult[FlextLDAPEntities.Entry].ok(result.value)
                return FlextResult[FlextLDAPEntities.Entry].fail("Entry not found")
            except Exception as e:
                return FlextResult[FlextLDAPEntities.Entry].fail(
                    f"Failed to get by ID: {e}"
                )

        def save(
            self, entity: FlextLDAPEntities.Entry
        ) -> FlextResult[FlextLDAPEntities.Entry]:
            """Save entry - implements FlextProtocols.Domain.Repository."""
            try:
                result = asyncio.run(self._save_async(entity))
                if result.is_success:
                    return FlextResult[FlextLDAPEntities.Entry].ok(entity)
                return FlextResult[FlextLDAPEntities.Entry].fail(
                    result.error or "Save failed"
                )
            except Exception as e:
                return FlextResult[FlextLDAPEntities.Entry].fail(f"Failed to save: {e}")

        def delete(self, entity_id: str) -> FlextResult[None]:
            """Delete entry by ID - implements FlextProtocols.Domain.Repository."""
            try:
                return asyncio.run(self._delete_async(entity_id))
            except Exception as e:
                return FlextResult[None].fail(f"Failed to delete: {e}")

        def find_all(self) -> FlextResult[list[FlextLDAPEntities.Entry]]:
            """Find all entries - not practical for LDAP, returns empty list."""
            return FlextResult[list[FlextLDAPEntities.Entry]].ok([])

        # ==========================================================================
        # PUBLIC ASYNC INTERFACE - SOLID Interface Segregation Principle
        # ==========================================================================

        async def save_async(
            self, entity: FlextLDAPEntities.Entry
        ) -> FlextResult[None]:
            """Save entry - public async interface exposing private implementation."""
            return await self._save_async(entity)

        async def find_by_dn(
            self, dn: str
        ) -> FlextResult[FlextLDAPEntities.Entry | None]:
            """Find entry by DN - public async interface exposing private implementation."""
            return await self._find_by_dn_async(dn)

        async def delete_async(self, dn: str) -> FlextResult[None]:
            """Delete entry - public async interface exposing private implementation."""
            return await self._delete_async(dn)

        async def update(
            self, dn: str, attributes: LdapAttributeDict
        ) -> FlextResult[None]:
            """Update entry attributes - async method for Repository."""
            return await self.update_attributes(dn, attributes)

        # ==========================================================================
        # PRIVATE ASYNC METHODS - LDAP-specific implementation details
        # ==========================================================================

        async def _find_by_dn_async(
            self, dn: str
        ) -> FlextResult[FlextLDAPEntities.Entry | None]:
            """Find entry by DN - internal async implementation."""
            # Validate DN using value object
            dn_validation = FlextLDAPValueObjects.DistinguishedName.create(dn)
            if not dn_validation.is_success:
                return FlextResult.fail(f"Invalid DN format: {dn_validation.error}")

            # Create search request for specific entry
            search_request = FlextLDAPEntities.SearchRequest(
                base_dn=dn,
                scope="base",
                filter_str="(objectClass=*)",
                attributes=None,
                size_limit=1,
                time_limit=30,
            )

            search_result = await self._client.search_with_request(search_request)
            if not search_result.is_success:
                error_msg = search_result.error or "Search failed"
                # LDAP error 32 = No such object
                if "No such object" in error_msg or "32" in error_msg:
                    return FlextResult.ok(None)
                return FlextResult.fail(error_msg)

            if not search_result.value.entries:
                return FlextResult.ok(None)

            # Convert to entry using Python 3.13 pattern matching
            entry_data = search_result.value.entries[0]

            # Extract object classes with pattern matching
            match entry_data.get("objectClass"):
                case list() as oc_list:
                    object_classes = [str(oc) for oc in oc_list]
                case str() | bytes() as oc_single:
                    object_classes = [str(oc_single)]
                case None:
                    object_classes = []
                case other_value:
                    object_classes = [str(other_value)]

            # Create entry using domain entities
            attributes = {k: v for k, v in entry_data.items() if k != "dn"}

            entry = FlextLDAPEntities.Entry(
                id=f"repo_{dn.replace(',', '_').replace('=', '_')}",
                dn=dn,
                object_classes=object_classes,
                attributes=cast("LdapAttributeDict", attributes),
                modified_at=None,
            )

            self._logger.debug("Found entry by DN", extra={"dn": dn})
            return FlextResult.ok(entry)

        async def _save_async(
            self, entry: FlextLDAPEntities.Entry
        ) -> FlextResult[None]:
            """Save entry - internal async implementation."""
            # Validate entry business rules
            validation_result = entry.validate_business_rules()
            if not validation_result.is_success:
                return FlextResult.fail(
                    f"Entry validation failed: {validation_result.error}"
                )

            # Check if entry exists
            existing_result = await self._find_by_dn_async(entry.dn)
            if not existing_result.is_success:
                return FlextResult.fail(
                    f"Could not check if entry exists: {existing_result.error}"
                )

            # Prepare LDAP attributes
            attributes: LdapAttributeDict = dict(entry.attributes)
            if entry.object_classes:
                attributes["objectClass"] = entry.object_classes

            # Create or update entry
            if existing_result.value:
                result = await self._client.modify_entry(entry.dn, attributes)
                if result.is_success:
                    self._logger.info("Entry updated", extra={"dn": entry.dn})
            else:
                result = await self._client.add_entry(entry.dn, attributes)
                if result.is_success:
                    self._logger.info("Entry created", extra={"dn": entry.dn})

            return result

        async def _delete_async(self, dn: str) -> FlextResult[None]:
            """Delete entry - internal async implementation."""
            # Validate DN format
            dn_validation = FlextLDAPValueObjects.DistinguishedName.create(dn)
            if not dn_validation.is_success:
                return FlextResult.fail(f"Invalid DN format: {dn_validation.error}")

            result = await self._client.delete(dn)
            if result.is_success:
                self._logger.info("Entry deleted", extra={"dn": dn})

            return result

        # ==========================================================================
        # LDAP-SPECIFIC DOMAIN METHODS - Direct implementation without wrappers
        # ==========================================================================

        async def search(
            self, request: FlextLDAPEntities.SearchRequest
        ) -> FlextResult[FlextLDAPEntities.SearchResponse]:
            """Search LDAP entries directly."""
            search_result = await self._client.search_with_request(request)
            if search_result.is_success:
                self._logger.debug(
                    "Search completed",
                    extra={
                        "base_dn": request.base_dn,
                        "filter": request.filter_str,
                        "count": search_result.value.total_count,
                    },
                )
            return search_result

        async def update_attributes(
            self, dn: str, attributes: LdapAttributeDict
        ) -> FlextResult[None]:
            """Update LDAP entry attributes directly."""
            # Validate DN format
            dn_validation = FlextLDAPValueObjects.DistinguishedName.create(dn)
            if not dn_validation.is_success:
                return FlextResult[None].fail(
                    f"Invalid DN format: {dn_validation.error}"
                )

            # Verify entry exists first
            find_result = await self._find_by_dn_async(dn)
            if not find_result.is_success:
                return FlextResult[None].fail(
                    find_result.error or "Entry lookup failed"
                )

            if not find_result.value:
                return FlextResult[None].fail(f"Entry does not exist: {dn}")

            result = await self._client.modify_entry(dn, attributes)
            if result.is_success:
                self._logger.info(
                    "Entry attributes updated",
                    extra={
                        "dn": dn,
                        "attributes": list(attributes.keys()),
                    },
                )
            return result

    class UserRepository(FlextMixins.Service):
        """User-specific repository operations."""

        def __init__(
            self, base_repo: "FlextLDAPRepositories.Repository", **data: object
        ) -> None:
            """Initialize user repository with base repository."""
            super().__init__(**data)
            self._repo = base_repo

        async def find_user_by_uid(
            self, uid: str, base_dn: str
        ) -> FlextResult[FlextLDAPEntities.Entry | None]:
            """Find user by UID."""
            search_request = FlextLDAPEntities.SearchRequest(
                base_dn=base_dn,
                filter_str=f"(&(objectClass=person)(uid={uid}))",
                scope="subtree",
                attributes=["uid", "cn", "sn", "mail"],
                size_limit=1,
                time_limit=30,
            )

            search_result = await self._repo.search(search_request)
            if not search_result.is_success:
                return FlextResult[FlextLDAPEntities.Entry | None].fail(
                    search_result.error or "Search failed"
                )

            if not search_result.value.entries:
                return FlextResult[FlextLDAPEntities.Entry | None].ok(None)

            # Convert first result to Entry
            entry_data = search_result.value.entries[0]
            dn_raw = entry_data.get("dn", "")
            dn = str(dn_raw) if dn_raw is not None else ""

            entry = FlextLDAPEntities.Entry(
                id=f"user_{uid}",
                dn=dn,
                object_classes=["person", "organizationalPerson"],
                attributes=cast(
                    "LdapAttributeDict",
                    {k: v for k, v in entry_data.items() if k != "dn"},
                ),
                modified_at=None,
            )

            return FlextResult[FlextLDAPEntities.Entry | None].ok(entry)

        async def find_users_by_filter(
            self, filter_str: str, base_dn: str
        ) -> FlextResult[list[FlextLDAPEntities.Entry]]:
            """Find users by custom filter."""
            search_request = FlextLDAPEntities.SearchRequest(
                base_dn=base_dn,
                filter_str=filter_str,
                scope="subtree",
                attributes=["uid", "cn", "sn", "mail"],
                size_limit=100,
                time_limit=30,
            )

            search_result = await self._repo.search(search_request)
            if not search_result.is_success:
                return FlextResult[list[FlextLDAPEntities.Entry]].fail(
                    search_result.error or "Search failed"
                )

            users = []
            for entry_data in search_result.value.entries:
                dn_raw = entry_data.get("dn", "")
                dn = str(dn_raw) if dn_raw is not None else ""
                uid_raw = entry_data.get("uid", "unknown")
                uid = str(uid_raw) if uid_raw is not None else "unknown"

                entry = FlextLDAPEntities.Entry(
                    id=f"user_{uid}",
                    dn=dn,
                    object_classes=["person", "organizationalPerson"],
                    attributes=cast(
                        "LdapAttributeDict",
                        {k: v for k, v in entry_data.items() if k != "dn"},
                    ),
                    modified_at=None,
                )
                users.append(entry)

            return FlextResult[list[FlextLDAPEntities.Entry]].ok(users)

    class GroupRepository(FlextMixins.Service):
        """Group-specific repository operations."""

        def __init__(
            self, base_repo: "FlextLDAPRepositories.Repository", **data: object
        ) -> None:
            """Initialize group repository with base repository."""
            super().__init__(**data)
            self._repo = base_repo

        async def find_group_by_cn(
            self, cn: str, base_dn: str
        ) -> FlextResult[FlextLDAPEntities.Entry | None]:
            """Find group by common name."""
            search_request = FlextLDAPEntities.SearchRequest(
                base_dn=base_dn,
                filter_str=f"(&(objectClass=groupOfNames)(cn={cn}))",
                scope="subtree",
                attributes=["cn", "description", "member"],
                size_limit=1,
                time_limit=30,
            )

            search_result = await self._repo.search(search_request)
            if not search_result.is_success:
                return FlextResult[FlextLDAPEntities.Entry | None].fail(
                    search_result.error or "Search failed"
                )

            if not search_result.value.entries:
                return FlextResult[FlextLDAPEntities.Entry | None].ok(None)

            # Convert first result to Entry
            entry_data = search_result.value.entries[0]
            dn_raw = entry_data.get("dn", "")
            dn = str(dn_raw) if dn_raw is not None else ""

            entry = FlextLDAPEntities.Entry(
                id=f"group_{cn}",
                dn=dn,
                object_classes=["groupOfNames"],
                attributes=cast(
                    "LdapAttributeDict",
                    {k: v for k, v in entry_data.items() if k != "dn"},
                ),
                modified_at=None,
            )

            return FlextResult[FlextLDAPEntities.Entry | None].ok(entry)

        async def find_groups_by_filter(
            self, filter_str: str, base_dn: str
        ) -> FlextResult[list[FlextLDAPEntities.Entry]]:
            """Find groups by custom filter."""
            search_request = FlextLDAPEntities.SearchRequest(
                base_dn=base_dn,
                filter_str=filter_str,
                scope="subtree",
                attributes=["cn", "description", "member"],
                size_limit=100,
                time_limit=30,
            )

            search_result = await self._repo.search(search_request)
            if not search_result.is_success:
                return FlextResult[list[FlextLDAPEntities.Entry]].fail(
                    search_result.error or "Search failed"
                )

            groups = []
            for entry_data in search_result.value.entries:
                dn_raw = entry_data.get("dn", "")
                dn = str(dn_raw) if dn_raw is not None else ""
                cn_raw = entry_data.get("cn", "unknown")
                cn = str(cn_raw) if cn_raw is not None else "unknown"

                entry = FlextLDAPEntities.Entry(
                    id=f"group_{cn}",
                    dn=dn,
                    object_classes=["groupOfNames"],
                    attributes=cast(
                        "LdapAttributeDict",
                        {k: v for k, v in entry_data.items() if k != "dn"},
                    ),
                    modified_at=None,
                )
                groups.append(entry)

            return FlextResult[list[FlextLDAPEntities.Entry]].ok(groups)

        async def get_group_members(self, group_dn: str) -> FlextResult[list[str]]:
            """Get group members using base repository - no duplication."""
            # Find the group first to get member list
            search_request = FlextLDAPEntities.SearchRequest(
                base_dn=group_dn,
                filter_str="(objectClass=groupOfNames)",
                scope="base",
                attributes=["member"],
                size_limit=1,
                time_limit=30,
            )

            search_result = await self._repo.search(search_request)
            if not search_result.is_success:
                return FlextResult[list[str]].fail(
                    search_result.error or "Failed to search group"
                )

            if not search_result.value.entries:
                return FlextResult[list[str]].fail("Group not found")

            # Extract member list from entry
            entry_data = search_result.value.entries[0]
            member_raw = entry_data.get("member", [])

            # Handle different member data types
            members: list[str] = []
            if isinstance(member_raw, list):
                members = [str(m) for m in member_raw if m is not None]
            elif isinstance(member_raw, str):
                members = [member_raw]
            elif member_raw is not None:
                members = [str(member_raw)]

            return FlextResult[list[str]].ok(members)

        async def add_member_to_group(
            self, group_dn: str, member_dn: str
        ) -> FlextResult[None]:
            """Add member to group using base repository - no duplication."""
            # First get current members
            current_members_result = await self.get_group_members(group_dn)
            if not current_members_result.is_success:
                return FlextResult[None].fail(
                    f"Failed to get current members: {current_members_result.error}"
                )

            current_members = current_members_result.unwrap()

            # Check if member already exists
            if member_dn in current_members:
                return FlextResult[None].ok(None)  # Already a member

            # Add new member to list
            updated_members = [*current_members, member_dn]

            # Update group with new member list
            attributes: LdapAttributeDict = {"member": updated_members}
            update_result = await self._repo.update(group_dn, attributes)

            if not update_result.is_success:
                return FlextResult[None].fail(
                    f"Failed to update group: {update_result.error}"
                )

            return FlextResult[None].ok(None)


__all__ = [
    "FlextLDAPRepositories",
]

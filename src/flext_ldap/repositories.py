"""LDAP repository implementations following Repository pattern."""

from __future__ import annotations

from typing import cast, override

from flext_core import FlextEntityId, FlextEntityStatus, FlextResult, get_logger

from flext_ldap.clients import FlextLdapClient
from flext_ldap.entities import (
    FlextLdapEntry,
    FlextLdapSearchRequest,
    FlextLdapSearchResponse,
)
from flext_ldap.interfaces import IFlextLdapRepository
from flext_ldap.typings import LdapAttributeDict
from flext_ldap.value_objects import FlextLdapDistinguishedName

logger = get_logger(__name__)


class FlextLdapRepository(IFlextLdapRepository):
    """LDAP repository implementation using dependency injection."""

    def __init__(self, client: FlextLdapClient) -> None:
        """Initialize repository with LDAP client."""
        self._client = client

    @override
    async def find_by_dn(self, dn: str) -> FlextResult[FlextLdapEntry | None]:
        """Find entry by distinguished name."""
        # Validate DN format
        dn_validation = FlextLdapDistinguishedName.create(dn)
        if not dn_validation.is_success:
            return FlextResult[FlextLdapEntry | None].fail(
                f"Invalid DN format: {dn_validation.error}",
            )

        # Search for the specific entry
        search_request = FlextLdapSearchRequest(
            base_dn=dn,
            scope="base",
            filter_str="(objectClass=*)",
            attributes=None,
            size_limit=1,
            time_limit=30,
        )

        search_result = await self._client.search(search_request)
        if not search_result.is_success:
            error_msg = search_result.error or "Search failed"
            if "No such object" in error_msg or "32" in error_msg:
                return FlextResult[FlextLdapEntry | None].ok(None)
            return FlextResult[FlextLdapEntry | None].fail(error_msg)

        if not search_result.value.entries:
            return FlextResult[FlextLdapEntry | None].ok(None)

        # Convert search result to entry
        entry_data = search_result.value.entries[0]
        typed_entry: dict[str, object] = cast("dict[str, object]", entry_data)

        # Extract object classes
        object_classes = []
        if "objectClass" in typed_entry:
            oc_value = typed_entry["objectClass"]
            if isinstance(oc_value, list):
                typed_oc_list: list[object] = cast("list[object]", oc_value)
                object_classes = [str(oc) for oc in typed_oc_list]
            else:
                object_classes = [str(oc_value)]

        # Create entry
        entry = FlextLdapEntry(
            id=FlextEntityId(f"repo_entry_{dn.replace(',', '_').replace('=', '_')}"),
            dn=dn,
            object_classes=object_classes,
            attributes=dict(entry_data),
            status=FlextEntityStatus.ACTIVE,
        )

        logger.debug("Found entry by DN", extra={"dn": dn})
        return FlextResult[FlextLdapEntry | None].ok(entry)

    @override
    async def search(
        self,
        request: FlextLdapSearchRequest,
    ) -> FlextResult[FlextLdapSearchResponse]:
        """Search entries with criteria."""
        search_result = await self._client.search(request)
        if not search_result.is_success:
            return FlextResult[FlextLdapSearchResponse].fail(
                search_result.error or "Search failed",
            )

        logger.debug(
            "Search completed",
            extra={
                "base_dn": request.base_dn,
                "filter": request.filter_str,
                "count": search_result.value.total_count,
            },
        )
        return search_result

    @override
    async def save(self, entry: FlextLdapEntry) -> FlextResult[None]:
        """Save entry to LDAP directory."""
        # Validate entry business rules
        validation_result = entry.validate_business_rules()
        if not validation_result.is_success:
            return FlextResult[None].fail(
                f"Entry validation failed: {validation_result.error}",
            )

        # Check if entry exists
        existing = await self.exists(entry.dn)
        if not existing.is_success:
            return FlextResult[None].fail(
                f"Could not check if entry exists: {existing.error}",
            )

        # Prepare attributes including object classes
        # Convert entry attributes to LDAP format
        attributes: LdapAttributeDict = {}
        for key, value in entry.attributes.items():
            if isinstance(value, (str, bytes, list)):
                attributes[key] = value  # Type validated by isinstance check

        if entry.object_classes:
            attributes["objectClass"] = entry.object_classes

        # Use value directly since we already checked success
        if existing.value:
            # Update existing entry
            result = await self._client.modify(entry.dn, attributes)
            if result.is_success:
                logger.info("Entry updated", extra={"dn": entry.dn})
        else:
            # Create new entry
            result = await self._client.add(entry.dn, attributes)
            if result.is_success:
                logger.info("Entry created", extra={"dn": entry.dn})

        return result

    @override
    async def delete(self, dn: str) -> FlextResult[None]:
        """Delete entry from LDAP directory."""
        # Validate DN format
        dn_validation = FlextLdapDistinguishedName.create(dn)
        if not dn_validation.is_success:
            return FlextResult[None].fail(f"Invalid DN format: {dn_validation.error}")

        result = await self._client.delete(dn)
        if result.is_success:
            logger.info("Entry deleted", extra={"dn": dn})

        return result

    @override
    async def exists(self, dn: str) -> FlextResult[bool]:
        """Check if entry exists."""
        find_result = await self.find_by_dn(dn)
        if not find_result.is_success:
            return FlextResult[bool].fail(find_result.error or "Find failed")

        # Check if entry exists (find_result.value is not None)
        return FlextResult[bool].ok(find_result.value is not None)

    @override
    async def update(self, dn: str, attributes: LdapAttributeDict) -> FlextResult[None]:
        """Update entry attributes."""
        # Validate DN format
        dn_validation = FlextLdapDistinguishedName.create(dn)
        if not dn_validation.is_success:
            return FlextResult[None].fail(f"Invalid DN format: {dn_validation.error}")

        # Verify entry exists
        exists_result = await self.exists(dn)
        if not exists_result.is_success:
            return FlextResult[None].fail(exists_result.error or "Exists check failed")

        # Use value directly since we already checked success
        if not exists_result.value:
            return FlextResult[None].fail(f"Entry does not exist: {dn}")

        result = await self._client.modify(dn, attributes)
        if result.is_success:
            logger.info(
                "Entry attributes updated",
                extra={"dn": dn, "attributes": list(attributes.keys())},
            )

        return result


class FlextLdapUserRepository:
    """Specialized repository for LDAP user operations."""

    def __init__(self, base_repository: FlextLdapRepository) -> None:
        """Initialize user repository."""
        self._repo = base_repository

    async def find_user_by_uid(
        self,
        uid: str,
        base_dn: str,
    ) -> FlextResult[FlextLdapEntry | None]:
        """Find user by UID attribute."""
        search_request = FlextLdapSearchRequest(
            base_dn=base_dn,
            scope="subtree",
            filter_str=f"(&(objectClass=inetOrgPerson)(uid={uid}))",
            attributes=None,
            size_limit=1,
            time_limit=30,
        )

        search_result = await self._repo.search(search_request)
        if not search_result.is_success:
            return FlextResult[FlextLdapEntry | None].fail(
                search_result.error or "User search failed",
            )

        if not search_result.value.entries:
            return FlextResult[FlextLdapEntry | None].ok(None)

        # Get the first entry and convert to FlextLdapEntry
        entry_data = search_result.value.entries[0]
        typed_entry_data: dict[str, object] = cast("dict[str, object]", entry_data)
        entry_dn = typed_entry_data.get("dn", "")

        if not entry_dn:
            return FlextResult[FlextLdapEntry | None].fail(
                "Entry DN not found in search results",
            )

        return await self._repo.find_by_dn(str(entry_dn))

    async def find_users_by_filter(
        self,
        ldap_filter: str,
        base_dn: str,
    ) -> FlextResult[list[FlextLdapEntry]]:
        """Find users by custom LDAP filter."""
        search_request = FlextLdapSearchRequest(
            base_dn=base_dn,
            scope="subtree",
            filter_str=f"(&(objectClass=inetOrgPerson){ldap_filter})",
            attributes=None,
            size_limit=1000,
            time_limit=30,
        )

        search_result = await self._repo.search(search_request)
        if not search_result.is_success:
            return FlextResult[list[FlextLdapEntry]].fail(
                search_result.error or "Users search failed",
            )

        entries: list[FlextLdapEntry] = []
        for entry_data in search_result.value.entries:
            typed_entry_data_loop: dict[str, object] = cast(
                "dict[str, object]", entry_data
            )
            entry_dn = typed_entry_data_loop.get("dn")
            if not entry_dn:
                continue

            find_result = await self._repo.find_by_dn(str(entry_dn))
            # Use simplified pattern with .value access
            if find_result.is_success:
                entry = find_result.value
                if entry:
                    entries.append(entry)

        return FlextResult[list[FlextLdapEntry]].ok(entries)


class FlextLdapGroupRepository:
    """Specialized repository for LDAP group operations."""

    def __init__(self, base_repository: FlextLdapRepository) -> None:
        """Initialize group repository."""
        self._repo = base_repository

    async def find_group_by_cn(
        self,
        cn: str,
        base_dn: str,
    ) -> FlextResult[FlextLdapEntry | None]:
        """Find group by CN attribute."""
        search_request = FlextLdapSearchRequest(
            base_dn=base_dn,
            scope="subtree",
            filter_str=f"(&(objectClass=groupOfNames)(cn={cn}))",
            attributes=None,
            size_limit=1,
            time_limit=30,
        )

        search_result = await self._repo.search(search_request)
        if not search_result.is_success:
            return FlextResult[FlextLdapEntry | None].fail(
                search_result.error or "Group search failed",
            )

        if not search_result.value.entries:
            return FlextResult[FlextLdapEntry | None].ok(None)

        # Get the first entry and convert to FlextLdapEntry
        entry_data = search_result.value.entries[0]
        typed_entry_data: dict[str, object] = cast("dict[str, object]", entry_data)
        entry_dn = typed_entry_data.get("dn", "")

        if not entry_dn:
            return FlextResult[FlextLdapEntry | None].fail(
                "Entry DN not found in search results",
            )

        return await self._repo.find_by_dn(str(entry_dn))

    async def get_group_members(self, group_dn: str) -> FlextResult[list[str]]:
        """Get members of a group."""
        entry_result = await self._repo.find_by_dn(group_dn)
        if not entry_result.is_success:
            return FlextResult[list[str]].fail(
                entry_result.error or "Group lookup failed",
            )

        if not entry_result.value:
            return FlextResult[list[str]].fail("Group not found")

        entry = entry_result.value
        members = entry.get_attribute_values("member")

        return FlextResult[list[str]].ok(members)

    async def add_member_to_group(
        self,
        group_dn: str,
        member_dn: str,
    ) -> FlextResult[None]:
        """Add member to group."""
        # Get current members
        members_result = await self.get_group_members(group_dn)
        if not members_result.is_success:
            return FlextResult[None].fail(
                members_result.error or "Members lookup failed",
            )

        current_members = members_result.value
        if member_dn in current_members:
            return FlextResult[None].fail("Member already in group")

        # Add new member
        new_members = [*current_members, member_dn]
        attributes: LdapAttributeDict = {"member": new_members}

        return await self._repo.update(group_dn, attributes)

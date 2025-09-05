"""SINGLE CONSOLIDATED FlextLDAPRepositories class following FLEXT architectural patterns.

FLEXT_REFACTORING_PROMPT.md COMPLIANCE: Single consolidated class for all LDAP repository functionality.
All specialized functionality delivered through internal subclasses within FlextLDAPRepositories.

CONSOLIDATED CLASSES: FlextLDAPRepository + FlextLDAPUserRepository + FlextLDAPGroupRepository
"""

import asyncio
from typing import cast

from flext_core import (
    FlextLogger,
    FlextProcessors,
    FlextProtocols,
    FlextResult,
)

from flext_ldap.clients import FlextLDAPClient
from flext_ldap.entities import FlextLDAPEntities
from flext_ldap.fields import FlextLDAPFields
from flext_ldap.typings import LdapAttributeDict
from flext_ldap.value_objects import FlextLDAPValueObjects

logger = FlextLogger(__name__)


# =============================================================================
# REPOSITORY SEARCH STRATEGIES - Template Method Pattern for Eliminating Duplication
# =============================================================================


class RepositorySearchStrategies:
    """Strategy classes for eliminating 35-line duplication in repository search methods."""

    class _BaseSearchProcessor(FlextProcessors.BaseProcessor):
        """Template Method base class eliminating 35-line duplication across find_* methods."""

        def __init__(self, repo: object) -> None:
            self._repo = repo

        async def process_search(
            self,
            params: FlextLDAPEntities.SearchParams,
        ) -> FlextResult[FlextLDAPEntities.Entry | None]:
            """Template method implementing common search pattern - eliminates duplication."""
            # Step 1: Build search request using parameters
            search_request = self._build_search_request(params)

            # Step 2: Execute search
            search_result = await self._execute_search(search_request)
            if not search_result.is_success:
                return FlextResult.fail(
                    search_result.error or "Search failed",
                )

            # Step 3: Process search results
            if not search_result.value.entries:
                return FlextResult.ok(None)

            # Step 4: Convert entry
            return await self._convert_entry(search_result.value.entries[0])

        def _build_search_request(
            self,
            params: FlextLDAPEntities.SearchParams,
        ) -> FlextLDAPEntities.SearchRequest:
            """Build search request from parameters."""
            return FlextLDAPEntities.SearchRequest(
                base_dn=params.base_dn,
                scope="subtree",
                filter_str=params.search_filter,
                attributes=params.attributes,
                size_limit=params.size_limit,
                time_limit=params.time_limit,
            )

        async def _execute_search(
            self,
            request: FlextLDAPEntities.SearchRequest,
        ) -> FlextResult[FlextLDAPEntities.SearchResponse]:
            """Execute search using repository."""
            repo = cast("FlextLDAPRepositories.Repository", self._repo)
            return await repo.search(request)

        async def _convert_entry(
            self,
            entry_data: object,
        ) -> FlextResult[FlextLDAPEntities.Entry | None]:
            """Convert search result entry to repository entry."""
            typed_entry_data = cast("dict[str, object]", entry_data)
            entry_dn = typed_entry_data.get("dn", "")

            if not entry_dn:
                return FlextResult.fail(
                    "Entry DN not found in search results",
                )

            repo = cast("FlextLDAPRepositories.Repository", self._repo)
            return await repo.find_by_dn(str(entry_dn))


class FlextLDAPRepositories:
    """SINGLE CONSOLIDATED CLASS for all LDAP repository functionality.

    Following FLEXT architectural patterns - consolidates ALL LDAP repository functionality
    including base repository operations, user-specific operations, and group-specific operations
    into one main class with specialized internal subclasses for organization.

    CONSOLIDATED CLASSES: FlextLDAPRepository + FlextLDAPUserRepository + FlextLDAPGroupRepository
    """

    # ==========================================================================
    # INTERNAL SPECIALIZED CLASSES FOR DIFFERENT REPOSITORY DOMAINS
    # ==========================================================================

    class Repository(FlextProtocols.Domain.Repository):  # type: ignore[type-arg]
        """Internal base LDAP repository implementation using dependency injection."""

        def __init__(self, client: FlextLDAPClient) -> None:
            """Initialize repository with LDAP client."""
            self._client = client

        # FlextProtocols.Domain.Repository protocol implementation
        def get_by_id(
            self,
            entity_id: str,
        ) -> FlextResult[FlextLDAPEntities.Entry | None]:
            """Get entity by ID (synchronous wrapper for async find_by_dn)."""
            try:
                return asyncio.run(self.find_by_dn(entity_id))
            except Exception as e:
                return FlextResult.fail(
                    f"Failed to get by ID: {e}",
                )

        def find_all(self) -> FlextResult[list[FlextLDAPEntities.Entry]]:
            """Find all entities - not practical for LDAP, returns error."""
            return FlextResult[list[FlextLDAPEntities.Entry]].fail(
                "find_all not supported for LDAP repositories - use search with filters",
            )

        # LDAP-specific methods (extend protocol functionality)
        async def find_by_dn(
            self,
            dn: str,
        ) -> FlextResult[FlextLDAPEntities.Entry | None]:
            """Find entry by distinguished name."""
            # Validate DN format
            dn_validation = FlextLDAPValueObjects.DistinguishedName.create(dn)
            if not dn_validation.is_success:
                return FlextResult.fail(
                    f"Invalid DN format: {dn_validation.error}",
                )

            # Search for the specific entry
            search_request = FlextLDAPEntities.SearchRequest(
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
                    return FlextResult.ok(None)
                return FlextResult.fail(error_msg)

            if not search_result.value.entries:
                return FlextResult.ok(None)

            # Convert search result to entry
            entry_data = search_result.value.entries[0]
            typed_entry = entry_data

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
            entry = FlextLDAPEntities.Entry(
                id=f"repo_entry_{dn.replace(',', '_').replace('=', '_')}",
                dn=dn,
                object_classes=object_classes,
                attributes=FlextLDAPFields.Processors.normalize_attributes(entry_data),
                modified_at=None,
            )

            logger.debug("Found entry by DN", extra={"dn": dn})
            return FlextResult.ok(entry)

        async def search(
            self,
            request: FlextLDAPEntities.SearchRequest,
        ) -> FlextResult[FlextLDAPEntities.SearchResponse]:
            """Search entries with criteria."""
            search_result = await self._client.search(request)
            if not search_result.is_success:
                return FlextResult.fail(
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

        def save(
            self,
            entity: FlextLDAPEntities.Entry,
        ) -> FlextResult[FlextLDAPEntities.Entry]:
            """Save entity (synchronous wrapper for async save_async)."""
            try:
                result = asyncio.run(self.save_async(entity))
                if result.is_success:
                    return FlextResult.ok(entity)
                return FlextResult.fail(
                    result.error or "Save failed",
                )
            except Exception as e:
                return FlextResult.fail(f"Failed to save: {e}")

        async def save_async(self, entry: FlextLDAPEntities.Entry) -> FlextResult[None]:
            """Save entry to LDAP directory."""
            # Validate entry business rules
            validation_result = entry.validate_business_rules()
            if not validation_result.is_success:
                return FlextResult.fail(
                    f"Entry validation failed: {validation_result.error}",
                )

            # Check if entry exists
            existing = await self.exists(entry.dn)
            if not existing.is_success:
                return FlextResult.fail(
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

        def delete(self, entity_id: str) -> FlextResult[None]:
            """Delete entity by ID (synchronous wrapper for async delete_async)."""
            try:
                return asyncio.run(self.delete_async(entity_id))
            except Exception as e:
                return FlextResult.fail(f"Failed to delete: {e}")

        async def delete_async(self, dn: str) -> FlextResult[None]:
            """Delete entry from LDAP directory."""
            # Validate DN format
            dn_validation = FlextLDAPValueObjects.DistinguishedName.create(dn)
            if not dn_validation.is_success:
                return FlextResult.fail(
                    f"Invalid DN format: {dn_validation.error}",
                )

            result = await self._client.delete(dn)
            if result.is_success:
                logger.info("Entry deleted", extra={"dn": dn})

            return result

        async def exists(self, dn: str) -> FlextResult[bool]:
            """Check if entry exists."""
            find_result = await self.find_by_dn(dn)
            if not find_result.is_success:
                return FlextResult.fail(find_result.error or "Find failed")

            # Check if entry exists (find_result.value is not None)
            return FlextResult.ok(find_result.value is not None)

        async def update(
            self,
            dn: str,
            attributes: LdapAttributeDict,
        ) -> FlextResult[None]:
            """Update entry attributes."""
            # Validate DN format
            dn_validation = FlextLDAPValueObjects.DistinguishedName.create(dn)
            if not dn_validation.is_success:
                return FlextResult.fail(
                    f"Invalid DN format: {dn_validation.error}",
                )

            # Verify entry exists
            exists_result = await self.exists(dn)
            if not exists_result.is_success:
                return FlextResult.fail(
                    exists_result.error or "Exists check failed",
                )

            # Use value directly since we already checked success
            if not exists_result.value:
                return FlextResult.fail(f"Entry does not exist: {dn}")

            result = await self._client.modify(dn, attributes)
            if result.is_success:
                logger.info(
                    "Entry attributes updated",
                    extra={"dn": dn, "attributes": list(attributes.keys())},
                )

            return result

    class UserRepository:
        """Internal specialized repository for LDAP user operations."""

        def __init__(self, base_repository: "FlextLDAPRepositories.Repository") -> None:
            """Initialize user repository."""
            self._repo = base_repository

        async def find_user_by_uid(
            self,
            uid: str,
            base_dn: str,
        ) -> FlextResult[FlextLDAPEntities.Entry | None]:
            """Find user by UID attribute using Template Method Pattern - eliminates 35-line duplication."""
            search_params = FlextLDAPEntities.SearchParams.create_user_search(
                connection_id="repo_connection",
                uid=uid,
                base_dn=base_dn,
                size_limit=1,
                time_limit=30,
            )

            search_processor = RepositorySearchStrategies._BaseSearchProcessor(
                self._repo,
            )
            return await search_processor.process_search(search_params)

        async def find_users_by_filter(
            self,
            ldap_filter: str,
            base_dn: str,
        ) -> FlextResult[list[FlextLDAPEntities.Entry]]:
            """Find users by custom LDAP filter."""
            search_request = FlextLDAPEntities.SearchRequest(
                base_dn=base_dn,
                scope="subtree",
                filter_str=f"(&(objectClass=inetOrgPerson){ldap_filter})",
                attributes=None,
                size_limit=1000,
                time_limit=30,
            )

            search_result = await self._repo.search(search_request)
            if not search_result.is_success:
                return FlextResult[list[FlextLDAPEntities.Entry]].fail(
                    search_result.error or "Users search failed",
                )

            entries: list[FlextLDAPEntities.Entry] = []
            for entry_data in search_result.value.entries:
                typed_entry_data_loop = entry_data
                entry_dn = typed_entry_data_loop.get("dn")
                if not entry_dn:
                    continue

                find_result = await self._repo.find_by_dn(str(entry_dn))
                # Use simplified pattern with .value access
                if find_result.is_success:
                    entry = find_result.value
                    if entry:
                        entries.append(entry)

            return FlextResult[list[FlextLDAPEntities.Entry]].ok(entries)

    class GroupRepository:
        """Internal specialized repository for LDAP group operations."""

        def __init__(self, base_repository: "FlextLDAPRepositories.Repository") -> None:
            """Initialize group repository."""
            self._repo = base_repository

        async def find_group_by_cn(
            self,
            cn: str,
            base_dn: str,
        ) -> FlextResult[FlextLDAPEntities.Entry | None]:
            """Find group by CN attribute using Template Method Pattern - eliminates 35-line duplication."""
            search_params = FlextLDAPEntities.SearchParams.create_group_search(
                connection_id="repo_connection",
                cn=cn,
                base_dn=base_dn,
                size_limit=1,
                time_limit=30,
            )

            search_processor = RepositorySearchStrategies._BaseSearchProcessor(
                self._repo,
            )
            return await search_processor.process_search(search_params)

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
            member_attr = entry.get_attribute("member")

            # Convert attribute value to list of strings
            members: list[str] = []
            if member_attr:
                if isinstance(member_attr, list):
                    members = [str(m) for m in member_attr]
                else:
                    members = [str(member_attr)]

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
                return FlextResult.fail(
                    members_result.error or "Members lookup failed",
                )

            current_members = members_result.value
            if member_dn in current_members:
                return FlextResult.fail("Member already in group")

            # Add new member
            new_members = [*current_members, member_dn]
            attributes: LdapAttributeDict = {"member": new_members}

            return await self._repo.update(group_dn, attributes)

    # ==========================================================================
    # MAIN CONSOLIDATED INTERFACE
    # ==========================================================================

    def __init__(self, client: FlextLDAPClient) -> None:
        """Initialize all repository handlers with consolidated pattern."""
        self._base_repo = self.Repository(client)
        self._user_repo = self.UserRepository(self._base_repo)
        self._group_repo = self.GroupRepository(self._base_repo)

    @property
    def repository(self) -> Repository:
        """Access base repository operations through consolidated interface."""
        return self._base_repo

    @property
    def users(self) -> UserRepository:
        """Access user repository operations through consolidated interface."""
        return self._user_repo

    @property
    def groups(self) -> GroupRepository:
        """Access group repository operations through consolidated interface."""
        return self._group_repo

    # High-level convenience methods for common operations
    async def find_by_dn(self, dn: str) -> FlextResult[FlextLDAPEntities.Entry | None]:
        """Find entry by distinguished name (convenience method)."""
        return await self._base_repo.find_by_dn(dn)

    async def search(
        self,
        request: FlextLDAPEntities.SearchRequest,
    ) -> FlextResult[FlextLDAPEntities.SearchResponse]:
        """Search entries with criteria (convenience method)."""
        return await self._base_repo.search(request)

    async def save_async(self, entry: FlextLDAPEntities.Entry) -> FlextResult[None]:
        """Save entry to LDAP directory (convenience method)."""
        return await self._base_repo.save_async(entry)

    async def delete_async(self, dn: str) -> FlextResult[None]:
        """Delete entry from LDAP directory (convenience method)."""
        return await self._base_repo.delete_async(dn)

    async def exists(self, dn: str) -> FlextResult[bool]:
        """Check if entry exists (convenience method)."""
        return await self._base_repo.exists(dn)

    async def update(self, dn: str, attributes: LdapAttributeDict) -> FlextResult[None]:
        """Update entry attributes (convenience method)."""
        return await self._base_repo.update(dn, attributes)


# =============================================================================
# BACKWARD COMPATIBILITY ALIASES - Following FLEXT consolidation patterns
# =============================================================================

# Export internal classes for external access (backward compatibility)
# Export aliases eliminated - use FlextLDAPRepositories.* directly following flext-core pattern

__all__ = [
    "FlextLDAPRepositories",
]

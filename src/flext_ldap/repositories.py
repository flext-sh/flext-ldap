"""Class for all LDAP repository functionality.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

import asyncio
from typing import cast

from flext_core import (
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


# =============================================================================
# LDAP REPOSITORY USING FLEXT-CORE PATTERNS - ZERO DUPLICATION
# =============================================================================


class FlextLDAPRepositories(
    FlextMixins.Service,
    FlextProtocols.Domain.Repository[FlextLDAPEntities.Entry],
):
    """LDAP repository implementing Domain.Repository protocol from flext-core.

    Implements FlextProtocols.Domain.Repository[Entry] protocol correctly without duplication.
    Uses FlextMixins.Service for logging capabilities from flext-core.
    Single consolidated class following SOLID principles.
    """

    def __init__(self, client: FlextLDAPClient, **data: object) -> None:
        """Initialize repository with LDAP client and FlextMixins.Service."""
        super().__init__(**data)
        self._client = client
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
    # COMPATIBILITY ALIASES FOR TESTS
    # ==========================================================================

    async def save_async(self, entity: FlextLDAPEntities.Entry) -> FlextResult[None]:
        """Compatibility alias for _save_async - test compatibility."""
        return await self._save_async(entity)

    async def update(self, dn: str, attributes: dict) -> FlextResult[None]:
        """Update entry attributes - alias for test compatibility."""
        # Convert dict attributes to Entry and save
        entry = FlextLDAPEntities.Entry(
            id=f"update_{dn.replace(',', '_').replace('=', '_')}",
            dn=dn,
            object_classes=attributes.get("objectClass", []),
            attributes=cast(
                "LdapAttributeDict",
                {k: v for k, v in attributes.items() if k != "objectClass"},
            ),
            modified_at=None,
        )
        return await self._save_async(entry)

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

        # Create entry without FlextLDAPFields dependency
        attributes = {k: v for k, v in entry_data.items() if k != "dn"}

        entry = FlextLDAPEntities.Entry(
            id=f"repo_{dn.replace(',', '_').replace('=', '_')}",
            dn=dn,
            object_classes=object_classes,
            attributes=cast("LdapAttributeDict", attributes),
            modified_at=None,
        )

        self.log_debug("Found entry by DN", dn=dn)
        return FlextResult.ok(entry)

    async def _save_async(self, entry: FlextLDAPEntities.Entry) -> FlextResult[None]:
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
                self.log_info("Entry updated", dn=entry.dn)
        else:
            result = await self._client.add_entry(entry.dn, attributes)
            if result.is_success:
                self.log_info("Entry created", dn=entry.dn)

        return result

    async def _delete_async(self, dn: str) -> FlextResult[None]:
        """Delete entry - internal async implementation."""
        # Validate DN format
        dn_validation = FlextLDAPValueObjects.DistinguishedName.create(dn)
        if not dn_validation.is_success:
            return FlextResult.fail(f"Invalid DN format: {dn_validation.error}")

        result = await self._client.delete(dn)
        if result.is_success:
            self.log_info("Entry deleted", dn=dn)

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
            self.log_debug(
                "Search completed",
                base_dn=request.base_dn,
                filter=request.filter_str,
                count=search_result.value.total_count,
            )
        return search_result

    async def find_by_dn(self, dn: str) -> FlextResult[FlextLDAPEntities.Entry | None]:
        """Find LDAP entry by DN directly."""
        return await self._find_by_dn_async(dn)

    async def exists(self, dn: str) -> FlextResult[bool]:
        """Check if LDAP entry exists directly."""
        result = await self._find_by_dn_async(dn)
        if not result.is_success:
            return FlextResult[bool].fail(result.error or "Find failed")
        return FlextResult[bool].ok(result.value is not None)

    async def update_attributes(
        self, dn: str, attributes: LdapAttributeDict
    ) -> FlextResult[None]:
        """Update LDAP entry attributes directly."""
        # Validate DN format
        dn_validation = FlextLDAPValueObjects.DistinguishedName.create(dn)
        if not dn_validation.is_success:
            return FlextResult[None].fail(f"Invalid DN format: {dn_validation.error}")

        # Verify entry exists first
        exists_result = await self.exists(dn)
        if not exists_result.is_success:
            return FlextResult[None].fail(exists_result.error or "Exists check failed")

        if not exists_result.value:
            return FlextResult[None].fail(f"Entry does not exist: {dn}")

        result = await self._client.modify_entry(dn, attributes)
        if result.is_success:
            self.log_info(
                "Entry attributes updated",
                dn=dn,
                attributes=list(attributes.keys()),
            )
        return result


# =============================================================================
# MODULE EXPORTS - Clean single class export
# =============================================================================

__all__ = [
    "FlextLDAPRepositories",
]

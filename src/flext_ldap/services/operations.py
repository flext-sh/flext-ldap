"""LDAP Operations Service.

This service provides LDAP CRUD operations (search, add, modify, delete).
Delegates to Ldap3Adapter which already handles conversion to Entry models
using FlextLdifParser, maximizing code reuse.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT

"""

from __future__ import annotations

from flext_core import FlextLogger, FlextResult, FlextService
from flext_ldif.models import FlextLdifModels
from flext_ldif.utilities import FlextLdifUtilities

from flext_ldap.constants import FlextLdapConstants
from flext_ldap.models import FlextLdapModels
from flext_ldap.services.connection import FlextLdapConnection


class FlextLdapOperations(FlextService[FlextLdapModels.SearchResult]):
    """LDAP operations service providing CRUD operations.

    Handles search, add, modify, and delete operations.
    Delegates to Ldap3Adapter which already uses FlextLdifParser for conversion.
    This maximizes code reuse - adapter handles all parsing logic.
    """

    _connection: FlextLdapConnection
    _logger: FlextLogger

    def __init__(
        self,
        connection: FlextLdapConnection,
    ) -> None:
        """Initialize operations service.

        Args:
            connection: FlextLdapConnection instance

        """
        super().__init__()
        self._connection = connection
        self._logger = FlextLogger(__name__)

    def search(
        self,
        search_options: FlextLdapModels.SearchOptions,
        server_type: str = FlextLdapConstants.ServerTypes.RFC,
    ) -> FlextResult[FlextLdapModels.SearchResult]:
        """Perform LDAP search operation.

        Delegates to Ldap3Adapter which already converts results to Entry models
        using FlextLdifParser.parse_ldap3_results(), maximizing code reuse.

        Args:
            search_options: Search configuration
            server_type: LDAP server type for parsing (default: RFC constant)

        Returns:
            FlextResult containing SearchResult with Entry models
                (reusing FlextLdifModels.Entry)

        """
        # Normalize base_dn using FlextLdifUtilities.DN
        # Skip validation for performance
        normalized_base_dn = FlextLdifUtilities.DN.norm_string(search_options.base_dn)
        # Update search_options with normalized DN for consistency
        normalized_options = FlextLdapModels.SearchOptions(
            base_dn=normalized_base_dn,
            filter_str=search_options.filter_str,
            scope=search_options.scope,
            attributes=search_options.attributes,
            size_limit=search_options.size_limit,
            time_limit=search_options.time_limit,
        )

        # Adapter handles connection check via _get_connection() - no duplication
        return self._connection.adapter.search(
            normalized_options,
            server_type=server_type,
        ).map(
            lambda entries: FlextLdapModels.SearchResult(
                entries=entries,
                total_count=len(entries),
                search_options=normalized_options,
            ),
        )

    def add(
        self,
        entry: FlextLdifModels.Entry,
    ) -> FlextResult[FlextLdapModels.OperationResult]:
        """Add LDAP entry.

        Delegates to Ldap3Adapter which accepts Entry model directly,
        reusing FlextLdifModels.Entry for type safety.

        Args:
            entry: Entry model to add (reusing FlextLdifModels.Entry)

        Returns:
            FlextResult containing OperationResult

        """
        # Adapter handles connection check via _get_connection() - no duplication
        return self._connection.adapter.add(entry)

    def modify(
        self,
        dn: str | FlextLdifModels.DistinguishedName,
        changes: dict[str, list[tuple[str, list[str]]]],
    ) -> FlextResult[FlextLdapModels.OperationResult]:
        """Modify LDAP entry.

        Args:
            dn: Distinguished name of entry to modify (str or DistinguishedName)
            changes: Modification changes in ldap3 format

        Returns:
            FlextResult containing OperationResult

        """
        # Convert to DistinguishedName model if needed
        dn_model = (
            dn
            if isinstance(dn, FlextLdifModels.DistinguishedName)
            else FlextLdifModels.DistinguishedName(value=dn)
        )

        # Adapter handles connection check via _get_connection() - no duplication
        return self._connection.adapter.modify(dn_model, changes)

    def delete(
        self,
        dn: str | FlextLdifModels.DistinguishedName,
    ) -> FlextResult[FlextLdapModels.OperationResult]:
        """Delete LDAP entry.

        Args:
            dn: Distinguished name of entry to delete (str or DistinguishedName)

        Returns:
            FlextResult containing OperationResult

        """
        # Convert to DistinguishedName model if needed
        dn_model = (
            dn
            if isinstance(dn, FlextLdifModels.DistinguishedName)
            else FlextLdifModels.DistinguishedName(value=dn)
        )

        # Adapter handles connection check via _get_connection() - no duplication
        return self._connection.adapter.delete(dn_model)

    @property
    def is_connected(self) -> bool:
        """Check if operations service has active connection.

        Returns:
            True if connected, False otherwise

        """
        return self._connection.is_connected

    def upsert(
        self,
        entry: FlextLdifModels.Entry,
    ) -> FlextResult[dict[str, str]]:
        """Upsert LDAP entry (add if doesn't exist, skip if exists).

        Generic method that handles both regular entries and schema modifications.
        For regular entries: tries add, returns "added" or "skipped" if already exists.
        For schema entries (changetype=modify): checks if attribute exists, adds if not.

        Args:
            entry: Entry model to upsert

        Returns:
            FlextResult containing dict with "operation" key:
                - "added": Entry was added
                - "modified": Entry was modified (for schema)
                - "skipped": Entry already exists (identical)

        """
        # Check if this is a modify operation (schema entry)
        changetype_values = entry.attributes.attributes.get("changetype", [])
        is_modify = changetype_values and changetype_values[0].lower() == "modify"

        if is_modify:
            # Schema modify operation - check if attribute exists first
            # For now, try to modify - ldap3 will handle duplicates
            # TODO: Implement attribute existence check for schema
            add_op = entry.attributes.attributes.get("add", [])
            if not add_op:
                return FlextResult[dict[str, str]].fail(
                    "Schema modify entry missing 'add' attribute",
                )

            # Extract the attribute being added (e.g., "attributeTypes", "objectClasses")
            attr_type = add_op[0]
            attr_values = entry.attributes.attributes.get(attr_type, [])

            if not attr_values:
                return FlextResult[dict[str, str]].fail(
                    f"Schema modify entry missing '{attr_type}' values",
                )

            # Build modify changes dict for ldap3
            # Format: {attr_name: [(operation, [values])]}
            # operation is MODIFY_ADD from ldap3
            from ldap3 import MODIFY_ADD

            changes: dict[str, list[tuple[int, list[str]]]] = {
                attr_type: [(MODIFY_ADD, attr_values)],
            }

            modify_result = self.modify(entry.dn, changes)
            if modify_result.is_success:
                return FlextResult[dict[str, str]].ok({"operation": "modified"})

            # Check if error is "attribute already exists" - then skip
            error = modify_result.error or ""
            if (
                "attribute or value exists" in error.lower()
                or "already exists" in error.lower()
            ):
                return FlextResult[dict[str, str]].ok({"operation": "skipped"})

            return FlextResult[dict[str, str]].fail(error)

        # Regular add operation - try to add
        add_result = self.add(entry)
        if add_result.is_success:
            return FlextResult[dict[str, str]].ok({"operation": "added"})

        # Check if error is "already exists" - then skip
        error = add_result.error or ""
        if "already exists" in error.lower() or "entryalreadyexists" in error.lower():
            return FlextResult[dict[str, str]].ok({"operation": "skipped"})

        # Other error - propagate
        return FlextResult[dict[str, str]].fail(error)

    def execute(self) -> FlextResult[FlextLdapModels.SearchResult]:
        """Execute service health check.

        Returns health check result based on connection status.
        Fast fail if not connected - no fallback.

        Returns:
            FlextResult containing SearchResult if connected,
            or failure if not connected

        """
        if not self._connection.is_connected:
            return FlextResult[FlextLdapModels.SearchResult].fail(
                "Not connected to LDAP server",
            )

        # Return empty search result as health check indicator
        # Attributes default to all attributes from model
        empty_options = FlextLdapModels.SearchOptions(
            base_dn="",
            filter_str=FlextLdapConstants.Filters.ALL_ENTRIES_FILTER,
        )
        result = FlextLdapModels.SearchResult(
            entries=[],
            total_count=0,
            search_options=empty_options,
        )
        return FlextResult[FlextLdapModels.SearchResult].ok(result)

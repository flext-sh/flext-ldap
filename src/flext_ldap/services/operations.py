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
from ldap3 import MODIFY_ADD, MODIFY_DELETE, MODIFY_REPLACE

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

        self._logger.debug(
            "Performing LDAP search",
            base_dn=normalized_base_dn,
            filter_str=normalized_options.filter_str,
            scope=normalized_options.scope,
            server_type=server_type,
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
        self._logger.debug(
            "Adding LDAP entry",
            entry_dn=str(entry.dn) if entry.dn else None,
            attributes_count=len(entry.attributes.attributes)
            if entry.attributes
            else 0,
        )

        # Adapter handles connection check via _get_connection() - no duplication
        add_result = self._connection.adapter.add(entry)

        if add_result.is_failure:
            self._logger.warning(
                "Failed to add LDAP entry",
                entry_dn=str(entry.dn) if entry.dn else None,
                error=str(add_result.error) if add_result.error else None,
                error_type=type(add_result.error).__name__
                if add_result.error
                else None,
            )

        return add_result

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

        self._logger.debug(
            "Modifying LDAP entry",
            entry_dn=str(dn_model),
            changes_count=len(changes),
            changed_attributes=list(changes.keys()),
        )

        # Adapter handles connection check via _get_connection() - no duplication
        modify_result = self._connection.adapter.modify(dn_model, changes)

        if modify_result.is_failure:
            self._logger.warning(
                "Failed to modify LDAP entry",
                entry_dn=str(dn_model),
                error=str(modify_result.error) if modify_result.error else None,
                error_type=type(modify_result.error).__name__
                if modify_result.error
                else None,
            )

        return modify_result

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

        self._logger.debug(
            "Deleting LDAP entry",
            entry_dn=str(dn_model),
        )

        # Adapter handles connection check via _get_connection() - no duplication
        delete_result = self._connection.adapter.delete(dn_model)

        if delete_result.is_failure:
            self._logger.warning(
                "Failed to delete LDAP entry",
                entry_dn=str(dn_model),
                error=str(delete_result.error) if delete_result.error else None,
                error_type=type(delete_result.error).__name__
                if delete_result.error
                else None,
            )

        return delete_result

    @property
    def is_connected(self) -> bool:
        """Check if operations service has active connection.

        Returns:
            True if connected, False otherwise

        """
        return self._connection.is_connected

    def _is_already_exists_error(self, error_message: str | None) -> bool:
        """Check if error indicates entry/attribute already exists.

        Args:
            error_message: Error message to check

        Returns:
            True if error indicates duplicate, False otherwise

        """
        if not error_message:
            return False
        error_lower = error_message.lower()
        return (
            "already exists" in error_lower
            or "entryalreadyexists" in error_lower
            or "attributeorvalueexists" in error_lower
        )

    def _compare_entries(
        self,
        existing_entry: FlextLdifModels.Entry,
        new_entry: FlextLdifModels.Entry,
    ) -> dict[str, list[tuple[str, list[str]]]] | None:
        """Compare two entries and return modify changes if different.

        Args:
            existing_entry: Entry currently in LDAP
            new_entry: Entry to be upserted

        Returns:
            Dict with modify changes if entries differ, None if identical.
            Changes format: {attr_name: [(operation, [values])]}

        """
        if not existing_entry.attributes or not new_entry.attributes:
            return None

        existing_attrs = existing_entry.attributes.attributes
        new_attrs = new_entry.attributes.attributes

        # Attributes to ignore in comparison (operational attributes)
        ignore_attrs = {
            "changetype",
            "add",
            "delete",
            "replace",
            "modify",
            "createTimestamp",
            "modifyTimestamp",
            "creatorsName",
            "modifiersName",
            "entryUUID",
            "entryCSN",
        }

        changes: dict[str, list[tuple[str, list[str]]]] = {}
        has_changes = False

        # Normalize attribute names to lowercase for case-insensitive comparison
        existing_attrs_lower = {k.lower(): (k, v) for k, v in existing_attrs.items()}
        new_attrs_lower = {k.lower(): (k, v) for k, v in new_attrs.items()}

        # Check for new/modified attributes
        for attr_name_lower, (attr_name, new_values) in new_attrs_lower.items():
            if attr_name_lower in ignore_attrs:
                continue

            existing_attr_name, existing_values = existing_attrs_lower.get(
                attr_name_lower,
                (attr_name, []),
            )

            # Normalize values for comparison (convert to sets, ignoring order)
            existing_set = set(str(v).lower() for v in existing_values if v)
            new_set = set(str(v).lower() for v in new_values if v)

            if existing_set != new_set:
                # Replace entire attribute with new values
                # Use original attribute name from existing entry if available
                changes[existing_attr_name] = [
                    (MODIFY_REPLACE, [str(v) for v in new_values if v])
                ]
                has_changes = True

        # Check for deleted attributes (in existing but not in new)
        for attr_name_lower, (attr_name, existing_values) in existing_attrs_lower.items():
            if attr_name_lower in ignore_attrs:
                continue

            if attr_name_lower not in new_attrs_lower:
                # Attribute was removed - delete it
                changes[attr_name] = [(MODIFY_DELETE, [])]
                has_changes = True

        return changes if has_changes else None

    def upsert(
        self,
        entry: FlextLdifModels.Entry,
    ) -> FlextResult[dict[str, str]]:
        """Upsert LDAP entry (add if doesn't exist, modify if exists with differences, skip if identical).

        Generic method that handles both regular entries and schema modifications.
        For regular entries:
            - Tries add first
            - If entryAlreadyExists, fetches existing entry and compares attributes
            - If different, performs modify operation
            - If identical, skips
        For schema entries (changetype=modify): checks if attribute exists, adds if not.

        Args:
            entry: Entry model to upsert

        Returns:
            FlextResult containing dict with "operation" key:
                - "added": Entry was added
                - "modified": Entry was modified (differences found and updated)
                - "skipped": Entry already exists (identical)

        """
        # Check if this is a modify operation (schema entry)
        changetype_values = entry.attributes.attributes.get("changetype", [])
        is_modify = changetype_values and changetype_values[0].lower() == "modify"

        if is_modify:
            # Schema modify operation using ldap3 MODIFY_ADD
            # Duplicate detection handled by LDAP server error responses
            add_op = entry.attributes.attributes.get("add", [])
            if not add_op:
                self._logger.warning(
                    "Schema modify entry missing 'add' attribute",
                    entry_dn=str(entry.dn) if entry.dn else None,
                )
                return FlextResult[dict[str, str]].fail(
                    "Schema modify entry missing 'add' attribute",
                )

            # Extract the attribute being added (e.g., "attributeTypes", "objectClasses")
            attr_type = add_op[0]
            attr_values = entry.attributes.attributes.get(attr_type, [])

            if not attr_values:
                self._logger.warning(
                    "Schema modify entry missing attribute values",
                    entry_dn=str(entry.dn) if entry.dn else None,
                    attribute_type=attr_type,
                )
                return FlextResult[dict[str, str]].fail(
                    f"Schema modify entry missing '{attr_type}' values",
                )

            # Filter out empty values - LDAP doesn't accept empty attributes
            # This prevents invalidAttributeSyntax errors
            filtered_values = [v for v in attr_values if v]

            if not filtered_values:
                self._logger.warning(
                    "Schema modify entry has only empty values",
                    entry_dn=str(entry.dn) if entry.dn else None,
                    attribute_type=attr_type,
                    original_values_count=len(attr_values),
                )
                return FlextResult[dict[str, str]].fail(
                    f"Schema modify entry has only empty values for '{attr_type}'",
                )

            self._logger.debug(
                "Performing schema modify operation",
                entry_dn=str(entry.dn) if entry.dn else None,
                attribute_type=attr_type,
                values_count=len(filtered_values),
            )

            # Build modify changes dict for ldap3
            # Format: {attr_name: [(operation, [values])]}
            schema_changes: dict[str, list[tuple[str, list[str]]]] = {
                attr_type: [(MODIFY_ADD, filtered_values)],
            }

            modify_result = self.modify(str(entry.dn), schema_changes)
            if modify_result.is_success:
                self._logger.debug(
                    "Schema modify operation succeeded",
                    entry_dn=str(entry.dn) if entry.dn else None,
                    operation="modified",
                )
                return FlextResult[dict[str, str]].ok({"operation": "modified"})

            # Check if error is "attribute already exists" - then skip
            if self._is_already_exists_error(modify_result.error):
                self._logger.debug(
                    "Schema modify operation skipped (already exists)",
                    entry_dn=str(entry.dn) if entry.dn else None,
                    operation="skipped",
                )
                return FlextResult[dict[str, str]].ok({"operation": "skipped"})

            error = modify_result.error or "Modify failed with unknown error"
            return FlextResult[dict[str, str]].fail(error)

        # Regular add operation - try to add
        self._logger.debug(
            "Performing upsert operation (add)",
            entry_dn=str(entry.dn) if entry.dn else None,
            operation_type="add",
        )

        add_result = self.add(entry)
        if add_result.is_success:
            self._logger.debug(
                "Upsert operation succeeded",
                entry_dn=str(entry.dn) if entry.dn else None,
                operation="added",
            )
            return FlextResult[dict[str, str]].ok({"operation": "added"})

        # Check if error is "already exists" - fetch and compare
        if self._is_already_exists_error(add_result.error):
            entry_dn_str = str(entry.dn) if entry.dn else ""
            if not entry_dn_str:
                error = add_result.error or "Add failed with unknown error"
                return FlextResult[dict[str, str]].fail(error)

            self._logger.debug(
                "Entry already exists, fetching for comparison",
                entry_dn=entry_dn_str,
            )

            # Search for existing entry using BASE scope (exact DN match)
            search_options = FlextLdapModels.SearchOptions(
                base_dn=entry_dn_str,
                filter_str=FlextLdapConstants.Filters.ALL_ENTRIES_FILTER,
                scope="BASE",  # type: ignore[assignment]
                attributes=None,  # Get all attributes
            )

            search_result = self.search(search_options)
            if search_result.is_failure:
                self._logger.warning(
                    "Failed to fetch existing entry for comparison",
                    entry_dn=entry_dn_str,
                    error=str(search_result.error),
                )
                # If we can't fetch, assume identical and skip
                return FlextResult[dict[str, str]].ok({"operation": "skipped"})

            existing_entries = search_result.unwrap().entries
            if not existing_entries:
                self._logger.warning(
                    "Existing entry not found (should not happen)",
                    entry_dn=entry_dn_str,
                )
                # Entry doesn't exist after all - try add again
                add_result_retry = self.add(entry)
                if add_result_retry.is_success:
                    return FlextResult[dict[str, str]].ok({"operation": "added"})
                error = add_result_retry.error or "Add failed with unknown error"
                return FlextResult[dict[str, str]].fail(error)

            existing_entry = existing_entries[0]

            # Compare entries
            changes_or_none = self._compare_entries(existing_entry, entry)
            if changes_or_none is None:
                # Entries are identical
                self._logger.debug(
                    "Entry already exists and is identical, skipping",
                    entry_dn=entry_dn_str,
                    operation="skipped",
                )
                return FlextResult[dict[str, str]].ok({"operation": "skipped"})

            # Entries differ - perform modify
            changes: dict[str, list[tuple[str, list[str]]]] = changes_or_none
            self._logger.info(
                "Entry exists but differs, updating",
                entry_dn=entry_dn_str,
                changed_attributes=list(changes.keys()),
                changes_count=len(changes),
            )

            modify_result = self.modify(entry_dn_str, changes)
            if modify_result.is_success:
                self._logger.info(
                    "Entry updated successfully",
                    entry_dn=entry_dn_str,
                    operation="modified",
                    changed_attributes=list(changes.keys()),
                )
                return FlextResult[dict[str, str]].ok({"operation": "modified"})

            # Modify failed
            error = modify_result.error or "Modify failed with unknown error"
            self._logger.warning(
                "Failed to update existing entry",
                entry_dn=entry_dn_str,
                error=error,
                changed_attributes=list(changes.keys()),
            )
            return FlextResult[dict[str, str]].fail(error)

        # Other error - propagate
        error = add_result.error or "Add failed with unknown error"
        return FlextResult[dict[str, str]].fail(error)

    def execute(self, **_kwargs: object) -> FlextResult[FlextLdapModels.SearchResult]:
        """Execute service health check.

        Returns health check result based on connection status.
        Fast fail if not connected - no fallback.

        Args:
            **_kwargs: Unused - health check requires no configuration

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

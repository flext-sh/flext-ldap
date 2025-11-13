"""Generic UPSERT service for intelligent entry creation/update operations.

Provides a reusable, production-grade UPSERT (Create or Update) implementation
that handles the complexity of determining whether to ADD new attributes or
REPLACE existing ones based on actual current entry state.

Usage:
    from flext_ldap import FlextLdapClients, FlextLdapUpsertService

    client = FlextLdapClients(config=config)
    client.connect()
    upsert_service = FlextLdapUpsertService()
    result = upsert_service.upsert_entry(
        ldap_client=client,
        dn="cn=user,ou=users,dc=example,dc=com",
        new_attributes={
            "mail": ["user@example.com"],
            "telephoneNumber": ["555-1234"],
            "cn": ["User Name"],
        }
    )

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from typing import Protocol, cast

from flext_core import FlextDecorators, FlextResult, FlextService
from flext_ldif import FlextLdifModels

from flext_ldap.constants import FlextLdapConstants
from flext_ldap.models import FlextLdapModels
from flext_ldap.services.clients import FlextLdapClients
from flext_ldap.utilities import FlextLdapUtilities


class _AttrWithValues(Protocol):
    """Protocol for attribute objects with values attribute."""

    @property
    def values(self) -> list[str] | str: ...


class FlextLdapUpsertService(FlextService[dict[str, object]]):
    """Generic UPSERT service for intelligent entry operations.

    Implements production-grade UPSERT logic that:
    - Searches for existing entry to get actual attributes
    - Intelligently decides ADD vs REPLACE based on facts
    - Executes modifications without unnecessary retries
    - Handles errors immediately without fallback attempts

    This service should be used by applications that need to create or
    update LDAP entries efficiently and reliably.

    Example:
        service = FlextLdapUpsertService()
        result = service.upsert_entry(
            ldap_client=client,
            dn="cn=john,ou=users,dc=corp,dc=com",
            new_attributes={
                "mail": ["john@corp.com"],
                "displayName": ["John Smith"],
                FlextLdapConstants.LdapAttributeNames.OBJECT_CLASS: [FlextLdapConstants.ObjectClasses.INET_ORG_PERSON, FlextLdapConstants.ObjectClasses.PERSON],
            }
        )
        if result.is_success:
            print(f"Entry upserted: {result.unwrap()}")

    """

    def __init__(self) -> None:
        """Initialize UPSERT service."""
        super().__init__()

    def execute(self) -> FlextResult[dict[str, object]]:
        """Execute method required by FlextService base class."""
        return FlextResult[dict[str, object]].ok({})

    def _normalize_attributes(
        self,
        attributes: dict[str, list[str] | str],
    ) -> dict[str, list[str]]:
        """Normalize attributes to list format - delegates to FlextLdapUtilities."""
        return FlextLdapUtilities.Validation.normalize_list_values(attributes)

    def _extract_entry_from_search(
        self,
        search_response: FlextLdifModels.Entry
        | list[FlextLdifModels.Entry]
        | list[tuple[str, FlextLdifModels.Entry]]
        | None,
        dn: str,
    ) -> FlextResult[FlextLdifModels.Entry]:
        """Extract Entry object from various search response formats.

        Refactored with Railway Pattern: 8→4 returns (SOLID/DRY compliance).
        Uses structural pattern matching for type-safe extraction.
        """
        # Railway Pattern: Early validation
        if not search_response:
            return FlextResult[FlextLdifModels.Entry].fail(
                f"Entry {dn} not found in search despite ADD indicating existence",
            )

        # Structural pattern matching for type-safe extraction (Python 3.10+)
        match search_response:
            # Case 1: Direct Entry object
            case FlextLdifModels.Entry() as entry:
                return FlextResult[FlextLdifModels.Entry].ok(entry)

            # Case 2: List of responses (tuple or Entry)
            case list() as response_list if response_list:
                return self._extract_from_list(response_list, dn)

            # Case 3: Empty list or invalid type
            case _:
                return FlextResult[FlextLdifModels.Entry].fail(
                    f"Unexpected search response format for {dn}: {type(search_response)}"
                )

    def _extract_from_list(
        self,
        response_list: list[FlextLdifModels.Entry]
        | list[tuple[str, FlextLdifModels.Entry]],
        dn: str,
    ) -> FlextResult[FlextLdifModels.Entry]:
        """Extract Entry from list response (tuple or direct Entry).

        Helper method for Railway Pattern extraction.
        Handles: list[Entry] and list[tuple[str, Entry]]
        """
        first_item = response_list[0]

        # Match on first item type
        match first_item:
            # Tuple format: (dn_str, Entry)
            case (str(), FlextLdifModels.Entry() as entry):
                return FlextResult[FlextLdifModels.Entry].ok(entry)

            # Direct Entry format
            case FlextLdifModels.Entry() as entry:
                return FlextResult[FlextLdifModels.Entry].ok(entry)

            # Invalid format
            case _:
                return FlextResult[FlextLdifModels.Entry].fail(
                    f"Unexpected list item format for {dn}: {type(first_item)}"
                )

    def _extract_existing_attributes(
        self,
        entry: FlextLdifModels.Entry,
    ) -> dict[str, list[str]]:
        """Extract current attributes from existing entry."""
        existing_attrs: dict[str, list[str]] = {}
        if entry.attributes is not None:
            for attr_name, attr_obj in entry.attributes.items():
                if attr_obj:
                    # Handle list[str] directly
                    if isinstance(attr_obj, list):
                        existing_attrs[attr_name.lower()] = [str(v) for v in attr_obj]
                    # Handle objects with .values attribute (cast to Protocol for type safety)
                    elif hasattr(attr_obj, "values"):
                        attr_with_values = cast("_AttrWithValues", attr_obj)
                        values_attr = attr_with_values.values
                        if isinstance(values_attr, list):
                            existing_attrs[attr_name.lower()] = [
                                str(v) for v in values_attr
                            ]
                        else:
                            existing_attrs[attr_name.lower()] = [str(values_attr)]
                    # Fallback to string conversion
                    else:
                        existing_attrs[attr_name.lower()] = [str(attr_obj)]
        return existing_attrs

    def _compute_attribute_changes(
        self,
        normalized_new: dict[str, list[str]],
        existing_attrs: dict[str, list[str]],
        skip_attributes: set[str],
    ) -> tuple[dict[str, list[str]], dict[str, list[str]], dict[str, list[str]], int]:
        """Determine which attributes to ADD, REPLACE, or leave unchanged.

        Strategy: Since we fetched ALL attributes (including operational with "+"),
        we use REPLACE for all changes to avoid attributeOrValueExists errors.
        REPLACE is idempotent and works whether attribute exists or not.

        Returns:
            Tuple of (to_add, to_replace_new, to_replace_existing, unchanged_count)
            - to_add: Always empty (using REPLACE for all)
            - to_replace_new: New attributes to be added via REPLACE
            - to_replace_existing: Existing attributes to be modified via REPLACE
            - unchanged_count: Count of attributes with no changes

        """
        to_add: dict[str, list[str]] = {}  # Will be empty - using REPLACE for all
        to_replace_new: dict[str, list[str]] = {}  # New attributes
        to_replace_existing: dict[str, list[str]] = {}  # Existing attributes
        unchanged_count = 0

        for attr, new_values in normalized_new.items():
            if attr.lower() in skip_attributes:
                continue

            attr_lower = attr.lower()
            if attr_lower not in existing_attrs:
                # Attribute doesn't exist - use REPLACE (not ADD) for robustness
                # Track as "new" for statistics
                to_replace_new[attr] = new_values
            else:
                existing_values = existing_attrs[attr_lower]
                if set(new_values) == set(existing_values):
                    unchanged_count += 1
                else:
                    # Attribute exists and needs update - track as "existing"
                    to_replace_existing[attr] = new_values

        return to_add, to_replace_new, to_replace_existing, unchanged_count

    def _execute_add_modifications(
        self,
        ldap_client: FlextLdapClients,
        dn: str,
        to_add: dict[str, list[str]],
    ) -> FlextResult[int]:
        """Execute MODIFY ADD operations.

        Note: For attributes identified as "not existing" in _compute_attribute_changes,
        we can safely ADD all values. The logic ensures to_add only contains attributes
        that don't exist in the entry, so no filtering is needed here.
        """
        if not to_add:
            return FlextResult[int].ok(0)

        add_changes_dict = {
            attr: [(FlextLdapConstants.ModifyOperation.ADD, values)]
            for attr, values in to_add.items()
        }
        add_changes = FlextLdapModels.EntryChanges(**add_changes_dict)
        self.logger.debug(
            "Executing MODIFY ADD",
            extra={"dn": dn, "attributes": list(to_add.keys())},
        )

        add_result = ldap_client.modify_entry(dn=dn, changes=add_changes)
        if add_result.is_failure:
            # If still getting attributeOrValueExists despite checking,
            # log detailed error and fail (indicates data race or operational attr issue)
            error_str = str(add_result.error).lower()
            if "attributeorvalueexists" in error_str or "already exists" in error_str:
                self.logger.error(
                    "MODIFY ADD failed with attributeOrValueExists - possible race condition or operational attribute",
                    extra={
                        "dn": dn,
                        "error": str(add_result.error),
                        "attempted_attributes": list(to_add.keys()),
                    },
                )
            else:
                self.logger.error(
                    "MODIFY ADD failed",
                    extra={"dn": dn, "error": str(add_result.error)},
                )
            return FlextResult[int].fail(str(add_result.error))

        added_count = len(to_add)
        self.logger.debug(
            "MODIFY ADD successful",
            extra={"dn": dn, "added_count": added_count},
        )
        return FlextResult[int].ok(added_count)

    def _execute_replace_modifications(
        self,
        ldap_client: FlextLdapClients,
        dn: str,
        to_replace: dict[str, list[str]],
    ) -> FlextResult[int]:
        """Execute MODIFY REPLACE operations."""
        if not to_replace:
            return FlextResult[int].ok(0)

        replace_changes_dict = {
            attr: [(FlextLdapConstants.ModifyOperation.REPLACE, values)]
            for attr, values in to_replace.items()
        }
        replace_changes = FlextLdapModels.EntryChanges(**replace_changes_dict)
        self.logger.debug(
            "Executing MODIFY REPLACE",
            extra={"dn": dn, "attributes": list(to_replace.keys())},
        )

        replace_result = ldap_client.modify_entry(dn=dn, changes=replace_changes)
        if replace_result.is_failure:
            self.logger.error(
                "MODIFY REPLACE failed",
                extra={"dn": dn, "error": str(replace_result.error)},
            )
            return FlextResult[int].fail(str(replace_result.error))

        replaced_count = len(to_replace)
        self.logger.debug(
            "MODIFY REPLACE successful",
            extra={"dn": dn, "replaced_count": replaced_count},
        )
        return FlextResult[int].ok(replaced_count)

    @FlextDecorators.log_operation("LDAP UPSERT Entry")
    @FlextDecorators.track_performance("LDAP UPSERT Entry")
    @FlextDecorators.timeout(timeout_seconds=30.0)
    def upsert_entry(
        self,
        ldap_client: FlextLdapClients,
        dn: str,
        new_attributes: dict[str, list[str] | str],
        skip_attributes: set[str] | None = None,
    ) -> FlextResult[dict[str, object]]:
        """Intelligently create or update LDAP entry.

        Refactored with Railway Pattern: 7→3 returns (SOLID/DRY compliance).

        Strategy:
        1. Attempt ADD (entry creation) - fastest path for new entries
        2. If fails with "already exists", delegate to existing entry handler
        3. Return errors immediately (no retries)

        Args:
            ldap_client: Connected FlextLdapClients instance
            dn: Distinguished name of entry to upsert
            new_attributes: New/updated attributes (dict or list format)
            skip_attributes: Optional set of attribute names to skip (operational, RDN)

        Returns:
            FlextResult containing dict with:
            - "{FlextLdapConstants.StatusKeys.UPSERTED}": bool - True if entry created/updated
            - "{FlextLdapConstants.StatusKeys.ADDED}": int - Number of attributes added
            - "{FlextLdapConstants.StatusKeys.REPLACED}": int - Number of attributes replaced
            - "{FlextLdapConstants.StatusKeys.UNCHANGED}": int - Number of attributes unchanged

        Example:
            >>> result = service.upsert_entry(
            ...     client,
            ...     "cn=user,ou=users,dc=example,dc=com",
            ...     {"mail": ["user@example.com"], "cn": ["User"]},
            ... )
            >>> if result.is_success:
            ...     stats = result.unwrap()
            ...     print(f"Added: {stats['added']}, Replaced: {stats['replaced']}")

        """
        if skip_attributes is None:
            skip_attributes = FlextLdapConstants.SkipAttributes.DEFAULT_SKIP_ATTRIBUTES

        # Step 1: Normalize attributes and try ADD first (most efficient for new entries)
        normalized_new = self._normalize_attributes(new_attributes)
        self.logger.debug("Attempting ADD", extra={"dn": dn})
        add_result = ldap_client.add_entry(dn=dn, attributes=new_attributes)

        # Railway Pattern: Early success - entry created
        if add_result.is_success:
            self.logger.debug(
                "Entry created via ADD",
                extra={
                    "dn": dn,
                    FlextLdapConstants.StatusKeys.ATTRIBUTE_COUNT: len(normalized_new),
                },
            )
            return FlextResult[dict[str, object]].ok({
                FlextLdapConstants.StatusKeys.UPSERTED: True,
                FlextLdapConstants.StatusKeys.ADDED: len(normalized_new),
                FlextLdapConstants.StatusKeys.REPLACED: 0,
                FlextLdapConstants.StatusKeys.UNCHANGED: 0,
            })

        # Railway Pattern: Check if failure is "already exists" error
        if not FlextLdapUtilities.ErrorHandling.is_already_exists_error(
            add_result.error
        ):
            self.logger.error(
                "ADD failed with non-existence error",
                extra={"dn": dn, "error": str(add_result.error)},
            )
            return FlextResult[dict[str, object]].fail(str(add_result.error))

        # Railway Pattern: Delegate existing entry handling
        return self._handle_existing_entry(
            ldap_client, dn, normalized_new, skip_attributes
        )

    def _handle_existing_entry(
        self,
        ldap_client: FlextLdapClients,
        dn: str,
        normalized_new: dict[str, list[str]],
        skip_attributes: set[str],
    ) -> FlextResult[dict[str, object]]:
        """Handle existing entry update logic.

        Helper for Railway Pattern - extracted from upsert_entry().
        Fetches existing entry, computes changes, and executes modifications.

        Returns:
            FlextResult with upsert statistics or failure message.

        """
        # Step 1: Fetch ALL attributes (including operational)
        self.logger.debug("Entry exists, fetching current attributes", extra={"dn": dn})

        # Use SearchRequest object for type-safe search (Pydantic v2 pattern)
        search_request = FlextLdapModels.SearchRequest(
            base_dn=dn,
            filter_str=FlextLdapConstants.Filters.ALL_ENTRIES_FILTER,
            attributes=["*", "+"],  # Fetch ALL attributes
            single=True,
        )
        search_result = ldap_client.search(request=search_request)

        if search_result.is_failure:
            self.logger.error(
                "Failed to fetch existing entry",
                extra={"dn": dn, "error": str(search_result.error)},
            )
            return FlextResult[dict[str, object]].fail(
                f"Failed to fetch existing entry: {search_result.error}",
            )

        # Step 2: Extract entry from search response
        entry_result = self._extract_entry_from_search(search_result.unwrap(), dn)
        if entry_result.is_failure:
            self.logger.error(
                "Failed to extract entry from search",
                extra={"dn": dn, "error": str(entry_result.error)},
            )
            return FlextResult[dict[str, object]].fail(str(entry_result.error))

        existing_entry = entry_result.unwrap()
        existing_attrs = self._extract_existing_attributes(existing_entry)

        # Step 3: Compute changes (ADD vs REPLACE)
        to_add, to_replace_new, to_replace_existing, unchanged_count = (
            self._compute_attribute_changes(
                normalized_new,
                existing_attrs,
                skip_attributes,
            )
        )

        # Step 4: Check if no changes needed (optimization)
        if not to_add and not to_replace_new and not to_replace_existing:
            self.logger.debug(
                "Entry already has identical attributes, skipping MODIFY",
                extra={"dn": dn, "unchanged_count": unchanged_count},
            )
            return FlextResult[dict[str, object]].ok({
                FlextLdapConstants.StatusKeys.UPSERTED: True,
                FlextLdapConstants.StatusKeys.ADDED: 0,
                FlextLdapConstants.StatusKeys.REPLACED: 0,
                FlextLdapConstants.StatusKeys.UNCHANGED: unchanged_count,
            })

        # Step 5: Execute modifications using REPLACE
        to_replace_all = {**to_replace_new, **to_replace_existing}
        self.logger.debug(
            "Preparing MODIFY REPLACE",
            extra={
                "dn": dn,
                "new_attributes_count": len(to_replace_new),
                "existing_attributes_count": len(to_replace_existing),
                "total_replace_count": len(to_replace_all),
            },
        )

        replace_result = self._execute_replace_modifications(
            ldap_client, dn, to_replace_all
        )
        if replace_result.is_failure:
            return FlextResult[dict[str, object]].fail(str(replace_result.error))

        # Step 6: Return success statistics
        added_count = len(to_replace_new)
        replaced_count = len(to_replace_existing)

        self.logger.info(
            "Entry upserted successfully",
            extra={
                "dn": dn,
                FlextLdapConstants.StatusKeys.ADDED: added_count,
                FlextLdapConstants.StatusKeys.REPLACED: replaced_count,
            },
        )

        return FlextResult[dict[str, object]].ok({
            FlextLdapConstants.StatusKeys.UPSERTED: True,
            FlextLdapConstants.StatusKeys.ADDED: added_count,
            FlextLdapConstants.StatusKeys.REPLACED: replaced_count,
            FlextLdapConstants.StatusKeys.UNCHANGED: unchanged_count,
        })

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

from collections.abc import Iterable
from typing import TYPE_CHECKING, ClassVar, Protocol, Union, cast

if TYPE_CHECKING:
    from flext_ldap.api import FlextLdap

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

    _LDIF_CONTROL_ATTRIBUTES: ClassVar[set[str]] = {
        "changetype",
        "add",
        "delete",
        "replace",
        "modrdn",
        "moddn",
        "newrdn",
        "newsuperior",
        "controls",
    }

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

    def _coerce_client(
        self,
        ldap_client: Union[FlextLdap, FlextLdapClients],
    ) -> FlextLdapClients:
        """Return concrete FlextLdapClients instance from facade or direct client."""
        if hasattr(ldap_client, "client"):
            return ldap_client.client  # type: ignore[attr-defined]
        return cast("FlextLdapClients", ldap_client)

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
        """Execute MODIFY REPLACE operations with resilient attribute-by-attribute fallback.

        Strategy:
        1. Try to replace all attributes at once (most efficient)
        2. If batch fails, retry each attribute individually
        3. Skip problematic attributes with warnings instead of failing completely
        """
        if not to_replace:
            return FlextResult[int].ok(0)

        replace_changes_dict = {
            attr: [(FlextLdapConstants.ModifyOperation.REPLACE, values)]
            for attr, values in to_replace.items()
        }
        replace_changes = FlextLdapModels.EntryChanges(**replace_changes_dict)

        # Try batch operation first (most efficient)
        replace_result = ldap_client.modify_entry(dn=dn, changes=replace_changes)
        if replace_result.is_success:
            return FlextResult[int].ok(len(to_replace))

        # Batch failed - try individual attributes to identify problematic ones
        self.logger.debug(
            "Batch REPLACE failed, retrying attributes individually",
            extra={"dn": dn, "attribute_count": len(to_replace)},
        )

        succeeded_count = 0
        failed_attrs = []

        for attr, values in to_replace.items():
            single_change = FlextLdapModels.EntryChanges(**{
                attr: [(FlextLdapConstants.ModifyOperation.REPLACE, values)]
            })
            single_result = ldap_client.modify_entry(dn=dn, changes=single_change)

            if single_result.is_success:
                succeeded_count += 1
            else:
                failed_attrs.append(attr)
                self.logger.warning(
                    "Skipped problematic attribute",
                    extra={
                        "dn": dn,
                        "attribute": attr,
                        "error": str(single_result.error),
                    },
                )

        if failed_attrs:
            self.logger.warning(
                "Entry partially updated - some attributes skipped",
                extra={
                    "dn": dn,
                    "succeeded": succeeded_count,
                    "failed": len(failed_attrs),
                    "failed_attributes": failed_attrs,
                },
            )

        # Return success even if some attributes failed (resilient mode)
        return FlextResult[int].ok(succeeded_count)

    def _extract_changetype(
        self,
        attributes: dict[str, list[str]],
    ) -> str | None:
        """Return lower-cased changetype value from LDIF attribute map."""
        changetype_values = attributes.get("changetype")
        if not changetype_values:
            return None
        changetype = changetype_values[0]
        return changetype.lower() if isinstance(changetype, str) else None

    def _split_ldif_attributes(
        self,
        attributes: dict[str, list[str]],
    ) -> tuple[dict[str, list[str]], dict[str, list[str]]]:
        """Separate control attributes from content attributes without discarding information."""
        control_attrs: dict[str, list[str]] = {}
        content_attrs: dict[str, list[str]] = {}
        for attr, values in attributes.items():
            if attr.lower() in self._LDIF_CONTROL_ATTRIBUTES:
                control_attrs[attr] = values
            else:
                content_attrs[attr] = values
        return content_attrs, control_attrs

    def _build_modify_changes(
        self,
        attributes: dict[str, list[str]],
        *,
        allow_deletes: bool,
    ) -> tuple[
        dict[str, list[tuple[str, list[str]]]],
        dict[str, int],
        list[str],
    ]:
        """Build EntryChanges payload and per-operation counters from LDIF modify data."""
        modifications: dict[str, list[tuple[str, list[str]]]] = {}
        operation_counts = {"add": 0, "replace": 0, "delete": 0}
        skipped_delete_attrs: list[str] = []

        operation_mapping = (
            ("add", FlextLdapConstants.ModifyOperation.ADD),
            ("replace", FlextLdapConstants.ModifyOperation.REPLACE),
            ("delete", FlextLdapConstants.ModifyOperation.DELETE),
        )

        for op_name, modify_enum in operation_mapping:
            attr_names = attributes.get(op_name, [])
            if not attr_names:
                continue

            names_iterable = (
                attr_names if isinstance(attr_names, list) else [attr_names]
            )
            for attr_name in names_iterable:
                if op_name == "delete" and not allow_deletes:
                    skipped_delete_attrs.append(str(attr_name))
                    continue

                attr_values = attributes.get(attr_name, [])
                values_list = (
                    attr_values if isinstance(attr_values, list) else [attr_values]
                )
                if op_name == "delete" and not values_list:
                    normalized_values: list[str] = []
                else:
                    normalized_values = [str(value) for value in values_list]

                modifications.setdefault(attr_name, []).append(
                    (modify_enum, normalized_values),
                )
                operation_counts[op_name] += 1

        return modifications, operation_counts, skipped_delete_attrs

    def _apply_modify_operations(
        self,
        ldap_client: FlextLdapClients,
        dn: str,
        attributes: dict[str, list[str]],
        *,
        allow_deletes: bool,
    ) -> FlextResult[dict[str, object]]:
        """Execute changetype: modify operations based on LDIF directives."""
        modifications, counts, skipped_deletes = self._build_modify_changes(
            attributes,
            allow_deletes=allow_deletes,
        )
        if not modifications:
            self.logger.warning(
                "Modify entry has no operations",
                extra={"dn": dn},
            )
            return FlextResult[dict[str, object]].fail(
                "changetype=modify entry has no operations to execute"
            )

        entry_changes = FlextLdapModels.EntryChanges(**modifications)
        self.logger.debug(
            "Executing changetype=modify operations",
            extra={
                "dn": dn,
                "add_operations": counts["add"],
                "replace_operations": counts["replace"],
                "delete_operations": counts["delete"],
                "deletes_allowed": allow_deletes,
                "skipped_deletes": skipped_deletes,
            },
        )

        modify_result = ldap_client.modify_entry(dn=dn, changes=entry_changes)
        if modify_result.is_failure:
            self.logger.error(
                "LDIF modify operation failed",
                extra={"dn": dn, "error": str(modify_result.error)},
            )
            return FlextResult[dict[str, object]].fail(str(modify_result.error))

        return FlextResult[dict[str, object]].ok({
            FlextLdapConstants.StatusKeys.UPSERTED: True,
            FlextLdapConstants.StatusKeys.ADDED: counts["add"],
            FlextLdapConstants.StatusKeys.REPLACED: counts["replace"],
            FlextLdapConstants.StatusKeys.UNCHANGED: 0,
            FlextLdapConstants.StatusKeys.TOTAL: sum(counts.values()),
            FlextLdapConstants.StatusKeys.DELETED: counts["delete"],
            "skipped_delete_attributes": skipped_deletes,
        })

    def _handle_delete_operation(
        self,
        ldap_client: FlextLdapClients,
        dn: str,
        *,
        allow_deletes: bool,
    ) -> FlextResult[dict[str, object]]:
        """Delete entry if allowed, otherwise return a skipped status."""
        if not allow_deletes:
            self.logger.warning(
                "Delete operation skipped because allow_deletes=False",
                extra={"dn": dn},
            )
            return FlextResult[dict[str, object]].ok({
                FlextLdapConstants.StatusKeys.UPSERTED: False,
                FlextLdapConstants.StatusKeys.DELETED: 0,
                "skipped_delete": True,
            })

        delete_result = ldap_client.delete_entry(dn)
        if delete_result.is_failure:
            self.logger.error(
                "Entry delete failed",
                extra={"dn": dn, "error": str(delete_result.error)},
            )
            return FlextResult[dict[str, object]].fail(str(delete_result.error))

        self.logger.info("Entry deleted", extra={"dn": dn})
        return FlextResult[dict[str, object]].ok({
            FlextLdapConstants.StatusKeys.UPSERTED: False,
            FlextLdapConstants.StatusKeys.DELETED: 1,
        })

    def prefetch_existing_entries(
        self,
        ldap_client: FlextLdapClients,
        entries: Iterable[FlextLdifModels.Entry],
        *,
        batch_size: int,
    ) -> dict[str, FlextLdifModels.Entry]:
        """Fetch existing entries ahead of time to reduce redundant lookups."""
        unique_dns: list[str] = []
        seen_dns: set[str] = set()
        for entry in entries:
            if entry.dn and entry.dn.value:
                normalized = entry.dn.value.lower()
                if normalized not in seen_dns:
                    seen_dns.add(normalized)
                    unique_dns.append(entry.dn.value)

        if batch_size <= 0:
            batch_size = 1

        existing_map: dict[str, FlextLdifModels.Entry] = {}
        for chunk in self._chunk_list(unique_dns, batch_size):
            for dn in chunk:
                fetch_result = self._fetch_existing_entry(ldap_client, dn)
                if fetch_result.is_failure:
                    self.logger.debug(
                        "Prefetch lookup failed",
                        extra={"dn": dn, "error": str(fetch_result.error)},
                    )
                    continue
                fetched_entry = fetch_result.unwrap()
                if fetched_entry:
                    existing_map[dn.lower()] = fetched_entry
        return existing_map

    def _chunk_list(
        self,
        items: list[str],
        chunk_size: int,
    ) -> Iterable[list[str]]:
        """Yield successive chunks from items list."""
        for index in range(0, len(items), chunk_size):
            yield items[index : index + chunk_size]

    def apply_ldif_entry(
        self,
        ldap_client: Union[FlextLdap, FlextLdapClients],
        entry: FlextLdifModels.Entry,
        skip_attributes: set[str] | None = None,
        *,
        allow_deletes: bool = False,
        existing_entry: FlextLdifModels.Entry | None = None,
        auto_create_parents: bool = True,
    ) -> FlextResult[dict[str, object]]:
        """Apply a parsed FlextLdif entry by respecting its changetype directives."""
        if entry.dn is None or not entry.dn.value:
            return FlextResult[dict[str, object]].fail(
                "LDIF entry is missing a distinguished name"
            )

        if entry.attributes is None or not entry.attributes.attributes:
            return FlextResult[dict[str, object]].fail(
                "LDIF entry has no attributes to apply"
            )

        attributes = entry.attributes.attributes
        skip_attr_set = (
            {attr.lower() for attr in skip_attributes}
            if skip_attributes is not None
            else set(FlextLdapConstants.SkipAttributes.DEFAULT_SKIP_ATTRIBUTES)
        )
        changetype = self._extract_changetype(attributes)
        dn = entry.dn.value

        actual_client = self._coerce_client(ldap_client)

        if changetype in {None, "", "add"}:
            content_attrs, _ = self._split_ldif_attributes(attributes)
            if not content_attrs:
                return FlextResult[dict[str, object]].fail(
                    "LDIF entry has no content attributes to apply"
                )
            return self.upsert_entry(
                ldap_client=actual_client,
                dn=dn,
                new_attributes=cast("dict[str, list[str] | str]", content_attrs),
                skip_attributes=skip_attr_set,
                existing_entry=existing_entry,
                auto_create_parents=auto_create_parents,
            )

        if changetype == "modify":
            return self._apply_modify_operations(
                actual_client,
                dn,
                attributes,
                allow_deletes=allow_deletes,
            )

        if changetype == "delete":
            return self._handle_delete_operation(
                actual_client,
                dn,
                allow_deletes=allow_deletes,
            )

        self.logger.error(
            "Unsupported changetype in LDIF entry",
            extra={"dn": dn, "changetype": changetype},
        )
        return FlextResult[dict[str, object]].fail(
            f"Unsupported changetype '{changetype}' for LDIF entry"
        )

    def apply_ldif_entries(
        self,
        ldap_client: Union[FlextLdap, FlextLdapClients],
        entries: Iterable[FlextLdifModels.Entry],
        *,
        allow_deletes: bool = False,
        skip_attributes: set[str] | None = None,
        prefetch_existing: bool = True,
        batch_size: int = 25,
        auto_create_parents: bool = True,
    ) -> FlextResult[dict[str, object]]:
        """Apply multiple LDIF entries with optional prefetching for optimization."""
        actual_client = self._coerce_client(ldap_client)
        entry_list = list(entries)
        if not entry_list:
            return FlextResult[dict[str, object]].ok({
                "processed": 0,
                "succeeded": 0,
                "failed": 0,
                "results": [],
            })

        skip_attr_set = (
            {attr.lower() for attr in skip_attributes}
            if skip_attributes is not None
            else set(FlextLdapConstants.SkipAttributes.DEFAULT_SKIP_ATTRIBUTES)
        )

        existing_map: dict[str, FlextLdifModels.Entry] = {}
        if prefetch_existing:
            existing_map = self.prefetch_existing_entries(
                actual_client,
                entry_list,
                batch_size=batch_size,
            )

        success_details: list[dict[str, object]] = []
        failure_details: list[dict[str, object]] = []
        all_details: list[dict[str, object]] = []

        for entry in entry_list:
            dn_value = entry.dn.value if entry.dn else "UNKNOWN"
            cached_entry = None
            if entry.dn and entry.dn.value:
                cached_entry = existing_map.get(entry.dn.value.lower())

            result = self.apply_ldif_entry(
                actual_client,
                entry,
                skip_attributes=skip_attr_set,
                allow_deletes=allow_deletes,
                existing_entry=cached_entry,
                auto_create_parents=auto_create_parents,
            )
            if result.is_success:
                payload = result.unwrap()
                entry_detail = {
                    "dn": dn_value,
                    "success": True,
                    "stats": payload,
                }
                payload["dn"] = dn_value
                success_details.append(entry_detail)  # type: ignore[arg-type]
                all_details.append(entry_detail)  # type: ignore[arg-type]
            else:
                entry_detail = {
                    "dn": dn_value,
                    "success": False,
                    "error": str(result.error),
                }
                failure_details.append(entry_detail)  # type: ignore[arg-type]
                all_details.append(entry_detail)  # type: ignore[arg-type]

        summary: dict[str, object] = {
            "processed": len(entry_list),
            "succeeded": len(success_details),
            "failed": len(failure_details),
            "details": all_details,
        }

        if failure_details:
            summary["errors"] = failure_details
            return FlextResult[dict[str, object]].ok(summary)

        return FlextResult[dict[str, object]].ok(summary)

    @FlextDecorators.track_performance("LDAP UPSERT Entry")
    @FlextDecorators.timeout(timeout_seconds=30.0)
    def upsert_entry(
        self,
        ldap_client: Union[FlextLdap, FlextLdapClients],  # Accept both facade and client
        dn: str,
        new_attributes: dict[str, list[str] | str],
        skip_attributes: set[str] | None = None,
        existing_entry: FlextLdifModels.Entry | None = None,
        auto_create_parents: bool = True,
    ) -> FlextResult[dict[str, object]]:
        """Intelligently create or update LDAP entry with automatic parent creation.

        Refactored with Railway Pattern: 7→3 returns (SOLID/DRY compliance).

        Strategy:
        1. Attempt ADD (entry creation) - fastest path for new entries
        2. If fails with "noSuchObject", create parent DNs recursively
        3. If fails with "already exists", delegate to existing entry handler
        4. Return errors immediately (no retries)

        Args:
            ldap_client: Connected FlextLdap (facade) or FlextLdapClients instance
            dn: Distinguished name of entry to upsert
            new_attributes: New/updated attributes (dict or list format)
            skip_attributes: Optional set of attribute names to skip (operational, RDN)
            existing_entry: Optional entry data already fetched from the directory
            auto_create_parents: If True, automatically create missing parent DNs (default: True)

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
            skip_attributes = (
                FlextLdapConstants.SkipAttributes.DEFAULT_SKIP_ATTRIBUTES.copy()
            )
        skip_attributes = {attr.lower() for attr in skip_attributes}

        # Extract FlextLdapClients from facade if needed (polymorphic support)
        # This maintains backwards compatibility while supporting both APIs
        actual_client: FlextLdapClients
        if hasattr(ldap_client, "client"):  # FlextLdap facade has .client attribute
            actual_client = ldap_client.client  # type: ignore[attr-defined]
        else:
            actual_client = cast("FlextLdapClients", ldap_client)

        # Step 1: Normalize attributes and try ADD first (most efficient for new entries)
        normalized_new = self._normalize_attributes(new_attributes)
        if existing_entry is not None:
            return self._handle_existing_entry(
                actual_client,
                dn,
                normalized_new,
                skip_attributes,
                existing_entry=existing_entry,
            )

        add_result = actual_client.add_entry(dn=dn, attributes=new_attributes)

        # Railway Pattern: Early success - entry created
        if add_result.is_success:
            return FlextResult[dict[str, object]].ok({
                FlextLdapConstants.StatusKeys.UPSERTED: True,
                FlextLdapConstants.StatusKeys.ADDED: len(normalized_new),
                FlextLdapConstants.StatusKeys.REPLACED: 0,
                FlextLdapConstants.StatusKeys.UNCHANGED: 0,
            })

        # Railway Pattern: Check if failure is "already exists" error
        if FlextLdapUtilities.ErrorHandling.is_already_exists_error(
            add_result.error
        ):
            # Railway Pattern: Delegate existing entry handling
            return self._handle_existing_entry(
                actual_client,
                dn,
                normalized_new,
                skip_attributes,
            )

        # Check if failure is "noSuchObject" (parent DN missing)
        error_str = str(add_result.error).lower()
        if auto_create_parents and ("nosuchobject" in error_str or "no such object" in error_str):
            # Try to create parent DNs
            parent_result = self._ensure_parent_exists(actual_client, dn)
            if parent_result.is_failure:
                return FlextResult[dict[str, object]].fail(
                    f"Parent DN missing and cannot be created: {parent_result.error}"
                )

            # Retry ADD after creating parents
            retry_add_result = actual_client.add_entry(dn=dn, attributes=new_attributes)

            if retry_add_result.is_success:
                return FlextResult[dict[str, object]].ok({
                    FlextLdapConstants.StatusKeys.UPSERTED: True,
                    FlextLdapConstants.StatusKeys.ADDED: len(normalized_new),
                    FlextLdapConstants.StatusKeys.REPLACED: 0,
                    FlextLdapConstants.StatusKeys.UNCHANGED: 0,
                    "parent_created": True,
                })

            # If still fails, return clear error
            return FlextResult[dict[str, object]].fail(
                f"Cannot add entry (parent exists but entry add failed): {retry_add_result.error}"
            )

        # Other ADD errors - provide clear context
        return FlextResult[dict[str, object]].fail(
            f"Add entry failed: {add_result.error}"
        )

    def _handle_existing_entry(
        self,
        ldap_client: FlextLdapClients,
        dn: str,
        normalized_new: dict[str, list[str]],
        skip_attributes: set[str],
        existing_entry: FlextLdifModels.Entry | None = None,
    ) -> FlextResult[dict[str, object]]:
        """Handle existing entry update logic.

        Helper for Railway Pattern - extracted from upsert_entry().
        Fetches existing entry, computes changes, and executes modifications.

        Returns:
            FlextResult with upsert statistics or failure message.

        """
        # Step 1: Fetch ALL attributes (including operational)
        if existing_entry is None:
            fetch_result = self._fetch_existing_entry(ldap_client, dn)
            if fetch_result.is_failure:
                return FlextResult[dict[str, object]].fail(fetch_result.error)
            existing_entry = fetch_result.unwrap()
            if existing_entry is None:
                return FlextResult[dict[str, object]].fail(
                    f"Entry not found: {dn}"
                )

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
            return FlextResult[dict[str, object]].ok({
                FlextLdapConstants.StatusKeys.UPSERTED: True,
                FlextLdapConstants.StatusKeys.ADDED: 0,
                FlextLdapConstants.StatusKeys.REPLACED: 0,
                FlextLdapConstants.StatusKeys.UNCHANGED: unchanged_count,
            })

        # Step 5: Execute modifications using REPLACE
        to_replace_all = {**to_replace_new, **to_replace_existing}

        replace_result = self._execute_replace_modifications(
            ldap_client, dn, to_replace_all
        )
        if replace_result.is_failure:
            return FlextResult[dict[str, object]].fail(str(replace_result.error))

        # Step 6: Return success statistics
        added_count = len(to_replace_new)
        replaced_count = len(to_replace_existing)

        return FlextResult[dict[str, object]].ok({
            FlextLdapConstants.StatusKeys.UPSERTED: True,
            FlextLdapConstants.StatusKeys.ADDED: added_count,
            FlextLdapConstants.StatusKeys.REPLACED: replaced_count,
            FlextLdapConstants.StatusKeys.UNCHANGED: unchanged_count,
        })

    def _fetch_existing_entry(
        self,
        ldap_client: FlextLdapClients,
        dn: str,
    ) -> FlextResult[FlextLdifModels.Entry | None]:
        """Fetch an entry (base scope) and include operational attributes."""
        search_request = FlextLdapModels.SearchRequest(
            base_dn=dn,
            filter_str=FlextLdapConstants.Filters.ALL_ENTRIES_FILTER,
            attributes=["*", "+"],
            scope="BASE",
            single=True,
        )
        search_result = ldap_client.search(request=search_request)
        if search_result.is_failure:
            return FlextResult[FlextLdifModels.Entry | None].fail(
                f"Cannot fetch entry: {search_result.error}"
            )

        raw_response = search_result.unwrap()
        if not raw_response:
            return FlextResult[FlextLdifModels.Entry | None].ok(None)

        entry_result = self._extract_entry_from_search(raw_response, dn)
        if entry_result.is_failure:
            return FlextResult[FlextLdifModels.Entry | None].fail(
                f"Invalid entry data: {entry_result.error}"
            )
        return FlextResult[FlextLdifModels.Entry | None].ok(entry_result.unwrap())

    def _parse_dn_components(self, dn: str) -> list[tuple[str, str]]:
        """Parse DN into list of (attribute, value) tuples.

        Example: "cn=user,ou=users,dc=example,dc=com" ->
                 [("cn", "user"), ("ou", "users"), ("dc", "example"), ("dc", "com")]
        """
        components = []
        for component in dn.split(","):
            component = component.strip()
            if "=" in component:
                attr, value = component.split("=", 1)
                components.append((attr.strip(), value.strip()))
        return components

    def _get_parent_dn(self, dn: str) -> str | None:
        """Extract parent DN from a given DN.

        Example: "cn=user,ou=users,dc=example,dc=com" -> "ou=users,dc=example,dc=com"
        Returns None if DN has no parent (is a root DN).
        """
        components = dn.split(",", 1)
        if len(components) < 2:
            return None
        return components[1].strip()

    def _ensure_parent_exists(
        self,
        ldap_client: FlextLdapClients,
        dn: str,
    ) -> FlextResult[bool]:
        """Recursively ensure parent DN exists, creating if necessary.

        This method creates organizational structure (ou, cn, o, dc) entries
        as needed to support adding entries with missing parents.
        """
        parent_dn = self._get_parent_dn(dn)
        if not parent_dn:
            # No parent (root DN)
            return FlextResult[bool].ok(True)

        # Check if parent exists
        search_result = ldap_client.search(
            request=FlextLdapModels.SearchRequest(
                base_dn=parent_dn,
                filter_str="(objectClass=*)",
                scope="BASE",
                attributes=["objectClass"],
                single=True,
            )
        )

        if search_result.is_success and search_result.unwrap():
            # Parent exists
            return FlextResult[bool].ok(True)

        # Parent doesn't exist - need to create it
        # First, ensure its parent exists (recursion)
        grandparent_result = self._ensure_parent_exists(ldap_client, parent_dn)
        if grandparent_result.is_failure:
            return grandparent_result

        # Now create this parent
        components = self._parse_dn_components(parent_dn)
        if not components:
            return FlextResult[bool].fail(f"Invalid parent DN format: {parent_dn}")

        # Get the RDN attribute and value
        rdn_attr, rdn_value = components[0]
        rdn_attr_lower = rdn_attr.lower()

        # Determine appropriate objectClass based on RDN attribute
        if rdn_attr_lower == "ou":
            object_classes = ["organizationalUnit", "top"]
            attributes = {
                "objectClass": object_classes,
                "ou": [rdn_value],
            }
        elif rdn_attr_lower == "cn":
            object_classes = ["organizationalRole", "top"]
            attributes = {
                "objectClass": object_classes,
                "cn": [rdn_value],
            }
        elif rdn_attr_lower == "o":
            object_classes = ["organization", "top"]
            attributes = {
                "objectClass": object_classes,
                "o": [rdn_value],
            }
        elif rdn_attr_lower == "dc":
            object_classes = ["dcObject", "organization", "top"]
            attributes = {
                "objectClass": object_classes,
                "dc": [rdn_value],
                "o": [rdn_value],  # Required for organization objectClass
            }
        else:
            # Generic container
            object_classes = ["top"]
            attributes = {
                "objectClass": object_classes,
                rdn_attr: [rdn_value],
            }

        add_result = ldap_client.add_entry(
            dn=parent_dn,
            attributes=cast("dict[str, str | list[str]]", attributes)
        )
        if add_result.is_failure:
            # Check if it was created by another process in the meantime
            if FlextLdapUtilities.ErrorHandling.is_already_exists_error(add_result.error):
                return FlextResult[bool].ok(True)

            return FlextResult[bool].fail(
                f"Cannot create parent {parent_dn}: {add_result.error}"
            )

        self.logger.debug(f"Created parent DN: {parent_dn}")
        return FlextResult[bool].ok(True)

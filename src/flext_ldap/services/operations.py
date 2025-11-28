"""LDAP Operations Service.

This service provides LDAP CRUD operations (search, add, modify, delete, upsert).
Delegates to Ldap3Adapter which handles conversion to Entry models using FlextLdifParser,
maximizing code reuse. Supports batch operations and entry comparison for upsert logic.

Modules: FlextLdapOperations
Scope: LDAP CRUD operations, entry comparison, batch upsert, entry existence checking
Pattern: Service extending FlextLdapServiceBase, delegates to Ldap3Adapter for actual operations

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from collections.abc import Callable
from typing import cast

from flext_core import FlextResult, FlextRuntime, FlextUtilities
from flext_ldif import FlextLdifModels
from flext_ldif.utilities import FlextLdifUtilities
from ldap3 import MODIFY_ADD, MODIFY_DELETE, MODIFY_REPLACE

from flext_ldap.base import FlextLdapServiceBase
from flext_ldap.config import FlextLdapConfig
from flext_ldap.constants import FlextLdapConstants
from flext_ldap.models import FlextLdapModels
from flext_ldap.protocols import FlextLdapProtocols
from flext_ldap.typings import FlextLdapTypes


class FlextLdapOperations(FlextLdapServiceBase[FlextLdapModels.SearchResult]):
    """LDAP operations service providing CRUD operations.

    Handles search, add, modify, and delete operations.
    Delegates to Ldap3Adapter which already uses FlextLdifParser for conversion.
    This maximizes code reuse - adapter handles all parsing logic.
    """

    _connection: FlextLdapProtocols.LdapConnection

    class EntryComparison:
        """Entry comparison logic - detects attribute changes for modify operations."""

        @staticmethod
        def extract_attributes(
            entry: FlextLdapProtocols.EntryProtocol | FlextLdifModels.Entry,
        ) -> dict[str, list[str]]:
            """Extract attributes from entry in normalized dict format."""
            if not entry.attributes:
                return {}
            # Type narrowing: FlextLdifModels.Entry has LdifAttributes with .attributes
            if isinstance(entry, FlextLdifModels.Entry):
                # LdifAttributes has .attributes: dict[str, list[str]]
                ldif_entry = cast("FlextLdifModels.Entry", entry)
                return ldif_entry.attributes.attributes
            # EntryProtocol has attributes: Mapping[str, Sequence[str]]
            if hasattr(entry, "attributes"):
                attrs = entry.attributes
                if hasattr(attrs, "items"):
                    return {k: list(v) for k, v in attrs.items()}
                if hasattr(attrs, "attributes"):
                    return attrs.attributes
            return {}

        @staticmethod
        def normalize_value_set(values: list[str]) -> set[str]:
            """Normalize attribute values to lowercase set for comparison."""
            return {str(v).lower() for v in values if v}

        @staticmethod
        def find_existing_values(
            attr_name: str,
            existing_attrs: dict[str, list[str]],
        ) -> list[str] | None:
            """Find existing attribute values by case-insensitive name."""
            attr_lower = attr_name.lower()
            return next(
                (v for k, v in existing_attrs.items() if k.lower() == attr_lower),
                None,
            )

        @staticmethod
        def process_new_attributes(
            new_attrs: dict[str, list[str]],
            existing_attrs: dict[str, list[str]],
            ignore: frozenset[str],
        ) -> tuple[FlextLdapTypes.LdapModifyChanges, set[str]]:
            """Process new attributes and detect changes."""
            changes: FlextLdapTypes.LdapModifyChanges = {}
            processed = set()

            for attr_name, new_vals in new_attrs.items():
                if not FlextRuntime.is_list_like(new_vals):
                    continue
                attr_lower = attr_name.lower()
                if attr_lower in ignore:
                    continue
                processed.add(attr_lower)

                existing_vals = (
                    FlextLdapOperations.EntryComparison.find_existing_values(
                        attr_name,
                        existing_attrs,
                    )
                )
                if existing_vals and FlextRuntime.is_list_like(existing_vals):
                    existing_set = (
                        FlextLdapOperations.EntryComparison.normalize_value_set([
                            str(v) for v in existing_vals if v
                        ])
                    )
                else:
                    existing_set = set()
                new_set = FlextLdapOperations.EntryComparison.normalize_value_set([
                    str(v) for v in new_vals if v
                ])
                if existing_set != new_set:
                    changes[attr_name] = [
                        (MODIFY_REPLACE, [str(v) for v in new_vals if v])
                    ]

            return changes, processed

        @staticmethod
        def process_deleted_attributes(
            existing_attrs: dict[str, list[str]],
            ignore: frozenset[str],
            processed: set[str],
        ) -> FlextLdapTypes.LdapModifyChanges:
            """Process attributes that exist in old but not in new (deletions)."""
            changes: FlextLdapTypes.LdapModifyChanges = {}

            for attr_name, existing_vals in existing_attrs.items():
                if not FlextRuntime.is_list_like(existing_vals):
                    continue
                attr_lower = attr_name.lower()
                if attr_lower not in ignore and attr_lower not in processed:
                    changes[attr_name] = [(MODIFY_DELETE, [])]

            return changes

        @staticmethod
        def compare(
            existing_entry: FlextLdapProtocols.EntryProtocol | FlextLdifModels.Entry,
            new_entry: FlextLdapProtocols.EntryProtocol | FlextLdifModels.Entry,
        ) -> FlextLdapTypes.LdapModifyChanges | None:
            """Compare two entries and return modify changes if different."""
            existing_attrs = FlextLdapOperations.EntryComparison.extract_attributes(
                existing_entry
            )
            new_attrs = FlextLdapOperations.EntryComparison.extract_attributes(
                new_entry
            )

            if not existing_attrs or not new_attrs:
                return None

            ignore = FlextLdapConstants.OperationalAttributes.IGNORE_SET
            changes, processed = (
                FlextLdapOperations.EntryComparison.process_new_attributes(
                    new_attrs,
                    existing_attrs,
                    ignore,
                )
            )
            delete_changes = (
                FlextLdapOperations.EntryComparison.process_deleted_attributes(
                    existing_attrs,
                    ignore,
                    processed,
                )
            )
            changes.update(delete_changes)

            return changes or None

    class _UpsertHandler:
        """Upsert operation handler (SRP)."""

        def __init__(self, operations: FlextLdapOperations) -> None:
            """Initialize with operations service."""
            self._ops = operations

        def execute(
            self, entry: FlextLdifModels.Entry
        ) -> FlextResult[FlextLdapModels.LdapOperationResult]:
            """Execute upsert operation."""
            attrs = entry.attributes.attributes if entry.attributes else {}
            changetype_val = attrs.get(
                FlextLdapConstants.LdapAttributeNames.CHANGETYPE, []
            )
            changetype = changetype_val[0].lower() if changetype_val else ""

            if changetype == FlextLdapConstants.ChangeTypeOperations.MODIFY:
                return self.handle_schema_modify(entry)
            return self.handle_regular_add(entry)

        def handle_schema_modify(
            self, entry: FlextLdifModels.Entry
        ) -> FlextResult[FlextLdapModels.LdapOperationResult]:
            """Handle schema modify operation."""
            attrs = entry.attributes.attributes if entry.attributes else {}
            add_op = attrs.get(FlextLdapConstants.ChangeTypeOperations.ADD, [])
            if not add_op:
                return FlextResult[FlextLdapModels.LdapOperationResult].fail(
                    "Schema modify entry missing 'add' attribute"
                )

            attr_type = add_op[0]
            attr_values = attrs.get(attr_type, [])
            filtered = [v for v in attr_values if v]

            if not filtered:
                return FlextResult[FlextLdapModels.LdapOperationResult].fail(
                    f"Schema modify entry has only empty values for '{attr_type}'"
                )

            changes: FlextLdapTypes.LdapModifyChanges = {
                attr_type: [(MODIFY_ADD, filtered)]
            }
            modify_result = self._ops.modify(str(entry.dn), changes)

            if modify_result.is_success:
                return FlextResult[FlextLdapModels.LdapOperationResult].ok(
                    FlextLdapModels.LdapOperationResult(
                        operation=FlextLdapConstants.UpsertOperations.MODIFIED
                    )
                )

            error_str = str(modify_result.error) if modify_result.error else ""
            if self._ops.is_already_exists_error(error_str):
                return FlextResult[FlextLdapModels.LdapOperationResult].ok(
                    FlextLdapModels.LdapOperationResult(
                        operation=FlextLdapConstants.UpsertOperations.SKIPPED
                    )
                )

            return FlextResult[FlextLdapModels.LdapOperationResult].fail(
                error_str or FlextLdapConstants.ErrorStrings.UNKNOWN_ERROR
            )

        def handle_regular_add(
            self, entry: FlextLdifModels.Entry
        ) -> FlextResult[FlextLdapModels.LdapOperationResult]:
            """Handle regular add operation."""
            add_result = self._ops.add(entry)

            if add_result.is_success:
                return FlextResult[FlextLdapModels.LdapOperationResult].ok(
                    FlextLdapModels.LdapOperationResult(
                        operation=FlextLdapConstants.UpsertOperations.ADDED
                    )
                )

            error_str = str(add_result.error) if add_result.error else ""
            if not self._ops.is_already_exists_error(error_str):
                return FlextResult[FlextLdapModels.LdapOperationResult].fail(error_str)

            return self.handle_existing_entry(entry)

        def handle_existing_entry(
            self, entry: FlextLdifModels.Entry
        ) -> FlextResult[FlextLdapModels.LdapOperationResult]:
            """Handle upsert when entry already exists."""
            entry_dn = str(entry.dn) if entry.dn else "unknown"
            search_options = FlextLdapModels.SearchOptions(
                base_dn=entry_dn,
                filter_str=FlextLdapConstants.Filters.ALL_ENTRIES_FILTER,
                scope=FlextLdapConstants.SearchScope.BASE,
            )

            search_result = self._ops.search(search_options)
            if search_result.is_failure:
                return FlextResult[FlextLdapModels.LdapOperationResult].ok(
                    FlextLdapModels.LdapOperationResult(
                        operation=FlextLdapConstants.UpsertOperations.SKIPPED
                    )
                )

            existing_entries = search_result.unwrap().entries
            if not existing_entries:
                retry_result = self._ops.add(entry)
                if retry_result.is_success:
                    return FlextResult[FlextLdapModels.LdapOperationResult].ok(
                        FlextLdapModels.LdapOperationResult(
                            operation=FlextLdapConstants.UpsertOperations.ADDED
                        )
                    )
                return FlextResult[FlextLdapModels.LdapOperationResult].fail(
                    str(retry_result.error) if retry_result.error else ""
                )

            changes = FlextLdapOperations.EntryComparison.compare(
                existing_entries[0], entry
            )
            if not changes:
                return FlextResult[FlextLdapModels.LdapOperationResult].ok(
                    FlextLdapModels.LdapOperationResult(
                        operation=FlextLdapConstants.UpsertOperations.SKIPPED
                    )
                )

            modify_result = self._ops.modify(entry_dn, changes)
            if modify_result.is_success:
                return FlextResult[FlextLdapModels.LdapOperationResult].ok(
                    FlextLdapModels.LdapOperationResult(
                        operation=FlextLdapConstants.UpsertOperations.MODIFIED
                    )
                )

            return FlextResult[FlextLdapModels.LdapOperationResult].fail(
                str(modify_result.error) if modify_result.error else ""
            )

    @staticmethod
    def is_already_exists_error(error_message: str) -> bool:
        """Check if error message indicates entry already exists."""
        error_lower = error_message.lower()
        return (
            str(FlextLdapConstants.ErrorStrings.ENTRY_ALREADY_EXISTS) in error_lower
            or str(FlextLdapConstants.ErrorStrings.ENTRY_ALREADY_EXISTS_ALT)
            in error_lower
            or str(FlextLdapConstants.ErrorStrings.ENTRY_ALREADY_EXISTS_LDAP)
            in error_lower
        )

    def __init__(
        self,
        connection: FlextLdapProtocols.LdapConnection,
        **kwargs: str | float | bool | None,
    ) -> None:
        """Initialize operations service."""
        super().__init__(**kwargs)
        self._connection = connection
        self._upsert_handler = self._UpsertHandler(self)

    def search(
        self,
        search_options: FlextLdapModels.SearchOptions,
        server_type: FlextLdapConstants.ServerTypes
        | str = FlextLdapConstants.ServerTypes.RFC,
        **_kwargs: str | float | bool | None,
    ) -> FlextResult[FlextLdapModels.SearchResult]:
        """Perform LDAP search operation."""
        normalized_options = search_options.model_copy(
            update={
                "base_dn": FlextLdifUtilities.DN.norm_string(search_options.base_dn)
            }
        )
        result = self._connection.adapter.search(
            normalized_options, server_type=server_type
        )
        # Type narrowing: adapter returns FlextResult[object] but actual type is SearchResult
        if result.is_success:
            search_result = result.unwrap()
            if isinstance(search_result, FlextLdapModels.SearchResult):
                return FlextResult[FlextLdapModels.SearchResult].ok(search_result)
        error_msg = str(result.error) if result.error else "Unknown error"
        return FlextResult[FlextLdapModels.SearchResult].fail(error_msg)

    def add(
        self,
        entry: FlextLdifModels.Entry,
        **_kwargs: str | float | bool | None,
    ) -> FlextResult[FlextLdapModels.OperationResult]:
        """Add LDAP entry."""
        result = self._connection.adapter.add(entry)
        # Type narrowing: adapter returns FlextResult[object] but actual type is OperationResult
        if result.is_success:
            operation_result = result.unwrap()
            if isinstance(operation_result, FlextLdapModels.OperationResult):
                return FlextResult[FlextLdapModels.OperationResult].ok(operation_result)
        error_msg = str(result.error) if result.error else "Unknown error"
        return FlextResult[FlextLdapModels.OperationResult].fail(error_msg)

    def modify(
        self,
        dn: str | FlextLdifModels.DistinguishedName,
        changes: FlextLdapTypes.LdapModifyChanges,
        **_kwargs: str | float | bool | None,
    ) -> FlextResult[FlextLdapModels.OperationResult]:
        """Modify LDAP entry."""
        dn_model = (
            dn
            if isinstance(dn, FlextLdifModels.DistinguishedName)
            else FlextLdifModels.DistinguishedName(
                value=FlextLdifUtilities.DN.get_dn_value(dn)
            )
        )
        result = self._connection.adapter.modify(
            dn_model,
            changes,
        )
        # Type narrowing: adapter returns FlextResult[object] but actual type is OperationResult
        if result.is_success:
            operation_result = result.unwrap()
            if isinstance(operation_result, FlextLdapModels.OperationResult):
                return FlextResult[FlextLdapModels.OperationResult].ok(operation_result)
        error_msg = str(result.error) if result.error else "Unknown error"
        return FlextResult[FlextLdapModels.OperationResult].fail(error_msg)

    def delete(
        self,
        dn: str | FlextLdifModels.DistinguishedName,
        **_kwargs: str | float | bool | None,
    ) -> FlextResult[FlextLdapModels.OperationResult]:
        """Delete LDAP entry."""
        dn_model = (
            dn
            if isinstance(dn, FlextLdifModels.DistinguishedName)
            else FlextLdifModels.DistinguishedName(
                value=FlextLdifUtilities.DN.get_dn_value(dn)
            )
        )
        result = self._connection.adapter.delete(
            cast("FlextLdapProtocols.DistinguishedNameProtocol", dn_model)
        )
        # Type narrowing: adapter returns FlextResult[object] but actual type is OperationResult
        if result.is_success:
            operation_result = result.unwrap()
            if isinstance(operation_result, FlextLdapModels.OperationResult):
                return FlextResult[FlextLdapModels.OperationResult].ok(operation_result)
        error_msg = str(result.error) if result.error else "Unknown error"
        return FlextResult[FlextLdapModels.OperationResult].fail(error_msg)

    @property
    def is_connected(self) -> bool:
        """Check if operations service has active connection."""
        return self._connection.is_connected

    def upsert(
        self,
        entry: FlextLdifModels.Entry,
        *,
        retry_on_errors: list[str] | None = None,
        max_retries: int = 1,
    ) -> FlextResult[FlextLdapModels.LdapOperationResult]:
        """Upsert LDAP entry with retry logic."""
        if not retry_on_errors or max_retries <= 1:
            return self._upsert_handler.execute(entry)

        result = self._upsert_handler.execute(entry)
        if result.is_success or not retry_on_errors:
            return result

        error_str = str(result.error).lower()
        if not any(pattern.lower() in error_str for pattern in retry_on_errors):
            return result

        return FlextUtilities.Reliability.retry(
            operation=lambda: self._upsert_handler.execute(entry),
            max_attempts=max_retries,
            delay_seconds=1.0,
        )

    def batch_upsert(
        self,
        entries: list[FlextLdifModels.Entry],
        *,
        progress_callback: Callable[
            [int, int, str, FlextLdapModels.LdapBatchStats], None
        ]
        | None = None,
        retry_on_errors: list[str] | None = None,
        max_retries: int = 1,
        stop_on_error: bool = False,
    ) -> FlextResult[FlextLdapModels.LdapBatchStats]:
        """Batch upsert multiple LDAP entries with progress tracking."""
        synced = 0
        failed = 0
        skipped = 0
        total_entries = len(entries)

        for i, entry in enumerate(entries, 1):
            entry_dn = entry.dn.value if entry.dn else "unknown"
            upsert_result = self.upsert(
                entry, retry_on_errors=retry_on_errors, max_retries=max_retries
            )

            if upsert_result.is_success:
                operation = upsert_result.unwrap().operation
                if operation == FlextLdapConstants.UpsertOperations.SKIPPED:
                    skipped += 1
                elif operation in {
                    FlextLdapConstants.UpsertOperations.ADDED,
                    FlextLdapConstants.UpsertOperations.MODIFIED,
                }:
                    synced += 1
            else:
                failed += 1
                self.logger.error(
                    "Batch upsert entry failed",
                    entry_index=i,
                    total_entries=total_entries,
                    entry_dn=entry_dn[:100] if entry_dn else None,
                    error=str(upsert_result.error)[:200],
                )

                if stop_on_error:
                    return FlextResult[FlextLdapModels.LdapBatchStats].fail(
                        f"Batch upsert stopped on error at entry {i}/{total_entries}: {upsert_result.error}"
                    )

            if progress_callback:
                try:
                    callback_stats = FlextLdapModels.LdapBatchStats(
                        synced=synced, failed=failed, skipped=skipped
                    )
                    progress_callback(i, total_entries, entry_dn, callback_stats)
                except Exception as e:
                    self.logger.warning(
                        "Progress callback failed",
                        operation=FlextLdapConstants.LdapOperationNames.SYNC,
                        entry_index=i,
                        error=str(e),
                    )

        stats = FlextLdapModels.LdapBatchStats(
            synced=synced, failed=failed, skipped=skipped
        )

        self.logger.info(
            "Batch upsert completed",
            operation=FlextLdapConstants.LdapOperationNames.BATCH_UPSERT.value,
            total_entries=total_entries,
            synced=synced,
            failed=failed,
            skipped=skipped,
        )

        if synced == 0 and failed > 0:
            return FlextResult[FlextLdapModels.LdapBatchStats].fail(
                f"Batch upsert failed: all {failed} entries failed, 0 synced"
            )

        return FlextResult[FlextLdapModels.LdapBatchStats].ok(stats)

    def execute(
        self, **_kwargs: str | float | bool | None
    ) -> FlextResult[FlextLdapModels.SearchResult]:
        """Execute service health check."""
        if not self._connection.is_connected:
            return FlextResult[FlextLdapModels.SearchResult].fail(
                FlextLdapConstants.ErrorStrings.NOT_CONNECTED
            )

        ldap_config = self.config.get_namespace("ldap", FlextLdapConfig)
        base_dn = getattr(ldap_config, "base_dn", None) or "dc=example,dc=com"
        return FlextResult[FlextLdapModels.SearchResult].ok(
            FlextLdapModels.SearchResult(
                entries=[],
                search_options=FlextLdapModels.SearchOptions(
                    base_dn=base_dn,
                    filter_str=FlextLdapConstants.Filters.ALL_ENTRIES_FILTER,
                ),
            )
        )

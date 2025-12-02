"""Search, CRUD, and upsert helpers built on ``Ldap3Adapter``.

This module keeps protocol concerns inside the adapter while exposing typed
inputs, normalized results, and reusable comparison utilities for callers.
"""

from __future__ import annotations

from collections.abc import Callable, Mapping, Sequence

from flext_core import FlextResult, FlextRuntime, FlextUtilities
from flext_ldif import FlextLdifModels
from flext_ldif.constants import FlextLdifConstants
from flext_ldif.utilities import FlextLdifUtilities
from ldap3 import MODIFY_ADD, MODIFY_DELETE, MODIFY_REPLACE
from pydantic import ConfigDict

from flext_ldap.base import FlextLdapServiceBase
from flext_ldap.config import FlextLdapConfig
from flext_ldap.constants import FlextLdapConstants
from flext_ldap.models import FlextLdapModels
from flext_ldap.protocols import FlextLdapProtocols
from flext_ldap.services.connection import FlextLdapConnection
from flext_ldap.typings import FlextLdapTypes


class FlextLdapOperations(FlextLdapServiceBase[FlextLdapModels.SearchResult]):
    """Coordinate LDAP operations on an active connection.

    Protocol calls are delegated to :class:`~flext_ldap.adapters.ldap3.Ldap3Adapter`
    so this layer can concentrate on typed arguments, predictable
    :class:`flext_core.FlextResult` responses, and shared comparison helpers.
    """

    model_config = ConfigDict(
        frozen=False,  # Service needs mutable state for connection reference
        extra="allow",
        arbitrary_types_allowed=True,
    )

    _connection: FlextLdapConnection

    class EntryComparison:
        """Compute attribute-level differences between entries.

        Utilities normalize attribute keys and values to build precise
        ``MODIFY`` payloads without duplicating comparison logic across
        services or tests.
        """

        @staticmethod
        def extract_attributes(
            entry: FlextLdapProtocols.LdapEntry.EntryProtocol | FlextLdifModels.Entry,
        ) -> Mapping[str, Sequence[str]]:
            """Return entry attributes as a normalized mapping of lists."""
            if not entry.attributes:
                return {}
            # Type narrowing: FlextLdifModels.Entry has LdifAttributes with .attributes
            if isinstance(entry, FlextLdifModels.Entry):
                # LdifAttributes has .attributes: dict[str, list[str]]
                ldif_attrs = entry.attributes
                if ldif_attrs and hasattr(ldif_attrs, "attributes"):
                    # Type is already dict[str, list[str]], no isinstance needed
                    return ldif_attrs.attributes
                return {}
            # EntryProtocol has attributes: Mapping[str, Sequence[str]]
            attrs = entry.attributes
            if isinstance(attrs, Mapping):
                return {k: list(v) for k, v in attrs.items()}
            if hasattr(attrs, "attributes"):
                attrs_dict = attrs.attributes
                # Type is already Mapping[str, Sequence[str]], isinstance check redundant
                return {k: list(v) for k, v in attrs_dict.items()}
            return {}

        @staticmethod
        def normalize_value_set(values: list[str]) -> set[str]:
            """Normalize attribute values to a lowercase set for comparison."""
            return {str(v).lower() for v in values if v}

        @staticmethod
        def find_existing_values(
            attr_name: str,
            existing_attrs: Mapping[str, Sequence[str]],
        ) -> list[str] | None:
            """Find existing attribute values by case-insensitive name."""
            attr_lower = attr_name.lower()
            found = next(
                (v for k, v in existing_attrs.items() if k.lower() == attr_lower),
                None,
            )
            # Convert Sequence[str] to list[str] for return type compatibility
            return list(found) if found is not None else None

        @staticmethod
        def process_new_attributes(
            new_attrs: Mapping[str, Sequence[str]],
            existing_attrs: Mapping[str, Sequence[str]],
            ignore: frozenset[str],
        ) -> tuple[FlextLdapTypes.Ldap.ModifyChanges, set[str]]:
            """Process new attributes and detect replacement changes."""
            changes: FlextLdapTypes.Ldap.ModifyChanges = {}
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
                        (MODIFY_REPLACE, [str(v) for v in new_vals if v]),
                    ]

            return changes, processed

        @staticmethod
        def process_deleted_attributes(
            existing_attrs: Mapping[str, Sequence[str]],
            ignore: frozenset[str],
            processed: set[str],
        ) -> FlextLdapTypes.Ldap.ModifyChanges:
            """Capture deletions for attributes missing from the new entry."""
            changes: FlextLdapTypes.Ldap.ModifyChanges = {}

            for attr_name, existing_vals in existing_attrs.items():
                if not FlextRuntime.is_list_like(existing_vals):
                    continue
                attr_lower = attr_name.lower()
                if attr_lower not in ignore and attr_lower not in processed:
                    changes[attr_name] = [(MODIFY_DELETE, [])]

            return changes

        @staticmethod
        def compare(
            existing_entry: FlextLdapProtocols.LdapEntry.EntryProtocol
            | FlextLdifModels.Entry,
            new_entry: FlextLdapProtocols.LdapEntry.EntryProtocol
            | FlextLdifModels.Entry,
        ) -> FlextLdapTypes.Ldap.ModifyChanges | None:
            """Compare two entries and return modify changes when needed."""
            existing_attrs_raw = FlextLdapOperations.EntryComparison.extract_attributes(
                existing_entry,
            )
            new_attrs_raw = FlextLdapOperations.EntryComparison.extract_attributes(
                new_entry,
            )
            # Convert to dict for processing
            existing_attrs: dict[str, list[str]] = {
                k: list(v) for k, v in existing_attrs_raw.items()
            }
            new_attrs: dict[str, list[str]] = {
                k: list(v) for k, v in new_attrs_raw.items()
            }

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
        """Handle add-or-modify flows for upsert calls."""

        def __init__(self, operations: FlextLdapOperations) -> None:
            """Store a reference to the operations service."""
            super().__init__()
            self._ops = operations

        def execute(
            self,
            entry: FlextLdifModels.Entry,
        ) -> FlextResult[FlextLdapModels.LdapOperationResult]:
            """Execute an upsert operation for the provided entry."""
            attrs = entry.attributes.attributes if entry.attributes else {}
            changetype_val = attrs.get(
                FlextLdapConstants.LdapAttributeNames.CHANGETYPE,
                [],
            )
            changetype = changetype_val[0].lower() if changetype_val else ""

            if changetype == FlextLdapConstants.ChangeTypeOperations.MODIFY:
                return self.handle_schema_modify(entry)
            return self.handle_regular_add(entry)

        def handle_schema_modify(
            self,
            entry: FlextLdifModels.Entry,
        ) -> FlextResult[FlextLdapModels.LdapOperationResult]:
            """Apply a schema modification entry."""
            attrs = entry.attributes.attributes if entry.attributes else {}
            add_op = attrs.get(FlextLdapConstants.ChangeTypeOperations.ADD, [])
            if not add_op:
                return FlextResult[FlextLdapModels.LdapOperationResult].fail(
                    "Schema modify entry missing 'add' attribute",
                )

            attr_type = add_op[0]
            attr_values = attrs.get(attr_type, [])
            filtered = [v for v in attr_values if v]

            if not filtered:
                return FlextResult[FlextLdapModels.LdapOperationResult].fail(
                    f"Schema modify entry has only empty values for '{attr_type}'",
                )

            changes: FlextLdapTypes.Ldap.ModifyChanges = {
                attr_type: [(MODIFY_ADD, filtered)],
            }
            modify_result = self._ops.modify(str(entry.dn), changes)

            if modify_result.is_success:
                return FlextResult[FlextLdapModels.LdapOperationResult].ok(
                    FlextLdapModels.LdapOperationResult(
                        operation=FlextLdapConstants.UpsertOperations.MODIFIED,
                    ),
                )

            error_str = str(modify_result.error) if modify_result.error else ""
            if self._ops.is_already_exists_error(error_str):
                return FlextResult[FlextLdapModels.LdapOperationResult].ok(
                    FlextLdapModels.LdapOperationResult(
                        operation=FlextLdapConstants.UpsertOperations.SKIPPED,
                    ),
                )

            return FlextResult[FlextLdapModels.LdapOperationResult].fail(
                error_str or FlextLdapConstants.ErrorStrings.UNKNOWN_ERROR,
            )

        def handle_regular_add(
            self,
            entry: FlextLdifModels.Entry,
        ) -> FlextResult[FlextLdapModels.LdapOperationResult]:
            """Add a standard entry or fall back to existing-entry handling."""
            add_result = self._ops.add(entry)

            if add_result.is_success:
                return FlextResult[FlextLdapModels.LdapOperationResult].ok(
                    FlextLdapModels.LdapOperationResult(
                        operation=FlextLdapConstants.UpsertOperations.ADDED,
                    ),
                )

            error_str = str(add_result.error) if add_result.error else ""
            if not self._ops.is_already_exists_error(error_str):
                return FlextResult[FlextLdapModels.LdapOperationResult].fail(error_str)

            return self.handle_existing_entry(entry)

        def handle_existing_entry(
            self,
            entry: FlextLdifModels.Entry,
        ) -> FlextResult[FlextLdapModels.LdapOperationResult]:
            """Handle an upsert when the entry already exists in LDAP."""
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
                        operation=FlextLdapConstants.UpsertOperations.SKIPPED,
                    ),
                )

            existing_entries = search_result.unwrap().entries
            if not existing_entries:
                retry_result = self._ops.add(entry)
                if retry_result.is_success:
                    return FlextResult[FlextLdapModels.LdapOperationResult].ok(
                        FlextLdapModels.LdapOperationResult(
                            operation=FlextLdapConstants.UpsertOperations.ADDED,
                        ),
                    )
                return FlextResult[FlextLdapModels.LdapOperationResult].fail(
                    str(retry_result.error) if retry_result.error else "",
                )

            changes = FlextLdapOperations.EntryComparison.compare(
                existing_entries[0],
                entry,
            )
            if not changes:
                return FlextResult[FlextLdapModels.LdapOperationResult].ok(
                    FlextLdapModels.LdapOperationResult(
                        operation=FlextLdapConstants.UpsertOperations.SKIPPED,
                    ),
                )

            modify_result = self._ops.modify(entry_dn, changes)
            if modify_result.is_success:
                return FlextResult[FlextLdapModels.LdapOperationResult].ok(
                    FlextLdapModels.LdapOperationResult(
                        operation=FlextLdapConstants.UpsertOperations.MODIFIED,
                    ),
                )

            return FlextResult[FlextLdapModels.LdapOperationResult].fail(
                str(modify_result.error) if modify_result.error else "",
            )

    @staticmethod
    def is_already_exists_error(error_message: str) -> bool:
        """Return ``True`` when the error indicates an existing entry."""
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
        connection: FlextLdapConnection,
        **kwargs: str | float | bool | None,
    ) -> None:
        """Initialize the operations service with a live connection."""
        super().__init__(**kwargs)
        self._connection = connection
        self._upsert_handler = self._UpsertHandler(self)

    def search(
        self,
        search_options: FlextLdapModels.SearchOptions,
        server_type: FlextLdifConstants.ServerTypes
        | str = FlextLdifConstants.ServerTypes.RFC,
        **_kwargs: str | float | bool | None,
    ) -> FlextResult[FlextLdapModels.SearchResult]:
        """Perform an LDAP search using normalized search options."""
        normalized_options = search_options.model_copy(
            update={
                "base_dn": FlextLdifUtilities.DN.norm_string(search_options.base_dn),
            },
        )
        result = self._connection.adapter.search(
            normalized_options,
            server_type=server_type,
        )
        # Adapter returns FlextResult[SearchResultProtocol] - unwrap directly
        if result.is_success:
            search_result = result.unwrap()
            # Type narrowing: SearchResultProtocol is compatible with SearchResult model
            return FlextResult[FlextLdapModels.SearchResult].ok(search_result)
        error_msg = str(result.error) if result.error else "Unknown error"
        return FlextResult[FlextLdapModels.SearchResult].fail(error_msg)

    def add(
        self,
        entry: FlextLdifModels.Entry,
        **_kwargs: str | float | bool | None,
    ) -> FlextResult[FlextLdapModels.OperationResult]:
        """Add an LDAP entry using the active adapter connection."""
        result = self._connection.adapter.add(entry)
        # Adapter returns FlextResult[OperationResultProtocol] - unwrap directly
        if result.is_success:
            operation_result = result.unwrap()
            return FlextResult[FlextLdapModels.OperationResult].ok(operation_result)
        error_msg = str(result.error) if result.error else "Unknown error"
        return FlextResult[FlextLdapModels.OperationResult].fail(error_msg)

    def modify(
        self,
        dn: str | FlextLdapProtocols.LdapEntry.DistinguishedNameProtocol,
        changes: FlextLdapTypes.Ldap.ModifyChanges,
        **_kwargs: str | float | bool | None,
    ) -> FlextResult[FlextLdapModels.OperationResult]:
        """Modify an LDAP entry with the provided change set."""
        # Type narrowing: convert str to DistinguishedName model if needed
        if isinstance(dn, str):
            dn_model: FlextLdapProtocols.LdapEntry.DistinguishedNameProtocol = (
                FlextLdifModels.DistinguishedName(
                    value=FlextLdifUtilities.DN.get_dn_value(dn),
                )
            )
        else:
            dn_model = dn
        result = self._connection.adapter.modify(
            dn_model,
            changes,
        )
        # Adapter returns FlextResult[OperationResultProtocol] - unwrap directly
        if result.is_success:
            operation_result = result.unwrap()
            return FlextResult[FlextLdapModels.OperationResult].ok(operation_result)
        error_msg = str(result.error) if result.error else "Unknown error"
        return FlextResult[FlextLdapModels.OperationResult].fail(error_msg)

    def delete(
        self,
        dn: str | FlextLdapProtocols.LdapEntry.DistinguishedNameProtocol,
        **_kwargs: str | float | bool | None,
    ) -> FlextResult[FlextLdapModels.OperationResult]:
        """Delete an LDAP entry identified by DN."""
        # Type narrowing: convert str to DistinguishedName model if needed
        if isinstance(dn, str):
            dn_model: FlextLdapProtocols.LdapEntry.DistinguishedNameProtocol = (
                FlextLdifModels.DistinguishedName(
                    value=FlextLdifUtilities.DN.get_dn_value(dn),
                )
            )
        else:
            dn_model = dn
        result = self._connection.adapter.delete(dn_model)
        # Adapter returns FlextResult[OperationResultProtocol] - unwrap directly
        if result.is_success:
            operation_result = result.unwrap()
            return FlextResult[FlextLdapModels.OperationResult].ok(operation_result)
        error_msg = str(result.error) if result.error else "Unknown error"
        return FlextResult[FlextLdapModels.OperationResult].fail(error_msg)

    @property
    def is_connected(self) -> bool:
        """Return ``True`` when the underlying connection is bound."""
        return self._connection.is_connected

    def upsert(
        self,
        entry: FlextLdifModels.Entry,
        *,
        retry_on_errors: list[str] | None = None,
        max_retries: int = 1,
    ) -> FlextResult[FlextLdapModels.LdapOperationResult]:
        """Upsert an entry, optionally retrying for configured error patterns."""
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
            [int, int, str, FlextLdapModels.LdapBatchStats],
            None,
        ]
        | None = None,
        retry_on_errors: list[str] | None = None,
        max_retries: int = 1,
        stop_on_error: bool = False,
    ) -> FlextResult[FlextLdapModels.LdapBatchStats]:
        """Upsert multiple entries and track per-item progress."""
        synced = 0
        failed = 0
        skipped = 0
        total_entries = len(entries)

        for i, entry in enumerate(entries, 1):
            entry_dn = entry.dn.value if entry.dn else "unknown"
            upsert_result = self.upsert(
                entry,
                retry_on_errors=retry_on_errors,
                max_retries=max_retries,
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
                        f"Batch upsert stopped on error at entry {i}/{total_entries}: {upsert_result.error}",
                    )

            if progress_callback:
                try:
                    callback_stats = FlextLdapModels.LdapBatchStats(
                        synced=synced,
                        failed=failed,
                        skipped=skipped,
                    )
                    progress_callback(i, total_entries, entry_dn, callback_stats)
                except (RuntimeError, TypeError, ValueError) as e:
                    self.logger.warning(
                        "Progress callback failed",
                        operation=FlextLdapConstants.LdapOperationNames.SYNC,
                        entry_index=i,
                        error=str(e),
                    )

        stats = FlextLdapModels.LdapBatchStats(
            synced=synced,
            failed=failed,
            skipped=skipped,
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
                f"Batch upsert failed: all {failed} entries failed, 0 synced",
            )

        return FlextResult[FlextLdapModels.LdapBatchStats].ok(stats)

    def execute(
        self,
        **_kwargs: str | float | bool | None,
    ) -> FlextResult[FlextLdapModels.SearchResult]:
        """Report readiness; fails when the connection is not bound."""
        if not self._connection.is_connected:
            return FlextResult[FlextLdapModels.SearchResult].fail(
                FlextLdapConstants.ErrorStrings.NOT_CONNECTED,
            )

        ldap_config = self.config.get_namespace("ldap", FlextLdapConfig)
        base_dn = ldap_config.base_dn or "dc=example,dc=com"
        return FlextResult[FlextLdapModels.SearchResult].ok(
            FlextLdapModels.SearchResult(
                entries=[],
                search_options=FlextLdapModels.SearchOptions(
                    base_dn=base_dn,
                    filter_str=FlextLdapConstants.Filters.ALL_ENTRIES_FILTER,
                ),
            ),
        )

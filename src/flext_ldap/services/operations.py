"""Search, CRUD, and upsert helpers built on ``Ldap3Adapter``.

This module keeps protocol concerns inside the adapter while exposing typed
inputs, normalized results, and reusable comparison utilities for callers.

Business Rules:
    - All LDAP operations are delegated to the adapter layer (Ldap3Adapter)
    - DN normalization is applied before all search operations using
      u.Ldif.norm_or_fallback() to ensure consistent DN format
    - Entry comparison ignores operational attributes defined in
      c.Ldif.OperationalAttributes.IGNORE_SET
    - Upsert operations implement add-or-modify pattern:
      1. First attempts ADD operation
      2. If entry exists (LDAP error 68), compares attributes and applies MODIFY
      3. If no changes detected, operation is marked as SKIPPED
    - Schema modifications are handled specially via changetype=modify entries

Audit Implications:
    - All operations log to s.logger for traceability
    - batch_upsert tracks synced/failed/skipped counts for compliance reporting
    - Progress callbacks enable real-time audit trail during batch operations
    - Error messages are logged with entry DN and index for forensic analysis

Architecture Notes:
    - Uses Railway-Oriented Programming pattern (r) for error handling
    - No exceptions are raised; all failures return r.fail()
    - All methods are type-safe with strict Pydantic v2 validation
    - Python 3.13: uses guard-based sequence handling
"""

from __future__ import annotations

import logging
from collections.abc import Mapping, Sequence
from typing import override

from pydantic import PrivateAttr

from flext_ldap import c, m, p, r, s, t, u
from flext_ldif import FlextLdifConversion


class FlextLdapOperations(s):
    """Coordinate LDAP operations on an active connection.

    Protocol calls are delegated to :class:`~flext.adapters.ldap3.Ldap3Adapter`
    so this layer can concentrate on typed arguments, predictable
    :class:`flext_core` responses, and shared comparison helpers.

    Business Rules:
        - Connection must be bound before operations (validated via is_connected)
        - Search operations normalize base_dn using u.Ldif.norm_or_fallback()
        - Add/Modify/Delete operations convert string DNs to DN models
        - Upsert implements LDAP idempotent write: add -> exists check -> modify
        - Batch operations track per-entry progress and support stop_on_error

    Audit Implications:
        - Each operation is logged with the operation name and result status
        - Batch operations log individual entry failures for forensic analysis
        - Progress callbacks allow external systems to track operation progress
        - All errors include context (DN, operation type, error message)

    Thread Safety:
        - Service instances are NOT thread-safe; use separate instances per thread
        - The underlying ldap3 Connection is managed by FlextLdapConnection

    Pydantic v2 Integration:
        - model_config allows frozen=False for mutable service state (_connection)
        - Uses extra="forbid" for strict validation
        - arbitrary_types_allowed=True enables non-Pydantic types in fields

    Examples:
        >>> ops = FlextLdapOperations(connection=conn)
        >>> result = ops.search(m.Ldap.SearchOptions(base_dn="dc=example,dc=com"))
        >>> if result.success:
        ...     entries = result.value.entries

    """

    _upsert_handler_instance: FlextLdapOperations._UpsertHandler | None = PrivateAttr(
        default=None,
    )

    @staticmethod
    def _get_structlog_logger() -> p.Logger | None:
        """Return structlog logger when runtime logger satisfies the protocol."""
        return u.fetch_logger(__name__)

    class _UpsertHandler:
        """Handle add-or-modify flows for upsert calls.

        Business Rules:
            - Schema modifications (changetype=modify) use MODIFY_ADD operations
            - Regular entries attempt ADD first, then compare and MODIFY if exists
            - "Entry already exists" errors trigger comparison and modification
            - Idempotent: SKIPPED if entry already matches desired state

        Audit Implications:
            - Returns operation type (ADDED, MODIFIED, SKIPPED) for tracking
            - All operations return r for consistent error handling
            - Error messages preserve original LDAP error context

        Architecture:
            - Private class (_) to encapsulate upsert state machine
            - Delegates to parent FlextLdapOperations for actual LDAP calls
        """

        def __init__(self, operations: FlextLdapOperations) -> None:
            """Initialize upsert handler with operations service.

            Business Rules:
                - Operations service is REQUIRED (no default, fail-fast pattern)
                - Handler stores reference for delegation to parent service
                - No connection validation at init (validated during execute)

            Architecture:
                - Private inner class encapsulates upsert state machine
                - Delegates all LDAP operations to parent FlextLdapOperations
                - Enables testability through dependency injection

            Args:
                operations: FlextLdapOperations instance for LDAP operations.
                    Must have active connection for execute() to succeed.

            """
            super().__init__()
            self._ops = operations

        def execute(self, entry: m.Ldif.Entry) -> p.Result[m.Ldap.LdapOperationResult]:
            """Execute an upsert operation for the provided entry.

            Business Rules:
                - Checks changetype attribute to route to schema modify vs regular add
                - Schema modifications use MODIFY_ADD for new schema elements
                - Regular entries use add-then-modify pattern for idempotency

            Audit Implication:
                Entry point for all upsert operations; returns operation type
                for audit trail (ADDED, MODIFIED, or SKIPPED).

            Returns:
                r with LdapOperationResult indicating operation type.

            """
            attrs = u.Ldap.extract_entry_attributes(entry)
            changetype_result = attrs.get(c.Ldap.LdapAttributeNames.CHANGETYPE, [])
            changetype_val: t.StrSequence = [str(item) for item in changetype_result]
            changetype = (
                u.Ldap.norm_str(changetype_val[0], case="lower")
                if changetype_val
                else ""
            )
            if not changetype and hasattr(entry, "changetype") and entry.changetype:
                changetype = str(entry.changetype).lower()
            if changetype == c.Ldif.ChangeTypeOperations.MODIFY:
                return self.handle_schema_modify(entry)
            return self.handle_regular_add(entry)

        def handle_existing_entry(
            self,
            entry: m.Ldif.Entry,
        ) -> p.Result[m.Ldap.LdapOperationResult]:
            """Handle an upsert when the entry already exists in LDAP.

            Business Rules:
                - Searches for existing entry using BASE scope on entry DN
                - If search fails, returns SKIPPED (entry may have been deleted)
                - If search returns empty (race condition), retries ADD
                - Compares existing vs new entry to compute MODIFY changes
                - If no differences, returns SKIPPED (idempotent)
                - Applies MODIFY_REPLACE/MODIFY_DELETE changes for sync

            Audit Implication:
                Critical for idempotent upserts; computes minimal change set.
                SKIPPED indicates no changes needed, enabling safe reruns.

            Returns:
                r with MODIFIED, SKIPPED, or ADDED (race condition).

            """
            entry_dn = (
                str(entry.dn.value)
                if entry.dn is not None
                else c.Ldif.EntryDefaults.UNKNOWN_VALUE
            )
            search_options = m.Ldap.SearchOptions.base_scope(entry_dn)
            search_result = self._ops.search(search_options)
            if search_result.failure:
                return r[m.Ldap.LdapOperationResult].ok(
                    m.Ldap.LdapOperationResult.with_operation(
                        c.Ldap.UpsertOperations.SKIPPED,
                    ),
                )
            search_data = search_result.map_or(None)
            existing_entries: Sequence[Mapping[str, t.StrSequence]] = []
            if search_data is not None and search_data.entries:
                existing_entries = list(search_data.entries)
            if not existing_entries:
                retry_result = self._ops.add(entry)
                if retry_result.success:
                    return r[m.Ldap.LdapOperationResult].ok(
                        m.Ldap.LdapOperationResult.with_operation(
                            c.Ldap.UpsertOperations.ADDED,
                        ),
                    )
                return r[m.Ldap.LdapOperationResult].fail(
                    u.Ldap.to_str(retry_result.error),
                )
            existing_entry_obj = existing_entries[0]
            existing_entry = u.Ldif.as_entry(existing_entry_obj)
            changes = u.Ldap.compare_entries(existing_entry, entry)
            if changes is None or not changes:
                return r[m.Ldap.LdapOperationResult].ok(
                    m.Ldap.LdapOperationResult.with_operation(
                        c.Ldap.UpsertOperations.SKIPPED,
                    ),
                )
            modify_result = self._ops.modify(entry_dn, changes)
            return modify_result.fold(
                on_failure=lambda e: r[m.Ldap.LdapOperationResult].fail(u.to_str(e)),
                on_success=lambda _: r[m.Ldap.LdapOperationResult].ok(
                    m.Ldap.LdapOperationResult.with_operation(
                        c.Ldap.UpsertOperations.MODIFIED,
                    ),
                ),
            )

        def handle_regular_add(
            self,
            entry: m.Ldif.Entry,
        ) -> p.Result[m.Ldap.LdapOperationResult]:
            """Add a standard entry or fall back to existing-entry handling.

            Business Rules:
                - First attempts LDAP ADD operation for optimistic path
                - If ADD succeeds, returns ADDED operation result
                - If "entry already exists" error (68), delegates to handle_existing_entry
                - Other errors are propagated as r.fail()

            Audit Implication:
                Primary upsert entry point for non-schema entries.
                Optimistic add minimizes round trips for new entries.

            Returns:
                r with ADDED or delegates to existing entry handler.

            """
            entry_for_add = u.Ldif.as_entry(entry)
            return (
                self._ops
                .add(entry_for_add)
                .map(
                    lambda _: m.Ldap.LdapOperationResult.with_operation(
                        c.Ldap.UpsertOperations.ADDED,
                    ),
                )
                .lash(
                    lambda e: (
                        self.handle_existing_entry(entry)
                        if self._ops.is_already_exists_error(u.to_str(e))
                        else r[m.Ldap.LdapOperationResult].fail(u.to_str(e))
                    ),
                )
            )

        def handle_schema_modify(
            self,
            entry: m.Ldif.Entry,
        ) -> p.Result[m.Ldap.LdapOperationResult]:
            """Apply a schema modification entry (supports multiple add operations).

            Business Rules:
                - Entry must have 'add' attribute specifying schema attribute(s) to add
                - Loops ALL add operations (supports both split and interleaved entries)
                - Uses MODIFY_ADD operation (not REPLACE) for additive schema changes
                - "Entry already exists" is interpreted as schema element exists -> SKIPPED
                - Empty values are filtered out before modification

            Audit Implication:
                Schema modifications are critical; returns MODIFIED, SKIPPED, or error.
                Preserves LDAP error context for schema validation failures.

            Returns:
                r with operation type (MODIFIED or SKIPPED).

            """
            entry_model = u.Ldif.as_entry(entry)
            dn_str: str
            if entry_model.dn is not None:
                dn_str = entry_model.dn.value or c.Ldif.EntryDefaults.UNKNOWN_VALUE
            else:
                dn_str = c.Ldif.EntryDefaults.UNKNOWN_VALUE
            schema_additions: list[tuple[str, t.StrSequence]] = []
            for change_operation in entry_model.change_operations:
                if change_operation.operation != c.Ldif.ChangeOperation.ADD:
                    continue
                filtered_values = [
                    change_value.value
                    for change_value in change_operation.values
                    if change_value.value
                ]
                if filtered_values:
                    schema_additions.append((
                        change_operation.attribute,
                        filtered_values,
                    ))
            if not schema_additions:
                attrs = u.Ldap.extract_entry_attributes(entry_model)
                add_op_result = attrs.get(c.Ldif.ChangeTypeOperations.ADD, [])
                add_op: t.StrSequence = [str(item) for item in add_op_result]
                for attr_type in add_op:
                    attr_values_raw = attrs.get(attr_type, [])
                    filtered_values = [str(item) for item in attr_values_raw if item]
                    if filtered_values:
                        schema_additions.append((attr_type, filtered_values))
            if not schema_additions:
                return r[m.Ldap.LdapOperationResult].fail(
                    "Schema modify entry missing add operations",
                )
            last_result: p.Result[m.Ldap.LdapOperationResult] | None = None
            for attr_type, filtered in schema_additions:
                changes: t.Ldap.OperationChanges = {
                    attr_type: [(c.Ldap.ModifyOperation.ADD, filtered)],
                }
                last_result = (
                    self._ops
                    .modify(dn_str, changes)
                    .map(
                        lambda _: m.Ldap.LdapOperationResult.with_operation(
                            c.Ldap.UpsertOperations.MODIFIED,
                        ),
                    )
                    .lash(
                        lambda e: (
                            r[m.Ldap.LdapOperationResult].ok(
                                m.Ldap.LdapOperationResult.with_operation(
                                    c.Ldap.UpsertOperations.SKIPPED,
                                ),
                            )
                            if self._ops.is_already_exists_error(u.to_str(e))
                            else r[m.Ldap.LdapOperationResult].fail(
                                u.to_str(e) or c.Ldap.ErrorStrings.UNKNOWN_ERROR,
                            )
                        ),
                    )
                )
                if last_result.failure:
                    return last_result
            if last_result is None:
                return r[m.Ldap.LdapOperationResult].fail(
                    "Schema modify entry has only empty values",
                )
            return last_result

        def _extract_schema_add_operation(
            self,
            attrs: Mapping[str, t.StrSequence],
        ) -> p.Result[str]:
            """Extract schema add operation attribute type.

            Args:
                attrs: Attributes dictionary.

            Returns:
                r with attribute type or error.

            """
            add_op_result = attrs.get(c.Ldif.ChangeTypeOperations.ADD, [])
            add_op_raw = add_op_result
            add_op: t.StrSequence = [str(item) for item in add_op_raw]
            if not add_op:
                return r[str].fail("Schema modify entry missing 'add' attribute")
            return r[str].ok(add_op[0])

        def _extract_schema_attribute_values(
            self,
            attrs: Mapping[str, t.StrSequence],
            attr_type: str,
        ) -> p.Result[t.StrSequence]:
            """Extract and filter schema attribute values.

            Args:
                attrs: Attributes dictionary.
                attr_type: Attribute type to extract.

            Returns:
                r with filtered values or error.

            """
            attr_values_result = attrs.get(attr_type, [])
            attr_values_raw = attr_values_result
            attr_values = [str(item) for item in attr_values_raw]
            filtered = [x for x in attr_values if x]
            if not filtered:
                return r[t.StrSequence].fail(
                    f"Schema modify entry has only empty values for '{attr_type}'",
                )
            return r[t.StrSequence].ok(filtered)

    @property
    def _upsert_handler(self) -> FlextLdapOperations._UpsertHandler:
        """Lazy-init upsert handler."""
        if self._upsert_handler_instance is None:
            self._upsert_handler_instance = self._UpsertHandler(self)
        return self._upsert_handler_instance

    @staticmethod
    def is_already_exists_error(error_message: str) -> bool:
        """Return ``True`` when the error indicates an existing entry.

        Business Rules:
            - Checks for LDAP error 68 (entryAlreadyExists) in error message
            - Case-insensitive matching for cross-server compatibility
            - Supports multiple error string patterns:
              - "entry already exists" (standard)
              - "already exists" (abbreviated)
              - "entryalreadyexists" (LDAP error constant)
              - "ldap_already_exists" (snake_case variant)

        Audit Implication:
            Used by upsert logic to distinguish "add failed because exists"
            from other failures (schema violation, permission denied, etc.)

        Returns:
            True if error indicates entry exists, False otherwise.

        """
        error_lower = u.Ldap.norm_str(error_message, case="lower")
        return (
            str(c.Ldap.ErrorStrings.ENTRY_ALREADY_EXISTS) in error_lower
            or str(c.Ldap.ErrorStrings.ENTRY_ALREADY_EXISTS_ALT) in error_lower
            or str(c.Ldap.ErrorStrings.ENTRY_ALREADY_EXISTS_LDAP) in error_lower
            or (str(c.Ldap.ErrorStrings.ENTRY_ALREADY_EXISTS_SNAKE) in error_lower)
        )

    def add(
        self,
        entry: m.Ldif.Entry,
        **_kwargs: str | float | bool | None,
    ) -> p.Result[m.Ldap.OperationResult]:
        """Add an LDAP entry using the active adapter connection.

        Business Rules:
            - Entry DN must be unique (LDAP error 68 if entry already exists)
            - Entry attributes are converted to ldap3 format via FlextLdapEntryAdapter
            - DN normalization is handled by adapter layer
            - Entry must conform to LDAP schema constraints

        Audit Implications:
            - Add operations are logged with entry DN
            - Successful adds log affected count (always 1)
            - Failed adds log error message and DN

        Architecture:
            - Delegates to Ldap3Adapter.add() for protocol-level execution
            - Entry conversion handled by FlextLdapEntryAdapter
            - Returns r pattern - no exceptions raised

        Args:
            entry: Entry model to add (must include DN and required attributes)

        Returns:
            r containing OperationResult with success status and entries_affected=1

        """
        entry_for_adapter: m.Ldif.Entry
        entry_for_adapter = m.Ldif.Entry.model_validate(entry)
        metadata = entry_for_adapter.metadata
        current_server_raw = (
            metadata.target_server_type
            or metadata.original_server_type
            or metadata.quirk_type
            if metadata is not None
            else None
        )
        current_server = (
            u.try_(
                lambda: u.Ldif.normalize_server_type(str(current_server_raw)),
                default=None,
            ).map_or(None)
            if current_server_raw is not None
            else None
        )
        target_server = u.Ldif.normalize_server_type(self._server_type)
        if current_server is not None and current_server != target_server:
            conversion_result = FlextLdifConversion().convert_entry(
                current_server,
                target_server,
                entry_for_adapter,
            )
            if conversion_result.failure:
                return r[m.Ldap.OperationResult].fail(
                    conversion_result.error or "Failed to convert entry for LDAP add",
                )
            converted_entry = conversion_result.value
            if not isinstance(converted_entry, m.Ldif.Entry):
                return r[m.Ldap.OperationResult].fail(
                    f"Expected converted Entry, got {type(converted_entry).__name__}",
                )
            entry_for_adapter = converted_entry
        return self._ensure_adapter().add(entry_for_adapter)

    def batch_upsert(
        self,
        entries: Sequence[m.Ldif.Entry],
        *,
        progress_callback: t.Ldap.LdapProgressCallback | None = None,
        retry_on_errors: t.StrSequence | None = None,
        max_retries: int = 1,
        stop_on_error: bool = False,
    ) -> p.Result[m.Ldap.LdapBatchStats]:
        """Upsert multiple entries and track per-item progress.

        Business Rules:
            - Processes entries sequentially (not parallel) for consistency
            - Each entry uses upsert logic (add/modify/skip based on comparison)
            - Progress callback is invoked after each entry (current, total, dn, stats)
            - stop_on_error=True aborts batch on first failure
            - stop_on_error=False continues processing remaining entries
            - Batch fails only if ALL entries fail (synced=0 and failed>0)
            - Statistics track synced (added+modified), failed, and skipped counts

        Audit Implications:
            - Batch operations log start/end with total entry count
            - Progress callbacks enable real-time audit trail during processing
            - Individual entry failures are logged with index and DN
            - Final statistics (synced/failed/skipped) logged for compliance reporting

        Architecture:
            - Uses upsert() method for each entry
            - Progress callback signature: (current: int, total: int, dn: str, stats: LdapBatchStats)
            - Returns r pattern - no exceptions raised

        Args:
            entries: List of entries to upsert (must include DN and attributes)
            progress_callback: Optional callback for progress tracking (4 parameters)
            retry_on_errors: Error patterns to retry on (e.g., ["session terminated"])
            max_retries: Maximum retries per entry (default: 1, no retry)
            stop_on_error: Stop processing on first error (default: False, continue)

        Returns:
            r containing LdapBatchStats with synced/failed/skipped counts

        """
        stats_builder: t.MutableIntMapping = {
            "synced": 0,
            "failed": 0,
            "skipped": 0,
        }
        total_entries = len(entries)
        for idx_entry in enumerate(entries, 1):
            try:
                i, entry = idx_entry
                entry_dn = u.Ldap.dn_str(str(entry.dn) if entry.dn else None)
                upsert_result = self.upsert(
                    entry,
                    retry_on_errors=retry_on_errors,
                    max_retries=max_retries,
                )
                self._update_batch_stats(
                    upsert_result,
                    stats_builder,
                    i,
                    entry_dn,
                    total_entries,
                )
                if stop_on_error and upsert_result.failure:
                    stats_builder["_stop_error"] = i
                    break
                if progress_callback:
                    self._invoke_batch_progress_callback(
                        progress_callback,
                        i,
                        total_entries,
                        entry_dn,
                        stats_builder,
                    )
            except (
                ValueError,
                TypeError,
                KeyError,
                AttributeError,
                OSError,
                RuntimeError,
                ImportError,
            ):
                entry_idx = idx_entry[0]
                logger = FlextLdapOperations._get_structlog_logger()
                if logger is not None:
                    logger.debug(
                        "Failed to process entry in batch, skipping",
                        entry_index=entry_idx,
                        exc_info=True,
                    )
                else:
                    logging.getLogger(__name__).debug(
                        "Failed to process entry in batch, skipping (entry_index=%s)",
                        entry_idx,
                        exc_info=True,
                    )
                continue
        if stop_on_error and "_stop_error" in stats_builder:
            error_idx = stats_builder["_stop_error"]
            match error_idx:
                case int():
                    return r[m.Ldap.LdapBatchStats].fail(
                        f"Batch upsert stopped on error at entry {error_idx}/{total_entries}",
                    )
        stats = m.Ldap.LdapBatchStats(
            synced=stats_builder["synced"],
            failed=stats_builder["failed"],
            skipped=stats_builder["skipped"],
        )
        logger = FlextLdapOperations._get_structlog_logger()
        if logger is not None:
            logger.info(
                "Batch upsert completed",
                operation=c.Ldap.LdapOperationNames.BATCH_UPSERT,
                total_entries=total_entries,
                synced=stats_builder["synced"],
                failed=stats_builder["failed"],
                skipped=stats_builder["skipped"],
            )
        else:
            logging.getLogger(__name__).info(
                "Batch upsert completed: total=%s synced=%s failed=%s skipped=%s",
                total_entries,
                stats_builder["synced"],
                stats_builder["failed"],
                stats_builder["skipped"],
            )
        if stats_builder["synced"] == 0 and stats_builder["failed"] > 0:
            return r[m.Ldap.LdapBatchStats].fail(
                f"Batch upsert failed: all {stats_builder['failed']} entries failed, 0 synced",
            )
        return r[m.Ldap.LdapBatchStats].ok(stats)

    def delete(
        self,
        dn: str | m.Ldif.DN,
        **_kwargs: str | float | bool | None,
    ) -> p.Result[m.Ldap.OperationResult]:
        """Delete an LDAP entry identified by DN.

        Business Rules:
            - Entry must exist before deletion (LDAP error 32 if not found)
            - Entry must not have children (LDAP error 66 if has children)
            - DN normalization is applied using u.Ldif.get_dn_value()
            - String DNs are converted to DN models for type safety
            - Deletion is permanent - no undo capability

        Audit Implications:
            - Delete operations are logged with DN for critical audit trail
            - Successful deletes log affected count (always 1)
            - Failed deletes log error message and DN

        Architecture:
            - Delegates to Ldap3Adapter.delete() for protocol-level execution
            - DN conversion handled by u.Ldif
            - Returns r pattern - no exceptions raised

        Args:
            dn: Distinguished name of entry to delete (string or DN model)

        Returns:
            r containing OperationResult with success status and entries_affected=1

        """
        match dn:
            case str():
                dn_model: m.Ldif.DN = m.Ldif.DN(
                    value=u.Ldif.get_dn_value(dn),
                    metadata=m.Ldif.EntryMetadata(),
                )
            case _:
                dn_model = dn
        result = self._ensure_adapter().delete(dn_model)
        return result.fold(
            on_failure=lambda e: r[m.Ldap.OperationResult].fail(
                u.to_str(e, default="Unknown error"),
            ),
            on_success=lambda v: r[m.Ldap.OperationResult].ok(v),
        )

    @override
    def execute(
        self, **_kwargs: str | float | bool | None
    ) -> p.Result[m.Ldap.Response]:
        """Report readiness; fails when the connection is not bound.

        Business Rules:
            - Returns failure if connection is not bound (NOT_CONNECTED error)
            - Returns empty SearchResult with configured base_dn on success
            - Uses default base_dn from FlextLdapSettings if not specified
            - Serves as health check for s.execute() pattern

        Audit Implication:
            Validates connection state before operations; useful for
            health checks and connection pool validation.

        Returns:
            r with empty SearchResult (success) or NOT_CONNECTED error.

        """
        if not self.is_connected:
            return r[m.Ldap.Response].fail(c.Ldap.ErrorStrings.NOT_CONNECTED)
        base_dn: str = c.Ldap.Defaults.EXAMPLE_BASE_DN
        return r[m.Ldap.Response].ok(
            m.Ldap.SearchResult(
                entries=[],
                search_options=m.Ldap.SearchOptions(
                    base_dn=base_dn,
                    filter_str=c.Ldap.Filters.ALL_ENTRIES_FILTER,
                ),
            ),
        )

    def modify(
        self,
        dn: str | m.Ldif.DN,
        changes: t.Ldap.OperationChanges,
        **_kwargs: str | float | bool | None,
    ) -> p.Result[m.Ldap.OperationResult]:
        """Modify an LDAP entry with the provided change set.

        Business Rules:
            - Entry must exist before modification (LDAP error 32 if not found)
            - Changes use ldap3 format: {attr_name: [(MODIFY_ADD|MODIFY_DELETE|MODIFY_REPLACE, [values])]}
            - DN normalization is applied using u.Ldif.get_dn_value()
            - String DNs are converted to DN models for type safety
            - Schema constraints are validated by LDAP server

        Audit Implications:
            - Modify operations are logged with DN and change summary
            - Successful modifies log affected count (always 1)
            - Failed modifies log error message and DN

        Architecture:
            - Delegates to Ldap3Adapter.modify() for protocol-level execution
            - DN conversion handled by u.Ldif
            - Returns r pattern - no exceptions raised

        Args:
            dn: Distinguished name of entry to modify (string or DN model)
            changes: Modification changes dict in ldap3 format

        Returns:
            r containing OperationResult with success status and entries_affected=1

        """
        match dn:
            case str():
                dn_model: m.Ldif.DN = m.Ldif.DN(
                    value=u.Ldif.get_dn_value(dn),
                    metadata=m.Ldif.EntryMetadata(),
                )
            case _:
                dn_model = dn
        result = self._ensure_adapter().modify(dn_model, changes)
        return result.fold(
            on_failure=lambda e: r[m.Ldap.OperationResult].fail(
                u.to_str(e, default="Unknown error"),
            ),
            on_success=lambda v: r[m.Ldap.OperationResult].ok(v),
        )

    def search(
        self,
        search_options: m.Ldap.SearchOptions,
        server_type: str | None = None,
        **_kwargs: str | float | bool | None,
    ) -> p.Result[m.Ldap.SearchResult]:
        """Perform an LDAP search using normalized search options.

        Business Rules:
            - Base DN is normalized using u.Ldif.norm_or_fallback() before search
            - Normalization ensures consistent DN format across server types
            - Search filter syntax is validated by LDAP server
            - Server type determines parsing quirks for entry attributes
            - Empty result sets return successful SearchResult with empty entries list

        Audit Implications:
            - Search operations are logged with normalized base_dn and filter
            - Result counts are logged for compliance reporting
            - Failed searches log error messages with search parameters

        Architecture:
            - Delegates to Ldap3Adapter.search() for protocol-level execution
            - Uses FlextLdifParser for server-specific entry parsing
            - Returns r pattern - no exceptions raised

        Args:
            search_options: Search configuration (base_dn, filter_str, scope, attributes)
            server_type: LDAP server type for parsing quirks (default: RFC)

        Returns:
            r containing SearchResult with Entry models

        """
        normalized_options = search_options.model_copy(
            update={
                "base_dn": u.Ldif.norm_or_fallback(
                    search_options.base_dn,
                ),
            },
        )
        effective_server_type = server_type or self._server_type
        result = self._ensure_adapter().search(
            normalized_options,
            server_type=effective_server_type,
        )
        return result.fold(
            on_failure=lambda e: r[m.Ldap.SearchResult].fail(
                u.to_str(e, default="Unknown error"),
            ),
            on_success=lambda v: r[m.Ldap.SearchResult].ok(v),
        )

    def upsert(
        self,
        entry: m.Ldif.Entry,
        *,
        retry_on_errors: t.StrSequence | None = None,
        max_retries: int = 1,
    ) -> p.Result[m.Ldap.LdapOperationResult]:
        """Upsert an entry, optionally retrying for configured error patterns.

        Business Rules:
            - First attempts ADD operation via _UpsertHandler
            - If entry exists (LDAP error 68), performs search and comparison
            - Entry comparison ignores operational attributes (modifyTimestamp, etc.)
            - If entries are identical, operation is SKIPPED (no changes needed)
            - If entries differ, MODIFY operation is applied with computed changes
            - Schema modification entries (changetype=modify) are handled specially
            - Retry mechanism uses u.retry() for transient errors
            - Retry only occurs if error matches retry_on_errors patterns

        Audit Implications:
            - Upsert operations log operation type (ADDED, MODIFIED, SKIPPED)
            - Retry attempts are logged individually for compliance
            - Skipped operations indicate no changes needed (audit efficiency)

        Architecture:
            - Uses _UpsertHandler.execute() for core upsert logic
            - Retry logic uses u.retry()
            - Returns r pattern - no exceptions raised

        Args:
            entry: Entry model to upsert (must include DN and attributes)
            retry_on_errors: List of error patterns to retry on (e.g., ["session terminated"])
            max_retries: Maximum number of retry attempts (default: 1, no retry)

        Returns:
            r containing LdapOperationResult with operation type (ADDED|MODIFIED|SKIPPED)

        """
        if not (retry_on_errors and max_retries > 1):
            return self._upsert_handler.execute(entry)
        result = self._upsert_handler.execute(entry)
        if result.success or not retry_on_errors:
            return result
        error_str = u.Ldap.norm_str(str(result.error), case="lower")
        if not any(
            u.Ldap.norm_in(error_str, [pattern], case="lower")
            for pattern in retry_on_errors
        ):
            return result

        def wrapped_execute() -> p.Result[m.Ldap.LdapOperationResult]:
            return self._upsert_handler.execute(entry)

        return u.retry(
            operation=wrapped_execute,
            max_attempts=max_retries,
            delay_seconds=1.0,
        )

    def _invoke_batch_progress_callback(
        self,
        callback: t.Ldap.LdapProgressCallback,
        entry_index: int,
        total: int,
        entry_dn: str | None,
        stats: t.IntMapping,
    ) -> None:
        """Invoke progress callback with error handling."""
        try:
            callback_stats = m.Ldap.LdapBatchStats(
                synced=stats["synced"],
                failed=stats["failed"],
                skipped=stats["skipped"],
            )
            callback(entry_index, total, entry_dn or "", callback_stats)
        except (RuntimeError, TypeError, ValueError) as e:
            logger = FlextLdapOperations._get_structlog_logger()
            if logger is not None:
                logger.warning(
                    "Progress callback failed",
                    operation=c.Ldap.LdapOperationNames.SYNC,
                    entry_index=entry_index,
                    error=str(e),
                )
            else:
                logging.getLogger(__name__).warning(
                    "Progress callback failed: operation=%s entry=%s error=%s",
                    c.Ldap.LdapOperationNames.SYNC,
                    entry_index,
                    e,
                )

    def _update_batch_stats(
        self,
        upsert_result: p.Result[m.Ldap.LdapOperationResult],
        stats: t.MutableIntMapping,
        entry_index: int,
        entry_dn: str | None,
        total_entries: int,
    ) -> None:
        """Update batch stats from upsert result."""
        if upsert_result.success:
            operation = upsert_result.value.operation
            if operation == c.Ldap.UpsertOperations.SKIPPED:
                stats["skipped"] += 1
            elif operation in {
                c.Ldap.UpsertOperations.ADDED,
                c.Ldap.UpsertOperations.MODIFIED,
            }:
                stats["synced"] += 1
        else:
            stats["failed"] += 1
            entry_dn_sliced: str = (
                entry_dn[: c.Ldap.Logging.DN_TRUNCATION_LENGTH] if entry_dn else ""
            )
            error_msg = (str(upsert_result.error) if upsert_result.error else "")[:200]
            logger = FlextLdapOperations._get_structlog_logger()
            if logger is not None:
                logger.error(
                    "Batch upsert entry failed",
                    entry_index=entry_index,
                    total_entries=total_entries,
                    entry_dn=entry_dn_sliced,
                    error=error_msg,
                )
            else:
                logging.getLogger(__name__).error(
                    "Batch upsert entry failed: entry=%s total=%s dn=%s error=%s",
                    entry_index,
                    total_entries,
                    entry_dn_sliced,
                    error_msg,
                )

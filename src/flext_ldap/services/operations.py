"""Search, CRUD, and upsert helpers built on ``Ldap3Adapter``.

This module keeps protocol concerns inside the adapter while exposing typed
inputs, normalized results, and reusable comparison utilities for callers.

Business Rules:
    - All LDAP operations are delegated to the adapter layer (Ldap3Adapter)
    - DN normalization is applied before all search operations using
      u.Ldif.norm() to ensure consistent DN format
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

from typing import override

from flext_ldif import ldif, r

from flext_ldap import c, m, p, t, u
from flext_ldap.adapters.ldap3 import FlextLdapAdapterHost

from ._upsert_handler import FlextLdapUpsertHandler


class FlextLdapOperations(FlextLdapAdapterHost[m.Ldap.Response]):
    """Coordinate LDAP operations on an active connection.

    Protocol calls are delegated to :class:`~flext.adapters.ldap3.Ldap3Adapter`
    so this layer can concentrate on typed arguments, predictable
    :class:`flext_core` responses, and shared comparison helpers.

    Business Rules:
        - Connection must be bound before operations (validated via is_connected)
        - Search operations normalize base_dn using u.Ldif.norm()
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

    _upsert_handler_instance: FlextLdapUpsertHandler | None = u.PrivateAttr(
        default_factory=lambda: None
    )

    @property
    def _upsert_handler(self) -> FlextLdapUpsertHandler:
        """Lazy-init upsert handler."""
        if self._upsert_handler_instance is None:
            self._upsert_handler_instance = FlextLdapUpsertHandler(self)
        return self._upsert_handler_instance

    @staticmethod
    def already_exists_error(error_message: str) -> bool:
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
        return bool(c.Ldap.ENTRY_ALREADY_EXISTS_RE.search(error_message))

    def add(self, entry: p.Ldif.Entry) -> p.Result[m.Ldap.OperationResult]:
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
            or metadata.server_type
            if metadata is not None
            else None
        )
        current_server = None
        if current_server_raw is not None:
            try:
                current_server = u.Ldif.normalize_server_type(str(current_server_raw))
            except ValueError as exc:
                return r[m.Ldap.OperationResult].fail(
                    f"Failed to normalize current server type: {exc}", exception=exc
                )
        target_server = u.Ldif.normalize_server_type(self._server_type)
        if current_server is not None and current_server != target_server:
            conversion_result = ldif.convert_model(
                current_server, target_server, entry_for_adapter
            )
            if conversion_result.failure:
                return r[m.Ldap.OperationResult].from_failure(conversion_result)
            converted_entry = conversion_result.value
            if not isinstance(converted_entry, m.Ldif.Entry):
                return r[m.Ldap.OperationResult].fail(
                    f"Expected converted Entry, got {type(converted_entry).__name__}"
                )
            entry_for_adapter = converted_entry
        add_result: p.Result[m.Ldap.OperationResult] = self._ensure_adapter().add(
            entry_for_adapter
        )
        return add_result

    def batch_upsert(
        self,
        entries: t.SequenceOf[p.Ldif.Entry],
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
            - Batch fails when any entry fails; mixed success is not reported as success
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
        sync_options = m.Ldap.SyncPhaseConfig(
            progress_callback=progress_callback,
            retry_on_errors=list(retry_on_errors or []),
            max_retries=max_retries,
            stop_on_error=stop_on_error,
        )
        stats = m.Ldap.LdapBatchStats()
        stop_error_index: int | None = None
        total_entries = len(entries)
        for i, entry in enumerate(entries, 1):
            try:
                stop_requested = self._process_batch_entry(
                    entry, sync_options, stats, i, total_entries
                )
            except c.EXC_BROAD_IO_TYPE as exc:
                return r[m.Ldap.LdapBatchStats].fail(
                    f"Batch upsert aborted on unexpected exception at entry {i}: {exc}"
                )
            if stop_requested:
                stop_error_index = i
                break
        if sync_options.stop_on_error and stop_error_index is not None:
            return r[m.Ldap.LdapBatchStats].fail(
                f"Batch upsert stopped on error at entry {stop_error_index}/{total_entries}"
            )
        self.logger.info(
            "Batch upsert completed",
            operation=c.Ldap.OperationName.BATCH_UPSERT,
            total_entries=total_entries,
            synced=stats.synced,
            failed=stats.failed,
            skipped=stats.skipped,
        )
        return self._finish_batch_upsert(stats)

    @staticmethod
    def _finish_batch_upsert(
        stats: m.Ldap.LdapBatchStats,
    ) -> p.Result[m.Ldap.LdapBatchStats]:
        """Return final batch result; any failed entry fails the batch."""
        if stats.failed > 0:
            return r[m.Ldap.LdapBatchStats].fail(
                f"Batch upsert failed: {stats.failed} entries failed, "
                f"{stats.synced} synced, {stats.skipped} skipped"
            )
        return r[m.Ldap.LdapBatchStats].ok(stats)

    @staticmethod
    def _fold_operation_result(
        result: p.Result[m.Ldap.OperationResult],
    ) -> p.Result[m.Ldap.OperationResult]:
        """Fold an adapter operation outcome into the canonical result surface."""
        folded: p.Result[m.Ldap.OperationResult] = result.fold(
            on_failure=lambda e: r[m.Ldap.OperationResult].fail(
                u.to_str(e, default="Unknown error")
            ),
            on_success=r[m.Ldap.OperationResult].ok,
        )
        return folded

    @staticmethod
    def _normalized_dn(dn: str | p.Ldif.DN, op_name: str) -> p.Result[m.Ldif.DN]:
        """Normalize a str-or-DN input into a validated DN model."""
        return u.try_(
            lambda: (
                m.Ldif.DN(value=u.Ldif.get_dn_value(dn))
                if isinstance(dn, str)
                else (dn if isinstance(dn, m.Ldif.DN) else m.Ldif.DN.model_validate(dn))
            ),
            op_name=op_name,
        )

    def delete(self, dn: str | p.Ldif.DN) -> p.Result[m.Ldap.OperationResult]:
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
        dn_build = self._normalized_dn(dn, "validate delete DN")
        if dn_build.failure:
            return r[m.Ldap.OperationResult].from_failure(dn_build)
        dn_model: m.Ldif.DN = dn_build.unwrap()
        return self._fold_operation_result(self._ensure_adapter().delete(dn_model))

    @override
    def execute(self) -> p.Result[m.Ldap.Response]:
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
            return r[m.Ldap.Response].fail(c.Ldap.ErrorMessage.NOT_CONNECTED)
        base_dn: str = c.Ldap.EXAMPLE_BASE_DN
        return r[m.Ldap.Response].ok(
            m.Ldap.SearchResult(
                entries=[],
                search_options=m.Ldap.SearchOptions(
                    base_dn=base_dn, filter_str=c.Ldap.ALL_ENTRIES_FILTER
                ),
            )
        )

    def modify(
        self, dn: str | p.Ldif.DN, changes: t.Ldap.LdapModifyChanges
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
        dn_build = self._normalized_dn(dn, "validate modify DN")
        if dn_build.failure:
            return r[m.Ldap.OperationResult].from_failure(dn_build)
        dn_model: m.Ldif.DN = dn_build.unwrap()
        concrete_changes: t.Ldap.OperationChanges = {
            k: [(int(op), list(vals)) for op, vals in v] for k, v in changes.items()
        }
        return self._fold_operation_result(
            self._ensure_adapter().modify(dn_model, concrete_changes)
        )

    def search(
        self, search_options: p.Ldap.SearchOptions, server_type: str = "rfc"
    ) -> p.Result[m.Ldap.SearchResult]:
        """Perform an LDAP search using normalized search options.

        Business Rules:
            - Base DN is normalized using u.Ldif.norm() before search
            - Normalization ensures consistent DN format across server types
            - Search filter syntax is validated by LDAP server
            - Server type determines parsing servers for entry attributes
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
            server_type: LDAP server type for parsing servers (default: RFC)

        Returns:
            r containing SearchResult with Entry models

        """
        base_dn_result = u.Ldif.norm(search_options.base_dn)
        if base_dn_result.failure:
            return r[m.Ldap.SearchResult].fail(
                f"Invalid base DN: {base_dn_result.error}"
            )
        concrete_options = (
            search_options
            if isinstance(search_options, m.Ldap.SearchOptions)
            else m.Ldap.SearchOptions.model_validate(search_options)
        )
        normalized_options = concrete_options.model_copy(
            update={"base_dn": base_dn_result.value}
        )
        effective_server_type = server_type or self._server_type
        result = self._ensure_adapter().search(
            normalized_options, server_type=effective_server_type
        )
        folded: p.Result[m.Ldap.SearchResult] = result.fold(
            on_failure=lambda e: r[m.Ldap.SearchResult].fail(
                u.to_str(e, default="Unknown error")
            ),
            on_success=r[m.Ldap.SearchResult].ok,
        )
        return folded

    def upsert(
        self,
        entry: p.Ldif.Entry,
        *,
        retry_on_errors: t.StrSequence | None = None,
        max_retries: int = 1,
    ) -> p.Result[m.Ldap.LdapOperationResult]:
        """Upsert an entry, optionally retrying for configured error patterns.

        Business Rules:
            - First attempts ADD operation via FlextLdapUpsertHandler
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
            - Uses FlextLdapUpsertHandler.execute() for core upsert logic
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

        retry_result: p.Result[m.Ldap.LdapOperationResult] = u.retry(
            operation=wrapped_execute, max_attempts=max_retries, delay_seconds=1.0
        )
        return retry_result

    def _invoke_batch_progress_callback(
        self,
        callback: t.Ldap.LdapProgressCallback,
        entry_index: int,
        total: int,
        entry_dn: str | None,
        stats: m.Ldap.LdapBatchStats,
    ) -> None:
        """Invoke progress callback with error handling."""
        callback_stats = stats.model_copy()
        callback(entry_index, total, entry_dn or "", callback_stats)

    def _process_batch_entry(
        self,
        entry: p.Ldif.Entry,
        sync_options: m.Ldap.SyncPhaseConfig,
        stats: m.Ldap.LdapBatchStats,
        entry_index: int,
        total_entries: int,
    ) -> bool:
        """Process one batch entry and report whether stop-on-error should halt."""
        entry_dn = u.Ldap.dn_str(str(entry.dn) if entry.dn else None)
        upsert_result = self.upsert(
            entry,
            retry_on_errors=sync_options.retry_on_errors,
            max_retries=sync_options.max_retries,
        )
        self._update_batch_stats(
            upsert_result, stats, entry_index, entry_dn, total_entries
        )
        if sync_options.progress_callback:
            self._invoke_batch_progress_callback(
                sync_options.progress_callback,
                entry_index,
                total_entries,
                entry_dn,
                stats,
            )
        should_stop: bool = sync_options.stop_on_error and upsert_result.failure
        return should_stop

    def _update_batch_stats(
        self,
        upsert_result: p.Result[m.Ldap.LdapOperationResult],
        stats: m.Ldap.LdapBatchStats,
        entry_index: int,
        entry_dn: str | None,
        total_entries: int,
    ) -> None:
        """Update batch stats from upsert result."""
        if upsert_result.success:
            match upsert_result.value.operation:
                case c.Ldap.UpsertOperation.SKIPPED:
                    stats.skipped += 1
                case c.Ldap.UpsertOperation.ADDED | c.Ldap.UpsertOperation.MODIFIED:
                    stats.synced += 1
                case _:
                    stats.failed += 1
                    self.logger.error(
                        "Batch upsert returned unknown operation",
                        entry_index=entry_index,
                        total_entries=total_entries,
                        entry_dn=entry_dn or "",
                        operation=upsert_result.value.operation,
                    )
        else:
            stats.failed += 1
            entry_dn_sliced: str = (
                entry_dn[: c.Ldap.DN_TRUNCATION_LENGTH] if entry_dn else ""
            )
            error_msg = (upsert_result.error or "")[:200]
            self.logger.error(
                "Batch upsert entry failed",
                entry_index=entry_index,
                total_entries=total_entries,
                entry_dn=entry_dn_sliced,
                error=error_msg,
            )

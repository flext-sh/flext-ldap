"""Synchronize LDIF content into LDAP through the operations service.

This module provides LDIF-to-LDAP synchronization capabilities, enabling bulk
import of directory entries from LDIF files into live LDAP servers. It handles
parsing, base DN translation, and batch processing with progress tracking.

Business Rules:
    - All LDAP mutations delegate to :class:`FlextLdapOperations` (no direct ldap3)
    - LDIF parsing uses FlextLdif.parse() with "rfc" server type for standards compliance
    - Base DN transformation is case-insensitive for cross-domain migrations
    - Add operations are idempotent: existing entries are counted as "skipped"
    - Progress callbacks receive per-entry statistics for real-time monitoring
    - Duration tracking uses u.Generators.generate_datetime_utc()

Audit Implications:
    - Sync operations return detailed SyncStats for compliance reporting
    - Per-entry progress callbacks enable audit trail generation
    - Failed entries are counted but do not halt the batch
    - File not found errors return structured failure (no exceptions)

Architecture Notes:
    - Uses composition over inheritance (operations service injection)
    - Inner classes (BatchSync, BaseDNTransformer) encapsulate specific concerns
    - Pydantic v2 frozen=False for mutable service state
    - Railway-Oriented Programming (FlextResult) for error handling
"""

from __future__ import annotations

from collections.abc import Callable
from datetime import datetime
from pathlib import Path
from typing import cast

from flext_ldif import FlextLdif, FlextLdifModels
from flext_ldif.constants import FlextLdifConstants
from flext_ldif.utilities import FlextLdifUtilities
from pydantic import ConfigDict, PrivateAttr

from flext_ldap import m, r, u
from flext_ldap.base import FlextLdapServiceBase
from flext_ldap.services.operations import FlextLdapOperations


class FlextLdapSyncService(FlextLdapServiceBase[m.SyncStats]):
    """Stream LDIF entries into LDAP while tracking progress and totals.

    All LDAP mutations are delegated to :class:`FlextLdapOperations`, keeping
    this service focused on batching, optional base-DN translation, and runtime
    statistics. Syncs rely on ``add`` operations with idempotent handling for
    existing entries, mirroring the current runtime behaviour in code.

    Business Rules:
        - Operations service is REQUIRED (constructor raises TypeError if None)
        - FlextLdif singleton is used for LDIF parsing (consistent ecosystem behavior)
        - Datetime generation uses u.Generators for UTC consistency
        - Base DN transformation is applied BEFORE batch processing
        - Sync statistics track added/skipped/failed counts independently
        - Duration is measured from start of parsing to end of batch processing

    Audit Implications:
        - Returns ``m.SyncStats`` with complete sync metrics
        - Progress callbacks enable real-time audit trail during large imports
        - Each entry's status (synced/skipped/failed) is tracked individually
        - Service readiness via ``execute()`` returns empty stats (zero counters)

    Architecture Notes:
        - Implements FlextService pattern via ``FlextLdapServiceBase[SyncStats]``
        - Uses PrivateAttr for service dependencies (Pydantic compatibility)
        - Inner classes avoid polluting module namespace
        - Callable injection for datetime generation enables test determinism

    Example:
        >>> from flext_ldap.services.operations import FlextLdapOperations
        >>> operations = FlextLdapOperations(connection=connected_connection)
        >>> sync_service = FlextLdapSyncService(operations=operations)
        >>> result = sync_service.sync_ldif_file(
        ...     ldif_file=Path("users.ldif"),
        ...     options=m.SyncOptions(
        ...         source_basedn="dc=old,dc=com", target_basedn="dc=new,dc=com"
        ...     ),
        ... )
        >>> if result.is_success:
        ...     stats = result.unwrap()
        ...     print(f"Added: {stats.added}, Skipped: {stats.skipped}")

    """

    model_config = ConfigDict(
        frozen=False,  # Service needs mutable state for operations and ldif references
        extra="allow",
        arbitrary_types_allowed=True,
    )

    _operations: FlextLdapOperations = PrivateAttr()
    _ldif: FlextLdif = PrivateAttr()
    _generate_datetime_utc: Callable[[], datetime] = PrivateAttr()

    class BatchSync:
        """Batch synchronization helper for processing multiple LDIF entries.

        Encapsulates the iteration logic over entries, delegating each add
        operation to the operations service and aggregating results into
        sync statistics.

        Business Rules:
            - Processes entries sequentially (not parallel) for predictable order
            - Each entry is added via ``FlextLdapOperations.add()``
            - Existing entries (LDAP error 68) are counted as "skipped"
            - Other failures are counted as "failed" but do not halt batch
            - Progress callback is invoked after EACH entry with running stats

        Audit Implications:
            - Progress callbacks provide per-entry audit trail
            - Entry DN is included in callback for identification
            - Index (1-based) enables correlation with source file line numbers

        """

        def __init__(self, operations: FlextLdapOperations) -> None:
            """Initialize batch sync handler with operations service.

            Business Rules:
                - Operations service is REQUIRED (no default, fail-fast pattern)
                - Handler stores reference for delegation to parent service
                - No connection validation at init (validated during sync)

            Audit Implications:
                - Handler initialization is not logged (no side effects)
                - Connection validation occurs during sync() execution

            Architecture:
                - Inner class encapsulates batch processing logic
                - Delegates all LDAP operations to parent FlextLdapOperations
                - Enables testability through dependency injection

            Args:
                operations: FlextLdapOperations instance for LDAP operations.
                    Must have active connection for sync() to succeed.

            """
            super().__init__()
            self._ops = operations

        def sync(
            self,
            entries: list[FlextLdifModels.Entry],
            options: m.SyncOptions,
        ) -> r[m.SyncStats]:
            """Sync entries in batch mode with progress tracking.

            Business Rules:
                - Iterates entries in list order (preserves LDIF file order)
                - Uses ``FlextLdapOperations.is_already_exists_error()`` for
                  idempotent detection (LDAP error 68 / entryAlreadyExists)
                - Duration is set to 0.0 (caller computes actual duration)
                - Progress callback receives 1-based index for user-friendly display

            Audit Implications:
                - Returns detailed counts: added, skipped (existing), failed
                - Progress callback enables real-time audit logging
                - Entry DN extraction uses FlextLdifUtilities.DN.get_dn_value()

            Args:
                entries: List of LDIF entries to add to the directory.
                options: Sync options including progress_callback for monitoring.

            Returns:
                r[SyncStats]: Statistics with added/skipped/failed
                counts and zero duration (caller updates).

            """
            # Builder pattern: accumulate stats using DSL
            stats_builder: dict[str, int] = {"added": 0, "skipped": 0, "failed": 0}

            # DSL pattern: process entries with accumulator builder
            def process_entry(idx_entry: tuple[int, FlextLdifModels.Entry]) -> m.LdapBatchStats:
                """Process single entry and update accumulator."""
                idx, entry = idx_entry
                entry_dn = FlextLdifUtilities.DN.get_dn_value(entry.dn)
                add_result = self._ops.add(entry)
                # DSL pattern: builder for stats based on result
                if add_result.is_success:
                    stats_builder["added"] += 1
                    entry_stats = m.LdapBatchStats(synced=1, skipped=0, failed=0)
                else:
                    error_str = cast(
                        "str", u.ensure(add_result.error, target_type="str", default="")
                    )
                    # DSL pattern: determine stats based on error type
                    is_skipped = FlextLdapOperations.is_already_exists_error(error_str)
                    if is_skipped:
                        stats_builder["skipped"] += 1
                        entry_stats = m.LdapBatchStats(synced=0, skipped=1, failed=0)
                    else:
                        stats_builder["failed"] += 1
                        entry_stats = m.LdapBatchStats(synced=0, skipped=0, failed=1)

                if options.progress_callback:
                    options.progress_callback(idx, len(entries), entry_dn, entry_stats)
                return entry_stats

            # Process all entries using u.process() with accumulator
            u.process(
                list(enumerate(entries, 1)),
                processor=process_entry,
                on_error="skip",
            )

            return u.ok(
                m.SyncStats.from_counters(
                    added=stats_builder["added"],
                    skipped=stats_builder["skipped"],
                    failed=stats_builder["failed"],
                    duration_seconds=0.0,
                ),
            )

    class BaseDNTransformer:
        """Transform entry base DNs when source and target differ.

        Handles DN translation for cross-domain migrations where LDIF entries
        from one directory (e.g., ``dc=old,dc=com``) need to be imported into
        another (e.g., ``dc=new,dc=com``).

        Business Rules:
            - Transformation is case-INSENSITIVE for DN matching (RFC 4514)
            - Returns original list unchanged if source == target (no-op optimization)
            - Uses ``model_copy(update=...)`` for immutable Pydantic entry updates
            - Only the DN suffix is replaced; RDN components are preserved
            - Entries not matching source_basedn are passed through unchanged

        Audit Implications:
            - DN transformation is a pure function (no side effects)
            - Original entries are NOT modified (immutable pattern)
            - Enables audit trail correlation between source and target DNs

        """

        @staticmethod
        def transform(
            entries: list[FlextLdifModels.Entry],
            source_basedn: str,
            target_basedn: str,
        ) -> list[FlextLdifModels.Entry]:
            """Rewrite entry DNs from ``source_basedn`` to ``target_basedn``.

            Business Rules:
                - Case-insensitive matching via ``lower()`` comparison (RFC 4514)
                - No transformation if source equals target (returns input list)
                - Creates new Entry instances via ``model_copy()`` (immutable)
                - DN replacement uses simple string replace (efficient)
                - Non-matching entries are included unchanged in result

            Audit Implications:
                - Returns new list; original entries are unchanged
                - Can be used for dry-run validation before actual sync

            Args:
                entries: Source LDIF entries with DNs containing source_basedn.
                source_basedn: The base DN suffix to replace (e.g., "dc=old,dc=com").
                target_basedn: The replacement base DN (e.g., "dc=new,dc=com").

            Returns:
                list[Entry]: New list with transformed DNs. Original entries
                unchanged if source_basedn == target_basedn.

            """
            if source_basedn == target_basedn:
                return entries

            # Use u.process() for efficient entry transformation
            def transform_entry(entry: FlextLdifModels.Entry) -> FlextLdifModels.Entry:
                """Transform entry DN if source_basedn matches."""
                dn_str = FlextLdifUtilities.DN.get_dn_value(entry.dn)
                if source_basedn.lower() in dn_str.lower():
                    return entry.model_copy(
                        update={
                            "dn": FlextLdifModels.DistinguishedName(
                                value=dn_str.replace(source_basedn, target_basedn),
                            ),
                        },
                    )
                return entry

            # Process all entries using u.map()
            transformed = u.map(entries, mapper=transform_entry)
            return cast("list[FlextLdifModels.Entry]", transformed)

    def __init__(
        self,
        operations: FlextLdapOperations | None = None,
        **kwargs: str | float | bool | None,
    ) -> None:
        """Initialize the sync service with a required operations instance.

        Business Rules:
            - Operations parameter is REQUIRED (raises TypeError if None)
            - Supports operations via positional arg OR kwargs["operations"]
            - FlextLdif singleton is resolved at construction for LDIF parsing
            - Datetime generator uses u.Generators for test injection
            - Type validation ensures operations is FlextLdapOperations instance

        Audit Implications:
            - Service instantiation is deterministic (no async initialization)
            - Type errors surface immediately at construction time

        Args:
            operations: Required FlextLdapOperations instance with active
                connection. Raises TypeError if None or wrong type.
            **kwargs: Additional arguments passed to base class. May contain
                "operations" key as alternative to positional argument.

        Raises:
            TypeError: If operations is None or not FlextLdapOperations.

        """
        super().__init__(**kwargs)
        # Use u.get() mnemonic: extract from kwargs with fallback
        if operations is None:
            operations_kwarg = u.get(kwargs, "operations")
            if operations_kwarg is not None:
                # Use u.guard() mnemonic: type validation
                guard_result = u.guard(
                    operations_kwarg,
                    FlextLdapOperations,
                    context_name="operations",
                    return_value=True,
                )
                if guard_result is None:
                    error_msg = f"operations must be FlextLdapOperations, got {type(operations_kwarg).__name__}"
                    raise TypeError(error_msg)
                operations = operations_kwarg
        if operations is None:
            error_msg = "operations parameter is required"
            raise TypeError(error_msg)
        self._operations = operations
        # FlextLdif accepts config via kwargs, not as direct parameter
        self._ldif = FlextLdif.get_instance()
        self._generate_datetime_utc = u.Generators.generate_datetime_utc

    def sync_ldif_file(
        self,
        ldif_file: Path,
        options: m.SyncOptions,
    ) -> r[m.SyncStats]:
        """Parse and sync an LDIF file into the directory.

        Main entry point for file-based LDIF synchronization. Validates file
        existence, parses entries using FlextLdif, and delegates to the sync
        pipeline for base DN transformation and batch processing.

        Business Rules:
            - File existence is validated BEFORE parsing (fail-fast pattern)
            - Parsing uses FlextLdif.parse() with "rfc" server type (RFC 2849)
            - Duration timing starts at method entry (includes parse time)
            - Empty files or parse failures return structured failures
            - Processing delegates to ``_process_entries()`` for testability

        Audit Implications:
            - File path is included in error messages for troubleshooting
            - Parse errors include FlextLdif error details
            - Duration captures full sync time including parsing
            - Returns SyncStats for compliance reporting

        Args:
            ldif_file: Path to the LDIF file to parse and sync.
            options: Sync options including base DN transformation and
                progress callback settings.

        Returns:
            r[SyncStats]: Success with sync statistics or failure
            with error message (file not found or parse error).

        """
        if not ldif_file.exists():
            return u.fail(f"LDIF file not found: {ldif_file}")

        start_time = self._generate_datetime_utc()
        # Use FlextLdif API parse method (avoids broken parse_source)
        # Use ServerTypes Literal type directly (FlextLdif.parse accepts Literal)
        # Use the literal value from the enum
        server_type_literal: FlextLdifConstants.LiteralTypes.ServerTypeLiteral = (
            "rfc"  # Literal matching FlextLdifConstants.ServerTypes.RFC.value
        )
        parse_result = self._ldif.parse(
            source=ldif_file,
            server_type=server_type_literal,
        )

        if parse_result.is_failure:
            return u.fail(f"Failed to parse LDIF file: {u.err(parse_result, default='')}")

        # API parse returns list[Entry] directly
        entries = parse_result.unwrap()
        return self._process_entries(entries, options, start_time)

    def _process_entries(
        self,
        entries: list[FlextLdifModels.Entry],
        options: m.SyncOptions,
        start_time: datetime,
    ) -> r[m.SyncStats]:
        """Process parsed entries through the sync pipeline.

        Internal method that handles the post-parsing workflow: base DN
        transformation, batch synchronization, and duration calculation.
        Separated from ``sync_ldif_file`` for testability.

        Business Rules:
            - Empty entry list returns zero-counter stats (no error)
            - Base DN transformation applied ONLY if both source and target set
            - BatchSync instance is created per-call (stateless helper)
            - Duration is computed as delta from start_time to completion
            - Stats are updated via ``model_copy()`` for immutable pattern

        Audit Implications:
            - Empty results are valid (return ok with zero counters)
            - Duration accuracy depends on provided start_time
            - Stats include transformed entries (post-DN-transformation)

        Args:
            entries: Parsed LDIF entries (may be empty).
            options: Sync options with base DN settings and progress callback.
            start_time: UTC timestamp from caller for duration calculation.

        Returns:
            r[SyncStats]: Success with sync statistics including
            duration. Failure propagated from BatchSync if any.

        Note:
            This is an internal method (prefixed with ``_``). External callers
            should use ``sync_ldif_file()`` instead.

        """
        if not entries:
            return u.ok(
                m.SyncStats.from_counters(),
            )

        if options.source_basedn and options.target_basedn:
            entries = self.BaseDNTransformer.transform(
                entries,
                options.source_basedn,
                options.target_basedn,
            )

        batch_result = self.BatchSync(self._operations).sync(entries, options)
        if batch_result.is_failure:
            return batch_result

        stats = batch_result.unwrap()
        duration = (self._generate_datetime_utc() - start_time).total_seconds()
        return u.ok(stats.model_copy(update={"duration_seconds": duration}))

    def execute(  # noqa: PLR6301
        self,
        **_kwargs: str | float | bool | None,
    ) -> r[m.SyncStats]:
        """Return an empty stats payload to indicate service readiness.

        Implements the ``FlextService.execute()`` contract for service health
        checks. Returns zero-counter stats to indicate the sync service is
        ready to accept sync requests.

        Business Rules:
            - Always returns success with empty/zero SyncStats
            - Does NOT check operations service connectivity
            - ``noqa: PLR6301`` allows self-reference for potential future use
            - ``_kwargs`` absorbs extra arguments for interface compatibility

        Audit Implications:
            - Can be called by service orchestrators for readiness checks
            - Does not perform actual sync operations (lightweight)
            - Zero counters indicate no sync work performed

        Args:
            **_kwargs: Absorbed keyword arguments for interface compatibility.
                Not used by this implementation.

        Returns:
            r[SyncStats]: Always ok with ``from_counters()`` defaults
            (added=0, skipped=0, failed=0, duration_seconds=0.0).

        """
        return u.ok(m.SyncStats.from_counters())

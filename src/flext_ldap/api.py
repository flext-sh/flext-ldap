"""FLEXT-LDAP API - Unified Facade for LDAP Operations.

This module provides the primary entry point for all LDAP operations in the FLEXT
ecosystem. The FlextLdap class serves as a facade for LDAP operations using clean
dependency injection of connection and operations services.

Business Rules:
    - All LDAP operations MUST flow through this facade (zero direct ldap3 usage)
    - Connection and operations services are injected (no internal instantiation)
    - FlextLdif singleton is used for LDIF parsing (consistent ecosystem behavior)
    - FlextResult pattern is used for all operations (no exceptions raised)
    - Search results use m.Ldap.Entry for cross-ecosystem compatibility
    - Upsert operations implement add-or-modify pattern with idempotent handling

Audit Implications:
    - All operations are logged via FlextLdapServiceBase.logger
    - Connection/disconnection events create audit trail
    - Operation results include affected counts for compliance reporting
    - Progress callbacks enable real-time audit during batch operations
    - Error messages include operation context for forensic analysis

Architecture Notes:
    - Implements Facade pattern over connection and operations services
    - Uses Pydantic v2 with frozen=False for mutable facade state
    - Context manager support for automatic resource cleanup
    - Decorator validation via u.Args.validated_with_result
    - Type guards for callback signature detection (multi-phase vs single-phase)

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT

"""

from __future__ import annotations

import inspect
import types
from collections.abc import Sequence
from datetime import UTC, datetime
from pathlib import Path
from typing import Protocol, Self, TypeGuard, override, runtime_checkable

from flext_core import FlextConfig, r
from flext_ldif import FlextLdif
from pydantic import ConfigDict, PrivateAttr

from flext_ldap.base import s
from flext_ldap.config import FlextLdapConfig
from flext_ldap.constants import c
from flext_ldap.models import m
from flext_ldap.protocols import p
from flext_ldap.services.connection import FlextLdapConnection
from flext_ldap.services.operations import FlextLdapOperations
from flext_ldap.typings import t
from flext_ldap.utilities import u

# Constants for callback parameter counting
MULTI_PHASE_CALLBACK_PARAM_COUNT: int = 5
SINGLE_PHASE_CALLBACK_PARAM_COUNT: int = 4


@runtime_checkable
class HasConfigAttribute(Protocol):
    """Protocol for objects with private _config attribute."""

    _config: FlextLdapConfig


def _is_multi_phase_callback(
    callback: m.Ldap.Types.ProgressCallbackUnion,
) -> TypeGuard[m.Ldap.Types.MultiPhaseProgressCallback]:
    """Type guard to check if callback is multi-phase (5 parameters).

    Business Rules:
        - Multi-phase callbacks have 5 parameters: (phase, current, total, dn, stats)
        - Used for sync_multiple_phases() where phase name is needed
        - Returns False for None callbacks (safe no-op pattern)
        - Uses inspect.signature() for parameter counting

    Args:
        callback: Progress callback union type to check.

    Returns:
        TypeGuard narrowing to MultiPhaseProgressCallback if 5 parameters.

    """
    if callback is None:
        return False
    try:
        sig = inspect.signature(callback)
        # Check parameter count matches multi-phase callback signature
        return len(sig.parameters) == MULTI_PHASE_CALLBACK_PARAM_COUNT
    except (TypeError, ValueError, AttributeError):
        return False


def _is_single_phase_callback(
    callback: m.Ldap.Types.ProgressCallbackUnion,
) -> TypeGuard[m.Ldap.Types.LdapProgressCallback]:
    """Type guard to check if callback is single-phase (4 parameters).

    Business Rules:
        - Single-phase callbacks have 4 parameters: (current, total, dn, stats)
        - Used for batch_upsert() where phase name is implicit
        - Returns False for None callbacks (safe no-op pattern)
        - Uses inspect.signature() for parameter counting

    Args:
        callback: Progress callback union type to check.

    Returns:
        TypeGuard narrowing to LdapProgressCallback if 4 parameters.

    """
    if callback is None:
        return False
    try:
        sig = inspect.signature(callback)
        # Check parameter count matches single-phase callback signature
        return len(sig.parameters) == SINGLE_PHASE_CALLBACK_PARAM_COUNT
    except (TypeError, ValueError, AttributeError):
        return False


def _convert_entries_to_protocol(
    entries: Sequence[p.Entry | p.Ldap.LdapEntryProtocol],
) -> list[p.Ldap.LdapEntryProtocol]:
    """Convert entries to protocol list with type safety.

    Args:
        entries: Sequence of entries (p.Entry or p.Ldif.Entry.EntryProtocol)

    Returns:
        List of p.Ldif.Entry.EntryProtocol-compatible entries

    """
    # Filter entries that are protocol-compatible
    # p.Entry is structurally compatible with p.Ldif.Entry.EntryProtocol
    # Use isinstance check for type narrowing
    return [entry for entry in entries if isinstance(entry, p.Ldap.LdapEntryProtocol)]


def _get_phase_result_value(
    phase_result: m.Ldap.PhaseSyncResult | p.Ldap.PhaseSyncResultProtocol,
    attr_name: str,
    default: int = 0,
) -> int:
    """Get phase result attribute value with type safety.

    Args:
        phase_result: Phase result (model or protocol-compatible)
        attr_name: Attribute name to extract
        default: Default value if attribute not found

    Returns:
        Attribute value or default

    """
    # Python 3.13: Both union types share same attributes - direct access
    # isinstance check ensures protocol compatibility
    if isinstance(
        phase_result, (m.Ldap.PhaseSyncResult, p.Ldap.PhaseSyncResultProtocol)
    ):
        # Use match-case for modern Python 3.13 pattern matching
        match attr_name:
            case "total_entries":
                return phase_result.total_entries
            case "synced":
                return phase_result.synced
            case "failed":
                return phase_result.failed
            case "skipped":
                return phase_result.skipped
            case _:
                return default
    return default


class FlextLdap(s[m.Ldap.SearchResult]):
    """Main API facade for LDAP operations using dependency injection.

    Uses FlextLdapConnection and FlextLdapOperations directly without wrapper logic.
    Implements clean composition pattern for orchestrating lower-layer services.

    Business Rules:
        - Connection and operations services are REQUIRED (no lazy initialization)
        - FlextLdif defaults to singleton if not provided (ecosystem consistency)
        - Config is inherited from connection service for consistency
        - All CRUD operations delegate to operations service (no direct ldap3)
        - Context manager support ensures cleanup on scope exit
        - Initialization logs facade readiness for audit trail

    Audit Implications:
        - Facade initialization logged at INFO level with service readiness
        - All operations inherit logging from service base class
        - Connection/disconnection create audit trail entries
        - Search result counts logged for compliance reporting
        - Batch operation progress trackable via callbacks

    Architecture Notes:
        - Implements FlextService pattern via ``FlextLdapServiceBase[SearchResult]``
        - Uses PrivateAttr for Pydantic v2 compatibility
        - frozen=False allows mutable state (logging, operation state)
        - extra="forbid" prevents accidental attribute additions
        - @override decorator for execute() ensures base class contract

    Example:
        >>> from flext_ldap import FlextLdap, FlextLdapConnection, FlextLdapOperations
        >>> connection = FlextLdapConnection(config=config, parser=ldif.parser)
        >>> operations = FlextLdapOperations(connection=connection)
        >>> api = FlextLdap(connection=connection, operations=operations, ldif=ldif)
        >>>
        >>> with api:
        ...     api.connect(connection_config)
        ...     result = api.search(search_options)
        ...     if result.is_success:
        ...         entries = result.unwrap().entries
        >>> # disconnect called automatically on context exit

    """

    @classmethod
    def _get_service_config_type(cls) -> type[FlextLdapConfig]:
        """Get FlextLdapConfig as the service-specific config type."""
        return FlextLdapConfig

    model_config = ConfigDict(
        frozen=False,  # Facade needs mutable state for logging
        extra="forbid",
        arbitrary_types_allowed=True,
    )

    _connection: FlextLdapConnection = PrivateAttr()
    _operations: FlextLdapOperations = PrivateAttr()
    _ldif: FlextLdif = PrivateAttr()
    _config: FlextConfig | None = PrivateAttr(
        default=None,
    )  # Compatible with base class

    def __init__(
        self,
        *,
        connection: FlextLdapConnection,
        operations: FlextLdapOperations,
        ldif: FlextLdif | None = None,
        **kwargs: str | float | bool | None,
    ) -> None:
        """Initialize LDAP facade with injected dependencies.

        Business Rules:
            - Connection and operations are REQUIRED (keyword-only, no defaults)
            - FlextLdif defaults to singleton for ecosystem consistency
            - Config is inherited from connection._config for consistency
            - Initialization is logged at INFO level for audit trail
            - Uses object.__setattr__ for Pydantic frozen model compatibility

        Audit Implications:
            - Facade initialization logged with service readiness flags
            - No actual LDAP operations performed during init
            - Ready state logged as connection_ready, operations_ready, ldif_available

        Args:
            connection: Initialized FlextLdapConnection instance. Must be
                configured but not necessarily connected.
            operations: Initialized FlextLdapOperations instance. Must reference
                the same connection for consistent state.
            ldif: FlextLdif instance (defaults to get_instance() singleton).
            **kwargs: Additional kwargs for FlextService base class.

        """
        # Python 3.13: Filter kwargs with modern comprehension
        service_kwargs: dict[str, str | float | bool | None] = {
            k: v
            for k, v in kwargs.items()
            if k != "_auto_result" and (v is None or isinstance(v, (str, float, bool)))
        }
        # Type narrowing: service_kwargs is dict[str, str | float | bool | None]
        # which matches FlextService.__init__ signature
        # Protocols are structurally compatible - no type ignore needed
        super().__init__(**service_kwargs)
        self._connection = connection
        self._operations = operations
        self._ldif = ldif or FlextLdif()
        # Use connection's config if available for consistency
        # Otherwise, super().__init__() already created proper
        # FlextLdapConfig via _get_service_config_type()
        # Access private attribute via Protocol for type safety
        # PrivateAttr is accessible but not part of public API
        # PrivateAttr access is necessary for copying config from
        # connection to facade
        connection_config: FlextLdapConfig | None = None
        # Python 3.13: Use Protocol check for type narrowing
        if isinstance(connection, HasConfigAttribute):
            config_raw = connection._config  # noqa: SLF001
            # Type narrowing: isinstance ensures config is FlextLdapConfig
            if isinstance(config_raw, FlextLdapConfig):
                connection_config = config_raw
        # Type narrowing: connection_config is already FlextLdapConfig | None
        # After isinstance check above, if it's not None, it's FlextLdapConfig
        if connection_config is not None:
            # Set attribute directly (no PrivateAttr needed, compatible with FlextService)
            self._config = connection_config
        self.logger.info(
            "FlextLdap facade initialized",
            connection_ready=True,
            operations_ready=True,
            ldif_available=True,
        )

    def __enter__(self) -> Self:
        """Context manager entry for 'with' statement support.

        Business Rules:
            - Returns self for use in 'with' block scope
            - No connection is established (caller must call connect())
            - Enables automatic resource cleanup on scope exit

        Audit Implications:
            - Context entry is not logged (lightweight operation)
            - Resource lifecycle is bounded by 'with' scope

        Returns:
            Self for use in 'with' statement body.

        """
        return self

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc_val: BaseException | None,
        exc_tb: types.TracebackType | None,
    ) -> None:
        """Context manager exit with automatic disconnection.

        Automatically disconnects when exiting 'with' block, regardless of
        whether an exception occurred. This ensures resource cleanup.

        Business Rules:
            - Always calls disconnect() for resource cleanup
            - Exception information is ignored (disconnect is idempotent)
            - No return value (does not suppress exceptions)
            - Safe to call even if not connected

        Audit Implications:
            - Disconnect is logged via disconnect() method
            - Exception handling is deferred to caller
            - Resource cleanup is guaranteed

        Args:
            exc_type: Exception type if exception occurred (not used).
            exc_val: Exception value if exception occurred (not used).
            exc_tb: Exception traceback if exception occurred (not used).

        """
        self.disconnect()

    def connect(
        self,
        connection_config: m.Ldap.ConnectionConfig | FlextLdapConfig,
        *,
        auto_retry: bool = False,
        max_retries: int = 3,
        retry_delay: float = 1.0,
        **_kwargs: str | float | bool | None,
    ) -> r[bool]:
        """Establish LDAP connection with optional auto-retry.

        Business Rules:
            - Connection is established via FlextLdapConnection service layer
            - Auto-retry mechanism uses exponential backoff (u.Reliability)
            - Connection state is tracked internally and validated before operations
            - SSL/TLS configuration is validated before connection attempt
            - Bind credentials are validated but not logged (security requirement)

        Audit Implications:
            - Connection attempts are logged with host/port (credentials excluded)
            - Successful connections log connection parameters for traceability
            - Failed connections log error messages for forensic analysis
            - Retry attempts are logged individually for compliance reporting
            - Connection state changes trigger audit events

        Architecture:
            - Delegates to FlextLdapConnection.connect() for actual connection logic
            - Uses FlextResult pattern - no exceptions raised
            - Supports both ConnectionConfig and FlextLdapConfig for flexibility
            - Connection must be established before any LDAP operations

        Args:
            connection_config: Connection configuration
              (ConnectionConfig or FlextLdapConfig)
            auto_retry: Enable automatic retry on connection failure (default: False)
            max_retries: Maximum number of retry attempts (default: 3)
            retry_delay: Delay between retries in seconds (default: 1.0)

        Returns:
            r[bool] indicating connection success

        """
        # Convert FlextLdapConfig to ConnectionConfig if needed
        if isinstance(connection_config, FlextLdapConfig):
            connection_config = m.Ldap.ConnectionConfig(
                host=connection_config.host,
                port=connection_config.port,
                use_ssl=connection_config.use_ssl,
                use_tls=connection_config.use_tls,
                bind_dn=connection_config.bind_dn,
                bind_password=connection_config.bind_password,
                timeout=connection_config.timeout,
                auto_bind=connection_config.auto_bind,
                auto_range=connection_config.auto_range,
            )

        self.logger.debug(
            "Connecting to LDAP server",
            host=connection_config.host,
            port=connection_config.port,
            use_ssl=connection_config.use_ssl,
            use_tls=connection_config.use_tls,
        )

        result = self._connection.connect(
            connection_config,
            auto_retry=auto_retry,
            max_retries=max_retries,
            retry_delay=retry_delay,
        )

        if result.is_success:
            self.logger.info(
                "LDAP connection established",
                host=connection_config.host,
                port=connection_config.port,
            )
        else:
            self.logger.error(
                "LDAP connection failed",
                host=connection_config.host,
                port=connection_config.port,
                error=str(result.error),
            )

        return result

    def disconnect(self) -> None:
        """Close LDAP connection.

        Business Rules:
            - Gracefully closes LDAP connection and releases resources
            - No-op if already disconnected (idempotent operation)
            - Connection state is cleared after disconnection
            - All pending operations are cancelled on disconnect

        Audit Implications:
            - Disconnection events are logged for audit trail
            - Connection duration can be calculated from connect/disconnect logs
            - Failed disconnections are logged as warnings

        Architecture:
            - Delegates to FlextLdapConnection.disconnect()
            - Safe to call multiple times (idempotent)
            - No exceptions raised - always succeeds

        """
        self.logger.debug("Disconnecting from LDAP server")
        self._connection.disconnect()
        self.logger.info("LDAP connection closed")

    @property
    def is_connected(self) -> bool:
        """Check if LDAP connection is active.

        Business Rules:
            - Delegates to FlextLdapConnection.is_connected property
            - Returns True if connection is bound and ready for operations
            - Returns False if connection is closed or not established
            - State is checked synchronously (no network calls)

        Audit Implications:
            - Connection state checks are not logged (frequent operation)
            - State changes are logged via connect/disconnect methods
            - State can be queried before operations for validation

        Returns:
            True if connected and bound, False otherwise.

        """
        return self._connection.is_connected

    @u.Args.validated_with_result
    def search(
        self,
        search_options: m.Ldap.SearchOptions,
        server_type: c.Ldif.ServerTypes = (c.Ldif.ServerTypes.RFC),
    ) -> r[m.Ldap.SearchResult]:
        """Perform LDAP search operation.

        Business Rules:
            - Base DN is normalized using FlextLdifUtilities.Ldif.DN.norm_string() before search
            - Search filter is validated against LDAP filter syntax
            - Server type determines parsing quirks (OpenLDAP, OUD, OID, RFC)
            - Search scope (BASE, ONELEVEL, SUBTREE) controls depth of search
            - Empty result sets return successful SearchResult with empty entries list
            - Operational attributes are filtered according to server type quirks

        Audit Implications:
            - All search operations are logged with base_dn, filter, and scope
            - Search result counts are logged for compliance reporting
            - Failed searches log error messages with search parameters
            - Large result sets (>1000 entries) trigger performance warnings
            - Search operations are auditable via LDAP server access logs

        Architecture:
            - Delegates to FlextLdapOperations.search() for execution
            - Uses FlextLdifParser for server-specific entry parsing
            - Returns FlextResult pattern - no exceptions raised
            - Entry models use m.Ldap.Entry for consistency

        Args:
            search_options: Search configuration (base_dn, filter_str, scope, attributes)
            server_type: LDAP server type for parsing quirks (default: RFC)

        Returns:
            FlextResult containing SearchResult with Entry models

        """
        return self._operations.search(search_options, server_type)

    def add(
        self,
        entry: p.Ldap.LdapEntryProtocol | m.Ldap.Entry | p.Entry,
    ) -> r[m.Ldap.OperationResult]:
        """Add LDAP entry.

        Business Rules:
            - Entry DN must be unique (LDAP error 68 if entry already exists)
            - Entry attributes are validated against LDAP schema
            - Required objectClass attributes must be present
            - DN normalization is applied before add operation
            - Operational attributes (modifyTimestamp, etc.) are auto-generated by server
            - Entry must conform to LDAP schema constraints

        Audit Implications:
            - Add operations are logged with entry DN for traceability
            - Successful adds log entry DN and affected count (always 1)
            - Failed adds log error message and DN for forensic analysis
            - Add operations are auditable via LDAP server access logs
            - Entry creation timestamps are tracked by LDAP server

        Architecture:
            - Delegates to FlextLdapOperations.add() for execution
            - Uses Ldap3Adapter for protocol-level operations
            - Entry conversion handled by FlextLdapEntryAdapter
            - Returns FlextResult pattern - no exceptions raised

        Args:
            entry: Entry model to add (must include DN and required attributes)

        Returns:
            FlextResult containing OperationResult with success status and entries_affected=1

        """
        return self._operations.add(entry)

    def modify(
        self,
        dn: str | p.Ldap.DistinguishedNameProtocol,
        changes: t.Ldap.ModifyChanges,
    ) -> r[m.Ldap.OperationResult]:
        """Modify LDAP entry.

        Business Rules:
            - Entry must exist before modification (LDAP error 32 if not found)
            - Changes use ldap3 format: {attr_name: [(MODIFY_ADD|MODIFY_DELETE|MODIFY_REPLACE, [values])]}
            - MODIFY_REPLACE replaces all values of an attribute
            - MODIFY_ADD adds values to existing attribute (multi-valued)
            - MODIFY_DELETE removes values from attribute (empty list removes all)
            - DN normalization is applied before modify operation
            - Schema constraints are validated by LDAP server

        Audit Implications:
            - Modify operations are logged with DN and change summary
            - Successful modifies log affected attribute names (not values for privacy)
            - Failed modifies log error message and DN for forensic analysis
            - Modify operations are auditable via LDAP server access logs
            - Entry modification timestamps are tracked by LDAP server

        Architecture:
            - Delegates to FlextLdapOperations.modify() for execution
            - Uses Ldap3Adapter for protocol-level operations
            - DN conversion handled by FlextLdifUtilities.DN
            - Returns FlextResult pattern - no exceptions raised

        Args:
            dn: Distinguished name of entry to modify (string or DistinguishedName model)
            changes: Modification changes dict in ldap3 format

        Returns:
            FlextResult containing OperationResult with success status and entries_affected=1

        """
        return self._operations.modify(dn, changes)

    @u.Args.validated_with_result
    def delete(
        self,
        dn: str | p.Ldap.DistinguishedNameProtocol,
    ) -> r[m.Ldap.OperationResult]:
        """Delete LDAP entry.

        Business Rules:
            - Entry must exist before deletion (LDAP error 32 if not found)
            - Entry must not have children (LDAP error 66 if has children)
            - DN normalization is applied before delete operation
            - Deletion is permanent - no undo capability
            - Cascade deletion is not supported (delete children first)

        Audit Implications:
            - Delete operations are logged with DN for critical audit trail
            - Successful deletes log entry DN and affected count (always 1)
            - Failed deletes log error message and DN for forensic analysis
            - Delete operations are auditable via LDAP server access logs
            - Entry deletion events are critical for compliance reporting

        Architecture:
            - Delegates to FlextLdapOperations.delete() for execution
            - Uses Ldap3Adapter for protocol-level operations
            - DN conversion handled by FlextLdifUtilities.DN
            - Returns FlextResult pattern - no exceptions raised

        Args:
            dn: Distinguished name of entry to delete (string or DistinguishedName model)

        Returns:
            FlextResult containing OperationResult with success status and entries_affected=1

        """
        return self._operations.delete(dn)

    @u.Args.validated_with_result
    def upsert(
        self,
        entry: p.Ldap.LdapEntryProtocol | m.Ldap.Entry | p.Entry,
        *,
        retry_on_errors: list[str] | None = None,
        max_retries: int = 1,
    ) -> r[m.Ldap.LdapOperationResult]:
        """Upsert LDAP entry (add if doesn't exist, modify if exists with changes, skip if identical).

        Business Rules:
            - First attempts ADD operation
            - If entry exists (LDAP error 68), performs search and comparison
            - Entry comparison ignores operational attributes (modifyTimestamp, etc.)
            - If entries are identical, operation is SKIPPED (no changes needed)
            - If entries differ, MODIFY operation is applied with computed changes
            - Schema modification entries (changetype=modify) are handled specially
            - Retry mechanism uses u.Reliability for transient errors

        Audit Implications:
            - Upsert operations log operation type (ADDED, MODIFIED, SKIPPED)
            - Comparison results are logged for audit trail
            - Retry attempts are logged individually for compliance
            - Skipped operations indicate no changes needed (audit efficiency)
            - All upsert outcomes are auditable via LDAP server access logs

        Architecture:
            - Delegates to FlextLdapOperations.upsert() for execution
            - Uses EntryComparison.compare() for attribute-level diff
            - Retry logic uses u.Reliability.retry()
            - Returns FlextResult pattern - no exceptions raised

        Args:
            entry: Entry model to upsert (must include DN and attributes)
            retry_on_errors: List of error patterns to retry on (e.g., ["session terminated"])
            max_retries: Maximum number of retry attempts (default: 1, no retry)

        Returns:
            FlextResult containing LdapOperationResult with operation type (ADDED|MODIFIED|SKIPPED)

        """
        return self._operations.upsert(
            entry,
            retry_on_errors=retry_on_errors,
            max_retries=max_retries,
        )

    @u.Args.validated_with_result
    def batch_upsert(
        self,
        entries: Sequence[p.Ldap.LdapEntryProtocol],
        *,
        progress_callback: m.Ldap.Types.LdapProgressCallback | None = None,
        retry_on_errors: list[str] | None = None,
        max_retries: int = 1,
        stop_on_error: bool = False,
    ) -> r[m.Ldap.LdapBatchStats]:
        """Batch upsert multiple LDAP entries with progress tracking.

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
            - Large batches (>1000 entries) trigger performance monitoring

        Architecture:
            - Delegates to FlextLdapOperations.batch_upsert() for execution
            - Uses FlextLdapOperations.upsert() for each entry
            - Progress callback signature: (current: int, total: int, dn: str, stats: LdapBatchStats)
            - Returns FlextResult pattern - no exceptions raised

        Args:
            entries: List of entries to upsert (must include DN and attributes)
            progress_callback: Optional callback for progress tracking (4 parameters)
            retry_on_errors: Error patterns to retry on (e.g., ["session terminated"])
            max_retries: Maximum retries per entry (default: 1, no retry)
            stop_on_error: Stop processing on first error (default: False, continue)

        Returns:
            FlextResult containing LdapBatchStats with synced/failed/skipped counts

        """
        return self._operations.batch_upsert(
            entries,
            progress_callback=progress_callback,
            retry_on_errors=retry_on_errors,
            max_retries=max_retries,
            stop_on_error=stop_on_error,
        )

    @u.Args.validated_with_result
    def sync_phase_entries(
        self,
        ldif_file_path: Path,
        phase_name: str,
        *,
        config: m.Ldap.SyncPhaseConfig | None = None,
    ) -> r[m.Ldap.PhaseSyncResult]:
        """Synchronize entries from LDIF file to LDAP server.

        Business Rules:
            - LDIF file is parsed using FlextLdif.parse() with server type quirks
            - Empty LDIF files return success with 0 entries (no-op)
            - Entries are processed via batch_upsert() with retry logic
            - Server type determines parsing quirks (OpenLDAP, OUD, OID, RFC)
            - Progress callback is converted from multi-phase to single-phase if needed
            - Default retry errors: ["session terminated", "not connected", "invalid messageid", "socket"]
            - Duration and success rate are calculated for performance monitoring

        Audit Implications:
            - Phase sync operations log phase name and file path
            - Parse failures are logged before batch processing
            - Batch statistics (synced/failed/skipped) logged for compliance
            - Duration and success rate logged for performance analysis
            - Multi-phase callbacks enable phase-level audit trail

        Architecture:
            - Uses FlextLdif.parse() for LDIF parsing with server type support
            - Delegates to batch_upsert() for entry processing
            - Callback conversion handles both single-phase (4 params) and multi-phase (5 params)
            - Returns FlextResult pattern - no exceptions raised

        Args:
            ldif_file_path: Path to LDIF file (must exist and be readable)
            phase_name: Name of the phase (for logging and callback identification)
            config: Sync configuration (server_type, progress_callback, retry settings)

        Returns:
            FlextResult containing PhaseSyncResult with statistics and duration

        """
        config = config or m.Ldap.SyncPhaseConfig()

        start_time = datetime.now(UTC)

        parse_result = self._ldif.parse(ldif_file_path, server_type=config.server_type)
        if parse_result.is_failure:
            error_msg = (
                str(parse_result.error) if parse_result.error else "Unknown error"
            )
            return r[m.Ldap.PhaseSyncResult].fail(
                f"Failed to parse LDIF file: {error_msg}"
            )

        # Type narrowing: parse_result.unwrap() returns list[p.Entry]
        # Runtime validation ensures correctness
        parse_value = parse_result.unwrap()
        # Type narrowing: parse_value is list[object] from unwrap(), but runtime guarantees p.Entry
        # Use list comprehension with isinstance for type narrowing
        entries: list[p.Entry] = [
            entry for entry in parse_value if isinstance(entry, p.Entry)
        ]
        if not entries:
            return r[m.Ldap.PhaseSyncResult].ok(
                m.Ldap.PhaseSyncResult(
                    phase_name=phase_name,
                    total_entries=0,
                    synced=0,
                    failed=0,
                    skipped=0,
                    duration_seconds=0.0,
                    success_rate=100.0,
                ),
            )

        # Convert multi-phase callback to single-phase if needed
        single_phase_callback: m.Ldap.Types.LdapProgressCallback | None = None
        callback = config.progress_callback
        if callback is not None:
            # Use models type for strict typing
            callback_union: m.Ldap.Types.ProgressCallbackUnion = callback
            # Use type guard for type narrowing
            if _is_multi_phase_callback(callback_union):
                # Multi-phase callback - wrap to single-phase
                # Type narrowing: callback is MultiPhaseProgressCallback after guard
                multi_phase_cb = callback_union

                def wrapped_cb(
                    current: int,
                    total: int,
                    dn: str,
                    stats: m.Ldap.LdapBatchStats,
                ) -> None:
                    # Use narrowed multi-phase callback
                    multi_phase_cb(phase_name, current, total, dn, stats)

                single_phase_callback = wrapped_cb
            elif _is_single_phase_callback(callback_union):
                # Single-phase callback - use directly
                # Type narrowing: callback is LdapProgressCallback (4 params)
                single_phase_callback = callback_union

        # p.Entry implements p.Ldif.Entry.EntryProtocol (structural compatibility)
        # Type narrowing: entries is list[FlextLdifModels.Entry] which implements p.Ldif.Entry.EntryProtocol
        # Structural typing: p.Entry implements p.Ldap.LdapEntryProtocol
        # Convert to list explicitly for type safety
        # Use helper function for type-safe conversion
        entries_protocol = _convert_entries_to_protocol(entries)
        batch_result = self.batch_upsert(
            entries_protocol,
            progress_callback=single_phase_callback,
            retry_on_errors=config.retry_on_errors
            or [
                "session terminated",
                "not connected",
                "invalid messageid",
                "socket",
            ],
            max_retries=config.max_retries,
            stop_on_error=config.stop_on_error,
        )

        if batch_result.is_failure:
            error_msg = (
                str(batch_result.error) if batch_result.error else "Unknown error"
            )
            return r[m.Ldap.PhaseSyncResult].fail(f"Batch sync failed: {error_msg}")

        batch_stats = batch_result.unwrap()
        duration = (datetime.now(UTC) - start_time).total_seconds()

        total_processed = batch_stats.synced + batch_stats.failed + batch_stats.skipped
        success_rate = (
            (batch_stats.synced + batch_stats.skipped) / total_processed * 100
            if total_processed > 0
            else 0.0
        )

        return r[m.Ldap.PhaseSyncResult].ok(
            m.Ldap.PhaseSyncResult(
                phase_name=phase_name,
                total_entries=len(entries),
                synced=batch_stats.synced,
                failed=batch_stats.failed,
                skipped=batch_stats.skipped,
                duration_seconds=duration,
                success_rate=success_rate,
            ),
        )

    @staticmethod
    def _make_phase_progress_callback(
        phase: str,
        config: m.Ldap.SyncPhaseConfig,
    ) -> m.Ldap.Types.LdapProgressCallback | None:
        """Create progress callback for a phase, handling both single and multi-phase signatures.

        Internal factory method that converts multi-phase callbacks (5 params) to
        single-phase callbacks (4 params) by binding the phase name.

        Business Rules:
            - Returns None if config.progress_callback is None (no-op)
            - Multi-phase callbacks (5 params) are wrapped with phase name binding
            - Single-phase callbacks (4 params) are returned unchanged
            - Unknown callback signatures return None (fallback safety)
            - Uses type guards for proper type narrowing

        Audit Implications:
            - Callback conversion is transparent to callers
            - Phase name is injected for multi-phase audit correlation

        Args:
            phase: Phase name to bind for multi-phase callbacks.
            config: m.Ldap.SyncPhaseConfig containing the callback to convert.

        Returns:
            LdapProgressCallback or None if no valid callback.

        Note:
            This is a static internal method. External callers should use
            sync_phase_entries() or sync_multiple_phases() directly.

        """
        if config.progress_callback is None:
            return None

        callback = config.progress_callback
        if callback is None:
            return None

        # Use models type for strict typing
        callback_union: m.Ldap.Types.ProgressCallbackUnion = callback

        # Use type guard for type narrowing
        if _is_multi_phase_callback(callback_union):
            # Multi-phase callback - wrap to single-phase
            # Type narrowing: callback is MultiPhaseProgressCallback after guard
            multi_phase_cb = callback_union

            def progress_cb(
                current: int,
                total: int,
                dn: str,
                stats: m.Ldap.LdapBatchStats,
            ) -> None:
                # Use narrowed multi-phase callback
                multi_phase_cb(phase, current, total, dn, stats)

            return progress_cb

        if _is_single_phase_callback(callback_union):
            # Single-phase callback - use directly
            # Type narrowing: callback is LdapProgressCallback (4 params)
            return callback_union

        # Fallback: return None if callback signature doesn't match
        return None

    def _prepare_phase_callback(
        self,
        phase_name: str,
        config: m.Ldap.SyncPhaseConfig,
    ) -> m.Ldap.Types.LdapProgressCallback | None:
        """Prepare phase-specific progress callback.

        Converts multi-phase callbacks to single-phase callbacks or uses
        the single-phase callback directly.

        Args:
            phase_name: Name of the phase being processed.
            config: Sync configuration with original callbacks.

        Returns:
            Prepared callback for single phase or None.

        """
        # Convert callback to single-phase if needed
        phase_callback_raw = (
            FlextLdap._make_phase_progress_callback(phase_name, config)
            or config.progress_callback
        )
        # Use models type for strict typing
        phase_callback_union: m.Ldap.Types.ProgressCallbackUnion = phase_callback_raw
        # Ensure result is LdapProgressCallback | None (not MultiPhaseProgressCallback)
        if phase_callback_union is None:
            return None

        if _is_single_phase_callback(phase_callback_union):
            return phase_callback_union

        if _is_multi_phase_callback(phase_callback_union):
            # Wrap multi-phase callback to single-phase
            multi_phase_cb = phase_callback_union

            def wrapped_phase_cb(
                current: int,
                total: int,
                dn: str,
                stats: m.Ldap.LdapBatchStats,
            ) -> None:
                multi_phase_cb(phase_name, current, total, dn, stats)

            return wrapped_phase_cb

        return None

    def _process_single_phase(
        self,
        phase_name: str,
        ldif_path: Path,
        config: m.Ldap.SyncPhaseConfig,
    ) -> r[m.Ldap.PhaseSyncResult]:
        """Process single phase file and return result.

        Handles phase-specific callback preparation and execution.

        Args:
            phase_name: Name of the phase being processed.
            ldif_path: Path to LDIF phase file.
            config: Sync configuration.

        Returns:
            Result containing phase sync data or error.

        """
        # Prepare phase-specific callback
        phase_callback = self._prepare_phase_callback(phase_name, config)

        # Execute phase sync with prepared callback
        return self.sync_phase_entries(
            ldif_path,
            phase_name,
            config=m.Ldap.SyncPhaseConfig(
                server_type=config.server_type,
                progress_callback=phase_callback,  # Structurally compatible, no cast needed
                retry_on_errors=config.retry_on_errors,
                max_retries=config.max_retries,
                stop_on_error=config.stop_on_error,
            ),
        )
        # sync_phase_entries already returns r[m.Ldap.PhaseSyncResult]

    def sync_multiple_phases(
        self,
        phase_files: dict[str, Path],
        *,
        config: m.Ldap.SyncPhaseConfig | None = None,
    ) -> r[m.Ldap.MultiPhaseSyncResult]:
        """Synchronize multiple LDIF phase files sequentially.

        Processes multiple LDIF files (phases) in the order provided by the
        dict keys, aggregating statistics across all phases.

        Business Rules:
            - Phases are processed in dict iteration order (Python 3.7+ preserves order)
            - Missing phase files are logged as warnings but skipped (not errors)
            - stop_on_error=True stops processing on first phase failure
            - stop_on_error=False continues with remaining phases
            - Progress callback is converted per-phase for proper phase identification
            - Success rate is calculated across ALL processed phases

        Audit Implications:
            - Each phase sync is logged individually via sync_phase_entries()
            - Missing files logged at WARNING level
            - Phase failures logged at ERROR level with phase name
            - Overall statistics available for compliance reporting
            - Duration includes all phases (start to finish)

        Args:
            phase_files: Dict mapping phase names to LDIF file paths.
                Keys are phase identifiers, values are Path objects.
            config: Sync configuration (defaults to m.Ldap.SyncPhaseConfig()).
                Applied to all phases uniformly.

        Returns:
            r[MultiPhaseSyncResult]: Aggregated results including
            per-phase statistics, totals, and overall success rate.

        """
        config = config or m.Ldap.SyncPhaseConfig()
        start_time = datetime.now(UTC)
        phase_results: dict[str, m.Ldap.PhaseSyncResult] = {}
        overall_success = True
        stop_requested = False

        # Process all phases in order
        for phase_name, phase_file in phase_files.items():
            if stop_requested:
                break

            if not phase_file.exists():
                self.logger.warning(
                    "Phase file not found",
                    phase=phase_name,
                    file=str(phase_file),
                )
                continue

            # Process single phase and update accumulator state
            phase_result = self._process_single_phase(
                phase_name,
                phase_file,
                config,
            )

            if phase_result.is_failure:
                self.logger.error(
                    "Phase sync failed",
                    phase=phase_name,
                    error=str(phase_result.error),
                )
                overall_success = False
                if config.stop_on_error:
                    stop_requested = True
            else:
                phase_results[phase_name] = phase_result.unwrap()

        # Aggregate totals from phase results
        phase_values = list(phase_results.values())
        totals = {
            "entries": sum(
                _get_phase_result_value(phase_result, "total_entries", 0)
                for phase_result in phase_values
            ),
            "synced": sum(
                _get_phase_result_value(phase_result, "synced", 0)
                for phase_result in phase_values
            ),
            "failed": sum(
                _get_phase_result_value(phase_result, "failed", 0)
                for phase_result in phase_values
            ),
            "skipped": sum(
                _get_phase_result_value(phase_result, "skipped", 0)
                for phase_result in phase_values
            ),
        }
        total_processed = totals["synced"] + totals["failed"] + totals["skipped"]
        overall_success_rate = (
            (totals["synced"] + totals["skipped"]) / total_processed * 100
            if total_processed > 0
            else 0.0
        )

        return r[m.Ldap.MultiPhaseSyncResult].ok(
            m.Ldap.MultiPhaseSyncResult(
                phase_results=phase_results,
                total_entries=totals["entries"],
                total_synced=totals["synced"],
                total_failed=totals["failed"],
                total_skipped=totals["skipped"],
                overall_success_rate=overall_success_rate,
                total_duration_seconds=(datetime.now(UTC) - start_time).total_seconds(),
                overall_success=overall_success,
            ),
        )

    @override
    def execute(
        self,
        **_kwargs: str | float | bool | None,
    ) -> r[m.Ldap.SearchResult]:
        """Execute service health check for FlextService pattern compliance.

        Implements the ``FlextService.execute()`` contract by delegating to
        the operations service health check. The @override decorator ensures
        base class contract is properly implemented.

        Business Rules:
            - Delegates entirely to ``_operations.execute()``
            - Returns SearchResult type per FlextLdapServiceBase[SearchResult]
            - ``_kwargs`` absorbs extra arguments for interface compatibility
            - Does not perform actual search (lightweight health check)

        Audit Implications:
            - Can be called by service orchestrators for readiness checks
            - Health status reflects operations service state
            - No logging performed at facade level (delegated to operations)

        Args:
            **_kwargs: Absorbed keyword arguments for interface compatibility.
                Not used by this implementation.

        Returns:
            r[SearchResult]: Health status from operations service.

        """
        return self._operations.execute()

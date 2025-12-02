"""FLEXT-LDAP API - Unified Facade for LDAP Operations.

This module provides the primary entry point for all LDAP operations.
The FlextLdap class serves as a facade for LDAP operations using dependency injection.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT

"""

from __future__ import annotations

import inspect
import types
from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Self, override

from flext_core import FlextConfig, FlextResult
from flext_ldif import FlextLdif, FlextLdifModels
from flext_ldif.constants import FlextLdifConstants
from pydantic import ConfigDict, PrivateAttr

from flext_ldap.base import FlextLdapServiceBase
from flext_ldap.config import FlextLdapConfig
from flext_ldap.models import FlextLdapModels
from flext_ldap.protocols import FlextLdapProtocols
from flext_ldap.services.connection import FlextLdapConnection
from flext_ldap.services.operations import FlextLdapOperations
from flext_ldap.typings import FlextLdapTypes
from flext_ldap.utilities import FlextLdapUtilities

# Protocol alias for type annotations
DistinguishedNameProtocol = FlextLdapProtocols.LdapEntry.DistinguishedNameProtocol

# Constants for callback parameter counting
MULTI_PHASE_CALLBACK_PARAM_COUNT: int = 5


@dataclass(frozen=True)
class SyncPhaseConfig:
    """Configuration for phase synchronization operations."""

    server_type: FlextLdifConstants.LiteralTypes.ServerTypeLiteral = "rfc"
    progress_callback: (
        Callable[[str, int, int, str, FlextLdapModels.LdapBatchStats], None]
        | FlextLdapModels.Types.LdapProgressCallback
        | None
    ) = None
    retry_on_errors: list[str] | None = None
    max_retries: int = 5
    stop_on_error: bool = False


class FlextLdap(FlextLdapServiceBase[FlextLdapModels.SearchResult]):
    """Main API facade for LDAP operations using dependency injection.

    Uses FlextLdapConnection and FlextLdapOperations directly without wrapper logic.
    Implements clean composition pattern for orchestrating lower-layer services.

    Usage:
        connection = FlextLdapConnection(config=config, parser=ldif.parser)
        operations = FlextLdapOperations(connection=connection)
        api = FlextLdap(connection=connection, operations=operations, ldif=ldif)

        async with api:
            result = api.search(search_options)
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

        Args:
            connection: Initialized FlextLdapConnection instance
            operations: Initialized FlextLdapOperations instance
            ldif: FlextLdif instance (defaults to get_instance())
            **kwargs: Additional kwargs for FlextService base

        """
        super().__init__(**kwargs)
        self._connection = connection
        self._operations = operations
        self._ldif = ldif or FlextLdif.get_instance()
        # Use connection's config if available for consistency
        # Otherwise, super().__init__() already created proper FlextLdapConfig via _get_service_config_type()
        if (
            hasattr(connection, "_config")
            and isinstance(connection._config, FlextLdapConfig)  # noqa: SLF001
        ):
            object.__setattr__(self, "_config", connection._config)  # noqa: SLF001
        self.logger.info(
            "FlextLdap facade initialized",
            connection_ready=True,
            operations_ready=True,
            ldif_available=True,
        )

    def __enter__(self) -> Self:
        """Context manager entry.

        Returns:
            Self for use in 'with' statement

        """
        return self

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc_val: BaseException | None,
        exc_tb: types.TracebackType | None,
    ) -> None:
        """Context manager exit.

        Automatically disconnects when exiting 'with' block.

        Args:
            exc_type: Exception type if exception occurred
            exc_val: Exception value if exception occurred
            exc_tb: Exception traceback if exception occurred

        """
        self.disconnect()

    def connect(
        self,
        connection_config: FlextLdapModels.ConnectionConfig | FlextLdapConfig,
        *,
        auto_retry: bool = False,
        max_retries: int = 3,
        retry_delay: float = 1.0,
        **_kwargs: str | float | bool | None,
    ) -> FlextResult[bool]:
        """Establish LDAP connection with optional auto-retry.

        Args:
            connection_config: Connection configuration (ConnectionConfig or FlextLdapConfig)
            auto_retry: Enable automatic retry on connection failure (default: False)
            max_retries: Maximum number of retry attempts (default: 3)
            retry_delay: Delay between retries in seconds (default: 1.0)

        Returns:
            FlextResult[bool] indicating connection success

        """
        # Convert FlextLdapConfig to ConnectionConfig if needed
        if isinstance(connection_config, FlextLdapConfig):
            connection_config = FlextLdapModels.ConnectionConfig(
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
        """Close LDAP connection."""
        self.logger.debug("Disconnecting from LDAP server")
        self._connection.disconnect()
        self.logger.info("LDAP connection closed")

    @FlextLdapUtilities.Args.validated_with_result
    def search(
        self,
        search_options: FlextLdapModels.SearchOptions,
        server_type: FlextLdifConstants.ServerTypes = FlextLdifConstants.ServerTypes.RFC,
    ) -> FlextResult[FlextLdapModels.SearchResult]:
        """Perform LDAP search operation.

        Args:
            search_options: Search configuration
            server_type: LDAP server type for parsing (default: RFC)

        Returns:
            FlextResult containing SearchResult with Entry models

        """
        return self._operations.search(search_options, server_type)

    @FlextLdapUtilities.Args.validated_with_result
    def add(
        self,
        entry: FlextLdifModels.Entry,
    ) -> FlextResult[FlextLdapModels.OperationResult]:
        """Add LDAP entry.

        Args:
            entry: Entry model to add

        Returns:
            FlextResult containing OperationResult

        """
        return self._operations.add(entry)

    @FlextLdapUtilities.Args.validated_with_result
    def modify(
        self,
        dn: str | DistinguishedNameProtocol,
        changes: FlextLdapTypes.Ldap.ModifyChanges,
    ) -> FlextResult[FlextLdapModels.OperationResult]:
        """Modify LDAP entry.

        Args:
            dn: Distinguished name of entry to modify
            changes: Modification changes in ldap3 format

        Returns:
            FlextResult containing OperationResult

        """
        return self._operations.modify(dn, changes)

    @FlextLdapUtilities.Args.validated_with_result
    def delete(
        self,
        dn: str | DistinguishedNameProtocol,
    ) -> FlextResult[FlextLdapModels.OperationResult]:
        """Delete LDAP entry.

        Args:
            dn: Distinguished name of entry to delete

        Returns:
            FlextResult containing OperationResult

        """
        return self._operations.delete(dn)

    @FlextLdapUtilities.Args.validated_with_result
    def upsert(
        self,
        entry: FlextLdifModels.Entry,
        *,
        retry_on_errors: list[str] | None = None,
        max_retries: int = 1,
    ) -> FlextResult[FlextLdapModels.LdapOperationResult]:
        """Upsert LDAP entry (add if doesn't exist, skip if exists).

        Args:
            entry: Entry model to upsert
            retry_on_errors: List of error patterns to retry on
            max_retries: Maximum number of retry attempts (default: 1)

        Returns:
            FlextResult containing operation result

        """
        return self._operations.upsert(
            entry,
            retry_on_errors=retry_on_errors,
            max_retries=max_retries,
        )

    @FlextLdapUtilities.Args.validated_with_result
    def batch_upsert(
        self,
        entries: list[FlextLdifModels.Entry],
        *,
        progress_callback: FlextLdapModels.Types.LdapProgressCallback | None = None,
        retry_on_errors: list[str] | None = None,
        max_retries: int = 1,
        stop_on_error: bool = False,
    ) -> FlextResult[FlextLdapModels.LdapBatchStats]:
        """Batch upsert multiple LDAP entries.

        Args:
            entries: List of entries to upsert
            progress_callback: Optional callback for progress tracking
            retry_on_errors: Error patterns to retry on
            max_retries: Maximum retries per entry (default: 1)
            stop_on_error: Stop processing on first error (default: False)

        Returns:
            FlextResult containing batch statistics

        """
        return self._operations.batch_upsert(
            entries,
            progress_callback=progress_callback,
            retry_on_errors=retry_on_errors,
            max_retries=max_retries,
            stop_on_error=stop_on_error,
        )

    @FlextLdapUtilities.Args.validated_with_result
    def sync_phase_entries(
        self,
        ldif_file_path: Path,
        phase_name: str,
        *,
        config: SyncPhaseConfig | None = None,
    ) -> FlextResult[FlextLdapModels.PhaseSyncResult]:
        """Synchronize entries from LDIF file to LDAP.

        Args:
            ldif_file_path: Path to LDIF file
            phase_name: Name of the phase
            config: Sync configuration (defaults to SyncPhaseConfig())

        Returns:
            FlextResult containing phase sync result

        """
        if config is None:
            config = SyncPhaseConfig()

        start_time = datetime.now(UTC)

        parse_result = self._ldif.parse(ldif_file_path, server_type=config.server_type)
        if parse_result.is_failure:
            return FlextResult[FlextLdapModels.PhaseSyncResult].fail(
                f"Failed to parse LDIF file: {parse_result.error}",
            )

        entries = parse_result.unwrap()
        if not entries:
            return FlextResult[FlextLdapModels.PhaseSyncResult].ok(
                FlextLdapModels.PhaseSyncResult(
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
        single_phase_callback: FlextLdapModels.Types.LdapProgressCallback | None = None
        callback = config.progress_callback
        if callback is not None:
            try:
                sig = inspect.signature(callback)
                param_count = len(sig.parameters)
                if param_count == MULTI_PHASE_CALLBACK_PARAM_COUNT:
                    # Multi-phase callback - wrap to single-phase
                    # Type narrowing: callback accepts 5 parameters (phase, current, total, dn, stats)
                    # Create wrapper that adapts multi-phase signature to single-phase
                    def wrapped_cb(
                        current: int,
                        total: int,
                        dn: str,
                        stats: FlextLdapModels.LdapBatchStats,
                    ) -> None:
                        # Call with phase_name as first parameter
                        # Type narrowing: callback is not None at this point
                        if callback is not None:
                            _ = callback(phase_name, current, total, dn, stats)  # type: ignore[call-arg,arg-type]  # pyright: ignore[reportCallIssue]

                    single_phase_callback = wrapped_cb
                else:
                    # Single-phase callback - use directly
                    # Type narrowing: callback accepts 4 parameters (current, total, dn, stats)
                    # Cast to LdapProgressCallback since we verified it has 4 parameters
                    single_phase_callback = callback  # type: ignore[assignment]  # pyright: ignore[reportAssignmentType]
            except (TypeError, ValueError, AttributeError):
                # Fallback: assume single-phase
                single_phase_callback = callback  # type: ignore[assignment]  # pyright: ignore[reportAssignmentType]

        batch_result = self.batch_upsert(
            entries,
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
            return FlextResult[FlextLdapModels.PhaseSyncResult].fail(
                f"Batch sync failed: {batch_result.error}",
            )

        batch_stats = batch_result.unwrap()
        duration = (datetime.now(UTC) - start_time).total_seconds()

        total_processed = batch_stats.synced + batch_stats.failed + batch_stats.skipped
        success_rate = (
            (batch_stats.synced + batch_stats.skipped) / total_processed * 100
            if total_processed > 0
            else 0.0
        )

        return FlextResult[FlextLdapModels.PhaseSyncResult].ok(
            FlextLdapModels.PhaseSyncResult(
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
        config: SyncPhaseConfig,
    ) -> FlextLdapModels.Types.LdapProgressCallback | None:
        """Create progress callback for a phase, handling both single and multi-phase signatures."""
        if config.progress_callback is None:
            return None

        # Check if callback accepts phase name (multi-phase) or just batch stats (single-phase)
        callback = config.progress_callback
        # Type narrowing: callback is guaranteed to be not None after the check above

        def progress_cb(
            current: int,
            total: int,
            dn: str,
            stats: FlextLdapModels.LdapBatchStats,
        ) -> None:
            # callback is captured from outer scope, guaranteed to be not None
            try:
                sig = inspect.signature(callback)
                param_count = len(sig.parameters)
                multi_phase_param_count = MULTI_PHASE_CALLBACK_PARAM_COUNT
                if param_count == multi_phase_param_count:
                    # Multi-phase callback: (phase: str, current: int, total: int, dn: str, stats: LdapBatchStats)
                    # Type narrowing: callback accepts 5 parameters
                    # Call with phase as first parameter
                    _ = callback(phase, current, total, dn, stats)  # type: ignore[arg-type,call-arg]  # pyright: ignore[reportCallIssue]
                else:
                    # Single-phase callback: (current: int, total: int, dn: str, stats: LdapBatchStats)
                    # Type narrowing: callback accepts 4 parameters
                    _ = callback(current, total, dn, stats)  # type: ignore[arg-type,call-arg]  # pyright: ignore[reportCallIssue]
            except (TypeError, ValueError, AttributeError):
                # Fallback: try single-phase signature
                # Type narrowing: callback may have different signature, runtime handles it
                _ = callback(current, total, dn, stats)  # type: ignore[arg-type,call-arg]  # pyright: ignore[reportCallIssue]

        return progress_cb

    def sync_multiple_phases(
        self,
        phase_files: dict[str, Path],
        *,
        config: SyncPhaseConfig | None = None,
    ) -> FlextResult[FlextLdapModels.MultiPhaseSyncResult]:
        """Synchronize multiple LDIF phase files.

        Args:
            phase_files: Dict mapping phase names to LDIF file paths
            config: Sync configuration (defaults to SyncPhaseConfig())

        Returns:
            FlextResult containing multi-phase sync result

        """
        if config is None:
            config = SyncPhaseConfig()

        start_time = datetime.now(UTC)
        phase_results: dict[str, FlextLdapModels.PhaseSyncResult] = {}
        overall_success = True

        for phase_name, ldif_path in phase_files.items():
            if not ldif_path.exists():
                self.logger.warning(
                    "Phase file not found",
                    phase=phase_name,
                    file=str(ldif_path),
                )
                continue

            phase_progress_cb = FlextLdap._make_phase_progress_callback(
                phase_name, config,
            )
            # Use phase_progress_cb if available, otherwise fall back to original callback
            # Type narrowing: both are compatible callback types
            final_callback: (
                Callable[[str, int, int, str, FlextLdapModels.LdapBatchStats], None]
                | FlextLdapModels.Types.LdapProgressCallback
                | None
            ) = (
                phase_progress_cb
                if phase_progress_cb is not None
                else config.progress_callback
            )
            phase_config = SyncPhaseConfig(
                server_type=config.server_type,
                progress_callback=final_callback,
                retry_on_errors=config.retry_on_errors,
                max_retries=config.max_retries,
                stop_on_error=config.stop_on_error,
            )
            phase_result = self.sync_phase_entries(
                ldif_path,
                phase_name,
                config=phase_config,
            )

            if phase_result.is_failure:
                self.logger.error(
                    "Phase sync failed",
                    phase=phase_name,
                    error=str(phase_result.error),
                )
                overall_success = False
                if config.stop_on_error:
                    break
                continue

            phase_results[phase_name] = phase_result.unwrap()

        total_entries = sum(r.total_entries for r in phase_results.values())
        total_synced = sum(r.synced for r in phase_results.values())
        total_failed = sum(r.failed for r in phase_results.values())
        total_skipped = sum(r.skipped for r in phase_results.values())

        total_processed = total_synced + total_failed + total_skipped
        overall_success_rate = (
            (total_synced + total_skipped) / total_processed * 100
            if total_processed > 0
            else 0.0
        )

        return FlextResult[FlextLdapModels.MultiPhaseSyncResult].ok(
            FlextLdapModels.MultiPhaseSyncResult(
                phase_results=phase_results,
                total_entries=total_entries,
                total_synced=total_synced,
                total_failed=total_failed,
                total_skipped=total_skipped,
                overall_success_rate=overall_success_rate,
                total_duration_seconds=(datetime.now(UTC) - start_time).total_seconds(),
                overall_success=overall_success,
            ),
        )

    @override
    def execute(
        self,
        **_kwargs: str | float | bool | None,
    ) -> FlextResult[FlextLdapModels.SearchResult]:
        """Execute service health check.

        Returns:
            FlextResult containing service status

        """
        return self._operations.execute()

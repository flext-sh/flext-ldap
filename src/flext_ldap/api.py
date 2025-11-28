"""FLEXT-LDAP API - Unified Facade for LDAP Operations.

This module provides the primary entry point for all LDAP operations.
The FlextLdap class serves as the sole facade for the FLEXT LDAP library,
coordinating connection management and LDAP operations.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT

"""

from __future__ import annotations

import types
from collections.abc import Callable
from datetime import UTC, datetime
from pathlib import Path
from typing import ClassVar, Self, TypeVar, cast, override

from flext_core import (
    FlextContainer,
    FlextDispatcher,
    FlextRegistry,
    FlextResult,
)
from flext_ldif import FlextLdif, FlextLdifModels
from flext_ldif.constants import FlextLdifConstants
from pydantic import ConfigDict, PrivateAttr

from flext_ldap.base import FlextLdapServiceBase
from flext_ldap.config import FlextLdapConfig
from flext_ldap.constants import FlextLdapConstants
from flext_ldap.models import FlextLdapModels
from flext_ldap.protocols import FlextLdapProtocols
from flext_ldap.services.connection import FlextLdapConnection
from flext_ldap.services.operations import FlextLdapOperations
from flext_ldap.typings import FlextLdapTypes

TResult = TypeVar("TResult")


class FlextLdap(FlextLdapServiceBase[FlextLdapModels.SearchResult]):
    """Main API facade for LDAP operations (connect, search, add, modify, delete)."""

    model_config = ConfigDict(extra="allow")

    _connection: FlextLdapConnection = PrivateAttr()
    _operations: FlextLdapOperations = PrivateAttr()
    _config: FlextLdapConfig = PrivateAttr()
    _ldif: FlextLdif = PrivateAttr()
    _dispatcher: FlextDispatcher = PrivateAttr()
    _registry: FlextRegistry = PrivateAttr()
    _context: dict[
        str,
        str
        | int
        | float
        | bool
        | list[str]
        | dict[str, str | int | float | bool | list[str]]
        | None,
    ] = PrivateAttr(default_factory=dict)
    _handlers: dict[
        str,
        Callable[
            ...,
            FlextResult[FlextLdapModels.SearchResult | FlextLdapModels.OperationResult],
        ],
    ] = PrivateAttr(default_factory=dict)
    _instance: ClassVar[FlextLdap | None] = None
    _pending_config: ClassVar[FlextLdapConfig | None] = None
    _pending_ldif: ClassVar[FlextLdif | None] = None

    @classmethod
    def get_instance(
        cls, config: FlextLdapConfig | None = None, ldif: FlextLdif | None = None
    ) -> FlextLdap:
        """Get singleton instance of FlextLdap facade."""
        if cls._instance is None:
            cls._instance = cls(config=config, ldif=ldif)
        return cls._instance

    @classmethod
    def _reset_instance(cls) -> None:
        """Reset singleton instance (testing only)."""
        cls._instance = None

    def __init__(
        self,
        config: FlextLdapConfig | None = None,
        ldif: FlextLdif | None = None,
        **kwargs: str | float | bool | None,
    ) -> None:
        """Initialize LDAP facade entry point."""
        FlextLdap._pending_config = config
        FlextLdap._pending_ldif = ldif
        _ = kwargs.pop("config", None)
        _ = kwargs.pop("ldif", None)
        super().__init__(**kwargs)
        FlextLdap._pending_config = None
        FlextLdap._pending_ldif = None

    def model_post_init(
        self, _context: dict[str, str | int | float | bool | None] | None, /
    ) -> None:
        """Initialize private attributes after Pydantic initialization."""
        dispatcher = FlextDispatcher()
        self._dispatcher = dispatcher
        self._registry = FlextRegistry(dispatcher=dispatcher)
        init_config = FlextLdap._pending_config
        init_ldif = FlextLdap._pending_ldif
        ldap_config = self.config.get_namespace("ldap", FlextLdapConfig)
        self._config = init_config if init_config is not None else ldap_config
        self._ldif = init_ldif if init_ldif is not None else FlextLdif.get_instance()
        self._context = {}
        self._handlers = {}
        self._connection = FlextLdapConnection(
            config=self._config,
            parser=self._ldif.parser,
        )
        self._operations = FlextLdapOperations(
            connection=cast("FlextLdapProtocols.LdapConnection", self._connection)
        )
        self._setup_services()
        self.logger.info(
            "FlextLdap facade initialized",
            config_available=True,
            ldif_available=True,
            connection_ready=True,
            operations_ready=True,
        )
        self.logger.debug(
            "Services setup completed",
            services_registered=["connection", "operations", "parser"],
        )

    # =========================================================================
    # PRIVATE: Service Setup
    # =========================================================================

    def _setup_services(self) -> None:
        """Register all services using FlextContainer patterns with metadata."""
        container = self.container

        # Execute service registration with error handling
        try:
            self._register_core_services(container)
        except Exception as e:
            self.logger.exception(
                "Failed to setup services - critical initialization error",
                exception=e,
            )
            raise

    def _register_core_services(self, container: FlextContainer) -> None:
        """Register core infrastructure services using generalized helper."""
        services = [
            ("connection", self._connection),
            ("operations", self._operations),
            ("parser", self._ldif.parser),
        ]
        for service_name, service_instance in services:
            if not container.has_service(service_name):
                result = container.register(service_name, service_instance)
                if result.is_failure:
                    error_msg = (
                        f"Failed to register {service_name} service: {result.error}"
                    )
                    self.logger.error(error_msg, critical=True)
                    raise RuntimeError(error_msg)
                self.logger.debug("Registered %s service in container", service_name)

    def connect(
        self,
        connection_config: FlextLdapModels.ConnectionConfig,
        *,
        auto_retry: bool = False,
        max_retries: int = 3,
        retry_delay: float = 1.0,
        **_kwargs: str | float | bool | None,
    ) -> FlextResult[bool]:
        """Establish LDAP connection with optional auto-retry.

        Args:
            connection_config: Connection configuration (required, no fallback)
            auto_retry: Enable automatic retry on connection failure (default: False)
            max_retries: Maximum number of retry attempts (default: 3)
            retry_delay: Delay between retries in seconds (default: 1.0)

        Returns:
            FlextResult[bool] indicating connection success

        """
        self.logger.debug(
            "Connecting to LDAP server",
            operation=FlextLdapConstants.LdapOperationNames.CONNECT.value,
            host=connection_config.host,
            port=connection_config.port,
            use_ssl=connection_config.use_ssl,
            use_tls=connection_config.use_tls,
            auto_retry=auto_retry,
            max_retries=max_retries,
            retry_delay=retry_delay,
            bind_dn=connection_config.bind_dn[:50]
            if connection_config.bind_dn
            else None,
            has_password=connection_config.bind_password is not None,
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
                operation=FlextLdapConstants.LdapOperationNames.CONNECT.value,
                host=connection_config.host,
                port=connection_config.port,
            )
        else:
            self.logger.error(
                "LDAP connection failed",
                operation=FlextLdapConstants.LdapOperationNames.CONNECT.value,
                host=connection_config.host,
                port=connection_config.port,
                error=str(result.error),
            )

        return result

    def disconnect(self) -> None:
        """Close LDAP connection."""
        self.logger.debug(
            "Disconnecting from LDAP server",
            operation=FlextLdapConstants.LdapOperationNames.DISCONNECT.value,
            was_connected=self._connection.is_connected,
        )

        self._connection.disconnect()

        self.logger.info(
            "LDAP connection closed",
            operation=FlextLdapConstants.LdapOperationNames.DISCONNECT.value,
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

    def search(
        self,
        search_options: FlextLdapModels.SearchOptions,
        server_type: FlextLdapConstants.ServerTypes
        | str = FlextLdapConstants.ServerTypes.RFC,
        **_kwargs: str | float | bool | None,
    ) -> FlextResult[FlextLdapModels.SearchResult]:
        """Perform LDAP search operation.

        Args:
            search_options: Search configuration
            server_type: LDAP server type for parsing (default: RFC constant)

        Returns:
            FlextResult containing SearchResult with Entry models

        """
        return self._operations.search(search_options, server_type)

    def add(
        self,
        entry: FlextLdifModels.Entry,
        **_kwargs: str | float | bool | None,
    ) -> FlextResult[FlextLdapModels.OperationResult]:
        """Add LDAP entry.

        Args:
            entry: Entry model to add

        Returns:
            FlextResult containing OperationResult

        """
        return self._operations.add(entry)

    def modify(
        self,
        dn: str | FlextLdifModels.DistinguishedName,
        changes: FlextLdapTypes.LdapModifyChanges,
        **_kwargs: str | float | bool | None,
    ) -> FlextResult[FlextLdapModels.OperationResult]:
        """Modify LDAP entry.

        Args:
            dn: Distinguished name of entry to modify
            changes: Modification changes in ldap3 format

        Returns:
            FlextResult containing OperationResult

        """
        return self._operations.modify(dn, changes)

    def delete(
        self,
        dn: str | FlextLdifModels.DistinguishedName,
        **_kwargs: str | float | bool | None,
    ) -> FlextResult[FlextLdapModels.OperationResult]:
        """Delete LDAP entry.

        Args:
            dn: Distinguished name of entry to delete

        Returns:
            FlextResult containing OperationResult

        """
        return self._operations.delete(dn)

    def upsert(
        self,
        entry: FlextLdifModels.Entry,
        *,
        retry_on_errors: list[str] | None = None,
        max_retries: int = 1,
    ) -> FlextResult[FlextLdapModels.LdapOperationResult]:
        """Upsert LDAP entry (add if doesn't exist, skip if exists) with optional retry.

        Generic method that handles both regular entries and schema modifications.
        For regular entries: tries add, returns "added" or "skipped" if already exists.
        For schema entries (changetype=modify): applies modify operation.

        Args:
            entry: Entry model to upsert
            retry_on_errors: List of error patterns to retry on
                (default: None = no retry)
            max_retries: Maximum number of retry attempts (default: 1)

        Returns:
            FlextResult containing dict with "operation" key:
                - "added": Entry was added
                - "modified": Entry was modified (for schema)
                - "skipped": Entry already exists

        """
        return self._operations.upsert(
            entry, retry_on_errors=retry_on_errors, max_retries=max_retries
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
        """Batch upsert multiple LDAP entries with progress tracking and retry.

        Processes entries sequentially, applying retry logic per-entry if configured.
        Aggregates results into synced/failed/skipped counters.

        Args:
            entries: List of entries to upsert
            progress_callback: Optional callback(idx: int, total: int,
                dn: str, stats: FlextLdapTypes.LdapBatchStats)
                after each entry
            retry_on_errors: Error patterns to retry on (passed to each upsert)
            max_retries: Maximum retries per entry (default: 1)
            stop_on_error: Stop processing on first error (default: False)

        Returns:
            FlextResult with dict containing:
                - "synced": Number of entries successfully added/modified
                - "failed": Number of entries that failed
                - "skipped": Number of entries skipped (already identical)

        """
        return self._operations.batch_upsert(
            entries,
            progress_callback=progress_callback,
            retry_on_errors=retry_on_errors,
            max_retries=max_retries,
            stop_on_error=stop_on_error,
        )

    def sync_phase_entries(
        self,
        ldif_file_path: Path,
        phase_name: str,
        *,
        server_type: FlextLdifConstants.LiteralTypes.ServerTypeLiteral = "rfc",
        progress_callback: Callable[
            [int, int, str, FlextLdapModels.LdapBatchStats], None
        ]
        | None = None,
        retry_on_errors: list[str] | None = None,
        max_retries: int = 5,
        stop_on_error: bool = False,
    ) -> FlextResult[FlextLdapModels.PhaseSyncResult]:
        """Synchronize all entries from an LDIF file to LDAP with comprehensive reporting.

        Generic method for phase-based LDIF synchronization that parses the file,
        performs batch upsert operations, and provides detailed statistics.

        Args:
            ldif_file_path: Path to LDIF file containing entries to sync
            phase_name: Name of the phase (for logging and reporting)
            server_type: Server type for LDIF parsing (default: "rfc")
            progress_callback: Optional callback(current, total, dn, stats) for progress tracking
            retry_on_errors: List of error patterns to retry on
            max_retries: Maximum retry attempts per entry
            stop_on_error: Whether to stop processing on first error

        Returns:
            FlextResult containing PhaseSyncResult with:
            - phase_name: Name of the phase
            - total_entries: Total entries in LDIF file
            - synced: Number of entries successfully synced
            - failed: Number of entries that failed to sync
            - skipped: Number of entries skipped (already exist)
            - duration_seconds: Time taken for sync operation
            - success_rate: Percentage of successful operations

        """
        start_time = datetime.now(UTC)

        # Parse LDIF file using integrated FlextLdif
        parse_result = self._ldif.parse(ldif_file_path, server_type=server_type)
        if parse_result.is_failure:
            return FlextResult[FlextLdapModels.PhaseSyncResult].fail(
                f"Failed to parse LDIF file {ldif_file_path}: {parse_result.error}"
            )

        entries = parse_result.unwrap()
        total_entries = len(entries)

        if total_entries == 0:
            return FlextResult[FlextLdapModels.PhaseSyncResult].ok(
                FlextLdapModels.PhaseSyncResult(
                    phase_name=phase_name,
                    total_entries=0,
                    synced=0,
                    failed=0,
                    skipped=0,
                    duration_seconds=0.0,
                    success_rate=100.0,
                )
            )

        # Perform batch upsert
        batch_result = self.batch_upsert(
            entries,
            progress_callback=progress_callback,
            retry_on_errors=retry_on_errors
            or [
                "session terminated",
                "not connected",
                "invalid messageid",
                "socket",
            ],
            max_retries=max_retries,
            stop_on_error=stop_on_error,
        )

        if batch_result.is_failure:
            return FlextResult[FlextLdapModels.PhaseSyncResult].fail(
                f"Batch sync failed for phase {phase_name}: {batch_result.error}"
            )

        batch_stats = batch_result.unwrap()
        duration = (datetime.now(UTC) - start_time).total_seconds()

        synced = batch_stats.synced
        failed = batch_stats.failed
        skipped = batch_stats.skipped

        total_processed = synced + failed + skipped
        success_rate = (
            (synced + skipped) / total_processed * 100 if total_processed > 0 else 0.0
        )

        return FlextResult[FlextLdapModels.PhaseSyncResult].ok(
            FlextLdapModels.PhaseSyncResult(
                phase_name=phase_name,
                total_entries=total_entries,
                synced=synced,
                failed=failed,
                skipped=skipped,
                duration_seconds=duration,
                success_rate=success_rate,
            )
        )

    def sync_multiple_phases(
        self,
        phase_files: dict[str, Path],
        *,
        server_type: FlextLdifConstants.LiteralTypes.ServerTypeLiteral = "rfc",
        progress_callback: Callable[
            [str, int, int, str, FlextLdapModels.LdapBatchStats], None
        ]
        | None = None,
        retry_on_errors: list[str] | None = None,
        max_retries: int = 5,
        stop_on_error: bool = False,
    ) -> FlextResult[FlextLdapModels.MultiPhaseSyncResult]:
        """Synchronize multiple LDIF phase files with aggregated reporting.

        Generic method for multi-phase synchronization that processes each phase file
        and aggregates results across all phases.

        Args:
            phase_files: Dict mapping phase names to LDIF file paths
            server_type: Server type for LDIF parsing (default: "rfc")
            progress_callback: Optional callback(phase_name, current, total, dn, stats)
            retry_on_errors: List of error patterns to retry on
            max_retries: Maximum retry attempts per entry
            stop_on_error: Whether to stop processing on first error

        Returns:
            FlextResult containing MultiPhaseSyncResult with:
            - phase_results: Dict of phase_name -> PhaseSyncResult
            - total_entries: Sum of all entries across phases
            - total_synced: Sum of synced entries across phases
            - total_failed: Sum of failed entries across phases
            - total_skipped: Sum of skipped entries across phases
            - overall_success_rate: Weighted average success rate

        """
        start_time = datetime.now(UTC)
        phase_results: dict[str, FlextLdapModels.PhaseSyncResult] = {}
        overall_success = True

        # Enhanced progress callback to include phase name
        def enhanced_progress_callback(
            phase_name: str,
            current: int,
            total: int,
            dn: str,
            stats: FlextLdapModels.LdapBatchStats,
        ) -> None:
            if progress_callback:
                progress_callback(phase_name, current, total, dn, stats)

        for phase_name, ldif_path in phase_files.items():
            if not ldif_path.exists():
                self.logger.warning(
                    "Phase file not found, skipping",
                    phase=phase_name,
                    file=str(ldif_path),
                )
                continue

            # Create phase-specific progress callback with captured phase_name
            def make_phase_progress(
                phase: str,
            ) -> Callable[[int, int, str, FlextLdapModels.LdapBatchStats], None]:
                def progress_cb(
                    current: int,
                    total: int,
                    dn: str,
                    stats: FlextLdapModels.LdapBatchStats,
                ) -> None:
                    enhanced_progress_callback(phase, current, total, dn, stats)

                return progress_cb

            phase_progress = make_phase_progress(phase_name)

            phase_result = self.sync_phase_entries(
                ldif_path,
                phase_name,
                server_type=server_type,
                progress_callback=phase_progress,
                retry_on_errors=retry_on_errors,
                max_retries=max_retries,
                stop_on_error=stop_on_error,
            )

            if phase_result.is_failure:
                self.logger.error(
                    "Phase sync failed",
                    phase=phase_name,
                    error=str(phase_result.error),
                )
                overall_success = False
                if stop_on_error:
                    break
                continue

            phase_results[phase_name] = phase_result.unwrap()

        # Calculate aggregated statistics
        total_entries = sum(result.total_entries for result in phase_results.values())
        total_synced = sum(result.synced for result in phase_results.values())
        total_failed = sum(result.failed for result in phase_results.values())
        total_skipped = sum(result.skipped for result in phase_results.values())

        total_processed = total_synced + total_failed + total_skipped
        overall_success_rate = (
            (total_synced + total_skipped) / total_processed * 100
            if total_processed > 0
            else 0.0
        )

        total_duration = (datetime.now(UTC) - start_time).total_seconds()

        return FlextResult[FlextLdapModels.MultiPhaseSyncResult].ok(
            FlextLdapModels.MultiPhaseSyncResult(
                phase_results=phase_results,
                total_entries=total_entries,
                total_synced=total_synced,
                total_failed=total_failed,
                total_skipped=total_skipped,
                overall_success_rate=overall_success_rate,
                total_duration_seconds=total_duration,
                overall_success=overall_success,
            )
        )

    @override
    def execute(
        self, **_kwargs: str | float | bool | None
    ) -> FlextResult[FlextLdapModels.SearchResult]:
        """Execute service health check.

        Returns:
            FlextResult containing service status

        """
        # Fast fail - delegate to operations, no fallback
        return self._operations.execute()


# Forward references are resolved automatically by Pydantic v2 with 'from __future__ import annotations'
# No manual model_rebuild() needed when using proper string annotations

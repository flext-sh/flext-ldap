"""LDIF to LDAP synchronization service.

This service provides direct LDIF to LDAP synchronization without any
attribute or DN conversions. Works with any LDAP-compatible server.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT

"""

from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path

from flext_core import FlextLogger, FlextResult, FlextService
from flext_ldif import FlextLdif
from flext_ldif.models import FlextLdifModels

from flext_ldap.constants import FlextLdapConstants
from flext_ldap.models import FlextLdapModels
from flext_ldap.services.operations import FlextLdapOperations


class FlextLdapSyncService(FlextService[FlextLdapModels.SyncStats]):
    """LDIF to LDAP synchronization service.

    Provides direct synchronization of LDIF files to LDAP directory without
    any attribute or DN conversions. Works with any LDAP-compatible server.

    Features:
        - Direct parsing without quirks/conversions (server_type uses RFC constant)
        - Batch processing for efficiency
        - Progress callbacks support
        - Automatic parent DN creation
        - Comprehensive statistics

    Example:
        # Initialize service
        ldap = FlextLdap()
        result = ldap.connect(config)
        if result.is_success:
            sync_service = FlextLdapSyncService(operations=ldap.client)
            sync_result = sync_service.sync_ldif_file(
                ldif_file=Path("data/output/01-hierarchy.ldif"),
                options=FlextLdapModels.SyncOptions(batch_size=50),
            )

    """

    _operations: FlextLdapOperations
    _ldif: FlextLdif
    _logger: FlextLogger

    def __init__(
        self,
        operations: FlextLdapOperations,
    ) -> None:
        """Initialize sync service.

        Args:
            operations: FlextLdapOperations instance for LDAP operations

        """
        super().__init__()
        self._operations = operations
        self._ldif = FlextLdif.get_instance()
        self._logger = FlextLogger(__name__)

    def sync_ldif_file(
        self,
        ldif_file: Path,
        options: FlextLdapModels.SyncOptions,
    ) -> FlextResult[FlextLdapModels.SyncStats]:
        """Sync LDIF file to LDAP directory.

        Parses LDIF file directly without any conversions
        (server_type uses RFC constant) and adds entries to LDAP directory
        using FlextLdapOperations.

        Args:
            ldif_file: Path to LDIF file to sync
            options: Sync configuration (required, no fallback)

        Returns:
            FlextResult containing SyncStats with synchronization statistics

        """
        # SyncOptions is required, no fallback - use directly
        start_time = datetime.now(UTC)

        # Check if file exists
        if not ldif_file.exists():
            return FlextResult[FlextLdapModels.SyncStats].fail(
                f"LDIF file not found: {ldif_file}",
            )

        # Check if operations service is connected
        if not self._operations.is_connected:
            return FlextResult[FlextLdapModels.SyncStats].fail(
                "Not connected to LDAP server",
            )

        # Parse LDIF directly without quirks (server_type=RFC = no conversions)
        _ = self._logger.debug(
            "Parsing LDIF file: %s",
            ldif_file,
        )

        # Monadic pattern - chain operations
        parse_result = self._ldif.parse(
            source=ldif_file,
            server_type=FlextLdapConstants.ServerTypes.RFC,
        )
        if parse_result.is_failure:
            return FlextResult[FlextLdapModels.SyncStats].fail(
                f"Failed to parse LDIF file: {parse_result.error}",
            )
        return self._process_entries(parse_result.unwrap(), options, start_time)

    def _process_entries(
        self,
        entries: list[FlextLdifModels.Entry],
        options: FlextLdapModels.SyncOptions,
        start_time: datetime,
    ) -> FlextResult[FlextLdapModels.SyncStats]:
        """Process entries through sync pipeline.

        Args:
            entries: List of entries to process
            options: Sync options
            start_time: Start time for duration calculation

        Returns:
            FlextResult containing SyncStats

        """
        # Fast fail - empty entries return empty stats
        if not entries:
            _ = self._logger.warning("No entries found in LDIF file")
            return FlextResult[FlextLdapModels.SyncStats].ok(
                FlextLdapModels.SyncStats(
                    added=0,
                    skipped=0,
                    failed=0,
                    total=0,
                    duration_seconds=0.0,
                ),
            )

        # Transform BaseDN if configured (both must be non-empty strings)
        if options.source_basedn.strip() and options.target_basedn.strip():
            _ = self._logger.debug(
                "Transforming BaseDN: %s → %s",
                options.source_basedn,
                options.target_basedn,
            )
            entries = self._transform_entries_basedn(
                entries,
                options.source_basedn,
                options.target_basedn,
            )

        # Process entries in batch
        _ = self._logger.info(
            f"Syncing {len(entries)} entries",
            extra={"batch_size": options.batch_size},
        )

        # Monadic pattern - chain sync batch and update duration
        return (
            self._sync_batch(entries, options)
            .map(
                lambda stats: FlextLdapModels.SyncStats(
                    added=stats.added,
                    skipped=stats.skipped,
                    failed=stats.failed,
                    total=stats.total,
                    duration_seconds=(datetime.now(UTC) - start_time).total_seconds(),
                ),
            )
            .map(
                lambda final_stats: (
                    self._logger.info(
                        "Sync completed",
                        extra={
                            "added": final_stats.added,
                            "skipped": final_stats.skipped,
                            "failed": final_stats.failed,
                            "duration_s": final_stats.duration_seconds,
                        },
                    ),
                    final_stats,
                )[1],
            )
        )

    def _sync_batch(
        self,
        entries: list[FlextLdifModels.Entry],
        options: FlextLdapModels.SyncOptions,
    ) -> FlextResult[FlextLdapModels.SyncStats]:
        """Sync entries in batch mode.

        Processes entries using FlextLdapOperations.add() for each entry.
        Handles duplicate entries gracefully (skips if already exists).

        Args:
            entries: List of Entry models to sync
            options: Sync configuration options

        Returns:
            FlextResult containing SyncStats

        """
        total_added = 0
        total_skipped = 0
        total_failed = 0

        for idx, entry in enumerate(entries, 1):
            # Add entry using operations service
            add_result = self._operations.add(entry)

            entry_stats: dict[str, int] = {"added": 0, "skipped": 0, "failed": 0}

            if add_result.is_success:
                total_added += 1
                entry_stats["added"] = 1
            else:
                # FlextResult contract guarantees error exists when is_failure is True
                # Type narrowing: assert for type checker
                assert add_result.error is not None, (
                    "FlextResult contract guarantees error when is_failure"
                )  # noqa: S101
                error_message = add_result.error
                error_lower = error_message.lower()
                if (
                    "already exists" in error_lower
                    or "entryalreadyexists" in error_lower
                ):
                    total_skipped += 1
                    entry_stats["skipped"] = 1
                else:
                    total_failed += 1
                    entry_stats["failed"] = 1
                    _ = self._logger.warning(
                        "Failed to add entry: %s",
                        error_message,
                        extra={"dn": str(entry.dn)},
                    )

            # Call progress callback if provided
            if options.progress_callback:
                dn_str = str(entry.dn)
                options.progress_callback(idx, len(entries), dn_str, entry_stats)

        return FlextResult[FlextLdapModels.SyncStats].ok(
            FlextLdapModels.SyncStats(
                added=total_added,
                skipped=total_skipped,
                failed=total_failed,
                total=len(entries),
                duration_seconds=0.0,  # Set by caller
            ),
        )

    def _transform_entries_basedn(
        self,
        entries: list[FlextLdifModels.Entry],
        source_basedn: str,
        target_basedn: str,
    ) -> list[FlextLdifModels.Entry]:
        """Transform BaseDN in entry DNs.

        Args:
            entries: List of Entry models
            source_basedn: Source BaseDN to replace
            target_basedn: Target BaseDN to use

        Returns:
            List of entries with transformed DNs

        """
        if source_basedn == target_basedn:
            return entries

        transformed = []
        for entry in entries:
            # Entry.dn is validated by Pydantic model - guaranteed to exist and non-empty
            # Pydantic validation ensures DN is never empty
            dn_str = str(entry.dn)

            # Replace source BaseDN with target BaseDN
            if source_basedn.lower() in dn_str.lower():
                new_dn_str = dn_str.replace(source_basedn, target_basedn)
                # Create new entry with updated DN using model_copy
                new_entry = entry.model_copy(
                    update={"dn": FlextLdifModels.DistinguishedName(value=new_dn_str)},
                )
                transformed.append(new_entry)
            else:
                transformed.append(entry)

        return transformed

    def execute(self) -> FlextResult[FlextLdapModels.SyncStats]:
        """Execute service health check.

        Returns:
            FlextResult containing empty SyncStats

        """
        return FlextResult[FlextLdapModels.SyncStats].ok(
            FlextLdapModels.SyncStats(
                added=0,
                skipped=0,
                failed=0,
                total=0,
                duration_seconds=0.0,
            ),
        )

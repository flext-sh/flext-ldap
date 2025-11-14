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

from flext_ldap.models import FlextLdapModels
from flext_ldap.services.operations import FlextLdapOperations


class FlextLdapSyncService(FlextService[FlextLdapModels.SyncStats]):
    """LDIF to LDAP synchronization service.

    Provides direct synchronization of LDIF files to LDAP directory without
    any attribute or DN conversions. Works with any LDAP-compatible server.

    Features:
        - Direct parsing without quirks/conversions (server_type="rfc")
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
        options: FlextLdapModels.SyncOptions | None = None,
    ) -> FlextResult[FlextLdapModels.SyncStats]:
        """Sync LDIF file to LDAP directory.

        Parses LDIF file directly without any conversions (server_type="rfc")
        and adds entries to LDAP directory using FlextLdapOperations.

        Args:
            ldif_file: Path to LDIF file to sync
            options: Optional sync configuration

        Returns:
            FlextResult containing SyncStats with synchronization statistics

        """
        opts = options or FlextLdapModels.SyncOptions()
        start_time = datetime.now(UTC)

        # Check if file exists
        if not ldif_file.exists():
            return FlextResult[FlextLdapModels.SyncStats].fail(
                f"LDIF file not found: {ldif_file}"
            )

        # Check if operations service is connected
        if not self._operations.is_connected:
            return FlextResult[FlextLdapModels.SyncStats].fail(
                "Not connected to LDAP server"
            )

        # Parse LDIF directly without quirks (server_type="rfc" = no conversions)
        _ = self._logger.debug(f"Parsing LDIF file: {ldif_file}")
        parse_result = self._ldif.parse(
            source=ldif_file,
            server_type="rfc",  # Direct parsing, no quirks/conversions
        )

        if parse_result.is_failure:
            return FlextResult[FlextLdapModels.SyncStats].fail(
                f"Failed to parse LDIF file: {parse_result.error}"
            )

        entries = parse_result.unwrap()
        if not entries:
            _ = self._logger.warning(f"No entries found in {ldif_file}")
            return FlextResult[FlextLdapModels.SyncStats].ok(
                FlextLdapModels.SyncStats(
                    added=0,
                    skipped=0,
                    failed=0,
                    total=0,
                    duration_seconds=0.0,
                )
            )

        # Transform BaseDN if configured
        if opts.source_basedn and opts.target_basedn:
            _ = self._logger.debug(
                f"Transforming BaseDN: {opts.source_basedn} → {opts.target_basedn}"
            )
            entries = self._transform_entries_basedn(
                entries, opts.source_basedn, opts.target_basedn
            )

        # Process entries in batch
        _ = self._logger.info(
            f"Syncing {len(entries)} entries",
            extra={"batch_size": opts.batch_size},
        )

        stats_result = self._sync_batch(entries, opts)
        if stats_result.is_failure:
            return stats_result

        stats = stats_result.unwrap()
        duration = (datetime.now(UTC) - start_time).total_seconds()

        # Update duration in stats
        final_stats = FlextLdapModels.SyncStats(
            added=stats.added,
            skipped=stats.skipped,
            failed=stats.failed,
            total=stats.total,
            duration_seconds=duration,
        )

        _ = self._logger.info(
            "Sync completed",
            extra={
                "added": final_stats.added,
                "skipped": final_stats.skipped,
                "failed": final_stats.failed,
                "duration_s": final_stats.duration_seconds,
            },
        )

        return FlextResult[FlextLdapModels.SyncStats].ok(final_stats)

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
                # Check if error is due to entry already existing
                error_msg = add_result.error or ""
                if (
                    "already exists" in error_msg.lower()
                    or "entryAlreadyExists" in error_msg
                ):
                    total_skipped += 1
                    entry_stats["skipped"] = 1
                else:
                    total_failed += 1
                    entry_stats["failed"] = 1
                    _ = self._logger.warning(
                        f"Failed to add entry: {error_msg}",
                        extra={"dn": str(entry.dn) if entry.dn else "unknown"},
                    )

            # Call progress callback if provided
            if options.progress_callback:
                dn_str = str(entry.dn) if entry.dn else "unknown"
                options.progress_callback(idx, len(entries), dn_str, entry_stats)

        return FlextResult[FlextLdapModels.SyncStats].ok(
            FlextLdapModels.SyncStats(
                added=total_added,
                skipped=total_skipped,
                failed=total_failed,
                total=len(entries),
                duration_seconds=0.0,  # Set by caller
            )
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
            if entry.dn:
                dn_str = str(entry.dn.value)
                # Replace source BaseDN with target BaseDN
                if source_basedn.lower() in dn_str.lower():
                    new_dn_str = dn_str.replace(source_basedn, target_basedn)
                    # Create new entry with updated DN
                    new_entry = entry.model_copy(update={"dn": new_dn_str})
                    transformed.append(new_entry)
                else:
                    transformed.append(entry)
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
            )
        )

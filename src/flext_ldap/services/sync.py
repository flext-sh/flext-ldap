"""LDIF to LDAP synchronization service.

This service provides direct LDIF to LDAP synchronization without any attribute
or DN conversions. Works with any LDAP-compatible server. Supports batch processing,
progress callbacks, automatic parent DN creation, and comprehensive statistics.

Modules: FlextLdapSyncService
Scope: LDIF file parsing and synchronization to LDAP, batch operations, statistics
Pattern: Service extending FlextLdapServiceBase, uses FlextLdapOperations for LDAP ops

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from datetime import datetime
from pathlib import Path

from flext_core import FlextResult, FlextUtilities
from flext_ldif import FlextLdif, FlextLdifConfig, FlextLdifModels

from flext_ldap.base import FlextLdapServiceBase
from flext_ldap.constants import FlextLdapConstants
from flext_ldap.models import FlextLdapModels
from flext_ldap.services.operations import FlextLdapOperations


class FlextLdapSyncService(FlextLdapServiceBase[FlextLdapModels.SyncStats]):
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

    def __init__(
        self,
        operations: FlextLdapOperations | None = None,
        **kwargs: object,
    ) -> None:
        """Initialize sync service.

        Args:
            operations: FlextLdapOperations instance for LDAP operations
            **kwargs: Additional keyword arguments passed to parent class

        """
        super().__init__(**kwargs)
        # Extract operations from kwargs if not provided directly
        if operations is None:
            operations_kwarg = kwargs.pop("operations", None)
            if operations_kwarg is not None:
                # Type narrowing: verify operations_kwarg is FlextLdapOperations
                if isinstance(operations_kwarg, FlextLdapOperations):
                    operations = operations_kwarg
                else:
                    msg = f"operations must be FlextLdapOperations, got {type(operations_kwarg).__name__}"
                    raise TypeError(msg)
        if operations is None:
            msg = "operations parameter is required"
            raise TypeError(msg)
        self._operations = operations
        # Create FlextLdif with RFC server type (no quirks/conversions for direct sync)
        # Use model_construct to bypass config_class validation for AutoConfig pattern
        config = FlextLdifConfig.model_construct(
            quirks_server_type=FlextLdapConstants.ServerTypes.RFC,
        )
        self._ldif = FlextLdif(config=config)

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
        self.logger.debug(
            "Starting LDIF file sync",
            operation="sync_ldif_file",
            ldif_file=str(ldif_file),
            batch_size=options.batch_size,
            source_basedn=options.source_basedn[:100]
            if options.source_basedn
            else None,
            target_basedn=options.target_basedn[:100]
            if options.target_basedn
            else None,
        )

        # Get generate_datetime_utc from Generators class
        generators_class = getattr(FlextUtilities, "Generators", None)
        if generators_class is None:  # pragma: no cover
            msg = "FlextUtilities.Generators not found"
            raise AttributeError(msg)  # pragma: no cover
        generate_datetime_utc_method = getattr(
            generators_class, "generate_datetime_utc", None
        )
        if generate_datetime_utc_method is None:  # pragma: no cover
            msg = "FlextUtilities.Generators.generate_datetime_utc not found"
            raise AttributeError(msg)  # pragma: no cover
        start_time = generate_datetime_utc_method()
        # Store method for use in lambda closure
        self._generate_datetime_utc = generate_datetime_utc_method

        if not ldif_file.exists():
            self.logger.error(
                "LDIF file not found",
                operation="sync_ldif_file",
                ldif_file=str(ldif_file),
            )
            return FlextResult[FlextLdapModels.SyncStats].fail(
                f"LDIF file not found: {ldif_file}",
            )

        file_size = ldif_file.stat().st_size if ldif_file.exists() else 0

        self.logger.debug(
            "Parsing LDIF file",
            operation="sync_ldif_file",
            ldif_file=str(ldif_file),
            file_size_bytes=file_size,
            server_type=FlextLdapConstants.ServerTypes.RFC,
        )

        # Monadic pattern - chain operations
        parse_result = self._ldif.parse(
            source=ldif_file,
            server_type=FlextLdapConstants.ServerTypes.RFC,
        )
        if parse_result.is_failure:
            self.logger.error(
                "Failed to parse LDIF file",
                operation="sync_ldif_file",
                ldif_file=str(ldif_file),
                error=str(parse_result.error),
                error_type=type(parse_result.error).__name__
                if parse_result.error
                else "Unknown",
                file_size_bytes=file_size,
                server_type=FlextLdapConstants.ServerTypes.RFC,
            )
            return FlextResult[FlextLdapModels.SyncStats].fail(
                f"Failed to parse LDIF file: {parse_result.error}",
            )

        parsed_entries = parse_result.unwrap()
        self.logger.debug(
            "LDIF file parsed successfully",
            operation="sync_ldif_file",
            ldif_file=str(ldif_file),
            file_size_bytes=file_size,
            parsed_entries_count=len(parsed_entries),
            server_type=FlextLdapConstants.ServerTypes.RFC,
        )

        return self._process_entries(parse_result.unwrap(), options, start_time)

    def _process_entries(
        self,
        entries: list[FlextLdifModels.Entry],
        options: FlextLdapModels.SyncOptions,
        start_time: datetime | None,
    ) -> FlextResult[FlextLdapModels.SyncStats]:
        """Process entries through sync pipeline.

        Args:
            entries: List of entries to process
            options: Sync options
            start_time: Start time for duration calculation

        Returns:
            FlextResult containing SyncStats

        """
        self.logger.debug(
            "Processing entries",
            operation="sync_ldif_file",
            entries_count=len(entries),
            batch_size=options.batch_size,
            source_basedn=options.source_basedn[:100]
            if options.source_basedn
            else None,
            target_basedn=options.target_basedn[:100]
            if options.target_basedn
            else None,
        )

        if not entries:
            self.logger.warning(
                "No entries found in LDIF file",
                operation="sync_ldif_file",
                entries_count=0,
            )
            return FlextResult[FlextLdapModels.SyncStats].ok(
                FlextLdapModels.SyncStats(
                    added=0,
                    skipped=0,
                    failed=0,
                    total=0,
                    duration_seconds=0.0,
                ),
            )

        original_entries_count = len(entries)
        # Validate base DNs are not empty or whitespace-only using FlextUtilities
        # Fast fail: if base DNs are empty, skip transformation
        if options.source_basedn and options.target_basedn:
            # Validate and clean base DNs using FlextUtilities (railway pattern)
            source_basedn_result = FlextUtilities.TextProcessor.safe_string(
                options.source_basedn,
            )
            target_basedn_result = FlextUtilities.TextProcessor.safe_string(
                options.target_basedn,
            )

            # Type narrowing: ensure results are FlextResult[str]
            if (
                isinstance(source_basedn_result, FlextResult)
                and isinstance(target_basedn_result, FlextResult)
                and source_basedn_result.is_success
                and target_basedn_result.is_success
            ):
                source_basedn_clean = source_basedn_result.unwrap()
                target_basedn_clean = target_basedn_result.unwrap()

                # Truncate for logging (max 100 chars)
                max_log_length = 100
                source_basedn_log = (
                    source_basedn_clean[:max_log_length]
                    if len(source_basedn_clean) > max_log_length
                    else source_basedn_clean
                )
                target_basedn_log = (
                    target_basedn_clean[:max_log_length]
                    if len(target_basedn_clean) > max_log_length
                    else target_basedn_clean
                )

                self.logger.debug(
                    "Transforming BaseDN for entries",
                    operation="sync_ldif_file",
                    source_basedn=source_basedn_log,
                    target_basedn=target_basedn_log,
                    entries_count_before=original_entries_count,
                )

                entries = self._transform_entries_basedn(
                    entries,
                    source_basedn_clean,
                    target_basedn_clean,
                )

                self.logger.debug(
                    "BaseDN transformation completed",
                    operation="sync_ldif_file",
                    entries_count_before=original_entries_count,
                    entries_count_after=len(entries),
                    source_basedn=source_basedn_log,
                    target_basedn=target_basedn_log,
                )
            else:  # pragma: no cover
                # If base DNs are invalid, skip transformation
                # Defensive: FlextUtilities.TextProcessor.safe_string always succeeds for strings
                self.logger.debug(  # pragma: no cover
                    "BaseDN transformation skipped - invalid base DNs",
                    operation="sync_ldif_file",
                    source_basedn=options.source_basedn[:100]
                    if options.source_basedn
                    else None,
                    target_basedn=options.target_basedn[:100]
                    if options.target_basedn
                    else None,
                )

        self.logger.info(
            "Starting batch sync of entries",
            operation="sync_ldif_file",
            entries_count=len(entries),
            batch_size=options.batch_size,
        )

        # Get batch result
        batch_result = self._sync_batch(entries, options)
        if batch_result.is_failure:
            return batch_result

        stats = batch_result.unwrap()
        duration_seconds = (self._generate_datetime_utc() - start_time).total_seconds()

        final_stats = FlextLdapModels.SyncStats(
            added=stats.added,
            skipped=stats.skipped,
            failed=stats.failed,
            total=stats.total,
            duration_seconds=duration_seconds,
        )

        self.logger.info(
            "LDIF file sync completed",
            operation="sync_ldif_file",
            added=final_stats.added,
            skipped=final_stats.skipped,
            failed=final_stats.failed,
            total=final_stats.total,
            success_rate=f"{(final_stats.added / final_stats.total * 100):.1f}%"
            if final_stats.total > 0
            else "0%",
            skip_rate=f"{(final_stats.skipped / final_stats.total * 100):.1f}%"
            if final_stats.total > 0
            else "0%",
            failure_rate=f"{(final_stats.failed / final_stats.total * 100):.1f}%"
            if final_stats.total > 0
            else "0%",
            duration_seconds=final_stats.duration_seconds,
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
        self.logger.debug(
            "Starting batch sync",
            operation="sync_ldif_file",
            entries_count=len(entries),
            batch_size=options.batch_size,
        )

        total_added = 0
        total_skipped = 0
        total_failed = 0

        for idx, entry in enumerate(entries, 1):
            entry_dn_str = str(entry.dn) if entry.dn else "unknown"

            add_result = self._operations.add(entry)

            entry_stats: dict[str, int] = {"added": 0, "skipped": 0, "failed": 0}

            if add_result.is_success:
                total_added += 1
                entry_stats["added"] = 1
                self.logger.debug(
                    "Entry added in batch",
                    operation="sync_ldif_file",
                    entry_index=idx,
                    total_entries=len(entries),
                    entry_dn=entry_dn_str[:100] if entry_dn_str else None,
                    added_count=total_added,
                    failed_count=total_failed,
                    skipped_count=total_skipped,
                )
            else:
                error_message = (
                    str(add_result.error) if add_result.error else "Unknown error"
                )
                is_already_exists = FlextLdapOperations.is_already_exists_error(
                    error_message,
                )

                if is_already_exists:
                    total_skipped += 1
                    entry_stats["skipped"] = 1
                    self.logger.debug(
                        "Entry skipped - already exists",
                        operation="sync_ldif_file",
                        entry_index=idx,
                        total_entries=len(entries),
                        entry_dn=entry_dn_str[:100] if entry_dn_str else None,
                        added_count=total_added,
                        failed_count=total_failed,
                        skipped_count=total_skipped,
                    )
                else:
                    total_failed += 1
                    entry_stats["failed"] = 1
                    self.logger.error(
                        "Failed to add entry during batch sync",
                        operation="sync_ldif_file",
                        entry_index=idx,
                        total_entries=len(entries),
                        entry_dn=entry_dn_str[:100] if entry_dn_str else None,
                        error=error_message[:200],
                        error_type=type(add_result.error).__name__
                        if add_result.error
                        else "Unknown",
                        added_count=total_added,
                        failed_count=total_failed,
                        skipped_count=total_skipped,
                    )

            if options.progress_callback:
                dn_str = str(entry.dn) if entry.dn else "unknown"
                options.progress_callback(idx, len(entries), dn_str, entry_stats)

        self.logger.info(
            "Batch sync completed",
            operation="sync_ldif_file",
            total_entries=len(entries),
            added_count=total_added,
            skipped_count=total_skipped,
            failed_count=total_failed,
            success_rate=f"{(total_added / len(entries) * 100):.1f}%"
            if len(entries) > 0
            else "0%",
            skip_rate=f"{(total_skipped / len(entries) * 100):.1f}%"
            if len(entries) > 0
            else "0%",
            failure_rate=f"{(total_failed / len(entries) * 100):.1f}%"
            if len(entries) > 0
            else "0%",
        )

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
        self.logger.debug(
            "Transforming BaseDN",
            operation="sync_ldif_file",
            source_basedn=source_basedn[:100] if source_basedn else None,
            target_basedn=target_basedn[:100] if target_basedn else None,
            entries_count=len(entries),
        )

        if source_basedn == target_basedn:
            self.logger.debug(
                "BaseDN transformation skipped - source equals target",
                operation="sync_ldif_file",
                source_basedn=source_basedn[:100] if source_basedn else None,
                entries_count=len(entries),
            )
            return entries

        transformed = []
        transformed_count = 0
        unchanged_count = 0

        for entry in entries:
            # Entry.dn is validated by Pydantic model - guaranteed to exist and non-empty
            # Pydantic validation ensures DN is never empty
            dn_str = str(entry.dn) if entry.dn else "unknown"

            if source_basedn.lower() in dn_str.lower():
                new_dn_str = dn_str.replace(source_basedn, target_basedn)

                new_entry = entry.model_copy(
                    update={"dn": FlextLdifModels.DistinguishedName(value=new_dn_str)},
                )
                transformed.append(new_entry)
                transformed_count += 1
            else:
                transformed.append(entry)
                unchanged_count += 1

        self.logger.debug(
            "BaseDN transformation completed",
            operation="sync_ldif_file",
            entries_count=len(entries),
            transformed_count=transformed_count,
            unchanged_count=unchanged_count,
            source_basedn=source_basedn[:100] if source_basedn else None,
            target_basedn=target_basedn[:100] if target_basedn else None,
        )

        return transformed

    def execute(self, **_kwargs: object) -> FlextResult[FlextLdapModels.SyncStats]:
        """Execute service health check.

        Args:
            **_kwargs: Unused - health check requires no configuration

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

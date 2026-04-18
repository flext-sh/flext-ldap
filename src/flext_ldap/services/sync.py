"""LDIF-to-LDAP synchronization mixins for the public LDAP facade.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

import inspect
from collections.abc import Mapping, MutableMapping
from datetime import UTC, datetime
from pathlib import Path
from typing import TypeIs

from flext_ldap import FlextLdapOperations, c, m, p, r, t


class FlextLdapSyncCallbacks:
    """Helpers and type guards for LDAP sync callbacks."""

    @staticmethod
    def is_multi_phase_callback(
        callback: t.Ldap.ProgressCallbackUnion,
    ) -> TypeIs[t.Ldap.MultiPhaseProgressCallback]:
        """Return ``True`` when callback expects the multi-phase signature."""
        if callback is None:
            return False
        try:
            signature = inspect.signature(callback)
        except (TypeError, ValueError, AttributeError):
            return False
        return len(signature.parameters) == c.Ldap.Callback.MULTI_PHASE_PARAM_COUNT

    @staticmethod
    def is_single_phase_callback(
        callback: t.Ldap.ProgressCallbackUnion,
    ) -> TypeIs[t.Ldap.LdapProgressCallback]:
        """Return ``True`` when callback expects the single-phase signature."""
        if callback is None:
            return False
        try:
            signature = inspect.signature(callback)
        except (TypeError, ValueError, AttributeError):
            return False
        return len(signature.parameters) == c.Ldap.Callback.SINGLE_PHASE_PARAM_COUNT


class FlextLdapSync(FlextLdapOperations):
    """MRO mixin that syncs parsed LDIF phases into LDAP."""

    @staticmethod
    def _make_phase_progress_callback(
        phase: str,
        settings: m.Ldap.SyncPhaseConfig,
    ) -> t.Ldap.LdapProgressCallback | None:
        """Normalize configured callbacks to the single-phase protocol."""
        callback = settings.progress_callback
        if callback is None:
            return None
        if FlextLdapSyncCallbacks.is_multi_phase_callback(callback):

            def progress_callback(
                current: int,
                total: int,
                dn: str,
                stats: p.Ldap.LdapBatchStats,
            ) -> None:
                callback(phase, current, total, dn, stats)

            return progress_callback
        if FlextLdapSyncCallbacks.is_single_phase_callback(callback):
            return callback
        return None

    def sync_multiple_phases(
        self,
        phase_files: Mapping[str, Path],
        *,
        settings: m.Ldap.SyncPhaseConfig | None = None,
    ) -> p.Result[m.Ldap.MultiPhaseSyncResult]:
        """Synchronize multiple LDIF phase files sequentially."""
        sync_config = settings or m.Ldap.SyncPhaseConfig()
        start_time = datetime.now(UTC)
        phase_results: MutableMapping[str, m.Ldap.PhaseSyncResult] = {}
        overall_success = True
        stop_requested = False
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
            phase_result = self._process_single_phase(
                phase_name,
                phase_file,
                sync_config,
            )
            if phase_result.failure:
                self.logger.error(
                    "Phase sync failed",
                    phase=phase_name,
                    error=str(phase_result.error),
                )
                overall_success = False
                if sync_config.stop_on_error:
                    stop_requested = True
                continue
            phase_results[phase_name] = phase_result.value
        phase_values = list(phase_results.values())
        total_entries = sum(phase_result.total_entries for phase_result in phase_values)
        total_synced = sum(phase_result.synced for phase_result in phase_values)
        total_failed = sum(phase_result.failed for phase_result in phase_values)
        total_skipped = sum(phase_result.skipped for phase_result in phase_values)
        total_processed = total_synced + total_failed + total_skipped
        overall_success_rate = (
            (total_synced + total_skipped) / total_processed * 100
            if total_processed > 0
            else 0.0
        )
        return r[m.Ldap.MultiPhaseSyncResult].ok(
            m.Ldap.MultiPhaseSyncResult.model_validate({
                "phase_results": phase_results,
                "total_entries": total_entries,
                "total_synced": total_synced,
                "total_failed": total_failed,
                "total_skipped": total_skipped,
                "overall_success_rate": overall_success_rate,
                "total_duration_seconds": (
                    datetime.now(UTC) - start_time
                ).total_seconds(),
                "overall_success": overall_success,
            }),
        )

    def sync_phase_entries(
        self,
        ldif_file_path: Path,
        phase_name: str,
        *,
        settings: m.Ldap.SyncPhaseConfig | None = None,
    ) -> p.Result[m.Ldap.PhaseSyncResult]:
        """Synchronize a single phase file into LDAP."""
        sync_config = settings or m.Ldap.SyncPhaseConfig()
        start_time = datetime.now(UTC)
        parse_result = self._ldif.parse_ldif_file(
            ldif_file_path,
            server_type=sync_config.server_type,
        )
        if parse_result.failure:
            error_msg = (
                str(parse_result.error) if parse_result.error else "Unknown error"
            )
            return r[m.Ldap.PhaseSyncResult].fail(
                f"Failed to parse LDIF file: {error_msg}",
            )
        entries = list(parse_result.value.entries)
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
        single_phase_callback = self._prepare_phase_callback(phase_name, sync_config)
        batch_result = self.batch_upsert(
            list(entries),
            progress_callback=single_phase_callback,
            retry_on_errors=sync_config.retry_on_errors
            or ["session terminated", "not connected", "invalid messageid", "socket"],
            max_retries=sync_config.max_retries,
            stop_on_error=sync_config.stop_on_error,
        )
        if batch_result.failure:
            error_msg = (
                str(batch_result.error) if batch_result.error else "Unknown error"
            )
            return r[m.Ldap.PhaseSyncResult].fail(f"Batch sync failed: {error_msg}")
        batch_stats = batch_result.value
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

    def _prepare_phase_callback(
        self,
        phase_name: str,
        settings: m.Ldap.SyncPhaseConfig,
    ) -> t.Ldap.LdapProgressCallback | None:
        """Prepare a phase-aware callback from the configured sync callback."""
        phase_callback = (
            FlextLdapSync._make_phase_progress_callback(phase_name, settings)
            or settings.progress_callback
        )
        if phase_callback is None:
            return None
        if FlextLdapSyncCallbacks.is_single_phase_callback(phase_callback):
            return phase_callback
        if FlextLdapSyncCallbacks.is_multi_phase_callback(phase_callback):

            def wrapped_callback(
                current: int,
                total: int,
                dn: str,
                stats: p.Ldap.LdapBatchStats,
            ) -> None:
                phase_callback(phase_name, current, total, dn, stats)

            return wrapped_callback
        return None

    def _process_single_phase(
        self,
        phase_name: str,
        ldif_path: Path,
        settings: m.Ldap.SyncPhaseConfig,
    ) -> p.Result[m.Ldap.PhaseSyncResult]:
        """Process one phase file with a callback normalized for that phase."""
        phase_callback = self._prepare_phase_callback(phase_name, settings)
        return self.sync_phase_entries(
            ldif_path,
            phase_name,
            settings=m.Ldap.SyncPhaseConfig(
                server_type=settings.server_type,
                progress_callback=phase_callback,
                retry_on_errors=settings.retry_on_errors,
                max_retries=settings.max_retries,
                stop_on_error=settings.stop_on_error,
            ),
        )


__all__: list[str] = ["FlextLdapSync", "FlextLdapSyncCallbacks"]

"""LDIF-to-LDAP synchronization mixin for the public LDAP facade.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

import inspect
from collections.abc import (
    MutableMapping,
)
from pathlib import Path
from typing import TypeIs

from flext_ldap import c, m, p, r, t, u
from flext_ldap.services.operations import FlextLdapOperations


class FlextLdapSync(FlextLdapOperations):
    """MRO mixin that syncs parsed LDIF phases into LDAP."""

    @staticmethod
    def multi_phase_callback(
        callback: t.Ldap.ProgressCallbackUnion | None,
    ) -> TypeIs[t.Ldap.MultiPhaseProgressCallback]:
        """Return ``True`` when callback expects the multi-phase signature."""
        if callback is None:
            return False
        try:
            signature: inspect.Signature = inspect.signature(callback)
        except c.EXC_BASIC_TYPE as exc:
            msg = f"progress_callback {callback!r} has an uninspectable signature"
            raise TypeError(msg) from exc
        parameter_count: int = len(signature.parameters)
        matches_multi_phase: bool = parameter_count == c.Ldap.MULTI_PHASE_PARAM_COUNT
        return matches_multi_phase

    @staticmethod
    def single_phase_callback(
        callback: t.Ldap.ProgressCallbackUnion | None,
    ) -> TypeIs[t.Ldap.LdapProgressCallback]:
        """Return ``True`` when callback expects the single-phase signature."""
        if callback is None:
            return False
        try:
            signature: inspect.Signature = inspect.signature(callback)
        except c.EXC_BASIC_TYPE as exc:
            msg = f"progress_callback {callback!r} has an uninspectable signature"
            raise TypeError(msg) from exc
        parameter_count: int = len(signature.parameters)
        matches_single_phase: bool = parameter_count == c.Ldap.SINGLE_PHASE_PARAM_COUNT
        return matches_single_phase

    @staticmethod
    def _make_phase_progress_callback(
        phase: str,
        settings: m.Ldap.SyncPhaseConfig,
    ) -> t.Ldap.LdapProgressCallback | None:
        """Normalize configured callbacks to the single-phase protocol."""
        callback = settings.progress_callback
        if callback is None:
            return None
        if FlextLdapSync.multi_phase_callback(callback):

            def progress_callback(
                current: int,
                total: int,
                dn: str,
                stats: p.Ldap.LdapBatchStats,
            ) -> None:
                callback(phase, current, total, dn, stats)

            return progress_callback
        if FlextLdapSync.single_phase_callback(callback):
            return callback
        try:
            sig = inspect.signature(callback)
            param_count = len(sig.parameters)
            msg = (
                f"progress_callback has {param_count} parameters but must have "
                f"{c.Ldap.SINGLE_PHASE_PARAM_COUNT} (single-phase) or "
                f"{c.Ldap.MULTI_PHASE_PARAM_COUNT} (multi-phase)"
            )
        except c.EXC_TYPE_VALIDATION:
            msg = (
                f"progress_callback {callback!r} has an incompatible signature: "
                f"must have {c.Ldap.SINGLE_PHASE_PARAM_COUNT} (single-phase) or "
                f"{c.Ldap.MULTI_PHASE_PARAM_COUNT} (multi-phase) parameters"
            )
        raise TypeError(msg)

    def sync_multiple_phases(
        self,
        phase_files: t.MappingKV[str, Path],
        *,
        settings: m.Ldap.SyncPhaseConfig | None = None,
    ) -> p.Result[p.Ldap.MultiPhaseSyncResult]:
        """Synchronize multiple LDIF phase files sequentially."""
        sync_config = settings or m.Ldap.SyncPhaseConfig()
        start_time = u.now()
        phase_results: MutableMapping[str, m.Ldap.PhaseSyncResult] = {}
        overall_success = True
        for phase_name, phase_file in phase_files.items():
            if not phase_file.exists():
                return r[p.Ldap.MultiPhaseSyncResult].fail(
                    f"Phase file not found: {phase_file}",
                )
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
                if sync_config.stop_on_error:
                    return r[p.Ldap.MultiPhaseSyncResult].fail(
                        f"Phase '{phase_name}' failed: {phase_result.error}",
                    )
                overall_success = False
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
        sync_result = m.Ldap.MultiPhaseSyncResult(
            phase_results=phase_results,
            total_entries=total_entries,
            total_synced=total_synced,
            total_failed=total_failed,
            total_skipped=total_skipped,
            overall_success_rate=overall_success_rate,
            total_duration_seconds=(u.now() - start_time).total_seconds(),
            overall_success=overall_success,
        )
        if not overall_success:
            return r[p.Ldap.MultiPhaseSyncResult].fail(
                f"Multi-phase sync completed with failures: {total_failed} entries failed",
            )
        return r[p.Ldap.MultiPhaseSyncResult].ok(sync_result)

    def sync_phase_entries(
        self,
        ldif_file_path: Path,
        phase_name: str,
        *,
        settings: m.Ldap.SyncPhaseConfig | None = None,
    ) -> p.Result[p.Ldap.PhaseSyncResult]:
        """Synchronize a single phase file into LDAP."""
        sync_config = settings or m.Ldap.SyncPhaseConfig()
        start_time = u.now()
        parse_result = self._ldif.parse_ldif_file(
            ldif_file_path,
            server_type=sync_config.server_type,
        )
        if parse_result.failure:
            error_msg = parse_result.error or "Unknown error"
            return r[p.Ldap.PhaseSyncResult].fail(
                f"Failed to parse LDIF file: {error_msg}",
            )
        entries = list(parse_result.value.entries)
        if not entries:
            return r[p.Ldap.PhaseSyncResult].ok(
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
            error_msg = batch_result.error or "Unknown error"
            return r[p.Ldap.PhaseSyncResult].fail_op("Batch sync", error_msg)
        batch_stats = batch_result.value
        duration = (u.now() - start_time).total_seconds()
        total_processed = batch_stats.synced + batch_stats.failed + batch_stats.skipped
        success_rate = (
            (batch_stats.synced + batch_stats.skipped) / total_processed * 100
            if total_processed > 0
            else 0.0
        )
        return r[p.Ldap.PhaseSyncResult].ok(
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
        if FlextLdapSync.single_phase_callback(phase_callback):
            return phase_callback
        if FlextLdapSync.multi_phase_callback(phase_callback):

            def wrapped_callback(
                current: int,
                total: int,
                dn: str,
                stats: p.Ldap.LdapBatchStats,
            ) -> None:
                phase_callback(phase_name, current, total, dn, stats)

            return wrapped_callback
        try:
            sig = inspect.signature(phase_callback)
            param_count = len(sig.parameters)
            msg = (
                f"progress_callback has {param_count} parameters but must have "
                f"{c.Ldap.SINGLE_PHASE_PARAM_COUNT} (single-phase) or "
                f"{c.Ldap.MULTI_PHASE_PARAM_COUNT} (multi-phase)"
            )
        except c.EXC_TYPE_VALIDATION:
            msg = (
                f"progress_callback {phase_callback!r} has an incompatible signature: "
                f"must have {c.Ldap.SINGLE_PHASE_PARAM_COUNT} (single-phase) or "
                f"{c.Ldap.MULTI_PHASE_PARAM_COUNT} (multi-phase) parameters"
            )
        raise TypeError(msg)

    def _process_single_phase(
        self,
        phase_name: str,
        ldif_path: Path,
        settings: m.Ldap.SyncPhaseConfig,
    ) -> p.Result[p.Ldap.PhaseSyncResult]:
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


__all__: list[str] = ["FlextLdapSync"]

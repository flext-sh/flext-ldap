"""LDIF-to-LDAP synchronization mixins for the public LDAP facade.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

import inspect
from collections.abc import Mapping, MutableMapping, Sequence
from datetime import UTC, datetime
from pathlib import Path
from typing import ClassVar, TypeIs, override

from pydantic import ConfigDict

from flext_core import r
from flext_ldap import (
    FlextLdapModels as m,
    FlextLdapOperations,
    FlextLdapProtocols as p,
    FlextLdapTypes as t,
)

MULTI_PHASE_CALLBACK_PARAM_COUNT: int = 5
SINGLE_PHASE_CALLBACK_PARAM_COUNT: int = 4


class FlextLdapSyncCallbacks:
    """Helpers and type guards for LDAP sync callbacks."""

    @staticmethod
    def convert_entries_to_protocol(
        entries: Sequence[m.Ldif.Entry],
    ) -> Sequence[m.Ldif.Entry]:
        """Return a concrete sequence for downstream protocol consumers."""
        return list(entries)

    @staticmethod
    def get_phase_result_value(
        phase_result: m.Ldap.PhaseSyncResult,
        attr_name: str,
        default: int = 0,
    ) -> int:
        """Read integer counters from phase results with a safe default."""
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
        return len(signature.parameters) == MULTI_PHASE_CALLBACK_PARAM_COUNT

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
        return len(signature.parameters) == SINGLE_PHASE_CALLBACK_PARAM_COUNT


class FlextLdapSync(FlextLdapOperations):
    """MRO mixin that syncs parsed LDIF phases into LDAP."""

    model_config: ClassVar[ConfigDict] = ConfigDict(
        frozen=False,
        extra="allow",
        arbitrary_types_allowed=True,
    )

    @override
    def execute(self, **_kwargs: object) -> r[m.Ldap.SearchResult]:
        """Placeholder for mixin compliance; overridden by the public facade."""
        return r[m.Ldap.SearchResult].fail("Not implemented in mixin")

    @staticmethod
    def _make_phase_progress_callback(
        phase: str,
        config: m.Ldap.SyncPhaseConfig,
    ) -> t.Ldap.LdapProgressCallback | None:
        """Normalize configured callbacks to the single-phase protocol."""
        callback = config.progress_callback
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
        config: m.Ldap.SyncPhaseConfig | None = None,
    ) -> r[m.Ldap.MultiPhaseSyncResult]:
        """Synchronize multiple LDIF phase files sequentially."""
        sync_config = config or m.Ldap.SyncPhaseConfig()
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
            if phase_result.is_failure:
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
        total_entries = sum(
            FlextLdapSyncCallbacks.get_phase_result_value(
                phase_result,
                "total_entries",
            )
            for phase_result in phase_values
        )
        total_synced = sum(
            FlextLdapSyncCallbacks.get_phase_result_value(phase_result, "synced")
            for phase_result in phase_values
        )
        total_failed = sum(
            FlextLdapSyncCallbacks.get_phase_result_value(phase_result, "failed")
            for phase_result in phase_values
        )
        total_skipped = sum(
            FlextLdapSyncCallbacks.get_phase_result_value(phase_result, "skipped")
            for phase_result in phase_values
        )
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
        config: m.Ldap.SyncPhaseConfig | None = None,
    ) -> r[m.Ldap.PhaseSyncResult]:
        """Synchronize a single phase file into LDAP."""
        sync_config = config or m.Ldap.SyncPhaseConfig()
        start_time = datetime.now(UTC)
        try:
            ldif_content = ldif_file_path.read_text(encoding="utf-8")
        except OSError as error:
            return r[m.Ldap.PhaseSyncResult].fail(
                f"Failed to read LDIF file: {error!s}",
            )
        parse_result = self._get_ldif().parse_ldif(ldif_content)
        if parse_result.is_failure:
            error_msg = (
                str(parse_result.error) if parse_result.error else "Unknown error"
            )
            return r[m.Ldap.PhaseSyncResult].fail(
                f"Failed to parse LDIF file: {error_msg}",
            )
        entries = [m.Ldif.Entry.model_validate(entry) for entry in parse_result.value]
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
        callback = sync_config.progress_callback
        single_phase_callback: t.Ldap.LdapProgressCallback | None = None
        if callback is not None:
            if FlextLdapSyncCallbacks.is_multi_phase_callback(callback):

                def wrapped_callback(
                    current: int,
                    total: int,
                    dn: str,
                    stats: p.Ldap.LdapBatchStats,
                ) -> None:
                    callback(phase_name, current, total, dn, stats)

                single_phase_callback = wrapped_callback
            elif FlextLdapSyncCallbacks.is_single_phase_callback(callback):
                single_phase_callback = callback
        batch_result = self.batch_upsert(
            FlextLdapSyncCallbacks.convert_entries_to_protocol(entries),
            progress_callback=single_phase_callback,
            retry_on_errors=sync_config.retry_on_errors
            or ["session terminated", "not connected", "invalid messageid", "socket"],
            max_retries=sync_config.max_retries,
            stop_on_error=sync_config.stop_on_error,
        )
        if batch_result.is_failure:
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
        config: m.Ldap.SyncPhaseConfig,
    ) -> t.Ldap.LdapProgressCallback | None:
        """Prepare a phase-aware callback from the configured sync callback."""
        phase_callback = (
            FlextLdapSync._make_phase_progress_callback(phase_name, config)
            or config.progress_callback
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
        config: m.Ldap.SyncPhaseConfig,
    ) -> r[m.Ldap.PhaseSyncResult]:
        """Process one phase file with a callback normalized for that phase."""
        phase_callback = self._prepare_phase_callback(phase_name, config)
        return self.sync_phase_entries(
            ldif_path,
            phase_name,
            config=m.Ldap.SyncPhaseConfig(
                server_type=config.server_type,
                progress_callback=phase_callback,
                retry_on_errors=config.retry_on_errors,
                max_retries=config.max_retries,
                stop_on_error=config.stop_on_error,
            ),
        )


__all__ = ["FlextLdapSync", "FlextLdapSyncCallbacks"]

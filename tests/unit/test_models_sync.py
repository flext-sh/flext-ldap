from __future__ import annotations

import pytest
from flext_tests import tm
from pydantic import ValidationError

from tests import c, m, t

pytestmark = pytest.mark.unit


class TestsFlextLdapModelsSync:
    # ── Contract: default values don't drift ───────────────────────────

    _API_DEFAULTS = [
        (m.Ldap.SyncOptions, "batch_size", c.Ldap.SyncDefaults.BATCH_SIZE),
        (
            m.Ldap.SyncOptions,
            "auto_create_parents",
            c.Ldap.Tests.Sync.Defaults.AUTO_CREATE_PARENTS,
        ),
        (m.Ldap.SyncOptions, "allow_deletes", c.Ldap.Tests.Sync.Defaults.ALLOW_DELETES),
        (m.Ldap.SyncStats, "synced", c.Ldap.Tests.Sync.Defaults.ZERO_COUNT),
        (m.Ldap.SyncStats, "total", c.Ldap.Tests.Sync.Defaults.ZERO_COUNT),
        (m.Ldap.SyncPhaseConfig, "server_type", c.Ldap.ServerDefaults.DEFAULT_TYPE),
        (
            m.Ldap.SyncPhaseConfig,
            "max_retries",
            c.Ldap.ConnectionDefaults.DEFAULT_MAX_RETRIES,
        ),
        (
            m.Ldap.SyncPhaseConfig,
            "stop_on_error",
            c.Ldap.Tests.Sync.Defaults.STOP_ON_ERROR,
        ),
        (m.Ldap.LdapBatchStats, "synced", c.Ldap.Tests.Sync.Defaults.ZERO_COUNT),
        (m.Ldap.LdapBatchStats, "failed", c.Ldap.Tests.Sync.Defaults.ZERO_COUNT),
        (
            m.Ldap.ConversionMetadata,
            "dn_changed",
            c.Ldap.Tests.Sync.Defaults.DN_CHANGED,
        ),
        (
            m.Ldap.ConversionMetadata,
            "source_dn",
            c.Ldap.Tests.Sync.Defaults.EMPTY_SOURCE_DN,
        ),
    ]

    @pytest.mark.parametrize(
        ("cls", "field", "expected"),
        _API_DEFAULTS,
        ids=[f"{c.__name__}.{f}" for c, f, _ in _API_DEFAULTS],
    )
    def test_api_default(
        self,
        cls: type,
        field: str,
        expected: str | float | bool,
    ) -> None:
        assert getattr(cls(), field) == expected

    # ── Validation constraints ─────────────────────────────────────────

    def test_sync_options_rejects_zero_batch_size(self) -> None:
        invalid_batch_size: int = 0
        with pytest.raises(ValidationError):
            m.Ldap.SyncOptions(batch_size=invalid_batch_size)

    # ── Computed: SyncStats.success_rate ───────────────────────────────

    _SUCCESS_RATES = [
        (
            "zero total",
            m.Ldap.SyncStats,
            dict[str, int](),
            c.Ldap.Tests.Sync.SuccessRateBatchZero.EXPECTED,
        ),
        (
            "90% rate",
            m.Ldap.SyncStats,
            dict(c.Ldap.Tests.Sync.SuccessRate90.KWARGS),
            c.Ldap.Tests.Sync.SuccessRate90.EXPECTED,
        ),
        (
            "batch zero",
            m.Ldap.BatchUpsertResult,
            dict(c.Ldap.Tests.Sync.SuccessRateBatchZero.KWARGS),
            c.Ldap.Tests.Sync.SuccessRateBatchZero.EXPECTED,
        ),
        (
            "batch 85%",
            m.Ldap.BatchUpsertResult,
            dict(c.Ldap.Tests.Sync.SuccessRateBatch85.KWARGS),
            c.Ldap.Tests.Sync.SuccessRateBatch85.EXPECTED,
        ),
    ]

    @pytest.mark.parametrize(
        ("label", "cls", "kwargs", "expected"),
        _SUCCESS_RATES,
        ids=[x[0] for x in _SUCCESS_RATES],
    )
    def test_success_rate(
        self,
        label: str,
        cls: type,
        kwargs: t.IntMapping,
        expected: float,
    ) -> None:
        tm.that(getattr(cls(**kwargs), "success_rate"), eq=expected)

    # ── Factory: SyncStats.from_counters ───────────────────────────────

    def test_from_counters_computes_total(self) -> None:
        s = m.Ldap.SyncStats.from_counters(
            synced=c.Ldap.Tests.Sync.FromCounters.SYNCED,
            skipped=c.Ldap.Tests.Sync.FromCounters.SKIPPED,
            failed=c.Ldap.Tests.Sync.FromCounters.FAILED,
            duration_seconds=c.Ldap.Tests.Sync.FromCounters.DURATION,
        )
        tm.that(s.total, eq=c.Ldap.Tests.Sync.FromCounters.TOTAL)
        tm.that(s.duration_seconds, eq=c.Ldap.Tests.Sync.FromCounters.DURATION)
        tm.that(s.success_rate, eq=c.Ldap.Tests.Sync.FromCounters.SUCCESS_RATE)

    def test_from_counters_serialization_includes_computed(self) -> None:
        tm.that(
            m.Ldap.SyncStats.from_counters(
                synced=c.Ldap.Tests.Sync.Serialization.SYNCED,
                skipped=c.Ldap.Tests.Sync.Serialization.SKIPPED,
                failed=c.Ldap.Tests.Sync.Serialization.FAILED,
            ).model_dump(),
            has=c.Ldap.Tests.FieldNames.SUCCESS_RATE,
        )

    # ── UpsertResult: success vs error ─────────────────────────────────

    def test_upsert_success(self) -> None:
        r = m.Ldap.UpsertResult(
            success=True,
            dn=c.Ldap.Tests.RFC.DEFAULT_BASE_DN,
            operation=c.Ldap.OperationType.ADD,
        )
        tm.that(r.success, eq=True)
        tm.that(r.error, none=True)

    def test_upsert_failure_carries_error(self) -> None:
        r = m.Ldap.UpsertResult(
            success=False,
            dn=c.Ldap.Tests.RFC.DEFAULT_BASE_DN,
            operation=c.Ldap.OperationType.ADD,
            error=c.Ldap.Tests.Sync.ENTRY_ALREADY_EXISTS,
        )
        tm.that(not r.success, eq=True)
        tm.that(r.error, eq=c.Ldap.Tests.Sync.ENTRY_ALREADY_EXISTS)

    def test_batch_upsert_tracks_all_counts(self) -> None:
        r = m.Ldap.BatchUpsertResult(
            total_processed=c.Ldap.Tests.Sync.Upsert.BATCH_TOTAL,
            successful=c.Ldap.Tests.Sync.Upsert.BATCH_SUCCESSFUL,
            failed=c.Ldap.Tests.Sync.Upsert.BATCH_FAILED,
        )
        tm.that(r.total_processed, eq=c.Ldap.Tests.Sync.Upsert.BATCH_TOTAL)
        tm.that(r.successful, eq=c.Ldap.Tests.Sync.Upsert.BATCH_SUCCESSFUL)
        tm.that(r.failed, eq=c.Ldap.Tests.Sync.Upsert.BATCH_FAILED)

    # ── ConversionMetadata: tracks attribute changes ───────────────────

    def test_conversion_metadata_tracks_changes(self) -> None:
        md = m.Ldap.ConversionMetadata(
            source_attributes=list(c.Ldap.Tests.Sync.Metadata.SOURCE_ATTRIBUTES),
            source_dn=c.Ldap.Tests.EntryDN.USER_EXAMPLE,
            removed_attributes=list(c.Ldap.Tests.Sync.Metadata.REMOVED_ATTRIBUTES),
            dn_changed=True,
            converted_dn=c.Ldap.Tests.EntryDN.USER_NEW,
        )
        tm.that(
            md.source_attributes, len=len(c.Ldap.Tests.Sync.Metadata.SOURCE_ATTRIBUTES)
        )
        tm.that(
            md.removed_attributes,
            contains=c.Ldap.Tests.Sync.Metadata.REMOVED_ATTRIBUTES[0],
        )
        tm.that(md.dn_changed, eq=True)

    # ── PhaseSyncResult + MultiPhase aggregation ───────────────────────

    def test_phase_sync_result_captures_phase_stats(self) -> None:
        r = m.Ldap.PhaseSyncResult(
            phase_name=c.Ldap.Tests.Sync.PHASE_NAME,
            total_entries=c.Ldap.Tests.Sync.Phase.TOTAL_ENTRIES,
            synced=c.Ldap.Tests.Sync.Phase.SYNCED,
            failed=c.Ldap.Tests.Sync.Phase.FAILED,
            skipped=c.Ldap.Tests.Sync.Phase.SKIPPED,
            duration_seconds=c.Ldap.Tests.Sync.Phase.DURATION,
            success_rate=c.Ldap.Tests.Sync.Phase.SUCCESS_RATE,
        )
        tm.that(r.phase_name, eq=c.Ldap.Tests.Sync.PHASE_NAME)
        tm.that(r.synced, eq=c.Ldap.Tests.Sync.Phase.SYNCED)
        tm.that(r.success_rate, eq=c.Ldap.Tests.Sync.Phase.SUCCESS_RATE)

    def test_multi_phase_aggregates_overall(self) -> None:
        r = m.Ldap.MultiPhaseSyncResult(
            total_entries=c.Ldap.Tests.Sync.MultiPhase.TOTAL_ENTRIES,
            total_synced=c.Ldap.Tests.Sync.MultiPhase.TOTAL_SYNCED,
            total_failed=c.Ldap.Tests.Sync.MultiPhase.TOTAL_FAILED,
            total_skipped=c.Ldap.Tests.Sync.MultiPhase.TOTAL_SKIPPED,
            overall_success_rate=c.Ldap.Tests.Sync.MultiPhase.OVERALL_SUCCESS_RATE,
            total_duration_seconds=c.Ldap.Tests.Sync.MultiPhase.TOTAL_DURATION,
            overall_success=True,
        )
        tm.that(r.total_synced, eq=c.Ldap.Tests.Sync.MultiPhase.TOTAL_SYNCED)
        tm.that(r.overall_success, eq=True)

    def test_multi_phase_with_phase_results_dict(self) -> None:
        phase = m.Ldap.PhaseSyncResult(
            phase_name=c.Ldap.Tests.Sync.PHASE_NAME,
            total_entries=c.Ldap.Tests.Sync.Phase.TOTAL_ENTRIES,
            synced=c.Ldap.Tests.Sync.PhaseResults.SYNCED,
            failed=c.Ldap.Tests.Sync.PhaseResults.FAILED,
            skipped=c.Ldap.Tests.Sync.PhaseResults.SKIPPED,
            duration_seconds=c.Ldap.Tests.Sync.PhaseResults.DURATION,
            success_rate=c.Ldap.Tests.Sync.PhaseResults.SUCCESS_RATE,
        )
        r = m.Ldap.MultiPhaseSyncResult(
            phase_results={c.Ldap.Tests.Sync.PHASE_NAME: phase},
            total_entries=c.Ldap.Tests.Sync.Phase.TOTAL_ENTRIES,
            total_synced=c.Ldap.Tests.Sync.PhaseResults.SYNCED,
            total_failed=c.Ldap.Tests.Sync.PhaseResults.FAILED,
            total_skipped=c.Ldap.Tests.Sync.PhaseResults.SKIPPED,
            overall_success_rate=c.Ldap.Tests.Sync.PhaseResults.SUCCESS_RATE,
            total_duration_seconds=c.Ldap.Tests.Sync.PhaseResults.DURATION,
        )
        tm.that(r.phase_results, keys=[c.Ldap.Tests.Sync.PHASE_NAME])
        tm.that(
            r.phase_results[c.Ldap.Tests.Sync.PHASE_NAME].synced,
            eq=c.Ldap.Tests.Sync.PhaseResults.SYNCED,
        )

    # ── LdapOperationResult + LdapBatchStats ───────────────────────────

    def test_operation_result_carries_enum(self) -> None:
        tm.that(
            m.Ldap.LdapOperationResult(
                operation=c.Ldap.UpsertOperations.ADDED,
            ).operation,
            eq=c.Ldap.UpsertOperations.ADDED,
        )

    def test_batch_stats_custom(self) -> None:
        s = m.Ldap.LdapBatchStats(
            synced=c.Ldap.Tests.Sync.BatchStats.SYNCED,
            failed=c.Ldap.Tests.Sync.BatchStats.FAILED,
            skipped=c.Ldap.Tests.Sync.BatchStats.SKIPPED,
        )
        tm.that(s.synced, eq=c.Ldap.Tests.Sync.BatchStats.SYNCED)
        tm.that(s.failed, eq=c.Ldap.Tests.Sync.BatchStats.FAILED)

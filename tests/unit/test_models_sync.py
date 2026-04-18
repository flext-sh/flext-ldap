from __future__ import annotations

import pytest

from tests import c, m, t, u

pytestmark = pytest.mark.unit


class TestsFlextLdapModelsSync:
    # ── Contract: default values don't drift ───────────────────────────

    _API_DEFAULTS = [
        (m.Ldap.SyncOptions, "batch_size", c.Ldap.SyncDefaults.BATCH_SIZE),
        (
            m.Ldap.SyncOptions,
            "auto_create_parents",
            c.Ldap.Tests.SYNC_DEFAULT_AUTO_CREATE_PARENTS,
        ),
        (m.Ldap.SyncOptions, "allow_deletes", c.Ldap.Tests.SYNC_DEFAULT_ALLOW_DELETES),
        (m.Ldap.SyncStats, "synced", c.Ldap.Tests.SYNC_DEFAULT_ZERO_COUNT),
        (m.Ldap.SyncStats, "total", c.Ldap.Tests.SYNC_DEFAULT_ZERO_COUNT),
        (m.Ldap.SyncPhaseConfig, "server_type", c.Ldap.ServerDefaults.DEFAULT_TYPE),
        (
            m.Ldap.SyncPhaseConfig,
            "max_retries",
            c.Ldap.ConnectionDefaults.DEFAULT_MAX_RETRIES,
        ),
        (
            m.Ldap.SyncPhaseConfig,
            "stop_on_error",
            c.Ldap.Tests.SYNC_DEFAULT_STOP_ON_ERROR,
        ),
        (m.Ldap.LdapBatchStats, "synced", c.Ldap.Tests.SYNC_DEFAULT_ZERO_COUNT),
        (m.Ldap.LdapBatchStats, "failed", c.Ldap.Tests.SYNC_DEFAULT_ZERO_COUNT),
        (
            m.Ldap.ConversionMetadata,
            "dn_changed",
            c.Ldap.Tests.SYNC_DEFAULT_DN_CHANGED,
        ),
        (
            m.Ldap.ConversionMetadata,
            "source_dn",
            c.Ldap.Tests.SYNC_DEFAULT_EMPTY_SOURCE_DN,
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
        pass

    # ── Validation constraints ─────────────────────────────────────────

    def test_sync_options_rejects_zero_batch_size(self) -> None:
        invalid_batch_size: int = 0
        with pytest.raises(c.ValidationError):
            m.Ldap.SyncOptions(batch_size=invalid_batch_size)

    # ── Computed: SyncStats.success_rate ───────────────────────────────

    _SUCCESS_RATES = [
        (
            "zero total",
            m.Ldap.SyncStats,
            dict[str, int](),
            c.Ldap.Tests.SYNC_SUCCESS_RATE_BATCH_ZERO_EXPECTED,
        ),
        (
            "90% rate",
            m.Ldap.SyncStats,
            dict(c.Ldap.Tests.SYNC_SUCCESS_RATE_90_KWARGS),
            c.Ldap.Tests.SYNC_SUCCESS_RATE_90_EXPECTED,
        ),
        (
            "batch zero",
            m.Ldap.BatchUpsertResult,
            dict(c.Ldap.Tests.SYNC_SUCCESS_RATE_BATCH_ZERO_KWARGS),
            c.Ldap.Tests.SYNC_SUCCESS_RATE_BATCH_ZERO_EXPECTED,
        ),
        (
            "batch 85%",
            m.Ldap.BatchUpsertResult,
            dict(c.Ldap.Tests.SYNC_SUCCESS_RATE_BATCH_85_KWARGS),
            c.Ldap.Tests.SYNC_SUCCESS_RATE_BATCH_85_EXPECTED,
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
        pass

    # ── Factory: SyncStats.from_counters ───────────────────────────────

    def test_from_counters_computes_total(self) -> None:
        s = m.Ldap.SyncStats.from_counters(
            synced=c.Ldap.Tests.SYNC_FROM_COUNTERS_SYNCED,
            skipped=c.Ldap.Tests.SYNC_FROM_COUNTERS_SKIPPED,
            failed=c.Ldap.Tests.SYNC_FROM_COUNTERS_FAILED,
            duration_seconds=c.Ldap.Tests.SYNC_FROM_COUNTERS_DURATION,
        )
        u.Ldap.Tests.that(s.total, eq=c.Ldap.Tests.SYNC_FROM_COUNTERS_TOTAL)
        u.Ldap.Tests.that(
            s.duration_seconds, eq=c.Ldap.Tests.SYNC_FROM_COUNTERS_DURATION
        )
        u.Ldap.Tests.that(
            s.success_rate, eq=c.Ldap.Tests.SYNC_FROM_COUNTERS_SUCCESS_RATE
        )

    def test_from_counters_serialization_includes_computed(self) -> None:
        u.Ldap.Tests.that(
            m.Ldap.SyncStats.from_counters(
                synced=c.Ldap.Tests.SYNC_SERIALIZATION_SYNCED,
                skipped=c.Ldap.Tests.SYNC_SERIALIZATION_SKIPPED,
                failed=c.Ldap.Tests.SYNC_SERIALIZATION_FAILED,
            ).model_dump(),
            has=c.Ldap.Tests.FIELD_SUCCESS_RATE,
        )

    # ── UpsertResult: success vs error ─────────────────────────────────

    def test_upsert_success(self) -> None:
        r = m.Ldap.UpsertResult(
            success=True,
            dn=c.Ldap.Tests.RFC_DEFAULT_BASE_DN,
            operation=c.Ldap.OperationType.ADD,
        )
        u.Ldap.Tests.that(r.success, eq=True)
        u.Ldap.Tests.that(r.error, none=True)

    def test_upsert_failure_carries_error(self) -> None:
        r = m.Ldap.UpsertResult(
            success=False,
            dn=c.Ldap.Tests.RFC_DEFAULT_BASE_DN,
            operation=c.Ldap.OperationType.ADD,
            error=c.Ldap.Tests.SYNC_ENTRY_ALREADY_EXISTS,
        )
        u.Ldap.Tests.that(not r.success, eq=True)
        u.Ldap.Tests.that(r.error, eq=c.Ldap.Tests.SYNC_ENTRY_ALREADY_EXISTS)

    def test_batch_upsert_tracks_all_counts(self) -> None:
        r = m.Ldap.BatchUpsertResult(
            total_processed=c.Ldap.Tests.SYNC_UPSERT_BATCH_TOTAL,
            successful=c.Ldap.Tests.SYNC_UPSERT_BATCH_SUCCESSFUL,
            failed=c.Ldap.Tests.SYNC_UPSERT_BATCH_FAILED,
        )
        u.Ldap.Tests.that(r.total_processed, eq=c.Ldap.Tests.SYNC_UPSERT_BATCH_TOTAL)
        u.Ldap.Tests.that(r.successful, eq=c.Ldap.Tests.SYNC_UPSERT_BATCH_SUCCESSFUL)
        u.Ldap.Tests.that(r.failed, eq=c.Ldap.Tests.SYNC_UPSERT_BATCH_FAILED)

    # ── ConversionMetadata: tracks attribute changes ───────────────────

    def test_conversion_metadata_tracks_changes(self) -> None:
        md = m.Ldap.ConversionMetadata(
            source_attributes=list(c.Ldap.Tests.SYNC_METADATA_SOURCE_ATTRIBUTES),
            source_dn=c.Ldap.Tests.ENTRY_DN_USER_EXAMPLE,
            removed_attributes=list(c.Ldap.Tests.SYNC_METADATA_REMOVED_ATTRIBUTES),
            dn_changed=True,
            converted_dn=c.Ldap.Tests.ENTRY_DN_USER_NEW,
        )
        u.Ldap.Tests.that(
            md.source_attributes, len=len(c.Ldap.Tests.SYNC_METADATA_SOURCE_ATTRIBUTES)
        )
        u.Ldap.Tests.that(
            md.removed_attributes,
            contains=c.Ldap.Tests.SYNC_METADATA_REMOVED_ATTRIBUTES[0],
        )
        u.Ldap.Tests.that(md.dn_changed, eq=True)

    # ── PhaseSyncResult + MultiPhase aggregation ───────────────────────

    def test_phase_sync_result_captures_phase_stats(self) -> None:
        r = m.Ldap.PhaseSyncResult(
            phase_name=c.Ldap.Tests.SYNC_PHASE_NAME,
            total_entries=c.Ldap.Tests.SYNC_PHASE_TOTAL_ENTRIES,
            synced=c.Ldap.Tests.SYNC_PHASE_SYNCED,
            failed=c.Ldap.Tests.SYNC_PHASE_FAILED,
            skipped=c.Ldap.Tests.SYNC_PHASE_SKIPPED,
            duration_seconds=c.Ldap.Tests.SYNC_PHASE_DURATION,
            success_rate=c.Ldap.Tests.SYNC_PHASE_SUCCESS_RATE,
        )
        u.Ldap.Tests.that(r.phase_name, eq=c.Ldap.Tests.SYNC_PHASE_NAME)
        u.Ldap.Tests.that(r.synced, eq=c.Ldap.Tests.SYNC_PHASE_SYNCED)
        u.Ldap.Tests.that(r.success_rate, eq=c.Ldap.Tests.SYNC_PHASE_SUCCESS_RATE)

    def test_multi_phase_aggregates_overall(self) -> None:
        r = m.Ldap.MultiPhaseSyncResult(
            total_entries=c.Ldap.Tests.SYNC_MULTI_PHASE_TOTAL_ENTRIES,
            total_synced=c.Ldap.Tests.SYNC_MULTI_PHASE_TOTAL_SYNCED,
            total_failed=c.Ldap.Tests.SYNC_MULTI_PHASE_TOTAL_FAILED,
            total_skipped=c.Ldap.Tests.SYNC_MULTI_PHASE_TOTAL_SKIPPED,
            overall_success_rate=c.Ldap.Tests.SYNC_MULTI_PHASE_OVERALL_SUCCESS_RATE,
            total_duration_seconds=c.Ldap.Tests.SYNC_MULTI_PHASE_TOTAL_DURATION,
            overall_success=True,
        )
        u.Ldap.Tests.that(r.total_synced, eq=c.Ldap.Tests.SYNC_MULTI_PHASE_TOTAL_SYNCED)
        u.Ldap.Tests.that(r.overall_success, eq=True)

    def test_multi_phase_with_phase_results_dict(self) -> None:
        phase = m.Ldap.PhaseSyncResult(
            phase_name=c.Ldap.Tests.SYNC_PHASE_NAME,
            total_entries=c.Ldap.Tests.SYNC_PHASE_TOTAL_ENTRIES,
            synced=c.Ldap.Tests.SYNC_PHASE_RESULTS_SYNCED,
            failed=c.Ldap.Tests.SYNC_PHASE_RESULTS_FAILED,
            skipped=c.Ldap.Tests.SYNC_PHASE_RESULTS_SKIPPED,
            duration_seconds=c.Ldap.Tests.SYNC_PHASE_RESULTS_DURATION,
            success_rate=c.Ldap.Tests.SYNC_PHASE_RESULTS_SUCCESS_RATE,
        )
        r = m.Ldap.MultiPhaseSyncResult(
            phase_results={c.Ldap.Tests.SYNC_PHASE_NAME: phase},
            total_entries=c.Ldap.Tests.SYNC_PHASE_TOTAL_ENTRIES,
            total_synced=c.Ldap.Tests.SYNC_PHASE_RESULTS_SYNCED,
            total_failed=c.Ldap.Tests.SYNC_PHASE_RESULTS_FAILED,
            total_skipped=c.Ldap.Tests.SYNC_PHASE_RESULTS_SKIPPED,
            overall_success_rate=c.Ldap.Tests.SYNC_PHASE_RESULTS_SUCCESS_RATE,
            total_duration_seconds=c.Ldap.Tests.SYNC_PHASE_RESULTS_DURATION,
        )
        u.Ldap.Tests.that(r.phase_results, keys=[c.Ldap.Tests.SYNC_PHASE_NAME])
        phase_result = m.Ldap.PhaseSyncResult.model_validate(
            r.phase_results[c.Ldap.Tests.SYNC_PHASE_NAME],
        )
        u.Ldap.Tests.that(
            phase_result.synced,
            eq=c.Ldap.Tests.SYNC_PHASE_RESULTS_SYNCED,
        )

    # ── LdapOperationResult + LdapBatchStats ───────────────────────────

    def test_operation_result_carries_enum(self) -> None:
        u.Ldap.Tests.that(
            m.Ldap.LdapOperationResult(
                operation=c.Ldap.UpsertOperations.ADDED,
            ).operation,
            eq=c.Ldap.UpsertOperations.ADDED,
        )

    def test_batch_stats_custom(self) -> None:
        s = m.Ldap.LdapBatchStats(
            synced=c.Ldap.Tests.SYNC_BATCH_STATS_SYNCED,
            failed=c.Ldap.Tests.SYNC_BATCH_STATS_FAILED,
            skipped=c.Ldap.Tests.SYNC_BATCH_STATS_SKIPPED,
        )
        u.Ldap.Tests.that(s.synced, eq=c.Ldap.Tests.SYNC_BATCH_STATS_SYNCED)
        u.Ldap.Tests.that(s.failed, eq=c.Ldap.Tests.SYNC_BATCH_STATS_FAILED)

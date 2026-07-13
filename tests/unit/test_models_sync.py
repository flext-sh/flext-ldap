from __future__ import annotations

import pytest

from tests import c, m, u

pytestmark = pytest.mark.unit


class TestsFlextLdapModelsSync:
    """Behavioral contract of the LDAP sync result models.

    Every test exercises the public model surface only: constructor
    validation, declared field values, computed fields, MRO-inherited
    fields, model_validate coercion, and model_dump round-trips.
    """

    # ── UpsertResult: success / failure contract ───────────────────────

    def test_upsert_success_has_no_error(self) -> None:
        result = m.Ldap.UpsertResult(
            success=True,
            dn=c.Ldap.Tests.RFC_DEFAULT_BASE_DN,
            operation=c.Ldap.OperationType.ADD,
        )
        u.Ldap.Tests.that(result.success, eq=True)
        u.Ldap.Tests.that(result.error, none=True)
        u.Ldap.Tests.that(result.dn, eq=c.Ldap.Tests.RFC_DEFAULT_BASE_DN)

    def test_upsert_failure_carries_error_message(self) -> None:
        result = m.Ldap.UpsertResult(
            success=False,
            dn=c.Ldap.Tests.RFC_DEFAULT_BASE_DN,
            operation=c.Ldap.OperationType.ADD,
            error=c.Ldap.Tests.SYNC_ENTRY_ALREADY_EXISTS,
        )
        u.Ldap.Tests.that(result.success, eq=False)
        u.Ldap.Tests.that(result.error, eq=c.Ldap.Tests.SYNC_ENTRY_ALREADY_EXISTS)

    def test_upsert_defaults_are_empty_and_unsuccessful(self) -> None:
        result = m.Ldap.UpsertResult()
        u.Ldap.Tests.that(result.success, eq=False)
        u.Ldap.Tests.that(result.dn, eq="")
        u.Ldap.Tests.that(result.operation, eq="")
        u.Ldap.Tests.that(result.error, none=True)

    def test_upsert_survives_dump_and_revalidate(self) -> None:
        original = m.Ldap.UpsertResult(
            success=True,
            dn=c.Ldap.Tests.RFC_DEFAULT_BASE_DN,
            operation=c.Ldap.OperationType.ADD,
        )
        restored = m.Ldap.UpsertResult.model_validate(original.model_dump())
        u.Ldap.Tests.that(restored, eq=original)

    # ── BatchUpsertResult: counts + success_rate computed field ────────

    def test_batch_upsert_tracks_all_counts(self) -> None:
        result = m.Ldap.BatchUpsertResult(
            total_processed=c.Ldap.Tests.SYNC_UPSERT_BATCH_TOTAL,
            successful=c.Ldap.Tests.SYNC_UPSERT_BATCH_SUCCESSFUL,
            failed=c.Ldap.Tests.SYNC_UPSERT_BATCH_FAILED,
        )
        u.Ldap.Tests.that(
            result.total_processed,
            eq=c.Ldap.Tests.SYNC_UPSERT_BATCH_TOTAL,
        )
        u.Ldap.Tests.that(
            result.successful,
            eq=c.Ldap.Tests.SYNC_UPSERT_BATCH_SUCCESSFUL,
        )
        u.Ldap.Tests.that(result.failed, eq=c.Ldap.Tests.SYNC_UPSERT_BATCH_FAILED)

    @pytest.mark.parametrize(
        ("total", "successful", "expected_rate"),
        [
            (100, 90, 0.9),
            (10, 10, 1.0),
            (4, 1, 0.25),
            (0, 0, 0.0),
        ],
    )
    def test_batch_upsert_success_rate_is_successful_over_total(
        self,
        total: int,
        successful: int,
        expected_rate: float,
    ) -> None:
        result = m.Ldap.BatchUpsertResult(
            total_processed=total,
            successful=successful,
        )
        u.Ldap.Tests.that(result.success_rate, eq=expected_rate)

    def test_batch_upsert_success_rate_appears_in_dump(self) -> None:
        result = m.Ldap.BatchUpsertResult(total_processed=100, successful=90)
        u.Ldap.Tests.that(result.model_dump(), kv={"success_rate": 0.9})

    def test_batch_upsert_results_validate_to_upsert_models(self) -> None:
        result = m.Ldap.BatchUpsertResult.model_validate({
            "results": [
                {
                    "success": True,
                    "dn": c.Ldap.Tests.RFC_DEFAULT_BASE_DN,
                    "operation": c.Ldap.OperationType.ADD,
                },
            ],
        })
        u.Ldap.Tests.that(result.results[0], is_=m.Ldap.UpsertResult)
        u.Ldap.Tests.that(result.results[0].operation, eq=c.Ldap.OperationType.ADD)

    def test_batch_upsert_defaults_to_empty_results(self) -> None:
        result = m.Ldap.BatchUpsertResult()
        u.Ldap.Tests.that(result.results, empty=True)
        u.Ldap.Tests.that(result.success_rate, eq=0.0)

    # ── ConversionMetadata: tracked change contract ────────────────────

    def test_conversion_metadata_tracks_changes(self) -> None:
        metadata = m.Ldap.ConversionMetadata(
            source_attributes=list(c.Ldap.Tests.SYNC_METADATA_SOURCE_ATTRIBUTES),
            source_dn=c.Ldap.Tests.ENTRY_DN_USER_EXAMPLE,
            removed_attributes=list(c.Ldap.Tests.SYNC_METADATA_REMOVED_ATTRIBUTES),
            dn_changed=True,
            converted_dn=c.Ldap.Tests.ENTRY_DN_USER_NEW,
        )
        u.Ldap.Tests.that(
            metadata.source_attributes,
            len=len(c.Ldap.Tests.SYNC_METADATA_SOURCE_ATTRIBUTES),
        )
        u.Ldap.Tests.that(
            metadata.removed_attributes,
            has=c.Ldap.Tests.SYNC_METADATA_REMOVED_ATTRIBUTES[0],
        )
        u.Ldap.Tests.that(metadata.dn_changed, eq=True)
        u.Ldap.Tests.that(metadata.converted_dn, eq=c.Ldap.Tests.ENTRY_DN_USER_NEW)

    def test_conversion_metadata_defaults_report_no_changes(self) -> None:
        metadata = m.Ldap.ConversionMetadata()
        u.Ldap.Tests.that(metadata.source_attributes, empty=True)
        u.Ldap.Tests.that(metadata.removed_attributes, empty=True)
        u.Ldap.Tests.that(metadata.dn_changed, eq=False)
        u.Ldap.Tests.that(metadata.source_dn, eq="")

    # ── PhaseSyncResult: stats + LdapBatchStats inheritance ────────────

    def test_phase_sync_result_captures_phase_stats(self) -> None:
        result = m.Ldap.PhaseSyncResult(
            phase_name=c.Ldap.Tests.SYNC_PHASE_NAME,
            total_entries=c.Ldap.Tests.SYNC_PHASE_TOTAL_ENTRIES,
            synced=c.Ldap.Tests.SYNC_PHASE_SYNCED,
            failed=c.Ldap.Tests.SYNC_PHASE_FAILED,
            skipped=c.Ldap.Tests.SYNC_PHASE_SKIPPED,
            duration_seconds=c.Ldap.Tests.SYNC_PHASE_DURATION,
            success_rate=c.Ldap.Tests.SYNC_PHASE_SUCCESS_RATE,
        )
        u.Ldap.Tests.that(result.phase_name, eq=c.Ldap.Tests.SYNC_PHASE_NAME)
        u.Ldap.Tests.that(result.synced, eq=c.Ldap.Tests.SYNC_PHASE_SYNCED)
        u.Ldap.Tests.that(result.success_rate, eq=c.Ldap.Tests.SYNC_PHASE_SUCCESS_RATE)

    def test_phase_sync_result_exposes_inherited_batch_counters(self) -> None:
        result = m.Ldap.PhaseSyncResult(
            phase_name=c.Ldap.Tests.SYNC_PHASE_NAME,
            synced=c.Ldap.Tests.SYNC_PHASE_SYNCED,
            failed=c.Ldap.Tests.SYNC_PHASE_FAILED,
            skipped=c.Ldap.Tests.SYNC_PHASE_SKIPPED,
        )
        u.Ldap.Tests.that(
            result,
            attr_eq={
                "synced": c.Ldap.Tests.SYNC_PHASE_SYNCED,
                "failed": c.Ldap.Tests.SYNC_PHASE_FAILED,
                "skipped": c.Ldap.Tests.SYNC_PHASE_SKIPPED,
            },
        )

    def test_phase_sync_result_defaults_to_zero_counters(self) -> None:
        result = m.Ldap.PhaseSyncResult()
        u.Ldap.Tests.that(
            result,
            attr_eq={
                "synced": c.Ldap.Tests.SYNC_DEFAULT_ZERO_COUNT,
                "failed": c.Ldap.Tests.SYNC_DEFAULT_ZERO_COUNT,
                "skipped": c.Ldap.Tests.SYNC_DEFAULT_ZERO_COUNT,
                "total_entries": c.Ldap.Tests.SYNC_DEFAULT_ZERO_COUNT,
            },
        )
        u.Ldap.Tests.that(result.success_rate, eq=0.0)

    # ── MultiPhaseSyncResult: aggregation + nested validation ──────────

    def test_multi_phase_aggregates_overall_totals(self) -> None:
        result = m.Ldap.MultiPhaseSyncResult(
            total_entries=c.Ldap.Tests.SYNC_MULTI_PHASE_TOTAL_ENTRIES,
            total_synced=c.Ldap.Tests.SYNC_MULTI_PHASE_TOTAL_SYNCED,
            total_failed=c.Ldap.Tests.SYNC_MULTI_PHASE_TOTAL_FAILED,
            total_skipped=c.Ldap.Tests.SYNC_MULTI_PHASE_TOTAL_SKIPPED,
            overall_success_rate=c.Ldap.Tests.SYNC_MULTI_PHASE_OVERALL_SUCCESS_RATE,
            total_duration_seconds=c.Ldap.Tests.SYNC_MULTI_PHASE_TOTAL_DURATION,
            overall_success=True,
        )
        u.Ldap.Tests.that(
            result.total_synced,
            eq=c.Ldap.Tests.SYNC_MULTI_PHASE_TOTAL_SYNCED,
        )
        u.Ldap.Tests.that(result.overall_success, eq=True)

    def test_multi_phase_defaults_report_empty_success(self) -> None:
        result = m.Ldap.MultiPhaseSyncResult()
        u.Ldap.Tests.that(result.phase_results, empty=True)
        u.Ldap.Tests.that(result.overall_success, eq=True)
        u.Ldap.Tests.that(result.total_synced, eq=c.Ldap.Tests.SYNC_DEFAULT_ZERO_COUNT)

    def test_multi_phase_retains_typed_phase_result(self) -> None:
        phase = m.Ldap.PhaseSyncResult(
            phase_name=c.Ldap.Tests.SYNC_PHASE_NAME,
            total_entries=c.Ldap.Tests.SYNC_PHASE_TOTAL_ENTRIES,
            synced=c.Ldap.Tests.SYNC_PHASE_RESULTS_SYNCED,
            failed=c.Ldap.Tests.SYNC_PHASE_RESULTS_FAILED,
            skipped=c.Ldap.Tests.SYNC_PHASE_RESULTS_SKIPPED,
            duration_seconds=c.Ldap.Tests.SYNC_PHASE_RESULTS_DURATION,
            success_rate=c.Ldap.Tests.SYNC_PHASE_RESULTS_SUCCESS_RATE,
        )
        result = m.Ldap.MultiPhaseSyncResult(
            phase_results={c.Ldap.Tests.SYNC_PHASE_NAME: phase},
        )
        u.Ldap.Tests.that(result.phase_results, keys=[c.Ldap.Tests.SYNC_PHASE_NAME])
        stored = result.phase_results[c.Ldap.Tests.SYNC_PHASE_NAME]
        u.Ldap.Tests.that(stored, is_=m.Ldap.PhaseSyncResult)
        u.Ldap.Tests.that(stored.synced, eq=c.Ldap.Tests.SYNC_PHASE_RESULTS_SYNCED)

    def test_multi_phase_coerces_dict_payloads_to_phase_models(self) -> None:
        result = m.Ldap.MultiPhaseSyncResult.model_validate({
            "phase_results": {
                c.Ldap.Tests.SYNC_PHASE_NAME: {
                    "phase_name": c.Ldap.Tests.SYNC_PHASE_NAME,
                    "total_entries": c.Ldap.Tests.SYNC_PHASE_TOTAL_ENTRIES,
                    "synced": c.Ldap.Tests.SYNC_PHASE_RESULTS_SYNCED,
                    "failed": c.Ldap.Tests.SYNC_PHASE_RESULTS_FAILED,
                    "skipped": c.Ldap.Tests.SYNC_PHASE_RESULTS_SKIPPED,
                    "duration_seconds": c.Ldap.Tests.SYNC_PHASE_RESULTS_DURATION,
                    "success_rate": c.Ldap.Tests.SYNC_PHASE_RESULTS_SUCCESS_RATE,
                },
            },
        })
        phase_result = result.phase_results[c.Ldap.Tests.SYNC_PHASE_NAME]
        u.Ldap.Tests.that(phase_result, is_=m.Ldap.PhaseSyncResult)
        u.Ldap.Tests.that(
            phase_result.synced,
            eq=c.Ldap.Tests.SYNC_PHASE_RESULTS_SYNCED,
        )

    # ── LdapOperationResult: field + factory contract ──────────────────

    def test_operation_result_carries_enum(self) -> None:
        result = m.Ldap.LdapOperationResult(
            operation=c.Ldap.UpsertOperation.ADDED,
        )
        u.Ldap.Tests.that(result.operation, eq=c.Ldap.UpsertOperation.ADDED)

    def test_operation_result_factory_builds_from_operation(self) -> None:
        result = m.Ldap.LdapOperationResult.with_operation(
            c.Ldap.UpsertOperation.ADDED,
        )
        u.Ldap.Tests.that(result, is_=m.Ldap.LdapOperationResult)
        u.Ldap.Tests.that(result.operation, eq=c.Ldap.UpsertOperation.ADDED)

    # ── LdapBatchStats: counters + validation invariants ───────────────

    def test_batch_stats_custom_counts(self) -> None:
        stats = m.Ldap.LdapBatchStats(
            synced=c.Ldap.Tests.SYNC_BATCH_STATS_SYNCED,
            failed=c.Ldap.Tests.SYNC_BATCH_STATS_FAILED,
            skipped=c.Ldap.Tests.SYNC_BATCH_STATS_SKIPPED,
        )
        u.Ldap.Tests.that(
            stats,
            attr_eq={
                "synced": c.Ldap.Tests.SYNC_BATCH_STATS_SYNCED,
                "failed": c.Ldap.Tests.SYNC_BATCH_STATS_FAILED,
                "skipped": c.Ldap.Tests.SYNC_BATCH_STATS_SKIPPED,
            },
        )

    def test_batch_stats_defaults_to_zero(self) -> None:
        stats = m.Ldap.LdapBatchStats()
        u.Ldap.Tests.that(
            stats,
            attr_eq={
                "synced": c.Ldap.Tests.SYNC_DEFAULT_ZERO_COUNT,
                "failed": c.Ldap.Tests.SYNC_DEFAULT_ZERO_COUNT,
                "skipped": c.Ldap.Tests.SYNC_DEFAULT_ZERO_COUNT,
            },
        )

    @pytest.mark.parametrize("field", ["synced", "failed", "skipped"])
    def test_batch_stats_rejects_negative_counters(self, field: str) -> None:
        with pytest.raises(c.ValidationError):
            m.Ldap.LdapBatchStats(**{field: -1})

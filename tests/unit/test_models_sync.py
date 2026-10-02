"""Tests for models sync."""

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

    @staticmethod
    def test_upsert_success_has_no_error() -> None:
        """Verify upsert success has no error."""
        result = m.Ldap.UpsertResult(
            success=True,
            dn=c.Ldap.Tests.RFC_DEFAULT_BASE_DN,
            operation=c.Ldap.OperationType.ADD,
        )
        u.Ldap.Tests.that(result.success, eq=True)
        u.Ldap.Tests.that(result.error, none=True)
        u.Ldap.Tests.that(result.dn, eq=c.Ldap.Tests.RFC_DEFAULT_BASE_DN)

    @staticmethod
    def test_upsert_failure_carries_error_message() -> None:
        """Verify upsert failure carries error message."""
        result = m.Ldap.UpsertResult(
            success=False,
            dn=c.Ldap.Tests.RFC_DEFAULT_BASE_DN,
            operation=c.Ldap.OperationType.ADD,
            error=c.Ldap.Tests.SYNC_ENTRY_ALREADY_EXISTS,
        )
        u.Ldap.Tests.that(result.success, eq=False)
        u.Ldap.Tests.that(result.error, eq=c.Ldap.Tests.SYNC_ENTRY_ALREADY_EXISTS)

    @staticmethod
    def test_upsert_defaults_are_empty_and_unsuccessful() -> None:
        """Verify upsert defaults are empty and unsuccessful."""
        result = m.Ldap.UpsertResult()
        u.Ldap.Tests.that(result.success, eq=False)
        u.Ldap.Tests.that(result.dn, eq="")
        u.Ldap.Tests.that(result.operation, eq="")
        u.Ldap.Tests.that(result.error, none=True)

    @staticmethod
    def test_upsert_survives_dump_and_revalidate() -> None:
        """Verify upsert survives dump and revalidate."""
        original = m.Ldap.UpsertResult(
            success=True,
            dn=c.Ldap.Tests.RFC_DEFAULT_BASE_DN,
            operation=c.Ldap.OperationType.ADD,
        )
        restored = m.Ldap.UpsertResult.model_validate(original.model_dump())
        u.Ldap.Tests.that(restored, eq=original)

    # ── BatchUpsertResult: counts + success_rate computed field ────────

    @staticmethod
    def test_batch_upsert_tracks_all_counts() -> None:
        """Verify batch upsert tracks all counts."""
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
        [(100, 90, 0.9), (10, 10, 1.0), (4, 1, 0.25), (0, 0, 0.0)],
    )
    @staticmethod
    def test_batch_upsert_success_rate_is_successful_over_total(
        total: int,
        successful: int,
        expected_rate: float,
    ) -> None:
        """Verify batch upsert success rate is successful over total."""
        result = m.Ldap.BatchUpsertResult(total_processed=total, successful=successful)
        u.Ldap.Tests.that(result.success_rate, eq=expected_rate)

    @staticmethod
    def test_batch_upsert_success_rate_appears_in_dump() -> None:
        """Verify batch upsert success rate appears in dump."""
        result = m.Ldap.BatchUpsertResult(total_processed=100, successful=90)
        u.Ldap.Tests.that(result.model_dump(), kv={"success_rate": 0.9})

    @staticmethod
    def test_batch_upsert_results_validate_to_upsert_models() -> None:
        """Verify batch upsert results validate to upsert models."""
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

    @staticmethod
    def test_batch_upsert_defaults_to_empty_results() -> None:
        """Verify batch upsert defaults to empty results."""
        result = m.Ldap.BatchUpsertResult()
        u.Ldap.Tests.that(result.results, empty=True)
        u.Ldap.Tests.that(result.success_rate, eq=0.0)

    # ── ConversionMetadata: tracked change contract ────────────────────

    @staticmethod
    def test_conversion_metadata_tracks_changes() -> None:
        """Verify conversion metadata tracks changes."""
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

    @staticmethod
    def test_conversion_metadata_defaults_report_no_changes() -> None:
        """Verify conversion metadata defaults report no changes."""
        metadata = m.Ldap.ConversionMetadata()
        u.Ldap.Tests.that(metadata.source_attributes, empty=True)
        u.Ldap.Tests.that(metadata.removed_attributes, empty=True)
        u.Ldap.Tests.that(metadata.dn_changed, eq=False)
        u.Ldap.Tests.that(metadata.source_dn, eq="")

    # ── PhaseSyncResult: stats + LdapBatchStats inheritance ────────────

    @staticmethod
    def test_phase_sync_result_captures_phase_stats() -> None:
        """Verify phase sync result captures phase stats."""
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

    @staticmethod
    def test_phase_sync_result_exposes_inherited_batch_counters() -> None:
        """Verify phase sync result exposes inherited batch counters."""
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

    @staticmethod
    def test_phase_sync_result_defaults_to_zero_counters() -> None:
        """Verify phase sync result defaults to zero counters."""
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

    @staticmethod
    def test_multi_phase_aggregates_overall_totals() -> None:
        """Verify multi phase aggregates overall totals."""
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

    @staticmethod
    def test_multi_phase_defaults_report_empty_success() -> None:
        """Verify multi phase defaults report empty success."""
        result = m.Ldap.MultiPhaseSyncResult()
        u.Ldap.Tests.that(result.phase_results, empty=True)
        u.Ldap.Tests.that(result.overall_success, eq=True)
        u.Ldap.Tests.that(result.total_synced, eq=c.Ldap.Tests.SYNC_DEFAULT_ZERO_COUNT)

    @staticmethod
    def test_multi_phase_retains_typed_phase_result() -> None:
        """Verify multi phase retains typed phase result."""
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

    @staticmethod
    def test_multi_phase_coerces_dict_payloads_to_phase_models() -> None:
        """Verify multi phase coerces dict payloads to phase models."""
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

    @staticmethod
    def test_operation_result_carries_enum() -> None:
        """Verify operation result carries enum."""
        result = m.Ldap.LdapOperationResult(operation=c.Ldap.UpsertOperation.ADDED)
        u.Ldap.Tests.that(result.operation, eq=c.Ldap.UpsertOperation.ADDED)

    @staticmethod
    def test_operation_result_factory_builds_from_operation() -> None:
        """Verify operation result factory builds from operation."""
        result = m.Ldap.LdapOperationResult(operation=c.Ldap.UpsertOperation.ADDED)
        u.Ldap.Tests.that(result, is_=m.Ldap.LdapOperationResult)
        u.Ldap.Tests.that(result.operation, eq=c.Ldap.UpsertOperation.ADDED)

    # ── LdapBatchStats: counters + validation invariants ───────────────

    @staticmethod
    def test_batch_stats_custom_counts() -> None:
        """Verify batch stats custom counts."""
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

    @staticmethod
    def test_batch_stats_defaults_to_zero() -> None:
        """Verify batch stats defaults to zero."""
        stats = m.Ldap.LdapBatchStats()
        u.Ldap.Tests.that(
            stats,
            attr_eq={
                "synced": c.Ldap.Tests.SYNC_DEFAULT_ZERO_COUNT,
                "failed": c.Ldap.Tests.SYNC_DEFAULT_ZERO_COUNT,
                "skipped": c.Ldap.Tests.SYNC_DEFAULT_ZERO_COUNT,
            },
        )

    @staticmethod
    @pytest.mark.parametrize("field", ["synced", "failed", "skipped"])
    def test_batch_stats_rejects_negative_counters(field: str) -> None:
        """Verify batch stats rejects negative counters."""
        with pytest.raises(c.ValidationError):
            m.Ldap.LdapBatchStats(**{field: -1})

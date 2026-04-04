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
        (m.Ldap.SyncOptions, "auto_create_parents", True),
        (m.Ldap.SyncOptions, "allow_deletes", False),
        (m.Ldap.SyncStats, "synced", 0),
        (m.Ldap.SyncStats, "total", 0),
        (m.Ldap.SyncPhaseConfig, "server_type", c.Ldap.ServerDefaults.DEFAULT_TYPE),
        (
            m.Ldap.SyncPhaseConfig,
            "max_retries",
            c.Ldap.ConnectionDefaults.DEFAULT_MAX_RETRIES,
        ),
        (m.Ldap.SyncPhaseConfig, "stop_on_error", False),
        (m.Ldap.LdapBatchStats, "synced", 0),
        (m.Ldap.LdapBatchStats, "failed", 0),
        (m.Ldap.ConversionMetadata, "dn_changed", False),
        (m.Ldap.ConversionMetadata, "source_dn", ""),
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
        ("zero total", m.Ldap.SyncStats, dict[str, int](), 0.0),
        (
            "90% rate",
            m.Ldap.SyncStats,
            {"synced": 70, "skipped": 20, "failed": 10, "total": 100},
            0.9,
        ),
        (
            "batch zero",
            m.Ldap.BatchUpsertResult,
            {"total_processed": 0, "successful": 0, "failed": 0},
            0.0,
        ),
        (
            "batch 85%",
            m.Ldap.BatchUpsertResult,
            {"total_processed": 100, "successful": 85, "failed": 15},
            0.85,
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
            synced=50,
            skipped=30,
            failed=20,
            duration_seconds=10.5,
        )
        tm.that(s.total, eq=100)
        tm.that(s.duration_seconds, eq=10.5)
        tm.that(s.success_rate, eq=0.8)

    def test_from_counters_serialization_includes_computed(self) -> None:
        tm.that(
            m.Ldap.SyncStats.from_counters(synced=9, skipped=1, failed=0).model_dump(),
            has="success_rate",
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
            error="Entry already exists",
        )
        tm.that(not r.success, eq=True)
        tm.that(r.error, eq="Entry already exists")

    def test_batch_upsert_tracks_all_counts(self) -> None:
        r = m.Ldap.BatchUpsertResult(total_processed=100, successful=90, failed=10)
        tm.that(r.total_processed, eq=100)
        tm.that(r.successful, eq=90)
        tm.that(r.failed, eq=10)

    # ── ConversionMetadata: tracks attribute changes ───────────────────

    def test_conversion_metadata_tracks_changes(self) -> None:
        md = m.Ldap.ConversionMetadata(
            source_attributes=["cn", "mail", "telephoneNumber"],
            source_dn=c.Ldap.Tests.EntryDN.USER_EXAMPLE,
            removed_attributes=["userPassword"],
            dn_changed=True,
            converted_dn=c.Ldap.Tests.EntryDN.USER_NEW,
        )
        tm.that(md.source_attributes, len=3)
        tm.that(md.removed_attributes, contains="userPassword")
        tm.that(md.dn_changed, eq=True)

    # ── PhaseSyncResult + MultiPhase aggregation ───────────────────────

    def test_phase_sync_result_captures_phase_stats(self) -> None:
        r = m.Ldap.PhaseSyncResult(
            phase_name="01-users",
            total_entries=100,
            synced=90,
            failed=5,
            skipped=5,
            duration_seconds=30.0,
            success_rate=95.0,
        )
        tm.that(r.phase_name, eq="01-users")
        tm.that(r.synced, eq=90)
        tm.that(r.success_rate, eq=95.0)

    def test_multi_phase_aggregates_overall(self) -> None:
        r = m.Ldap.MultiPhaseSyncResult(
            total_entries=500,
            total_synced=450,
            total_failed=25,
            total_skipped=25,
            overall_success_rate=95.0,
            total_duration_seconds=120.0,
            overall_success=True,
        )
        tm.that(r.total_synced, eq=450)
        tm.that(r.overall_success, eq=True)

    def test_multi_phase_with_phase_results_dict(self) -> None:
        phase = m.Ldap.PhaseSyncResult(
            phase_name="01-users",
            total_entries=100,
            synced=95,
            failed=5,
            skipped=0,
            duration_seconds=10.0,
            success_rate=95.0,
        )
        r = m.Ldap.MultiPhaseSyncResult(
            phase_results={"01-users": phase},
            total_entries=100,
            total_synced=95,
            total_failed=5,
            total_skipped=0,
            overall_success_rate=95.0,
            total_duration_seconds=10.0,
        )
        tm.that(r.phase_results, keys=["01-users"])
        tm.that(r.phase_results["01-users"].synced, eq=95)

    # ── LdapOperationResult + LdapBatchStats ───────────────────────────

    def test_operation_result_carries_enum(self) -> None:
        tm.that(
            m.Ldap.LdapOperationResult(
                operation=c.Ldap.UpsertOperations.ADDED,
            ).operation,
            eq=c.Ldap.UpsertOperations.ADDED,
        )

    def test_batch_stats_custom(self) -> None:
        s = m.Ldap.LdapBatchStats(synced=80, failed=10, skipped=10)
        tm.that(s.synced, eq=80)
        tm.that(s.failed, eq=10)

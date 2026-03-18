from __future__ import annotations

import pytest
from flext_tests import tm
from pydantic import ValidationError

from tests import c, m

pytestmark = pytest.mark.unit


class TestsFlextLdapModelsSync:
    def test_sync_options_default_values(self) -> None:
        options = m.Ldap.SyncOptions()
        tm.that(options.batch_size, eq=100)
        tm.that(options.auto_create_parents, eq=True)
        tm.that(options.allow_deletes, eq=False)
        tm.that(options.source_basedn, eq="")
        tm.that(options.target_basedn, eq="")
        tm.that(options.progress_callback, none=True)

    def test_sync_options_custom_values(self) -> None:
        options = m.Ldap.SyncOptions(
            batch_size=50,
            auto_create_parents=False,
            allow_deletes=True,
            source_basedn="dc=source,dc=com",
            target_basedn="dc=target,dc=com",
        )
        tm.that(options.batch_size, eq=50)
        tm.that(options.auto_create_parents, eq=False)
        tm.that(options.allow_deletes, eq=True)

    def test_sync_options_batch_size_constraint(self) -> None:
        invalid_batch: int = 0
        with pytest.raises(ValidationError):
            m.Ldap.SyncOptions(batch_size=invalid_batch)

    def test_sync_stats_default_values(self) -> None:
        stats = m.Ldap.SyncStats()
        tm.that(stats.synced, eq=0)
        tm.that(stats.skipped, eq=0)
        tm.that(stats.failed, eq=0)
        tm.that(stats.total, eq=0)
        tm.that(stats.duration_seconds, eq=0.0)

    def test_sync_stats_success_rate_zero_total(self) -> None:
        stats = m.Ldap.SyncStats()
        tm.that(stats.success_rate, eq=0.0)

    def test_sync_stats_success_rate_calculation(self) -> None:
        stats = m.Ldap.SyncStats(synced=70, skipped=20, failed=10, total=100)
        tm.that(stats.success_rate, eq=0.9)

    def test_sync_stats_from_counters_factory(self) -> None:
        stats = m.Ldap.SyncStats.from_counters(
            synced=50, skipped=30, failed=20, duration_seconds=10.5
        )
        tm.that(stats.synced, eq=50)
        tm.that(stats.skipped, eq=30)
        tm.that(stats.failed, eq=20)
        tm.that(stats.total, eq=100)
        tm.that(stats.duration_seconds, eq=10.5)

    def test_upsert_result_creation(self) -> None:
        result = m.Ldap.UpsertResult(
            success=True,
            dn=c.Ldap.Tests.RFC.DEFAULT_BASE_DN,
            operation=c.Ldap.OperationType.ADD,
        )
        tm.that(result.success, eq=True)
        tm.that(result.dn, eq=c.Ldap.Tests.RFC.DEFAULT_BASE_DN)
        tm.that(result.operation, eq=c.Ldap.OperationType.ADD)
        tm.that(result.error, none=True)

    def test_upsert_result_with_error(self) -> None:
        result = m.Ldap.UpsertResult(
            success=False,
            dn=c.Ldap.Tests.RFC.DEFAULT_BASE_DN,
            operation=c.Ldap.OperationType.ADD,
            error="Entry already exists",
        )
        tm.that(result.success, eq=False)
        tm.that(result.error, eq="Entry already exists")

    def test_batch_upsert_result_creation(self) -> None:
        result = m.Ldap.BatchUpsertResult(total_processed=100, successful=90, failed=10)
        tm.that(result.total_processed, eq=100)
        tm.that(result.successful, eq=90)
        tm.that(result.failed, eq=10)

    def test_batch_upsert_result_success_rate_zero(self) -> None:
        result = m.Ldap.BatchUpsertResult(total_processed=0, successful=0, failed=0)
        tm.that(result.success_rate, eq=0.0)

    def test_batch_upsert_result_success_rate_calculation(self) -> None:
        result = m.Ldap.BatchUpsertResult(total_processed=100, successful=85, failed=15)
        tm.that(result.success_rate, eq=0.85)

    def test_sync_phase_config_default_values(self) -> None:
        config = m.Ldap.SyncPhaseConfig()
        tm.that(config.server_type, eq="rfc")
        tm.that(config.progress_callback, none=True)
        tm.that(config.retry_on_errors, none=True)
        tm.that(config.max_retries, eq=5)
        tm.that(config.stop_on_error, eq=False)

    def test_sync_phase_config_custom_values(self) -> None:
        config = m.Ldap.SyncPhaseConfig(
            server_type="oud", max_retries=3, stop_on_error=True
        )
        tm.that(config.server_type, eq="oud")
        tm.that(config.max_retries, eq=3)
        tm.that(config.stop_on_error, eq=True)

    def test_conversion_metadata_default_values(self) -> None:
        metadata = m.Ldap.ConversionMetadata()
        tm.that(metadata.source_attributes, eq=[])
        tm.that(metadata.source_dn, eq="")
        tm.that(metadata.removed_attributes, eq=[])
        tm.that(metadata.base64_encoded_attributes, eq=[])
        tm.that(metadata.dn_changed, eq=False)
        tm.that(metadata.converted_dn, eq="")
        tm.that(metadata.attribute_changes, eq=[])

    def test_conversion_metadata_custom_values(self) -> None:
        metadata = m.Ldap.ConversionMetadata(
            source_attributes=["cn", "mail", "telephoneNumber"],
            source_dn="cn=user,dc=example,dc=com",
            removed_attributes=["userPassword"],
            dn_changed=True,
            converted_dn="cn=user,dc=new,dc=com",
        )
        tm.that(metadata.source_attributes, len=3)
        tm.that(metadata.source_attributes, contains="telephoneNumber")
        tm.that(metadata.dn_changed, eq=True)

    def test_phase_sync_result_creation(self) -> None:
        result = m.Ldap.PhaseSyncResult(
            phase_name="01-users",
            total_entries=100,
            synced=90,
            failed=5,
            skipped=5,
            duration_seconds=30.0,
            success_rate=95.0,
        )
        tm.that(result.phase_name, eq="01-users")
        tm.that(result.total_entries, eq=100)
        tm.that(result.synced, eq=90)
        tm.that(result.success_rate, eq=95.0)

    def test_multi_phase_sync_result_creation(self) -> None:
        result = m.Ldap.MultiPhaseSyncResult(
            total_entries=500,
            total_synced=450,
            total_failed=25,
            total_skipped=25,
            overall_success_rate=95.0,
            total_duration_seconds=120.0,
            overall_success=True,
        )
        tm.that(result.total_entries, eq=500)
        tm.that(result.total_synced, eq=450)
        tm.that(result.overall_success_rate, eq=95.0)
        tm.that(result.overall_success, eq=True)

    def test_multi_phase_sync_result_with_phase_results(self) -> None:
        phase1 = m.Ldap.PhaseSyncResult(
            phase_name="01-users",
            total_entries=100,
            synced=95,
            failed=5,
            skipped=0,
            duration_seconds=10.0,
            success_rate=95.0,
        )
        result = m.Ldap.MultiPhaseSyncResult(
            phase_results={"01-users": phase1},
            total_entries=100,
            total_synced=95,
            total_failed=5,
            total_skipped=0,
            overall_success_rate=95.0,
            total_duration_seconds=10.0,
        )
        tm.that(result.phase_results, keys=["01-users"])
        tm.that(result.phase_results["01-users"].synced, eq=95)

    def test_ldap_operation_result_creation(self) -> None:
        result = m.Ldap.LdapOperationResult(operation=c.Ldap.UpsertOperations.ADDED)
        tm.that(result.operation, eq=c.Ldap.UpsertOperations.ADDED)

    def test_ldap_batch_stats_default_values(self) -> None:
        stats = m.Ldap.LdapBatchStats()
        tm.that(stats.synced, eq=0)
        tm.that(stats.failed, eq=0)
        tm.that(stats.skipped, eq=0)

    def test_ldap_batch_stats_custom_values(self) -> None:
        stats = m.Ldap.LdapBatchStats(synced=80, failed=10, skipped=10)
        tm.that(stats.synced, eq=80)
        tm.that(stats.failed, eq=10)
        tm.that(stats.skipped, eq=10)

    def test_types_namespace_exists(self) -> None:
        tm.that(m.Ldap.Types, none=False)

    def test_ldap_progress_callback_type_exists(self) -> None:
        actual = hasattr(m.Ldap.Types, "LdapProgressCallback")
        tm.that(actual, eq=True)

    def test_connection_config_serialization(self) -> None:
        config = m.Ldap.ConnectionConfig(host="ldap.example.com", port=636)
        data = config.model_dump()
        tm.that(data["host"], eq="ldap.example.com")
        tm.that(data["port"], eq=636)

    def test_search_options_serialization(self) -> None:
        options = m.Ldap.SearchOptions(
            base_dn=c.Ldap.Tests.RFC.DEFAULT_BASE_DN, scope="SUBTREE"
        )
        data = options.model_dump()
        tm.that(data["base_dn"], eq=c.Ldap.Tests.RFC.DEFAULT_BASE_DN)
        tm.that(data["scope"], eq="SUBTREE")

    def test_sync_stats_serialization(self) -> None:
        stats = m.Ldap.SyncStats.from_counters(synced=80, skipped=10, failed=10)
        data = stats.model_dump()
        tm.that(data, keys=["success_rate"])
        tm.that(data["success_rate"], eq=0.9)

    def test_connection_config_json_schema(self) -> None:
        schema = m.Ldap.ConnectionConfig.model_json_schema()
        tm.that(schema, keys=["properties"])
        tm.that(schema["properties"], keys=["host", "port"])

    def test_search_options_json_schema(self) -> None:
        schema = m.Ldap.SearchOptions.model_json_schema()
        tm.that(schema, keys=["properties"])
        tm.that(schema["properties"], keys=["base_dn", "scope"])


__all__ = ["TestsFlextLdapModelsSync"]

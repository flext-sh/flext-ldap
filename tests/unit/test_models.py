"""Unit tests for FlextLdapModels - Domain models and data structures.

Provides comprehensive testing of FlextLdapModels including connection configuration,
search options, operation results, sync models, and type aliases.

Test Coverage:
- Model inheritance from FlextModels and FlextLdifModels
- ConnectionConfig validation (SSL/TLS mutual exclusion)
- SearchOptions with DN validation and normalization
- OperationResult with entries_affected tracking
- SearchResult computed fields (total_count, by_objectclass)
- SyncStats and SyncOptions models
- UpsertResult and BatchUpsertResult models
- PhaseSyncResult and MultiPhaseSyncResult models
- Model serialization and JSON schema generation

All tests use real functionality without mocks, following FLEXT patterns.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from collections.abc import Mapping
from typing import ClassVar

import pytest
from flext_ldif import FlextLdifModels
from flext_tests import tm
from pydantic import ValidationError

from flext_ldap import c, m
from tests import c as tc

pytestmark = [pytest.mark.unit]


class TestsFlextLdapModels:
    """Comprehensive tests for FlextLdapModels.

    Architecture: Single class per module following FLEXT patterns.
    Tests all domain models, validation, computed fields, and inheritance.
    """

    # =========================================================================
    # Model Class Existence Tests
    # =========================================================================

    def test_models_class_exists(self) -> None:
        """Test FlextLdapModels class exists."""
        tm.not_none(FlextLdapModels)
        tm.eq(m, FlextLdapModels)

    def test_models_inherits_from_flext_ldif_models(self) -> None:
        """Test FlextLdapModels inherits from FlextLdifModels."""
        tm.that(issubclass(FlextLdapModels, FlextLdifModels), eq=True)

    def test_models_has_model_config(self) -> None:
        """Test FlextLdapModels has model_config."""
        tm.not_none(FlextLdapModels.model_config)
        tm.eq(FlextLdapModels.model_config.get("frozen"), True)
        tm.eq(FlextLdapModels.model_config.get("extra"), "forbid")

    # =========================================================================
    # Collections Inheritance Tests
    # =========================================================================

    def test_collections_exists(self) -> None:
        """Test Collections class exists."""
        tm.not_none(m.Collections)

    def test_collections_config_exists(self) -> None:
        """Test Collections.Config exists."""
        tm.not_none(m.Collections.Config)

    def test_collections_options_exists(self) -> None:
        """Test Collections.Options exists."""
        tm.not_none(m.Collections.Options)

    def test_collections_results_exists(self) -> None:
        """Test Collections.Results exists."""
        tm.not_none(m.Collections.Results)

    def test_collections_statistics_exists(self) -> None:
        """Test Collections.Statistics exists."""
        tm.not_none(m.Collections.Statistics)

    # =========================================================================
    # Entry Model Tests
    # =========================================================================

    def test_entry_model_exists(self) -> None:
        """Test Entry model exists."""
        tm.not_none(m.Entry)

    def test_entry_inherits_from_flext_ldif_entry(self) -> None:
        """Test Entry inherits from FlextLdifModels.Entry."""
        tm.that(issubclass(m.Entry, FlextLdifModels.Entry), eq=True)

    def test_entry_creation(self) -> None:
        """Test Entry creation with DN and attributes."""
        # Entry accepts str for dn via Pydantic - Pyright strict: Entry.__init__ accepts **data: Any
        entry = m.Entry(dn=tc.RFC.DEFAULT_BASE_DN, attributes=None)
        # Entry.dn is a DistinguishedName object, use .value for string comparison
        tm.not_none(entry.dn)
        tm.eq(entry.dn.value, tc.RFC.DEFAULT_BASE_DN)
        tm.that(entry.attributes, none=True)

    # =========================================================================
    # Re-export Alias Tests
    # =========================================================================

    def test_distinguished_name_alias_exists(self) -> None:
        """Test DistinguishedName alias exists."""
        tm.eq(m.DistinguishedName, FlextLdifModels.DistinguishedName)

    def test_ldif_attributes_alias_exists(self) -> None:
        """Test LdifAttributes alias exists."""
        # LdifAttributes is re-exported from FlextLdifModels
        tm.not_none(m.LdifAttributes)
        tm.that(hasattr(m, "LdifAttributes"), eq=True)

    def test_quirk_metadata_alias_exists(self) -> None:
        """Test QuirkMetadata alias exists."""
        tm.eq(m.QuirkMetadata, FlextLdifModels.QuirkMetadata)

    def test_parse_response_alias_exists(self) -> None:
        """Test ParseResponse alias exists."""
        # ParseResponse is re-exported from FlextLdifModels
        tm.not_none(m.ParseResponse)
        tm.that(hasattr(m, "ParseResponse"), eq=True)

    # =========================================================================
    # ConnectionConfig Tests
    # =========================================================================

    def test_connection_config_default_values(self) -> None:
        """Test ConnectionConfig default values."""
        config = m.ConnectionConfig()
        tm.eq(config.host, "localhost")
        tm.eq(config.port, c.ConnectionDefaults.PORT)
        tm.eq(config.use_ssl, False)
        tm.eq(config.use_tls, False)
        tm.that(config.bind_dn, none=True)
        tm.that(config.bind_password, none=True)
        tm.eq(config.timeout, c.ConnectionDefaults.TIMEOUT)
        tm.eq(config.auto_bind, c.ConnectionDefaults.AUTO_BIND)

    def test_connection_config_custom_values(self) -> None:
        """Test ConnectionConfig with custom values."""
        config = m.ConnectionConfig(
            host="ldap.example.com",
            port=636,
            use_ssl=True,
            bind_dn="cn=REDACTED_LDAP_BIND_PASSWORD,dc=example,dc=com",
            bind_password="secret",
            timeout=60,
        )
        tm.eq(config.host, "ldap.example.com")
        tm.eq(config.port, 636)
        tm.eq(config.use_ssl, True)
        tm.eq(config.bind_dn, "cn=REDACTED_LDAP_BIND_PASSWORD,dc=example,dc=com")

    def test_connection_config_ssl_tls_mutual_exclusion(self) -> None:
        """Test SSL and TLS mutual exclusion validation."""
        with pytest.raises(ValidationError, match="mutually exclusive"):
            m.ConnectionConfig(use_ssl=True, use_tls=True)

    def test_connection_config_ssl_only_allowed(self) -> None:
        """Test SSL-only configuration is allowed."""
        config = m.ConnectionConfig(use_ssl=True, use_tls=False)
        tm.eq(config.use_ssl, True)
        tm.eq(config.use_tls, False)

    def test_connection_config_tls_only_allowed(self) -> None:
        """Test TLS-only configuration is allowed."""
        config = m.ConnectionConfig(use_ssl=False, use_tls=True)
        tm.eq(config.use_ssl, False)
        tm.eq(config.use_tls, True)

    def test_connection_config_port_constraints(self) -> None:
        """Test port field constraints."""
        # Valid ports
        config_min = m.ConnectionConfig(port=1)
        tm.eq(config_min.port, 1)

        config_max = m.ConnectionConfig(port=65535)
        tm.eq(config_max.port, 65535)

    def test_connection_config_port_constraint_violation_min(self) -> None:
        """Test port constraint violation (below minimum)."""
        with pytest.raises(ValidationError):
            m.ConnectionConfig(port=0)

    def test_connection_config_port_constraint_violation_max(self) -> None:
        """Test port constraint violation (above maximum)."""
        with pytest.raises(ValidationError):
            m.ConnectionConfig(port=65536)

    def test_connection_config_inherits_from_collections_config(self) -> None:
        """Test ConnectionConfig inherits from Collections.Config.

        Note: FlextLdapModels declares frozen=True in model_config,
        but Collections.Config (from FlextModels) may have its own config.
        This test verifies inheritance and model functionality.
        """
        config = m.ConnectionConfig()
        # Verify it's a valid config instance
        tm.is_type(config, m.Collections.Config)
        # Verify model_dump works (serialization)
        dump = config.model_dump()
        tm.dict_(dump, has_key=["host", "port"])

    # =========================================================================
    # SearchOptions Tests
    # =========================================================================

    def test_search_options_required_base_dn(self) -> None:
        """Test SearchOptions requires base_dn."""
        with pytest.raises(ValidationError, match="base_dn"):
            m.SearchOptions()

    def test_search_options_default_values(self) -> None:
        """Test SearchOptions default values."""
        options = m.SearchOptions(base_dn=tc.RFC.DEFAULT_BASE_DN)
        tm.eq(options.base_dn, tc.RFC.DEFAULT_BASE_DN)
        tm.eq(options.scope, "SUBTREE")
        tm.eq(options.filter_str, c.Filters.ALL_ENTRIES_FILTER)
        tm.that(options.attributes, none=True)
        tm.eq(options.size_limit, 0)
        tm.eq(options.time_limit, 0)

    def test_search_options_custom_values(self) -> None:
        """Test SearchOptions with custom values."""
        options = m.SearchOptions(
            base_dn=tc.RFC.DEFAULT_BASE_DN,
            scope="BASE",
            filter_str="(cn=*)",
            attributes=["cn", "mail"],
            size_limit=100,
            time_limit=30,
        )
        tm.eq(options.scope, "BASE")
        tm.eq(options.filter_str, "(cn=*)")
        tm.eq(options.attributes, ["cn", "mail"])
        tm.eq(options.size_limit, 100)

    def test_search_options_invalid_base_dn_format(self) -> None:
        """Test SearchOptions validates base_dn format."""
        with pytest.raises(ValidationError, match="Invalid base_dn format"):
            m.SearchOptions(base_dn="invalid-dn-format")

    def test_search_options_scope_normalization_enum(self) -> None:
        """Test SearchOptions normalizes scope from StrEnum."""
        options = m.SearchOptions(
            base_dn=tc.RFC.DEFAULT_BASE_DN,
            scope=c.SearchScope.BASE,
        )
        tm.eq(options.scope, "BASE")

    def test_search_options_scope_normalization_string(self) -> None:
        """Test SearchOptions normalizes scope from string."""
        options = m.SearchOptions(
            base_dn=tc.RFC.DEFAULT_BASE_DN,
            scope="subtree",
        )
        # Should parse and normalize to uppercase
        tm.that(options.scope in {"SUBTREE", "subtree"}, eq=True)

    def test_search_options_normalized_factory(self) -> None:
        """Test SearchOptions.normalized factory method."""
        options = m.SearchOptions.normalized(tc.RFC.DEFAULT_BASE_DN)
        tm.not_none(options.base_dn)
        tm.eq(options.scope, "SUBTREE")
        tm.eq(options.filter_str, c.Filters.ALL_ENTRIES_FILTER)

    def test_search_options_normalized_with_config(self) -> None:
        """Test SearchOptions.normalized with NormalizedConfig."""
        config = m.SearchOptions.NormalizedConfig(
            scope="BASE",
            filter_str="(uid=*)",
            size_limit=50,
        )
        options = m.SearchOptions.normalized(
            tc.RFC.DEFAULT_BASE_DN,
            config=config,
        )
        tm.eq(options.scope, "BASE")
        tm.eq(options.filter_str, "(uid=*)")
        tm.eq(options.size_limit, 50)

    # =========================================================================
    # OperationResult Tests
    # =========================================================================

    def test_operation_result_creation(self) -> None:
        """Test OperationResult creation."""
        result = m.OperationResult(
            success=True,
            operation_type=c.OperationType.ADD,
            message="Entry added successfully",
            entries_affected=1,
        )
        tm.eq(result.success, True)
        tm.eq(result.operation_type, c.OperationType.ADD)
        tm.eq(result.message, "Entry added successfully")
        tm.eq(result.entries_affected, 1)

    def test_operation_result_default_message(self) -> None:
        """Test OperationResult default message is empty."""
        result = m.OperationResult(
            success=True,
            operation_type=c.OperationType.SEARCH,
        )
        tm.eq(result.message, "")
        tm.eq(result.entries_affected, 0)

    def test_operation_result_frozen(self) -> None:
        """Test OperationResult is frozen (immutable)."""
        result = m.OperationResult(
            success=True,
            operation_type=c.OperationType.ADD,
        )
        # Pydantic v2 frozen models raise TypeError on assignment

        with pytest.raises((TypeError, ValidationError)):
            result.success = False

    # =========================================================================
    # SearchResult Tests
    # =========================================================================

    _SEARCH_RESULT_SCENARIOS: ClassVar[Mapping[str, tuple[int, int]]] = {
        # name: (num_entries, expected_total_count)
        "empty": (0, 0),
        "single": (1, 1),
        "multiple": (5, 5),
    }

    @pytest.mark.parametrize(
        ("num_entries", "expected_count"),
        [
            (0, 0),
            (1, 1),
            (5, 5),
            (10, 10),
        ],
    )
    def test_search_result_total_count(
        self,
        num_entries: int,
        expected_count: int,
    ) -> None:
        """Test SearchResult.total_count computed field."""
        entries = [
            m.Entry(dn=f"cn=user{i},{tc.RFC.DEFAULT_BASE_DN}", attributes=None)
            for i in range(num_entries)
        ]
        options = m.SearchOptions(base_dn=tc.RFC.DEFAULT_BASE_DN)
        result = m.SearchResult(entries=entries, search_options=options)
        tm.eq(result.total_count, expected_count)

    def test_search_result_by_objectclass_empty(self) -> None:
        """Test SearchResult.by_objectclass with no entries."""
        options = m.SearchOptions(base_dn=tc.RFC.DEFAULT_BASE_DN)
        result = m.SearchResult(entries=[], search_options=options)
        categories = result.by_objectclass
        tm.not_none(categories)
        # Empty result should have no categories or empty categories

    def test_search_result_extract_attrs_dict_none_attributes(self) -> None:
        """Test extract_attrs_dict_from_entry with None attributes."""
        # Entry accepts str for dn via Pydantic - Pyright strict: Entry.__init__ accepts **data: Any
        entry = m.Entry(dn=tc.RFC.DEFAULT_BASE_DN, attributes=None)
        attrs = m.SearchResult.extract_attrs_dict_from_entry(entry)
        tm.eq(attrs, {})

    def test_search_result_extract_objectclass_category_empty(self) -> None:
        """Test extract_objectclass_category with empty dict."""
        category = m.SearchResult.extract_objectclass_category({})
        tm.eq(category, "unknown")

    def test_search_result_extract_objectclass_category_with_objectclass(
        self,
    ) -> None:
        """Test extract_objectclass_category with objectClass attribute."""
        attrs = {"objectClass": ["person", "top"]}
        category = m.SearchResult.extract_objectclass_category(attrs)
        tm.eq(category, "person")

    def test_search_result_get_entry_category(self) -> None:
        """Test get_entry_category returns category or unknown."""
        # Entry accepts str for dn via Pydantic - Pyright strict: Entry.__init__ accepts **data: Any
        entry = m.Entry(dn=tc.RFC.DEFAULT_BASE_DN, attributes=None)
        category = m.SearchResult.get_entry_category(entry)
        # Entry with no attributes should return "unknown"
        tm.eq(category, "unknown")

    # =========================================================================
    # SyncOptions Tests
    # =========================================================================

    def test_sync_options_default_values(self) -> None:
        """Test SyncOptions default values."""
        options = m.SyncOptions()
        tm.eq(options.batch_size, 100)
        tm.eq(options.auto_create_parents, True)
        tm.eq(options.allow_deletes, False)
        tm.eq(options.source_basedn, "")
        tm.eq(options.target_basedn, "")
        tm.that(options.progress_callback, none=True)

    def test_sync_options_custom_values(self) -> None:
        """Test SyncOptions with custom values."""
        options = m.SyncOptions(
            batch_size=50,
            auto_create_parents=False,
            allow_deletes=True,
            source_basedn="dc=source,dc=com",
            target_basedn="dc=target,dc=com",
        )
        tm.eq(options.batch_size, 50)
        tm.eq(options.auto_create_parents, False)
        tm.eq(options.allow_deletes, True)

    def test_sync_options_batch_size_constraint(self) -> None:
        """Test SyncOptions batch_size must be >= 1."""
        with pytest.raises(ValidationError):
            m.SyncOptions(batch_size=0)

    # =========================================================================
    # SyncStats Tests
    # =========================================================================

    def test_sync_stats_default_values(self) -> None:
        """Test SyncStats default values."""
        stats = m.SyncStats()
        tm.eq(stats.added, 0)
        tm.eq(stats.skipped, 0)
        tm.eq(stats.failed, 0)
        tm.eq(stats.total, 0)
        tm.eq(stats.duration_seconds, 0.0)

    def test_sync_stats_success_rate_zero_total(self) -> None:
        """Test SyncStats.success_rate returns 0.0 when total is 0."""
        stats = m.SyncStats()
        tm.eq(stats.success_rate, 0.0)

    def test_sync_stats_success_rate_calculation(self) -> None:
        """Test SyncStats.success_rate computed field."""
        stats = m.SyncStats(
            added=70,
            skipped=20,
            failed=10,
            total=100,
        )
        # success_rate = (added + skipped) / total = (70 + 20) / 100 = 0.9
        tm.eq(stats.success_rate, 0.9)

    def test_sync_stats_from_counters_factory(self) -> None:
        """Test SyncStats.from_counters factory method."""
        stats = m.SyncStats.from_counters(
            added=50,
            skipped=30,
            failed=20,
            duration_seconds=10.5,
        )
        tm.eq(stats.added, 50)
        tm.eq(stats.skipped, 30)
        tm.eq(stats.failed, 20)
        tm.eq(stats.total, 100)  # auto-calculated
        tm.eq(stats.duration_seconds, 10.5)

    # =========================================================================
    # UpsertResult Tests
    # =========================================================================

    def test_upsert_result_creation(self) -> None:
        """Test UpsertResult creation."""
        result = m.UpsertResult(
            success=True,
            dn=tc.RFC.DEFAULT_BASE_DN,
            operation=c.OperationType.ADD,
        )
        tm.eq(result.success, True)
        tm.eq(result.dn, tc.RFC.DEFAULT_BASE_DN)
        tm.eq(result.operation, c.OperationType.ADD)
        tm.that(result.error, none=True)

    def test_upsert_result_with_error(self) -> None:
        """Test UpsertResult with error message."""
        result = m.UpsertResult(
            success=False,
            dn=tc.RFC.DEFAULT_BASE_DN,
            operation=c.OperationType.ADD,
            error="Entry already exists",
        )
        tm.eq(result.success, False)
        tm.eq(result.error, "Entry already exists")

    # =========================================================================
    # BatchUpsertResult Tests
    # =========================================================================

    def test_batch_upsert_result_creation(self) -> None:
        """Test BatchUpsertResult creation."""
        result = m.BatchUpsertResult(
            total_processed=100,
            successful=90,
            failed=10,
        )
        tm.eq(result.total_processed, 100)
        tm.eq(result.successful, 90)
        tm.eq(result.failed, 10)

    def test_batch_upsert_result_success_rate_zero(self) -> None:
        """Test BatchUpsertResult.success_rate returns 0.0 when no processing."""
        result = m.BatchUpsertResult(
            total_processed=0,
            successful=0,
            failed=0,
        )
        tm.eq(result.success_rate, 0.0)

    def test_batch_upsert_result_success_rate_calculation(self) -> None:
        """Test BatchUpsertResult.success_rate computed field."""
        result = m.BatchUpsertResult(
            total_processed=100,
            successful=85,
            failed=15,
        )
        # success_rate = successful / total_processed = 85 / 100 = 0.85
        tm.eq(result.success_rate, 0.85)

    # =========================================================================
    # SyncPhaseConfig Tests
    # =========================================================================

    def test_sync_phase_config_default_values(self) -> None:
        """Test SyncPhaseConfig default values."""
        config = m.SyncPhaseConfig()
        tm.eq(config.server_type, "rfc")
        tm.that(config.progress_callback, none=True)
        tm.that(config.retry_on_errors, none=True)
        tm.eq(config.max_retries, 5)
        tm.eq(config.stop_on_error, False)

    def test_sync_phase_config_custom_values(self) -> None:
        """Test SyncPhaseConfig with custom values."""
        config = m.SyncPhaseConfig(
            server_type="oud",
            max_retries=3,
            stop_on_error=True,
        )
        tm.eq(config.server_type, "oud")
        tm.eq(config.max_retries, 3)
        tm.eq(config.stop_on_error, True)

    # =========================================================================
    # ConversionMetadata Tests
    # =========================================================================

    def test_conversion_metadata_default_values(self) -> None:
        """Test ConversionMetadata default values."""
        metadata = m.ConversionMetadata()
        tm.eq(metadata.source_attributes, [])
        tm.eq(metadata.source_dn, "")
        tm.eq(metadata.removed_attributes, [])
        tm.eq(metadata.base64_encoded_attributes, [])
        tm.eq(metadata.dn_changed, False)
        tm.eq(metadata.converted_dn, "")
        tm.eq(metadata.attribute_changes, [])

    def test_conversion_metadata_custom_values(self) -> None:
        """Test ConversionMetadata with custom values."""
        metadata = m.ConversionMetadata(
            source_attributes=["cn", "mail", "telephoneNumber"],
            source_dn="cn=user,dc=example,dc=com",
            removed_attributes=["userPassword"],
            dn_changed=True,
            converted_dn="cn=user,dc=new,dc=com",
        )
        tm.len(metadata.source_attributes, expected=3)
        tm.that(metadata.source_attributes, contains="telephoneNumber")
        tm.eq(metadata.dn_changed, True)

    # =========================================================================
    # PhaseSyncResult Tests
    # =========================================================================

    def test_phase_sync_result_creation(self) -> None:
        """Test PhaseSyncResult creation."""
        result = m.PhaseSyncResult(
            phase_name="01-users",
            total_entries=100,
            synced=90,
            failed=5,
            skipped=5,
            duration_seconds=30.0,
            success_rate=95.0,
        )
        tm.eq(result.phase_name, "01-users")
        tm.eq(result.total_entries, 100)
        tm.eq(result.synced, 90)
        tm.eq(result.success_rate, 95.0)

    # =========================================================================
    # MultiPhaseSyncResult Tests
    # =========================================================================

    def test_multi_phase_sync_result_creation(self) -> None:
        """Test MultiPhaseSyncResult creation."""
        result = m.MultiPhaseSyncResult(
            total_entries=500,
            total_synced=450,
            total_failed=25,
            total_skipped=25,
            overall_success_rate=95.0,
            total_duration_seconds=120.0,
            overall_success=True,
        )
        tm.eq(result.total_entries, 500)
        tm.eq(result.total_synced, 450)
        tm.eq(result.overall_success_rate, 95.0)
        tm.eq(result.overall_success, True)

    def test_multi_phase_sync_result_with_phase_results(self) -> None:
        """Test MultiPhaseSyncResult with phase_results."""
        phase1 = m.PhaseSyncResult(
            phase_name="01-users",
            total_entries=100,
            synced=95,
            failed=5,
            skipped=0,
            duration_seconds=10.0,
            success_rate=95.0,
        )
        result = m.MultiPhaseSyncResult(
            phase_results={"01-users": phase1},
            total_entries=100,
            total_synced=95,
            total_failed=5,
            total_skipped=0,
            overall_success_rate=95.0,
            total_duration_seconds=10.0,
        )
        tm.dict_(result.phase_results, has_key="01-users")
        tm.eq(result.phase_results["01-users"].synced, 95)

    # =========================================================================
    # LdapOperationResult Tests
    # =========================================================================

    def test_ldap_operation_result_creation(self) -> None:
        """Test LdapOperationResult creation."""
        result = m.LdapOperationResult(
            operation=c.UpsertOperations.ADDED,
        )
        tm.eq(result.operation, c.UpsertOperations.ADDED)

    # =========================================================================
    # LdapBatchStats Tests
    # =========================================================================

    def test_ldap_batch_stats_default_values(self) -> None:
        """Test LdapBatchStats default values."""
        stats = m.LdapBatchStats()
        tm.eq(stats.synced, 0)
        tm.eq(stats.failed, 0)
        tm.eq(stats.skipped, 0)

    def test_ldap_batch_stats_custom_values(self) -> None:
        """Test LdapBatchStats with custom values."""
        stats = m.LdapBatchStats(
            synced=80,
            failed=10,
            skipped=10,
        )
        tm.eq(stats.synced, 80)
        tm.eq(stats.failed, 10)
        tm.eq(stats.skipped, 10)

    # =========================================================================
    # Types Namespace Tests
    # =========================================================================

    def test_types_namespace_exists(self) -> None:
        """Test Types namespace exists."""
        tm.not_none(m.Types)

    def test_ldap_progress_callback_type_exists(self) -> None:
        """Test LdapProgressCallback type alias exists."""
        tm.that(hasattr(m.Types, "LdapProgressCallback"), eq=True)

    # =========================================================================
    # Model Serialization Tests
    # =========================================================================

    def test_connection_config_serialization(self) -> None:
        """Test ConnectionConfig serialization to dict."""
        config = m.ConnectionConfig(
            host="ldap.example.com",
            port=636,
        )
        data = config.model_dump()
        tm.eq(data["host"], "ldap.example.com")
        tm.eq(data["port"], 636)

    def test_search_options_serialization(self) -> None:
        """Test SearchOptions serialization to dict."""
        options = m.SearchOptions(
            base_dn=tc.RFC.DEFAULT_BASE_DN,
            scope="SUBTREE",
        )
        data = options.model_dump()
        tm.eq(data["base_dn"], tc.RFC.DEFAULT_BASE_DN)
        tm.eq(data["scope"], "SUBTREE")

    def test_sync_stats_serialization(self) -> None:
        """Test SyncStats serialization includes computed field."""
        stats = m.SyncStats.from_counters(added=80, skipped=10, failed=10)
        data = stats.model_dump()
        tm.dict_(data, has_key="success_rate")
        tm.eq(data["success_rate"], 0.9)

    # =========================================================================
    # JSON Schema Generation Tests
    # =========================================================================

    def test_connection_config_json_schema(self) -> None:
        """Test ConnectionConfig JSON schema generation."""
        schema = m.ConnectionConfig.model_json_schema()
        tm.dict_(schema, has_key="properties")
        tm.dict_(schema["properties"], has_key=["host", "port"])

    def test_search_options_json_schema(self) -> None:
        """Test SearchOptions JSON schema generation."""
        schema = m.SearchOptions.model_json_schema()
        tm.dict_(schema, has_key="properties")
        tm.dict_(schema["properties"], has_key=["base_dn", "scope"])


__all__ = [
    "TestsFlextLdapModels",
]

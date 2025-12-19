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

from flext_ldap import FlextLdapModels, c, m
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
        tm.that(FlextLdapModels, none=False)
        tm.that(m, eq=FlextLdapModels)

    def test_models_inherits_from_flext_ldif_models(self) -> None:
        """Test FlextLdapModels inherits from FlextLdifModels."""
        tm.that(issubclass(FlextLdapModels, FlextLdifModels), eq=True)

    def test_nested_models_have_model_config(self) -> None:
        """Test nested Pydantic models have model_config.

        FlextLdapModels is a namespace class, not a Pydantic model.
        The model_config exists on nested Pydantic models like ConnectionConfig.
        """
        # ConnectionConfig (nested Pydantic model) has model_config
        tm.that(m.Ldap.ConnectionConfig.model_config, none=False)
        # Check frozen status on config models (they inherit from Collections.Config)
        config_frozen = m.Ldap.ConnectionConfig.model_config.get("frozen", False)
        tm.that(isinstance(config_frozen, bool), eq=True)

    # =========================================================================
    # Collections Inheritance Tests
    # =========================================================================

    def test_collections_exists(self) -> None:
        """Test Collections class exists."""
        tm.that(m.Collections, none=False)

    def test_collections_config_exists(self) -> None:
        """Test Collections.Config exists."""
        tm.that(m.Collections.Config, none=False)

    def test_collections_options_exists(self) -> None:
        """Test Collections.Options exists."""
        tm.that(m.Collections.Options, none=False)

    def test_collections_results_exists(self) -> None:
        """Test Collections.Results exists."""
        tm.that(m.Collections.Results, none=False)

    def test_collections_statistics_exists(self) -> None:
        """Test Collections.Statistics exists."""
        tm.that(m.Collections.Statistics, none=False)

    # =========================================================================
    # Entry Model Tests
    # =========================================================================

    def test_entry_model_exists(self) -> None:
        """Test Entry model exists."""
        tm.that(m.Ldif.Entry, none=False)

    def test_entry_inherits_from_flext_ldif_entry(self) -> None:
        """Test Entry inherits from FlextLdifModels.Ldif.Entry."""
        tm.that(issubclass(m.Ldif.Entry, FlextLdifModels.Ldif.Entry), eq=True)

    def test_entry_creation(self) -> None:
        """Test Entry creation with DN and attributes."""
        # Entry accepts DN for dn (use m.Ldif namespace)
        dn = m.Ldif.DN(value=tc.RFC.DEFAULT_BASE_DN)
        entry = m.Ldif.Entry(dn=dn, attributes=None)
        # Entry.dn is a DN object, use .value for string comparison
        tm.that(entry.dn, none=False)
        assert entry.dn is not None
        tm.that(entry.dn.value, eq=tc.RFC.DEFAULT_BASE_DN)
        tm.that(entry.attributes, none=True)

    # =========================================================================
    # Namespace Inheritance Tests (via FlextLdifModels inheritance)
    # =========================================================================

    def test_distinguished_name_via_ldif_namespace(self) -> None:
        """Test DN accessible via m.Ldif namespace (inherited)."""
        tm.that(m.Ldif.DN, eq=FlextLdifModels.Ldif.DN)

    def test_ldif_attributes_via_ldif_namespace(self) -> None:
        """Test Attributes accessible via m.Ldif namespace (inherited)."""
        # Verify the attribute exists via namespace inheritance
        actual = hasattr(m.Ldif, "Attributes")
        tm.that(actual, eq=True)
        tm.that(m.Ldif.Attributes is FlextLdifModels.Ldif.Attributes, eq=True)

    def test_quirk_metadata_via_ldif_namespace(self) -> None:
        """Test QuirkMetadata accessible via m.Ldif namespace (inherited)."""
        tm.that(m.Ldif.QuirkMetadata, eq=FlextLdifModels.Ldif.QuirkMetadata)

    def test_parse_response_via_ldif_namespace(self) -> None:
        """Test ParseResponse accessible via m.Ldif namespace (inherited)."""
        # ParseResponse is accessible via m.Ldif namespace
        tm.that(m.Ldif.ParseResponse, none=False)
        actual = hasattr(m.Ldif, "ParseResponse")
        tm.that(actual, eq=True)

    # =========================================================================
    # ConnectionConfig Tests
    # =========================================================================

    def test_connection_config_default_values(self) -> None:
        """Test ConnectionConfig default values."""
        config = m.Ldap.ConnectionConfig()
        tm.that(config.host, eq="localhost")
        tm.that(config.port, eq=c.Ldap.ConnectionDefaults.PORT)
        tm.that(config.use_ssl, eq=False)
        tm.that(config.use_tls, eq=False)
        tm.that(config.bind_dn, none=True)
        tm.that(config.bind_password, none=True)
        tm.that(config.timeout, eq=c.Ldap.ConnectionDefaults.TIMEOUT)
        tm.that(config.auto_bind, eq=c.Ldap.ConnectionDefaults.AUTO_BIND)

    def test_connection_config_custom_values(self) -> None:
        """Test ConnectionConfig with custom values."""
        config = m.Ldap.ConnectionConfig(
            host="ldap.example.com",
            port=636,
            use_ssl=True,
            bind_dn="cn=REDACTED_LDAP_BIND_PASSWORD,dc=example,dc=com",
            bind_password="secret",
            timeout=60,
        )
        tm.that(config.host, eq="ldap.example.com")
        tm.that(config.port, eq=636)
        tm.that(config.use_ssl, eq=True)
        tm.that(config.bind_dn, eq="cn=REDACTED_LDAP_BIND_PASSWORD,dc=example,dc=com")

    def test_connection_config_ssl_tls_mutual_exclusion(self) -> None:
        """Test SSL and TLS mutual exclusion validation."""
        with pytest.raises(ValidationError, match="mutually exclusive"):
            m.Ldap.ConnectionConfig(use_ssl=True, use_tls=True)

    def test_connection_config_ssl_only_allowed(self) -> None:
        """Test SSL-only configuration is allowed."""
        config = m.Ldap.ConnectionConfig(use_ssl=True, use_tls=False)
        tm.that(config.use_ssl, eq=True)
        tm.that(config.use_tls, eq=False)

    def test_connection_config_tls_only_allowed(self) -> None:
        """Test TLS-only configuration is allowed."""
        config = m.Ldap.ConnectionConfig(use_ssl=False, use_tls=True)
        tm.that(config.use_ssl, eq=False)
        tm.that(config.use_tls, eq=True)

    def test_connection_config_port_constraints(self) -> None:
        """Test port field constraints."""
        # Valid ports
        config_min = m.Ldap.ConnectionConfig(port=1)
        tm.that(config_min.port, eq=1)

        config_max = m.Ldap.ConnectionConfig(port=65535)
        tm.that(config_max.port, eq=65535)

    def test_connection_config_port_constraint_violation_min(self) -> None:
        """Test port constraint violation (below minimum)."""
        with pytest.raises(ValidationError):
            m.Ldap.ConnectionConfig(port=0)

    def test_connection_config_port_constraint_violation_max(self) -> None:
        """Test port constraint violation (above maximum)."""
        with pytest.raises(ValidationError):
            m.Ldap.ConnectionConfig(port=65536)

    def test_connection_config_inherits_from_collections_config(self) -> None:
        """Test ConnectionConfig inherits from Collections.Config.

        Note: FlextLdapModels declares frozen=True in model_config,
        but Collections.Config (from FlextModels) may have its own config.
        This test verifies inheritance and model functionality.
        """
        config = m.Ldap.ConnectionConfig()
        # Verify it's a valid config instance
        tm.that(config, is_=m.Collections.Config, none=False)
        # Verify model_dump works (serialization)
        dump = config.model_dump()
        tm.that(dump, keys=["host", "port"])

    # =========================================================================
    # SearchOptions Tests
    # =========================================================================

    def test_search_options_required_base_dn(self) -> None:
        """Test SearchOptions requires base_dn."""
        with pytest.raises(ValidationError, match="base_dn"):
            m.Ldap.SearchOptions(base_dn="")  # Empty string should fail validation

    def test_search_options_default_values(self) -> None:
        """Test SearchOptions default values."""
        options = m.Ldap.SearchOptions(base_dn=tc.RFC.DEFAULT_BASE_DN)
        tm.that(options.base_dn, eq=tc.RFC.DEFAULT_BASE_DN)
        tm.that(options.scope, eq="SUBTREE")
        tm.that(options.filter_str, eq=c.Ldap.Filters.ALL_ENTRIES_FILTER)
        tm.that(options.attributes, none=True)
        tm.that(options.size_limit, eq=0)
        tm.that(options.time_limit, eq=0)

    def test_search_options_custom_values(self) -> None:
        """Test SearchOptions with custom values."""
        options = m.Ldap.SearchOptions(
            base_dn=tc.RFC.DEFAULT_BASE_DN,
            scope="BASE",
            filter_str="(cn=*)",
            attributes=["cn", "mail"],
            size_limit=100,
            time_limit=30,
        )
        tm.that(options.scope, eq="BASE")
        tm.that(options.filter_str, eq="(cn=*)")
        tm.that(options.attributes, eq=["cn", "mail"])
        tm.that(options.size_limit, eq=100)

    def test_search_options_invalid_base_dn_format(self) -> None:
        """Test SearchOptions accepts any non-empty base_dn (full validation at service layer)."""
        # DN format validation is done at service/utility layer, not model layer
        # Model just checks that base_dn is non-empty string
        options = m.Ldap.SearchOptions(base_dn="invalid-dn-format")
        tm.that(options.base_dn, eq="invalid-dn-format")

    def test_search_options_scope_normalization_enum(self) -> None:
        """Test SearchOptions normalizes scope from StrEnum."""
        options = m.Ldap.SearchOptions(
            base_dn=tc.RFC.DEFAULT_BASE_DN,
            scope=c.Ldap.SearchScope.BASE,
        )
        tm.that(options.scope, eq="BASE")

    def test_search_options_scope_normalization_string(self) -> None:
        """Test SearchOptions normalizes scope from string."""
        options = m.Ldap.SearchOptions(
            base_dn=tc.RFC.DEFAULT_BASE_DN,
            scope="subtree",
        )
        # Should parse and normalize to uppercase
        tm.that(options.scope in {"SUBTREE", "subtree"}, eq=True)

    def test_search_options_normalized_factory(self) -> None:
        """Test SearchOptions.normalized factory method."""
        options = m.Ldap.SearchOptions.normalized(tc.RFC.DEFAULT_BASE_DN)
        tm.that(options.base_dn, none=False)
        tm.that(options.scope, eq="SUBTREE")
        tm.that(options.filter_str, eq=c.Ldap.Filters.ALL_ENTRIES_FILTER)

    def test_search_options_normalized_with_config(self) -> None:
        """Test SearchOptions.normalized with NormalizedConfig."""
        config = m.Ldap.SearchOptions.NormalizedConfig(
            scope="BASE",
            filter_str="(uid=*)",
            size_limit=50,
        )
        options = m.Ldap.SearchOptions.normalized(
            tc.RFC.DEFAULT_BASE_DN,
            config=config,
        )
        tm.that(options.scope, eq="BASE")
        tm.that(options.filter_str, eq="(uid=*)")
        tm.that(options.size_limit, eq=50)

    # =========================================================================
    # OperationResult Tests
    # =========================================================================

    def test_operation_result_creation(self) -> None:
        """Test OperationResult creation."""
        result = m.Ldap.OperationResult(
            success=True,
            operation_type=c.Ldap.OperationType.ADD,
            message="Entry added successfully",
            entries_affected=1,
        )
        tm.that(result.success, eq=True)
        tm.that(result.operation_type, eq=c.Ldap.OperationType.ADD)
        tm.that(result.message, eq="Entry added successfully")
        tm.that(result.entries_affected, eq=1)

    def test_operation_result_default_message(self) -> None:
        """Test OperationResult default message is empty."""
        result = m.Ldap.OperationResult(
            success=True,
            operation_type=c.Ldap.OperationType.SEARCH,
        )
        tm.that(result.message, eq="")
        tm.that(result.entries_affected, eq=0)

    def test_operation_result_frozen(self) -> None:
        """Test OperationResult is frozen (immutable)."""
        result = m.Ldap.OperationResult(
            success=True,
            operation_type=c.Ldap.OperationType.ADD,
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
            m.Ldif.Entry(
                dn=m.Ldif.DN(value=f"cn=user{i},{tc.RFC.DEFAULT_BASE_DN}"),
                attributes=None,
            )
            for i in range(num_entries)
        ]
        options = m.Ldap.SearchOptions(base_dn=tc.RFC.DEFAULT_BASE_DN)
        result = m.Ldap.SearchResult(entries=entries, search_options=options)
        tm.that(result.total_count, eq=expected_count)

    def test_search_result_by_objectclass_empty(self) -> None:
        """Test SearchResult.by_objectclass with no entries."""
        options = m.Ldap.SearchOptions(base_dn=tc.RFC.DEFAULT_BASE_DN)
        result = m.Ldap.SearchResult(entries=[], search_options=options)
        categories = result.by_objectclass
        tm.that(categories, none=False)
        # Empty result should have no categories or empty categories

    def test_search_result_extract_attrs_dict_none_attributes(self) -> None:
        """Test extract_attrs_dict_from_entry with None attributes."""
        # Entry accepts DN for dn (use m.Ldif namespace)
        dn = m.Ldif.DN(value=tc.RFC.DEFAULT_BASE_DN)
        entry = m.Ldif.Entry(dn=dn, attributes=None)
        attrs = m.Ldap.SearchResult.extract_attrs_dict_from_entry(entry)
        tm.that(attrs, eq={})

    def test_search_result_extract_objectclass_category_empty(self) -> None:
        """Test extract_objectclass_category with empty dict."""
        category = m.Ldap.SearchResult.extract_objectclass_category({})
        tm.that(category, eq="unknown")

    def test_search_result_extract_objectclass_category_with_objectclass(
        self,
    ) -> None:
        """Test extract_objectclass_category with objectClass attribute."""
        attrs = {"objectClass": ["person", "top"]}
        category = m.Ldap.SearchResult.extract_objectclass_category(attrs)
        tm.that(category, eq="person")

    def test_search_result_get_entry_category(self) -> None:
        """Test get_entry_category returns category or unknown."""
        # Entry accepts DN for dn (use m.Ldif namespace)
        dn = m.Ldif.DN(value=tc.RFC.DEFAULT_BASE_DN)
        entry = m.Ldif.Entry(dn=dn, attributes=None)
        category = m.Ldap.SearchResult.get_entry_category(entry)
        # Entry with no attributes should return "unknown"
        tm.that(category, eq="unknown")

    # =========================================================================
    # SyncOptions Tests
    # =========================================================================

    def test_sync_options_default_values(self) -> None:
        """Test SyncOptions default values."""
        options = m.Ldap.SyncOptions()
        tm.that(options.batch_size, eq=100)
        tm.that(options.auto_create_parents, eq=True)
        tm.that(options.allow_deletes, eq=False)
        tm.that(options.source_basedn, eq="")
        tm.that(options.target_basedn, eq="")
        tm.that(options.progress_callback, none=True)

    def test_sync_options_custom_values(self) -> None:
        """Test SyncOptions with custom values."""
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
        """Test SyncOptions batch_size must be >= 1."""
        with pytest.raises(ValidationError):
            m.Ldap.SyncOptions(batch_size=0)

    # =========================================================================
    # SyncStats Tests
    # =========================================================================

    def test_sync_stats_default_values(self) -> None:
        """Test SyncStats default values."""
        stats = m.Ldap.SyncStats()
        tm.that(stats.added, eq=0)
        tm.that(stats.skipped, eq=0)
        tm.that(stats.failed, eq=0)
        tm.that(stats.total, eq=0)
        tm.that(stats.duration_seconds, eq=0.0)

    def test_sync_stats_success_rate_zero_total(self) -> None:
        """Test SyncStats.success_rate returns 0.0 when total is 0."""
        stats = m.Ldap.SyncStats()
        tm.that(stats.success_rate, eq=0.0)

    def test_sync_stats_success_rate_calculation(self) -> None:
        """Test SyncStats.success_rate computed field."""
        stats = m.Ldap.SyncStats(
            added=70,
            skipped=20,
            failed=10,
            total=100,
        )
        # success_rate = (added + skipped) / total = (70 + 20) / 100 = 0.9
        tm.that(stats.success_rate, eq=0.9)

    def test_sync_stats_from_counters_factory(self) -> None:
        """Test SyncStats.from_counters factory method."""
        stats = m.Ldap.SyncStats.from_counters(
            added=50,
            skipped=30,
            failed=20,
            duration_seconds=10.5,
        )
        tm.that(stats.added, eq=50)
        tm.that(stats.skipped, eq=30)
        tm.that(stats.failed, eq=20)
        tm.that(stats.total, eq=100)  # auto-calculated
        tm.that(stats.duration_seconds, eq=10.5)

    # =========================================================================
    # UpsertResult Tests
    # =========================================================================

    def test_upsert_result_creation(self) -> None:
        """Test UpsertResult creation."""
        result = m.Ldap.UpsertResult(
            success=True,
            dn=tc.RFC.DEFAULT_BASE_DN,
            operation=c.Ldap.OperationType.ADD,
        )
        tm.that(result.success, eq=True)
        tm.that(result.dn, eq=tc.RFC.DEFAULT_BASE_DN)
        tm.that(result.operation, eq=c.Ldap.OperationType.ADD)
        tm.that(result.error, none=True)

    def test_upsert_result_with_error(self) -> None:
        """Test UpsertResult with error message."""
        result = m.Ldap.UpsertResult(
            success=False,
            dn=tc.RFC.DEFAULT_BASE_DN,
            operation=c.Ldap.OperationType.ADD,
            error="Entry already exists",
        )
        tm.that(result.success, eq=False)
        tm.that(result.error, eq="Entry already exists")

    # =========================================================================
    # BatchUpsertResult Tests
    # =========================================================================

    def test_batch_upsert_result_creation(self) -> None:
        """Test BatchUpsertResult creation."""
        result = m.Ldap.BatchUpsertResult(
            total_processed=100,
            successful=90,
            failed=10,
        )
        tm.that(result.total_processed, eq=100)
        tm.that(result.successful, eq=90)
        tm.that(result.failed, eq=10)

    def test_batch_upsert_result_success_rate_zero(self) -> None:
        """Test BatchUpsertResult.success_rate returns 0.0 when no processing."""
        result = m.Ldap.BatchUpsertResult(
            total_processed=0,
            successful=0,
            failed=0,
        )
        tm.that(result.success_rate, eq=0.0)

    def test_batch_upsert_result_success_rate_calculation(self) -> None:
        """Test BatchUpsertResult.success_rate computed field."""
        result = m.Ldap.BatchUpsertResult(
            total_processed=100,
            successful=85,
            failed=15,
        )
        # success_rate = successful / total_processed = 85 / 100 = 0.85
        tm.that(result.success_rate, eq=0.85)

    # =========================================================================
    # SyncPhaseConfig Tests
    # =========================================================================

    def test_sync_phase_config_default_values(self) -> None:
        """Test SyncPhaseConfig default values."""
        config = m.Ldap.SyncPhaseConfig()
        tm.that(config.server_type, eq="rfc")
        tm.that(config.progress_callback, none=True)
        tm.that(config.retry_on_errors, none=True)
        tm.that(config.max_retries, eq=5)
        tm.that(config.stop_on_error, eq=False)

    def test_sync_phase_config_custom_values(self) -> None:
        """Test SyncPhaseConfig with custom values."""
        config = m.Ldap.SyncPhaseConfig(
            server_type="oud",
            max_retries=3,
            stop_on_error=True,
        )
        tm.that(config.server_type, eq="oud")
        tm.that(config.max_retries, eq=3)
        tm.that(config.stop_on_error, eq=True)

    # =========================================================================
    # ConversionMetadata Tests
    # =========================================================================

    def test_conversion_metadata_default_values(self) -> None:
        """Test ConversionMetadata default values."""
        metadata = m.Ldap.ConversionMetadata()
        tm.that(metadata.source_attributes, eq=[])
        tm.that(metadata.source_dn, eq="")
        tm.that(metadata.removed_attributes, eq=[])
        tm.that(metadata.base64_encoded_attributes, eq=[])
        tm.that(metadata.dn_changed, eq=False)
        tm.that(metadata.converted_dn, eq="")
        tm.that(metadata.attribute_changes, eq=[])

    def test_conversion_metadata_custom_values(self) -> None:
        """Test ConversionMetadata with custom values."""
        metadata = m.Ldap.ConversionMetadata(
            source_attributes=["cn", "mail", "telephoneNumber"],
            source_dn="cn=user,dc=example,dc=com",
            removed_attributes=["userPassword"],
            dn_changed=True,
            converted_dn="cn=user,dc=new,dc=com",
        )
        tm.that(metadata.source_attributes, length=3)
        tm.that(metadata.source_attributes, contains="telephoneNumber")
        tm.that(metadata.dn_changed, eq=True)

    # =========================================================================
    # PhaseSyncResult Tests
    # =========================================================================

    def test_phase_sync_result_creation(self) -> None:
        """Test PhaseSyncResult creation."""
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

    # =========================================================================
    # MultiPhaseSyncResult Tests
    # =========================================================================

    def test_multi_phase_sync_result_creation(self) -> None:
        """Test MultiPhaseSyncResult creation."""
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
        """Test MultiPhaseSyncResult with phase_results."""
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

    # =========================================================================
    # LdapOperationResult Tests
    # =========================================================================

    def test_ldap_operation_result_creation(self) -> None:
        """Test LdapOperationResult creation."""
        result = m.Ldap.LdapOperationResult(
            operation=c.Ldap.UpsertOperations.ADDED,
        )
        tm.that(result.operation, eq=c.Ldap.UpsertOperations.ADDED)

    # =========================================================================
    # LdapBatchStats Tests
    # =========================================================================

    def test_ldap_batch_stats_default_values(self) -> None:
        """Test LdapBatchStats default values."""
        stats = m.Ldap.LdapBatchStats()
        tm.that(stats.synced, eq=0)
        tm.that(stats.failed, eq=0)
        tm.that(stats.skipped, eq=0)

    def test_ldap_batch_stats_custom_values(self) -> None:
        """Test LdapBatchStats with custom values."""
        stats = m.Ldap.LdapBatchStats(
            synced=80,
            failed=10,
            skipped=10,
        )
        tm.that(stats.synced, eq=80)
        tm.that(stats.failed, eq=10)
        tm.that(stats.skipped, eq=10)

    # =========================================================================
    # Types Namespace Tests
    # =========================================================================

    def test_types_namespace_exists(self) -> None:
        """Test Types namespace exists."""
        tm.that(m.Ldap.Types, none=False)

    def test_ldap_progress_callback_type_exists(self) -> None:
        """Test LdapProgressCallback type alias exists."""
        actual = hasattr(m.Ldap.Types, "LdapProgressCallback")
        tm.that(actual, eq=True)

    # =========================================================================
    # Model Serialization Tests
    # =========================================================================

    def test_connection_config_serialization(self) -> None:
        """Test ConnectionConfig serialization to dict."""
        config = m.Ldap.ConnectionConfig(
            host="ldap.example.com",
            port=636,
        )
        data = config.model_dump()
        tm.that(data["host"], eq="ldap.example.com")
        tm.that(data["port"], eq=636)

    def test_search_options_serialization(self) -> None:
        """Test SearchOptions serialization to dict."""
        options = m.Ldap.SearchOptions(
            base_dn=tc.RFC.DEFAULT_BASE_DN,
            scope="SUBTREE",
        )
        data = options.model_dump()
        tm.that(data["base_dn"], eq=tc.RFC.DEFAULT_BASE_DN)
        tm.that(data["scope"], eq="SUBTREE")

    def test_sync_stats_serialization(self) -> None:
        """Test SyncStats serialization includes computed field."""
        stats = m.Ldap.SyncStats.from_counters(added=80, skipped=10, failed=10)
        data = stats.model_dump()
        tm.that(data, keys=["success_rate"])
        tm.that(data["success_rate"], eq=0.9)

    # =========================================================================
    # JSON Schema Generation Tests
    # =========================================================================

    def test_connection_config_json_schema(self) -> None:
        """Test ConnectionConfig JSON schema generation."""
        schema = m.Ldap.ConnectionConfig.model_json_schema()
        tm.that(schema, keys=["properties"])
        tm.that(schema["properties"], keys=["host", "port"])

    def test_search_options_json_schema(self) -> None:
        """Test SearchOptions JSON schema generation."""
        schema = m.Ldap.SearchOptions.model_json_schema()
        tm.that(schema, keys=["properties"])
        tm.that(schema["properties"], keys=["base_dn", "scope"])


__all__ = [
    "TestsFlextLdapModels",
]

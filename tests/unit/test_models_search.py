from __future__ import annotations

from collections.abc import Mapping

import pytest
from pydantic import ValidationError

from tests import c, m, t, u

pytestmark = pytest.mark.unit


class TestsFlextLdapModelsSearch:
    def test_search_options_required_base_dn(self) -> None:
        with pytest.raises(ValidationError, match="base_dn"):
            m.Ldap.SearchOptions(base_dn="")

    def test_search_options_default_values(self) -> None:
        options = m.Ldap.SearchOptions(base_dn=c.Ldap.Tests.RFC_DEFAULT_BASE_DN)
        u.Ldap.Tests.that(options.base_dn, eq=c.Ldap.Tests.RFC_DEFAULT_BASE_DN)
        u.Ldap.Tests.that(options.scope, eq=c.Ldap.SearchDefaults.DEFAULT_SCOPE)
        u.Ldap.Tests.that(options.filter_str, eq=c.Ldap.Filters.ALL_ENTRIES_FILTER)
        u.Ldap.Tests.that(options.attributes, none=True)
        u.Ldap.Tests.that(options.size_limit, eq=c.Ldap.Tests.SEARCH_DEFAULT_LIMIT_ZERO)
        u.Ldap.Tests.that(options.time_limit, eq=c.Ldap.Tests.SEARCH_DEFAULT_LIMIT_ZERO)

    def test_search_options_custom_values(self) -> None:
        options = m.Ldap.SearchOptions(
            base_dn=c.Ldap.Tests.RFC_DEFAULT_BASE_DN,
            scope=c.Ldap.Tests.SEARCH_SCOPE_BASE,
            filter_str=c.Ldap.Tests.SEARCH_FILTER_CN,
            attributes=list(c.Ldap.Tests.SEARCH_ATTRIBUTES),
            size_limit=c.Ldap.Tests.SEARCH_SIZE_LIMIT_CUSTOM,
            time_limit=c.Ldap.Tests.SEARCH_TIME_LIMIT_CUSTOM,
        )
        u.Ldap.Tests.that(options.scope, eq=c.Ldap.Tests.SEARCH_SCOPE_BASE)
        u.Ldap.Tests.that(options.filter_str, eq=c.Ldap.Tests.SEARCH_FILTER_CN)
        u.Ldap.Tests.that(options.attributes, eq=list(c.Ldap.Tests.SEARCH_ATTRIBUTES))
        u.Ldap.Tests.that(options.size_limit, eq=c.Ldap.Tests.SEARCH_SIZE_LIMIT_CUSTOM)

    def test_search_options_invalid_base_dn_format(self) -> None:
        options = m.Ldap.SearchOptions(base_dn=c.Ldap.Tests.MODELS_INVALID_DN_FORMAT)
        u.Ldap.Tests.that(options.base_dn, eq=c.Ldap.Tests.MODELS_INVALID_DN_FORMAT)

    def test_search_options_scope_normalization_enum(self) -> None:
        options = m.Ldap.SearchOptions(
            base_dn=c.Ldap.Tests.RFC_DEFAULT_BASE_DN,
            scope=c.Ldap.SearchScope.BASE,
        )
        u.Ldap.Tests.that(options.scope, eq=c.Ldap.Tests.SEARCH_SCOPE_BASE)

    def test_search_options_scope_normalization_string(self) -> None:
        options = m.Ldap.SearchOptions(
            base_dn=c.Ldap.Tests.RFC_DEFAULT_BASE_DN,
            scope=c.Ldap.Tests.SEARCH_SCOPE_SUBTREE_LOWER,
        )
        u.Ldap.Tests.that(
            {
                c.Ldap.SearchDefaults.DEFAULT_SCOPE,
                c.Ldap.Tests.SEARCH_SCOPE_SUBTREE_LOWER,
            },
            has=options.scope,
        )

    def test_search_options_normalized_factory(self) -> None:
        options = m.Ldap.SearchOptions.normalized(c.Ldap.Tests.RFC_DEFAULT_BASE_DN)
        u.Ldap.Tests.that(options.base_dn, none=False)
        u.Ldap.Tests.that(options.scope, eq=c.Ldap.SearchDefaults.DEFAULT_SCOPE)
        u.Ldap.Tests.that(options.filter_str, eq=c.Ldap.Filters.ALL_ENTRIES_FILTER)

    def test_search_options_normalized_with_config(self) -> None:
        config = m.Ldap.NormalizedConfig(
            scope=c.Ldap.Tests.SEARCH_SCOPE_BASE,
            filter_str=c.Ldap.Tests.SEARCH_FILTER_UID,
            size_limit=c.Ldap.Tests.SEARCH_NORMALIZED_SIZE_LIMIT,
        )
        options = m.Ldap.SearchOptions.normalized(
            c.Ldap.Tests.RFC_DEFAULT_BASE_DN,
            config=config,
        )
        u.Ldap.Tests.that(options.scope, eq=c.Ldap.Tests.SEARCH_SCOPE_BASE)
        u.Ldap.Tests.that(options.filter_str, eq=c.Ldap.Tests.SEARCH_FILTER_UID)
        u.Ldap.Tests.that(
            options.size_limit, eq=c.Ldap.Tests.SEARCH_NORMALIZED_SIZE_LIMIT
        )

    def test_operation_result_creation(self) -> None:
        result = m.Ldap.OperationResult(
            success=True,
            operation_type=c.Ldap.OperationType.ADD,
            message=c.Ldap.Tests.SEARCH_ENTRY_ADDED_MESSAGE,
            entries_affected=c.Ldap.Tests.SEARCH_ENTRIES_AFFECTED_ONE,
        )
        u.Ldap.Tests.that(result.success, eq=True)
        u.Ldap.Tests.that(result.operation_type, eq=c.Ldap.OperationType.ADD)
        u.Ldap.Tests.that(result.message, eq=c.Ldap.Tests.SEARCH_ENTRY_ADDED_MESSAGE)
        u.Ldap.Tests.that(
            result.entries_affected, eq=c.Ldap.Tests.SEARCH_ENTRIES_AFFECTED_ONE
        )

    def test_operation_result_default_message(self) -> None:
        result = m.Ldap.OperationResult(
            success=True,
            operation_type=c.Ldap.OperationType.SEARCH,
        )
        u.Ldap.Tests.that(result.message, eq=c.Ldap.Tests.SYNC_DEFAULT_EMPTY_SOURCE_DN)
        u.Ldap.Tests.that(
            result.entries_affected, eq=c.Ldap.Tests.SEARCH_DEFAULT_LIMIT_ZERO
        )

    def test_operation_result_frozen(self) -> None:
        result = m.Ldap.OperationResult(
            success=True,
            operation_type=c.Ldap.OperationType.ADD,
        )
        exc_types: tuple[type[Exception], ...] = (TypeError, ValidationError)
        with pytest.raises(exc_types):
            setattr(result, "is_success", False)

    @pytest.mark.parametrize(
        ("num_entries", "expected_count"),
        [*c.Ldap.Tests.SEARCH_RESULT_SCENARIO_COUNTS.values(), (10, 10)],
    )
    def test_search_result_total_count(
        self,
        num_entries: int,
        expected_count: int,
    ) -> None:
        entries = [
            {"dn": [f"cn=user{i},{c.Ldap.Tests.RFC_DEFAULT_BASE_DN}"]}
            for i in range(num_entries)
        ]
        options = m.Ldap.SearchOptions(base_dn=c.Ldap.Tests.RFC_DEFAULT_BASE_DN)
        result = m.Ldap.SearchResult(entries=entries, search_options=options)
        u.Ldap.Tests.that(result.total_count, eq=expected_count)

    def test_search_result_by_objectclass_empty(self) -> None:
        options = m.Ldap.SearchOptions(base_dn=c.Ldap.Tests.RFC_DEFAULT_BASE_DN)
        result = m.Ldap.SearchResult(entries=[], search_options=options)
        categories = result.by_objectclass
        u.Ldap.Tests.that(categories, none=False)

    def test_search_result_extract_attrs_dict_none_attributes(self) -> None:
        entry: Mapping[str, t.StrSequence] = {}
        attrs = m.Ldap.SearchResult.extract_attrs_dict_from_entry(entry)
        u.Ldap.Tests.that(attrs, eq={})

    def test_search_result_extract_objectclass_category_empty(self) -> None:
        category = m.Ldap.SearchResult.extract_objectclass_category({})
        u.Ldap.Tests.that(category, eq=c.Ldap.Defaults.UNKNOWN_CATEGORY)

    def test_search_result_extract_objectclass_category_with_objectclass(self) -> None:
        attrs = {
            k: list(v) for k, v in c.Ldap.Tests.SEARCH_OBJECTCLASS_PERSON_TOP.items()
        }
        category = m.Ldap.SearchResult.extract_objectclass_category(attrs)
        u.Ldap.Tests.that(category, eq=c.Ldap.Tests.SEARCH_EXPECTED_CATEGORY_PERSON)

    def test_search_result_get_entry_category(self) -> None:
        entry: Mapping[str, t.StrSequence] = {}
        category = m.Ldap.SearchResult.get_entry_category(entry)
        u.Ldap.Tests.that(category, eq=c.Ldap.Defaults.UNKNOWN_CATEGORY)

    def test_sync_phase_config_has_progress_callback(self) -> None:
        """Verify progress_callback field exists on SyncPhaseConfig."""
        u.Ldap.Tests.that(hasattr(m.Ldap.SyncPhaseConfig, "model_fields"), eq=True)
        u.Ldap.Tests.that(
            "progress_callback" in m.Ldap.SyncPhaseConfig.model_fields, eq=True
        )

    def test_connection_config_serialization(self) -> None:
        data = m.Ldap.ConnectionConfig(
            host=c.Ldap.Tests.MODELS_LDAP_EXAMPLE_HOST,
            port=c.Ldap.Tests.CONFIG_LDAPS_PORT,
        ).model_dump()
        u.Ldap.Tests.that(data["host"], eq=c.Ldap.Tests.MODELS_LDAP_EXAMPLE_HOST)
        u.Ldap.Tests.that(data["port"], eq=c.Ldap.Tests.CONFIG_LDAPS_PORT)

    def test_search_options_serialization(self) -> None:
        data = m.Ldap.SearchOptions(
            base_dn=c.Ldap.Tests.RFC_DEFAULT_BASE_DN,
            scope=c.Ldap.SearchDefaults.DEFAULT_SCOPE,
        ).model_dump()
        u.Ldap.Tests.that(data["base_dn"], eq=c.Ldap.Tests.RFC_DEFAULT_BASE_DN)
        u.Ldap.Tests.that(data["scope"], eq=c.Ldap.SearchDefaults.DEFAULT_SCOPE)

    def test_sync_stats_serialization(self) -> None:
        data = m.Ldap.SyncStats.from_counters(
            synced=c.Ldap.Tests.SEARCH_SYNC_COUNTERS_SYNCED,
            skipped=c.Ldap.Tests.SEARCH_SYNC_COUNTERS_SKIPPED,
            failed=c.Ldap.Tests.SEARCH_SYNC_COUNTERS_FAILED,
        ).model_dump()
        u.Ldap.Tests.that(data, keys=[c.Ldap.Tests.FIELD_SUCCESS_RATE])
        u.Ldap.Tests.that(
            data[c.Ldap.Tests.FIELD_SUCCESS_RATE],
            eq=c.Ldap.Tests.SEARCH_EXPECTED_SUCCESS_RATE_90,
        )

    def test_connection_config_json_schema(self) -> None:
        u.Ldap.Tests.that(
            m.Ldap.ConnectionConfig.model_json_schema()["properties"],
            keys=[c.Ldap.Tests.FIELD_HOST, c.Ldap.Tests.FIELD_PORT],
        )

    def test_search_options_json_schema(self) -> None:
        u.Ldap.Tests.that(
            m.Ldap.SearchOptions.model_json_schema()["properties"],
            keys=[c.Ldap.Tests.FIELD_BASE_DN, c.Ldap.Tests.FIELD_SCOPE],
        )


__all__ = ["TestsFlextLdapModelsSearch"]

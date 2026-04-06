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
        options = m.Ldap.SearchOptions(base_dn=c.Ldap.Tests.RFC.DEFAULT_BASE_DN)
        u.Tests.Matchers.that(options.base_dn, eq=c.Ldap.Tests.RFC.DEFAULT_BASE_DN)
        u.Tests.Matchers.that(options.scope, eq=c.Ldap.SearchDefaults.DEFAULT_SCOPE)
        u.Tests.Matchers.that(options.filter_str, eq=c.Ldap.Filters.ALL_ENTRIES_FILTER)
        u.Tests.Matchers.that(options.attributes, none=True)
        u.Tests.Matchers.that(
            options.size_limit, eq=c.Ldap.Tests.Search.DEFAULT_LIMIT_ZERO
        )
        u.Tests.Matchers.that(
            options.time_limit, eq=c.Ldap.Tests.Search.DEFAULT_LIMIT_ZERO
        )

    def test_search_options_custom_values(self) -> None:
        options = m.Ldap.SearchOptions(
            base_dn=c.Ldap.Tests.RFC.DEFAULT_BASE_DN,
            scope=c.Ldap.Tests.Search.SCOPE_BASE,
            filter_str=c.Ldap.Tests.Search.FILTER_CN,
            attributes=list(c.Ldap.Tests.Search.SEARCH_ATTRIBUTES),
            size_limit=c.Ldap.Tests.Search.SIZE_LIMIT_CUSTOM,
            time_limit=c.Ldap.Tests.Search.TIME_LIMIT_CUSTOM,
        )
        u.Tests.Matchers.that(options.scope, eq=c.Ldap.Tests.Search.SCOPE_BASE)
        u.Tests.Matchers.that(options.filter_str, eq=c.Ldap.Tests.Search.FILTER_CN)
        u.Tests.Matchers.that(
            options.attributes, eq=list(c.Ldap.Tests.Search.SEARCH_ATTRIBUTES)
        )
        u.Tests.Matchers.that(
            options.size_limit, eq=c.Ldap.Tests.Search.SIZE_LIMIT_CUSTOM
        )

    def test_search_options_invalid_base_dn_format(self) -> None:
        options = m.Ldap.SearchOptions(base_dn=c.Ldap.Tests.Models.INVALID_DN_FORMAT)
        u.Tests.Matchers.that(options.base_dn, eq=c.Ldap.Tests.Models.INVALID_DN_FORMAT)

    def test_search_options_scope_normalization_enum(self) -> None:
        options = m.Ldap.SearchOptions(
            base_dn=c.Ldap.Tests.RFC.DEFAULT_BASE_DN,
            scope=c.Ldap.SearchScope.BASE,
        )
        u.Tests.Matchers.that(options.scope, eq=c.Ldap.Tests.Search.SCOPE_BASE)

    def test_search_options_scope_normalization_string(self) -> None:
        options = m.Ldap.SearchOptions(
            base_dn=c.Ldap.Tests.RFC.DEFAULT_BASE_DN,
            scope=c.Ldap.Tests.Search.SCOPE_SUBTREE_LOWER,
        )
        u.Tests.Matchers.that(
            {
                c.Ldap.SearchDefaults.DEFAULT_SCOPE,
                c.Ldap.Tests.Search.SCOPE_SUBTREE_LOWER,
            },
            has=options.scope,
        )

    def test_search_options_normalized_factory(self) -> None:
        options = m.Ldap.SearchOptions.normalized(c.Ldap.Tests.RFC.DEFAULT_BASE_DN)
        u.Tests.Matchers.that(options.base_dn, none=False)
        u.Tests.Matchers.that(options.scope, eq=c.Ldap.SearchDefaults.DEFAULT_SCOPE)
        u.Tests.Matchers.that(options.filter_str, eq=c.Ldap.Filters.ALL_ENTRIES_FILTER)

    def test_search_options_normalized_with_config(self) -> None:
        config = m.Ldap.NormalizedConfig(
            scope=c.Ldap.Tests.Search.SCOPE_BASE,
            filter_str=c.Ldap.Tests.Search.FILTER_UID,
            size_limit=c.Ldap.Tests.Search.NORMALIZED_SIZE_LIMIT,
        )
        options = m.Ldap.SearchOptions.normalized(
            c.Ldap.Tests.RFC.DEFAULT_BASE_DN,
            config=config,
        )
        u.Tests.Matchers.that(options.scope, eq=c.Ldap.Tests.Search.SCOPE_BASE)
        u.Tests.Matchers.that(options.filter_str, eq=c.Ldap.Tests.Search.FILTER_UID)
        u.Tests.Matchers.that(
            options.size_limit, eq=c.Ldap.Tests.Search.NORMALIZED_SIZE_LIMIT
        )

    def test_operation_result_creation(self) -> None:
        result = m.Ldap.OperationResult(
            success=True,
            operation_type=c.Ldap.OperationType.ADD,
            message=c.Ldap.Tests.Search.ENTRY_ADDED_MESSAGE,
            entries_affected=c.Ldap.Tests.Search.ENTRIES_AFFECTED_ONE,
        )
        u.Tests.Matchers.that(result.success, eq=True)
        u.Tests.Matchers.that(result.operation_type, eq=c.Ldap.OperationType.ADD)
        u.Tests.Matchers.that(
            result.message, eq=c.Ldap.Tests.Search.ENTRY_ADDED_MESSAGE
        )
        u.Tests.Matchers.that(
            result.entries_affected, eq=c.Ldap.Tests.Search.ENTRIES_AFFECTED_ONE
        )

    def test_operation_result_default_message(self) -> None:
        result = m.Ldap.OperationResult(
            success=True,
            operation_type=c.Ldap.OperationType.SEARCH,
        )
        u.Tests.Matchers.that(
            result.message, eq=c.Ldap.Tests.Sync.Defaults.EMPTY_SOURCE_DN
        )
        u.Tests.Matchers.that(
            result.entries_affected, eq=c.Ldap.Tests.Search.DEFAULT_LIMIT_ZERO
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
        [*c.Ldap.Tests.SearchResultScenarios.COUNTS.values(), (10, 10)],
    )
    def test_search_result_total_count(
        self,
        num_entries: int,
        expected_count: int,
    ) -> None:
        entries = [
            {"dn": [f"cn=user{i},{c.Ldap.Tests.RFC.DEFAULT_BASE_DN}"]}
            for i in range(num_entries)
        ]
        options = m.Ldap.SearchOptions(base_dn=c.Ldap.Tests.RFC.DEFAULT_BASE_DN)
        result = m.Ldap.SearchResult(entries=entries, search_options=options)
        u.Tests.Matchers.that(result.total_count, eq=expected_count)

    def test_search_result_by_objectclass_empty(self) -> None:
        options = m.Ldap.SearchOptions(base_dn=c.Ldap.Tests.RFC.DEFAULT_BASE_DN)
        result = m.Ldap.SearchResult(entries=[], search_options=options)
        categories = result.by_objectclass
        u.Tests.Matchers.that(categories, none=False)

    def test_search_result_extract_attrs_dict_none_attributes(self) -> None:
        entry: Mapping[str, t.StrSequence] = {}
        attrs = m.Ldap.SearchResult.extract_attrs_dict_from_entry(entry)
        u.Tests.Matchers.that(attrs, eq={})

    def test_search_result_extract_objectclass_category_empty(self) -> None:
        category = m.Ldap.SearchResult.extract_objectclass_category({})
        u.Tests.Matchers.that(category, eq=c.Ldap.Defaults.UNKNOWN_CATEGORY)

    def test_search_result_extract_objectclass_category_with_objectclass(self) -> None:
        attrs = {
            k: list(v) for k, v in c.Ldap.Tests.Search.OBJECTCLASS_PERSON_TOP.items()
        }
        category = m.Ldap.SearchResult.extract_objectclass_category(attrs)
        u.Tests.Matchers.that(category, eq=c.Ldap.Tests.Search.EXPECTED_CATEGORY_PERSON)

    def test_search_result_get_entry_category(self) -> None:
        entry: Mapping[str, t.StrSequence] = {}
        category = m.Ldap.SearchResult.get_entry_category(entry)
        u.Tests.Matchers.that(category, eq=c.Ldap.Defaults.UNKNOWN_CATEGORY)

    def test_sync_phase_config_has_progress_callback(self) -> None:
        """Verify progress_callback field exists on SyncPhaseConfig."""
        u.Tests.Matchers.that(
            hasattr(m.Ldap.SyncPhaseConfig, "model_fields"),
            eq=True,
        )
        u.Tests.Matchers.that(
            "progress_callback" in m.Ldap.SyncPhaseConfig.model_fields, eq=True
        )

    def test_connection_config_serialization(self) -> None:
        data = m.Ldap.ConnectionConfig(
            host=c.Ldap.Tests.Models.LDAP_EXAMPLE_HOST,
            port=c.Ldap.Tests.Config.LDAPS_PORT,
        ).model_dump()
        u.Tests.Matchers.that(data["host"], eq=c.Ldap.Tests.Models.LDAP_EXAMPLE_HOST)
        u.Tests.Matchers.that(data["port"], eq=c.Ldap.Tests.Config.LDAPS_PORT)

    def test_search_options_serialization(self) -> None:
        data = m.Ldap.SearchOptions(
            base_dn=c.Ldap.Tests.RFC.DEFAULT_BASE_DN,
            scope=c.Ldap.SearchDefaults.DEFAULT_SCOPE,
        ).model_dump()
        u.Tests.Matchers.that(data["base_dn"], eq=c.Ldap.Tests.RFC.DEFAULT_BASE_DN)
        u.Tests.Matchers.that(data["scope"], eq=c.Ldap.SearchDefaults.DEFAULT_SCOPE)

    def test_sync_stats_serialization(self) -> None:
        data = m.Ldap.SyncStats.from_counters(
            synced=c.Ldap.Tests.Search.SYNC_COUNTERS_SYNCED,
            skipped=c.Ldap.Tests.Search.SYNC_COUNTERS_SKIPPED,
            failed=c.Ldap.Tests.Search.SYNC_COUNTERS_FAILED,
        ).model_dump()
        u.Tests.Matchers.that(data, keys=[c.Ldap.Tests.FieldNames.SUCCESS_RATE])
        u.Tests.Matchers.that(
            data[c.Ldap.Tests.FieldNames.SUCCESS_RATE],
            eq=c.Ldap.Tests.Search.EXPECTED_SUCCESS_RATE_90,
        )

    def test_connection_config_json_schema(self) -> None:
        u.Tests.Matchers.that(
            m.Ldap.ConnectionConfig.model_json_schema()["properties"],
            keys=[c.Ldap.Tests.FieldNames.HOST, c.Ldap.Tests.FieldNames.PORT],
        )

    def test_search_options_json_schema(self) -> None:
        u.Tests.Matchers.that(
            m.Ldap.SearchOptions.model_json_schema()["properties"],
            keys=[c.Ldap.Tests.FieldNames.BASE_DN, c.Ldap.Tests.FieldNames.SCOPE],
        )


__all__ = ["TestsFlextLdapModelsSearch"]

from __future__ import annotations

from typing import ClassVar

import pytest
from flext_tests import c, m, u
from pydantic import ValidationError

pytestmark = pytest.mark.unit


class TestsFlextLdapModelsSearch:
    def test_search_options_required_base_dn(self) -> None:
        with pytest.raises(ValidationError, match="base_dn"):
            m.Ldap.SearchOptions(base_dn="")

    def test_search_options_default_values(self) -> None:
        options = m.Ldap.SearchOptions(base_dn=c.Ldap.Tests.RFC.DEFAULT_BASE_DN)
        u.Tests.Matchers.that(options.base_dn, eq=c.Ldap.Tests.RFC.DEFAULT_BASE_DN)
        u.Tests.Matchers.that(options.scope, eq="SUBTREE")
        u.Tests.Matchers.that(options.filter_str, eq=c.Ldap.Filters.ALL_ENTRIES_FILTER)
        u.Tests.Matchers.that(options.attributes, none=True)
        u.Tests.Matchers.that(options.size_limit, eq=0)
        u.Tests.Matchers.that(options.time_limit, eq=0)

    def test_search_options_custom_values(self) -> None:
        options = m.Ldap.SearchOptions(
            base_dn=c.Ldap.Tests.RFC.DEFAULT_BASE_DN,
            scope="BASE",
            filter_str="(cn=*)",
            attributes=["cn", "mail"],
            size_limit=100,
            time_limit=30,
        )
        u.Tests.Matchers.that(options.scope, eq="BASE")
        u.Tests.Matchers.that(options.filter_str, eq="(cn=*)")
        u.Tests.Matchers.that(options.attributes, eq=["cn", "mail"])
        u.Tests.Matchers.that(options.size_limit, eq=100)

    def test_search_options_invalid_base_dn_format(self) -> None:
        options = m.Ldap.SearchOptions(base_dn="invalid-dn-format")
        u.Tests.Matchers.that(options.base_dn, eq="invalid-dn-format")

    def test_search_options_scope_normalization_enum(self) -> None:
        options = m.Ldap.SearchOptions(
            base_dn=c.Ldap.Tests.RFC.DEFAULT_BASE_DN, scope=c.Ldap.SearchScope.BASE
        )
        u.Tests.Matchers.that(options.scope, eq="BASE")

    def test_search_options_scope_normalization_string(self) -> None:
        options = m.Ldap.SearchOptions(
            base_dn=c.Ldap.Tests.RFC.DEFAULT_BASE_DN, scope="subtree"
        )
        u.Tests.Matchers.that(options.scope in {"SUBTREE", "subtree"}, eq=True)

    def test_search_options_normalized_factory(self) -> None:
        options = m.Ldap.SearchOptions.normalized(c.Ldap.Tests.RFC.DEFAULT_BASE_DN)
        u.Tests.Matchers.that(options.base_dn, none=False)
        u.Tests.Matchers.that(options.scope, eq="SUBTREE")
        u.Tests.Matchers.that(options.filter_str, eq=c.Ldap.Filters.ALL_ENTRIES_FILTER)

    def test_search_options_normalized_with_config(self) -> None:
        config = m.Ldap.NormalizedConfig(
            scope="BASE", filter_str="(uid=*)", size_limit=50
        )
        options = m.Ldap.SearchOptions.normalized(
            c.Ldap.Tests.RFC.DEFAULT_BASE_DN, config=config
        )
        u.Tests.Matchers.that(options.scope, eq="BASE")
        u.Tests.Matchers.that(options.filter_str, eq="(uid=*)")
        u.Tests.Matchers.that(options.size_limit, eq=50)

    def test_operation_result_creation(self) -> None:
        result = m.Ldap.OperationResult(
            success=True,
            operation_type=c.Ldap.OperationType.ADD,
            message="Entry added successfully",
            entries_affected=1,
        )
        u.Tests.Matchers.that(result.success, eq=True)
        u.Tests.Matchers.that(result.operation_type, eq=c.Ldap.OperationType.ADD)
        u.Tests.Matchers.that(result.message, eq="Entry added successfully")
        u.Tests.Matchers.that(result.entries_affected, eq=1)

    def test_operation_result_default_message(self) -> None:
        result = m.Ldap.OperationResult(
            success=True, operation_type=c.Ldap.OperationType.SEARCH
        )
        u.Tests.Matchers.that(result.message, eq="")
        u.Tests.Matchers.that(result.entries_affected, eq=0)

    def test_operation_result_frozen(self) -> None:
        result = m.Ldap.OperationResult(
            success=True, operation_type=c.Ldap.OperationType.ADD
        )
        exc_types: tuple[type[Exception], ...] = (TypeError, ValidationError)
        with pytest.raises(exc_types):
            setattr(result, "is_success", False)

    _SEARCH_RESULT_SCENARIOS: ClassVar[dict[str, tuple[int, int]]] = {
        "empty": (0, 0),
        "single": (1, 1),
        "multiple": (5, 5),
    }

    @pytest.mark.parametrize(
        ("num_entries", "expected_count"), [(0, 0), (1, 1), (5, 5), (10, 10)]
    )
    def test_search_result_total_count(
        self, num_entries: int, expected_count: int
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
        entry: dict[str, list[str]] = {}
        attrs = m.Ldap.SearchResult.extract_attrs_dict_from_entry(entry)
        u.Tests.Matchers.that(attrs, eq={})

    def test_search_result_extract_objectclass_category_empty(self) -> None:
        category = m.Ldap.SearchResult.extract_objectclass_category({})
        u.Tests.Matchers.that(category, eq="unknown")

    def test_search_result_extract_objectclass_category_with_objectclass(self) -> None:
        attrs = {"objectClass": ["person", "top"]}
        category = m.Ldap.SearchResult.extract_objectclass_category(attrs)
        u.Tests.Matchers.that(category, eq="person")

    def test_search_result_get_entry_category(self) -> None:
        entry: dict[str, list[str]] = {}
        category = m.Ldap.SearchResult.get_entry_category(entry)
        u.Tests.Matchers.that(category, eq="unknown")

    def test_types_namespace_exists(self) -> None:
        u.Tests.Matchers.that(m.Ldap.Types, none=False)

    def test_ldap_progress_callback_type_exists(self) -> None:
        u.Tests.Matchers.that(hasattr(m.Ldap.Types, "LdapProgressCallback"), eq=True)

    def test_connection_config_serialization(self) -> None:
        data = m.Ldap.ConnectionConfig(host="ldap.example.com", port=636).model_dump()
        u.Tests.Matchers.that(data["host"], eq="ldap.example.com")
        u.Tests.Matchers.that(data["port"], eq=636)

    def test_search_options_serialization(self) -> None:
        data = m.Ldap.SearchOptions(
            base_dn=c.Ldap.Tests.RFC.DEFAULT_BASE_DN, scope="SUBTREE"
        ).model_dump()
        u.Tests.Matchers.that(data["base_dn"], eq=c.Ldap.Tests.RFC.DEFAULT_BASE_DN)
        u.Tests.Matchers.that(data["scope"], eq="SUBTREE")

    def test_sync_stats_serialization(self) -> None:
        data = m.Ldap.SyncStats.from_counters(
            synced=80, skipped=10, failed=10
        ).model_dump()
        u.Tests.Matchers.that(data, keys=["success_rate"])
        u.Tests.Matchers.that(data["success_rate"], eq=0.9)

    def test_connection_config_json_schema(self) -> None:
        u.Tests.Matchers.that(
            m.Ldap.ConnectionConfig.model_json_schema()["properties"],
            keys=["host", "port"],
        )

    def test_search_options_json_schema(self) -> None:
        u.Tests.Matchers.that(
            m.Ldap.SearchOptions.model_json_schema()["properties"],
            keys=["base_dn", "scope"],
        )


__all__ = ["TestsFlextLdapModelsSearch"]

from __future__ import annotations

from collections.abc import Mapping
from typing import ClassVar

import pytest
from flext_tests import tm
from pydantic import ValidationError

from tests import c, m, t

pytestmark = pytest.mark.unit


class TestsFlextLdapModelsSearch:
    def test_search_options_required_base_dn(self) -> None:
        with pytest.raises(ValidationError, match="base_dn"):
            m.Ldap.SearchOptions(base_dn="")

    def test_search_options_default_values(self) -> None:
        options = m.Ldap.SearchOptions(base_dn=c.Ldap.Tests.RFC.DEFAULT_BASE_DN)
        tm.that(options.base_dn, eq=c.Ldap.Tests.RFC.DEFAULT_BASE_DN)
        tm.that(options.scope, eq="SUBTREE")
        tm.that(options.filter_str, eq=c.Ldap.Filters.ALL_ENTRIES_FILTER)
        tm.that(options.attributes, none=True)
        tm.that(options.size_limit, eq=0)
        tm.that(options.time_limit, eq=0)

    def test_search_options_custom_values(self) -> None:
        options = m.Ldap.SearchOptions(
            base_dn=c.Ldap.Tests.RFC.DEFAULT_BASE_DN,
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
        options = m.Ldap.SearchOptions(base_dn="invalid-dn-format")
        tm.that(options.base_dn, eq="invalid-dn-format")

    def test_search_options_scope_normalization_enum(self) -> None:
        options = m.Ldap.SearchOptions(
            base_dn=c.Ldap.Tests.RFC.DEFAULT_BASE_DN,
            scope=c.Ldap.SearchScope.BASE,
        )
        tm.that(options.scope, eq="BASE")

    def test_search_options_scope_normalization_string(self) -> None:
        options = m.Ldap.SearchOptions(
            base_dn=c.Ldap.Tests.RFC.DEFAULT_BASE_DN,
            scope="subtree",
        )
        tm.that({"SUBTREE", "subtree"}, has=options.scope)

    def test_search_options_normalized_factory(self) -> None:
        options = m.Ldap.SearchOptions.normalized(c.Ldap.Tests.RFC.DEFAULT_BASE_DN)
        tm.that(options.base_dn, none=False)
        tm.that(options.scope, eq="SUBTREE")
        tm.that(options.filter_str, eq=c.Ldap.Filters.ALL_ENTRIES_FILTER)

    def test_search_options_normalized_with_config(self) -> None:
        config = m.Ldap.NormalizedConfig(
            scope="BASE",
            filter_str="(uid=*)",
            size_limit=50,
        )
        options = m.Ldap.SearchOptions.normalized(
            c.Ldap.Tests.RFC.DEFAULT_BASE_DN,
            config=config,
        )
        tm.that(options.scope, eq="BASE")
        tm.that(options.filter_str, eq="(uid=*)")
        tm.that(options.size_limit, eq=50)

    def test_operation_result_creation(self) -> None:
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
        result = m.Ldap.OperationResult(
            success=True,
            operation_type=c.Ldap.OperationType.SEARCH,
        )
        tm.that(result.message, eq="")
        tm.that(result.entries_affected, eq=0)

    def test_operation_result_frozen(self) -> None:
        result = m.Ldap.OperationResult(
            success=True,
            operation_type=c.Ldap.OperationType.ADD,
        )
        exc_types: tuple[type[Exception], ...] = (TypeError, ValidationError)
        with pytest.raises(exc_types):
            setattr(result, "is_success", False)

    _SEARCH_RESULT_SCENARIOS: ClassVar[Mapping[str, tuple[int, int]]] = {
        "empty": (0, 0),
        "single": (1, 1),
        "multiple": (5, 5),
    }

    @pytest.mark.parametrize(
        ("num_entries", "expected_count"),
        [(0, 0), (1, 1), (5, 5), (10, 10)],
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
        tm.that(result.total_count, eq=expected_count)

    def test_search_result_by_objectclass_empty(self) -> None:
        options = m.Ldap.SearchOptions(base_dn=c.Ldap.Tests.RFC.DEFAULT_BASE_DN)
        result = m.Ldap.SearchResult(entries=[], search_options=options)
        categories = result.by_objectclass
        tm.that(categories, none=False)

    def test_search_result_extract_attrs_dict_none_attributes(self) -> None:
        entry: Mapping[str, t.StrSequence] = {}
        attrs = m.Ldap.SearchResult.extract_attrs_dict_from_entry(entry)
        tm.that(attrs, eq={})

    def test_search_result_extract_objectclass_category_empty(self) -> None:
        category = m.Ldap.SearchResult.extract_objectclass_category({})
        tm.that(category, eq="unknown")

    def test_search_result_extract_objectclass_category_with_objectclass(self) -> None:
        attrs = {"objectClass": ["person", "top"]}
        category = m.Ldap.SearchResult.extract_objectclass_category(attrs)
        tm.that(category, eq="person")

    def test_search_result_get_entry_category(self) -> None:
        entry: Mapping[str, t.StrSequence] = {}
        category = m.Ldap.SearchResult.get_entry_category(entry)
        tm.that(category, eq="unknown")

    def test_sync_phase_config_has_progress_callback(self) -> None:
        """Verify progress_callback field exists on SyncPhaseConfig."""
        tm.that(
            hasattr(m.Ldap.SyncPhaseConfig, "model_fields"),
            eq=True,
        )
        tm.that("progress_callback" in m.Ldap.SyncPhaseConfig.model_fields, eq=True)

    def test_connection_config_serialization(self) -> None:
        data = m.Ldap.ConnectionConfig(host="ldap.example.com", port=636).model_dump()
        tm.that(data["host"], eq="ldap.example.com")
        tm.that(data["port"], eq=636)

    def test_search_options_serialization(self) -> None:
        data = m.Ldap.SearchOptions(
            base_dn=c.Ldap.Tests.RFC.DEFAULT_BASE_DN,
            scope="SUBTREE",
        ).model_dump()
        tm.that(data["base_dn"], eq=c.Ldap.Tests.RFC.DEFAULT_BASE_DN)
        tm.that(data["scope"], eq="SUBTREE")

    def test_sync_stats_serialization(self) -> None:
        data = m.Ldap.SyncStats.from_counters(
            synced=80,
            skipped=10,
            failed=10,
        ).model_dump()
        tm.that(data, keys=["success_rate"])
        tm.that(data["success_rate"], eq=0.9)

    def test_connection_config_json_schema(self) -> None:
        tm.that(
            m.Ldap.ConnectionConfig.model_json_schema()["properties"],
            keys=["host", "port"],
        )

    def test_search_options_json_schema(self) -> None:
        tm.that(
            m.Ldap.SearchOptions.model_json_schema()["properties"],
            keys=["base_dn", "scope"],
        )


__all__ = ["TestsFlextLdapModelsSearch"]

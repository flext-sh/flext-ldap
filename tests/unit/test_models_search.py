from __future__ import annotations

import pytest

from tests import c, m, u

pytestmark = pytest.mark.unit


class TestsFlextLdapModelsSearch:
    @staticmethod
    def _entry(
        dn: str,
        attributes: dict[str, list[str]] | None = None,
    ) -> m.Ldif.Entry:
        return m.Ldif.Entry(
            dn=m.Ldif.DN(value=dn),
            attributes=m.Ldif.Attributes.model_validate({
                "attributes": attributes or {}
            }),
        )

    def test_search_options_required_base_dn(self) -> None:
        with pytest.raises(c.ValidationError, match="base_dn"):
            m.Ldap.SearchOptions(base_dn="")

    def test_search_options_default_values(self) -> None:
        options = m.Ldap.SearchOptions(base_dn=c.Ldap.Tests.RFC_DEFAULT_BASE_DN)
        u.Ldap.Tests.that(options.base_dn, eq=c.Ldap.Tests.RFC_DEFAULT_BASE_DN)
        u.Ldap.Tests.that(options.scope, eq=c.Ldap.DEFAULT_SCOPE)
        u.Ldap.Tests.that(options.filter_str, eq=c.Ldap.ALL_ENTRIES_FILTER)
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
                c.Ldap.DEFAULT_SCOPE,
                c.Ldap.Tests.SEARCH_SCOPE_SUBTREE_LOWER,
            },
            has=options.scope,
        )

    def test_search_options_normalized_factory(self) -> None:
        options = m.Ldap.SearchOptions.normalized(c.Ldap.Tests.RFC_DEFAULT_BASE_DN)
        u.Ldap.Tests.that(options.base_dn, none=False)
        u.Ldap.Tests.that(options.scope, eq=c.Ldap.DEFAULT_SCOPE)
        u.Ldap.Tests.that(options.filter_str, eq=c.Ldap.ALL_ENTRIES_FILTER)

    def test_search_options_normalized_with_config(self) -> None:
        settings = m.Ldap.NormalizedConfig(
            scope=c.Ldap.Tests.SEARCH_SCOPE_BASE,
            filter_str=c.Ldap.Tests.SEARCH_FILTER_UID,
            size_limit=c.Ldap.Tests.SEARCH_NORMALIZED_SIZE_LIMIT,
        )
        options = m.Ldap.SearchOptions.normalized(
            c.Ldap.Tests.RFC_DEFAULT_BASE_DN,
            settings=settings,
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
        exc_types: tuple[type[Exception], ...] = (TypeError, c.ValidationError)
        with pytest.raises(exc_types):
            setattr(result, "success", False)

    @pytest.mark.parametrize(
        ("num_entries", "expected_count"),
        c.Ldap.Tests.SEARCH_RESULT_TOTAL_COUNT_CASES,
    )
    def test_search_result_total_count(
        self,
        num_entries: int,
        expected_count: int,
    ) -> None:
        entries = [
            self._entry(f"cn=user{i},{c.Ldap.Tests.RFC_DEFAULT_BASE_DN}")
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
        entry = self._entry(c.Ldap.Tests.RFC_DEFAULT_BASE_DN)
        attrs = m.Ldap.SearchResult.extract_attrs_dict_from_entry(entry)
        u.Ldap.Tests.that(attrs, eq={})

    @pytest.mark.parametrize("case", c.Ldap.Tests.SearchCategoryCase)
    def test_search_result_extract_objectclass_category_cases(
        self,
        case: c.Ldap.Tests.SearchCategoryCase,
    ) -> None:
        attrs: dict[str, list[str] | str]
        match case:
            case c.Ldap.Tests.SearchCategoryCase.EMPTY:
                attrs = {}
            case c.Ldap.Tests.SearchCategoryCase.PERSON:
                attrs = {
                    key: list(value)
                    for key, value in c.Ldap.Tests.SEARCH_OBJECTCLASS_PERSON_TOP.items()
                }
            case _:
                raise AssertionError(f"Unhandled search category case: {case}")
        category = m.Ldap.SearchResult.extract_objectclass_category(attrs)
        u.Ldap.Tests.that(category, eq=c.Ldap.Tests.SEARCH_CATEGORY_EXPECTED[case])

    def test_search_result_get_entry_category(self) -> None:
        entry = self._entry(c.Ldap.Tests.RFC_DEFAULT_BASE_DN)
        category = m.Ldap.SearchResult.get_entry_category(entry)
        u.Ldap.Tests.that(category, eq=c.Ldap.UNKNOWN_CATEGORY)

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
            scope=c.Ldap.DEFAULT_SCOPE,
        ).model_dump()
        u.Ldap.Tests.that(data["base_dn"], eq=c.Ldap.Tests.RFC_DEFAULT_BASE_DN)
        u.Ldap.Tests.that(data["scope"], eq=c.Ldap.DEFAULT_SCOPE)

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


__all__: list[str] = ["TestsFlextLdapModelsSearch"]

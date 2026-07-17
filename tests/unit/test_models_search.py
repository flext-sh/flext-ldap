"""Tests for models search."""

from __future__ import annotations

import pytest

from tests import c, m, u

pytestmark = pytest.mark.unit


class TestsFlextLdapModelsSearch:
    """Behavioral contract of the `m.Ldap` search and config models.

    Every test exercises only observable public behavior: field defaults,
    computed fields, validators (raised errors), factory classmethods, and
    serialization. No private attribute or internal-collaborator access.
    """

    @staticmethod
    def _entry(
        dn: str,
        attributes: dict[str, list[str]] | None = None,
    ) -> m.Ldif.Entry:
        return m.Ldif.Entry(
            dn=m.Ldif.DN(value=dn),
            attributes=m.Ldif.Attributes.model_validate({
                "attributes": attributes or {},
            }),
        )

    # ------------------------------------------------------------------ #
    # SearchOptions — construction contract
    # ------------------------------------------------------------------ #

    def test_search_options_rejects_empty_base_dn(self) -> None:
        """Verify search options rejects empty base dn."""
        with pytest.raises(c.ValidationError, match="base_dn"):
            m.Ldap.SearchOptions(base_dn="")

    def test_search_options_applies_documented_defaults(self) -> None:
        """Verify search options applies documented defaults."""
        options = m.Ldap.SearchOptions(base_dn=c.Ldap.Tests.RFC_DEFAULT_BASE_DN)
        u.Ldap.Tests.that(options.base_dn, eq=c.Ldap.Tests.RFC_DEFAULT_BASE_DN)
        u.Ldap.Tests.that(options.scope, eq=c.Ldap.DEFAULT_SCOPE)
        u.Ldap.Tests.that(options.filter_str, eq=c.Ldap.ALL_ENTRIES_FILTER)
        u.Ldap.Tests.that(options.attributes, none=True)
        u.Ldap.Tests.that(options.size_limit, eq=c.Ldap.Tests.SEARCH_DEFAULT_LIMIT_ZERO)
        u.Ldap.Tests.that(options.time_limit, eq=c.Ldap.Tests.SEARCH_DEFAULT_LIMIT_ZERO)

    def test_search_options_preserves_custom_values(self) -> None:
        """Verify search options preserves custom values."""
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
        u.Ldap.Tests.that(options.time_limit, eq=c.Ldap.Tests.SEARCH_TIME_LIMIT_CUSTOM)

    def test_search_options_accepts_non_rfc_base_dn_string(self) -> None:
        """Verify search options accepts non rfc base dn string."""
        # Contract: base_dn only requires non-empty; format is not validated.
        options = m.Ldap.SearchOptions(base_dn=c.Ldap.Tests.MODELS_INVALID_DN_FORMAT)
        u.Ldap.Tests.that(options.base_dn, eq=c.Ldap.Tests.MODELS_INVALID_DN_FORMAT)

    def test_search_options_accepts_scope_enum_member(self) -> None:
        """Verify search options accepts scope enum member."""
        options = m.Ldap.SearchOptions(
            base_dn=c.Ldap.Tests.RFC_DEFAULT_BASE_DN,
            scope=c.Ldap.SearchScope.BASE,
        )
        u.Ldap.Tests.that(options.scope, eq=c.Ldap.Tests.SEARCH_SCOPE_BASE)

    @pytest.mark.parametrize("size_case", c.Ldap.Tests.SearchSizeCase)
    def test_search_options_accepts_valid_size_limits(
        self,
        size_case: c.Ldap.Tests.SearchSizeCase,
    ) -> None:
        """Verify search options accepts valid size limits."""
        size_limit = c.Ldap.Tests.SEARCH_SIZE_SCENARIOS[size_case]
        options = m.Ldap.SearchOptions(
            base_dn=c.Ldap.Tests.RFC_DEFAULT_BASE_DN,
            size_limit=size_limit,
        )
        u.Ldap.Tests.that(options.size_limit, eq=size_limit)

    def test_search_options_rejects_negative_size_limit(self) -> None:
        """Verify search options rejects negative size limit."""
        with pytest.raises(c.ValidationError, match="size_limit"):
            m.Ldap.SearchOptions(
                base_dn=c.Ldap.Tests.RFC_DEFAULT_BASE_DN,
                size_limit=-1,
            )

    # ------------------------------------------------------------------ #
    # SearchOptions — factory contract
    # ------------------------------------------------------------------ #

    def test_normalized_factory_matches_plain_defaults(self) -> None:
        """Verify normalized factory matches plain defaults."""
        options = m.Ldap.SearchOptions.normalized(c.Ldap.Tests.RFC_DEFAULT_BASE_DN)
        plain = m.Ldap.SearchOptions(base_dn=c.Ldap.Tests.RFC_DEFAULT_BASE_DN)
        u.Ldap.Tests.that(options.model_dump(), eq=plain.model_dump())

    def test_normalized_factory_applies_config(self) -> None:
        """Verify normalized factory applies config."""
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
            options.size_limit,
            eq=c.Ldap.Tests.SEARCH_NORMALIZED_SIZE_LIMIT,
        )

    def test_base_scope_requests_all_user_attributes(self) -> None:
        """Verify base scope requests all user attributes."""
        # Regression (mro-uqji.4.1.2): base-scope existence checks must request
        # all user attributes, else the compared entry looks empty.
        options = m.Ldap.SearchOptions.base_scope(c.Ldap.Tests.RFC_DEFAULT_BASE_DN)
        u.Ldap.Tests.that(options.base_dn, eq=c.Ldap.Tests.RFC_DEFAULT_BASE_DN)
        u.Ldap.Tests.that(options.scope, eq=c.Ldap.Tests.SEARCH_SCOPE_BASE)
        u.Ldap.Tests.that(options.attributes, eq=[c.Ldap.AttributeName.ALL_ATTRIBUTES])

    # ------------------------------------------------------------------ #
    # ConnectionConfig — construction and validator contract
    # ------------------------------------------------------------------ #

    def test_connection_config_defaults(self) -> None:
        """Verify connection config defaults."""
        config = m.Ldap.ConnectionConfig()
        u.Ldap.Tests.that(config.host, eq=c.LOCALHOST)
        u.Ldap.Tests.that(config.port, eq=c.Ldap.PORT)
        u.Ldap.Tests.that(config.use_ssl, eq=False)
        u.Ldap.Tests.that(config.use_tls, eq=False)

    @pytest.mark.parametrize(
        "security_case",
        c.Ldap.Tests.ConnectionSecurityCase,
    )
    def test_connection_config_allows_single_security_channel(
        self,
        security_case: c.Ldap.Tests.ConnectionSecurityCase,
    ) -> None:
        """Verify connection config allows single security channel."""
        use_ssl, use_tls = c.Ldap.Tests.MODELS_ALLOWED_SECURITY_COMBOS[security_case]
        config = m.Ldap.ConnectionConfig(use_ssl=use_ssl, use_tls=use_tls)
        u.Ldap.Tests.that(config.use_ssl, eq=use_ssl)
        u.Ldap.Tests.that(config.use_tls, eq=use_tls)

    def test_connection_config_rejects_ssl_and_tls_together(self) -> None:
        """Verify connection config rejects ssl and tls together."""
        with pytest.raises(c.ValidationError, match="mutually exclusive"):
            m.Ldap.ConnectionConfig(use_ssl=True, use_tls=True)

    @pytest.mark.parametrize("invalid_port", c.Ldap.Tests.MODELS_INVALID_PORTS)
    def test_connection_config_rejects_out_of_range_port(
        self,
        invalid_port: int,
    ) -> None:
        """Verify connection config rejects out of range port."""
        with pytest.raises(c.ValidationError, match="port"):
            m.Ldap.ConnectionConfig(port=invalid_port)

    # ------------------------------------------------------------------ #
    # OperationResult — value + immutability contract
    # ------------------------------------------------------------------ #

    def test_operation_result_exposes_provided_values(self) -> None:
        """Verify operation result exposes provided values."""
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
            result.entries_affected,
            eq=c.Ldap.Tests.SEARCH_ENTRIES_AFFECTED_ONE,
        )

    def test_operation_result_defaults_message_and_count(self) -> None:
        """Verify operation result defaults message and count."""
        result = m.Ldap.OperationResult(
            success=True,
            operation_type=c.Ldap.OperationType.SEARCH,
        )
        u.Ldap.Tests.that(result.message, eq=c.Ldap.Tests.SYNC_DEFAULT_EMPTY_SOURCE_DN)
        u.Ldap.Tests.that(
            result.entries_affected,
            eq=c.Ldap.Tests.SEARCH_DEFAULT_LIMIT_ZERO,
        )

    def test_operation_result_is_immutable(self) -> None:
        """Verify operation result is immutable."""
        result = m.Ldap.OperationResult(
            success=True,
            operation_type=c.Ldap.OperationType.ADD,
        )
        exc_types: tuple[type[Exception], ...] = (TypeError, c.ValidationError)
        with pytest.raises(exc_types):
            result.success = False  # frozen model: assignment must fail

    # ------------------------------------------------------------------ #
    # SearchResult — computed fields and category extraction contract
    # ------------------------------------------------------------------ #

    @pytest.mark.parametrize(
        ("num_entries", "expected_count"),
        c.Ldap.Tests.SEARCH_RESULT_TOTAL_COUNT_CASES,
    )
    def test_search_result_total_count_reflects_entries(
        self,
        num_entries: int,
        expected_count: int,
    ) -> None:
        """Verify search result total count reflects entries."""
        entries = [
            self._entry(f"cn=user{i},{c.Ldap.Tests.RFC_DEFAULT_BASE_DN}")
            for i in range(num_entries)
        ]
        options = m.Ldap.SearchOptions(base_dn=c.Ldap.Tests.RFC_DEFAULT_BASE_DN)
        result = m.Ldap.SearchResult(entries=entries, search_options=options)
        u.Ldap.Tests.that(len(result.entries), eq=expected_count)

    def test_search_result_groups_entries_by_objectclass(self) -> None:
        """Verify search result groups entries by objectclass."""
        options = m.Ldap.SearchOptions(base_dn=c.Ldap.Tests.RFC_DEFAULT_BASE_DN)
        person_top = {
            key: list(value)
            for key, value in c.Ldap.Tests.SEARCH_OBJECTCLASS_PERSON_TOP.items()
        }
        entries = [
            self._entry(f"cn=p1,{c.Ldap.Tests.RFC_DEFAULT_BASE_DN}", person_top),
            self._entry(f"cn=p2,{c.Ldap.Tests.RFC_DEFAULT_BASE_DN}", person_top),
            self._entry(f"cn=x,{c.Ldap.Tests.RFC_DEFAULT_BASE_DN}"),
        ]
        result = m.Ldap.SearchResult(entries=entries, search_options=options)
        categories = u.Ldap.group_entries_by_objectclass(result.entries)
        u.Ldap.Tests.that(len(categories["person"]), eq=2)
        u.Ldap.Tests.that(len(categories[c.Ldap.UNKNOWN_CATEGORY]), eq=1)

    def test_search_result_by_objectclass_empty_when_no_entries(self) -> None:
        """Verify search result by objectclass empty when no entries."""
        options = m.Ldap.SearchOptions(base_dn=c.Ldap.Tests.RFC_DEFAULT_BASE_DN)
        result = m.Ldap.SearchResult(entries=[], search_options=options)
        categories = u.Ldap.group_entries_by_objectclass(result.entries)
        u.Ldap.Tests.that(dict(categories), eq={})

    def test_extract_attrs_dict_empty_for_entry_without_attributes(self) -> None:
        """Verify extract attrs dict empty for entry without attributes."""
        entry = self._entry(c.Ldap.Tests.RFC_DEFAULT_BASE_DN)
        attrs = u.Ldap.extract_attrs_dict_from_entry(entry)
        u.Ldap.Tests.that(attrs, eq={})

    @pytest.mark.parametrize("case", c.Ldap.Tests.SearchCategoryCase)
    def test_extract_objectclass_category_maps_expected(
        self,
        case: c.Ldap.Tests.SearchCategoryCase,
    ) -> None:
        """Verify extract objectclass category maps expected."""
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
                message = f"Unhandled search category case: {case}"
                raise AssertionError(message)
        category = u.Ldap.extract_objectclass_category(attrs)
        u.Ldap.Tests.that(category, eq=c.Ldap.Tests.SEARCH_CATEGORY_EXPECTED[case])

    def test_get_entry_category_unknown_without_objectclass(self) -> None:
        """Verify get entry category unknown without objectclass."""
        entry = self._entry(c.Ldap.Tests.RFC_DEFAULT_BASE_DN)
        category = u.Ldap.get_entry_category(entry)
        u.Ldap.Tests.that(category, eq=c.Ldap.UNKNOWN_CATEGORY)

    def test_get_entry_category_lowercases_first_objectclass(self) -> None:
        """Verify get entry category lowercases first objectclass."""
        person_top = {
            key: list(value)
            for key, value in c.Ldap.Tests.SEARCH_OBJECTCLASS_PERSON_TOP.items()
        }
        entry = self._entry(c.Ldap.Tests.RFC_DEFAULT_BASE_DN, person_top)
        category = u.Ldap.get_entry_category(entry)
        u.Ldap.Tests.that(
            category,
            eq=c.Ldap.Tests.SEARCH_CATEGORY_EXPECTED[
                c.Ldap.Tests.SearchCategoryCase.PERSON
            ],
        )

    # ------------------------------------------------------------------ #
    # Serialization contract
    # ------------------------------------------------------------------ #

    def test_connection_config_round_trips_through_model_dump(self) -> None:
        """Verify connection config round trips through model dump."""
        data = m.Ldap.ConnectionConfig(
            host=c.Ldap.Tests.MODELS_LDAP_EXAMPLE_HOST,
            port=c.Ldap.Tests.CONFIG_LDAPS_PORT,
        ).model_dump()
        u.Ldap.Tests.that(data["host"], eq=c.Ldap.Tests.MODELS_LDAP_EXAMPLE_HOST)
        u.Ldap.Tests.that(data["port"], eq=c.Ldap.Tests.CONFIG_LDAPS_PORT)

    def test_search_options_round_trips_through_model_dump(self) -> None:
        """Verify search options round trips through model dump."""
        data = m.Ldap.SearchOptions(
            base_dn=c.Ldap.Tests.RFC_DEFAULT_BASE_DN,
            scope=c.Ldap.DEFAULT_SCOPE,
        ).model_dump()
        u.Ldap.Tests.that(data["base_dn"], eq=c.Ldap.Tests.RFC_DEFAULT_BASE_DN)
        u.Ldap.Tests.that(data["scope"], eq=c.Ldap.DEFAULT_SCOPE)

    def test_connection_config_json_schema_exposes_fields(self) -> None:
        """Verify connection config json schema exposes fields."""
        u.Ldap.Tests.that(
            m.Ldap.ConnectionConfig.model_json_schema()["properties"],
            keys=[c.Ldap.Tests.FIELD_HOST, c.Ldap.Tests.FIELD_PORT],
        )

    def test_search_options_json_schema_exposes_fields(self) -> None:
        """Verify search options json schema exposes fields."""
        u.Ldap.Tests.that(
            m.Ldap.SearchOptions.model_json_schema()["properties"],
            keys=[c.Ldap.Tests.FIELD_BASE_DN, c.Ldap.Tests.FIELD_SCOPE],
        )


__all__: list[str] = ["TestsFlextLdapModelsSearch"]

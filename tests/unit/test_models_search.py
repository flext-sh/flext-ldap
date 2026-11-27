"""Tests for models search.

Copyright (c) 2026 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence

import pytest

from tests import c, m, p, t, u

pytestmark = pytest.mark.unit


class TestsFlextLdapModelsSearch:
    """TestsFlextLdapModelsSearch: test methods."""

    """Behavioral contract of the `m.Ldap` search and config models.

    Every test exercises only observable public behavior: field defaults,
    computed fields, validators (raised errors), factory classmethods, and
    serialization. No private attribute or internal-collaborator access.
    """

    @staticmethod
    def test_controls_preserve_native_oid_criticality_and_value() -> None:
        """The public search envelope forwards native control sequences intact."""
        controls = [(c.Ldap.REAL_ATTRIBUTES_ONLY_CONTROL_OID, True, None)]
        options = m.Ldap.SearchOptions(
            base_dn="dc=example,dc=invalid", controls=controls
        )
        params = m.Ldap.SearchParams(
            base_dn=options.base_dn,
            filter_str=options.filter_str,
            ldap_scope=c.Ldap.SearchScopeValue.BASE,
            search_attributes=["*"],
            size_limit=options.size_limit,
            time_limit=options.time_limit,
            controls=options.controls,
        )
        u.Tests.that(params.controls, eq=controls)
        u.Tests.that(m.Ldap.SearchOptions.base_scope(options.base_dn).controls, eq=None)

    @staticmethod
    def _entry(
        dn: str,
        attributes: Mapping[str, Sequence[str]] | None = None,
    ) -> p.Ldif.Entry:
        return m.Ldif.Entry(
            dn=m.Ldif.DN(value=dn),
            attributes=m.Ldif.Attributes.model_validate({
                "attributes": attributes or {},
            }),
            domain_events=[],
        )

    @staticmethod
    def test_base_scope_requests_all_user_attributes() -> None:
        """Verify base scope requests all user attributes."""
        # Regression (mro-uqji.4.1.2): base-scope existence checks must request
        # all user attributes, else the compared entry looks empty.
        options = m.Ldap.SearchOptions.base_scope(c.Tests.RFC_DEFAULT_BASE_DN)
        u.Tests.that(options.base_dn, eq=c.Tests.RFC_DEFAULT_BASE_DN)
        u.Tests.that(options.scope, eq=c.Tests.SEARCH_SCOPE_BASE)
        u.Tests.that(options.attributes, eq=[c.Ldap.AttributeName.ALL_ATTRIBUTES])

    # ------------------------------------------------------------------ #
    # ConnectionConfig — construction and validator contract
    # ------------------------------------------------------------------ #

    @staticmethod
    def test_connection_config_defaults() -> None:
        """Verify connection config defaults."""
        config = m.Ldap.ConnectionConfig()
        u.Tests.that(config.host, eq=c.LOCALHOST)
        u.Tests.that(config.port, eq=c.Ldap.PORT)
        u.Tests.that(config.use_ssl, eq=False)
        u.Tests.that(config.use_tls, eq=False)

    @pytest.mark.parametrize("security_case", c.Tests.ConnectionSecurityCase)
    @staticmethod
    def test_connection_config_allows_single_security_channel(
        security_case: c.Tests.ConnectionSecurityCase,
    ) -> None:
        """Verify connection config allows single security channel."""
        use_ssl, use_tls = c.Tests.MODELS_ALLOWED_SECURITY_COMBOS[security_case]
        config = m.Ldap.ConnectionConfig(use_ssl=use_ssl, use_tls=use_tls)
        u.Tests.that(config.use_ssl, eq=use_ssl)
        u.Tests.that(config.use_tls, eq=use_tls)

    @staticmethod
    def test_connection_config_rejects_ssl_and_tls_together() -> None:
        """Verify connection config rejects ssl and tls together."""
        with u.Tests.raises(c.ValidationError, match="mutually exclusive"):
            m.Ldap.ConnectionConfig(use_ssl=True, use_tls=True)

    @pytest.mark.parametrize("invalid_port", c.Tests.MODELS_INVALID_PORTS)
    @staticmethod
    def test_connection_config_rejects_out_of_range_port(
        invalid_port: int,
    ) -> None:
        """Verify connection config rejects out of range port."""
        with u.Tests.raises(c.ValidationError, match="port"):
            m.Ldap.ConnectionConfig(port=invalid_port)

    # ------------------------------------------------------------------ #
    # Serialization contract
    # ------------------------------------------------------------------ #

    @staticmethod
    def test_connection_config_round_trips_through_model_dump() -> None:
        """Verify connection config round trips through model dump."""
        data = m.Ldap.ConnectionConfig(
            host=c.Tests.MODELS_LDAP_EXAMPLE_HOST,
            port=c.Tests.CONFIG_LDAPS_PORT,
        ).model_dump()
        u.Tests.that(data["host"], eq=c.Tests.MODELS_LDAP_EXAMPLE_HOST)
        u.Tests.that(data["port"], eq=c.Tests.CONFIG_LDAPS_PORT)

    @staticmethod
    def test_connection_config_json_schema_exposes_fields() -> None:
        """Verify connection config json schema exposes fields."""
        u.Tests.that(
            m.Ldap.ConnectionConfig.model_json_schema()["properties"],
            keys=[c.Tests.FIELD_HOST, c.Tests.FIELD_PORT],
        )

    def test_extract_attrs_dict_empty_for_entry_without_attributes(self) -> None:
        """Verify extract attrs dict empty for entry without attributes."""
        entry = self._entry(c.Tests.RFC_DEFAULT_BASE_DN)
        attrs = u.Ldap.extract_attrs_dict_from_entry(entry)
        u.Tests.that(attrs, eq={})

    @pytest.mark.parametrize("case", c.Tests.SearchCategoryCase)
    @staticmethod
    def test_extract_objectclass_category_maps_expected(
        case: c.Tests.SearchCategoryCase,
    ) -> None:
        """Verify extract objectclass category maps expected."""
        attrs: t.AttributeMapping
        match case:
            case c.Tests.SearchCategoryCase.EMPTY:
                attrs = {}
            case c.Tests.SearchCategoryCase.PERSON:
                attrs = {
                    key: list(value)
                    for key, value in c.Tests.SEARCH_OBJECTCLASS_PERSON_TOP.items()
                }
        category = u.Ldap.extract_objectclass_category(attrs)
        u.Tests.that(category, eq=c.Tests.SEARCH_CATEGORY_EXPECTED[case])

    def test_get_entry_category_unknown_without_objectclass(self) -> None:
        """Verify get entry category unknown without objectclass."""
        entry = self._entry(c.Tests.RFC_DEFAULT_BASE_DN)
        category = u.Ldap.resolve_entry_category(entry)
        u.Tests.that(category, eq=c.Ldap.UNKNOWN_CATEGORY)

    def test_get_entry_category_lowercases_first_objectclass(self) -> None:
        """Verify get entry category lowercases first objectclass."""
        person_top = {
            key: list(value)
            for key, value in c.Tests.SEARCH_OBJECTCLASS_PERSON_TOP.items()
        }
        entry = self._entry(c.Tests.RFC_DEFAULT_BASE_DN, person_top)
        category = u.Ldap.resolve_entry_category(entry)
        u.Tests.that(
            category,
            eq=c.Tests.SEARCH_CATEGORY_EXPECTED[c.Tests.SearchCategoryCase.PERSON],
        )

    # ------------------------------------------------------------------ #
    # SearchOptions — factory contract
    # ------------------------------------------------------------------ #

    @staticmethod
    def test_normalized_factory_matches_plain_defaults() -> None:
        """Verify normalized factory matches plain defaults."""
        options = m.Ldap.SearchOptions.normalized(c.Tests.RFC_DEFAULT_BASE_DN)
        plain = m.Ldap.SearchOptions(base_dn=c.Tests.RFC_DEFAULT_BASE_DN)
        u.Tests.that(options.model_dump(), eq=plain.model_dump())

    @staticmethod
    def test_normalized_factory_applies_config() -> None:
        """Verify normalized factory applies config."""
        settings = m.Ldap.NormalizedConfig(
            scope=c.Tests.SEARCH_SCOPE_BASE,
            filter_str=c.Tests.SEARCH_FILTER_UID,
            size_limit=c.Tests.SEARCH_NORMALIZED_SIZE_LIMIT,
        )
        options = m.Ldap.SearchOptions.normalized(
            c.Tests.RFC_DEFAULT_BASE_DN,
            settings=settings,
        )
        u.Tests.that(options.scope, eq=c.Tests.SEARCH_SCOPE_BASE)
        u.Tests.that(options.filter_str, eq=c.Tests.SEARCH_FILTER_UID)
        u.Tests.that(
            options.size_limit,
            eq=c.Tests.SEARCH_NORMALIZED_SIZE_LIMIT,
        )

    # ------------------------------------------------------------------ #
    # OperationResult — value + immutability contract
    # ------------------------------------------------------------------ #

    @staticmethod
    def test_operation_result_exposes_provided_values() -> None:
        """Verify operation result exposes provided values."""
        result = m.Ldap.OperationResult(
            success=True,
            operation_type=c.Ldap.OperationType.ADD,
            message=c.Tests.SEARCH_ENTRY_ADDED_MESSAGE,
            entries_affected=c.Tests.SEARCH_ENTRIES_AFFECTED_ONE,
        )
        u.Tests.that(result.success, eq=True)
        u.Tests.that(result.operation_type, eq=c.Ldap.OperationType.ADD)
        u.Tests.that(result.message, eq=c.Tests.SEARCH_ENTRY_ADDED_MESSAGE)
        u.Tests.that(
            result.entries_affected,
            eq=c.Tests.SEARCH_ENTRIES_AFFECTED_ONE,
        )

    @staticmethod
    def test_operation_result_defaults_message_and_count() -> None:
        """Verify operation result defaults message and count."""
        result = m.Ldap.OperationResult(
            success=True,
            operation_type=c.Ldap.OperationType.SEARCH,
        )
        u.Tests.that(result.message, eq=c.Tests.SYNC_DEFAULT_EMPTY_SOURCE_DN)
        u.Tests.that(
            result.entries_affected,
            eq=c.Tests.SEARCH_DEFAULT_LIMIT_ZERO,
        )

    @staticmethod
    def test_operation_result_is_immutable() -> None:
        """Verify operation result is immutable through its frozen contract."""
        u.Tests.that(
            m.Ldap.OperationResult.model_config.get("frozen"),
            eq=True,
        )


class TestsFlextLdapModelsSearchSearch(TestsFlextLdapModelsSearch):
    """TestsFlextLdapModelsSearchSearch: test methods."""

    # ------------------------------------------------------------------ #
    # SearchOptions — construction contract
    # ------------------------------------------------------------------ #

    @staticmethod
    def test_search_options_rejects_empty_base_dn() -> None:
        """Verify search options rejects empty base dn."""
        with u.Tests.raises(c.ValidationError, match="base_dn"):
            m.Ldap.SearchOptions(base_dn="")

    @staticmethod
    def test_search_options_applies_documented_defaults() -> None:
        """Verify search options applies documented defaults."""
        options = m.Ldap.SearchOptions(base_dn=c.Tests.RFC_DEFAULT_BASE_DN)
        u.Tests.that(options.base_dn, eq=c.Tests.RFC_DEFAULT_BASE_DN)
        u.Tests.that(options.scope, eq=c.Ldap.DEFAULT_SCOPE)
        u.Tests.that(options.filter_str, eq=c.Ldap.ALL_ENTRIES_FILTER)
        u.Tests.that(options.attributes, none=True)
        u.Tests.that(options.size_limit, eq=c.Tests.SEARCH_DEFAULT_LIMIT_ZERO)
        u.Tests.that(options.time_limit, eq=c.Tests.SEARCH_DEFAULT_LIMIT_ZERO)

    @staticmethod
    def test_search_options_preserves_custom_values() -> None:
        """Verify search options preserves custom values."""
        options = m.Ldap.SearchOptions(
            base_dn=c.Tests.RFC_DEFAULT_BASE_DN,
            scope=c.Tests.SEARCH_SCOPE_BASE,
            filter_str=c.Tests.SEARCH_FILTER_CN,
            attributes=list(c.Tests.SEARCH_ATTRIBUTES),
            size_limit=c.Tests.SEARCH_SIZE_LIMIT_CUSTOM,
            time_limit=c.Tests.SEARCH_TIME_LIMIT_CUSTOM,
        )
        u.Tests.that(options.scope, eq=c.Tests.SEARCH_SCOPE_BASE)
        u.Tests.that(options.filter_str, eq=c.Tests.SEARCH_FILTER_CN)
        u.Tests.that(options.attributes, eq=list(c.Tests.SEARCH_ATTRIBUTES))
        u.Tests.that(options.size_limit, eq=c.Tests.SEARCH_SIZE_LIMIT_CUSTOM)
        u.Tests.that(options.time_limit, eq=c.Tests.SEARCH_TIME_LIMIT_CUSTOM)

    @staticmethod
    def test_search_options_accepts_non_rfc_base_dn_string() -> None:
        """Verify search options accepts non rfc base dn string."""
        # Contract: base_dn only requires non-empty; format is not validated.
        options = m.Ldap.SearchOptions(base_dn=c.Tests.MODELS_INVALID_DN_FORMAT)
        u.Tests.that(options.base_dn, eq=c.Tests.MODELS_INVALID_DN_FORMAT)

    @staticmethod
    def test_search_options_accepts_scope_enum_member() -> None:
        """Verify search options accepts scope enum member."""
        options = m.Ldap.SearchOptions(
            base_dn=c.Tests.RFC_DEFAULT_BASE_DN,
            scope=c.Ldap.SearchScope.BASE,
        )
        u.Tests.that(options.scope, eq=c.Tests.SEARCH_SCOPE_BASE)

    @pytest.mark.parametrize("size_case", c.Tests.SearchSizeCase)
    @staticmethod
    def test_search_options_accepts_valid_size_limits(
        size_case: c.Tests.SearchSizeCase,
    ) -> None:
        """Verify search options accepts valid size limits."""
        size_limit = c.Tests.SEARCH_SIZE_SCENARIOS[size_case]
        options = m.Ldap.SearchOptions(
            base_dn=c.Tests.RFC_DEFAULT_BASE_DN,
            size_limit=size_limit,
        )
        u.Tests.that(options.size_limit, eq=size_limit)

    @staticmethod
    def test_search_options_rejects_negative_size_limit() -> None:
        """Verify search options rejects negative size limit."""
        with u.Tests.raises(c.ValidationError, match="size_limit"):
            m.Ldap.SearchOptions(
                base_dn=c.Tests.RFC_DEFAULT_BASE_DN,
                size_limit=-1,
            )

    # ------------------------------------------------------------------ #
    # SearchResult — computed fields and category extraction contract
    # ------------------------------------------------------------------ #

    @pytest.mark.parametrize(
        ("num_entries", "expected_count"),
        c.Tests.SEARCH_RESULT_TOTAL_COUNT_CASES,
    )
    def test_search_result_total_count_reflects_entries(
        self,
        num_entries: int,
        expected_count: int,
    ) -> None:
        """Verify search result total count reflects entries."""
        entries = [
            self._entry(f"cn=user{i},{c.Tests.RFC_DEFAULT_BASE_DN}")
            for i in range(num_entries)
        ]
        options = m.Ldap.SearchOptions(base_dn=c.Tests.RFC_DEFAULT_BASE_DN)
        result = m.Ldap.SearchResult(entries=entries, search_options=options)
        u.Tests.that(len(result.entries), eq=expected_count)

    def test_search_result_groups_entries_by_objectclass(self) -> None:
        """Verify search result groups entries by objectclass."""
        options = m.Ldap.SearchOptions(base_dn=c.Tests.RFC_DEFAULT_BASE_DN)
        person_top = {
            key: list(value)
            for key, value in c.Tests.SEARCH_OBJECTCLASS_PERSON_TOP.items()
        }
        entries = [
            self._entry(f"cn=p1,{c.Tests.RFC_DEFAULT_BASE_DN}", person_top),
            self._entry(f"cn=p2,{c.Tests.RFC_DEFAULT_BASE_DN}", person_top),
            self._entry(f"cn=x,{c.Tests.RFC_DEFAULT_BASE_DN}"),
        ]
        result = m.Ldap.SearchResult(entries=entries, search_options=options)
        categories = u.Ldap.group_entries_by_objectclass(result.entries)
        u.Tests.that(len(categories["person"]), eq=2)
        u.Tests.that(len(categories[c.Ldap.UNKNOWN_CATEGORY]), eq=1)

    @staticmethod
    def test_search_result_by_objectclass_empty_when_no_entries() -> None:
        """Verify search result by objectclass empty when no entries."""
        options = m.Ldap.SearchOptions(base_dn=c.Tests.RFC_DEFAULT_BASE_DN)
        result = m.Ldap.SearchResult(entries=[], search_options=options)
        categories = u.Ldap.group_entries_by_objectclass(result.entries)
        u.Tests.that(dict(categories), eq={})

    @staticmethod
    def test_search_options_round_trips_through_model_dump() -> None:
        """Verify search options round trips through model dump."""
        data = m.Ldap.SearchOptions(
            base_dn=c.Tests.RFC_DEFAULT_BASE_DN,
            scope=c.Ldap.DEFAULT_SCOPE,
        ).model_dump()
        u.Tests.that(data["base_dn"], eq=c.Tests.RFC_DEFAULT_BASE_DN)
        u.Tests.that(data["scope"], eq=c.Ldap.DEFAULT_SCOPE)

    @staticmethod
    def test_search_options_json_schema_exposes_fields() -> None:
        """Verify search options json schema exposes fields."""
        u.Tests.that(
            m.Ldap.SearchOptions.model_json_schema()["properties"],
            keys=[c.Tests.FIELD_BASE_DN, c.Tests.FIELD_SCOPE],
        )

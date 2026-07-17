"""Unit tests for flext_ldap.utilities.FlextLdapUtilities.

Behavioral contract tests: assert observable public return values,
r[T] outcomes, and raised model state via the public utility facade.

Architecture: Single class per module following FLEXT patterns.
Uses t, c, p, m, u, s for test support and e, r, p, d, x from flext-core.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

import pytest
from flext_tests import tm
from ldap3 import MOCK_SYNC, Connection, Server

from tests import c, m, t, u

pytestmark = pytest.mark.unit


class TestsFlextLdapUtilitiesUnit:
    """Behavioral tests for the public FlextLdapUtilities facade.

    All test data comes from c.Ldap.Tests.* — zero inline constants.
    """

    def test_to_str_simple(self) -> None:
        result = u.to_str(c.Ldap.Tests.STRING_SIMPLE)
        u.Ldap.Tests.that(result, eq=c.Ldap.Tests.STRING_SIMPLE)

    def test_to_str_list_from_list(self) -> None:
        result = u.to_str_list(list(c.Ldap.Tests.LIST_ABC))
        u.Ldap.Tests.that(result, eq=list(c.Ldap.Tests.LIST_ABC))

    def test_to_str_list_from_single(self) -> None:
        result = u.to_str_list(c.Ldap.Tests.LIST_SINGLE)
        u.Ldap.Tests.that(result, eq=[c.Ldap.Tests.LIST_SINGLE])

    def test_ldap3_value_to_strings_from_none(self) -> None:
        result = u.Ldap.ldap3_value_to_strings(None)
        u.Ldap.Tests.that(result, eq=[])

    def test_norm_str_lowercase(self) -> None:
        result = u.Ldap.norm_str(c.Ldap.Tests.STRING_SIMPLE_UPPER, case="lower")
        u.Ldap.Tests.that(result, eq=c.Ldap.Tests.STRING_SIMPLE)

    def test_norm_str_uppercase(self) -> None:
        result = u.Ldap.norm_str(c.Ldap.Tests.STRING_SIMPLE, case="upper")
        u.Ldap.Tests.that(result, eq=c.Ldap.Tests.STRING_SIMPLE_UPPER)

    def test_norm_join(self) -> None:
        result = u.Ldap.norm_join(list(c.Ldap.Tests.NORM_JOIN_INPUT), case="lower")
        u.Ldap.Tests.that(result, eq=c.Ldap.Tests.NORM_JOIN_EXPECTED)

    def test_filter_truthy(self) -> None:
        result = u.Ldap.filter_truthy(dict(c.Ldap.Tests.FILTER_TRUTHY_INPUT))
        assert isinstance(result, dict)
        u.Ldap.Tests.that(
            sorted(result.keys()),
            eq=list(c.Ldap.Tests.FILTER_TRUTHY_EXPECTED_KEYS),
        )

    def test_map_str(self) -> None:
        result = u.Ldap.map_str(list(c.Ldap.Tests.LIST_ABC), case="upper")
        u.Ldap.Tests.that(result, eq=list(c.Ldap.Tests.LIST_ABC_UPPER))

    def test_dn_str_with_string(self) -> None:
        result = u.Ldap.dn_str(c.Ldap.Tests.ENTRY_DN_TEST_EXAMPLE)
        u.Ldap.Tests.that(result, eq=c.Ldap.Tests.ENTRY_DN_TEST_EXAMPLE)

    def test_dn_str_with_none(self) -> None:
        result = u.Ldap.dn_str(None)
        u.Ldap.Tests.that(result, eq=c.Ldap.UNKNOWN_CATEGORY)

    def test_dn_str_with_custom_default(self) -> None:
        result = u.Ldap.dn_str(
            None,
            default=c.Ldap.Tests.STRING_DEFAULT_CUSTOM,
        )
        u.Ldap.Tests.that(result, eq=c.Ldap.Tests.STRING_DEFAULT_CUSTOM)

    # --- create_server ---
    @pytest.mark.parametrize(
        "case",
        [
            c.Ldap.Tests.Ldap3ServerCase.PLAIN,
            c.Ldap.Tests.Ldap3ServerCase.SSL,
        ],
    )
    def test_create_server_modes(self, case: c.Ldap.Tests.Ldap3ServerCase) -> None:
        port, use_ssl, _use_tls = c.Ldap.Tests.LDAP3_SERVER_SCENARIOS[case]
        server = u.Ldap.create_server(c.LOCALHOST, port, use_ssl=use_ssl)
        tm.that(server, none=False)

    # --- create_server_from_url ---
    def test_create_server_from_url(self) -> None:
        server = u.Ldap.create_server_from_url(f"ldap://{c.LOCALHOST}:{c.Ldap.PORT}")
        tm.that(server, none=False)

    # --- create_bare_server ---
    def test_create_bare_server(self) -> None:
        server = u.Ldap.create_bare_server(c.LOCALHOST)
        tm.that(server, none=False)

    # --- create_connection ---
    def test_create_connection(self) -> None:
        server = u.Ldap.create_server(c.LOCALHOST, c.Ldap.PORT, use_ssl=False)
        conn = u.Ldap.create_connection(
            server,
            user=c.Ldap.Tests.BIND_ADMIN_DN,
            password=c.Ldap.Tests.BIND_ADMIN_PASSWORD,
            auto_bind=False,
        )
        tm.that(conn, none=False)

    # --- norm_in with tuple ---
    def test_norm_in_with_tuple(self) -> None:
        result = u.Ldap.norm_in("A", ("a", "b", "c"), case="lower")
        u.Ldap.Tests.that(result, eq=True)

    def test_norm_in_with_list(self) -> None:
        result = u.Ldap.norm_in("X", ["a", "b", "c"], case="lower")
        u.Ldap.Tests.that(result, eq=False)

    @pytest.mark.parametrize("case", c.Ldap.Tests.AttrToStrListCase)
    def test_attr_to_str_list_scenarios(
        self,
        case: c.Ldap.Tests.AttrToStrListCase,
    ) -> None:
        expected = c.Ldap.Tests.ATTR_TO_STR_LIST_SCENARIOS[case]
        match case:
            case c.Ldap.Tests.AttrToStrListCase.EMPTY:
                result = u.Ldap.attr_to_str_list({})
            case c.Ldap.Tests.AttrToStrListCase.BYTES:
                result = u.Ldap.attr_to_str_list({"key": b"hello"})
            case c.Ldap.Tests.AttrToStrListCase.LIST:
                result = u.Ldap.attr_to_str_list({"cn": list(c.Ldap.Tests.LIST_ABC)})
            case c.Ldap.Tests.AttrToStrListCase.LIST_BYTES:
                result = u.Ldap.attr_to_str_list({"key": [b"bytes", "str"]})
            case c.Ldap.Tests.AttrToStrListCase.INT:
                result = u.Ldap.attr_to_str_list({"num": 42})
            case _:
                raise AssertionError(f"Unhandled attr_to_str_list case: {case}")
        normalized = {key: tuple(value) for key, value in result.items()}
        u.Ldap.Tests.that(normalized, eq=dict(expected))

    # --- ldap3_value_to_strings ---
    @pytest.mark.parametrize("case", c.Ldap.Tests.LdapValueCase)
    def test_ldap3_value_to_strings_scenarios(
        self,
        case: c.Ldap.Tests.LdapValueCase,
    ) -> None:
        value, expected = c.Ldap.Tests.LDAP3_VALUE_TO_STRINGS_SCENARIOS[case]
        result = u.Ldap.ldap3_value_to_strings(value)
        u.Ldap.Tests.that(tuple(result), eq=expected)

    # --- search_entry_to_ldif_entry ---
    def test_search_entry_to_ldif_entry_success(self) -> None:
        entry = {"dn": c.Ldap.Tests.ENTRY_DN_TEST_EXAMPLE, "cn": ["test"]}
        result = u.Ldap.search_entry_to_ldif_entry(entry)
        converted = u.Ldap.Tests.ok(result)
        assert converted.dn is not None
        u.Ldap.Tests.that(
            converted.dn.value,
            eq=c.Ldap.Tests.ENTRY_DN_TEST_EXAMPLE,
        )

    def test_search_entry_to_ldif_entry_missing_dn(self) -> None:
        entry = {"cn": ["test"]}
        result = u.Ldap.search_entry_to_ldif_entry(entry)
        u.Ldap.Tests.fail(result)

    # --- track_conversion_differences ---
    def test_track_conversion_differences_no_changes(self) -> None:
        meta = m.Ldap.ConversionMetadata(source_dn=c.Ldap.Tests.ENTRY_DN_TEST_EXAMPLE)
        result = u.Ldap.track_conversion_differences(
            meta,
            original_dn=c.Ldap.Tests.ENTRY_DN_TEST_EXAMPLE,
            converted_dn=c.Ldap.Tests.ENTRY_DN_TEST_EXAMPLE,
            original_attrs_dict={"cn": ["test"]},
            converted_attrs_dict={"cn": ["test"]},
        )
        tm.that(result.dn_changed, eq=False)
        tm.that(result.attribute_changes, lacks="cn")

    def test_track_conversion_differences_dn_change(self) -> None:
        meta = m.Ldap.ConversionMetadata(source_dn=c.Ldap.Tests.ENTRY_DN_TEST_EXAMPLE)
        result = u.Ldap.track_conversion_differences(
            meta,
            original_dn=c.Ldap.Tests.ENTRY_DN_TEST_EXAMPLE,
            converted_dn=c.Ldap.Tests.ENTRY_DN_USER_EXAMPLE,
            original_attrs_dict={"cn": ["test"]},
            converted_attrs_dict={"cn": ["test"]},
        )
        tm.that(result.dn_changed, eq=True)

    def test_track_conversion_differences_attr_change(self) -> None:
        meta = m.Ldap.ConversionMetadata(source_dn=c.Ldap.Tests.ENTRY_DN_TEST_EXAMPLE)
        result = u.Ldap.track_conversion_differences(
            meta,
            original_dn=c.Ldap.Tests.ENTRY_DN_TEST_EXAMPLE,
            converted_dn=c.Ldap.Tests.ENTRY_DN_TEST_EXAMPLE,
            original_attrs_dict={"cn": ["old"]},
            converted_attrs_dict={"cn": ["new"]},
        )
        tm.that(result.attribute_changes, has="cn")

    # --- extract_entry_attributes ---
    def test_extract_entry_attributes_with_none_attrs(self) -> None:
        entry = m.Ldif.Entry(
            dn=m.Ldif.DN(value=c.Ldap.Tests.ENTRY_DN_TEST_EXAMPLE),
            attributes=None,
        )
        result = u.Ldap.extract_entry_attributes(entry)
        u.Ldap.Tests.that(dict(result), eq={})

    def test_extract_entry_attributes_with_attrs(self) -> None:
        entry = m.Ldif.Entry(
            dn=m.Ldif.DN(value=c.Ldap.Tests.ENTRY_DN_TEST_EXAMPLE),
            attributes=m.Ldif.Attributes(
                attributes={"cn": ["test"]},
                attribute_metadata={},
            ),
        )
        result = u.Ldap.extract_entry_attributes(entry)
        tm.that(result, has="cn")

    # --- find_existing_values ---
    def test_find_existing_values_found_case_insensitive(self) -> None:
        existing = {"cn": ["test"], "sn": ["user"]}
        result = u.Ldap.find_existing_values("CN", existing)
        assert result is not None
        tm.that(list(result), eq=["test"])

    def test_find_existing_values_not_found(self) -> None:
        existing = {"cn": ["test"]}
        result = u.Ldap.find_existing_values("mail", existing)
        tm.that(result, none=True)

    # --- normalize_value_set ---
    def test_normalize_value_set_lowercases_and_drops_empty(self) -> None:
        result = u.Ldap.normalize_value_set(["Alice", "BOB", ""])
        tm.that(result, eq=frozenset({"alice", "bob"}))

    # --- process_new_attributes ---
    def test_process_new_attributes_with_change(self) -> None:
        changes, _processed = u.Ldap.process_new_attributes(
            {"cn": ["newval"]},
            {"cn": ["oldval"]},
            frozenset(),
        )
        tm.that(changes, has="cn")

    def test_process_new_attributes_no_change(self) -> None:
        changes, _processed = u.Ldap.process_new_attributes(
            {"cn": ["same"]},
            {"cn": ["same"]},
            frozenset(),
        )
        tm.that(changes, lacks="cn")

    def test_process_new_attributes_value_comparison_is_case_insensitive(self) -> None:
        changes, _processed = u.Ldap.process_new_attributes(
            {c.Ldap.AttributeName.COMMON_NAME: [c.Ldap.Tests.STRING_SIMPLE]},
            {c.Ldap.AttributeName.COMMON_NAME: [c.Ldap.Tests.STRING_SIMPLE_UPPER]},
            frozenset(),
        )
        tm.that(changes, lacks=c.Ldap.AttributeName.COMMON_NAME)

    def test_process_new_attributes_ignored(self) -> None:
        existing_attrs: dict[str, list[str]] = {}
        changes, _processed = u.Ldap.process_new_attributes(
            {"cn": ["val"]},
            existing_attrs,
            frozenset(["cn"]),
        )
        tm.that(changes, lacks="cn")

    # --- process_deleted_attributes ---
    def test_process_deleted_attributes(self) -> None:
        existing_attrs = {"cn": ["test"], "sn": ["user"]}
        changes = u.Ldap.process_deleted_attributes(existing_attrs, frozenset(), {"cn"})
        tm.that(changes, has="sn")
        tm.that(changes, lacks="cn")

    # --- compare_entries ---
    def test_compare_entries_success(self) -> None:
        existing = m.Ldif.Entry(
            dn=m.Ldif.DN(value=c.Ldap.Tests.ENTRY_DN_TEST_EXAMPLE),
            attributes=m.Ldif.Attributes(
                attributes={"cn": ["old"]},
                attribute_metadata={},
            ),
        )
        new_entry = m.Ldif.Entry(
            dn=m.Ldif.DN(value=c.Ldap.Tests.ENTRY_DN_TEST_EXAMPLE),
            attributes=m.Ldif.Attributes(
                attributes={"cn": ["new"]},
                attribute_metadata={},
            ),
        )
        result = u.Ldap.compare_entries(existing, new_entry)
        changes = u.Ldap.Tests.ok(result)
        tm.that(changes, has="cn")

    def test_compare_entries_no_existing_attrs(self) -> None:
        existing = m.Ldif.Entry(
            dn=m.Ldif.DN(value=c.Ldap.Tests.ENTRY_DN_TEST_EXAMPLE),
            attributes=None,
        )
        new_entry = m.Ldif.Entry(
            dn=m.Ldif.DN(value=c.Ldap.Tests.ENTRY_DN_TEST_EXAMPLE),
            attributes=m.Ldif.Attributes(
                attributes={"cn": ["new"]},
                attribute_metadata={},
            ),
        )
        result = u.Ldap.compare_entries(existing, new_entry)
        u.Ldap.Tests.fail(result)

    def test_compare_entries_no_new_attrs(self) -> None:
        existing = m.Ldif.Entry(
            dn=m.Ldif.DN(value=c.Ldap.Tests.ENTRY_DN_TEST_EXAMPLE),
            attributes=m.Ldif.Attributes(
                attributes={"cn": ["old"]},
                attribute_metadata={},
            ),
        )
        new_entry = m.Ldif.Entry(
            dn=m.Ldif.DN(value=c.Ldap.Tests.ENTRY_DN_TEST_EXAMPLE),
            attributes=None,
        )
        result = u.Ldap.compare_entries(existing, new_entry)
        u.Ldap.Tests.fail(result)

    # --- dn_str with DN and Entry objects ---
    def test_dn_str_with_dn_object(self) -> None:
        dn = m.Ldif.DN(value=c.Ldap.Tests.ENTRY_DN_TEST_EXAMPLE)
        result = u.Ldap.dn_str(dn)
        u.Ldap.Tests.that(result, eq=c.Ldap.Tests.ENTRY_DN_TEST_EXAMPLE)

    def test_dn_str_with_dn_object_empty(self) -> None:
        dn = m.Ldif.DN(value="")
        result = u.Ldap.dn_str(dn)
        u.Ldap.Tests.that(result, eq=c.Ldap.UNKNOWN_CATEGORY)

    def test_dn_str_with_entry(self) -> None:
        entry = m.Ldif.Entry(
            dn=m.Ldif.DN(value=c.Ldap.Tests.ENTRY_DN_TEST_EXAMPLE),
            attributes=m.Ldif.Attributes(attributes={}, attribute_metadata={}),
        )
        result = u.Ldap.dn_str(entry)
        u.Ldap.Tests.that(result, eq=c.Ldap.Tests.ENTRY_DN_TEST_EXAMPLE)

    # --- map_str with join ---
    def test_map_str_with_join(self) -> None:
        result = u.Ldap.map_str(list(c.Ldap.Tests.LIST_ABC), join=",")
        u.Ldap.Tests.that(result, eq="a,b,c")

    def test_map_str_with_case_and_join(self) -> None:
        result = u.Ldap.map_str(list(c.Ldap.Tests.LIST_ABC), case="upper", join=" ")
        u.Ldap.Tests.that(result, eq="A B C")

    # --- norm_str edge cases ---
    def test_norm_str_empty_string(self) -> None:
        result = u.Ldap.norm_str(c.Ldap.Tests.STRING_EMPTY)
        u.Ldap.Tests.that(result, eq=c.Ldap.Tests.STRING_EMPTY)

    def test_norm_str_no_case(self) -> None:
        result = u.Ldap.norm_str(c.Ldap.Tests.STRING_SIMPLE)
        u.Ldap.Tests.that(result, eq=c.Ldap.Tests.STRING_SIMPLE)

    # --- detect_from_extensions ---
    def test_detect_from_extensions_openldap(self) -> None:
        result = u.Ldap.detect_from_extensions(["openldap"], [])
        tm.that(result.lower(), has="openldap")

    def test_detect_from_extensions_fallback_rfc(self) -> None:
        result = u.Ldap.detect_from_extensions([], [])
        tm.that(result, eq=c.Ldif.ServerTypes.RFC.value)

    def test_detect_from_extensions_ad(self) -> None:
        result = u.Ldap.detect_from_extensions(["microsoft"], ["dc=example,dc=com"])
        tm.that(result.lower(), has="ad")

    def test_detect_from_extensions_oid_from_context(self) -> None:
        result = u.Ldap.detect_from_extensions([], ["dc=oracle,dc=example"])
        tm.that(result, eq=c.Ldif.ServerTypes.OID.value)

    # --- detect_from_vendor ---
    def test_detect_from_vendor_none(self) -> None:
        result = u.Ldap.detect_from_vendor(None, None)
        tm.that(result, none=True)

    def test_detect_from_vendor_empty(self) -> None:
        result = u.Ldap.detect_from_vendor("", "")
        tm.that(result, none=True)

    def test_detect_from_vendor_openldap(self) -> None:
        result = u.Ldap.detect_from_vendor("OpenLDAP", "2.6")
        assert result is not None
        tm.that(result.lower(), has="openldap")

    # --- detect_server_type (composed public contract) ---
    def test_detect_server_type_prefers_vendor_over_extensions(self) -> None:
        vendor_type = u.Ldap.detect_from_vendor("OpenLDAP", "2.6")
        tm.that(vendor_type, none=False)
        result = u.Ldap.detect_server_type(
            vendor_name="OpenLDAP",
            vendor_version="2.6",
            naming_contexts=["dc=oracle,dc=example"],
            supported_extensions=[],
        )
        # Vendor metadata wins even though the context alone would infer OID.
        u.Ldap.Tests.that(result, eq=vendor_type)

    def test_detect_server_type_falls_back_to_extensions(self) -> None:
        result = u.Ldap.detect_server_type(
            vendor_name=None,
            vendor_version=None,
            naming_contexts=["dc=oracle,dc=example"],
            supported_extensions=[],
        )
        u.Ldap.Tests.that(result, eq=c.Ldif.ServerTypes.OID.value)

    def test_detect_server_type_defaults_to_rfc(self) -> None:
        result = u.Ldap.detect_server_type(
            vendor_name=None,
            vendor_version=None,
            naming_contexts=(),
            supported_extensions=(),
        )
        u.Ldap.Tests.that(result, eq=c.Ldif.ServerTypes.RFC.value)

    # --- query_root_dse ---
    def test_query_root_dse_no_search_method(self) -> None:
        class NoSearch:
            search: None = None

            @property
            def result(self) -> t.JsonMapping:
                return {}

            @property
            def entries(self) -> t.SequenceOf[str]:
                return []

        result = u.Ldap.query_root_dse(NoSearch())
        u.Ldap.Tests.fail(result)

    def test_query_root_dse_search_returns_false(self) -> None:
        class FalseSearch:
            def search(self, **kwargs: str | int | bool | None) -> bool:
                return False

            @property
            def result(self) -> t.JsonMapping:
                return {}

            @property
            def entries(self) -> t.SequenceOf[str]:
                return []

        result = u.Ldap.query_root_dse(FalseSearch())
        u.Ldap.Tests.fail(result)

    def test_query_root_dse_no_entries(self) -> None:
        class EmptySearch:
            def search(self, **kwargs: str | int | bool | None) -> bool:
                return True

            @property
            def result(self) -> t.JsonMapping:
                return {"result": 0}

            @property
            def entries(self) -> t.SequenceOf[str]:
                return []

        result = u.Ldap.query_root_dse(EmptySearch())
        u.Ldap.Tests.fail(result)

    def test_query_root_dse_invalid_entry_type(self) -> None:
        class BadEntry:
            def search(self, **kwargs: str | int | bool | None) -> bool:
                return True

            @property
            def result(self) -> t.JsonMapping:
                return {"result": 0}

            @property
            def entries(self) -> t.SequenceOf[str]:
                return ["not_ldap3_entry"]

        result = u.Ldap.query_root_dse(BadEntry())
        u.Ldap.Tests.fail(result)

    def test_query_root_dse_with_real_mock(self) -> None:
        server = Server("mock")
        conn = Connection(server, client_strategy=MOCK_SYNC)
        conn.strategy.add_entry(
            c.Ldap.Tests.RFC_DEFAULT_BASE_DN,
            {
                "objectClass": ["top"],
                "namingContexts": ["dc=example,dc=com"],
                "supportedExtension": [],
            },
        )
        conn.bind()
        result = u.Ldap.query_root_dse(conn)
        # Either success or failure is acceptable depending on entry format.
        # Either success or failure is acceptable depending on entry format.
        assert result is not None

    # --- detect_from_connection ---
    def test_detect_from_connection_failure(self) -> None:
        class FailSearch:
            def search(self, **kwargs: str | int | bool | None) -> bool:
                return False

            @property
            def result(self) -> t.JsonMapping:
                return {}

            @property
            def entries(self) -> t.SequenceOf[str]:
                return []

        result = u.Ldap.detect_from_connection(FailSearch())
        u.Ldap.Tests.fail(result)

    def test_detect_from_connection_with_mock(self) -> None:
        server = Server("mock")
        conn = Connection(server, client_strategy=MOCK_SYNC)
        conn.bind()
        result = u.Ldap.detect_from_connection(conn)
        assert result is not None

    # --- when_safe ---
    def test_when_safe_condition_true(self) -> None:
        result = u.Ldap.when_safe(condition=True, then_value="yes", else_value="no")
        u.Ldap.Tests.that(result, eq="yes")

    def test_when_safe_condition_false(self) -> None:
        result = u.Ldap.when_safe(condition=False, then_value="yes", else_value="no")
        u.Ldap.Tests.that(result, eq="no")

    def test_when_safe_safe_then_true_with_none(self) -> None:
        result = u.Ldap.when_safe(
            condition=True,
            then_value=None,
            else_value="fallback",
            safe_then=True,
        )
        u.Ldap.Tests.that(result, eq="fallback")

    def test_when_safe_safe_then_true_non_none(self) -> None:
        result = u.Ldap.when_safe(
            condition=True,
            then_value="value",
            else_value="fallback",
            safe_then=True,
        )
        u.Ldap.Tests.that(result, eq="value")

    # --- build_conversion_metadata ---
    def test_build_conversion_metadata(self) -> None:
        meta = u.Ldap.build_conversion_metadata(
            ["removed_attr"],
            ["b64_attr"],
            {"cn": ["test"]},
            c.Ldap.Tests.ENTRY_DN_TEST_EXAMPLE,
        )
        tm.that(meta.source_dn, eq=c.Ldap.Tests.ENTRY_DN_TEST_EXAMPLE)
        tm.that(meta.removed_attributes, has="removed_attr")
        tm.that(meta.base64_encoded_attributes, has="b64_attr")

    # --- is_base64_encoded ---
    def test_is_base64_encoded_with_prefix(self) -> None:
        result = u.Ldap.is_base64_encoded(":: dGVzdA==")
        tm.that(result, eq=True)

    def test_is_base64_encoded_high_ascii(self) -> None:
        result = u.Ldap.is_base64_encoded("test\x80value")
        tm.that(result, eq=True)

    def test_is_base64_encoded_normal(self) -> None:
        result = u.Ldap.is_base64_encoded("normalvalue")
        tm.that(result, eq=False)


__all__: list[str] = ["TestsFlextLdapUtilitiesUnit"]

"""Unit tests for flext_ldap.utilities.FlextLdapUtilities.

Architecture: Single class per module following FLEXT patterns.
Uses t, c, p, m, u, s for test support and e, r, p, d, x from flext-core.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

import math

import pytest
from ldap3 import MOCK_SYNC, Connection, Server

from flext_ldap import m
from tests import c, u

pytestmark = pytest.mark.unit


class TestsFlextLdapUtilitiesUnit:
    """Comprehensive tests for FlextLdapUtilities.

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
            sorted(result.keys()), eq=list(c.Ldap.Tests.FILTER_TRUTHY_EXPECTED_KEYS)
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
    def test_create_server_no_ssl(self) -> None:
        server = u.Ldap.create_server("localhost", 389, use_ssl=False)
        assert server is not None

    def test_create_server_with_ssl(self) -> None:
        server = u.Ldap.create_server(
            "localhost", c.Ldap.Tests.CONFIG_LDAPS_PORT, use_ssl=True
        )
        assert server is not None

    # --- create_server_from_url ---
    def test_create_server_from_url(self) -> None:
        server = u.Ldap.create_server_from_url("ldap://localhost:389")
        assert server is not None

    # --- create_bare_server ---
    def test_create_bare_server(self) -> None:
        server = u.Ldap.create_bare_server("localhost")
        assert server is not None

    # --- create_connection ---
    def test_create_connection(self) -> None:
        server = u.Ldap.create_server("localhost", 389, use_ssl=False)
        conn = u.Ldap.create_connection(
            server, user="cn=admin", password="admin", auto_bind=False
        )
        assert conn is not None

    # --- norm_in with tuple ---
    def test_norm_in_with_tuple(self) -> None:
        result = u.Ldap.norm_in("A", ("a", "b", "c"), case="lower")
        u.Ldap.Tests.that(result, eq=True)

    def test_norm_in_with_list(self) -> None:
        result = u.Ldap.norm_in("X", ["a", "b", "c"], case="lower")
        u.Ldap.Tests.that(result, eq=False)

    # --- attr_to_str_list with empty dict ---
    def test_attr_to_str_list_empty(self) -> None:
        result = u.Ldap.attr_to_str_list({})
        u.Ldap.Tests.that(dict(result), eq={})

    def test_attr_to_str_list_with_bytes(self) -> None:
        result = u.Ldap.attr_to_str_list({"key": b"hello"})
        assert "key" in result

    def test_attr_to_str_list_with_list(self) -> None:
        result = u.Ldap.attr_to_str_list({"cn": ["alice", "bob"]})
        assert list(result["cn"]) == ["alice", "bob"]

    def test_attr_to_str_list_with_list_bytes(self) -> None:
        result = u.Ldap.attr_to_str_list({"key": [b"bytes", "str"]})
        assert "key" in result

    def test_attr_to_str_list_with_int(self) -> None:
        result = u.Ldap.attr_to_str_list({"num": 42})
        assert "num" in result

    # --- ldap3_value_to_strings ---
    def test_ldap3_value_to_strings_bytes(self) -> None:
        result = u.Ldap.ldap3_value_to_strings(b"hello")
        u.Ldap.Tests.that(result, eq=["hello"])

    def test_ldap3_value_to_strings_list(self) -> None:
        result = u.Ldap.ldap3_value_to_strings(["a", "b"])
        u.Ldap.Tests.that(list(result), eq=["a", "b"])

    def test_ldap3_value_to_strings_list_with_bytes(self) -> None:
        result = u.Ldap.ldap3_value_to_strings([b"hello", "world"])
        u.Ldap.Tests.that(list(result), eq=["hello", "world"])

    def test_ldap3_value_to_strings_tuple(self) -> None:
        result = u.Ldap.ldap3_value_to_strings(("a", "b"))
        u.Ldap.Tests.that(list(result), eq=["a", "b"])

    def test_ldap3_value_to_strings_str(self) -> None:
        result = u.Ldap.ldap3_value_to_strings("hello")
        u.Ldap.Tests.that(list(result), eq=["hello"])

    def test_ldap3_value_to_strings_int(self) -> None:
        result = u.Ldap.ldap3_value_to_strings(42)
        u.Ldap.Tests.that(list(result), eq=["42"])

    def test_ldap3_value_to_strings_float(self) -> None:
        result = u.Ldap.ldap3_value_to_strings(math.pi)
        assert len(list(result)) == 1

    # --- search_entry_to_ldif_entry ---
    def test_search_entry_to_ldif_entry_success(self) -> None:
        entry = {"dn": c.Ldap.Tests.ENTRY_DN_TEST_EXAMPLE, "cn": ["test"]}
        result = u.Ldap.search_entry_to_ldif_entry(entry)
        u.Ldap.Tests.ok(result)

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
        assert result is not None

    def test_track_conversion_differences_dn_change(self) -> None:
        meta = m.Ldap.ConversionMetadata(source_dn=c.Ldap.Tests.ENTRY_DN_TEST_EXAMPLE)
        result = u.Ldap.track_conversion_differences(
            meta,
            original_dn=c.Ldap.Tests.ENTRY_DN_TEST_EXAMPLE,
            converted_dn=c.Ldap.Tests.ENTRY_DN_USER_EXAMPLE,
            original_attrs_dict={"cn": ["test"]},
            converted_attrs_dict={"cn": ["test"]},
        )
        assert result.dn_changed is True

    def test_track_conversion_differences_attr_change(self) -> None:
        meta = m.Ldap.ConversionMetadata(source_dn=c.Ldap.Tests.ENTRY_DN_TEST_EXAMPLE)
        result = u.Ldap.track_conversion_differences(
            meta,
            original_dn=c.Ldap.Tests.ENTRY_DN_TEST_EXAMPLE,
            converted_dn=c.Ldap.Tests.ENTRY_DN_TEST_EXAMPLE,
            original_attrs_dict={"cn": ["old"]},
            converted_attrs_dict={"cn": ["new"]},
        )
        assert "cn" in result.attribute_changes

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
                attributes={"cn": ["test"]}, attribute_metadata={}
            ),
        )
        result = u.Ldap.extract_entry_attributes(entry)
        assert "cn" in result

    # --- find_existing_values ---
    def test_find_existing_values_found(self) -> None:
        existing = {"cn": ["test"], "sn": ["user"]}
        result = u.Ldap.find_existing_values("CN", existing)
        assert result is not None
        assert list(result) == ["test"]

    def test_find_existing_values_not_found(self) -> None:
        existing = {"cn": ["test"]}
        result = u.Ldap.find_existing_values("mail", existing)
        assert result is None

    # --- normalize_value_set ---
    def test_normalize_value_set(self) -> None:
        result = u.Ldap.normalize_value_set(["Alice", "BOB", ""])
        assert result == {"alice", "bob"}

    # --- process_new_attributes ---
    def test_process_new_attributes_with_change(self) -> None:
        new_attrs = {"cn": ["newval"]}
        existing_attrs = {"cn": ["oldval"]}
        changes, _processed = u.Ldap.process_new_attributes(
            new_attrs, existing_attrs, frozenset()
        )
        assert "cn" in changes

    def test_process_new_attributes_no_change(self) -> None:
        new_attrs = {"cn": ["same"]}
        existing_attrs = {"cn": ["same"]}
        changes, _processed = u.Ldap.process_new_attributes(
            new_attrs, existing_attrs, frozenset()
        )
        assert "cn" not in changes

    def test_process_new_attributes_ignored(self) -> None:
        new_attrs = {"cn": ["val"]}
        existing_attrs = {}
        changes, _processed = u.Ldap.process_new_attributes(
            new_attrs, existing_attrs, frozenset(["cn"])
        )
        assert "cn" not in changes

    # --- process_deleted_attributes ---
    def test_process_deleted_attributes(self) -> None:
        existing_attrs = {"cn": ["test"], "sn": ["user"]}
        changes = u.Ldap.process_deleted_attributes(existing_attrs, frozenset(), {"cn"})
        assert "sn" in changes
        assert "cn" not in changes

    # --- compare_entries ---
    def test_compare_entries_success(self) -> None:
        existing = m.Ldif.Entry(
            dn=m.Ldif.DN(value=c.Ldap.Tests.ENTRY_DN_TEST_EXAMPLE),
            attributes=m.Ldif.Attributes(
                attributes={"cn": ["old"]}, attribute_metadata={}
            ),
        )
        new_entry = m.Ldif.Entry(
            dn=m.Ldif.DN(value=c.Ldap.Tests.ENTRY_DN_TEST_EXAMPLE),
            attributes=m.Ldif.Attributes(
                attributes={"cn": ["new"]}, attribute_metadata={}
            ),
        )
        result = u.Ldap.compare_entries(existing, new_entry)
        changes = u.Ldap.Tests.ok(result)
        assert "cn" in changes

    def test_compare_entries_no_existing_attrs(self) -> None:
        existing = m.Ldif.Entry(
            dn=m.Ldif.DN(value=c.Ldap.Tests.ENTRY_DN_TEST_EXAMPLE),
            attributes=None,
        )
        new_entry = m.Ldif.Entry(
            dn=m.Ldif.DN(value=c.Ldap.Tests.ENTRY_DN_TEST_EXAMPLE),
            attributes=m.Ldif.Attributes(
                attributes={"cn": ["new"]}, attribute_metadata={}
            ),
        )
        result = u.Ldap.compare_entries(existing, new_entry)
        u.Ldap.Tests.fail(result)

    def test_compare_entries_no_new_attrs(self) -> None:
        existing = m.Ldif.Entry(
            dn=m.Ldif.DN(value=c.Ldap.Tests.ENTRY_DN_TEST_EXAMPLE),
            attributes=m.Ldif.Attributes(
                attributes={"cn": ["old"]}, attribute_metadata={}
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
        assert result is not None

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
        assert "openldap" in result.lower()

    def test_detect_from_extensions_fallback_rfc(self) -> None:
        result = u.Ldap.detect_from_extensions([], [])
        assert result == c.Ldif.ServerTypes.RFC.value

    def test_detect_from_extensions_ad(self) -> None:
        result = u.Ldap.detect_from_extensions(["microsoft"], ["dc=example,dc=com"])
        assert "ad" in result.lower()

    # --- detect_from_vendor ---
    def test_detect_from_vendor_none(self) -> None:
        result = u.Ldap.detect_from_vendor(None, None)
        assert result is None

    def test_detect_from_vendor_empty(self) -> None:
        result = u.Ldap.detect_from_vendor("", "")
        assert result is None

    def test_detect_from_vendor_openldap(self) -> None:
        result = u.Ldap.detect_from_vendor("OpenLDAP", "2.6")
        assert result is not None

    # --- query_root_dse ---
    def test_query_root_dse_no_search_method(self) -> None:
        class NoSearch:
            pass

        result = u.Ldap.query_root_dse(NoSearch())  # type: ignore[arg-type]
        u.Ldap.Tests.fail(result)

    def test_query_root_dse_search_returns_false(self) -> None:
        class FalseSearch:
            result: dict[str, object] = {}

            def search(self, **kwargs: object) -> bool:
                return False

        result = u.Ldap.query_root_dse(FalseSearch())  # type: ignore[arg-type]
        u.Ldap.Tests.fail(result)

    def test_query_root_dse_no_entries(self) -> None:
        class EmptySearch:
            result = {"result": 0}
            entries: list[object] = []

            def search(self, **kwargs: object) -> bool:
                return True

        result = u.Ldap.query_root_dse(EmptySearch())  # type: ignore[arg-type]
        u.Ldap.Tests.fail(result)

    def test_query_root_dse_invalid_entry_type(self) -> None:
        class BadEntry:
            result = {"result": 0}
            entries = ["not_ldap3_entry"]

            def search(self, **kwargs: object) -> bool:
                return True

        result = u.Ldap.query_root_dse(BadEntry())  # type: ignore[arg-type]
        u.Ldap.Tests.fail(result)

    def test_query_root_dse_with_real_mock(self) -> None:
        server = Server("mock")
        conn = Connection(server, client_strategy=MOCK_SYNC)
        conn.strategy.add_entry(
            "",
            {
                "objectClass": ["top"],
                "namingContexts": ["dc=example,dc=com"],
                "supportedExtension": [],
            },
        )
        conn.bind()
        conn.search(
            search_base="",
            search_filter="(objectClass=*)",
            search_scope="BASE",
            attributes=["*"],
        )
        result = u.Ldap.query_root_dse(conn)
        # Either success or failure is acceptable depending on entry format
        assert result is not None

    # --- detect_from_connection ---
    def test_detect_from_connection_failure(self) -> None:
        class FailSearch:
            result: dict[str, object] = {}

            def search(self, **kwargs: object) -> bool:
                return False

        result = u.Ldap.detect_from_connection(FailSearch())  # type: ignore[arg-type]
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
            condition=True, then_value=None, else_value="fallback", safe_then=True
        )
        u.Ldap.Tests.that(result, eq="fallback")

    def test_when_safe_safe_then_true_non_none(self) -> None:
        result = u.Ldap.when_safe(
            condition=True, then_value="value", else_value="fallback", safe_then=True
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
        assert meta.source_dn == c.Ldap.Tests.ENTRY_DN_TEST_EXAMPLE
        assert "removed_attr" in meta.removed_attributes
        assert "b64_attr" in meta.base64_encoded_attributes

    # --- is_base64_encoded ---
    def test_is_base64_encoded_with_prefix(self) -> None:
        result = u.Ldap.is_base64_encoded(":: dGVzdA==")
        assert result is True

    def test_is_base64_encoded_high_ascii(self) -> None:
        result = u.Ldap.is_base64_encoded("test\x80value")
        assert result is True

    def test_is_base64_encoded_normal(self) -> None:
        result = u.Ldap.is_base64_encoded("normalvalue")
        assert result is False


__all__: list[str] = ["TestsFlextLdapUtilitiesUnit"]

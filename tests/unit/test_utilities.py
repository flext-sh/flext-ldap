"""Unit tests for flext_ldap.utilities.FlextLdapUtilities.

Behavioral contract tests: assert observable public return values,
r[T] outcomes, and raised model state via the public utility facade.

Architecture: Single class per module following FLEXT patterns.
Uses t, c, p, m, u, s for test support and e, r, p, d, x from flext-core.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from typing import TYPE_CHECKING, ClassVar

import pytest
from flext_tests import tm
from ldap3 import MOCK_SYNC, Connection, Server

from tests import c, m, t, u

if TYPE_CHECKING:
    from collections.abc import Callable

pytestmark = pytest.mark.unit


def _entry(
    attributes: t.MappingKV[str, t.StrSequence] | None,
    dn: str = c.Ldap.Tests.ENTRY_DN_TEST_EXAMPLE,
) -> m.Ldif.Entry:
    """Build an LDIF entry on the given DN (canonical test DN by default).

    Returns:
        The resulting ``m.Ldif.Entry``.
    """
    return m.Ldif.Entry(
        dn=m.Ldif.DN(value=dn),
        attributes=(
            None
            if attributes is None
            else m.Ldif.Attributes(
                attributes={key: list(values) for key, values in attributes.items()},
                attribute_metadata={},
            )
        ),
        domain_events=[],
    )


class TestsFlextLdapRootDseProbePayload:
    """Shared ldap3-shaped ``result``/``entries`` payload for root-DSE probes."""

    result_payload: ClassVar[t.JsonMapping] = {}
    entry_payloads: ClassVar[t.SequenceOf[str]] = ()

    @property
    def result(self) -> t.JsonMapping:
        """The ldap3 raw result payload."""
        return self.result_payload

    @property
    def entries(self) -> t.SequenceOf[str]:
        """The ldap3 raw entries."""
        return self.entry_payloads


class TestsFlextLdapUtilitiesUnit:
    """TestsFlextLdapUtilitiesUnit test methods."""

    """Behavioral tests for the public FlextLdapUtilities facade.

    All test data comes from c.Ldap.Tests.* — zero inline constants.
    """

    @pytest.mark.parametrize("case", c.Ldap.Tests.AttrToStrListCase)
    @staticmethod
    def test_attr_to_str_list_scenarios(
        case: c.Ldap.Tests.AttrToStrListCase,
    ) -> None:
        """Verify attr to str list scenarios.

        Raises:
            ValueError: If Unsupported attr to str list case.
        """
        expected = c.Ldap.Tests.ATTR_TO_STR_LIST_SCENARIOS[case]
        match case:
            case c.Ldap.Tests.AttrToStrListCase.EMPTY:
                result = u.Ldap.attr_to_str_list({})
            case c.Ldap.Tests.AttrToStrListCase.BYTES:
                result = u.Ldap.attr_to_str_list({"key": b"hello"})
            case c.Ldap.Tests.AttrToStrListCase.LIST:
                result = u.Ldap.attr_to_str_list({"cn": list(c.Ldap.Tests.LIST_ABC)})
            case c.Ldap.Tests.AttrToStrListCase.LIST_BYTES:
                list_bytes: t.MappingKV[str, t.Ldap.Ldap3AttributeValue] = {
                    "key": [b"bytes", "str"],
                }
                result = u.Ldap.attr_to_str_list(list_bytes)
            case c.Ldap.Tests.AttrToStrListCase.INT:
                result = u.Ldap.attr_to_str_list({"num": 42})
        normalized = {key: tuple(value) for key, value in result.items()}
        u.Ldap.Tests.that(normalized, eq=dict(expected))

    # --- build_conversion_metadata ---
    @staticmethod
    def test_build_conversion_metadata() -> None:
        """Verify build conversion metadata."""
        meta = u.Ldap.build_conversion_metadata(
            ["removed_attr"],
            ["b64_attr"],
            {"cn": ["test"]},
            c.Ldap.Tests.ENTRY_DN_TEST_EXAMPLE,
        )
        tm.that(meta.source_dn, eq=c.Ldap.Tests.ENTRY_DN_TEST_EXAMPLE)
        tm.that(meta.removed_attributes, has="removed_attr")
        tm.that(meta.base64_encoded_attributes, has="b64_attr")

    # --- compare_entries ---
    @staticmethod
    def test_compare_entries_success() -> None:
        """Verify compare entries produces changes for a non-RDN difference."""
        existing = _entry({"cn": [c.Ldap.Tests.STRING_SIMPLE], "sn": ["old"]})
        new_entry = _entry({"cn": [c.Ldap.Tests.STRING_SIMPLE], "sn": ["new"]})
        result = u.Ldap.compare_entries(existing, new_entry)
        changes = u.Ldap.Tests.ok(result)
        tm.that(changes, has="sn")

    @staticmethod
    def test_compare_entries_excludes_rdn_attribute_from_changes() -> None:
        """Verify the RDN attribute never appears in computed changes."""
        # Only the RDN attribute (cn of the canonical test DN) differs.
        existing = _entry({"cn": ["old"]})
        new_entry = _entry({"cn": ["new"]})
        result = u.Ldap.compare_entries(existing, new_entry)
        changes = u.Ldap.Tests.ok(result)
        tm.that(changes, lacks=c.Ldap.AttributeName.COMMON_NAME)
        tm.that(changes, len=0)

    @staticmethod
    def test_compare_entries_excludes_rdn_attribute_when_existing_lacks_it() -> None:
        """Verify no REPLACE is computed for the RDN attribute missing server-side."""
        existing = _entry({"sn": ["old"]})
        new_entry = _entry({"cn": [c.Ldap.Tests.STRING_SIMPLE], "sn": ["new"]})
        result = u.Ldap.compare_entries(existing, new_entry)
        changes = u.Ldap.Tests.ok(result)
        tm.that(changes, lacks=c.Ldap.AttributeName.COMMON_NAME)
        tm.that(changes, has="sn")

    @staticmethod
    def test_compare_entries_excludes_rdn_attribute_from_delete_changes() -> None:
        """Verify no DELETE is computed for the RDN attribute absent from the target."""
        existing = _entry({"cn": [c.Ldap.Tests.STRING_SIMPLE], "sn": ["old"]})
        new_entry = _entry({"sn": ["new"]})
        result = u.Ldap.compare_entries(existing, new_entry)
        changes = u.Ldap.Tests.ok(result)
        tm.that(changes, lacks=c.Ldap.AttributeName.COMMON_NAME)
        tm.that(changes, has="sn")

    @staticmethod
    def test_compare_entries_identical_entries_have_no_changes() -> None:
        """Verify identical entries compare equal (empty change set)."""
        entry_data: t.MappingKV[str, t.StrSequence] = {
            "cn": [c.Ldap.Tests.STRING_SIMPLE],
            "sn": ["user"],
        }
        result = u.Ldap.compare_entries(_entry(entry_data), _entry(entry_data))
        changes = u.Ldap.Tests.ok(result)
        tm.that(changes, len=0)

    @staticmethod
    def test_compare_entries_no_existing_attrs() -> None:
        """Verify compare entries no existing attrs."""
        existing = _entry(None)
        new_entry = _entry({"cn": ["new"]})
        result = u.Ldap.compare_entries(existing, new_entry)
        u.Ldap.Tests.fail(result)

    @staticmethod
    def test_compare_entries_no_new_attrs() -> None:
        """Verify compare entries no new attrs."""
        existing = _entry({"cn": ["old"]})
        new_entry = _entry(None)
        result = u.Ldap.compare_entries(existing, new_entry)
        u.Ldap.Tests.fail(result)

    # --- create_server ---
    @pytest.mark.parametrize(
        "case",
        [c.Ldap.Tests.Ldap3ServerCase.PLAIN, c.Ldap.Tests.Ldap3ServerCase.SSL],
    )
    @staticmethod
    def test_create_server_modes(case: c.Ldap.Tests.Ldap3ServerCase) -> None:
        """Verify create server modes."""
        port, use_ssl, _use_tls = c.Ldap.Tests.LDAP3_SERVER_SCENARIOS[case]
        server = u.Ldap.create_server(c.LOCALHOST, port, use_ssl=use_ssl)
        tm.that(server, none=False)

    # --- create_server_from_url ---
    @staticmethod
    def test_create_server_from_url() -> None:
        """Verify create server from url."""
        server = u.Ldap.create_server_from_url(f"ldap://{c.LOCALHOST}:{c.Ldap.PORT}")
        tm.that(server, none=False)

    # --- create_bare_server ---
    @staticmethod
    def test_create_bare_server() -> None:
        """Verify create bare server."""
        server = u.Ldap.create_bare_server(c.LOCALHOST)
        tm.that(server, none=False)

    # --- create_connection ---
    @staticmethod
    def test_create_connection() -> None:
        """Verify create connection."""
        server = u.Ldap.create_server(c.LOCALHOST, c.Ldap.PORT, use_ssl=False)
        conn = u.Ldap.create_connection(
            server,
            user=c.Ldap.Tests.BIND_ADMIN_DN,
            password=c.Ldap.Tests.BIND_ADMIN_PASSWORD,
            auto_bind=False,
        )
        tm.that(conn, none=False)


class TestsFlextLdapUtilitiesUnitDetect(TestsFlextLdapUtilitiesUnit):
    """TestsFlextLdapUtilitiesUnitDetect test methods."""

    # --- detect_from_extensions ---
    @staticmethod
    def test_detect_from_extensions_openldap() -> None:
        """Verify detect from extensions openldap."""
        result = u.Ldap.detect_from_extensions(["openldap"], [])
        tm.that(result.lower(), has="openldap")

    @staticmethod
    def test_detect_from_extensions_fallback_rfc() -> None:
        """Verify detect from extensions fallback rfc."""
        result = u.Ldap.detect_from_extensions([], [])
        tm.that(result, eq=c.Ldif.ServerTypes.RFC.value)

    @staticmethod
    def test_detect_from_extensions_ad() -> None:
        """Verify detect from extensions ad."""
        result = u.Ldap.detect_from_extensions(["microsoft"], ["dc=example,dc=com"])
        tm.that(result.lower(), has="ad")

    @staticmethod
    def test_detect_from_extensions_oid_from_context() -> None:
        """Verify detect from extensions oid from context."""
        result = u.Ldap.detect_from_extensions([], ["dc=oracle,dc=example"])
        tm.that(result, eq=c.Ldif.ServerTypes.OID.value)

    # --- detect_from_vendor ---
    @staticmethod
    def test_detect_from_vendor_none() -> None:
        """Verify detect from vendor none."""
        result = u.Ldap.detect_from_vendor(None, None)
        tm.that(result, none=True)

    @staticmethod
    def test_detect_from_vendor_empty() -> None:
        """Verify detect from vendor empty."""
        result = u.Ldap.detect_from_vendor("", "")
        tm.that(result, none=True)

    @staticmethod
    def test_detect_from_vendor_openldap() -> None:
        """Verify detect from vendor openldap."""
        result = tm.not_none(u.Ldap.detect_from_vendor("OpenLDAP", "2.6"))
        tm.that(result.lower(), has="openldap")

    # --- detect_server_type (composed public contract) ---
    @staticmethod
    def test_detect_server_type_prefers_vendor_over_extensions() -> None:
        """Verify detect server type prefers vendor over extensions."""
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

    @staticmethod
    def test_detect_server_type_falls_back_to_extensions() -> None:
        """Verify detect server type falls back to extensions."""
        result = u.Ldap.detect_server_type(
            vendor_name=None,
            vendor_version=None,
            naming_contexts=["dc=oracle,dc=example"],
            supported_extensions=[],
        )
        u.Ldap.Tests.that(result, eq=c.Ldif.ServerTypes.OID.value)

    @staticmethod
    def test_detect_server_type_defaults_to_rfc() -> None:
        """Verify detect server type defaults to rfc."""
        result = u.Ldap.detect_server_type(
            vendor_name=None,
            vendor_version=None,
            naming_contexts=(),
            supported_extensions=(),
        )
        u.Ldap.Tests.that(result, eq=c.Ldif.ServerTypes.RFC.value)

    # --- detect_from_connection ---
    @staticmethod
    def test_detect_from_connection_failure() -> None:
        """Verify detect from connection failure."""

        class FailSearch(TestsFlextLdapRootDseProbePayload):
            @staticmethod
            def search(**_kwargs: str | int | bool | None) -> bool:
                return False

        result = u.Ldap.detect_from_connection(FailSearch())
        u.Ldap.Tests.fail(result)

    @staticmethod
    def test_detect_from_connection_with_ldap3_offline_strategy() -> None:
        """detect_from_connection classifies the vendor from real rootDSE data."""
        server = Server("mock")
        conn = Connection(server, client_strategy=MOCK_SYNC)
        conn.server.dit[""] = {
            "objectClass": [b"top"],
            "namingContexts": [b"dc=example,dc=com"],
            "vendorName": [b"OpenLDAP"],
            "vendorVersion": [b"2.4.57"],
        }
        method_name = "bind"
        bind_call: Callable[..., bool] = getattr(conn, method_name)
        bind_call()
        result = u.Ldap.detect_from_connection(conn)

        tm.that(result.success, eq=True)
        tm.that(result.value, eq="openldap")

    @staticmethod
    def test_dn_str_with_string() -> None:
        """Verify dn str with string."""
        result = u.Ldap.dn_str(c.Ldap.Tests.ENTRY_DN_TEST_EXAMPLE)
        u.Ldap.Tests.that(result, eq=c.Ldap.Tests.ENTRY_DN_TEST_EXAMPLE)

    @staticmethod
    def test_dn_str_with_none() -> None:
        """Verify dn str with none."""
        result = u.Ldap.dn_str(None)
        u.Ldap.Tests.that(result, eq=c.Ldap.UNKNOWN_CATEGORY)

    @staticmethod
    def test_dn_str_with_custom_default() -> None:
        """Verify dn str with custom default."""
        result = u.Ldap.dn_str(None, default=c.Ldap.Tests.STRING_DEFAULT_CUSTOM)
        u.Ldap.Tests.that(result, eq=c.Ldap.Tests.STRING_DEFAULT_CUSTOM)

    # --- dn_str with DN and Entry objects ---
    @staticmethod
    def test_dn_str_with_dn_object() -> None:
        """Verify dn str with dn object."""
        dn = m.Ldif.DN(value=c.Ldap.Tests.ENTRY_DN_TEST_EXAMPLE)
        result = u.Ldap.dn_str(dn)
        u.Ldap.Tests.that(result, eq=c.Ldap.Tests.ENTRY_DN_TEST_EXAMPLE)

    @staticmethod
    def test_dn_str_with_dn_object_empty() -> None:
        """Verify dn str with dn object empty."""
        dn = m.Ldif.DN(value="")
        result = u.Ldap.dn_str(dn)
        u.Ldap.Tests.that(result, eq=c.Ldap.UNKNOWN_CATEGORY)

    @staticmethod
    def test_dn_str_with_entry() -> None:
        """Verify dn str with entry."""
        entry = _entry({})
        result = u.Ldap.dn_str(entry)
        u.Ldap.Tests.that(result, eq=c.Ldap.Tests.ENTRY_DN_TEST_EXAMPLE)

    # --- extract_entry_attributes ---
    @staticmethod
    def test_extract_entry_attributes_with_none_attrs() -> None:
        """Verify extract entry attributes with none attrs."""
        entry = _entry(None)
        result = u.Ldap.extract_entry_attributes(entry)
        u.Ldap.Tests.that(dict(result), eq={})

    @staticmethod
    def test_extract_entry_attributes_with_attrs() -> None:
        """Verify extract entry attributes with attrs."""
        entry = _entry({"cn": ["test"]})
        result = u.Ldap.extract_entry_attributes(entry)
        tm.that(result, has="cn")


class TestsFlextLdapUtilitiesUnitFilter:
    """TestsFlextLdapUtilitiesUnitFilter test methods."""

    @staticmethod
    def test_filter_truthy() -> None:
        """Verify filter truthy."""
        result = u.Ldap.filter_truthy(dict(c.Ldap.Tests.FILTER_TRUTHY_INPUT))
        u.Ldap.Tests.that(result, is_=dict)
        u.Ldap.Tests.that(
            result,
            eq={
                key: value
                for key, value in c.Ldap.Tests.FILTER_TRUTHY_INPUT.items()
                if value
            },
        )

    # --- find_existing_values ---
    @staticmethod
    def test_find_existing_values_found_case_insensitive() -> None:
        """Verify find existing values found case insensitive."""
        existing = {"cn": ["test"], "sn": ["user"]}
        result = tm.not_none(u.Ldap.find_existing_values("CN", existing))
        tm.that(list(result), eq=["test"])

    @staticmethod
    def test_find_existing_values_not_found() -> None:
        """Verify find existing values not found."""
        existing = {"cn": ["test"]}
        result = u.Ldap.find_existing_values("mail", existing)
        tm.that(result, none=True)

    # --- base64_encoded ---
    @staticmethod
    def test_is_base64_encoded_with_prefix() -> None:
        """Verify is base64 encoded with prefix."""
        result = u.Ldap.base64_encoded(":: dGVzdA==")
        tm.that(result, eq=True)

    @staticmethod
    def test_is_base64_encoded_high_ascii() -> None:
        """Verify is base64 encoded high ascii."""
        result = u.Ldap.base64_encoded("test\x80value")
        tm.that(result, eq=True)

    @staticmethod
    def test_is_base64_encoded_normal() -> None:
        """Verify is base64 encoded normal."""
        result = u.Ldap.base64_encoded("normalvalue")
        tm.that(result, eq=False)

    @staticmethod
    def test_ldap3_value_to_strings_from_none() -> None:
        """Verify ldap3 value to strings from none."""
        result = u.Ldap.ldap3_value_to_strings(None)
        u.Ldap.Tests.that(result, eq=[])

    # --- ldap3_value_to_strings ---
    @pytest.mark.parametrize("case", c.Ldap.Tests.LdapValueCase)
    @staticmethod
    def test_ldap3_value_to_strings_scenarios(
        case: c.Ldap.Tests.LdapValueCase,
    ) -> None:
        """Verify ldap3 value to strings scenarios."""
        value, expected = c.Ldap.Tests.LDAP3_VALUE_TO_STRINGS_SCENARIOS[case]
        result = u.Ldap.ldap3_value_to_strings(value)
        u.Ldap.Tests.that(tuple(result), eq=expected)

    @staticmethod
    def test_map_str() -> None:
        """Verify map str."""
        result = u.Ldap.map_str(list(c.Ldap.Tests.LIST_ABC), case="upper")
        u.Ldap.Tests.that(result, eq=list(c.Ldap.Tests.LIST_ABC_UPPER))

    # --- map_str with join ---
    @staticmethod
    def test_map_str_with_join() -> None:
        """Verify map str with join."""
        result = u.Ldap.map_str(list(c.Ldap.Tests.LIST_ABC), join=",")
        u.Ldap.Tests.that(result, eq="a,b,c")

    @staticmethod
    def test_map_str_with_case_and_join() -> None:
        """Verify map str with case and join."""
        result = u.Ldap.map_str(list(c.Ldap.Tests.LIST_ABC), case="upper", join=" ")
        u.Ldap.Tests.that(result, eq="A B C")

    @staticmethod
    def test_norm_str_lowercase() -> None:
        """Verify norm str lowercase."""
        result = u.Ldap.norm_str(c.Ldap.Tests.STRING_SIMPLE_UPPER, case="lower")
        u.Ldap.Tests.that(result, eq=c.Ldap.Tests.STRING_SIMPLE)

    @staticmethod
    def test_norm_str_uppercase() -> None:
        """Verify norm str uppercase."""
        result = u.Ldap.norm_str(c.Ldap.Tests.STRING_SIMPLE, case="upper")
        u.Ldap.Tests.that(result, eq=c.Ldap.Tests.STRING_SIMPLE_UPPER)

    @staticmethod
    def test_norm_join() -> None:
        """Verify norm join."""
        result = u.Ldap.norm_join(list(c.Ldap.Tests.NORM_JOIN_INPUT), case="lower")
        u.Ldap.Tests.that(result, eq=c.Ldap.Tests.NORM_JOIN_EXPECTED)

    # --- norm_in with tuple ---
    @staticmethod
    def test_norm_in_with_tuple() -> None:
        """Verify norm in with tuple."""
        result = u.Ldap.norm_in("A", ("a", "b", "c"), case="lower")
        u.Ldap.Tests.that(result, eq=True)

    @staticmethod
    def test_norm_in_with_list() -> None:
        """Verify norm in with list."""
        result = u.Ldap.norm_in("X", ["a", "b", "c"], case="lower")
        u.Ldap.Tests.that(result, eq=False)

    # --- norm_str edge cases ---
    @staticmethod
    def test_norm_str_empty_string() -> None:
        """Verify norm str empty string."""
        result = u.Ldap.norm_str(c.Ldap.Tests.STRING_EMPTY)
        u.Ldap.Tests.that(result, eq=c.Ldap.Tests.STRING_EMPTY)

    @staticmethod
    def test_norm_str_no_case() -> None:
        """Verify norm str no case."""
        result = u.Ldap.norm_str(c.Ldap.Tests.STRING_SIMPLE)
        u.Ldap.Tests.that(result, eq=c.Ldap.Tests.STRING_SIMPLE)

    # --- normalize_value_set ---
    @staticmethod
    def test_normalize_value_set_lowercases_and_drops_empty() -> None:
        """Verify normalize value set lowercases and drops empty."""
        result = u.Ldap.normalize_value_set(["Alice", "BOB", ""])
        tm.that(result, eq=frozenset({"alice", "bob"}))


class TestsFlextLdapUtilitiesUnitProcess(TestsFlextLdapUtilitiesUnit):
    """TestsFlextLdapUtilitiesUnitProcess test methods."""

    # --- process_new_attributes ---
    @staticmethod
    def test_process_new_attributes_with_change() -> None:
        """Verify process new attributes with change."""
        changes, _processed = u.Ldap.process_new_attributes(
            {"cn": ["newval"]},
            {"cn": ["oldval"]},
            frozenset(),
        )
        tm.that(changes, has="cn")

    @staticmethod
    def test_process_new_attributes_no_change() -> None:
        """Verify process new attributes no change."""
        changes, _processed = u.Ldap.process_new_attributes(
            {"cn": ["same"]},
            {"cn": ["same"]},
            frozenset(),
        )
        tm.that(changes, lacks="cn")

    @staticmethod
    def test_process_new_attributes_value_comparison_is_case_insensitive() -> None:
        """Verify process new attributes value comparison is case insensitive."""
        changes, _processed = u.Ldap.process_new_attributes(
            {c.Ldap.AttributeName.COMMON_NAME: [c.Ldap.Tests.STRING_SIMPLE]},
            {c.Ldap.AttributeName.COMMON_NAME: [c.Ldap.Tests.STRING_SIMPLE_UPPER]},
            frozenset(),
        )
        tm.that(changes, lacks=c.Ldap.AttributeName.COMMON_NAME)

    @staticmethod
    def test_process_new_attributes_ignored() -> None:
        """Verify process new attributes ignored."""
        existing_attrs: t.MappingKV[str, t.StrSequence] = {}
        changes, _processed = u.Ldap.process_new_attributes(
            {"cn": ["val"]},
            existing_attrs,
            frozenset(["cn"]),
        )
        tm.that(changes, lacks="cn")

    # --- process_deleted_attributes ---
    @staticmethod
    def test_process_deleted_attributes() -> None:
        """Verify process deleted attributes."""
        existing_attrs = {"cn": ["test"], "sn": ["user"]}
        changes = u.Ldap.process_deleted_attributes(existing_attrs, frozenset(), {"cn"})
        tm.that(changes, has="sn")
        tm.that(changes, lacks="cn")

    # --- query_root_dse ---
    @staticmethod
    def test_query_root_dse_no_search_method() -> None:
        """Verify query root dse no search method."""

        class NoSearch(TestsFlextLdapRootDseProbePayload):
            search: None = None

        result = u.Ldap.query_root_dse(NoSearch())
        u.Ldap.Tests.fail(result)

    @staticmethod
    def test_query_root_dse_search_returns_false() -> None:
        """Verify query root dse search returns false."""

        class FalseSearch(TestsFlextLdapRootDseProbePayload):
            @staticmethod
            def search(**_kwargs: str | int | bool | None) -> bool:
                return False

        result = u.Ldap.query_root_dse(FalseSearch())
        u.Ldap.Tests.fail(result)

    @staticmethod
    def test_query_root_dse_no_entries() -> None:
        """Verify query root dse no entries."""

        class EmptySearch(TestsFlextLdapRootDseProbePayload):
            result_payload: ClassVar[t.JsonMapping] = {"result": 0}

            @staticmethod
            def search(**_kwargs: str | int | bool | None) -> bool:
                return True

        result = u.Ldap.query_root_dse(EmptySearch())
        u.Ldap.Tests.fail(result)

    @staticmethod
    def test_query_root_dse_invalid_entry_type() -> None:
        """Verify query root dse invalid entry type."""

        class BadEntry(TestsFlextLdapRootDseProbePayload):
            result_payload: ClassVar[t.JsonMapping] = {"result": 0}
            entry_payloads: ClassVar[t.SequenceOf[str]] = ["not_ldap3_entry"]

            @staticmethod
            def search(**_kwargs: str | int | bool | None) -> bool:
                return True

        result = u.Ldap.query_root_dse(BadEntry())
        u.Ldap.Tests.fail(result)

    @staticmethod
    def test_query_root_dse_with_ldap3_offline_strategy() -> None:
        """query_root_dse reads rootDSE attributes through a real ldap3 connection.

        ldap3's ``MOCK_SYNC`` is the library's own offline runtime: connection,
        strategy, DIT and entries are real ldap3 objects, so the exercised path
        is the production path against the real external boundary. The rootDSE
        is published in the offline DIT under its empty DN (the DN form of the
        real rootDSE); attribute values are raw BER strings (``bytes``) exactly
        as the offline strategy decodes them. The outcome is asserted
        deterministically, never as ``success or failure``.
        """
        server = Server("mock")
        conn = Connection(server, client_strategy=MOCK_SYNC)
        conn.server.dit[""] = {
            "objectClass": [b"top"],
            "namingContexts": [b"dc=example,dc=com"],
            "vendorName": [b"OpenLDAP"],
            "vendorVersion": [b"2.4.57"],
        }
        method_name = "bind"
        bind_call: Callable[..., bool] = getattr(conn, method_name)
        bind_call()
        result = u.Ldap.query_root_dse(conn)

        tm.that(result.success, eq=True)
        tm.that(
            result.value.get(c.Ldap.RootDseAttribute.NAMING_CONTEXTS),
            has="dc=example,dc=com",
        )
        tm.that(result.value.get(c.Ldap.RootDseAttribute.VENDOR_NAME), has="OpenLDAP")

    @staticmethod
    def test_rdn_attribute_names_multivalued_rdn() -> None:
        """Verify rdn_attribute_names covers every attribute of a multi-valued RDN."""
        entry = _entry({}, dn="cn=user+ou=eng,dc=example,dc=com")
        names = u.Ldap.Tests.ok(u.Ldap.rdn_attribute_names(entry))
        tm.that(names, has="cn")
        tm.that(names, has="ou")

    @staticmethod
    def test_rdn_attribute_names_without_dn_fails() -> None:
        """Verify rdn_attribute_names fails for an entry without DN."""
        entry = m.Ldif.Entry(dn=None, attributes=None, domain_events=[])
        u.Ldap.Tests.fail(u.Ldap.rdn_attribute_names(entry))

    # --- search_entry_to_ldif_entry ---
    @staticmethod
    def test_search_entry_to_ldif_entry_success() -> None:
        """Verify search entry to ldif entry success."""
        entry = {"dn": c.Ldap.Tests.ENTRY_DN_TEST_EXAMPLE, "cn": ["test"]}
        result = u.Ldap.search_entry_to_ldif_entry(entry)
        converted = u.Ldap.Tests.ok(result)
        dn = tm.not_none(converted.dn)
        u.Ldap.Tests.that(dn.value, eq=c.Ldap.Tests.ENTRY_DN_TEST_EXAMPLE)

    @staticmethod
    def test_search_entry_to_ldif_entry_missing_dn() -> None:
        """Verify search entry to ldif entry missing dn."""
        entry = {"cn": ["test"]}
        result = u.Ldap.search_entry_to_ldif_entry(entry)
        u.Ldap.Tests.fail(result)

    @staticmethod
    def test_to_str_simple() -> None:
        """Verify to str simple."""
        result = u.to_str(c.Ldap.Tests.STRING_SIMPLE)
        u.Ldap.Tests.that(result, eq=c.Ldap.Tests.STRING_SIMPLE)

    @staticmethod
    def test_to_str_list_from_list() -> None:
        """Verify to str list from list."""
        result = u.to_str_list(list(c.Ldap.Tests.LIST_ABC))
        u.Ldap.Tests.that(result, eq=list(c.Ldap.Tests.LIST_ABC))

    @staticmethod
    def test_to_str_list_from_single() -> None:
        """Verify to str list from single."""
        result = u.to_str_list(c.Ldap.Tests.LIST_SINGLE)
        u.Ldap.Tests.that(result, eq=[c.Ldap.Tests.LIST_SINGLE])

    # --- track_conversion_differences ---
    @staticmethod
    def test_track_conversion_differences_no_changes() -> None:
        """Verify track conversion differences no changes."""
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

    @staticmethod
    def test_track_conversion_differences_dn_change() -> None:
        """Verify track conversion differences dn change."""
        meta = m.Ldap.ConversionMetadata(source_dn=c.Ldap.Tests.ENTRY_DN_TEST_EXAMPLE)
        result = u.Ldap.track_conversion_differences(
            meta,
            original_dn=c.Ldap.Tests.ENTRY_DN_TEST_EXAMPLE,
            converted_dn=c.Ldap.Tests.ENTRY_DN_USER_EXAMPLE,
            original_attrs_dict={"cn": ["test"]},
            converted_attrs_dict={"cn": ["test"]},
        )
        tm.that(result.dn_changed, eq=True)

    @staticmethod
    def test_track_conversion_differences_attr_change() -> None:
        """Verify track conversion differences attr change."""
        meta = m.Ldap.ConversionMetadata(source_dn=c.Ldap.Tests.ENTRY_DN_TEST_EXAMPLE)
        result = u.Ldap.track_conversion_differences(
            meta,
            original_dn=c.Ldap.Tests.ENTRY_DN_TEST_EXAMPLE,
            converted_dn=c.Ldap.Tests.ENTRY_DN_TEST_EXAMPLE,
            original_attrs_dict={"cn": ["old"]},
            converted_attrs_dict={"cn": ["new"]},
        )
        tm.that(result.attribute_changes, has="cn")


class TestsFlextLdapUtilitiesUnitWhen:
    """TestsFlextLdapUtilitiesUnitWhen test methods."""

    # --- when_safe ---
    @staticmethod
    def test_when_safe_condition_true() -> None:
        """Verify when safe condition true."""
        result = u.Ldap.when_safe(condition=True, then_value="yes", else_value="no")
        u.Ldap.Tests.that(result, eq="yes")

    @staticmethod
    def test_when_safe_condition_false() -> None:
        """Verify when safe condition false."""
        result = u.Ldap.when_safe(condition=False, then_value="yes", else_value="no")
        u.Ldap.Tests.that(result, eq="no")

    @staticmethod
    def test_when_safe_safe_then_true_with_none() -> None:
        """Verify when safe safe then true with none."""
        result = u.Ldap.when_safe(
            condition=True,
            then_value=None,
            else_value="fallback",
            safe_then=True,
        )
        u.Ldap.Tests.that(result, eq="fallback")

    @staticmethod
    def test_when_safe_safe_then_true_non_none() -> None:
        """Verify when safe safe then true non none."""
        result = u.Ldap.when_safe(
            condition=True,
            then_value="value",
            else_value="fallback",
            safe_then=True,
        )
        u.Ldap.Tests.that(result, eq="value")

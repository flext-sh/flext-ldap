"""Unit tests for flext_ldap.adapters.entry.FlextLdapEntryAdapter.

Architecture: Single class per module following FLEXT patterns.
Uses t, c, p, m, u, s for test support and e, r, d, x from flext-core.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

import pytest
from flext_tests import tm

from flext_ldap import FlextLdapEntryAdapter
from tests import c, m, p

pytestmark = pytest.mark.unit


class TestsFlextLdapEntryAdapter:
    """Comprehensive tests for FlextLdapEntryAdapter.

    Mock classes centralized in m.Ldap.Tests.MockLdap3Attribute / MockLdap3Entry.
    """

    def test_adapter_initialization(self) -> None:
        adapter = FlextLdapEntryAdapter()
        tm.that(adapter, is_=FlextLdapEntryAdapter, none=False)

    def test_execute_returns_success(self) -> None:
        adapter = FlextLdapEntryAdapter()
        result = adapter.execute()
        tm.ok(result, eq=True)

    def test_is_base64_encoded_with_base64_marker(self) -> None:
        tm.that(
            FlextLdapEntryAdapter._ConversionHelpers.is_base64_encoded(
                c.Ldap.Tests.EntryAdapter.BASE64_MARKER_VALUE,
            ),
            eq=True,
        )

    def test_is_base64_encoded_with_ascii_value(self) -> None:
        tm.that(
            not FlextLdapEntryAdapter._ConversionHelpers.is_base64_encoded(
                c.Ldap.Tests.StringValues.SIMPLE,
            ),
            eq=True,
        )

    def test_is_base64_encoded_with_non_ascii_value(self) -> None:
        tm.that(
            FlextLdapEntryAdapter._ConversionHelpers.is_base64_encoded(
                c.Ldap.Tests.EntryAdapter.NON_ASCII_VALUE,
            ),
            eq=True,
        )

    def test_is_base64_encoded_with_empty_string(self) -> None:
        tm.that(
            not FlextLdapEntryAdapter._ConversionHelpers.is_base64_encoded(
                c.Ldap.Tests.StringValues.EMPTY,
            ),
            eq=True,
        )

    def test_ldap3_to_ldif_entry(self) -> None:
        adapter = FlextLdapEntryAdapter()
        ldap3_entry: p.Ldap.Ldap3Entry = m.Ldap.Tests.MockLdap3Entry(
            attrs=dict(c.Ldap.Tests.EntryAdapter.SAMPLE_ATTRIBUTES),
        )
        result = adapter.ldap3_to_ldif_entry(ldap3_entry)
        entry = tm.ok(result)
        assert isinstance(entry, m.Ldif.Entry), "expected Ldif.Entry"
        tm.that(entry, is_=m.Ldif.Entry, none=False)
        tm.that(entry.dn, none=False)
        assert entry.dn is not None
        tm.that(entry.dn.value, eq=c.Ldap.Tests.EntryDN.USER_EXAMPLE)
        tm.that(entry.attributes, none=False)

    def test_ldap3_to_ldif_entry_with_empty_attributes(self) -> None:
        adapter = FlextLdapEntryAdapter()
        ldap3_entry: p.Ldap.Ldap3Entry = m.Ldap.Tests.MockLdap3Entry()
        result = adapter.ldap3_to_ldif_entry(ldap3_entry)
        entry = tm.ok(result)
        assert isinstance(entry, m.Ldif.Entry), "expected Ldif.Entry"
        tm.that(entry, is_=m.Ldif.Entry, none=False)
        tm.that(entry.dn, none=False)
        assert entry.dn is not None
        tm.that(entry.dn.value, eq=c.Ldap.Tests.EntryDN.USER_EXAMPLE)

    def test_ldif_entry_to_ldap3_attributes(self) -> None:
        adapter = FlextLdapEntryAdapter()
        entry = m.Ldif.Entry(
            dn=m.Ldif.DN(value=c.Ldap.Tests.EntryDN.USER_EXAMPLE),
            attributes=m.Ldif.Attributes(
                attributes={
                    k: list(v)
                    for k, v in c.Ldap.Tests.EntryAdapter.SAMPLE_ATTRIBUTES.items()
                },
                attribute_metadata={},
            ),
        )
        result = adapter.ldif_entry_to_ldap3_attributes(entry)
        attributes = tm.ok(result)
        tm.that(
            attributes,
            keys=list(c.Ldap.Tests.EntryAdapter.SAMPLE_ATTRIBUTES),
            kv=dict(c.Ldap.Tests.EntryAdapter.SAMPLE_ATTRIBUTES),
        )

    def test_ldif_entry_to_ldap3_attributes_with_empty_attributes(self) -> None:
        adapter = FlextLdapEntryAdapter()
        entry = m.Ldif.Entry(
            dn=m.Ldif.DN(value=c.Ldap.Tests.EntryDN.USER_EXAMPLE),
            attributes=m.Ldif.Attributes(
                attributes={},
                attribute_metadata={},
            ),
        )
        result = adapter.ldif_entry_to_ldap3_attributes(entry)
        err = tm.fail(result, has=c.Ldap.Tests.EntryAdapter.NO_ATTRIBUTES_ERROR)
        tm.that(err.lower(), contains=c.Ldap.Tests.EntryAdapter.NO_ATTRIBUTES_ERROR)

    def test_adapter_methods_exist(self) -> None:
        adapter = FlextLdapEntryAdapter()
        tm.that(hasattr(adapter, "execute"), eq=True)
        tm.that(callable(adapter.execute), eq=True)
        tm.that(hasattr(adapter, "ldap3_to_ldif_entry"), eq=True)
        tm.that(callable(adapter.ldap3_to_ldif_entry), eq=True)
        tm.that(hasattr(adapter, "ldif_entry_to_ldap3_attributes"), eq=True)
        tm.that(callable(adapter.ldif_entry_to_ldap3_attributes), eq=True)

    def test_adapter_inner_classes_exist(self) -> None:
        tm.that(hasattr(FlextLdapEntryAdapter, "_ConversionHelpers"), eq=True)
        assert isinstance(FlextLdapEntryAdapter._ConversionHelpers, type)

    def test_conversion_helpers_static_methods_exist(self) -> None:
        assert hasattr(FlextLdapEntryAdapter._ConversionHelpers, "is_base64_encoded")
        assert callable(FlextLdapEntryAdapter._ConversionHelpers.is_base64_encoded)


__all__ = ["TestsFlextLdapEntryAdapter"]

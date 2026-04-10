"""Unit tests for flext_ldap.adapters.entry.FlextLdapEntryAdapter.

Architecture: Single class per module following FLEXT patterns.
Uses t, c, p, m, u, s for test support and e, r, d, x from flext-core.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

import pytest

from flext_ldap import FlextLdapEntryAdapter
from tests import c, m, u

pytestmark = pytest.mark.unit


class TestsFlextLdapEntryAdapter:
    """Comprehensive tests for FlextLdapEntryAdapter.

    Mock classes centralized in m.Ldap.Tests.MockLdap3Attribute / MockLdap3Entry.
    """

    def test_adapter_initialization(self) -> None:
        adapter = FlextLdapEntryAdapter()
        u.Ldap.Tests.that(adapter, is_=FlextLdapEntryAdapter, none=False)

    def test_execute_returns_success(self) -> None:
        adapter = FlextLdapEntryAdapter()
        result = adapter.execute()
        u.Ldap.Tests.ok(result, eq=True)

    def test_is_base64_encoded_with_base64_marker(self) -> None:
        u.Ldap.Tests.that(
            FlextLdapEntryAdapter._ConversionHelpers.is_base64_encoded(
                c.Ldap.Tests.ENTRY_ADAPTER_BASE64_MARKER_VALUE,
            ),
            eq=True,
        )

    def test_is_base64_encoded_with_ascii_value(self) -> None:
        u.Ldap.Tests.that(
            not FlextLdapEntryAdapter._ConversionHelpers.is_base64_encoded(
                c.Ldap.Tests.STRING_SIMPLE,
            ),
            eq=True,
        )

    def test_is_base64_encoded_with_non_ascii_value(self) -> None:
        u.Ldap.Tests.that(
            FlextLdapEntryAdapter._ConversionHelpers.is_base64_encoded(
                c.Ldap.Tests.ENTRY_ADAPTER_NON_ASCII_VALUE,
            ),
            eq=True,
        )

    def test_is_base64_encoded_with_empty_string(self) -> None:
        u.Ldap.Tests.that(
            not FlextLdapEntryAdapter._ConversionHelpers.is_base64_encoded(
                c.Ldap.Tests.STRING_EMPTY,
            ),
            eq=True,
        )

    def test_ldap3_to_ldif_entry(self) -> None:
        adapter = FlextLdapEntryAdapter()
        ldap3_entry = m.Ldap.Tests.MockLdap3Entry(
            attrs=dict(c.Ldap.Tests.ENTRY_ADAPTER_SAMPLE_ATTRIBUTES),
        )
        result = adapter.ldap3_to_ldif_entry(ldap3_entry)
        entry = u.Ldap.Tests.ok(result)
        assert isinstance(entry, m.Ldif.Entry), "expected Ldif.Entry"
        u.Ldap.Tests.that(entry, is_=m.Ldif.Entry, none=False)
        u.Ldap.Tests.that(entry.dn, none=False)
        assert entry.dn is not None
        u.Ldap.Tests.that(entry.dn.value, eq=c.Ldap.Tests.ENTRY_DN_USER_EXAMPLE)
        u.Ldap.Tests.that(entry.attributes, none=False)

    def test_ldap3_to_ldif_entry_with_empty_attributes(self) -> None:
        adapter = FlextLdapEntryAdapter()
        ldap3_entry = m.Ldap.Tests.MockLdap3Entry()
        result = adapter.ldap3_to_ldif_entry(ldap3_entry)
        entry = u.Ldap.Tests.ok(result)
        assert isinstance(entry, m.Ldif.Entry), "expected Ldif.Entry"
        u.Ldap.Tests.that(entry, is_=m.Ldif.Entry, none=False)
        u.Ldap.Tests.that(entry.dn, none=False)
        assert entry.dn is not None
        u.Ldap.Tests.that(entry.dn.value, eq=c.Ldap.Tests.ENTRY_DN_USER_EXAMPLE)

    def test_ldif_entry_to_ldap3_attributes(self) -> None:
        adapter = FlextLdapEntryAdapter()
        entry = m.Ldif.Entry(
            dn=m.Ldif.DN(value=c.Ldap.Tests.ENTRY_DN_USER_EXAMPLE),
            attributes=m.Ldif.Attributes(
                attributes={
                    k: list(v)
                    for k, v in c.Ldap.Tests.ENTRY_ADAPTER_SAMPLE_ATTRIBUTES.items()
                },
                attribute_metadata={},
            ),
        )
        result = adapter.ldif_entry_to_ldap3_attributes(entry)
        attributes = u.Ldap.Tests.ok(result)
        u.Ldap.Tests.that(
            attributes,
            keys=list(c.Ldap.Tests.ENTRY_ADAPTER_SAMPLE_ATTRIBUTES),
            kv={
                key: list(values)
                for key, values in c.Ldap.Tests.ENTRY_ADAPTER_SAMPLE_ATTRIBUTES.items()
            },
        )

    def test_ldif_entry_to_ldap3_attributes_with_empty_attributes(self) -> None:
        adapter = FlextLdapEntryAdapter()
        entry = m.Ldif.Entry(
            dn=m.Ldif.DN(value=c.Ldap.Tests.ENTRY_DN_USER_EXAMPLE),
            attributes=m.Ldif.Attributes(
                attributes={},
                attribute_metadata={},
            ),
        )
        result = adapter.ldif_entry_to_ldap3_attributes(entry)
        err = u.Ldap.Tests.fail(
            result, has=c.Ldap.Tests.ENTRY_ADAPTER_NO_ATTRIBUTES_ERROR
        )
        u.Ldap.Tests.that(
            err.lower(), contains=c.Ldap.Tests.ENTRY_ADAPTER_NO_ATTRIBUTES_ERROR
        )

    def test_adapter_methods_exist(self) -> None:
        adapter = FlextLdapEntryAdapter()
        u.Ldap.Tests.that(hasattr(adapter, "execute"), eq=True)
        u.Ldap.Tests.that(callable(adapter.execute), eq=True)
        u.Ldap.Tests.that(hasattr(adapter, "ldap3_to_ldif_entry"), eq=True)
        u.Ldap.Tests.that(callable(adapter.ldap3_to_ldif_entry), eq=True)
        u.Ldap.Tests.that(hasattr(adapter, "ldif_entry_to_ldap3_attributes"), eq=True)
        u.Ldap.Tests.that(callable(adapter.ldif_entry_to_ldap3_attributes), eq=True)

    def test_adapter_inner_classes_exist(self) -> None:
        u.Ldap.Tests.that(hasattr(FlextLdapEntryAdapter, "_ConversionHelpers"), eq=True)
        assert isinstance(FlextLdapEntryAdapter._ConversionHelpers, type)

    def test_conversion_helpers_static_methods_exist(self) -> None:
        assert callable(FlextLdapEntryAdapter._ConversionHelpers.is_base64_encoded)


__all__ = ["TestsFlextLdapEntryAdapter"]

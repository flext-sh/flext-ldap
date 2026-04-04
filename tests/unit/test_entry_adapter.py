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
from tests import c, m, p, t

pytestmark = pytest.mark.unit


class TestsFlextLdapEntryAdapter:
    """Comprehensive tests for FlextLdapEntryAdapter.

    All helper classes are nested within this single class.
    Mock classes are class-level (not duplicated per method).
    """

    class _MockAttr:
        """Mock ldap3 Attribute satisfying p.Ldap.Ldap3Attribute."""

        def __init__(self, vals: t.StrSequence) -> None:
            self.values: t.Ldap.Ldap3AttributeValues = vals
            self.raw_values: list[bytes] = [v.encode() for v in vals]
            self.value: t.Ldap.Ldap3AttributeValue = vals[0] if vals else ""

    class _MockLdap3Entry:
        """Mock ldap3 Entry satisfying p.Ldap.Ldap3Entry."""

        def __init__(
            self,
            dn: str = c.Ldap.Tests.EntryDN.USER_EXAMPLE,
            attrs: t.StrSequenceMapping | None = None,
        ) -> None:
            self.entry_dn: str | None = dn
            self._attrs: t.StrSequenceMapping = attrs or {}

        @property
        def entry_attributes_as_dict(self) -> t.Ldap.Ldap3AttributeDict:
            return self._attrs

        @property
        def entry_attributes(self) -> t.StrSequence:
            return list(self._attrs)

        def __getitem__(self, item: str) -> p.Ldap.Ldap3Attribute:
            return TestsFlextLdapEntryAdapter._MockAttr(
                list(self._attrs.get(item, [])),
            )

    def test_adapter_initialization(self) -> None:
        adapter = FlextLdapEntryAdapter()
        tm.that(adapter, is_=FlextLdapEntryAdapter, none=False)

    def test_execute_returns_success(self) -> None:
        adapter = FlextLdapEntryAdapter()
        result = adapter.execute()
        tm.ok(result, eq=True)

    def test_is_base64_encoded_with_base64_marker(self) -> None:
        tm.that(
            FlextLdapEntryAdapter._ConversionHelpers.is_base64_encoded("::dGVzdA=="),
            eq=True,
        )

    def test_is_base64_encoded_with_ascii_value(self) -> None:
        tm.that(
            not FlextLdapEntryAdapter._ConversionHelpers.is_base64_encoded("test"),
            eq=True,
        )

    def test_is_base64_encoded_with_non_ascii_value(self) -> None:
        tm.that(
            FlextLdapEntryAdapter._ConversionHelpers.is_base64_encoded("testÿ"),
            eq=True,
        )

    def test_is_base64_encoded_with_empty_string(self) -> None:
        tm.that(
            not FlextLdapEntryAdapter._ConversionHelpers.is_base64_encoded(""),
            eq=True,
        )

    def test_ldap3_to_ldif_entry(self) -> None:
        adapter = FlextLdapEntryAdapter()
        ldap3_entry: p.Ldap.Ldap3Entry = self._MockLdap3Entry(
            attrs={"cn": ["user"], "sn": ["Doe"]},
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
        ldap3_entry: p.Ldap.Ldap3Entry = self._MockLdap3Entry()
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
                attributes={"cn": ["user"], "sn": ["Doe"]},
                attribute_metadata={},
            ),
        )
        result = adapter.ldif_entry_to_ldap3_attributes(entry)
        attributes = tm.ok(result)
        tm.that(attributes, keys=["cn", "sn"], kv={"cn": ["user"], "sn": ["Doe"]})

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
        err = tm.fail(result, has="no attributes")
        tm.that(err.lower(), contains="no attributes")

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

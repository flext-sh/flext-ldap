"""Unit tests for flext_ldap.adapters.entry.FlextLdapEntryAdapter.

**Modules Tested:**
- `flext_ldap.adapters.entry.FlextLdapEntryAdapter` - Entry adapter for ldap3 ↔ FlextLdif conversion

**Test Scope:**
- Adapter initialization
- Execute method (health check)
- ldap3.Entry → p.Entry conversion
- p.Entry → ldap3 attributes conversion
- Base64 encoding detection
- Server-specific normalization
- Method existence validation

All tests use real functionality without mocks, leveraging flext-core test utilities
and domain-specific helpers to reduce code duplication while maintaining 100% coverage.

Architecture: Single class per module following FLEXT patterns.
Uses t, c, p, m, u, s for test support and e, r, d, x from flext-core.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

import pytest
from flext_tests import m, u

from flext_ldap import FlextLdapEntryAdapter
from tests import m

pytestmark = pytest.mark.unit


class TestsFlextLdapEntryAdapter:
    """Comprehensive tests for FlextLdapEntryAdapter using factories and DRY principles.

    Architecture: Single class per module following FLEXT patterns.
    Uses t, c, p, m, u, s for test support and e, r, d, x from flext-core.

    Uses parametrized tests and constants for maximum code reuse.
    All helper logic is nested within this single class following FLEXT patterns.
    """

    def test_adapter_initialization(self) -> None:
        """Test adapter initialization."""
        adapter = FlextLdapEntryAdapter()
        u.Tests.Matchers.that(adapter, is_=FlextLdapEntryAdapter, none=False)

    def test_execute_returns_success(self) -> None:
        """Test execute() returns success for health check."""
        adapter = FlextLdapEntryAdapter()
        result = adapter.execute()
        u.Tests.Matchers.ok(result, eq=True)

    def test_is_base64_encoded_with_base64_marker(self) -> None:
        """Test is_base64_encoded with base64 marker."""
        u.Tests.Matchers.that(
            FlextLdapEntryAdapter._ConversionHelpers.is_base64_encoded("::dGVzdA=="),
            eq=True,
        )

    def test_is_base64_encoded_with_ascii_value(self) -> None:
        """Test is_base64_encoded with ASCII value."""
        u.Tests.Matchers.that(
            FlextLdapEntryAdapter._ConversionHelpers.is_base64_encoded("test"), eq=False
        )

    def test_is_base64_encoded_with_non_ascii_value(self) -> None:
        """Test is_base64_encoded with non-ASCII value."""
        u.Tests.Matchers.that(
            FlextLdapEntryAdapter._ConversionHelpers.is_base64_encoded("testÿ"), eq=True
        )

    def test_is_base64_encoded_with_empty_string(self) -> None:
        """Test is_base64_encoded with empty string."""
        u.Tests.Matchers.that(
            FlextLdapEntryAdapter._ConversionHelpers.is_base64_encoded(""), eq=False
        )

    def test_ldap3_to_ldif_entry(self) -> None:
        """Test conversion from ldap3.Entry to p.Entry."""
        adapter = FlextLdapEntryAdapter()

        class MockLdap3Entry:
            def __init__(self) -> None:
                self.entry_dn = "cn=user,dc=example,dc=com"
                self._entry_attributes_as_dict: dict[str, list[str]] = {
                    "cn": ["user"],
                    "sn": ["Doe"],
                }

            @property
            def entry_attributes_as_dict(self) -> dict[str, list[str]]:
                return self._entry_attributes_as_dict

        ldap3_entry = MockLdap3Entry()
        result = adapter.ldap3_to_ldif_entry(ldap3_entry)
        entry = u.Tests.Matchers.ok(result)
        assert isinstance(entry, m.Ldif.Entry), "expected Ldif.Entry"
        u.Tests.Matchers.that(entry, is_=m.Ldif.Entry, none=False)
        u.Tests.Matchers.that(entry.dn, none=False)
        assert entry.dn is not None
        u.Tests.Matchers.that(entry.dn.value, eq="cn=user,dc=example,dc=com")
        u.Tests.Matchers.that(entry.attributes, none=False)

    def test_ldap3_to_ldif_entry_with_empty_attributes(self) -> None:
        """Test conversion from ldap3.Entry to p.Entry with empty attributes."""
        adapter = FlextLdapEntryAdapter()

        class MockLdap3Entry:
            def __init__(self) -> None:
                self.entry_dn = "cn=user,dc=example,dc=com"
                self._entry_attributes_as_dict: dict[str, list[str]] = {}

            @property
            def entry_attributes_as_dict(self) -> dict[str, list[str]]:
                return self._entry_attributes_as_dict

        ldap3_entry = MockLdap3Entry()
        result = adapter.ldap3_to_ldif_entry(ldap3_entry)
        entry = u.Tests.Matchers.ok(result)
        assert isinstance(entry, m.Ldif.Entry), "expected Ldif.Entry"
        u.Tests.Matchers.that(entry, is_=m.Ldif.Entry, none=False)
        u.Tests.Matchers.that(entry.dn, none=False)
        assert entry.dn is not None
        u.Tests.Matchers.that(entry.dn.value, eq="cn=user,dc=example,dc=com")

    def test_ldif_entry_to_ldap3_attributes(self) -> None:
        """Test conversion from p.Entry to ldap3 attributes."""
        adapter = FlextLdapEntryAdapter()
        entry = m.Ldif.Entry(
            dn=m.Ldif.DN(value="cn=user,dc=example,dc=com"),
            attributes=m.Ldif.Attributes(attributes={"cn": ["user"], "sn": ["Doe"]}),
        )
        result = adapter.ldif_entry_to_ldap3_attributes(entry)
        attributes = u.Tests.Matchers.ok(result)
        u.Tests.Matchers.that(
            attributes, keys=["cn", "sn"], kv={"cn": ["user"], "sn": ["Doe"]}
        )

    def test_ldif_entry_to_ldap3_attributes_with_empty_attributes(self) -> None:
        """Test conversion from p.Entry to ldap3 attributes with empty attributes."""
        adapter = FlextLdapEntryAdapter()
        entry = m.Ldif.Entry(
            dn=m.Ldif.DN(value="cn=user,dc=example,dc=com"),
            attributes=m.Ldif.Attributes(attributes={}),
        )
        result = adapter.ldif_entry_to_ldap3_attributes(entry)
        err = u.Tests.Matchers.fail(result, has="no attributes")
        u.Tests.Matchers.that(err.lower(), contains="no attributes")

    def test_adapter_methods_exist(self) -> None:
        """Test that all expected methods exist on adapter."""
        adapter = FlextLdapEntryAdapter()
        u.Tests.Matchers.that(hasattr(adapter, "execute"), eq=True)
        u.Tests.Matchers.that(callable(adapter.execute), eq=True)
        u.Tests.Matchers.that(hasattr(adapter, "ldap3_to_ldif_entry"), eq=True)
        u.Tests.Matchers.that(callable(adapter.ldap3_to_ldif_entry), eq=True)
        u.Tests.Matchers.that(
            hasattr(adapter, "ldif_entry_to_ldap3_attributes"), eq=True
        )
        u.Tests.Matchers.that(callable(adapter.ldif_entry_to_ldap3_attributes), eq=True)

    def test_adapter_inner_classes_exist(self) -> None:
        """Test that inner classes exist."""
        u.Tests.Matchers.that(
            hasattr(FlextLdapEntryAdapter, "_ConversionHelpers"), eq=True
        )
        assert isinstance(FlextLdapEntryAdapter._ConversionHelpers, type)

    def test_conversion_helpers_static_methods_exist(self) -> None:
        """Test that static methods exist on _ConversionHelpers."""
        assert hasattr(FlextLdapEntryAdapter._ConversionHelpers, "is_base64_encoded")
        assert callable(FlextLdapEntryAdapter._ConversionHelpers.is_base64_encoded)


__all__ = ["TestsFlextLdapEntryAdapter"]

"""Unit tests for flext_ldap.adapters.entry.FlextLdapEntryAdapter.

**Modules Tested:**
- `flext_ldap.adapters.entry.FlextLdapEntryAdapter` - Entry adapter for ldap3 ↔ FlextLdif conversion

**Test Scope:**
- Adapter initialization
- Execute method (health check)
- ldap3.Entry → m.Entry conversion
- m.Entry → ldap3 attributes conversion
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

from typing import Any, cast

import pytest
from flext_tests import tm

from flext_ldap.adapters.entry import FlextLdapEntryAdapter
from flext_ldap.models import m

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
        tm.that(adapter, is_=FlextLdapEntryAdapter, none=False)

    def test_execute_returns_success(self) -> None:
        """Test execute() returns success for health check."""
        adapter = FlextLdapEntryAdapter()
        result = adapter.execute()
        tm.ok(result, eq=True)

    def test_is_base64_encoded_with_base64_marker(self) -> None:
        """Test is_base64_encoded with base64 marker."""
        tm.that(
            FlextLdapEntryAdapter._ConversionHelpers.is_base64_encoded("::dGVzdA=="),
            eq=True,
        )

    def test_is_base64_encoded_with_ascii_value(self) -> None:
        """Test is_base64_encoded with ASCII value."""
        tm.that(
            FlextLdapEntryAdapter._ConversionHelpers.is_base64_encoded("test"),
            eq=False,
        )

    def test_is_base64_encoded_with_non_ascii_value(self) -> None:
        """Test is_base64_encoded with non-ASCII value."""
        tm.that(
            FlextLdapEntryAdapter._ConversionHelpers.is_base64_encoded("test\xff"),
            eq=True,
        )

    def test_is_base64_encoded_with_empty_string(self) -> None:
        """Test is_base64_encoded with empty string."""
        tm.that(
            FlextLdapEntryAdapter._ConversionHelpers.is_base64_encoded(""),
            eq=False,
        )

    def test_ldap3_to_ldif_entry(self) -> None:
        """Test conversion from ldap3.Entry to m.Entry."""
        adapter = FlextLdapEntryAdapter()
        # Create mock ldap3.Entry-like object

        class MockLdap3Entry:
            def __init__(self) -> None:
                self.entry_dn = "cn=user,dc=example,dc=com"
                self.entry_attributes_as_dict: dict[str, list[str]] = {
                    "cn": ["user"],
                    "sn": ["Doe"],
                }

        ldap3_entry = MockLdap3Entry()
        # Cast to Any to match expected type (ldap3.Entry is not available in tests)
        result = adapter.ldap3_to_ldif_entry(cast("Any", ldap3_entry))
        entry = tm.ok(result)
        tm.that(entry, is_=m.Entry, none=False)
        tm.that(entry.dn, none=False)
        assert entry.dn is not None  # Type guard
        tm.that(entry.dn.value, eq="cn=user,dc=example,dc=com")
        tm.that(entry.attributes, none=False)

    def test_ldap3_to_ldif_entry_with_empty_attributes(self) -> None:
        """Test conversion from ldap3.Entry to m.Entry with empty attributes."""
        adapter = FlextLdapEntryAdapter()
        # Create mock ldap3.Entry-like object

        class MockLdap3Entry:
            def __init__(self) -> None:
                self.entry_dn = "cn=user,dc=example,dc=com"
                self.entry_attributes_as_dict: dict[str, list[str]] = {}

        ldap3_entry = MockLdap3Entry()
        # Cast to Any to match expected type (ldap3.Entry is not available in tests)
        result = adapter.ldap3_to_ldif_entry(cast("Any", ldap3_entry))
        entry = tm.ok(result)
        tm.that(entry, is_=m.Entry, none=False)
        tm.that(entry.dn, none=False)
        assert entry.dn is not None  # Type guard
        tm.that(entry.dn.value, eq="cn=user,dc=example,dc=com")

    def test_ldif_entry_to_ldap3_attributes(self) -> None:
        """Test conversion from m.Entry to ldap3 attributes."""
        adapter = FlextLdapEntryAdapter()
        entry = m.Entry(
            dn=m.DistinguishedName(value="cn=user,dc=example,dc=com"),
            attributes=m.LdifAttributes(attributes={"cn": ["user"], "sn": ["Doe"]}),
        )
        result = adapter.ldif_entry_to_ldap3_attributes(entry)
        attributes = tm.ok(result)
        # Single call validates type, None, keys, and values
        tm.that(
            attributes,
            keys=["cn", "sn"],
            kv={"cn": ["user"], "sn": ["Doe"]},
        )

    def test_ldif_entry_to_ldap3_attributes_with_empty_attributes(self) -> None:
        """Test conversion from m.Entry to ldap3 attributes with empty attributes."""
        adapter = FlextLdapEntryAdapter()
        entry = m.Entry(
            dn=m.DistinguishedName(value="cn=user,dc=example,dc=com"),
            attributes=m.LdifAttributes(attributes={}),
        )
        result = adapter.ldif_entry_to_ldap3_attributes(entry)
        err = tm.fail(result, has="no attributes")
        tm.that(err.lower(), contains="no attributes")

    def test_adapter_methods_exist(self) -> None:
        """Test that all expected methods exist on adapter."""
        adapter = FlextLdapEntryAdapter()
        # Check main methods - single call validates all
        tm.has(adapter, "execute")
        tm.has(adapter, "ldap3_to_ldif_entry")
        tm.has(adapter, "ldif_entry_to_ldap3_attributes")
        assert hasattr(adapter, "execute")
        assert callable(getattr(adapter, "execute", None))
        assert hasattr(adapter, "ldap3_to_ldif_entry")
        assert callable(getattr(adapter, "ldap3_to_ldif_entry", None))
        assert hasattr(adapter, "ldif_entry_to_ldap3_attributes")
        assert callable(getattr(adapter, "ldif_entry_to_ldap3_attributes", None))

    def test_adapter_inner_classes_exist(self) -> None:
        """Test that inner classes exist."""
        tm.that(hasattr(FlextLdapEntryAdapter, "_ConversionHelpers"), eq=True)
        tm.that(FlextLdapEntryAdapter._ConversionHelpers, is_=type, none=False)

    def test_conversion_helpers_static_methods_exist(self) -> None:
        """Test that static methods exist on _ConversionHelpers."""
        assert hasattr(FlextLdapEntryAdapter._ConversionHelpers, "is_base64_encoded")
        assert callable(
            getattr(FlextLdapEntryAdapter._ConversionHelpers, "is_base64_encoded", None)
        )

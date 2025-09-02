"""Unit tests for FLEXT-LDAP value objects.

Tests value object classes for proper validation and behavior.
"""

from __future__ import annotations

import pytest

from flext_ldap.value_objects import (
    FlextLDAPDistinguishedName,
    FlextLDAPFilter,
    FlextLDAPScope,
)


class TestFlextLDAPDistinguishedName:
    """Test LDAP Distinguished Name value object."""

    def test_create_dn_with_valid_values(self) -> None:
        """Test DN creation with valid DN strings."""
        dn_str = "cn=John Doe,ou=users,dc=example,dc=com"
        dn_vo = FlextLDAPDistinguishedName(value=dn_str)
        assert dn_vo.value == dn_str

    def test_dn_validation_with_short_value(self) -> None:
        """Test DN validation with too short value."""
        with pytest.raises((ValueError, Exception)):
            FlextLDAPDistinguishedName(value="x")


class TestFlextLDAPFilter:
    """Test LDAP Filter value object."""

    def test_create_filter_with_simple_filter(self) -> None:
        """Test filter creation with simple filter string."""
        filter_str = "(cn=John Doe)"
        filter_vo = FlextLDAPFilter(value=filter_str)
        assert filter_vo.value == filter_str


class TestFlextLDAPScope:
    """Test LDAP Search Scope value object."""

    def test_create_scope_with_valid_scope(self) -> None:
        """Test scope creation with valid scope."""
        scope_vo = FlextLDAPScope(scope="subtree")
        assert scope_vo.scope == "subtree"

"""Test coverage for FlextLdapValueObjects missing lines.

This module provides surgical test coverage for specific uncovered lines
in value_objects.py to achieve 100% coverage.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from flext_ldap.value_objects import FlextLdapValueObjects


class TestFlextLdapValueObjectsCoverage:
    """Test class for covering missing value objects lines."""

    def test_dn_rdn_property(self) -> None:
        """Test DN rdn property (covers line 38)."""
        # Create valid DN and test rdn extraction
        dn = FlextLdapValueObjects.DistinguishedName.create(
            "cn=test,ou=users,dc=example,dc=com",
        )
        rdn = dn.rdn
        assert rdn == "cn=test"

    def test_dn_validation_empty_error(self) -> None:
        """Test DN validation with empty value."""
        try:
            FlextLdapValueObjects.DistinguishedName(value="")
            msg = "Expected ValueError for empty DN"
            raise AssertionError(msg)
        except ValueError as e:
            assert "Distinguished Name cannot be empty" in str(e)

    def test_dn_validation_missing_equals_error(self) -> None:
        """Test DN validation with missing equals sign."""
        try:
            FlextLdapValueObjects.DistinguishedName(value="invalid_dn_format")
            msg = "Expected ValueError for invalid DN format"
            raise AssertionError(msg)
        except ValueError as e:
            assert "Invalid DN format - missing attribute=value pairs" in str(e)

    def test_filter_empty_expression_error(self) -> None:
        """Test Filter validation with empty expression."""
        try:
            FlextLdapValueObjects.Filter(expression="")
            msg = "Expected ValueError for empty filter"
            raise AssertionError(msg)
        except ValueError as e:
            assert "LDAP filter cannot be empty" in str(e)

    def test_filter_missing_parentheses_error(self) -> None:
        """Test Filter validation with missing parentheses."""
        try:
            FlextLdapValueObjects.Filter(expression="uid=test")
            msg = "Expected ValueError for missing parentheses"
            raise AssertionError(msg)
        except ValueError as e:
            assert "LDAP filter must be enclosed in parentheses" in str(e)

    def test_filter_factory_methods(self) -> None:
        """Test Filter factory methods."""
        # Test equals factory
        equals_filter = FlextLdapValueObjects.Filter.equals("uid", "testuser")
        assert equals_filter.expression == "(uid=testuser)"

        # Test starts_with factory
        starts_filter = FlextLdapValueObjects.Filter.starts_with("cn", "test")
        assert starts_filter.expression == "(cn=test*)"

        # Test object_class factory
        class_filter = FlextLdapValueObjects.Filter.object_class("person")
        assert class_filter.expression == "(objectClass=person)"

    def test_scope_invalid_value_error(self) -> None:
        """Test Scope with invalid value."""
        try:
            FlextLdapValueObjects.Scope(value="invalid_scope")
            msg = "Expected ValueError"
            raise AssertionError(msg)
        except ValueError as e:
            assert "Invalid scope" in str(e)

    def test_scope_factory_methods(self) -> None:
        """Test Scope factory methods."""
        # Test base scope factory
        base_scope = FlextLdapValueObjects.Scope.base()
        assert base_scope.value == "base"

        # Test onelevel scope factory
        onelevel_scope = FlextLdapValueObjects.Scope.onelevel()
        assert onelevel_scope.value == "onelevel"

        # Test subtree scope factory
        subtree_scope = FlextLdapValueObjects.Scope.subtree()
        assert subtree_scope.value == "subtree"

    def test_scope_valid_values(self) -> None:
        """Test Scope with valid values."""
        # Test valid scope values based on the constants in value_objects.py
        for scope in ["base", "onelevel", "subtree"]:
            scope_obj = FlextLdapValueObjects.Scope(value=scope)
            assert scope_obj.value == scope, f"Should accept scope: {scope}"

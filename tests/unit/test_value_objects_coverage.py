"""Test coverage for FlextLdapValueObjects missing lines.

This module provides surgical test coverage for specific uncovered lines
in value_objects.py to achieve 100% coverage.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

import pytest

from flext_ldap.models import FlextLdapModels


class TestFlextLdapValueObjectsCoverage:
    """Test class for covering missing value objects lines."""

    def test_dn_rdn_property(self) -> None:
        """Test DN rdn property (covers line 38)."""
        # Create valid DN and test rdn extraction
        dn_result = FlextLdapModels.DistinguishedName.create(
            "cn=test,ou=users,dc=example,dc=com",
        )
        assert dn_result.is_success, f"DN creation should succeed: {dn_result.error}"
        dn = dn_result.value
        rdn = dn.rdn
        assert rdn == "cn=test"

    def test_dn_validation_empty_error(self) -> None:
        """Test DN validation with empty value."""
        with pytest.raises(ValueError, match="Distinguished Name cannot be empty"):
            FlextLdapModels.DistinguishedName(value="")

    def test_dn_validation_missing_equals_error(self) -> None:
        """Test DN validation with missing equals sign."""
        with pytest.raises(
            ValueError,
            match="Invalid DN format - missing attribute=value pairs",
        ):
            FlextLdapModels.DistinguishedName(value="invalid_dn_format")

    def test_filter_empty_expression_error(self) -> None:
        """Test Filter validation with empty expression."""
        with pytest.raises(ValueError, match="LDAP filter cannot be empty"):
            FlextLdapModels.Filter(expression="")

    def test_filter_missing_parentheses_error(self) -> None:
        """Test Filter validation with missing parentheses."""
        with pytest.raises(
            ValueError,
            match="LDAP filter must be enclosed in parentheses",
        ):
            FlextLdapModels.Filter(expression="uid=test")

    def test_filter_factory_methods(self) -> None:
        """Test Filter factory methods."""
        # Test equals factory
        equals_filter = FlextLdapModels.Filter.equals("uid", "testuser")
        assert equals_filter.expression == "(uid=testuser)"

        # Test starts_with factory
        starts_filter = FlextLdapModels.Filter.starts_with("cn", "test")
        assert starts_filter.expression == "(cn=test*)"

        # Test object_class factory
        class_filter = FlextLdapModels.Filter.object_class("person")
        assert class_filter.expression == "(objectClass=person)"

    def test_scope_invalid_value_error(self) -> None:
        """Test Scope with invalid value."""
        with pytest.raises(ValueError, match="Invalid scope"):
            FlextLdapModels.Scope(value="invalid_scope")

    def test_scope_factory_methods(self) -> None:
        """Test Scope factory methods."""
        # Test base scope factory
        base_scope = FlextLdapModels.Scope.base()
        assert base_scope.value == "base"

        # Test onelevel scope factory
        onelevel_scope = FlextLdapModels.Scope.onelevel()
        assert onelevel_scope.value == "onelevel"

        # Test subtree scope factory
        subtree_scope = FlextLdapModels.Scope.subtree()
        assert subtree_scope.value == "subtree"

    def test_scope_valid_values(self) -> None:
        """Test Scope with valid values."""
        # Test valid scope values based on the constants in value_objects.py
        for scope in ["base", "onelevel", "subtree"]:
            scope_obj = FlextLdapModels.Scope(value=scope)
            assert scope_obj.value == scope, f"Should accept scope: {scope}"

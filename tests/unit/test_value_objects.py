"""Test module for flext-ldap functionality."""

from __future__ import annotations

import pytest

from flext_core import FlextResult
from flext_ldap import FlextLdapModels

"""Value object tests for flext-ldap.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""


class TestFlextLdapDistinguishedName:
    """Test LDAP Distinguished Name value object."""

    def test_create_dn_with_valid_values(self) -> None:
        """Test DN creation with valid DN strings."""
        dn_str = "cn=John Doe,ou=users,dc=example,dc=com"
        dn_vo = FlextLdapModels.ValueObjects.DistinguishedName(value=dn_str)
        assert dn_vo.value == dn_str

    def test_dn_validation_with_short_value(self) -> None:
        """Test DN validation with too short value."""
        with pytest.raises(
            (ValueError, Exception),
            match="String should have at least 3 characters",
        ):
            FlextLdapModels.ValueObjects.DistinguishedName(value="x")

    def test_dn_create_method_success(self) -> None:
        """Test DN create method with valid input."""
        dn_str = "cn=test,dc=example,dc=com"
        result = FlextLdapModels.ValueObjects.DistinguishedName.create(dn_str)
        assert isinstance(result, FlextResult)
        assert result.is_success
        assert result.value.value == dn_str

    def test_dn_create_method_failure(self) -> None:
        """Test DN create method with invalid input."""
        result = FlextLdapModels.ValueObjects.DistinguishedName.create("")
        assert isinstance(result, FlextResult)
        assert not result.is_success
        assert result.error is not None

    def test_dn_validation_business_rules(self) -> None:
        """Test DN business rules validation."""
        dn_str = "cn=test,dc=example,dc=com"
        dn_vo = FlextLdapModels.ValueObjects.DistinguishedName(value=dn_str)
        result = dn_vo.validate_business_rules()
        assert isinstance(result, FlextResult)
        assert result.is_success

    def test_dn_equality(self) -> None:
        """Test DN equality comparison."""
        dn_str = "cn=test,dc=example,dc=com"
        dn1 = FlextLdapModels.ValueObjects.DistinguishedName(value=dn_str)
        dn2 = FlextLdapModels.ValueObjects.DistinguishedName(value=dn_str)
        assert dn1 == dn2

    def test_dn_inequality(self) -> None:
        """Test DN inequality comparison."""
        dn1 = FlextLdapModels.ValueObjects.DistinguishedName(
            value="cn=test1,dc=example,dc=com",
        )
        dn2 = FlextLdapModels.ValueObjects.DistinguishedName(
            value="cn=test2,dc=example,dc=com",
        )
        assert dn1 != dn2


class TestFlextLdapFilter:
    """Test LDAP Filter value object."""

    def test_create_filter_with_simple_filter(self) -> None:
        """Test filter creation with simple filter string."""
        filter_str = "(cn=John Doe)"
        filter_vo = FlextLdapModels.ValueObjects.Filter(value=filter_str)
        assert filter_vo.value == filter_str

    def test_filter_create_method_success(self) -> None:
        """Test filter create method with valid input."""
        filter_str = "(cn=test)"
        result = FlextLdapModels.ValueObjects.Filter.create(filter_str)
        assert isinstance(result, FlextResult)
        assert result.is_success
        assert result.value.value == filter_str

    def test_filter_create_method_failure(self) -> None:
        """Test filter create method with invalid input."""
        result = FlextLdapModels.ValueObjects.Filter.create("")
        assert isinstance(result, FlextResult)
        assert not result.is_success
        assert result.error is not None

    def test_filter_equals_method(self) -> None:
        """Test filter equals factory method."""
        filter_vo = FlextLdapModels.ValueObjects.Filter.equals("cn", "test")
        assert filter_vo.value == "(cn=test)"

    def test_filter_starts_with_method(self) -> None:
        """Test filter starts_with factory method."""
        filter_vo = FlextLdapModels.ValueObjects.Filter.starts_with("cn", "test")
        assert filter_vo.value == "(cn=test*)"

    def test_filter_object_class_method(self) -> None:
        """Test filter object_class factory method."""
        filter_vo = FlextLdapModels.ValueObjects.Filter.object_class("person")
        assert filter_vo.value == "(objectClass=person)"

    def test_filter_all_objects_method(self) -> None:
        """Test filter all_objects factory method."""
        filter_vo = FlextLdapModels.ValueObjects.Filter.all_objects()
        assert filter_vo.value == "(objectClass=*)"

    def test_filter_validation_business_rules(self) -> None:
        """Test filter business rules validation."""
        filter_str = "(cn=test)"
        filter_vo = FlextLdapModels.ValueObjects.Filter(value=filter_str)
        result = filter_vo.validate_business_rules()
        assert isinstance(result, FlextResult)
        assert result.is_success


class TestFlextLdapScope:
    """Test LDAP Search Scope value object."""

    def test_create_scope_with_valid_scope(self) -> None:
        """Test scope creation with valid scope."""
        scope_vo = FlextLdapModels.ValueObjects.Scope(scope="subtree")
        assert scope_vo.scope == "subtree"

    def test_scope_create_method_success(self) -> None:
        """Test scope create method with valid input."""
        result = FlextLdapModels.ValueObjects.Scope.create("subtree")
        assert isinstance(result, FlextResult)
        assert result.is_success
        assert result.value.scope == "subtree"

    def test_scope_create_method_failure(self) -> None:
        """Test scope create method with invalid input."""
        result = FlextLdapModels.ValueObjects.Scope.create("invalid")
        assert isinstance(result, FlextResult)
        assert not result.is_success
        assert result.error is not None

    def test_scope_base_method(self) -> None:
        """Test scope base factory method."""
        scope_vo = FlextLdapModels.ValueObjects.Scope.base()
        assert scope_vo.scope == "base"

    def test_scope_one_method(self) -> None:
        """Test scope one factory method."""
        scope_vo = FlextLdapModels.ValueObjects.Scope.one()
        assert scope_vo.scope == "onelevel"

    def test_scope_sub_method(self) -> None:
        """Test scope sub factory method."""
        scope_vo = FlextLdapModels.ValueObjects.Scope.sub()
        assert scope_vo.scope == "subtree"

    def test_scope_subtree_method(self) -> None:
        """Test scope subtree factory method."""
        scope_vo = FlextLdapModels.ValueObjects.Scope.subtree()
        assert scope_vo.scope == "subtree"

    def test_scope_onelevel_method(self) -> None:
        """Test scope onelevel factory method."""
        scope_vo = FlextLdapModels.ValueObjects.Scope.onelevel()
        assert scope_vo.scope == "onelevel"

    def test_scope_validation_business_rules(self) -> None:
        """Test scope business rules validation."""
        scope_vo = FlextLdapModels.ValueObjects.Scope(scope="subtree")
        result = scope_vo.validate_business_rules()
        assert isinstance(result, FlextResult)
        assert result.is_success

    def test_scope_validation_invalid_scope(self) -> None:
        """Test scope validation with invalid scope."""
        with pytest.raises(ValueError, match="Invalid LDAP scope"):
            FlextLdapModels.ValueObjects.Scope(scope="invalid")

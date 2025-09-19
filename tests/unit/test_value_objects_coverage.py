"""Test coverage for FlextLdapModels.ValueObjects missing lines.

This module provides surgical test coverage for specific uncovered lines
in value_objects.py to achieve 100% coverage.
"""

from flext_ldap.value_objects import FlextLdapModels


class TestFlextLdapValueObjectsCoverage:
    """Test class for covering missing value objects lines."""

    def test_execute_method_coverage(self) -> None:
        """Test execute method (covers line 39)."""
        # Create instance and call execute method
        service = FlextLdapModels.ValueObjects()
        result = service.execute()
        assert result.is_success
        assert result.data == {"status": "value_objects_available"}

    def test_dn_rdn_property(self) -> None:
        """Test DN rdn property (covers line 92)."""
        # Create valid DN and test rdn extraction
        result = FlextLdapModels.ValueObjects.DistinguishedName.create(
            "cn=test,ou=users,dc=example,dc=com",
        )
        assert result.is_success
        dn = result.unwrap()
        rdn = dn.rdn
        assert rdn == "cn=test"

    def test_dn_is_descendant_of_string_input(self) -> None:
        """Test is_descendant_of with string input (covers lines 99-100)."""
        # Create DN and test descendant check with string
        result = FlextLdapModels.ValueObjects.DistinguishedName.create(
            "cn=test,ou=users,dc=example,dc=com",
        )
        assert result.is_success
        dn = result.unwrap()

        # Test with string parent DN
        is_descendant = dn.is_descendant_of("dc=example,dc=com")
        assert is_descendant

    def test_dn_is_descendant_of_dn_object(self) -> None:
        """Test is_descendant_of with DN object input."""
        # Create DN and test descendant check with DN object
        result1 = FlextLdapModels.ValueObjects.DistinguishedName.create(
            "cn=test,ou=users,dc=example,dc=com",
        )
        result2 = FlextLdapModels.ValueObjects.DistinguishedName.create(
            "dc=example,dc=com"
        )
        assert result1.is_success
        assert result2.is_success

        dn = result1.unwrap()
        parent_dn = result2.unwrap()

        # Test with DN object parent
        is_descendant = dn.is_descendant_of(parent_dn)
        assert is_descendant

    def test_scope_invalid_value_error(self) -> None:
        """Test Scope with invalid value."""
        # This should trigger scope validation error
        result = FlextLdapModels.ValueObjects.Scope.create("invalid_scope")
        assert result.is_failure
        assert result.error is not None
        assert "Invalid LDAP scope" in result.error

    def test_scope_valid_values(self) -> None:
        """Test Scope with valid values."""
        # Test valid scope values based on error message
        for scope in ["base", "one", "sub", "subtree", "onelevel", "children"]:
            result = FlextLdapModels.ValueObjects.Scope.create(scope)
            assert result.is_success, f"Should accept scope: {scope}"

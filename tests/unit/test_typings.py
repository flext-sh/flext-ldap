"""Tests for FlextLdapTypes module."""

from flext_ldap.typings import FlextLdapTypes


class TestFlextLdapTypes:
    """Test cases for FlextLdapTypes."""

    def test_typings_initialization(self) -> None:
        """Test typings initialization."""
        types = FlextLdapTypes()
        assert types is not None

    def test_typings_basic_functionality(self) -> None:
        """Test basic typings functionality."""
        types = FlextLdapTypes()
        # Add specific test cases based on typings functionality
        assert hasattr(types, "__class__")

    def test_ldap_domain_types(self) -> None:
        """Test LDAP domain types."""
        assert hasattr(FlextLdapTypes, "LdapDomain")
        assert hasattr(FlextLdapTypes.LdapDomain, "SearchScope")
        assert hasattr(FlextLdapTypes.LdapDomain, "ConnectionState")

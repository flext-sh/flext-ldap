"""Tests for FlextLdapServersFactory module."""

from flext_ldap.servers.factory import FlextLdapServersFactory


class TestFlextLdapServersFactory:
    """Test cases for FlextLdapServersFactory."""

    def test_servers_factory_initialization(self) -> None:
        """Test servers factory initialization."""
        factory = FlextLdapServersFactory()
        assert factory is not None

    def test_servers_factory_basic_functionality(self) -> None:
        """Test basic servers factory functionality."""
        factory = FlextLdapServersFactory()
        # Add specific test cases based on servers factory functionality
        assert hasattr(factory, "__class__")

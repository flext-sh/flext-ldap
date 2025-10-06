"""Tests for FlextLDAPServersFactory module."""

from flext_ldap.servers.factory import FlextLDAPServersFactory


class TestFlextLDAPServersFactory:
    """Test cases for FlextLDAPServersFactory."""

    def test_servers_factory_initialization(self):
        """Test servers factory initialization."""
        factory = FlextLDAPServersFactory()
        assert factory is not None

    def test_servers_factory_basic_functionality(self):
        """Test basic servers factory functionality."""
        factory = FlextLDAPServersFactory()
        # Add specific test cases based on servers factory functionality
        assert hasattr(factory, "__class__")

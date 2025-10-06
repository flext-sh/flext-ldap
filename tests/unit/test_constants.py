"""Tests for FlextLDAPConstants module."""

from flext_ldap.constants import FlextLDAPConstants


class TestFlextLDAPConstants:
    """Test cases for FlextLDAPConstants."""

    def test_constants_initialization(self):
        """Test constants initialization."""
        constants = FlextLDAPConstants()
        assert constants is not None

    def test_protocol_constants(self):
        """Test protocol constants."""
        assert FlextLDAPConstants.Protocol.DEFAULT_PORT == 389
        assert FlextLDAPConstants.Protocol.DEFAULT_SSL_PORT == 636

    def test_scopes_constants(self):
        """Test scopes constants."""
        assert FlextLDAPConstants.Scopes.BASE == "base"
        assert FlextLDAPConstants.Scopes.ONELEVEL == "level"
        assert FlextLDAPConstants.Scopes.SUBTREE == "subtree"

    def test_literal_types_constants(self):
        """Test literal types constants."""
        assert FlextLDAPConstants.LiteralTypes.SEARCH_SCOPE_BASE == "BASE"
        assert FlextLDAPConstants.LiteralTypes.SEARCH_SCOPE_LEVEL == "LEVEL"
        assert FlextLDAPConstants.LiteralTypes.SEARCH_SCOPE_SUBTREE == "SUBTREE"

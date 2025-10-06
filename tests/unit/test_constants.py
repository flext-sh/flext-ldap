"""Tests for FlextLdapConstants module."""

from flext_ldap.constants import FlextLdapConstants


class TestFlextLdapConstants:
    """Test cases for FlextLdapConstants."""

    def test_constants_initialization(self):
        """Test constants initialization."""
        constants = FlextLdapConstants()
        assert constants is not None

    def test_protocol_constants(self):
        """Test protocol constants."""
        assert FlextLdapConstants.Protocol.DEFAULT_PORT == 389
        assert FlextLdapConstants.Protocol.DEFAULT_SSL_PORT == 636

    def test_scopes_constants(self):
        """Test scopes constants."""
        assert FlextLdapConstants.Scopes.BASE == "base"
        assert FlextLdapConstants.Scopes.ONELEVEL == "level"
        assert FlextLdapConstants.Scopes.SUBTREE == "subtree"

    def test_literal_types_constants(self):
        """Test literal types constants."""
        assert FlextLdapConstants.LiteralTypes.SEARCH_SCOPE_BASE == "BASE"
        assert FlextLdapConstants.LiteralTypes.SEARCH_SCOPE_LEVEL == "LEVEL"
        assert FlextLdapConstants.LiteralTypes.SEARCH_SCOPE_SUBTREE == "SUBTREE"

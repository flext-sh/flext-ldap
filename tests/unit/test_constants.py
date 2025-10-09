"""Tests for FlextLdapConstants module."""

from flext_ldap.constants import FlextLdapConstants


class TestFlextLdapConstants:
    """Test cases for FlextLdapConstants."""

    def test_constants_initialization(self) -> None:
        """Test constants initialization."""
        constants = FlextLdapConstants()
        assert constants is not None

    def test_protocol_constants(self) -> None:
        """Test protocol constants delegated to flext-core."""
        from flext_core import FlextConstants

        # Protocol constants are now delegated to flext-core
        assert FlextConstants.Platform.LDAP_DEFAULT_PORT == 389
        assert FlextConstants.Platform.LDAPS_DEFAULT_PORT == 636

        # Verify domain-specific protocol constants still exist
        assert FlextLdapConstants.Protocol.LDAP == "ldap"
        assert FlextLdapConstants.Protocol.LDAPS == "ldaps"

    def test_scopes_constants(self) -> None:
        """Test scopes constants."""
        assert FlextLdapConstants.Scopes.BASE == "base"
        assert FlextLdapConstants.Scopes.ONELEVEL == "level"
        assert FlextLdapConstants.Scopes.SUBTREE == "subtree"

    def test_literal_types_constants(self) -> None:
        """Test literal types constants."""
        assert FlextLdapConstants.LiteralTypes.SEARCH_SCOPE_BASE == "BASE"
        assert FlextLdapConstants.LiteralTypes.SEARCH_SCOPE_LEVEL == "LEVEL"
        assert FlextLdapConstants.LiteralTypes.SEARCH_SCOPE_SUBTREE == "SUBTREE"

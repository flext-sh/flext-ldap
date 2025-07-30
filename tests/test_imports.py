"""Test that all imports work correctly."""

import pytest
from flext_ldap.models import LDAPEntry, LDAPFilter, LDAPScope

# Import legacy aliases for backward compatibility testing
try:
    from flext_ldap import LDAPClient
except ImportError:
    # If not available, create a dummy for testing
    LDAPClient = None


class TestImports:
    """Test import functionality."""

    @pytest.mark.unit
    def test_main_imports(self) -> None:
        """Test main package imports (backward compatibility)."""


        # These should work via backward compatibility aliases
        assert LDAPClient is not None
        assert LDAPEntry is not None
        assert LDAPFilter is not None
        assert LDAPScope is not None

    @pytest.mark.unit
    def test_new_imports(self) -> None:
        """Test new FlextLdap imports."""
        from flext_ldap import (
            FlextLdapClient,
            FlextLdapEntry,
            FlextLdapFilter,
            FlextLdapScope,
        )

        assert FlextLdapClient is not None
        assert FlextLdapEntry is not None
        assert FlextLdapFilter is not None
        assert FlextLdapScope is not None

    @pytest.mark.unit
    def test_models_imports(self) -> None:
        """Test models imports (backward compatibility)."""
        try:


            assert LDAPEntry is not None
            assert LDAPFilter is not None
            assert LDAPScope is not None
        except ImportError:
            # Models module may not exist, that's okay
            pass

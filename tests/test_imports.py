"""Test that all imports work correctly."""

import pytest


class TestImports:
    """Test import functionality."""

    @pytest.mark.unit
    def test_main_imports(self):
        """Test main package imports."""
        from flext_ldap import LDAPClient, LDAPEntry, LDAPFilter, LDAPScope
        
        assert LDAPClient is not None
        assert LDAPEntry is not None
        assert LDAPFilter is not None
        assert LDAPScope is not None

    @pytest.mark.unit
    def test_models_imports(self):
        """Test models imports."""
        from flext_ldap.models import LDAPEntry, LDAPFilter, LDAPScope
        
        assert LDAPEntry is not None
        assert LDAPFilter is not None
        assert LDAPScope is not None
